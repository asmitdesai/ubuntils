"""Attach related timeline events to findings (correlation, never causation).

After detection and timeline build, each finding is matched against timeline
events (program name + message) by two cheap, conservative signals, both
matched as whole words: identifying tokens from the finding (a path basename, a
/home/<user> name, a package or module name, an account name) and a small set
of per-rule activity keywords (program names like sshd/cron/dpkg).

Only an event that names the finding's artifact AND shows the rule's kind of
activity corroborates it and earns the timeline_corroboration signal. When a
finding has no identifying token (PROCESS_* rules), keyword matches are still
attached for context but never scored — on a real host common words like
"exec" or "connect" match thousands of unrelated lines.

This is a heuristic surfacing aid — it does not assert that any event caused the
finding.
"""
from __future__ import annotations

import os
import re
from typing import List, Optional, Set

from ubuntils.detectors.finding import Finding
from ubuntils.detectors.scoring import apply_signal
from ubuntils.timeline.builder import TimelineEvent

_MAX_RELATED = 5

# Too generic to use as a path token (would match almost anything).
_GENERIC_BASENAMES = frozenset({
    "exe", "authorized_keys", "environment", "sudoers", "passwd", "shadow", "group",
})

_CORROBORATION_WEIGHT = 25

# Account rules point at /etc/passwd or /etc/shadow; the account name (first
# field of raw_value) is what log lines actually mention.
_USERNAME_RULES = frozenset({"USER_UID_ZERO", "USER_EMPTY_PASSWORD"})

_RULE_KEYWORDS = {
    "SSH_UNAUTHORIZED_KEY": ("sshd", "publickey", "accepted", "session opened"),
    "CRON_ROOT_EXEC": ("cron",),
    "CRON_TMP_PATH": ("cron",),
    "SUSPICIOUS_SYSTEMD_TIMER": ("systemd", "timer"),
    "SUDOERS_NOPASSWD": ("sudo",),
    "USER_UID_ZERO": ("useradd", "passwd", "groupadd"),
    "PROCESS_MASQUERADE": ("exec", "execve"),
    "PROCESS_SUSPICIOUS_CONNECTION": ("connect", "exec"),
    "LD_PRELOAD_INJECT": ("ld.so", "ld_preload", "preload"),
    "SHELL_RC_MODIFICATION": (),
    "USER_EMPTY_PASSWORD": ("passwd", "usermod", "chpasswd"),
    # Package-manager programs only: "install" alone matched snap hooks
    # (snap.firefox.hook.install) on a stock 26.04 host.
    "PACKAGE_TAMPERED": ("dpkg", "apt", "apt-get", "unattended-upgrade", "unattended-upgrades"),
    "IMMUTABLE_FLAG_SET": ("chattr",),
    "SETUID_INVENTORY": ("chmod", "setuid"),
    "PAM_BACKDOOR": ("pam_", "nsswitch"),
    "KERNEL_MODULE_SUSPICIOUS": ("insmod", "modprobe", "module"),
}


def _path_tokens(finding: Finding) -> Set[str]:
    tokens: Set[str] = set()
    path = finding.artifact_path or ""
    base = os.path.basename(path.rstrip("/"))
    if base and base.lower() not in _GENERIC_BASENAMES:
        tokens.add(base.lower())
    parts = [p for p in path.split("/") if p]
    if len(parts) >= 2 and parts[0] == "home":
        tokens.add(parts[1].lower())
    if finding.rule_id in _USERNAME_RULES:
        username = (finding.raw_value or "").split(":", 1)[0].strip()
        if username:
            tokens.add(username.lower())
    return tokens


def _whole_word_pattern(needles) -> Optional[re.Pattern]:
    """Match any needle as a whole word. Hyphens count as word characters, as
    in package names: "apt" must not match "apt-daily". A needle that ends in
    punctuation (e.g. "pam_") is a prefix, so only its start is bounded."""
    parts = []
    for n in needles:
        trail = r"(?![\w-])" if n[-1:].isalnum() else ""
        parts.append(r"(?<![\w-])" + re.escape(n) + trail)
    return re.compile("|".join(parts)) if parts else None


def correlate(findings: List[Finding], timeline: List[TimelineEvent]) -> List[Finding]:
    """Attach related timeline events to each finding, and add the
    timeline_corroboration signal to findings that have corroborating events.

    Mutates each finding's `related_events` (and signals) in place. The return value is the
    same `findings` list that was passed in — returned only as a convenience for
    call-chaining; callers do not need to use it, since the input findings are
    modified directly.
    """
    # Lower-case each event once, not once per finding.
    lowered = [(event, f"{event.program} {event.description}".lower()) for event in timeline]
    for finding in findings:
        tokens = _path_tokens(finding)
        keywords = _RULE_KEYWORDS.get(finding.rule_id, ())
        token_re = _whole_word_pattern(sorted(tokens))
        keyword_re = _whole_word_pattern(keywords)
        if token_re is None and keyword_re is None:
            finding.related_events = []
            continue
        corroborating, context = [], []
        for event, text in lowered:
            names_artifact = token_re is not None and token_re.search(text)
            shows_activity = keyword_re is not None and keyword_re.search(text)
            if names_artifact and (shows_activity or keyword_re is None):
                corroborating.append(event)
            elif shows_activity and token_re is None:
                context.append(event)
        corroborating.sort(key=lambda e: e.timestamp, reverse=True)
        context.sort(key=lambda e: e.timestamp, reverse=True)
        finding.related_events = (corroborating + context)[:_MAX_RELATED]
        if corroborating:
            apply_signal(finding, "timeline_corroboration", _CORROBORATION_WEIGHT,
                         f"{len(corroborating)} timeline event(s) name this artifact "
                         "alongside related activity")
    return findings
