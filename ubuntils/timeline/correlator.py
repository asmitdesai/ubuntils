"""Attach related timeline events to findings (correlation, never causation).

After detection and timeline build, each finding is matched against timeline
events by two cheap, conservative signals: a path token derived from the
finding's artifact_path (a basename or a /home/<user> name), and a small set of
per-rule keywords. The most recent matches (capped) are stored on the finding.
This is a heuristic surfacing aid — it does not assert that any event caused the
finding.
"""
from __future__ import annotations

import os
from typing import List, Set

from ubuntils.detectors.finding import Finding
from ubuntils.timeline.builder import TimelineEvent

_MAX_RELATED = 5

# Too generic to use as a path token (would match almost anything).
_GENERIC_BASENAMES = frozenset({"exe", "authorized_keys", "environment", "sudoers"})

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
    return tokens


def correlate(findings: List[Finding], timeline: List[TimelineEvent]) -> List[Finding]:
    """Attach related timeline events to each finding.

    Mutates each finding's `related_events` in place. The return value is the
    same `findings` list that was passed in — returned only as a convenience for
    call-chaining; callers do not need to use it, since the input findings are
    modified directly.
    """
    for finding in findings:
        tokens = _path_tokens(finding)
        keywords = _RULE_KEYWORDS.get(finding.rule_id, ())
        matches = []
        for event in timeline:
            desc = event.description.lower()
            if any(t in desc for t in tokens) or any(k in desc for k in keywords):
                matches.append(event)
        matches.sort(key=lambda e: e.timestamp, reverse=True)
        finding.related_events = matches[:_MAX_RELATED]
    return findings
