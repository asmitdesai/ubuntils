"""Baseline suppression: environment-specific known-good fingerprints.

Distinct from --config (Allowlist): an allowlist mutes a rule or path
everywhere; a baseline says "in *this* environment, this specific
artifact is known good" — an SSH key fingerprint, a file path, etc.
A baseline match drops the finding entirely; the count is recorded in
scan_metadata (never a silent drop) and allowlist suppression still
applies on top.

Example baseline (YAML):

    baseline:
      - rule_id: SSH_UNAUTHORIZED_KEY
        fingerprint: SHA256:Qx4…           # the key's fingerprint, or its base64 data
      - rule_id: SHELL_RC_MODIFICATION
        fingerprint: /home/deploy/.bashrc  # exact match against artifact_path

Never key a baseline on text an attacker chooses. For SSH keys that means
the key's comment and options: anyone who can add a key picks its comment,
so `fingerprint: ci@ci-runner` would hide a planted key labelled
`ci@ci-runner`. Key entries therefore match the key type and data (or the
`SHA256:` fingerprint) only. A path entry says "this file's ordinary churn
is expected": it never hides a finding whose *content* is suspicious (a
`content_match` signal, e.g. a download-and-execute line).
"""
import re
import warnings
from dataclasses import dataclass, field
from typing import List

import yaml

from ubuntils.collectors.ssh import _parse_key_line, key_fingerprint
from ubuntils.detectors.identity import rule_names

# Rules whose raw_value is an authorized_keys line: only the key itself (type
# and data) identifies it; options and comment are attacker-chosen.
_KEY_RULES = frozenset({"SSH_UNAUTHORIZED_KEY", "SSH_KEY_INVENTORY"})

V1_DEPRECATION = (
    "baseline {path!r} uses the text-matching format that ubuntils 3.0 replaces "
    "with hash-keyed entries (`ubuntils baseline create`). It still works in 2.3, "
    "but SSH key entries now match only the key, never its comment."
)

# Fingerprints match raw_value only on word boundaries ("ghost" matches
# "ghost:x:0:0" but not "ghostly"), and must be at least this long — a bare
# "a" or "ss" would otherwise silently suppress far more than intended.
MIN_FINGERPRINT_LENGTH = 3


def _fingerprint_in(fingerprint: str, text: str) -> bool:
    return re.search(rf"(?<![\w.@-]){re.escape(fingerprint)}(?![\w.@-])", text) is not None


def _has_content_signal(finding) -> bool:
    return any(s.get("name") == "content_match" for s in (finding.signals or []))


def _key_matches(fingerprint: str, raw_line: str) -> bool:
    """Match a baseline entry against the key itself, never its comment or
    options: either the sshd-style SHA256 fingerprint, or a whole-word match
    within "<key_type> <key_data>"."""
    key = _parse_key_line(raw_line)
    if fingerprint.startswith("SHA256:"):
        return key_fingerprint(key["key_data"]) == fingerprint
    return _fingerprint_in(fingerprint, f"{key['key_type']} {key['key_data']}")


@dataclass
class Baseline:
    entries: List[dict] = field(default_factory=list)

    def matches(self, finding) -> bool:
        for entry in self.entries:
            if entry.get("rule_id") not in rule_names(finding.rule_id):
                continue
            fingerprint = entry.get("fingerprint", "")
            if not fingerprint:
                continue
            if fingerprint == finding.artifact_path:
                if not _has_content_signal(finding):
                    return True
                continue
            if finding.rule_id in _KEY_RULES:
                if _key_matches(fingerprint, finding.raw_value or ""):
                    return True
                continue
            if _fingerprint_in(fingerprint, finding.raw_value):
                return True
        return False

    def filter(self, findings: list) -> tuple:
        kept = []
        suppressed = []
        for f in findings:
            if self.matches(f):
                suppressed.append(f)
            else:
                kept.append(f)
        return kept, suppressed


def load_baseline(path: str) -> Baseline:
    """Parse a baseline from a YAML config file.

    Raises ValueError with a clear message on malformed config.
    """
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Baseline {path!r} must be a YAML mapping at the top level")
    version = data.get("version", 1)
    if version != 1:
        raise ValueError(f"Baseline {path!r} has version {version!r}; this ubuntils reads "
                         "version 1 only (version 2 baselines need ubuntils 3.0)")
    if "version" not in data:
        warnings.warn(V1_DEPRECATION.format(path=path), FutureWarning, stacklevel=2)
    raw_entries = data.get("baseline", []) or []
    if not isinstance(raw_entries, list):
        raise ValueError(f"'baseline' in {path!r} must be a list")
    entries = []
    for i, e in enumerate(raw_entries):
        if not isinstance(e, dict) or "rule_id" not in e or "fingerprint" not in e:
            raise ValueError(
                f"'baseline' entry {i} in {path!r} must be a mapping with "
                "'rule_id' and 'fingerprint'"
            )
        fingerprint = str(e["fingerprint"])
        if len(fingerprint) < MIN_FINGERPRINT_LENGTH:
            raise ValueError(
                f"'baseline' entry {i} in {path!r}: fingerprint {fingerprint!r} is shorter "
                f"than {MIN_FINGERPRINT_LENGTH} characters and would suppress too broadly"
            )
        entries.append({"rule_id": str(e["rule_id"]), "fingerprint": fingerprint})
    return Baseline(entries=entries)
