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
        fingerprint: ci@ci-runner        # whole-word match within raw_value
      - rule_id: SHELL_RC_MODIFICATION
        fingerprint: /home/deploy/.bashrc  # exact match against artifact_path
"""
import re
from dataclasses import dataclass, field
from typing import List

import yaml

# Fingerprints match raw_value only on word boundaries ("ghost" matches
# "ghost:x:0:0" but not "ghostly"), and must be at least this long — a bare
# "a" or "ss" would otherwise silently suppress far more than intended.
MIN_FINGERPRINT_LENGTH = 3


def _fingerprint_in(fingerprint: str, text: str) -> bool:
    return re.search(rf"(?<![\w.@-]){re.escape(fingerprint)}(?![\w.@-])", text) is not None


@dataclass
class Baseline:
    entries: List[dict] = field(default_factory=list)

    def matches(self, finding) -> bool:
        for entry in self.entries:
            if entry.get("rule_id") != finding.rule_id:
                continue
            fingerprint = entry.get("fingerprint", "")
            if not fingerprint:
                continue
            if fingerprint == finding.artifact_path:
                return True
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
