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
        fingerprint: ci@ci-runner        # substring match against raw_value
      - rule_id: SHELL_RC_MODIFICATION
        fingerprint: /home/deploy/.bashrc  # exact match against artifact_path
"""
from dataclasses import dataclass, field
from typing import List

import yaml


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
            if fingerprint in finding.raw_value or fingerprint == finding.artifact_path:
                return True
        return False

    def filter(self, findings: list) -> tuple:
        kept = []
        suppressed = 0
        for f in findings:
            if self.matches(f):
                suppressed += 1
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
        entries.append({"rule_id": str(e["rule_id"]), "fingerprint": str(e["fingerprint"])})
    return Baseline(entries=entries)
