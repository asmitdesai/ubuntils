"""Optional YAML configuration: false-positive allowlisting.

A config file lets responders suppress known-good findings so a hot system's
output isn't drowned in noise from legitimate, expected artifacts (CI keys,
provisioning crontabs, etc.). Suppression is intentionally explicit — by rule
id and/or by artifact path — never a blanket "ignore everything" switch.

Example config (YAML):

    allowlist:
      rules:
        - SHELL_RC_MODIFICATION        # suppress this rule entirely
      paths:
        - /home/ci/.ssh/authorized_keys  # suppress any finding on this path
"""
from dataclasses import dataclass, field
from typing import List

import yaml


@dataclass
class Allowlist:
    rules: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)

    def suppresses(self, finding) -> bool:
        """Return True if this finding matches an allowlist entry."""
        if finding.rule_id in self.rules:
            return True
        if finding.artifact_path and finding.artifact_path in self.paths:
            return True
        return False

    def filter(self, findings: list) -> list:
        return [f for f in findings if not self.suppresses(f)]


def load_allowlist(path: str) -> Allowlist:
    """Parse an allowlist from a YAML config file.

    Raises ValueError with a clear message on malformed config rather than
    letting a YAML stack trace escape into a triage session.
    """
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config {path!r} must be a YAML mapping at the top level")
    section = data.get("allowlist", {}) or {}
    if not isinstance(section, dict):
        raise ValueError(f"'allowlist' in {path!r} must be a mapping")
    rules = section.get("rules", []) or []
    paths = section.get("paths", []) or []
    if not isinstance(rules, list) or not isinstance(paths, list):
        raise ValueError(f"'allowlist.rules' and 'allowlist.paths' in {path!r} must be lists")
    return Allowlist(rules=[str(r) for r in rules], paths=[str(p) for p in paths])
