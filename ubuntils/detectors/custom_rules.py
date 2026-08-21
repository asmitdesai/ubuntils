"""User-supplied pattern-match detection rules loaded via `--rules FILE`.

Custom rules *add* detections (the allowlist `--config` *suppresses* them).
They are pattern-match only — regex, substring, or path-glob against a named
artifact source — with NO code execution, so a rules file is safe by
construction. Allowlist suppression still applies to custom-rule findings
(handled by DetectionEngine after these run).
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Iterator, List, Tuple

import yaml

from ubuntils.detectors.finding import Finding, Severity

_MATCH_TYPES = frozenset({"regex", "substring", "glob"})
_VALID_SOURCES = frozenset({"cron", "environment", "ssh", "process", "network"})
_REQUIRED_FIELDS = ("id", "severity", "title", "description", "source", "match", "pattern")


@dataclass
class CustomRule:
    id: str
    severity: Severity
    title: str
    description: str
    source: str
    match: str  # one of _MATCH_TYPES
    pattern: str

    def matches(self, path: str, text: str) -> bool:
        if self.match == "glob":
            return fnmatch.fnmatch(path or "", self.pattern)
        if self.match == "substring":
            return self.pattern in (text or "")
        try:  # regex
            return re.search(self.pattern, text or "") is not None
        except re.error:
            return False


def _iter_items(source: str, artifacts: dict) -> Iterator[Tuple[str, str]]:
    """Yield (artifact_path, searchable_text) pairs for a named source.

    Note: for the `network` source, the first element is `remote_addr:remote_port`
    (an endpoint, not a filesystem path). `glob` rules match it; `regex`/`substring`
    match the second element. This is intentional.
    """
    if source == "cron":
        for e in artifacts.get("cron_entries", []):
            yield e.get("source", ""), e.get("command", "")
    elif source == "environment":
        for e in artifacts.get("env_definitions", []):
            yield e.get("source", ""), e.get("raw_line", e.get("value", ""))
    elif source == "ssh":
        for e in artifacts.get("authorized_keys", []):
            path = f"{e.get('home', '')}/.ssh/authorized_keys"
            text = " ".join(filter(None, [
                e.get("key_type", ""), e.get("key_data", ""), e.get("comment", ""),
            ]))
            yield path, text
    elif source == "process":
        for e in artifacts.get("processes", []):
            yield e.get("exe", ""), e.get("cmdline", "")
    elif source == "network":
        for e in artifacts.get("connections", []):
            path = f"{e.get('remote_addr', '')}:{e.get('remote_port', '')}"
            text = (
                f"{e.get('proto', '')} "
                f"{e.get('local_addr', '')}:{e.get('local_port', '')} -> "
                f"{e.get('remote_addr', '')}:{e.get('remote_port', '')} "
                f"{e.get('state', '')}"
            )
            yield path, text


def apply_custom_rules(rules: List[CustomRule], artifacts: dict) -> List[Finding]:
    findings: List[Finding] = []
    for rule in rules:
        for path, text in _iter_items(rule.source, artifacts):
            if rule.matches(path, text):
                findings.append(Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    artifact_path=path,
                    raw_value=text,
                    remediation_available=False,
                    remediation_description=None,
                ))
    return findings


def load_custom_rules(path: str) -> List[CustomRule]:
    """Parse custom rules from a YAML file. Raises ValueError on malformed config."""
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Rules file {path!r} must be a YAML mapping at the top level")
    raw_rules = data.get("rules", []) or []
    if not isinstance(raw_rules, list):
        raise ValueError(f"'rules' in {path!r} must be a list")

    rules: List[CustomRule] = []
    for i, entry in enumerate(raw_rules):
        if not isinstance(entry, dict):
            raise ValueError(f"Rule #{i} in {path!r} must be a mapping")
        missing = [k for k in _REQUIRED_FIELDS if k not in entry]
        if missing:
            raise ValueError(f"Rule #{i} in {path!r} missing required field {missing[0]!r}")

        rid = str(entry["id"])
        severity = str(entry["severity"]).upper()
        source = str(entry["source"])
        match = str(entry["match"])
        if severity not in Severity.__members__:
            raise ValueError(f"Rule {rid!r}: severity must be HIGH/MEDIUM/LOW, got {severity!r}")
        if source not in _VALID_SOURCES:
            raise ValueError(
                f"Rule {rid!r}: source must be one of {sorted(_VALID_SOURCES)}, got {source!r}"
            )
        if match not in _MATCH_TYPES:
            raise ValueError(
                f"Rule {rid!r}: match must be one of {sorted(_MATCH_TYPES)}, got {match!r}"
            )
        rules.append(CustomRule(
            id=rid,
            severity=Severity[severity],
            title=str(entry["title"]),
            description=str(entry["description"]),
            source=source,
            match=match,
            pattern=str(entry["pattern"]),
        ))
    return rules
