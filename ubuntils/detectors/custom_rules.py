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
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Pattern, Tuple

import yaml

from ubuntils.detectors.finding import Finding, Severity

_MATCH_TYPES = frozenset({"regex", "substring", "glob"})
_VALID_SOURCES = frozenset({"cron", "environment", "ssh", "process", "network"})
_REQUIRED_FIELDS = ("id", "severity", "title", "description", "source", "match", "pattern")

# Regex rules run against attacker-controlled text (cmdlines, cron commands),
# and Python's `re` has no timeout. Two guards against catastrophic
# backtracking: reject the classic nested-quantifier shapes at load time, and
# cap how much text any rule scans.
_MAX_MATCH_TEXT = 4096
_NESTED_QUANTIFIER_RE = re.compile(r"\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)\s*[+*{]")


@dataclass
class CustomRule:
    id: str
    severity: Severity
    title: str
    description: str
    source: str
    match: str  # one of _MATCH_TYPES
    pattern: str
    compiled: Optional[Pattern] = field(default=None, repr=False, compare=False)

    def matches(self, path: str, text: str) -> bool:
        if self.match == "glob":
            return fnmatch.fnmatch(path or "", self.pattern)
        text = (text or "")[:_MAX_MATCH_TEXT]
        if self.match == "substring":
            return self.pattern in text
        regex = self.compiled if self.compiled is not None else re.compile(self.pattern)
        return regex.search(text) is not None


def _compile_regex(rid: str, pattern: str) -> Pattern:
    """Compile at load so a typo fails loudly instead of silently never matching."""
    if _NESTED_QUANTIFIER_RE.search(pattern):
        raise ValueError(
            f"Rule {rid!r}: pattern {pattern!r} nests quantifiers (e.g. '(a+)+'), which can "
            "backtrack catastrophically on attacker-controlled text — simplify it"
        )
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Rule {rid!r}: invalid regex {pattern!r}: {exc}")


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
            compiled=_compile_regex(rid, str(entry["pattern"])) if match == "regex" else None,
        ))
    return rules
