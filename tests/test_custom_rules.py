import pytest

from ubuntils.detectors.custom_rules import (
    CustomRule,
    apply_custom_rules,
    load_custom_rules,
)
from ubuntils.detectors.finding import Severity


def _rule(**kw):
    base = dict(
        id="CUSTOM_TEST", severity=Severity.HIGH, title="t", description="d",
        source="process", match="substring", pattern="xmrig",
    )
    base.update(kw)
    return CustomRule(**base)


def test_substring_match_on_process_cmdline():
    artifacts = {"processes": [{"pid": 1, "name": "x", "exe": "/tmp/x", "cmdline": "xmrig --donate 0"}]}
    findings = apply_custom_rules([_rule()], artifacts)
    assert len(findings) == 1
    assert findings[0].rule_id == "CUSTOM_TEST"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].artifact_path == "/tmp/x"
    assert findings[0].remediation_available is False


def test_regex_match_on_environment():
    rule = _rule(source="environment", match="regex", pattern=r"/tmp/.*\.so")
    artifacts = {"env_definitions": [
        {"variable": "LD_PRELOAD", "value": "/tmp/h.so", "raw_line": "LD_PRELOAD=/tmp/h.so",
         "source": "/etc/environment", "owner": "system"},
    ]}
    findings = apply_custom_rules([rule], artifacts)
    assert len(findings) == 1
    assert findings[0].artifact_path == "/etc/environment"


def test_glob_match_on_network_remote():
    rule = _rule(source="network", match="glob", pattern="10.0.0.*:*")
    artifacts = {"connections": [
        {"proto": "tcp", "local_addr": "0.0.0.0", "local_port": "4444",
         "remote_addr": "10.0.0.9", "remote_port": "53", "state": "ESTAB", "pid": "7"},
    ]}
    findings = apply_custom_rules([rule], artifacts)
    assert len(findings) == 1


def test_no_match_returns_empty():
    artifacts = {"processes": [{"pid": 1, "name": "x", "exe": "/bin/ls", "cmdline": "ls -la"}]}
    assert apply_custom_rules([_rule()], artifacts) == []


def test_load_custom_rules_parses_valid_file(tmp_path):
    p = tmp_path / "rules.yaml"
    p.write_text(
        "rules:\n"
        "  - id: CUSTOM_MINER\n"
        "    severity: HIGH\n"
        "    title: Known miner\n"
        "    description: cmdline matches a miner\n"
        "    source: process\n"
        "    match: substring\n"
        "    pattern: xmrig\n"
    )
    rules = load_custom_rules(str(p))
    assert len(rules) == 1
    assert rules[0].id == "CUSTOM_MINER"
    assert rules[0].severity == Severity.HIGH
    assert rules[0].source == "process"


def test_load_custom_rules_rejects_bad_severity(tmp_path):
    p = tmp_path / "rules.yaml"
    p.write_text(
        "rules:\n  - id: X\n    severity: CRITICAL\n    title: t\n"
        "    description: d\n    source: process\n    match: substring\n    pattern: y\n"
    )
    with pytest.raises(ValueError, match="severity"):
        load_custom_rules(str(p))


def test_load_custom_rules_rejects_bad_source(tmp_path):
    p = tmp_path / "rules.yaml"
    p.write_text(
        "rules:\n  - id: X\n    severity: HIGH\n    title: t\n"
        "    description: d\n    source: kernel\n    match: substring\n    pattern: y\n"
    )
    with pytest.raises(ValueError, match="source"):
        load_custom_rules(str(p))


def test_load_custom_rules_rejects_missing_field(tmp_path):
    p = tmp_path / "rules.yaml"
    p.write_text("rules:\n  - id: X\n    severity: HIGH\n    title: t\n")
    with pytest.raises(ValueError, match="missing required field"):
        load_custom_rules(str(p))


def test_load_custom_rules_empty_file(tmp_path):
    p = tmp_path / "rules.yaml"
    p.write_text("")
    assert load_custom_rules(str(p)) == []
