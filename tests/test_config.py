import pytest

from ubuntils.detectors.engine import DetectionEngine
from ubuntils.detectors.finding import Finding, Severity
from ubuntils.utils.config import Allowlist, load_allowlist


def _finding(rule_id="SHELL_RC_MODIFICATION", path="/home/ci/.bashrc"):
    return Finding(
        rule_id=rule_id,
        severity=Severity.LOW,
        title="t",
        description="d",
        artifact_path=path,
        raw_value="r",
        remediation_available=False,
    )


def test_allowlist_suppresses_by_rule():
    al = Allowlist(rules=["SHELL_RC_MODIFICATION"])
    assert al.suppresses(_finding()) is True
    assert al.suppresses(_finding(rule_id="CRON_TMP_PATH")) is False


def test_allowlist_suppresses_by_path():
    al = Allowlist(paths=["/home/ci/.ssh/authorized_keys"])
    assert al.suppresses(_finding(path="/home/ci/.ssh/authorized_keys")) is True
    assert al.suppresses(_finding(path="/home/bob/.ssh/authorized_keys")) is False


def test_allowlist_filter_removes_matches():
    al = Allowlist(rules=["SHELL_RC_MODIFICATION"])
    findings = [_finding(), _finding(rule_id="CRON_TMP_PATH")]
    out = al.filter(findings)
    assert len(out) == 1
    assert out[0].rule_id == "CRON_TMP_PATH"


def test_engine_applies_allowlist():
    artifacts = {"users": [
        {"username": "backdoor", "uid": 0, "gid": 0, "shell": "/bin/bash"},
    ]}
    assert any(f.rule_id == "USER_UID_ZERO" for f in DetectionEngine().run(artifacts))
    al = Allowlist(rules=["USER_UID_ZERO"])
    assert DetectionEngine(allowlist=al).run(artifacts) == []


def test_load_allowlist_from_file(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        "allowlist:\n  rules:\n    - SHELL_RC_MODIFICATION\n  paths:\n    - /home/ci/.bashrc\n"
    )
    al = load_allowlist(str(cfg))
    assert al.rules == ["SHELL_RC_MODIFICATION"]
    assert al.paths == ["/home/ci/.bashrc"]


def test_load_allowlist_empty_file(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("")
    al = load_allowlist(str(cfg))
    assert al.rules == [] and al.paths == []


def test_load_allowlist_rejects_non_mapping(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("- just\n- a list\n")
    with pytest.raises(ValueError):
        load_allowlist(str(cfg))


def test_load_allowlist_rejects_bad_rules_type(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("allowlist:\n  rules: notalist\n")
    with pytest.raises(ValueError):
        load_allowlist(str(cfg))
