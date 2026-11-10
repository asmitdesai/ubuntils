"""QW-13: SUSPICIOUS_SYSTEMD_TIMER answers to SUSPICIOUS_SYSTEMD_UNIT before 3.0 switches."""
import json

from tests import fixture_hosts as fh
from ubuntils.cli import main
from ubuntils.detectors.finding import Finding, Severity
from ubuntils.detectors.identity import deprecated_rule_ids, rule_aliases, rule_names
from ubuntils.utils.baseline import Baseline
from ubuntils.utils.config import Allowlist


def _f(rule="SUSPICIOUS_SYSTEMD_TIMER"):
    return Finding(rule_id=rule, severity=Severity.HIGH, title="t", description="d",
                   artifact_path="/etc/systemd/system/x.service", raw_value="/tmp/x",
                   remediation_available=False)


def test_alias_helpers():
    assert rule_aliases("SUSPICIOUS_SYSTEMD_TIMER") == ["SUSPICIOUS_SYSTEMD_UNIT"]
    assert rule_aliases("CRON_TMP_PATH") == []
    assert rule_names("SUSPICIOUS_SYSTEMD_TIMER") == {"SUSPICIOUS_SYSTEMD_TIMER",
                                                      "SUSPICIOUS_SYSTEMD_UNIT"}
    assert deprecated_rule_ids(["CRON_TMP_PATH", "SUSPICIOUS_SYSTEMD_TIMER"]) == \
        [("SUSPICIOUS_SYSTEMD_TIMER", "SUSPICIOUS_SYSTEMD_UNIT")]


def test_allowlist_and_baseline_accept_either_name():
    for name in ("SUSPICIOUS_SYSTEMD_TIMER", "SUSPICIOUS_SYSTEMD_UNIT"):
        assert Allowlist(rules=[name]).suppresses(_f())
        assert Baseline(entries=[{"rule_id": name,
                                  "fingerprint": "/etc/systemd/system/x.service"}]).matches(_f())
    assert not Allowlist(rules=["SUSPICIOUS_SYSTEMD_UNIT"]).suppresses(_f("CRON_TMP_PATH"))


def test_report_and_wazuh_line_carry_the_alias(tmp_path):
    from ubuntils.integrations.wazuh import finding_line
    r = fh.scan(fh.build_host("lab", tmp_path / "h"))
    systemd = [f for f in r.findings if f.rule_id == "SUSPICIOUS_SYSTEMD_TIMER"]
    assert systemd and all(f.rule_aliases == ["SUSPICIOUS_SYSTEMD_UNIT"] for f in systemd)
    assert json.loads(finding_line(systemd[0], "h"))["rule_aliases"] == ["SUSPICIOUS_SYSTEMD_UNIT"]
    other = next(f for f in r.findings if f.rule_id == "CRON_TMP_PATH")
    assert other.rule_aliases == []


def test_using_the_old_name_in_an_allowlist_warns(split_runner, tmp_path):
    cfg = tmp_path / "a.yaml"
    cfg.write_text("allowlist:\n  rules:\n    - SUSPICIOUS_SYSTEMD_TIMER\n")
    root = fh.build_host("clean", tmp_path / "h")
    r = split_runner.invoke(main, ["analyze", "--root", str(root), "--json", "--config", str(cfg)])
    assert r.exit_code == 0
    assert "SUSPICIOUS_SYSTEMD_TIMER is renamed SUSPICIOUS_SYSTEMD_UNIT in ubuntils 3.0" in r.stderr
    cfg.write_text("allowlist:\n  rules:\n    - SUSPICIOUS_SYSTEMD_UNIT\n")
    r = split_runner.invoke(main, ["analyze", "--root", str(root), "--json", "--config", str(cfg)])
    assert "renamed" not in r.stderr
