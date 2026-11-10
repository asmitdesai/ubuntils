"""E4-S5 / QW-9: --fail-on-findings and the exit-code table."""
import pytest

from tests import fixture_hosts as fh
from ubuntils import cli
from ubuntils.cli import main


def _analyze(runner, root, *extra):
    return runner.invoke(main, ["analyze", "--root", str(root), "--json", *extra])


def test_without_the_flag_findings_never_change_the_exit_status(split_runner, tmp_path):
    root = fh.build_host("lab", tmp_path / "h")
    assert _analyze(split_runner, root).exit_code == 0


def test_high_findings_exit_4_and_say_why(split_runner, tmp_path):
    root = fh.build_host("lab", tmp_path / "h")
    r = _analyze(split_runner, root, "--fail-on-findings")
    assert r.exit_code == cli.EXIT_FINDINGS_PRESENT == 4
    assert "at or above HIGH (--fail-on-findings)" in r.stderr
    assert '"findings"' in r.stdout  # the report is still written


def test_threshold_is_respected(split_runner, tmp_path):
    root = fh.build(tmp_path / "h", {"/etc/passwd": fh.STOCK_PASSWD,
                                     "/home/admin/.bashrc": "alias sudo='/tmp/.s/sudo'\n"})
    # A shell hijack is MEDIUM: under the default (high) threshold it passes.
    assert _analyze(split_runner, root, "--fail-on-findings").exit_code == 0
    assert _analyze(split_runner, root, "--fail-on-findings=medium").exit_code == 4
    assert _analyze(split_runner, root, "--fail-on-findings", "LOW").exit_code == 4


def test_inventory_never_counts(tmp_path):
    from ubuntils.detectors.finding import Finding, Severity
    inv = Finding(rule_id="SSH_KEY_INVENTORY", severity=Severity.LOW, title="t", description="d",
                  artifact_path="/a", raw_value="r", remediation_available=False)
    inv.category = "inventory"
    assert cli._findings_at_or_above([inv], "low") == 0
    inv.category = "persistence"
    assert cli._findings_at_or_above([inv], "low") == 1


def test_detection_failure_takes_precedence_over_findings(split_runner, tmp_path, monkeypatch):
    from ubuntils.pipeline import run_scan as real_run_scan

    def failing(*a, **k):
        r = real_run_scan(*a, **k)
        r.scan_metadata["detection_error"] = "RuntimeError: boom"
        return r

    monkeypatch.setattr(cli, "run_scan", failing)
    root = fh.build_host("lab", tmp_path / "h")
    assert _analyze(split_runner, root, "--fail-on-findings").exit_code == cli.EXIT_DETECTION_FAILED


@pytest.mark.parametrize("bad", ["--fail-on-findings=critical"])
def test_unknown_severity_is_a_usage_error(split_runner, tmp_path, bad):
    root = fh.build_host("clean", tmp_path / "h")
    assert _analyze(split_runner, root, bad).exit_code == 2


def test_tui_scan_with_the_flag_is_a_usage_error(split_runner, monkeypatch):
    monkeypatch.setattr(cli, "_ensure_root", lambda: None)
    r = split_runner.invoke(main, ["scan", "--fail-on-findings"])
    assert r.exit_code == 2 and "needs --json or --output" in r.stderr


def test_scan_json_exits_4_on_findings(split_runner, tmp_path, monkeypatch):
    # scan always reads the live host; feed it a fixture scan instead.
    r = fh.scan(fh.build_host("lab", tmp_path / "h"))
    monkeypatch.setattr(cli, "_ensure_root", lambda: None)
    monkeypatch.setattr(cli, "_run_pipeline", lambda **k: (
        r.findings, r.timeline, r.stats, r.scan_metadata, r.artifact_counts, []))
    assert split_runner.invoke(main, ["scan", "--json", "--no-wazuh"]).exit_code == 0
    res = split_runner.invoke(main, ["scan", "--json", "--no-wazuh", "--fail-on-findings"])
    assert res.exit_code == 4


def test_remediate_confirm_warns_about_tipping_off_once(split_runner, tmp_path, monkeypatch):
    r = fh.scan(fh.build_host("clean", tmp_path / "h"))
    monkeypatch.setattr(cli, "_ensure_root", lambda: None)
    monkeypatch.setattr(cli, "_run_pipeline", lambda **k: (
        r.findings, r.timeline, r.stats, r.scan_metadata, r.artifact_counts, []))
    res = split_runner.invoke(main, ["scan", "--json", "--no-wazuh", "--remediate", "--confirm"])
    assert res.stderr.count("can tip off an intruder") == 1
    dry = split_runner.invoke(main, ["scan", "--json", "--no-wazuh", "--remediate"])
    assert "tip off" not in dry.stderr  # a dry run changes nothing
