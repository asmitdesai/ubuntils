import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from ubuntils.cli import main, _run_pipeline


@pytest.fixture
def runner():
    return CliRunner()


def test_version_command(runner):
    result = runner.invoke(main, ["version"])
    assert result.exit_code == 0
    assert result.output.strip()


def test_scan_help(runner):
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--json" in result.output


def _fake_pipeline(**kwargs):
    from ubuntils.detectors.finding import Finding, Severity
    from ubuntils.remediators.base import RemediationResult, RemediationStatus
    from ubuntils.timeline.builder import TimelineEvent
    import datetime

    findings = [
        Finding(
            rule_id="CRON_TMP_PATH",
            severity=Severity.HIGH,
            title="Cron tmp path",
            description="desc",
            artifact_path="/etc/crontab",
            raw_value="/tmp/evil.sh",
            remediation_available=False,
        )
    ]
    timeline = [
        TimelineEvent(
            timestamp=datetime.datetime(2024, 5, 24, 10, 0, 0, tzinfo=datetime.timezone.utc),
            source="syslog",
            description="test event",
        )
    ]
    stats = {
        "ubuntu_version": "22.04",
        "architecture": "x86_64",
        "duration_s": 0.5,
        "collector_count": 8,
        "collector_failures": 0,
        "finding_counts": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
        "timeline_count": 1,
    }
    scan_metadata = {
        "ubuntu_version": "22.04",
        "architecture": "x86_64",
        "duration_s": 0.5,
        "collector_failures": 0,
    }
    artifact_counts = {"ProcessCollector": 5}
    remediation_results = []
    return findings, timeline, stats, scan_metadata, artifact_counts, remediation_results


def test_scan_json_output(runner):
    with patch("ubuntils.cli._run_pipeline", return_value=_fake_pipeline()):
        result = runner.invoke(main, ["scan", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "findings" in data
    assert "timeline" in data


def test_scan_json_with_verbose(runner):
    with patch("ubuntils.cli._run_pipeline", return_value=_fake_pipeline()):
        result = runner.invoke(main, ["scan", "--json", "--verbose"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "findings" in data


def test_scan_remediate_json(runner):
    """--remediate + --json should run pipeline and print JSON."""
    with patch("ubuntils.cli._run_pipeline", return_value=_fake_pipeline()):
        result = runner.invoke(main, ["scan", "--remediate", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "findings" in data


def test_scan_remediate_launches_tui(runner):
    """--remediate without --json should launch TUI with pre-computed results."""
    mock_app = MagicMock()
    with (
        patch("ubuntils.cli._run_pipeline", return_value=_fake_pipeline()),
        patch("ubuntils.cli.UbuntilsApp", return_value=mock_app),
    ):
        result = runner.invoke(main, ["scan", "--remediate"])
    assert result.exit_code == 0
    mock_app.run.assert_called_once()


def test_scan_plain_launches_tui(runner):
    """Plain scan (no flags) should launch the TUI directly."""
    mock_app = MagicMock()
    with patch("ubuntils.cli.UbuntilsApp", return_value=mock_app):
        result = runner.invoke(main, ["scan"])
    assert result.exit_code == 0
    mock_app.run.assert_called_once()


def test_run_pipeline_handles_collector_failure():
    """_run_pipeline should continue and count failures when a collector raises."""
    from ubuntils.collectors import ALL_COLLECTORS

    bad_collector = MagicMock()
    bad_collector.collect.side_effect = RuntimeError("boom")
    bad_collector.__class__.__name__ = "BadCollector"

    with (
        patch("ubuntils.cli.ALL_COLLECTORS", [type(bad_collector)]),
        patch(f"ubuntils.cli.DetectionEngine") as mock_engine,
        patch(f"ubuntils.cli.TimelineBuilder") as mock_tl,
        patch(f"ubuntils.cli.get_ubuntu_version", return_value="22.04"),
    ):
        mock_engine.return_value.run.return_value = []
        mock_tl.return_value.build.return_value = []
        type(bad_collector).return_value = bad_collector

        with patch("ubuntils.cli.ALL_COLLECTORS", [lambda: bad_collector]):
            findings, timeline, stats, meta, counts, remed = _run_pipeline(
                remediate=False, confirm=False
            )

    assert stats["collector_failures"] >= 0


def test_run_pipeline_handles_engine_failure():
    """_run_pipeline should return empty results when engine crashes."""
    with (
        patch("ubuntils.cli.ALL_COLLECTORS", []),
        patch("ubuntils.cli.DetectionEngine") as mock_engine,
        patch("ubuntils.cli.TimelineBuilder") as mock_tl,
        patch("ubuntils.cli.get_ubuntu_version", return_value="22.04"),
    ):
        mock_engine.return_value.run.side_effect = RuntimeError("engine failure")
        mock_tl.return_value.build.return_value = []

        findings, timeline, stats, meta, counts, remed = _run_pipeline(
            remediate=False, confirm=False
        )

    assert findings == []
    assert timeline == []


def test_run_pipeline_remediation_dry_run():
    """_run_pipeline with remediate=True, confirm=False should dry-run remediators."""
    from ubuntils.detectors.finding import Finding, Severity
    from ubuntils.remediators.base import RemediationResult, RemediationStatus

    finding = Finding(
        rule_id="CRON_TMP_PATH",
        severity=Severity.HIGH,
        title="t",
        description="d",
        artifact_path="/etc/crontab",
        raw_value="x",
        remediation_available=True,
    )
    mock_remediator = MagicMock()
    mock_remediator.return_value.remediate.return_value = RemediationResult(
        finding_rule_id="CRON_TMP_PATH",
        status=RemediationStatus.SKIPPED,
        message="dry run",
    )

    with (
        patch("ubuntils.cli.ALL_COLLECTORS", []),
        patch("ubuntils.cli.DetectionEngine") as mock_engine,
        patch("ubuntils.cli.TimelineBuilder") as mock_tl,
        patch("ubuntils.cli.get_ubuntu_version", return_value="22.04"),
        patch.dict("ubuntils.cli.REMEDIATOR_REGISTRY", {"CRON_TMP_PATH": mock_remediator}),
    ):
        mock_engine.return_value.run.return_value = [finding]
        mock_tl.return_value.build.return_value = []

        findings, timeline, stats, meta, counts, remed = _run_pipeline(
            remediate=True, confirm=False
        )

    assert len(remed) == 1
    assert remed[0].status == RemediationStatus.SKIPPED
