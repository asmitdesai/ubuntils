import datetime as dt
import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from ubuntils.cli import main, _run_pipeline
from ubuntils.utils.since_parser import parse_since


@pytest.fixture(autouse=True)
def mock_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)


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


def test_scan_json_includes_report_hash(runner):
    with patch("ubuntils.cli._run_pipeline", return_value=_fake_pipeline()):
        result = runner.invoke(main, ["scan", "--json"])
    data = json.loads(result.output)
    assert "report_sha256" in data
    assert len(data["report_sha256"]) == 64


def test_scan_output_writes_file(runner, tmp_path):
    out = tmp_path / "report.json"
    with patch("ubuntils.cli._run_pipeline", return_value=_fake_pipeline()):
        result = runner.invoke(main, ["scan", "--output", str(out)])
    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert "findings" in data
    assert "report_sha256" in data


def test_scan_config_invalid_errors(runner, tmp_path):
    cfg = tmp_path / "bad.yaml"
    cfg.write_text("- not a mapping\n")
    with patch("ubuntils.cli._run_pipeline", return_value=_fake_pipeline()):
        result = runner.invoke(main, ["scan", "--json", "--config", str(cfg)])
    assert result.exit_code != 0
    assert "Invalid config" in result.output


def test_scan_since_invalid_errors(runner):
    with patch("ubuntils.cli._run_pipeline", return_value=_fake_pipeline()):
        result = runner.invoke(main, ["scan", "--json", "--since", "garbage"])
    assert result.exit_code != 0
    assert "Invalid --since" in result.output


def test_pipeline_since_filters_timeline():
    from ubuntils.collectors import ALL_COLLECTORS
    from ubuntils.timeline.builder import TimelineEvent

    old = TimelineEvent(
        timestamp=dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc),
        source="syslog", description="ancient",
    )
    recent = TimelineEvent(
        timestamp=dt.datetime(2099, 1, 1, tzinfo=dt.timezone.utc),
        source="syslog", description="future",
    )
    cutoff = dt.datetime(2050, 1, 1, tzinfo=dt.timezone.utc)
    with (
        patch("ubuntils.cli.ALL_COLLECTORS", []),
        patch("ubuntils.cli.DetectionEngine") as eng,
        patch("ubuntils.cli.TimelineBuilder") as tb,
    ):
        eng.return_value.run.return_value = []
        tb.return_value.build.return_value = [old, recent]
        _, timeline, *_ = _run_pipeline(remediate=False, confirm=False, since=cutoff)
    assert [e.description for e in timeline] == ["future"]


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


def test_parse_since_hours():
    before = dt.datetime.now(tz=dt.timezone.utc)
    result = parse_since("24h")
    expected = before - dt.timedelta(hours=24)
    assert abs((result - expected).total_seconds()) < 2
    assert result.tzinfo == dt.timezone.utc


def test_parse_since_days():
    result = parse_since("7d")
    expected = dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(days=7)
    assert abs((result - expected).total_seconds()) < 2
    assert result.tzinfo == dt.timezone.utc


def test_parse_since_minutes():
    result = parse_since("30m")
    assert result.tzinfo == dt.timezone.utc


def test_parse_since_weeks():
    result = parse_since("2w")
    expected = dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(weeks=2)
    assert abs((result - expected).total_seconds()) < 2


def test_parse_since_absolute_date():
    result = parse_since("2026-05-20")
    assert result.year == 2026
    assert result.month == 5
    assert result.day == 20
    assert result.tzinfo is not None


def test_parse_since_absolute_datetime():
    result = parse_since("2026-05-20 14:00")
    assert result.hour == 14
    assert result.tzinfo is not None


def test_parse_since_invalid_raises():
    with pytest.raises(ValueError, match="Invalid --since"):
        parse_since("foo")
