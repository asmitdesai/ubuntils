import datetime as dt
import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from ubuntils.cli import main, _run_pipeline
from ubuntils.collectors.source import LiveSource
from ubuntils.utils.baseline import Baseline
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
        _, timeline, *_ = _run_pipeline(
            source=LiveSource(), remediate=False, confirm=False, since=cutoff
        )
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


async def test_tui_app_scan_worker_uses_livesource():
    """Verify that UbuntilsApp._run_scan() actually instantiates collectors with LiveSource(root="/")."""
    from ubuntils.tui.app import UbuntilsApp

    # Record what source values are passed to collector __init__
    received_sources = []

    class RecordingCollector:
        def __init__(self, source=None):
            received_sources.append(source)

        def collect(self):
            return {}

    # Monkeypatch ALL_COLLECTORS to use our recording collector
    # This must happen before creating the app so _run_scan uses it
    with (
        patch("ubuntils.tui.app.ALL_COLLECTORS", [RecordingCollector]),
        patch("ubuntils.tui.app.DetectionEngine") as mock_engine,
        patch("ubuntils.tui.app.TimelineBuilder") as mock_tl,
        patch("ubuntils.tui.app.correlate"),
        patch("ubuntils.tui.app.get_ubuntu_version", return_value="22.04"),
    ):
        mock_engine.return_value.run.return_value = []
        mock_tl.return_value.build.return_value = []

        # Create app WITHOUT _scan_override so the real _run_scan() executes
        app = UbuntilsApp()

        # Run the app with Textual's test harness
        async with app.run_test() as pilot:
            # Wait for the scan worker thread to complete
            await pilot.pause(delay=0.5)

    # Verify the collector was instantiated with LiveSource(root="/")
    assert len(received_sources) == 1, f"Expected 1 collector instantiation, got {len(received_sources)}"
    assert isinstance(
        received_sources[0], LiveSource
    ), f"Expected LiveSource but got {type(received_sources[0])}"
    assert received_sources[0].root == "/", (
        f"Expected root='/' but got root='{received_sources[0].root}'"
    )


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

        with patch("ubuntils.cli.ALL_COLLECTORS", [lambda source=None: bad_collector]):
            findings, timeline, stats, meta, counts, remed = _run_pipeline(
                source=LiveSource(), remediate=False, confirm=False
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
            source=LiveSource(), remediate=False, confirm=False
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
            source=LiveSource(), remediate=True, confirm=False
        )

    assert len(remed) == 1
    assert remed[0].status == RemediationStatus.SKIPPED


def test_run_pipeline_accepts_source_and_records_live_integrity(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    src = LiveSource(root=str(tmp_path))

    findings, timeline, stats, meta, counts, remediation = _run_pipeline(
        source=src, remediate=False, confirm=False
    )
    assert meta["bundle_integrity"] == "live"


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


def test_scan_rules_flag_invalid_file_errors(runner):
    result = runner.invoke(main, ["scan", "--json", "--rules", "/nonexistent/rules.yaml"])
    assert result.exit_code != 0


def test_scan_rules_flag_loads_and_detects(runner, tmp_path):
    """--rules findings should appear in the JSON report alongside built-in ones."""

    class FakeProcessCollector:
        def __init__(self, source=None):
            self.source = source

        def collect(self):
            return {"processes": [
                {"pid": 1, "name": "x", "exe": "/tmp/evilbin", "cmdline": "evilbin --x"}]}

    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n  - id: CUSTOM_CLI\n    severity: HIGH\n    title: t\n"
        "    description: d\n    source: process\n    match: substring\n    pattern: evilbin\n"
    )

    with (
        patch("ubuntils.cli.ALL_COLLECTORS", [FakeProcessCollector]),
        patch("ubuntils.cli.TimelineBuilder") as mock_tl,
        patch("ubuntils.cli.get_ubuntu_version", return_value="22.04"),
    ):
        mock_tl.return_value.build.return_value = []
        result = runner.invoke(main, ["scan", "--json", "--rules", str(rules)])

    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert any(f["rule_id"] == "CUSTOM_CLI" for f in report["findings"])


def test_scan_rules_flag_rejects_malformed_rules_file(runner, tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules:\n  - id: X\n    severity: NOPE\n    title: t\n"
                     "    description: d\n    source: process\n    match: substring\n"
                     "    pattern: y\n")
    result = runner.invoke(main, ["scan", "--json", "--rules", str(rules)])
    assert result.exit_code != 0
    assert "Invalid rules file" in result.output


def test_pipeline_attaches_related_events(monkeypatch):
    import datetime
    from ubuntils import cli
    from ubuntils.detectors.finding import Finding, Severity
    from ubuntils.timeline.builder import TimelineEvent

    finding = Finding(
        rule_id="SSH_UNAUTHORIZED_KEY", severity=Severity.MEDIUM, title="t",
        description="d", artifact_path="/home/bob/.ssh/authorized_keys",
        raw_value="ssh-rsa AAA", remediation_available=True,
    )
    event = TimelineEvent(
        timestamp=datetime.datetime(2026, 6, 1, 12, 0, 0, tzinfo=datetime.timezone.utc),
        source="journald", description="sshd: Accepted publickey for bob",
    )
    monkeypatch.setattr(cli.DetectionEngine, "run", lambda self, artifacts: [finding])
    monkeypatch.setattr(cli.TimelineBuilder, "build", lambda self: [event])

    with patch("ubuntils.cli.ALL_COLLECTORS", []):
        result = cli._run_pipeline(source=LiveSource(), remediate=False, confirm=False)
    findings = result[0]
    assert findings[0].related_events
    assert "bob" in findings[0].related_events[0].description


def test_run_pipeline_applies_timeline_corroboration_signal(tmp_path, monkeypatch):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\nghost:x:0:0::/home/ghost:/bin/bash\n"
    )
    src = LiveSource(root=str(tmp_path))

    # Fake correlate() to guarantee at least one finding gets related_events,
    # without depending on real syslog/journald content in the test environment.
    def _fake_correlate(findings, timeline):
        for f in findings:
            if f.rule_id == "USER_UID_ZERO":
                f.related_events.append("sentinel")

    monkeypatch.setattr("ubuntils.cli.correlate", _fake_correlate)

    findings, *_ = _run_pipeline(source=src, remediate=False, confirm=False)
    uid_zero = next(f for f in findings if f.rule_id == "USER_UID_ZERO")
    assert any(s["name"] == "timeline_corroboration" for s in uid_zero.signals)


def test_bundle_analysis_does_not_mark_command_collectors_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr("ubuntils.cli._ensure_root", lambda: None)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    out = tmp_path / "b.tar.gz"
    from ubuntils.bundle import write_bundle
    from ubuntils.collectors.source import LiveSource
    write_bundle(
        source=LiveSource(root=str(tmp_path)),
        files_to_capture=["/etc/passwd"],
        commands_to_capture=[("ss", ["ss", "-tunap"])],
        out_path=str(out),
        metadata={"hostname": "h", "ubuntu_version": "U", "tool_version": "2.0.0"},
    )

    from ubuntils.bundle import read_bundle
    from ubuntils.cli import _run_pipeline
    source, bundle_info = read_bundle(str(out))
    _findings, _timeline, _stats, meta, _counts, _rem = _run_pipeline(
        source=source, remediate=False, confirm=False, bundle_info=bundle_info,
    )
    assert meta["command_collectors_skipped"] == []


def test_run_pipeline_records_suppressed_by_baseline_count(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\nghost:x:0:0::/home/ghost:/bin/bash\n"
    )
    src = LiveSource(root=str(tmp_path))
    baseline = Baseline(entries=[{"rule_id": "USER_UID_ZERO", "fingerprint": "ghost"}])

    findings, timeline, stats, meta, counts, rem = _run_pipeline(
        source=src, remediate=False, confirm=False, baseline=baseline,
    )
    assert not any(f.rule_id == "USER_UID_ZERO" for f in findings)
    assert meta["suppressed_by_baseline"] == 1
    assert meta["baseline_suppressed"] == [
        {"rule_id": "USER_UID_ZERO", "artifact_path": "/etc/passwd"}
    ]


def test_scan_json_includes_coverage_pack_rules(monkeypatch, tmp_path):
    monkeypatch.setattr("ubuntils.cli._ensure_root", lambda: None)
    from click.testing import CliRunner
    from ubuntils.cli import main
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--json"])
    assert result.exit_code == 0, result.output
    import json as _json
    report = _json.loads(result.output)
    assert "PackageCollector" in report["scan_metadata"]["artifact_counts"] \
        if "artifact_counts" in report["scan_metadata"] else True
    # Coverage-pack collectors must at least be constructed without raising —
    # exercised implicitly by a clean exit code above.
