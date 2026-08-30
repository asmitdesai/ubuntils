import datetime
import platform

import pytest

from ubuntils.detectors.finding import Finding, Severity
from ubuntils.timeline.builder import TimelineEvent
from ubuntils.tui.findings_panel import format_detail, sort_findings
from ubuntils.tui.stats_panel import format_stats


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(rule_id="CRON_TMP_PATH", severity=Severity.HIGH, description="desc",
             artifact_path="/etc/cron.d/evil", raw_value="bad line",
             remediation_available=True, remediation_description=None):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title="Test",
        description=description,
        artifact_path=artifact_path,
        raw_value=raw_value,
        remediation_available=remediation_available,
        remediation_description=remediation_description,
    )


def _stats(ubuntu_version="Ubuntu 22.04.3 LTS", architecture="x86_64",
           duration_s=2.4, collector_count=8, collector_failures=0,
           high=2, medium=1, low=1, timeline_count=47):
    return {
        "ubuntu_version": ubuntu_version,
        "architecture": architecture,
        "duration_s": duration_s,
        "collector_count": collector_count,
        "collector_failures": collector_failures,
        "finding_counts": {"HIGH": high, "MEDIUM": medium, "LOW": low},
        "timeline_count": timeline_count,
    }


# ---------------------------------------------------------------------------
# sort_findings
# ---------------------------------------------------------------------------

def test_sort_findings_high_before_medium_before_low():
    findings = [
        _finding("A", Severity.LOW),
        _finding("B", Severity.HIGH),
        _finding("C", Severity.MEDIUM),
    ]
    result = sort_findings(findings)
    assert result[0].severity == Severity.HIGH
    assert result[1].severity == Severity.MEDIUM
    assert result[2].severity == Severity.LOW


def test_sort_findings_empty_list():
    assert sort_findings([]) == []


def test_sort_findings_all_same_severity_preserves_input_order():
    findings = [_finding("A", Severity.HIGH), _finding("B", Severity.HIGH)]
    result = sort_findings(findings)
    assert [f.rule_id for f in result] == ["A", "B"]


# ---------------------------------------------------------------------------
# format_detail
# ---------------------------------------------------------------------------

def test_format_detail_includes_description_path_raw():
    f = _finding(
        description="A cron job runs from /tmp",
        artifact_path="/etc/cron.d/evil",
        raw_value="* * * * * root /tmp/evil.sh",
        remediation_available=True,
        remediation_description="Remove the cron entry",
    )
    detail = format_detail(f)
    assert "A cron job runs from /tmp" in detail
    assert "/etc/cron.d/evil" in detail
    assert "* * * * * root /tmp/evil.sh" in detail
    assert "Remove the cron entry" in detail


def test_format_detail_no_remediation_description():
    f = _finding(remediation_available=True, remediation_description=None)
    detail = format_detail(f)
    assert "available" in detail.lower()


def test_format_detail_remediation_not_available():
    f = _finding(remediation_available=False)
    detail = format_detail(f)
    assert "not available" in detail.lower()


# ---------------------------------------------------------------------------
# format_stats
# ---------------------------------------------------------------------------

def test_format_stats_all_fields_present():
    text = format_stats(_stats())
    assert "Ubuntu 22.04.3 LTS" in text
    assert "x86_64" in text
    assert "2.4s" in text
    assert "8 (0 failed)" in text
    assert "2 HIGH" in text
    assert "1 MEDIUM" in text
    assert "1 LOW" in text
    assert "47" in text


def test_format_stats_nonzero_failures():
    text = format_stats(_stats(collector_failures=2))
    assert "2 failed" in text


# ---------------------------------------------------------------------------
# StatsPanel widget
# ---------------------------------------------------------------------------

from textual.app import App, ComposeResult
from textual.widgets import Label, ListView, Static

from ubuntils.tui.stats_panel import StatsPanel


# ---------------------------------------------------------------------------
# FindingsPanel widget
# ---------------------------------------------------------------------------

from ubuntils.tui.findings_panel import FindingsPanel


def _findings_fixture():
    return [
        _finding("LOW_RULE", Severity.LOW, description="Low severity finding",
                 artifact_path="/home/alice/.bashrc", raw_value="export PATH=$PATH:/tmp"),
        _finding("HIGH_RULE", Severity.HIGH, description="High severity finding",
                 artifact_path="/etc/cron.d/evil", raw_value="* * * * * root /tmp/evil.sh",
                 remediation_description="Remove the cron entry"),
        _finding("MED_RULE", Severity.MEDIUM, description="Medium severity finding",
                 artifact_path="/home/alice/.ssh/authorized_keys",
                 raw_value="ssh-rsa AAAA evil"),
    ]


async def test_findings_panel_list_count_matches_findings():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(_findings_fixture())

    async with _App().run_test() as pilot:
        await pilot.pause()
        lv = pilot.app.query_one(ListView)
        assert len(lv.children) == 3


async def test_findings_panel_first_row_is_high():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(_findings_fixture())

    async with _App().run_test() as pilot:
        await pilot.pause()
        lv = pilot.app.query_one(ListView)
        first_item = lv.children[0]
        first_label_text = first_item.query_one(Label).content
        assert "HIGH" in first_label_text


async def test_findings_panel_detail_pane_empty_on_mount():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(_findings_fixture())

    async with _App().run_test() as pilot:
        await pilot.pause()
        detail = str(pilot.app.query_one("#detail", Static).content)
        assert "Select a finding" in detail


from ubuntils.tui.findings_panel import FindingDetail


async def test_findings_panel_enter_shows_detail():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(_findings_fixture())

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        detail = str(pilot.app.query_one(FindingDetail).content)
        assert "High severity finding" in detail


async def test_findings_panel_enter_shows_r_hint_for_remediable():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(_findings_fixture())

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        detail = str(pilot.app.query_one(FindingDetail).content)
        assert "R: remediate" in detail


async def test_findings_panel_enter_shows_no_remediation_for_flag_only():
    flag_only = _finding(
        rule_id="SHELL_RC_MODIFICATION",
        severity=Severity.LOW,
        description="Shell rc modified",
        remediation_available=False,
    )

    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel([flag_only])

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        detail = str(pilot.app.query_one(FindingDetail).content)
        assert "No automated remediation available" in detail


async def test_findings_panel_mark_fixed_updates_list_item():
    findings = _findings_fixture()
    high_finding = next(f for f in findings if f.severity == Severity.HIGH)
    result = RemediationResult(
        finding_rule_id=high_finding.rule_id,
        status=RemediationStatus.SUCCESS,
        message="Done",
        backup_path="/var/backups/ubuntils/20260526/cron",
    )

    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(findings)

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        panel = pilot.app.query_one(FindingsPanel)
        panel.mark_fixed(high_finding, result)
        await pilot.pause()
        lv = pilot.app.query_one(ListView)
        first_label = str(lv.children[0].query_one(Label).content)
        assert "fixed" in first_label.lower()


async def test_findings_panel_mark_fixed_shows_backup_in_detail():
    findings = _findings_fixture()
    high_finding = next(f for f in findings if f.severity == Severity.HIGH)
    result = RemediationResult(
        finding_rule_id=high_finding.rule_id,
        status=RemediationStatus.SUCCESS,
        message="Done",
        backup_path="/var/backups/ubuntils/20260526/cron",
        rollback_command="sudo cp /var/backups/ubuntils/20260526/cron /etc/cron.d/evil",
    )

    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(findings)

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        panel = pilot.app.query_one(FindingsPanel)
        panel.mark_fixed(high_finding, result)
        await pilot.pause()
        detail = str(pilot.app.query_one(FindingDetail).content)
        assert "Remediated" in detail
        assert "/var/backups/ubuntils/20260526/cron" in detail


async def test_findings_panel_mark_fixed_failed_shows_error():
    findings = _findings_fixture()
    high_finding = next(f for f in findings if f.severity == Severity.HIGH)
    result = RemediationResult(
        finding_rule_id=high_finding.rule_id,
        status=RemediationStatus.FAILED,
        message="Permission denied",
    )

    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(findings)

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        panel = pilot.app.query_one(FindingsPanel)
        panel.mark_fixed(high_finding, result)
        await pilot.pause()
        detail = str(pilot.app.query_one(FindingDetail).content)
        assert "Failed" in detail
        assert "Permission denied" in detail


# ---------------------------------------------------------------------------
# TimelinePanel widget
# ---------------------------------------------------------------------------

from textual.widgets import ListView

from ubuntils.tui.timeline_panel import TimelinePanel


def _event(source="syslog", description="test event", hour=14, minute=22, second=0):
    ts = datetime.datetime(2024, 1, 15, hour, minute, second, tzinfo=datetime.timezone.utc)
    return TimelineEvent(timestamp=ts, source=source, description=description)


async def test_timeline_panel_row_count_matches_events():
    events = [_event(description=f"event {i}") for i in range(5)]

    class _App(App):
        def compose(self) -> ComposeResult:
            yield TimelinePanel(events)

    async with _App().run_test() as pilot:
        await pilot.pause()
        lv = pilot.app.query_one(ListView)
        assert len(lv.children) == 5


async def test_timeline_panel_empty_events():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield TimelinePanel([])

    async with _App().run_test() as pilot:
        await pilot.pause()
        lv = pilot.app.query_one(ListView)
        assert len(lv.children) == 0


async def test_stats_panel_renders_all_fields():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield StatsPanel(_stats())

    async with _App().run_test() as pilot:
        await pilot.pause()
        rendered = pilot.app.query_one(Static).content
        assert "Ubuntu 22.04.3 LTS" in rendered
        assert "x86_64" in rendered
        assert "2.4s" in rendered


# ---------------------------------------------------------------------------
# Textual messages
# ---------------------------------------------------------------------------

from ubuntils.tui.app import CollectorProgress, ScanComplete, UbuntilsApp
from ubuntils.tui.scan_screen import ScanScreen


def test_collector_progress_fields():
    msg = CollectorProgress(name="CronCollector", index=3, total=8)
    assert msg.name == "CronCollector"
    assert msg.index == 3
    assert msg.total == 8
    assert msg.success is True


def test_collector_progress_failed():
    msg = CollectorProgress(name="CronCollector", index=3, total=8, success=False)
    assert msg.success is False


def test_scan_complete_fields():
    msg = ScanComplete(findings=[], timeline=[], stats={"key": "val"})
    assert msg.findings == []
    assert msg.timeline == []
    assert msg.stats == {"key": "val"}


# ---------------------------------------------------------------------------
# ScanScreen
# ---------------------------------------------------------------------------


async def test_scan_screen_renders():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield ScanScreen()

    async with _App().run_test() as pilot:
        await pilot.pause()
        assert pilot.app.query_one(ScanScreen) is not None



async def test_scan_screen_lists_all_collectors_on_mount():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield ScanScreen(collector_names=["ProcessCollector", "CronCollector", "SSHCollector"])

    async with _App().run_test() as pilot:
        await pilot.pause()
        body = str(pilot.app.query_one("#checklist", Static).content)
        assert "Process" in body
        assert "Cron" in body
        assert "SSH" in body


async def test_scan_screen_mark_done_shows_check():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield ScanScreen(collector_names=["ProcessCollector", "CronCollector"])

    async with _App().run_test() as pilot:
        await pilot.pause()
        screen = pilot.app.query_one(ScanScreen)
        screen.mark("ProcessCollector", success=True)
        await pilot.pause()
        body = str(pilot.app.query_one("#checklist", Static).content)
        assert "✓" in body


async def test_scan_screen_mark_failed_shows_cross():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield ScanScreen(collector_names=["ProcessCollector", "CronCollector"])

    async with _App().run_test() as pilot:
        await pilot.pause()
        screen = pilot.app.query_one(ScanScreen)
        screen.mark("CronCollector", success=False)
        await pilot.pause()
        body = str(pilot.app.query_one("#checklist", Static).content)
        assert "✗" in body



# ---------------------------------------------------------------------------
# UbuntilsApp — full app
# ---------------------------------------------------------------------------



async def test_ubuntils_app_q_exits():
    def _override():
        return ([], [], _stats())

    async with UbuntilsApp(_scan_override=_override).run_test() as pilot:
        await pilot.pause(delay=0.5)
        await pilot.press("q")


# ---------------------------------------------------------------------------
# Package exports
# ---------------------------------------------------------------------------


def test_ubuntils_app_importable_from_tui_package():
    from ubuntils.tui import UbuntilsApp as _UbuntilsApp
    assert _UbuntilsApp is UbuntilsApp


def test_scan_screen_importable_from_tui_package():
    from ubuntils.tui import ScanScreen as _ScanScreen
    assert _ScanScreen is ScanScreen


def test_results_screen_importable_from_tui_package():
    from ubuntils.tui import ResultsScreen as _ResultsScreen
    assert _ResultsScreen is ResultsScreen


def test_confirm_modal_importable_from_tui_package():
    from ubuntils.tui import ConfirmModal as _ConfirmModal
    assert _ConfirmModal is ConfirmModal


# ---------------------------------------------------------------------------
# ResultsScreen — tabbed navigation
# ---------------------------------------------------------------------------

from ubuntils.tui.results_screen import ResultsScreen
from textual.widgets import TabbedContent

from ubuntils.tui.confirm_modal import ConfirmModal, RemediateRequest


async def test_confirm_modal_renders_rule_id():
    finding = _finding(rule_id="CRON_TMP_PATH", remediation_description="Remove cron entry")

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ConfirmModal(finding))

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        content = str(pilot.app.screen.query_one("#rule-id", Static).content)
        assert "CRON_TMP_PATH" in content


async def test_confirm_modal_renders_fix_description():
    finding = _finding(rule_id="CRON_TMP_PATH", remediation_description="Remove the cron entry")

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ConfirmModal(finding))

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        content = str(pilot.app.screen.query_one("#fix-desc", Static).content)
        assert "Remove the cron entry" in content


async def test_confirm_modal_y_calls_callback_with_true():
    finding = _finding(rule_id="CRON_TMP_PATH")
    results: list[bool] = []

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ConfirmModal(finding), results.append)

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("y")
        await pilot.pause()
        assert results == [True]


async def test_confirm_modal_esc_calls_callback_with_false():
    finding = _finding()
    results: list[bool] = []

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ConfirmModal(finding), results.append)

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        assert results == [False]


async def test_results_screen_default_tab_is_summary():
    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ResultsScreen(findings=[], timeline=[], stats=_stats()))

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        tc = pilot.app.screen.query_one(TabbedContent)
        assert tc.active == "summary"


async def test_results_screen_summary_shows_clean_message():
    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ResultsScreen(findings=[], timeline=[], stats=_stats(high=0, medium=0, low=0)))

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        body = str(pilot.app.screen.query_one("#summary-body", Static).content)
        assert "System appears clean" in body


async def test_results_screen_key_3_switches_to_timeline():
    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ResultsScreen(findings=[], timeline=[], stats=_stats()))

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("3")
        await pilot.pause()
        tc = pilot.app.screen.query_one(TabbedContent)
        assert tc.active == "timeline"


async def test_results_screen_panes_fill_height():
    events = [_event(description=f"e{i}") for i in range(10)]

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ResultsScreen(findings=[], timeline=events, stats=_stats()))

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("3")
        await pilot.pause()
        tl = pilot.app.screen.query_one(TimelinePanel)
        assert tl.region.height > 1, f"timeline pane collapsed: {tl.region}"


# ---------------------------------------------------------------------------
# ResultsScreen — remediation worker
# ---------------------------------------------------------------------------

from unittest.mock import MagicMock, patch

from ubuntils.detectors.finding import RemediationResult, RemediationStatus
from ubuntils.tui.results_screen import RemediationDone


async def test_remediate_request_triggers_worker_and_posts_done_on_success():
    finding = _finding(rule_id="CRON_TMP_PATH")
    mock_result = RemediationResult(
        finding_rule_id="CRON_TMP_PATH",
        status=RemediationStatus.SUCCESS,
        message="Done",
        backup_path="/var/backups/ubuntils/20260526/cron",
        rollback_command="sudo cp /var/backups/ubuntils/20260526/cron /var/spool/cron/crontabs/parallels",
    )
    received: list[RemediationDone] = []

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ResultsScreen(findings=[finding], timeline=[], stats=_stats()))

        def on_remediation_done(self, msg: RemediationDone) -> None:
            received.append(msg)

    with patch("ubuntils.tui.results_screen.REMEDIATOR_REGISTRY") as mock_reg:
        mock_remediator = MagicMock()
        mock_remediator.remediate.return_value = mock_result
        mock_reg.get.return_value = mock_remediator

        async with _App().run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            pilot.app.screen.post_message(RemediateRequest(finding))
            await pilot.pause(delay=0.5)
            assert len(received) == 1
            assert received[0].result.status == RemediationStatus.SUCCESS
            assert received[0].result.backup_path == "/var/backups/ubuntils/20260526/cron"


async def test_remediate_request_posts_failed_when_no_remediator():
    finding = _finding(rule_id="UNKNOWN_RULE")
    received: list[RemediationDone] = []

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ResultsScreen(findings=[finding], timeline=[], stats=_stats()))

        def on_remediation_done(self, msg: RemediationDone) -> None:
            received.append(msg)

    with patch("ubuntils.tui.results_screen.REMEDIATOR_REGISTRY") as mock_reg:
        mock_reg.get.return_value = None

        async with _App().run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            pilot.app.screen.post_message(RemediateRequest(finding))
            await pilot.pause(delay=0.5)
            assert len(received) == 1
            assert received[0].result.status == RemediationStatus.FAILED


# ---------------------------------------------------------------------------
# Full UbuntilsApp end-to-end (scan -> results -> tab navigation)
# ---------------------------------------------------------------------------

from ubuntils.tui.app import UbuntilsApp
from ubuntils.tui.results_screen import ResultsScreen as _ResultsScreen
from ubuntils.tui.scan_screen import ScanScreen as _ScanScreen


def _override_factory():
    findings = _findings_fixture()
    timeline = [
        TimelineEvent(
            timestamp=datetime.datetime(2024, 5, 24, 10, 0, 0, tzinfo=datetime.timezone.utc),
            source="syslog", description="cron job ran",
        )
    ]
    def _ov():
        return (findings, timeline, _stats())
    return _ov


async def test_app_scan_transitions_to_results():
    app = UbuntilsApp(_scan_override=_override_factory())
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await pilot.pause(delay=0.3)
        assert isinstance(pilot.app.screen, _ResultsScreen)


async def test_app_tab_navigation_keys_do_not_crash():
    app = UbuntilsApp(_scan_override=_override_factory())
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await pilot.pause(delay=0.3)
        for key in ("2", "3", "4", "1"):
            await pilot.press(key)
            await pilot.pause()
        assert isinstance(pilot.app.screen, _ResultsScreen)


async def test_app_findings_tab_enter_and_remediate_modal():
    app = UbuntilsApp(_scan_override=_override_factory())
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await pilot.pause(delay=0.3)
        await pilot.press("2")          # Findings tab
        await pilot.pause()
        await pilot.press("enter")      # expand detail
        await pilot.pause()
        await pilot.press("r")          # open confirm modal
        await pilot.pause()
        await pilot.press("escape")     # cancel modal
        await pilot.pause()
        assert isinstance(pilot.app.screen, _ResultsScreen)


async def test_app_applies_allowlist_in_own_scan():
    """allowlist passed to UbuntilsApp must filter the app's own scan findings."""
    from ubuntils.utils.config import Allowlist
    al = Allowlist(rules=["USER_UID_ZERO"])
    captured = {}

    app = UbuntilsApp(allowlist=al)

    def fake_engine_run(self, artifacts):
        # engine receives the allowlist; emulate a UID-0 finding being suppressed
        from ubuntils.detectors.engine import DetectionEngine
        captured["allowlist"] = self.allowlist
        return self.allowlist.filter([
            _finding(rule_id="USER_UID_ZERO", remediation_available=False),
            _finding(rule_id="CRON_TMP_PATH"),
        ])

    with (
        patch("ubuntils.tui.app.ALL_COLLECTORS", []),
        patch("ubuntils.detectors.engine.DetectionEngine.run", fake_engine_run),
        patch("ubuntils.tui.app.TimelineBuilder") as tb,
    ):
        tb.return_value.build.return_value = []
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.pause(delay=0.3)
            screen = pilot.app.screen
            assert isinstance(screen, _ResultsScreen)
            assert captured["allowlist"] is al
            assert all(f.rule_id != "USER_UID_ZERO" for f in screen._findings)


async def test_app_applies_timeline_corroboration_signal_and_surfaces_baseline_suppression():
    """UbuntilsApp._run_scan must mirror cli.py's _run_pipeline: apply the
    timeline_corroboration signal after correlate(), and surface
    suppressed_by_baseline into stats (not silently drop it)."""
    from ubuntils.utils.baseline import Baseline

    baseline = Baseline(entries=[{"rule_id": "CRON_TMP_PATH", "fingerprint": "bad line"}])
    app = UbuntilsApp(baseline=baseline)

    def fake_engine_run(self, artifacts):
        self.baseline_suppressed_findings = []
        kept, self.baseline_suppressed_findings = self.baseline.filter([
            _finding(rule_id="USER_UID_ZERO", remediation_available=False),
            _finding(rule_id="CRON_TMP_PATH"),
        ])
        self.suppressed_by_baseline = len(self.baseline_suppressed_findings)
        return kept

    def fake_correlate(findings, timeline):
        for f in findings:
            if f.rule_id == "USER_UID_ZERO":
                f.related_events.append("sentinel")

    with (
        patch("ubuntils.tui.app.ALL_COLLECTORS", []),
        patch("ubuntils.detectors.engine.DetectionEngine.run", fake_engine_run),
        patch("ubuntils.tui.app.correlate", fake_correlate),
        patch("ubuntils.tui.app.TimelineBuilder") as tb,
    ):
        tb.return_value.build.return_value = []
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.pause(delay=0.3)
            screen = pilot.app.screen
            assert isinstance(screen, _ResultsScreen)
            uid_zero = next(f for f in screen._findings if f.rule_id == "USER_UID_ZERO")
            assert any(s["name"] == "timeline_corroboration" for s in uid_zero.signals)
            assert not any(f.rule_id == "CRON_TMP_PATH" for f in screen._findings)
            assert screen._stats.get("suppressed_by_baseline") == 1


def test_detail_text_includes_guided_remediation_and_related_events():
    import datetime
    from ubuntils.detectors.finding import Finding, Severity
    from ubuntils.timeline.builder import TimelineEvent
    from ubuntils.tui.findings_panel import _detail_text

    event = TimelineEvent(
        timestamp=datetime.datetime(2026, 6, 1, 12, 0, 0, tzinfo=datetime.timezone.utc),
        source="journald", description="sshd: Accepted publickey for alice",
    )
    finding = Finding(
        rule_id="PROCESS_MASQUERADE", severity=Severity.MEDIUM, title="t",
        description="d", artifact_path="/proc/99/exe", raw_value="/tmp/sshd",
        remediation_available=False, guided_remediation="kill -9 99",
        related_events=[event],
    )
    text = _detail_text(finding)
    assert "Guided remediation:" in text
    assert "kill -9 99" in text
    assert "Related events:" in text
    assert "Accepted publickey" in text


def _finding_with_signals():
    f = Finding(
        rule_id="SSH_UNAUTHORIZED_KEY", severity=Severity.MEDIUM, title="t", description="d",
        artifact_path="/x", raw_value="v", remediation_available=False,
    )
    from ubuntils.detectors.scoring import apply_signal
    apply_signal(f, "content_match", 30, "dangerous option present")
    return f


def test_format_detail_includes_confidence_band():
    text = format_detail(_finding_with_signals())
    assert "HIGH" in text


def test_findings_list_row_shows_confidence_band(tmp_path):
    # FindingsPanel.compose() builds one Label per finding — assert the
    # confidence band string appears in the rendered label text.
    from ubuntils.tui.findings_panel import FindingsPanel
    panel = FindingsPanel([_finding_with_signals()])
    # compose() is a generator; materialize it without mounting a full app.
    items = list(panel.compose())
    list_view = items[0]
    # Positional children passed to a Textual widget land in
    # `_pending_children` until the widget is mounted into a running app;
    # `.children` stays empty until then, so inspect the pending list instead.
    list_item = list_view._pending_children[0]
    label = list_item._pending_children[0]
    label_text = str(label.render())
    assert "HIGH" in label_text
