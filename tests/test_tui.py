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


async def test_findings_panel_detail_pane_shows_first_finding_on_mount():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(_findings_fixture())

    async with _App().run_test() as pilot:
        await pilot.pause()
        detail = pilot.app.query_one("#detail", Static).content
        assert "High severity finding" in detail


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


# ---------------------------------------------------------------------------
# ResultsScreen — tabbed navigation
# ---------------------------------------------------------------------------

from ubuntils.tui.results_screen import ResultsScreen
from textual.widgets import TabbedContent


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
