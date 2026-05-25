from __future__ import annotations

import platform
import time

import structlog
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.message import Message
from textual.screen import Screen
from textual.widgets import ContentSwitcher, Footer, Header, Label, ProgressBar, Static

from ubuntils.collectors import ALL_COLLECTORS
from ubuntils.detectors.engine import DetectionEngine
from ubuntils.detectors.finding import Finding, Severity
from ubuntils.timeline.builder import TimelineBuilder, TimelineEvent
from ubuntils.tui.findings_panel import FindingsPanel
from ubuntils.tui.stats_panel import StatsPanel, get_ubuntu_version
from ubuntils.tui.timeline_panel import TimelinePanel

logger = structlog.get_logger()


class CollectorProgress(Message):
    def __init__(self, name: str, index: int, total: int) -> None:
        self.name = name
        self.index = index
        self.total = total
        super().__init__()


class ScanComplete(Message):
    def __init__(
        self,
        findings: list[Finding],
        timeline: list[TimelineEvent],
        stats: dict,
    ) -> None:
        self.findings = findings
        self.timeline = timeline
        self.stats = stats
        super().__init__()


class LoadingScreen(Screen):
    DEFAULT_CSS = """
    LoadingScreen {
        align: center middle;
        layout: vertical;
    }
    LoadingScreen Label {
        margin-bottom: 1;
    }
    LoadingScreen ProgressBar {
        margin-bottom: 1;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._log_lines: list[str] = []

    def compose(self) -> ComposeResult:
        yield Label("Scanning system...", id="status")
        yield ProgressBar(total=8, show_eta=False, id="progress")
        yield Static("", id="checklist")

    def update_progress(self, name: str, index: int, total: int) -> None:
        self.query_one("#progress", ProgressBar).advance(1)
        self._log_lines.append(f"✓ {name}")
        self.query_one("#checklist", Static).update("\n".join(self._log_lines))
        self.query_one("#status", Label).update(
            f"Scanning system... [{index}/{total}]"
        )


class MainScreen(Screen):
    BINDINGS = [
        Binding("1", "switch_to_findings", "Findings"),
        Binding("2", "switch_to_timeline", "Timeline"),
        Binding("3", "switch_to_stats", "Stats"),
        Binding("q", "quit_app", "Quit"),
    ]

    def __init__(
        self,
        findings: list[Finding],
        timeline: list[TimelineEvent],
        stats: dict,
    ) -> None:
        super().__init__()
        self._findings = findings
        self._timeline = timeline
        self._stats = stats

    def compose(self) -> ComposeResult:
        yield Header()
        with ContentSwitcher(initial="findings"):
            yield FindingsPanel(self._findings, id="findings")
            yield TimelinePanel(self._timeline, id="timeline")
            yield StatsPanel(self._stats, id="stats")
        yield Footer()

    def action_switch_to_findings(self) -> None:
        self.query_one(ContentSwitcher).current = "findings"

    def action_switch_to_timeline(self) -> None:
        self.query_one(ContentSwitcher).current = "timeline"

    def action_switch_to_stats(self) -> None:
        self.query_one(ContentSwitcher).current = "stats"

    def action_quit_app(self) -> None:
        self.app.exit()


class UbuntilsApp(App):
    TITLE = "ubuntils"
    BINDINGS = [Binding("q", "quit", "Quit")]

    def __init__(self, verbose: bool = False, _scan_override=None) -> None:
        super().__init__()
        self._verbose = verbose
        self._scan_override = _scan_override

    def on_mount(self) -> None:
        self.push_screen(LoadingScreen())
        self._run_scan()

    @work(thread=True)
    def _run_scan(self) -> None:
        if self._scan_override is not None:
            findings, timeline, stats = self._scan_override()
            self.post_message(ScanComplete(findings=findings, timeline=timeline, stats=stats))
            return

        start = time.monotonic()
        artifacts: dict = {}
        failures = 0
        collectors = [C() for C in ALL_COLLECTORS]

        for i, collector in enumerate(collectors):
            name = type(collector).__name__
            try:
                result = collector.collect()
                artifacts.update(result)
            except Exception as exc:
                logger.error("collector_failed", name=name, error=str(exc))
                failures += 1
            self.post_message(
                CollectorProgress(name=name, index=i + 1, total=len(collectors))
            )

        findings = DetectionEngine().run(artifacts)
        timeline = TimelineBuilder().build()
        duration = time.monotonic() - start

        stats = {
            "ubuntu_version": get_ubuntu_version(),
            "architecture": platform.machine(),
            "duration_s": duration,
            "collector_count": len(collectors),
            "collector_failures": failures,
            "finding_counts": {
                "HIGH": sum(1 for f in findings if f.severity == Severity.HIGH),
                "MEDIUM": sum(1 for f in findings if f.severity == Severity.MEDIUM),
                "LOW": sum(1 for f in findings if f.severity == Severity.LOW),
            },
            "timeline_count": len(timeline),
        }
        self.post_message(
            ScanComplete(findings=findings, timeline=timeline, stats=stats)
        )

    def on_collector_progress(self, message: CollectorProgress) -> None:
        screen = self.screen
        if isinstance(screen, LoadingScreen):
            screen.update_progress(message.name, message.index, message.total)

    def on_scan_complete(self, message: ScanComplete) -> None:
        self.switch_screen(
            MainScreen(
                findings=message.findings,
                timeline=message.timeline,
                stats=message.stats,
            )
        )
