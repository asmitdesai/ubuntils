from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Header, Static, TabbedContent, TabPane

from ubuntils.detectors.finding import Finding
from ubuntils.timeline.builder import TimelineEvent
from ubuntils.tui.findings_panel import FindingsPanel
from ubuntils.tui.stats_panel import StatsPanel
from ubuntils.tui.summary_screen import _build_summary
from ubuntils.tui.timeline_panel import TimelinePanel


class ResultsScreen(Screen):
    BINDINGS = [
        Binding("1", "show('summary')", "Summary"),
        Binding("2", "show('findings')", "Findings"),
        Binding("3", "show('timeline')", "Timeline"),
        Binding("4", "show('stats')", "Stats"),
        Binding("q", "quit_app", "Quit"),
    ]

    DEFAULT_CSS = """
    ResultsScreen TabPane {
        height: 1fr;
        padding: 0;
    }
    ResultsScreen #summary-body {
        margin: 1 2;
    }
    """

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
        with TabbedContent(initial="summary"):
            with TabPane("Summary", id="summary"):
                yield Static(
                    Text(_build_summary(self._findings, self._timeline, self._stats)),
                    id="summary-body",
                )
            with TabPane("Findings", id="findings"):
                yield FindingsPanel(self._findings)
            with TabPane("Timeline", id="timeline"):
                yield TimelinePanel(self._timeline)
            with TabPane("Stats", id="stats"):
                yield StatsPanel(self._stats)
        yield Footer()

    def action_show(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id

    def action_quit_app(self) -> None:
        self.app.exit()
