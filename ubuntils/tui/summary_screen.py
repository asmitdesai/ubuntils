from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from ubuntils.detectors.finding import Finding, Severity
from ubuntils.timeline.builder import TimelineEvent

_SEV_BULLET = {Severity.HIGH: "●", Severity.MEDIUM: "○", Severity.LOW: "○"}
_SEV_LABEL = {Severity.HIGH: "HIGH", Severity.MEDIUM: "MED ", Severity.LOW: "LOW "}
_MAX_FINDINGS_SHOWN = 5


def _build_summary(
    findings: list[Finding],
    timeline: list[TimelineEvent],
    stats: dict,
) -> str:
    fc = stats.get("finding_counts", {})
    failures = stats.get("collector_failures", 0)
    collector_count = stats.get("collector_count", 0)
    duration = stats.get("duration_s", 0.0)
    timeline_count = stats.get("timeline_count", len(timeline))

    lines = [
        f"Collectors:  {collector_count} run · {failures} failed",
        f"Findings:    {fc.get('HIGH', 0)} HIGH · {fc.get('MEDIUM', 0)} MEDIUM · {fc.get('LOW', 0)} LOW",
        f"Timeline:    {timeline_count} events",
        f"Duration:    {duration:.1f}s",
        "",
    ]

    if findings:
        shown = findings[:_MAX_FINDINGS_SHOWN]
        for f in shown:
            bullet = _SEV_BULLET[f.severity]
            sev = _SEV_LABEL[f.severity]
            rule = f"{f.rule_id[:22]:<22}"
            path = f.artifact_path[:30]
            lines.append(f"  {bullet} {sev}  {rule}  {path}")
        if len(findings) > _MAX_FINDINGS_SHOWN:
            lines.append(f"  … and {len(findings) - _MAX_FINDINGS_SHOWN} more")
    else:
        lines.append("  System appears clean.")

    return "\n".join(lines)


class SummaryScreen(Screen):
    BINDINGS = [
        Binding("1", "open_findings", "Findings"),
        Binding("2", "open_timeline", "Timeline"),
        Binding("3", "open_stats", "Stats"),
        Binding("q", "quit_app", "Quit"),
    ]

    DEFAULT_CSS = """
    SummaryScreen {
        layout: vertical;
    }
    SummaryScreen #summary-body {
        margin: 2 4;
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
        yield Static(
            Text(_build_summary(self._findings, self._timeline, self._stats)),
            id="summary-body",
        )
        yield Footer()

    def action_open_findings(self) -> None:
        from ubuntils.tui.app import MainScreen
        self.app.push_screen(
            MainScreen(self._findings, self._timeline, self._stats, initial_panel="findings")
        )

    def action_open_timeline(self) -> None:
        from ubuntils.tui.app import MainScreen
        self.app.push_screen(
            MainScreen(self._findings, self._timeline, self._stats, initial_panel="timeline")
        )

    def action_open_stats(self) -> None:
        from ubuntils.tui.app import MainScreen
        self.app.push_screen(
            MainScreen(self._findings, self._timeline, self._stats, initial_panel="stats")
        )

    def action_quit_app(self) -> None:
        self.app.exit()
