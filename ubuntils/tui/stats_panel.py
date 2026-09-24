import platform

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static


def format_stats(stats: dict) -> str:
    fc = stats.get("finding_counts", {})
    lines = [
        f"Ubuntu Version:   {stats.get('ubuntu_version', 'Unknown')}",
        f"Architecture:     {stats.get('architecture', platform.machine())}",
        f"Scan Duration:    {stats.get('duration_s', 0):.1f}s",
        f"Collectors run:   {stats.get('collector_count', 0)} ({stats.get('collector_failures', 0)} failed)",
        f"Findings:         {fc.get('HIGH', 0)} HIGH  {fc.get('MEDIUM', 0)} MEDIUM  {fc.get('LOW', 0)} LOW",
        f"Timeline events:  {stats.get('timeline_count', 0)}",
    ]
    suppressed = stats.get("suppressed_by_baseline", 0)
    if suppressed:
        lines.append(f"Suppressed by baseline: {suppressed}")
    integrity = stats.get("bundle_integrity")
    if integrity and integrity != "live":
        lines.append(f"Bundle integrity: {integrity.upper()}")
    for name, reasons in sorted((stats.get("collectors_degraded") or {}).items()):
        lines.append(f"Degraded: {name} — {'; '.join(reasons)}")
    if stats.get("rules_failed"):
        lines.append(f"Rules failed: {', '.join(stats['rules_failed'])}")
    if stats.get("timeline_error"):
        lines.append(f"Timeline error: {stats['timeline_error']}")
    return "\n".join(lines)


class StatsPanel(Widget):
    DEFAULT_CSS = """
    StatsPanel {
        height: 100%;
        padding: 1 2;
    }
    """

    def __init__(self, stats: dict, **kwargs) -> None:
        super().__init__(**kwargs)
        self._stats = stats

    def compose(self) -> ComposeResult:
        yield Static(format_stats(self._stats))
