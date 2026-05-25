import platform

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static


def get_ubuntu_version() -> str:
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "Unknown"


def format_stats(stats: dict) -> str:
    fc = stats.get("finding_counts", {})
    return "\n".join([
        f"Ubuntu Version:   {stats.get('ubuntu_version', 'Unknown')}",
        f"Architecture:     {stats.get('architecture', platform.machine())}",
        f"Scan Duration:    {stats.get('duration_s', 0):.1f}s",
        f"Collectors run:   {stats.get('collector_count', 0)} ({stats.get('collector_failures', 0)} failed)",
        f"Findings:         {fc.get('HIGH', 0)} HIGH  {fc.get('MEDIUM', 0)} MEDIUM  {fc.get('LOW', 0)} LOW",
        f"Timeline events:  {stats.get('timeline_count', 0)}",
    ])


class StatsPanel(Widget):
    def __init__(self, stats: dict, **kwargs) -> None:
        super().__init__(**kwargs)
        self._stats = stats

    def compose(self) -> ComposeResult:
        yield Static(format_stats(self._stats))
