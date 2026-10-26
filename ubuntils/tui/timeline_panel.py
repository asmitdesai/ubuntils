from rich.text import Text
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable

from ubuntils.timeline.builder import TimelineEvent


class TimelinePanel(Widget):
    """The timeline as a table.

    A DataTable renders only the rows on screen; one ListItem widget per event
    took seconds per thousand events and never finished mounting a real
    host's 7-day journal (tens of thousands of events).
    """

    DEFAULT_CSS = """
    TimelinePanel {
        height: 100%;
    }
    TimelinePanel DataTable {
        height: 100%;
    }
    """

    def __init__(self, timeline: list[TimelineEvent], **kwargs) -> None:
        super().__init__(**kwargs)
        self._timeline = timeline

    def compose(self) -> ComposeResult:
        yield DataTable(cursor_type="row", zebra_stripes=True)

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Time (UTC)", "Source", "Program", "Message")
        # Text cells, never markup strings: log lines are attacker text.
        table.add_rows(
            (
                e.timestamp.strftime("%m-%d %H:%M:%S"),
                e.source,
                Text(e.program),
                Text(e.description),
            )
            for e in self._timeline
        )
