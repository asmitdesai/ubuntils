from rich.text import Text
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Label, ListItem, ListView

from ubuntils.timeline.builder import TimelineEvent


class TimelinePanel(Widget):
    DEFAULT_CSS = """
    TimelinePanel {
        height: 100%;
    }
    TimelinePanel ListView {
        height: 100%;
    }
    """

    def __init__(self, timeline: list[TimelineEvent], **kwargs) -> None:
        super().__init__(**kwargs)
        self._timeline = timeline

    def compose(self) -> ComposeResult:
        items = [
            ListItem(
                Label(
                    Text(
                        f"{e.timestamp.strftime('%m-%d %H:%M:%S')}  "
                        f"{e.source:<12}  {e.description}"
                    )
                )
            )
            for e in self._timeline
        ]
        yield ListView(*items)
