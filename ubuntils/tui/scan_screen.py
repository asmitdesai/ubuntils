from rich.text import Text
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Label, LoadingIndicator, Static


class ScanScreen(Screen):
    DEFAULT_CSS = """
    ScanScreen {
        align: center middle;
        layout: vertical;
    }
    ScanScreen LoadingIndicator {
        height: 3;
    }
    ScanScreen #label {
        margin-bottom: 1;
    }
    ScanScreen #ticker {
        dock: bottom;
        height: 1;
        padding: 0 2;
        color: $text-muted;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._ticker_parts: list[str] = []

    def compose(self) -> ComposeResult:
        yield Label("Scanning system...", id="label")
        yield LoadingIndicator()
        yield Static(Text(""), id="ticker")

    def add_to_ticker(self, name: str, success: bool = True) -> None:
        prefix = "✗ " if not success else ""
        self._ticker_parts.append(f"{prefix}{name}")
        self.query_one("#ticker", Static).update(
            Text(" · ".join(self._ticker_parts))
        )
