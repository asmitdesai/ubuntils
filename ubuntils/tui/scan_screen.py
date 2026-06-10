from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Label, Static

_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _display_name(class_name: str) -> str:
    return class_name[: -len("Collector")] if class_name.endswith("Collector") else class_name


class ScanScreen(Screen):
    DEFAULT_CSS = """
    ScanScreen {
        align: center middle;
        layout: vertical;
    }
    ScanScreen #title {
        margin-bottom: 1;
        text-style: bold;
    }
    ScanScreen #checklist {
        width: auto;
    }
    """

    def __init__(self, collector_names: list[str] | None = None) -> None:
        super().__init__()
        names = collector_names or []
        self._rows: list[dict] = [
            {"raw": name, "name": _display_name(name), "status": "pending"}
            for name in names
        ]
        if self._rows:
            self._rows[0]["status"] = "running"
        self._frame = 0

    def compose(self) -> ComposeResult:
        yield Label("Scanning system…", id="title")
        yield Static(Text(self._checklist_text()), id="checklist")

    def on_mount(self) -> None:
        self.set_interval(0.1, self._tick)

    def _tick(self) -> None:
        self._frame = (self._frame + 1) % len(_SPINNER_FRAMES)
        self.query_one("#checklist", Static).update(Text(self._checklist_text()))

    def _checklist_text(self) -> str:
        spinner = _SPINNER_FRAMES[self._frame]
        lines = []
        for row in self._rows:
            status = row["status"]
            if status == "done":
                marker = "✓"
            elif status == "failed":
                marker = "✗"
            elif status == "running":
                marker = spinner
            else:
                marker = " "
            lines.append(f"  {marker}  {row['name']}")
        return "\n".join(lines)

    def mark(self, name: str, success: bool = True) -> None:
        for i, row in enumerate(self._rows):
            if row["raw"] == name:
                row["status"] = "done" if success else "failed"
                for nxt in self._rows[i + 1 :]:
                    if nxt["status"] == "pending":
                        nxt["status"] = "running"
                        break
                break
        self.query_one("#checklist", Static).update(Text(self._checklist_text()))
