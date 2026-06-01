from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Center, Vertical
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Static

from ubuntils.detectors.finding import Finding


class RemediateRequest(Message):
    def __init__(self, finding: Finding) -> None:
        self.finding = finding
        super().__init__()


class ConfirmModal(ModalScreen):
    BINDINGS = [
        Binding("y", "confirm", "Confirm"),
        Binding("escape", "cancel", "Cancel"),
    ]

    DEFAULT_CSS = """
    ConfirmModal {
        align: center middle;
    }
    ConfirmModal #dialog {
        width: 60;
        height: auto;
        background: $surface;
        border: tall $primary;
        padding: 1 2;
    }
    ConfirmModal #rule-id {
        text-style: bold;
        margin-bottom: 1;
    }
    ConfirmModal #hint {
        margin-top: 1;
        color: $text-muted;
    }
    """

    def __init__(self, finding: Finding) -> None:
        super().__init__()
        self._finding = finding

    def compose(self) -> ComposeResult:
        with Center():
            with Vertical(id="dialog"):
                yield Static(f"Remediate {self._finding.rule_id}?", id="rule-id")
                desc = self._finding.remediation_description or "Remove the offending entry."
                yield Static(desc, id="fix-desc")
                yield Static("Backup will be created at /var/backups/ubuntils/…")
                yield Static("Y: confirm    Esc: cancel", id="hint")

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)
