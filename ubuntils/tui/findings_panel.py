from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Label, ListItem, ListView, Static

from ubuntils.detectors.finding import Finding, Severity

_SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: _SEVERITY_ORDER[f.severity])


def format_detail(finding: Finding) -> str:
    lines = [
        finding.description,
        "",
        f"Artifact:  {finding.artifact_path}",
        f"Raw:       {finding.raw_value}",
    ]
    if finding.remediation_available and finding.remediation_description:
        lines.append(f"Remediation: {finding.remediation_description}")
    elif finding.remediation_available:
        lines.append("Remediation: available")
    else:
        lines.append("Remediation: not available")
    return "\n".join(lines)


_SEVERITY_COLORS = {
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}

_SEVERITY_SHORT = {
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED ",
    Severity.LOW: "LOW ",
}


class FindingsPanel(Widget):
    DEFAULT_CSS = """
    FindingsPanel {
        layout: vertical;
    }
    FindingsPanel ListView {
        height: 60%;
    }
    FindingsPanel #detail {
        height: 40%;
        border-top: solid $primary;
        padding: 1 2;
    }
    """

    def __init__(self, findings: list[Finding], **kwargs) -> None:
        super().__init__(**kwargs)
        self._findings = sort_findings(findings)

    def compose(self) -> ComposeResult:
        items = []
        for f in self._findings:
            color = _SEVERITY_COLORS[f.severity]
            sev = _SEVERITY_SHORT[f.severity]
            rule = f"{f.rule_id[:20]:<20}"
            path = f.artifact_path[:35]
            items.append(
                ListItem(Label(f"[{color} bold]{sev}[/{color} bold]  {rule}  {escape(path)}"))
            )
        yield ListView(*items)
        initial = format_detail(self._findings[0]) if self._findings else "No findings."
        yield Static(Text(initial), id="detail")

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        idx = event.list_view.index
        if idx is not None and 0 <= idx < len(self._findings):
            self.query_one("#detail", Static).update(
                Text(format_detail(self._findings[idx]))
            )
