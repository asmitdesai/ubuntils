from __future__ import annotations

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.widget import Widget
from textual.widgets import Label, ListItem, ListView, Static

from ubuntils.detectors.finding import Finding, RemediationResult, RemediationStatus, Severity

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


def _detail_text(finding: Finding | None, result: RemediationResult | None = None) -> str:
    if finding is None:
        return "Select a finding to see details."

    lines = [
        finding.description,
        "",
        f"Artifact:  {finding.artifact_path}",
        f"Raw:       {finding.raw_value}",
    ]

    if result is not None:
        if result.status == RemediationStatus.SUCCESS:
            lines += ["", "✓ Remediated"]
            if result.backup_path:
                lines.append(f"Backup:    {result.backup_path}")
            if result.rollback_command:
                lines.append(f"Rollback:  {result.rollback_command}")
        else:
            lines += ["", f"✗ Failed: {result.message}"]
    elif finding.remediation_available:
        desc = finding.remediation_description or "Automated remediation available."
        lines.append(f"Fix:       {desc}")
        lines += ["", "R: remediate"]
    else:
        lines += ["", "No automated remediation available for this finding."]

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


class FindingDetail(Static):
    DEFAULT_CSS = """
    FindingDetail {
        height: 10;
        border-top: solid $primary;
        padding: 1 2;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(_detail_text(None), **kwargs)

    def show(self, finding: Finding | None, result: RemediationResult | None = None) -> None:
        self.update(_detail_text(finding, result))


class FindingsPanel(Widget):
    BINDINGS = [
        Binding("r", "remediate", "Remediate", show=False),
        Binding("escape", "collapse", "Collapse", show=False),
    ]

    DEFAULT_CSS = """
    FindingsPanel {
        layout: vertical;
        height: 100%;
    }
    FindingsPanel ListView {
        height: 1fr;
    }
    FindingsPanel FindingDetail {
        height: 10;
    }
    """

    def __init__(self, findings: list[Finding], **kwargs) -> None:
        super().__init__(**kwargs)
        self._findings = sort_findings(findings)
        self._selected: Finding | None = None

    def compose(self) -> ComposeResult:
        items = []
        for i, f in enumerate(self._findings):
            color = _SEVERITY_COLORS[f.severity]
            sev = _SEVERITY_SHORT[f.severity]
            rule = f"{f.rule_id[:20]:<20}"
            path = f.artifact_path[:35]
            items.append(
                ListItem(
                    Label(f"[{color} bold]{sev}[/{color} bold]  {rule}  {escape(path)}"),
                    id=f"finding-{i}",
                )
            )
        yield ListView(*items)
        yield FindingDetail(id="detail")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        idx = event.list_view.index
        if idx is not None and 0 <= idx < len(self._findings):
            self._selected = self._findings[idx]
            self.query_one(FindingDetail).show(self._selected)

    def action_remediate(self) -> None:
        if self._selected is not None and self._selected.remediation_available:
            from ubuntils.tui.confirm_modal import ConfirmModal, RemediateRequest
            finding = self._selected

            def _on_confirmed(confirmed: bool) -> None:
                if confirmed:
                    self.post_message(RemediateRequest(finding))

            self.app.push_screen(ConfirmModal(finding), _on_confirmed)

    def action_collapse(self) -> None:
        self._selected = None
        self.query_one(FindingDetail).show(None)

    def mark_fixed(self, finding: Finding, result: RemediationResult) -> None:
        try:
            idx = self._findings.index(finding)
        except ValueError:
            return
        item = self.query_one(f"#finding-{idx}", ListItem)
        label = item.query_one(Label)
        sev = _SEVERITY_SHORT[finding.severity]
        rule = f"{finding.rule_id[:20]:<20}"
        path = finding.artifact_path[:35]
        label.update(f"[green]✓ {sev}[/green]  {rule}  {escape(path)}  [fixed]")
        self.query_one(FindingDetail).show(finding, result)
