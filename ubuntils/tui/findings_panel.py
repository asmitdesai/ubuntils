from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.widget import Widget
from textual.widgets import Label, ListItem, ListView, Static

from ubuntils.detectors.finding import Finding, RemediationResult, RemediationStatus, Severity

_SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    # Most severe first, and the most confident within each severity.
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER[f.severity], -f.confidence))


def format_detail(finding: Finding) -> str:
    lines = [
        finding.description,
        "",
        f"Confidence: {finding.confidence} ({finding.confidence_band})",
        f"Artifact:  {finding.artifact_path}",
        f"Raw:       {finding.raw_value}",
    ]
    if finding.signals:
        lines.append("")
        lines.append("Signals:")
        for s in finding.signals:
            sign = "+" if s["weight"] >= 0 else ""
            lines.append(f"  {sign}{s['weight']:>4}  {s['name']}: {s['detail']}")
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
        f"Confidence: {finding.confidence} ({finding.confidence_band})",
        f"Artifact:  {finding.artifact_path}",
        f"Raw:       {finding.raw_value}",
    ]
    if finding.signals:
        lines.append("")
        lines.append("Signals:")
        for s in finding.signals:
            sign = "+" if s["weight"] >= 0 else ""
            lines.append(f"  {sign}{s['weight']:>4}  {s['name']}: {s['detail']}")

    if finding.guided_remediation:
        lines += ["", "Guided remediation:", f"  {finding.guided_remediation}"]

    if finding.related_events:
        lines += ["", "Related events:"]
        for e in finding.related_events[:5]:
            ts = e.timestamp.strftime("%m-%d %H:%M:%S")
            lines.append(f"  {ts} [{e.source}] {e.description[:60]}")

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
        lines += ["", "R: remediate    PgUp/PgDn: scroll this detail"]
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
        height: auto;
        padding: 1 2;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(Text(_detail_text(None)), **kwargs)

    def show(self, finding: Finding | None, result: RemediationResult | None = None) -> None:
        # Text, never a markup string: raw values and log lines are attacker
        # text, and "[/bold]" in a cron line would crash the TUI (MarkupError)
        # the moment the responder selected that finding.
        self.update(Text(_detail_text(finding, result)))


class FindingsPanel(Widget):
    BINDINGS = [
        Binding("r", "remediate", "Remediate", show=False),
        Binding("escape", "collapse", "Collapse", show=False),
        Binding("pagedown", "scroll_detail(1)", "Scroll detail", show=False),
        Binding("pageup", "scroll_detail(-1)", "Scroll detail", show=False),
    ]

    DEFAULT_CSS = """
    FindingsPanel {
        layout: vertical;
        height: 100%;
    }
    FindingsPanel ListView {
        height: 1fr;
    }
    FindingsPanel #detail-scroll {
        /* Fixed share of the screen; a long detail (a package with 20 changed
           files, signals, related events) scrolls instead of being cut off. */
        height: 16;
        border-top: solid $primary;
    }
    """

    def __init__(self, findings: list[Finding], **kwargs) -> None:
        super().__init__(**kwargs)
        self._findings = sort_findings(findings)
        self._selected: Finding | None = None
        # Findings already remediated successfully, by index: running the
        # remediator again would only fail with "line not found".
        self._fixed: set = set()

    def compose(self) -> ComposeResult:
        items = []
        for i, f in enumerate(self._findings):
            color = _SEVERITY_COLORS[f.severity]
            sev = _SEVERITY_SHORT[f.severity]
            rule = f"{f.rule_id[:20]:<20}"
            path = f.artifact_path[:35]
            items.append(
                ListItem(
                    Label(Text.assemble((sev, f"bold {color}"),
                                        f"  {rule}  {path}  ({f.confidence_band})")),
                    id=f"finding-{i}",
                )
            )
        yield ListView(*items)
        detail_scroll = VerticalScroll(FindingDetail(id="detail"), id="detail-scroll")
        # Never takes focus: the list keeps the keyboard (and the 1-4 tab
        # keys keep working); PgUp/PgDn scroll the detail instead.
        detail_scroll.can_focus = False
        yield detail_scroll

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        idx = event.list_view.index
        if idx is not None and 0 <= idx < len(self._findings):
            self._selected = self._findings[idx]
            self.query_one(FindingDetail).show(self._selected)
            self.query_one("#detail-scroll", VerticalScroll).scroll_home(animate=False)

    def action_remediate(self) -> None:
        if self._selected is not None and self._selected.remediation_available:
            if self._findings.index(self._selected) in self._fixed:
                self.app.notify("Already remediated.", severity="information")
                return
            from ubuntils.tui.confirm_modal import ConfirmModal, RemediateRequest
            finding = self._selected

            def _on_confirmed(confirmed: bool) -> None:
                if confirmed:
                    self.post_message(RemediateRequest(finding))

            self.app.push_screen(ConfirmModal(finding), _on_confirmed)

    def action_scroll_detail(self, direction: int) -> None:
        scroll = self.query_one("#detail-scroll", VerticalScroll)
        if direction > 0:
            scroll.scroll_page_down(animate=False)
        else:
            scroll.scroll_page_up(animate=False)

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
        # A failed remediation changed nothing; the row must not claim it did.
        if result.status == RemediationStatus.SUCCESS:
            self._fixed.add(idx)
            label.update(Text.assemble((f"✓ {sev}", "green"), f"  {rule}  {path}  [fixed]"))
        else:
            label.update(Text.assemble((f"✗ {sev}", "bold red"),
                                       f"  {rule}  {path}  [remediation failed]"))
        self.query_one(FindingDetail).show(finding, result)
