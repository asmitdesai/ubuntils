# In-TUI Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow users to navigate findings with arrow keys, press Enter to expand a detail pane, and press R to remediate the selected finding in-place — with a confirmation modal, backup creation, and rollback info shown after success.

**Architecture:** `ConfirmModal` (new `ModalScreen`) posts `RemediateRequest`; `ResultsScreen` handles it via a background worker that calls the existing remediator and posts `RemediationDone`; `FindingsPanel` receives `mark_fixed(finding, result)` to update the list item and detail pane. No changes to the scan pipeline, CLI flags, or remediators.

**Tech Stack:** Python 3.11, Textual 8.2.5 (`ModalScreen`, `Binding`, `@work`), pytest + pytest-asyncio, `unittest.mock.patch`.

**Spec:** `docs/in-tui-remediation-design.md`

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Create | `ubuntils/tui/confirm_modal.py` | `RemediateRequest` message + `ConfirmModal` ModalScreen |
| Modify | `ubuntils/tui/results_screen.py` | `RemediationDone` message + `on_remediate_request` + `_run_remediation` worker + `on_remediation_done` |
| Rewrite | `ubuntils/tui/findings_panel.py` | `_detail_text()` helper + `FindingDetail` widget + `FindingsPanel` rewrite with Enter/R/Esc + `mark_fixed()` |
| Modify | `ubuntils/tui/__init__.py` | export `ConfirmModal` |
| Modify | `tests/test_tui.py` | new remediation tests; update one stale findings test |

**Untouched:** `cli.py`, `app.py`, `scan_screen.py`, `results_screen.py` compose/CSS, all collectors, detectors, remediators, timeline, formatters.

---

### Task 1: Create `ConfirmModal` + `RemediateRequest`

**Files:**
- Create: `ubuntils/tui/confirm_modal.py`
- Test: `tests/test_tui.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_tui.py` after the existing ResultsScreen imports block (after line with `from textual.widgets import TabbedContent`):

```python
from ubuntils.tui.confirm_modal import ConfirmModal, RemediateRequest


async def test_confirm_modal_renders_rule_id():
    finding = _finding(rule_id="CRON_TMP_PATH", remediation_description="Remove cron entry")

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ConfirmModal(finding))

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        content = str(pilot.app.screen.query_one("#rule-id", Static).content)
        assert "CRON_TMP_PATH" in content


async def test_confirm_modal_renders_fix_description():
    finding = _finding(rule_id="CRON_TMP_PATH", remediation_description="Remove the cron entry")

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ConfirmModal(finding))

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        content = str(pilot.app.screen.query_one("#fix-desc", Static).content)
        assert "Remove the cron entry" in content


async def test_confirm_modal_y_posts_remediate_request():
    finding = _finding(rule_id="CRON_TMP_PATH")
    received: list[RemediateRequest] = []

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ConfirmModal(finding))

        def on_remediate_request(self, msg: RemediateRequest) -> None:
            received.append(msg)

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("y")
        await pilot.pause()
        assert len(received) == 1
        assert received[0].finding.rule_id == "CRON_TMP_PATH"


async def test_confirm_modal_esc_dismisses_without_posting():
    finding = _finding()
    received: list[RemediateRequest] = []

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ConfirmModal(finding))

        def on_remediate_request(self, msg: RemediateRequest) -> None:
            received.append(msg)

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        assert len(received) == 0
```

- [ ] **Step 2: Run to confirm they fail**

```bash
python -m pytest tests/test_tui.py::test_confirm_modal_renders_rule_id tests/test_tui.py::test_confirm_modal_renders_fix_description tests/test_tui.py::test_confirm_modal_y_posts_remediate_request tests/test_tui.py::test_confirm_modal_esc_dismisses_without_posting -v --no-cov
```

Expected: `ModuleNotFoundError: ubuntils.tui.confirm_modal`

- [ ] **Step 3: Create `ubuntils/tui/confirm_modal.py`**

```python
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
        self.post_message(RemediateRequest(self._finding))
        self.dismiss()

    def action_cancel(self) -> None:
        self.dismiss()
```

- [ ] **Step 4: Run tests to confirm pass**

```bash
python -m pytest tests/test_tui.py::test_confirm_modal_renders_rule_id tests/test_tui.py::test_confirm_modal_renders_fix_description tests/test_tui.py::test_confirm_modal_y_posts_remediate_request tests/test_tui.py::test_confirm_modal_esc_dismisses_without_posting -v --no-cov
```

Expected: 4 PASSED.

- [ ] **Step 5: Commit**

```bash
git add ubuntils/tui/confirm_modal.py tests/test_tui.py
git commit -m "feat: add ConfirmModal and RemediateRequest message"
```

---

### Task 2: Add `RemediationDone` + worker + handlers to `ResultsScreen`

**Files:**
- Modify: `ubuntils/tui/results_screen.py`
- Test: `tests/test_tui.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_tui.py` after the ConfirmModal tests:

```python
from unittest.mock import MagicMock, patch

from ubuntils.detectors.finding import RemediationResult, RemediationStatus
from ubuntils.tui.results_screen import RemediationDone


async def test_remediate_request_triggers_worker_and_posts_done_on_success():
    finding = _finding(rule_id="CRON_TMP_PATH")
    mock_result = RemediationResult(
        finding_rule_id="CRON_TMP_PATH",
        status=RemediationStatus.SUCCESS,
        message="Done",
        backup_path="/var/backups/ubuntils/20260526/cron",
        rollback_command="sudo cp /var/backups/ubuntils/20260526/cron /var/spool/cron/crontabs/parallels",
    )
    received: list[RemediationDone] = []

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ResultsScreen(findings=[finding], timeline=[], stats=_stats()))

        def on_remediation_done(self, msg: RemediationDone) -> None:
            received.append(msg)

    with patch("ubuntils.tui.results_screen.REMEDIATOR_REGISTRY") as mock_reg:
        mock_remediator = MagicMock()
        mock_remediator.remediate.return_value = mock_result
        mock_reg.get.return_value = mock_remediator

        async with _App().run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            pilot.app.screen.post_message(RemediateRequest(finding))
            await pilot.pause(delay=0.5)
            assert len(received) == 1
            assert received[0].result.status == RemediationStatus.SUCCESS
            assert received[0].result.backup_path == "/var/backups/ubuntils/20260526/cron"


async def test_remediate_request_posts_failed_when_no_remediator():
    finding = _finding(rule_id="UNKNOWN_RULE")
    received: list[RemediationDone] = []

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ResultsScreen(findings=[finding], timeline=[], stats=_stats()))

        def on_remediation_done(self, msg: RemediationDone) -> None:
            received.append(msg)

    with patch("ubuntils.tui.results_screen.REMEDIATOR_REGISTRY") as mock_reg:
        mock_reg.get.return_value = None

        async with _App().run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            pilot.app.screen.post_message(RemediateRequest(finding))
            await pilot.pause(delay=0.5)
            assert len(received) == 1
            assert received[0].result.status == RemediationStatus.FAILED
```

- [ ] **Step 2: Run to confirm they fail**

```bash
python -m pytest tests/test_tui.py::test_remediate_request_triggers_worker_and_posts_done_on_success tests/test_tui.py::test_remediate_request_posts_failed_when_no_remediator -v --no-cov
```

Expected: `ImportError: cannot import name 'RemediationDone' from 'ubuntils.tui.results_screen'`

- [ ] **Step 3: Edit `ubuntils/tui/results_screen.py`**

Add these imports at the top:

```python
from textual import work

from ubuntils.detectors.finding import Finding, RemediationResult, RemediationStatus
from ubuntils.remediators import REMEDIATOR_REGISTRY
from ubuntils.tui.confirm_modal import RemediateRequest
from ubuntils.tui.findings_panel import FindingsPanel
```

Add `RemediationDone` message class after the imports:

```python
class RemediationDone(Message):
    def __init__(self, finding: Finding, result: RemediationResult) -> None:
        self.finding = finding
        self.result = result
        super().__init__()
```

Add these three methods to `ResultsScreen` (after `action_quit_app`):

```python
    def on_remediate_request(self, message: RemediateRequest) -> None:
        self._run_remediation(message.finding)

    @work(thread=True)
    def _run_remediation(self, finding: Finding) -> None:
        remediator = REMEDIATOR_REGISTRY.get(finding.rule_id)
        if remediator is None:
            result = RemediationResult(
                finding_rule_id=finding.rule_id,
                status=RemediationStatus.FAILED,
                message=f"No remediator registered for {finding.rule_id}",
            )
        else:
            try:
                result = remediator.remediate(finding, dry_run=False)
            except Exception as exc:
                result = RemediationResult(
                    finding_rule_id=finding.rule_id,
                    status=RemediationStatus.FAILED,
                    message=str(exc),
                )
        self.post_message(RemediationDone(finding, result))

    def on_remediation_done(self, message: RemediationDone) -> None:
        self.query_one(FindingsPanel).mark_fixed(message.finding, message.result)
```

The full updated `results_screen.py` imports block should be:

```python
from __future__ import annotations

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.message import Message
from textual.screen import Screen
from textual.widgets import Footer, Header, Static, TabbedContent, TabPane

from ubuntils.detectors.finding import Finding, RemediationResult, RemediationStatus
from ubuntils.remediators import REMEDIATOR_REGISTRY
from ubuntils.timeline.builder import TimelineEvent
from ubuntils.tui.confirm_modal import RemediateRequest
from ubuntils.tui.findings_panel import FindingsPanel
from ubuntils.tui.stats_panel import StatsPanel
from ubuntils.tui.summary_screen import _build_summary
from ubuntils.tui.timeline_panel import TimelinePanel
```

- [ ] **Step 4: Run tests to confirm pass**

```bash
python -m pytest tests/test_tui.py::test_remediate_request_triggers_worker_and_posts_done_on_success tests/test_tui.py::test_remediate_request_posts_failed_when_no_remediator -v --no-cov
```

Expected: 2 PASSED.

- [ ] **Step 5: Commit**

```bash
git add ubuntils/tui/results_screen.py tests/test_tui.py
git commit -m "feat: add RemediationDone message and remediation worker to ResultsScreen"
```

---

### Task 3: Rewrite `FindingsPanel` with `FindingDetail` + `mark_fixed`

**Files:**
- Rewrite: `ubuntils/tui/findings_panel.py`
- Test: `tests/test_tui.py`

- [ ] **Step 1: Update the stale existing test**

In `tests/test_tui.py`, find and replace `test_findings_panel_detail_pane_shows_first_finding_on_mount`:

Old:
```python
async def test_findings_panel_detail_pane_shows_first_finding_on_mount():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(_findings_fixture())

    async with _App().run_test() as pilot:
        await pilot.pause()
        detail = pilot.app.query_one("#detail", Static).content
        assert "High severity finding" in detail
```

New:
```python
async def test_findings_panel_detail_pane_empty_on_mount():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(_findings_fixture())

    async with _App().run_test() as pilot:
        await pilot.pause()
        detail = str(pilot.app.query_one("#detail", Static).content)
        assert "Select a finding" in detail
```

- [ ] **Step 2: Write the new failing tests**

Add to `tests/test_tui.py` after the existing FindingsPanel tests:

```python
from ubuntils.tui.findings_panel import FindingDetail


async def test_findings_panel_enter_shows_detail():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(_findings_fixture())

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        detail = str(pilot.app.query_one(FindingDetail).content)
        assert "High severity finding" in detail


async def test_findings_panel_enter_shows_r_hint_for_remediable():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(_findings_fixture())

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        detail = str(pilot.app.query_one(FindingDetail).content)
        assert "R: remediate" in detail


async def test_findings_panel_enter_shows_no_remediation_for_flag_only():
    flag_only = _finding(
        rule_id="SHELL_RC_MODIFICATION",
        severity=Severity.LOW,
        description="Shell rc modified",
        remediation_available=False,
    )

    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel([flag_only])

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        detail = str(pilot.app.query_one(FindingDetail).content)
        assert "No automated remediation available" in detail


async def test_findings_panel_mark_fixed_updates_list_item():
    findings = _findings_fixture()
    high_finding = next(f for f in findings if f.severity == Severity.HIGH)
    result = RemediationResult(
        finding_rule_id=high_finding.rule_id,
        status=RemediationStatus.SUCCESS,
        message="Done",
        backup_path="/var/backups/ubuntils/20260526/cron",
    )

    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(findings)

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        panel = pilot.app.query_one(FindingsPanel)
        panel.mark_fixed(high_finding, result)
        await pilot.pause()
        lv = pilot.app.query_one(ListView)
        first_label = str(lv.children[0].query_one(Label).content)
        assert "fixed" in first_label.lower()


async def test_findings_panel_mark_fixed_shows_backup_in_detail():
    findings = _findings_fixture()
    high_finding = next(f for f in findings if f.severity == Severity.HIGH)
    result = RemediationResult(
        finding_rule_id=high_finding.rule_id,
        status=RemediationStatus.SUCCESS,
        message="Done",
        backup_path="/var/backups/ubuntils/20260526/cron",
        rollback_command="sudo cp /var/backups/ubuntils/20260526/cron /etc/cron.d/evil",
    )

    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(findings)

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        panel = pilot.app.query_one(FindingsPanel)
        panel.mark_fixed(high_finding, result)
        await pilot.pause()
        detail = str(pilot.app.query_one(FindingDetail).content)
        assert "Remediated" in detail
        assert "/var/backups/ubuntils/20260526/cron" in detail


async def test_findings_panel_mark_fixed_failed_shows_error():
    findings = _findings_fixture()
    high_finding = next(f for f in findings if f.severity == Severity.HIGH)
    result = RemediationResult(
        finding_rule_id=high_finding.rule_id,
        status=RemediationStatus.FAILED,
        message="Permission denied",
    )

    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(findings)

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        panel = pilot.app.query_one(FindingsPanel)
        panel.mark_fixed(high_finding, result)
        await pilot.pause()
        detail = str(pilot.app.query_one(FindingDetail).content)
        assert "Failed" in detail
        assert "Permission denied" in detail
```

- [ ] **Step 3: Run to confirm they fail**

```bash
python -m pytest tests/test_tui.py -k "findings_panel" -v --no-cov 2>&1 | grep -E "PASSED|FAILED|ERROR"
```

Expected: `test_findings_panel_detail_pane_empty_on_mount` FAILED (still shows first finding), all new tests FAILED (no `FindingDetail` class).

- [ ] **Step 4: Rewrite `ubuntils/tui/findings_panel.py`**

```python
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
            from ubuntils.tui.confirm_modal import ConfirmModal
            self.app.push_screen(ConfirmModal(self._selected))

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
```

Note: `ConfirmModal` is imported inside `action_remediate` to avoid a circular import (`confirm_modal` → `finding`, `findings_panel` → `confirm_modal` → fine; but lazy import is safer if the dependency graph grows).

- [ ] **Step 5: Run the FindingsPanel tests to confirm pass**

```bash
python -m pytest tests/test_tui.py -k "findings_panel" -v --no-cov
```

Expected: all PASSED. If `test_findings_panel_enter_shows_detail` fails because Enter doesn't trigger `on_list_view_selected` in the test harness, use `await pilot.press("down")` first to ensure a highlight, then `await pilot.press("enter")`.

- [ ] **Step 6: Commit**

```bash
git add ubuntils/tui/findings_panel.py tests/test_tui.py
git commit -m "feat: rewrite FindingsPanel with FindingDetail, Enter/R/Esc, and mark_fixed"
```

---

### Task 4: Update `__init__.py`, run full suite, update CLAUDE.md

**Files:**
- Modify: `ubuntils/tui/__init__.py`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update `ubuntils/tui/__init__.py`**

Replace the whole file with:

```python
from ubuntils.tui.app import UbuntilsApp
from ubuntils.tui.confirm_modal import ConfirmModal
from ubuntils.tui.results_screen import ResultsScreen
from ubuntils.tui.scan_screen import ScanScreen

__all__ = ["ConfirmModal", "ResultsScreen", "ScanScreen", "UbuntilsApp"]
```

- [ ] **Step 2: Add `ConfirmModal` export test**

Add to `tests/test_tui.py` in the package-exports section (near `test_results_screen_importable_from_tui_package`):

```python
def test_confirm_modal_importable_from_tui_package():
    from ubuntils.tui import ConfirmModal as _ConfirmModal
    assert _ConfirmModal is ConfirmModal
```

- [ ] **Step 3: Run the full suite with coverage gate**

```bash
python -m pytest -q
```

Expected: all PASS, coverage ≥ 80%. If `confirm_modal.py` or the new `FindingDetail`/`mark_fixed` code drops coverage below gate, add targeted tests (e.g., assert `_detail_text(None)` returns the placeholder string, assert `action_remediate` is a no-op when `_selected` is None).

- [ ] **Step 4: Confirm no stale references**

```bash
grep -rn "format_detail\b" ubuntils/ tests/
```

Expected: only in `findings_panel.py` (definition) and `tests/test_tui.py` (existing unit tests) — both are still valid.

- [ ] **Step 5: Update `CLAUDE.md`**

In the "Completed" section, add after Phase 13:

```
- **Phase 14** — In-TUI remediation: Enter expands FindingDetail pane; R on a remediable finding opens ConfirmModal; worker calls remediator in background thread; success marks the row [fixed] and shows backup path + rollback command inline; failure shows error in detail pane; no CLI flags required
```

Update "Current test count" to the new total from Step 3.

In "Known Bugs Fixed" (no bugs introduced — skip unless a real issue was found during implementation).

- [ ] **Step 6: Commit**

```bash
git add ubuntils/tui/__init__.py tests/test_tui.py CLAUDE.md
git commit -m "feat: export ConfirmModal; update CLAUDE.md for Phase 14"
```

---

## Self-Review

**Spec coverage:**
- Per-finding Enter to expand → Task 3 (`on_list_view_selected` + `FindingDetail.show`) ✓
- Always-on confirmation modal → Task 1 (`ConfirmModal` + `RemediateRequest`) ✓
- Mark ✓ in list after success → Task 3 (`mark_fixed` updates `ListItem` label) ✓
- Backup + rollback shown inline after success → Task 3 (`_detail_text` with `result`) ✓
- Error shown inline after failure → Task 3 (`_detail_text` with FAILED result) ✓
- "No automated remediation available" for flag-only → Task 3 (`_detail_text` when `remediation_available=False`) ✓
- No CLI flags required → no CLI changes; worker always runs `dry_run=False` ✓
- Worker runs in background thread → Task 2 (`@work(thread=True)`) ✓
- `ConfirmModal` exported from `ubuntils.tui` → Task 4 ✓
- `RemediationDone` defined in `results_screen.py` → Task 2 ✓
- `RemediateRequest` defined in `confirm_modal.py` → Task 1 ✓

**Placeholder scan:** None found.

**Type/name consistency:**
- `FindingDetail.show(finding, result=None)` — used in Task 3 `on_list_view_selected`, `action_collapse`, `mark_fixed` ✓
- `mark_fixed(finding: Finding, result: RemediationResult)` — defined in Task 3, called in Task 2 `on_remediation_done` ✓
- `RemediateRequest.finding` — defined Task 1, accessed in Task 2 `on_remediate_request` ✓
- `RemediationDone.finding` + `RemediationDone.result` — defined Task 2, accessed in Task 2 `on_remediation_done` ✓
- `REMEDIATOR_REGISTRY.get(rule_id)` — registry uses dict `.get()`, consistent with Task 2 worker ✓
- `#finding-{i}` ListItem ids — set in Task 3 `compose`, queried in Task 3 `mark_fixed` ✓
- `#detail` Static id — Task 3 `compose` yields `FindingDetail(id="detail")`, queried as `query_one(FindingDetail)` in tests ✓
