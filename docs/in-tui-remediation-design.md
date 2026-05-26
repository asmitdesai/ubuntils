# In-TUI Remediation — Design Spec

**Date:** 2026-05-26

---

## Overview

Allow users to remediate findings directly from the TUI Findings tab without quitting and re-running with CLI flags. Remediation is always available in TUI mode — no `--remediate` or `--confirm` flags required. The existing CLI flags remain for headless/scripted use and are untouched.

---

## Architecture

The remediation flow lives entirely inside `ResultsScreen` and `FindingsPanel`. No new screens, no changes to `UbuntilsApp` or the scan pipeline. The `FindingsPanel` gains a split layout (list on top, detail below). A `ConfirmModal` (`ModalScreen`) handles per-finding confirmation. Remediation runs in a Textual worker thread so the UI stays responsive.

---

## Components

### 1. `FindingsPanel` (rewrite) — `tui/findings_panel.py`

Split layout:
- **Top**: existing `ListView` (scrollable, full findings list)
- **Bottom**: new `FindingDetail` widget (fixed height, ~8 rows)

Behaviour:
- `↑`/`↓` moves selection; `Enter` expands the detail pane for the selected finding
- `R` (when detail is open and finding is remediable) pushes `ConfirmModal`
- `Esc` collapses the detail pane
- After successful remediation, the `ListItem` label gains a `[fixed]` suffix and renders green; `FindingDetail` shows backup path + rollback command
- After a failed remediation, the row is unchanged; `FindingDetail` shows the error in red
- `mark_fixed(finding, result)` — public method called by `ResultsScreen` after `RemediationDone`; updates the matching `ListItem` and calls `FindingDetail.show(finding, result)`

Key bindings (added to `FindingsPanel.BINDINGS`):
- `enter` → `action_expand`
- `r` → `action_remediate` (no-op if no remediable finding selected)
- `escape` → `action_collapse`

### 2. `FindingDetail` (new widget) — `tui/findings_panel.py`

A `Static` widget rendered inside `FindingsPanel`. Swaps content on each selection change via `show(finding, result=None)`.

Content rendered per state:

| State | Content |
|---|---|
| Nothing selected | `"Select a finding to see details"` |
| Non-remediable finding selected | Description · Path · Raw value · `"No automated remediation available"` |
| Remediable finding selected | Description · Path · Raw value · Fix description · `R: remediate` hint |
| Remediation succeeded | Description · Path · `✓ Remediated` · Backup path · Rollback command |
| Remediation failed | Description · Path · `✗ Failed: <error message>` in red |

### 3. `ConfirmModal` (new `ModalScreen`) — `tui/confirm_modal.py`

Receives a `Finding`. Renders:
- Rule ID and severity
- What the fix will do (`finding.remediation_description`)
- Backup path prefix (`/var/backups/ubuntils/…`)
- `Y: confirm` / `Esc: cancel`

On `Y`: posts `RemediateRequest(finding)` to the app and calls `self.dismiss()`.  
On `Esc`: dismisses with no message.

---

## Messages

Two new `Message` subclasses:

```python
# tui/confirm_modal.py — posted by ConfirmModal when user presses Y
class RemediateRequest(Message):
    def __init__(self, finding: Finding) -> None: ...

# tui/results_screen.py — posted by the remediation worker when done
class RemediationDone(Message):
    def __init__(self, finding: Finding, result: RemediationResult) -> None: ...
```

---

## Data Flow

```
User presses Enter on ListItem
  → FindingsPanel.action_expand()
    → FindingDetail.show(finding)

User presses R (remediable finding open)
  → FindingsPanel.action_remediate()
    → app.push_screen(ConfirmModal(finding))

User presses Y in ConfirmModal
  → ConfirmModal posts RemediateRequest(finding)
  → ConfirmModal dismisses

ResultsScreen.on_remediate_request(msg)
  → spawns @work(thread=True) _run_remediation(finding)
    → REMEDIATOR_REGISTRY[rule_id].remediate(finding)
    → posts RemediationDone(finding, result)

ResultsScreen.on_remediation_done(msg)
  → findings_panel.mark_fixed(finding, result)
    → if SUCCESS: update ListItem label → [fixed], green
                  FindingDetail.show(finding, result)  ← backup + rollback
    → if FAILED:  FindingDetail.show(finding, result)  ← error in red
```

---

## Error Handling

- `REMEDIATOR_REGISTRY` lookup: if `rule_id` not in registry (flag-only rule), `action_remediate` is a no-op — this can't happen via the UI since the `R` hint is only shown for remediable findings, but guarded defensively.
- Remediator raises an exception: caught in the worker, wrapped as `RemediationResult(status=FAILED, message=str(exc))` and posted as `RemediationDone`.
- Worker runs on the thread pool — UI never blocks.

---

## Files Changed

| Action | File |
|---|---|
| Rewrite | `ubuntils/tui/findings_panel.py` |
| Create | `ubuntils/tui/confirm_modal.py` |
| Modify | `ubuntils/tui/results_screen.py` — add `on_remediate_request`, `on_remediation_done`, `_run_remediation` worker |
| Modify | `ubuntils/tui/__init__.py` — export `ConfirmModal` |
| Modify | `tests/test_tui.py` — new remediation tests |

`cli.py`, `app.py`, all collectors, detectors, remediators, and the scan pipeline are **untouched**.

---

## Testing

Four test areas:

1. **`FindingDetail` rendering** — assert detail shows description/path/raw for a selected finding; assert "No automated remediation available" for flag-only rules; assert `R: remediate` hint for remediable rules
2. **`ConfirmModal`** — assert renders rule ID and fix description; assert `Y` posts `RemediateRequest`; assert `Esc` dismisses without posting
3. **Post-remediation success** — mock remediator returning `SUCCESS` with fake backup path; assert `ListItem` shows `[fixed]`; assert `FindingDetail` shows backup path and rollback command
4. **Post-remediation failure** — mock remediator returning `FAILED`; assert row stays unfixed; assert error message appears in detail pane
