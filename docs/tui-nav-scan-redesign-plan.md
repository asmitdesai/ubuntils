# TUI Redesign v2 — Tabbed Navigation + Scan Checklist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the two-level `SummaryScreen`→`MainScreen` navigation with a single tabbed `ResultsScreen`, and replace the growing scan ticker with a fixed live checklist.

**Architecture:** After the scan, a single `ResultsScreen` hosts a `TabbedContent` with four panes (Summary, Findings, Timeline, Stats) — no screen pushing/popping. `ScanScreen` is rewritten to show every collector as a row that resolves to ✓/✗ in place. The `_build_summary()` helper from the old `SummaryScreen` is kept and reused by the Summary tab.

**Tech Stack:** Python 3.11, Textual 8.2.5 (`TabbedContent`/`TabPane`), pytest + pytest-asyncio.

**Spec:** `docs/2026-05-26-tui-nav-scan-redesign-spec.md`

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Rewrite | `ubuntils/tui/scan_screen.py` | `ScanScreen` — fixed live checklist of collectors |
| Refactor | `ubuntils/tui/summary_screen.py` | keep `_build_summary()` + constants; remove `SummaryScreen` class |
| Create | `ubuntils/tui/results_screen.py` | `ResultsScreen` — `TabbedContent` of 4 panes |
| Modify | `ubuntils/tui/app.py` | wire `ScanScreen`/`ResultsScreen`; remove `MainScreen` |
| Modify | `ubuntils/tui/__init__.py` | export `ScanScreen`, `ResultsScreen`; drop `SummaryScreen` |
| Modify | `tests/test_tui.py` | checklist + tabbed-nav tests; remove `MainScreen`/`SummaryScreen` tests |

**Existing helpers reused (do not rewrite):**
- `_build_summary(findings, timeline, stats)`, `_SEV_BULLET`, `_SEV_LABEL`, `_MAX_FINDINGS_SHOWN` — `ubuntils/tui/summary_screen.py`
- `FindingsPanel` — `ubuntils/tui/findings_panel.py`
- `TimelinePanel` — `ubuntils/tui/timeline_panel.py`
- `StatsPanel`, `get_ubuntu_version` — `ubuntils/tui/stats_panel.py`
- `ALL_COLLECTORS` — `ubuntils/collectors/__init__.py`
- `CollectorProgress`, `ScanComplete` messages — `ubuntils/tui/app.py` (kept unchanged)

---

### Task 1: Rewrite `ScanScreen` as a live checklist

**Files:**
- Rewrite: `ubuntils/tui/scan_screen.py`
- Test: `tests/test_tui.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_tui.py` (near the existing ScanScreen tests):

```python
async def test_scan_screen_lists_all_collectors_on_mount():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield ScanScreen(collector_names=["ProcessCollector", "CronCollector", "SSHCollector"])

    async with _App().run_test() as pilot:
        await pilot.pause()
        body = str(pilot.app.query_one("#checklist", Static).renderable)
        assert "Process" in body
        assert "Cron" in body
        assert "SSH" in body


async def test_scan_screen_mark_done_shows_check():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield ScanScreen(collector_names=["ProcessCollector", "CronCollector"])

    async with _App().run_test() as pilot:
        await pilot.pause()
        screen = pilot.app.query_one(ScanScreen)
        screen.mark("ProcessCollector", success=True)
        await pilot.pause()
        body = str(pilot.app.query_one("#checklist", Static).renderable)
        assert "✓" in body


async def test_scan_screen_mark_failed_shows_cross():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield ScanScreen(collector_names=["ProcessCollector", "CronCollector"])

    async with _App().run_test() as pilot:
        await pilot.pause()
        screen = pilot.app.query_one(ScanScreen)
        screen.mark("CronCollector", success=False)
        await pilot.pause()
        body = str(pilot.app.query_one("#checklist", Static).renderable)
        assert "✗" in body
```

Note: these replace the old `test_scan_screen_ticker_updates`, `test_scan_screen_ticker_marks_failed`, and `test_scan_screen_add_to_ticker` tests — delete those three in Task 5.

- [ ] **Step 2: Run to confirm they fail**

Run: `python -m pytest tests/test_tui.py::test_scan_screen_lists_all_collectors_on_mount tests/test_tui.py::test_scan_screen_mark_done_shows_check tests/test_tui.py::test_scan_screen_mark_failed_shows_cross -v --no-cov`
Expected: FAIL — `ScanScreen.__init__` takes no `collector_names`; no `#checklist`; no `mark()`.

- [ ] **Step 3: Rewrite `ubuntils/tui/scan_screen.py`**

```python
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

    def __init__(self, collector_names: list[str]) -> None:
        super().__init__()
        # status: "pending" | "running" | "done" | "failed"
        self._rows: list[dict] = [
            {"raw": name, "name": _display_name(name), "status": "pending"}
            for name in collector_names
        ]
        if self._rows:
            self._rows[0]["status"] = "running"
        self._frame = 0

    def compose(self) -> ComposeResult:
        yield Label("Scanning system…", id="title")
        yield Static(Text(self._render()), id="checklist")

    def on_mount(self) -> None:
        self.set_interval(0.1, self._tick)

    def _tick(self) -> None:
        self._frame = (self._frame + 1) % len(_SPINNER_FRAMES)
        self.query_one("#checklist", Static).update(Text(self._render()))

    def _render(self) -> str:
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
        advanced = False
        for i, row in enumerate(self._rows):
            if row["raw"] == name:
                row["status"] = "done" if success else "failed"
                for nxt in self._rows[i + 1:]:
                    if nxt["status"] == "pending":
                        nxt["status"] = "running"
                        advanced = True
                        break
                break
        # mark _ used to keep linters quiet about advanced when last row finishes
        _ = advanced
        self.query_one("#checklist", Static).update(Text(self._render()))
```

- [ ] **Step 4: Run tests to confirm pass**

Run: `python -m pytest tests/test_tui.py::test_scan_screen_lists_all_collectors_on_mount tests/test_tui.py::test_scan_screen_mark_done_shows_check tests/test_tui.py::test_scan_screen_mark_failed_shows_cross -v --no-cov`
Expected: 3 PASSED.

- [ ] **Step 5: Commit**

```bash
git add ubuntils/tui/scan_screen.py tests/test_tui.py
git commit -m "feat: rewrite ScanScreen as a live collector checklist"
```

---

### Task 2: Refactor `summary_screen.py` — keep helper, drop the screen class

**Files:**
- Modify: `ubuntils/tui/summary_screen.py`

- [ ] **Step 1: Remove the `SummaryScreen` class**

In `ubuntils/tui/summary_screen.py`, delete the entire `class SummaryScreen(Screen):` definition (from `class SummaryScreen` through its last `action_quit_app` method). Keep everything above it: the imports needed by `_build_summary` plus `_SEV_BULLET`, `_SEV_LABEL`, `_MAX_FINDINGS_SHOWN`, and `_build_summary`.

Then prune now-unused imports. After the edit the import block should be exactly:

```python
from ubuntils.detectors.finding import Finding, Severity
from ubuntils.timeline.builder import TimelineEvent
```

(`rich.text.Text`, `textual` `ComposeResult`/`Binding`/`Screen`/`Footer`/`Header`/`Static` are only used by the deleted class — remove them.)

- [ ] **Step 2: Verify the module still imports and the helper works**

Run: `python -c "from ubuntils.tui.summary_screen import _build_summary; print(_build_summary([], [], {'collector_count': 8, 'timeline_count': 42, 'finding_counts': {}}))"`
Expected: prints the summary block containing `8 run`, `42 events`, and `System appears clean.`

- [ ] **Step 3: Commit**

```bash
git add ubuntils/tui/summary_screen.py
git commit -m "refactor: drop SummaryScreen class, keep _build_summary helper"
```

---

### Task 3: Create `ResultsScreen` with a `TabbedContent`

**Files:**
- Create: `ubuntils/tui/results_screen.py`
- Test: `tests/test_tui.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_tui.py`:

```python
from ubuntils.tui.results_screen import ResultsScreen
from textual.widgets import TabbedContent


async def test_results_screen_default_tab_is_summary():
    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ResultsScreen(findings=[], timeline=[], stats=_stats()))

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        tc = pilot.app.screen.query_one(TabbedContent)
        assert tc.active == "summary"


async def test_results_screen_summary_shows_clean_message():
    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ResultsScreen(findings=[], timeline=[], stats=_stats(high=0, medium=0, low=0)))

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        body = str(pilot.app.screen.query_one("#summary-body", Static).renderable)
        assert "System appears clean" in body


async def test_results_screen_key_3_switches_to_timeline():
    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ResultsScreen(findings=[], timeline=[], stats=_stats()))

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("3")
        await pilot.pause()
        tc = pilot.app.screen.query_one(TabbedContent)
        assert tc.active == "timeline"


async def test_results_screen_panes_fill_height():
    events = [_event(description=f"e{i}") for i in range(10)]

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(ResultsScreen(findings=[], timeline=events, stats=_stats()))

    async with _App().run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("3")
        await pilot.pause()
        tl = pilot.app.screen.query_one(TimelinePanel)
        assert tl.region.height > 1, f"timeline pane collapsed: {tl.region}"
```

- [ ] **Step 2: Run to confirm they fail**

Run: `python -m pytest tests/test_tui.py -k results_screen -v --no-cov`
Expected: FAIL — `ModuleNotFoundError: ubuntils.tui.results_screen`.

- [ ] **Step 3: Create `ubuntils/tui/results_screen.py`**

```python
from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Header, Static, TabbedContent, TabPane

from ubuntils.detectors.finding import Finding
from ubuntils.timeline.builder import TimelineEvent
from ubuntils.tui.findings_panel import FindingsPanel
from ubuntils.tui.stats_panel import StatsPanel
from ubuntils.tui.summary_screen import _build_summary
from ubuntils.tui.timeline_panel import TimelinePanel


class ResultsScreen(Screen):
    BINDINGS = [
        Binding("1", "show('summary')", "Summary"),
        Binding("2", "show('findings')", "Findings"),
        Binding("3", "show('timeline')", "Timeline"),
        Binding("4", "show('stats')", "Stats"),
        Binding("q", "quit_app", "Quit"),
    ]

    DEFAULT_CSS = """
    ResultsScreen TabPane {
        height: 1fr;
        padding: 0;
    }
    ResultsScreen #summary-body {
        margin: 1 2;
    }
    """

    def __init__(
        self,
        findings: list[Finding],
        timeline: list[TimelineEvent],
        stats: dict,
    ) -> None:
        super().__init__()
        self._findings = findings
        self._timeline = timeline
        self._stats = stats

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(initial="summary"):
            with TabPane("Summary", id="summary"):
                yield Static(
                    Text(_build_summary(self._findings, self._timeline, self._stats)),
                    id="summary-body",
                )
            with TabPane("Findings", id="findings"):
                yield FindingsPanel(self._findings)
            with TabPane("Timeline", id="timeline"):
                yield TimelinePanel(self._timeline)
            with TabPane("Stats", id="stats"):
                yield StatsPanel(self._stats)
        yield Footer()

    def action_show(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id

    def action_quit_app(self) -> None:
        self.app.exit()
```

- [ ] **Step 4: Run tests to confirm pass**

Run: `python -m pytest tests/test_tui.py -k results_screen -v --no-cov`
Expected: 4 PASSED.

- [ ] **Step 5: Commit**

```bash
git add ubuntils/tui/results_screen.py tests/test_tui.py
git commit -m "feat: add tabbed ResultsScreen (Summary/Findings/Timeline/Stats)"
```

---

### Task 4: Wire `ScanScreen`/`ResultsScreen` into `UbuntilsApp`; remove `MainScreen`

**Files:**
- Modify: `ubuntils/tui/app.py`
- Test: `tests/test_tui.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_tui.py`:

```python
async def test_app_scan_screen_lists_collectors_on_mount():
    import threading
    proceed = threading.Event()

    def _override():
        proceed.wait(timeout=5.0)
        return ([], [], _stats())

    async with UbuntilsApp(_scan_override=_override).run_test() as pilot:
        assert isinstance(pilot.app.screen, ScanScreen)
        body = str(pilot.app.query_one("#checklist", Static).renderable)
        assert "Process" in body
        proceed.set()
        await pilot.pause(delay=0.2)


async def test_app_transitions_to_results_screen():
    def _override():
        return ([], [], _stats())

    async with UbuntilsApp(_scan_override=_override).run_test(size=(100, 30)) as pilot:
        await pilot.pause(delay=0.5)
        assert isinstance(pilot.app.screen, ResultsScreen)
```

- [ ] **Step 2: Run to confirm they fail**

Run: `python -m pytest tests/test_tui.py::test_app_scan_screen_lists_collectors_on_mount tests/test_tui.py::test_app_transitions_to_results_screen -v --no-cov`
Expected: FAIL — `ScanScreen()` is constructed without `collector_names`; app still switches to `SummaryScreen`.

- [ ] **Step 3: Edit `ubuntils/tui/app.py`**

3a. Update imports. Replace:

```python
from ubuntils.tui.scan_screen import ScanScreen
from ubuntils.tui.stats_panel import StatsPanel, get_ubuntu_version
from ubuntils.tui.summary_screen import SummaryScreen
from ubuntils.tui.timeline_panel import TimelinePanel
```

with:

```python
from ubuntils.tui.results_screen import ResultsScreen
from ubuntils.tui.scan_screen import ScanScreen
from ubuntils.tui.stats_panel import get_ubuntu_version
```

(After this, `FindingsPanel`, `StatsPanel`, `TimelinePanel`, `ContentSwitcher`, `Header`, `Footer`, and `Binding` are only used by `MainScreen`, which is removed in 3b — remove their imports too. The remaining widget import line becomes unnecessary; delete `from textual.widgets import ContentSwitcher, Footer, Header` and the `from textual.binding import Binding` and `from textual.screen import Screen` lines, and the `FindingsPanel` import.)

3b. Delete the entire `class MainScreen(Screen):` definition.

3c. Replace `on_mount`:

```python
    def on_mount(self) -> None:
        self.push_screen(
            ScanScreen(collector_names=[C.__name__ for C in ALL_COLLECTORS])
        )
        self._run_scan()
```

3d. Replace `on_collector_progress`:

```python
    def on_collector_progress(self, message: CollectorProgress) -> None:
        screen = self.screen
        if isinstance(screen, ScanScreen):
            screen.mark(message.name, message.success)
```

3e. Replace `on_scan_complete`:

```python
    def on_scan_complete(self, message: ScanComplete) -> None:
        self.switch_screen(
            ResultsScreen(
                findings=message.findings,
                timeline=message.timeline,
                stats=message.stats,
            )
        )
```

After these edits, the only remaining top section of `app.py` is: module imports, `logger`, `CollectorProgress`, `ScanComplete`, and `UbuntilsApp`. `Finding`, `Severity`, `TimelineEvent`, `TimelineBuilder`, `DetectionEngine`, `platform`, `time`, `structlog`, `work`, `App`, `ComposeResult`, `Message` all stay (used by messages and `_run_scan`).

- [ ] **Step 4: Run the full TUI test file to surface every remaining break**

Run: `python -m pytest tests/test_tui.py --no-cov 2>&1 | grep -E "FAILED|ERROR|ImportError" | head -40`
Expected: failures only in the *old* tests that import/reference `MainScreen` or `SummaryScreen` (cleaned up in Task 5). The two new tests from Step 1 must pass:
Run: `python -m pytest tests/test_tui.py::test_app_scan_screen_lists_collectors_on_mount tests/test_tui.py::test_app_transitions_to_results_screen -v --no-cov`
Expected: 2 PASSED.

- [ ] **Step 5: Commit**

```bash
git add ubuntils/tui/app.py tests/test_tui.py
git commit -m "feat: wire ScanScreen checklist + ResultsScreen; remove MainScreen"
```

---

### Task 5: Clean up obsolete tests and update `__init__.py` exports

**Files:**
- Modify: `ubuntils/tui/__init__.py`
- Modify: `tests/test_tui.py`

- [ ] **Step 1: Update `ubuntils/tui/__init__.py`**

Replace the whole file with:

```python
from ubuntils.tui.app import UbuntilsApp
from ubuntils.tui.results_screen import ResultsScreen
from ubuntils.tui.scan_screen import ScanScreen

__all__ = ["UbuntilsApp", "ResultsScreen", "ScanScreen"]
```

- [ ] **Step 2: Fix the broken import line in `tests/test_tui.py`**

Find:

```python
from ubuntils.tui.app import CollectorProgress, MainScreen, ScanComplete, UbuntilsApp
from ubuntils.tui.scan_screen import ScanScreen
from ubuntils.tui.summary_screen import SummaryScreen
from textual.widgets import ContentSwitcher
```

Replace with:

```python
from ubuntils.tui.app import CollectorProgress, ScanComplete, UbuntilsApp
from ubuntils.tui.scan_screen import ScanScreen
```

(`ContentSwitcher` was only used by removed `MainScreen` tests; `TabbedContent` is imported in Task 3's test block; `ResultsScreen` is imported in Task 3's block.)

- [ ] **Step 3: Delete every obsolete test**

Delete these test functions entirely from `tests/test_tui.py` (they reference removed classes/behaviors):

- `test_scan_screen_ticker_updates`
- `test_scan_screen_ticker_marks_failed`
- `test_scan_screen_add_to_ticker`
- `test_main_screen_starts_on_findings_panel`
- `test_main_screen_key_2_switches_to_timeline`
- `test_main_screen_key_3_switches_to_stats`
- `test_main_screen_key_1_switches_back_to_findings`
- `test_main_screen_initial_panel_timeline`
- `test_main_screen_panels_fill_height`
- `test_main_screen_escape_pops_to_summary`
- `test_summary_screen_renders_stats`
- `test_summary_screen_clean_system_message`
- `test_summary_screen_shows_findings_list_when_not_empty`
- `test_summary_screen_no_clean_message_when_findings_exist`
- `test_summary_screen_importable_from_tui_package`
- `test_ubuntils_app_shows_scan_screen_on_mount`
- `test_ubuntils_app_transitions_to_summary_screen_after_scan`
- `test_ubuntils_app_passes_findings_to_summary_screen`

- [ ] **Step 4: Add the `ResultsScreen` export test**

Add to `tests/test_tui.py` (with the other export tests):

```python
def test_results_screen_importable_from_tui_package():
    from ubuntils.tui import ResultsScreen as _ResultsScreen
    assert _ResultsScreen is ResultsScreen
```

- [ ] **Step 5: Run the full TUI suite**

Run: `python -m pytest tests/test_tui.py --no-cov -v`
Expected: all PASS, no errors, no references to `MainScreen`/`SummaryScreen`.

- [ ] **Step 6: Commit**

```bash
git add ubuntils/tui/__init__.py tests/test_tui.py
git commit -m "test: drop MainScreen/SummaryScreen tests; export ResultsScreen"
```

---

### Task 6: Full suite, manual smoke check, CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Run the full suite with the coverage gate**

Run: `python -m pytest -q`
Expected: all PASS, coverage ≥ 80%. If `scan_screen.py`/`results_screen.py` drop coverage below the gate, add targeted tests (e.g. assert the spinner frame advances, or that `mark()` on the last row doesn't error).

- [ ] **Step 2: Confirm no stale references remain**

Run: `grep -rn "MainScreen\|SummaryScreen\|LoadingScreen\|ContentSwitcher" ubuntils/ tests/`
Expected: no output.

- [ ] **Step 3: Manual smoke check (headless)**

Run: `python -c "
import asyncio
from ubuntils.tui.app import UbuntilsApp
from ubuntils.tui.results_screen import ResultsScreen
async def m():
    app = UbuntilsApp(_scan_override=lambda: ([], [], {'collector_count':8,'collector_failures':0,'timeline_count':0,'duration_s':1.0,'finding_counts':{}}))
    async with app.run_test(size=(100,30)) as p:
        await p.pause(delay=0.4)
        assert isinstance(p.app.screen, ResultsScreen)
        for k in ('2','3','4','1'):
            await p.press(k); await p.pause()
        print('smoke OK')
asyncio.run(m())
"`
Expected: prints `smoke OK`.

- [ ] **Step 4: Update `CLAUDE.md`**

In the "Completed" section, update the Phase 13 line to:

```
- **Phase 13** — TUI redesign: ScanScreen live collector checklist (✓/✗ per row); single tabbed ResultsScreen (Summary/Findings/Timeline/Stats via keys 1–4, no screen stacking) replacing the SummaryScreen→MainScreen flow
```

Update "Current test count" to the new total from Step 1.

In "Known Bugs Fixed", add:

```
- **Confusing two-level TUI navigation** | `tui/app.py`, `tui/results_screen.py` | Replaced SummaryScreen→MainScreen push/pop (two redundant nav mechanisms) with a single ResultsScreen TabbedContent; keys 1–4 switch tabs in place, no Escape/back
```

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: record tabbed-nav + scan-checklist TUI redesign"
```

(`CLAUDE.md` is gitignored; the commit will be a no-op if so — that is expected, skip it then.)

---

## Self-Review

**Spec coverage:**
- Tabbed navigation (single `ResultsScreen`, keys 1–4, Tab/←→) → Task 3 + Task 4. ✓
- Scan live checklist (all rows, spinner, ✓/✗ in place) → Task 1. ✓
- Keep `_build_summary`, remove `SummaryScreen` class → Task 2. ✓
- Remove `MainScreen` → Task 4. ✓
- Exports updated → Task 5. ✓
- Pane height > 1 regression guard → Task 3 (`test_results_screen_panes_fill_height`). ✓
- Empty states (clean message) → Task 3 (`test_results_screen_summary_shows_clean_message`). ✓

**Type/name consistency:**
- `ScanScreen(collector_names=...)` and `.mark(name, success)` used consistently in Tasks 1, 4. ✓
- `ResultsScreen(findings, timeline, stats)` and `action_show(tab_id)` / `query_one(TabbedContent).active` consistent in Tasks 3, 4. ✓
- `#checklist` Static id (Task 1) and `#summary-body` Static id (Task 3) referenced consistently in tests. ✓
- `_build_summary` import path `ubuntils.tui.summary_screen` consistent (Tasks 2, 3). ✓

**Placeholder scan:** No TBD/TODO; every code step shows full code. ✓
