# TUI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current LoadingScreen→FindingsPanel flow with a Spinner scan screen → Summary dashboard → panel drill-down, and fix the blank-findings bug.

**Architecture:** Three screens in sequence: `ScanScreen` (spinner + ticker) → `SummaryScreen` (stats + finding counts, always shown) → `MainScreen` (three panels, pushed on top). `SummaryScreen` is the fix for the blank-findings bug — it always shows scan results clearly whether findings exist or not.

**Tech Stack:** Python 3.11+, Textual ≥ 0.50.0, pytest + pytest-asyncio for TUI tests.

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Create | `ubuntils/tui/scan_screen.py` | `ScanScreen` — spinner + collector ticker |
| Create | `ubuntils/tui/summary_screen.py` | `SummaryScreen` — stats + findings summary + panel nav |
| Modify | `ubuntils/tui/app.py` | Wire new screens; update `UbuntilsApp` and `MainScreen` |
| Modify | `ubuntils/tui/__init__.py` | Export new screens |
| Modify | `tests/test_tui.py` | Update broken imports; add tests for new screens |

---

### Task 1: ScanScreen — spinner + collector ticker

**Files:**
- Create: `ubuntils/tui/scan_screen.py`
- Test: `tests/test_tui.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_tui.py`:

```python
from ubuntils.tui.scan_screen import ScanScreen

async def test_scan_screen_renders():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield ScanScreen()

    async with _App().run_test() as pilot:
        await pilot.pause()
        # ScanScreen must render without error
        assert pilot.app.query_one(ScanScreen) is not None


async def test_scan_screen_ticker_updates():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield ScanScreen()

    async with _App().run_test() as pilot:
        await pilot.pause()
        screen = pilot.app.query_one(ScanScreen)
        screen.add_to_ticker("ProcessCollector", success=True)
        await pilot.pause()
        ticker_text = pilot.app.query_one("#ticker", Static).renderable
        assert "ProcessCollector" in str(ticker_text)


async def test_scan_screen_ticker_marks_failed():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield ScanScreen()

    async with _App().run_test() as pilot:
        await pilot.pause()
        screen = pilot.app.query_one(ScanScreen)
        screen.add_to_ticker("CronCollector", success=False)
        await pilot.pause()
        ticker_text = str(pilot.app.query_one("#ticker", Static).renderable)
        assert "✗" in ticker_text
```

- [ ] **Step 2: Run to confirm they fail**

```bash
python -m pytest tests/test_tui.py::test_scan_screen_renders tests/test_tui.py::test_scan_screen_ticker_updates tests/test_tui.py::test_scan_screen_ticker_marks_failed -v --no-cov
```

Expected: `ImportError` or `ModuleNotFoundError` for `scan_screen`.

- [ ] **Step 3: Create `ubuntils/tui/scan_screen.py`**

```python
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
```

- [ ] **Step 4: Run tests to confirm pass**

```bash
python -m pytest tests/test_tui.py::test_scan_screen_renders tests/test_tui.py::test_scan_screen_ticker_updates tests/test_tui.py::test_scan_screen_ticker_marks_failed -v --no-cov
```

Expected: 3 PASSED.

- [ ] **Step 5: Commit**

```bash
git add ubuntils/tui/scan_screen.py tests/test_tui.py
git commit -m "feat: add ScanScreen with spinner and collector ticker"
```

---

### Task 2: SummaryScreen — stats + findings summary + panel nav

**Files:**
- Create: `ubuntils/tui/summary_screen.py`
- Test: `tests/test_tui.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_tui.py`:

```python
from ubuntils.tui.summary_screen import SummaryScreen


async def test_summary_screen_renders_stats():
    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(SummaryScreen(
                findings=[],
                timeline=[],
                stats=_stats(high=0, medium=0, low=0, timeline_count=42),
            ))

    async with _App().run_test() as pilot:
        await pilot.pause()
        content = pilot.app.screen.query_one("#summary-body", Static).renderable
        assert "8 run" in str(content)
        assert "42" in str(content)


async def test_summary_screen_clean_system_message():
    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(SummaryScreen(findings=[], timeline=[], stats=_stats(high=0, medium=0, low=0)))

    async with _App().run_test() as pilot:
        await pilot.pause()
        content = str(pilot.app.screen.query_one("#summary-body", Static).renderable)
        assert "System appears clean" in content


async def test_summary_screen_shows_findings_list_when_not_empty():
    findings = [_finding("CRON_TMP_PATH", Severity.HIGH)]

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(SummaryScreen(
                findings=findings,
                timeline=[],
                stats=_stats(high=1, medium=0, low=0),
            ))

    async with _App().run_test() as pilot:
        await pilot.pause()
        content = str(pilot.app.screen.query_one("#summary-body", Static).renderable)
        assert "CRON_TMP_PATH" in content


async def test_summary_screen_no_clean_message_when_findings_exist():
    findings = [_finding("CRON_TMP_PATH", Severity.HIGH)]

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(SummaryScreen(
                findings=findings,
                timeline=[],
                stats=_stats(high=1, medium=0, low=0),
            ))

    async with _App().run_test() as pilot:
        await pilot.pause()
        content = str(pilot.app.screen.query_one("#summary-body", Static).renderable)
        assert "System appears clean" not in content
```

- [ ] **Step 2: Run to confirm they fail**

```bash
python -m pytest tests/test_tui.py::test_summary_screen_renders_stats tests/test_tui.py::test_summary_screen_clean_system_message tests/test_tui.py::test_summary_screen_shows_findings_list_when_not_empty tests/test_tui.py::test_summary_screen_no_clean_message_when_findings_exist -v --no-cov
```

Expected: `ImportError` for `summary_screen`.

- [ ] **Step 3: Create `ubuntils/tui/summary_screen.py`**

```python
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from ubuntils.detectors.finding import Finding, Severity
from ubuntils.timeline.builder import TimelineEvent

_SEV_BULLET = {Severity.HIGH: "●", Severity.MEDIUM: "○", Severity.LOW: "○"}
_SEV_LABEL = {Severity.HIGH: "HIGH", Severity.MEDIUM: "MED ", Severity.LOW: "LOW "}
_MAX_FINDINGS_SHOWN = 5


def _build_summary(
    findings: list[Finding],
    timeline: list[TimelineEvent],
    stats: dict,
) -> str:
    fc = stats.get("finding_counts", {})
    failures = stats.get("collector_failures", 0)
    collector_count = stats.get("collector_count", 0)
    duration = stats.get("duration_s", 0.0)
    timeline_count = stats.get("timeline_count", len(timeline))

    lines = [
        f"Collectors:  {collector_count} run · {failures} failed",
        f"Findings:    {fc.get('HIGH', 0)} HIGH · {fc.get('MEDIUM', 0)} MEDIUM · {fc.get('LOW', 0)} LOW",
        f"Timeline:    {timeline_count} events",
        f"Duration:    {duration:.1f}s",
        "",
    ]

    if findings:
        shown = findings[:_MAX_FINDINGS_SHOWN]
        for f in shown:
            bullet = _SEV_BULLET[f.severity]
            sev = _SEV_LABEL[f.severity]
            rule = f"{f.rule_id[:22]:<22}"
            path = f.artifact_path[:30]
            lines.append(f"  {bullet} {sev}  {rule}  {path}")
        if len(findings) > _MAX_FINDINGS_SHOWN:
            lines.append(f"  … and {len(findings) - _MAX_FINDINGS_SHOWN} more")
    else:
        lines.append("  System appears clean.")

    return "\n".join(lines)


class SummaryScreen(Screen):
    BINDINGS = [
        Binding("1", "open_findings", "Findings"),
        Binding("2", "open_timeline", "Timeline"),
        Binding("3", "open_stats", "Stats"),
        Binding("q", "quit_app", "Quit"),
    ]

    DEFAULT_CSS = """
    SummaryScreen {
        layout: vertical;
    }
    SummaryScreen #summary-body {
        margin: 2 4;
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
        yield Static(
            Text(_build_summary(self._findings, self._timeline, self._stats)),
            id="summary-body",
        )
        yield Footer()

    def action_open_findings(self) -> None:
        from ubuntils.tui.app import MainScreen
        self.app.push_screen(
            MainScreen(self._findings, self._timeline, self._stats, initial_panel="findings")
        )

    def action_open_timeline(self) -> None:
        from ubuntils.tui.app import MainScreen
        self.app.push_screen(
            MainScreen(self._findings, self._timeline, self._stats, initial_panel="timeline")
        )

    def action_open_stats(self) -> None:
        from ubuntils.tui.app import MainScreen
        self.app.push_screen(
            MainScreen(self._findings, self._timeline, self._stats, initial_panel="stats")
        )

    def action_quit_app(self) -> None:
        self.app.exit()
```

- [ ] **Step 4: Run tests to confirm pass**

```bash
python -m pytest tests/test_tui.py::test_summary_screen_renders_stats tests/test_tui.py::test_summary_screen_clean_system_message tests/test_tui.py::test_summary_screen_shows_findings_list_when_not_empty tests/test_tui.py::test_summary_screen_no_clean_message_when_findings_exist -v --no-cov
```

Expected: 4 PASSED.

- [ ] **Step 5: Commit**

```bash
git add ubuntils/tui/summary_screen.py tests/test_tui.py
git commit -m "feat: add SummaryScreen with stats and findings summary"
```

---

### Task 3: Update app.py — wire new screens into UbuntilsApp and MainScreen

**Files:**
- Modify: `ubuntils/tui/app.py`
- Test: `tests/test_tui.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_tui.py`:

```python
from ubuntils.tui.scan_screen import ScanScreen
from ubuntils.tui.summary_screen import SummaryScreen


async def test_ubuntils_app_shows_scan_screen_on_mount():
    import threading
    proceed = threading.Event()

    def _override():
        proceed.wait(timeout=5.0)
        return ([], [], _stats())

    async with UbuntilsApp(_scan_override=_override).run_test() as pilot:
        assert isinstance(pilot.app.screen, ScanScreen)
        proceed.set()
        await pilot.pause(delay=0.2)


async def test_ubuntils_app_transitions_to_summary_screen_after_scan():
    def _override():
        return ([], [], _stats())

    async with UbuntilsApp(_scan_override=_override).run_test() as pilot:
        await pilot.pause(delay=0.5)
        assert isinstance(pilot.app.screen, SummaryScreen)


async def test_main_screen_initial_panel_timeline():
    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(
                MainScreen(findings=[], timeline=[], stats=_stats(), initial_panel="timeline")
            )

    async with _App().run_test() as pilot:
        await pilot.pause()
        switcher = pilot.app.screen.query_one(ContentSwitcher)
        assert switcher.current == "timeline"


async def test_main_screen_escape_pops_to_summary():
    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(SummaryScreen(findings=[], timeline=[], stats=_stats()))

    async with _App().run_test() as pilot:
        await pilot.pause()
        await pilot.app.push_screen(
            MainScreen(findings=[], timeline=[], stats=_stats(), initial_panel="findings")
        )
        await pilot.pause()
        assert isinstance(pilot.app.screen, MainScreen)
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(pilot.app.screen, SummaryScreen)
```

- [ ] **Step 2: Run to confirm they fail**

```bash
python -m pytest tests/test_tui.py::test_ubuntils_app_shows_scan_screen_on_mount tests/test_tui.py::test_ubuntils_app_transitions_to_summary_screen_after_scan tests/test_tui.py::test_main_screen_initial_panel_timeline tests/test_tui.py::test_main_screen_escape_pops_to_summary -v --no-cov
```

Expected: failures — `ScanScreen` not used, `MainScreen` has no `initial_panel`, no escape binding.

- [ ] **Step 3: Replace `LoadingScreen` with `ScanScreen`, update `MainScreen`, wire `SummaryScreen` in `UbuntilsApp`**

Replace the full contents of `ubuntils/tui/app.py`:

```python
from __future__ import annotations

import platform
import time

import structlog
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.message import Message
from textual.screen import Screen
from textual.widgets import ContentSwitcher, Footer, Header

from ubuntils.collectors import ALL_COLLECTORS
from ubuntils.detectors.engine import DetectionEngine
from ubuntils.detectors.finding import Finding, Severity
from ubuntils.timeline.builder import TimelineBuilder, TimelineEvent
from ubuntils.tui.findings_panel import FindingsPanel
from ubuntils.tui.scan_screen import ScanScreen
from ubuntils.tui.stats_panel import StatsPanel, get_ubuntu_version
from ubuntils.tui.summary_screen import SummaryScreen
from ubuntils.tui.timeline_panel import TimelinePanel

logger = structlog.get_logger()


class CollectorProgress(Message):
    def __init__(self, name: str, index: int, total: int, success: bool = True) -> None:
        self.name = name
        self.index = index
        self.total = total
        self.success = success
        super().__init__()


class ScanComplete(Message):
    def __init__(
        self,
        findings: list[Finding],
        timeline: list[TimelineEvent],
        stats: dict,
    ) -> None:
        self.findings = findings
        self.timeline = timeline
        self.stats = stats
        super().__init__()


class MainScreen(Screen):
    BINDINGS = [
        Binding("1", "switch_to_findings", "Findings"),
        Binding("2", "switch_to_timeline", "Timeline"),
        Binding("3", "switch_to_stats", "Stats"),
        Binding("escape", "go_back", "Back"),
        Binding("q", "quit_app", "Quit"),
    ]

    def __init__(
        self,
        findings: list[Finding],
        timeline: list[TimelineEvent],
        stats: dict,
        initial_panel: str = "findings",
    ) -> None:
        super().__init__()
        self._findings = findings
        self._timeline = timeline
        self._stats = stats
        self._initial_panel = initial_panel

    def compose(self) -> ComposeResult:
        fc = self._stats.get("finding_counts", {})
        tl_count = self._stats.get("timeline_count", len(self._timeline))
        yield Header()
        with ContentSwitcher(initial=self._initial_panel):
            yield FindingsPanel(self._findings, id="findings")
            yield TimelinePanel(self._timeline, id="timeline")
            yield StatsPanel(self._stats, id="stats")
        yield Footer()

    def action_switch_to_findings(self) -> None:
        self.query_one(ContentSwitcher).current = "findings"

    def action_switch_to_timeline(self) -> None:
        self.query_one(ContentSwitcher).current = "timeline"

    def action_switch_to_stats(self) -> None:
        self.query_one(ContentSwitcher).current = "stats"

    def action_go_back(self) -> None:
        self.app.pop_screen()

    def action_quit_app(self) -> None:
        self.app.exit()


class UbuntilsApp(App):
    TITLE = "ubuntils"

    def __init__(self, verbose: bool = False, _scan_override=None) -> None:
        super().__init__()
        self._verbose = verbose
        self._scan_override = _scan_override

    def on_mount(self) -> None:
        self.push_screen(ScanScreen())
        self._run_scan()

    @work(thread=True)
    def _run_scan(self) -> None:
        if self._scan_override is not None:
            findings, timeline, stats = self._scan_override()
            self.post_message(ScanComplete(findings=findings, timeline=timeline, stats=stats))
            return

        start = time.monotonic()
        artifacts: dict = {}
        failures = 0
        collectors = [C() for C in ALL_COLLECTORS]

        for i, collector in enumerate(collectors):
            name = type(collector).__name__
            success = True
            try:
                result = collector.collect()
                artifacts.update(result)
            except Exception as exc:
                logger.error("collector_failed", name=name, error=str(exc))
                failures += 1
                success = False
            self.post_message(
                CollectorProgress(name=name, index=i + 1, total=len(collectors), success=success)
            )

        try:
            findings = DetectionEngine().run(artifacts)
            timeline = TimelineBuilder().build()
        except Exception as exc:
            logger.error("scan_engine_failed", error=str(exc))
            findings = []
            timeline = []

        duration = time.monotonic() - start

        stats = {
            "ubuntu_version": get_ubuntu_version(),
            "architecture": platform.machine(),
            "duration_s": duration,
            "collector_count": len(collectors),
            "collector_failures": failures,
            "finding_counts": {
                "HIGH": sum(1 for f in findings if f.severity == Severity.HIGH),
                "MEDIUM": sum(1 for f in findings if f.severity == Severity.MEDIUM),
                "LOW": sum(1 for f in findings if f.severity == Severity.LOW),
            },
            "timeline_count": len(timeline),
        }
        self.post_message(
            ScanComplete(findings=findings, timeline=timeline, stats=stats)
        )

    def on_collector_progress(self, message: CollectorProgress) -> None:
        screen = self.screen
        if isinstance(screen, ScanScreen):
            screen.add_to_ticker(message.name, message.success)

    def on_scan_complete(self, message: ScanComplete) -> None:
        self.switch_screen(
            SummaryScreen(
                findings=message.findings,
                timeline=message.timeline,
                stats=message.stats,
            )
        )
```

- [ ] **Step 4: Run the new tests**

```bash
python -m pytest tests/test_tui.py::test_ubuntils_app_shows_scan_screen_on_mount tests/test_tui.py::test_ubuntils_app_transitions_to_summary_screen_after_scan tests/test_tui.py::test_main_screen_initial_panel_timeline tests/test_tui.py::test_main_screen_escape_pops_to_summary -v --no-cov
```

Expected: 4 PASSED.

- [ ] **Step 5: Commit**

```bash
git add ubuntils/tui/app.py tests/test_tui.py
git commit -m "feat: wire ScanScreen and SummaryScreen into UbuntilsApp"
```

---

### Task 4: Fix broken existing tests and update imports

**Files:**
- Modify: `tests/test_tui.py`

The existing tests import `LoadingScreen` from `ubuntils.tui.app` and test transitions to `MainScreen`. These must be updated because:
- `LoadingScreen` no longer exists — replaced by `ScanScreen`
- After scan, app transitions to `SummaryScreen` not `MainScreen`

- [ ] **Step 1: Identify all broken imports and tests**

```bash
python -m pytest tests/test_tui.py --no-cov 2>&1 | grep -E "FAILED|ERROR|ImportError"
```

- [ ] **Step 2: Fix the broken import line in `tests/test_tui.py`**

Find this line:
```python
from ubuntils.tui.app import CollectorProgress, LoadingScreen, MainScreen, ScanComplete, UbuntilsApp
```

Replace with:
```python
from ubuntils.tui.app import CollectorProgress, MainScreen, ScanComplete, UbuntilsApp
from ubuntils.tui.scan_screen import ScanScreen
from ubuntils.tui.summary_screen import SummaryScreen
```

- [ ] **Step 3: Replace the LoadingScreen test with a ScanScreen test**

Find and remove:
```python
async def test_loading_screen_updates_progress():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield LoadingScreen()

    async with _App().run_test() as pilot:
        await pilot.pause()
        screen = pilot.app.query_one(LoadingScreen)
        screen.update_progress("CronCollector", 1, 8)
        await pilot.pause()
        label_text = pilot.app.query_one("#status", Label).content
        assert "1/8" in label_text
```

Replace with:
```python
async def test_scan_screen_add_to_ticker():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield ScanScreen()

    async with _App().run_test() as pilot:
        await pilot.pause()
        screen = pilot.app.query_one(ScanScreen)
        screen.add_to_ticker("CronCollector", success=True)
        await pilot.pause()
        ticker = str(pilot.app.query_one("#ticker", Static).renderable)
        assert "CronCollector" in ticker
```

- [ ] **Step 4: Update the two UbuntilsApp integration tests that check for MainScreen**

Find:
```python
async def test_ubuntils_app_shows_loading_screen_on_mount():
    import threading
    proceed = threading.Event()

    def _override():
        proceed.wait(timeout=5.0)
        return ([], [], _stats())

    async with UbuntilsApp(_scan_override=_override).run_test() as pilot:
        assert isinstance(pilot.app.screen, LoadingScreen)
        proceed.set()
        await pilot.pause(delay=0.2)


async def test_ubuntils_app_transitions_to_main_screen_after_scan():
    def _override():
        return ([], [], _stats())

    async with UbuntilsApp(_scan_override=_override).run_test() as pilot:
        await pilot.pause(delay=0.5)
        assert isinstance(pilot.app.screen, MainScreen)


async def test_ubuntils_app_passes_findings_to_main_screen():
    findings = [_finding("CRON_TMP_PATH", Severity.HIGH)]

    def _override():
        return (findings, [], _stats(high=1, medium=0, low=0))

    async with UbuntilsApp(_scan_override=_override).run_test() as pilot:
        await pilot.pause(delay=0.5)
        screen = pilot.app.screen
        assert isinstance(screen, MainScreen)
        lv = pilot.app.screen.query_one(ListView)
        assert len(lv.children) == 1
```

Replace with:
```python
async def test_ubuntils_app_shows_scan_screen_on_mount_initially():
    import threading
    proceed = threading.Event()

    def _override():
        proceed.wait(timeout=5.0)
        return ([], [], _stats())

    async with UbuntilsApp(_scan_override=_override).run_test() as pilot:
        assert isinstance(pilot.app.screen, ScanScreen)
        proceed.set()
        await pilot.pause(delay=0.2)


async def test_ubuntils_app_transitions_to_summary_screen_after_scan():
    def _override():
        return ([], [], _stats())

    async with UbuntilsApp(_scan_override=_override).run_test() as pilot:
        await pilot.pause(delay=0.5)
        assert isinstance(pilot.app.screen, SummaryScreen)


async def test_ubuntils_app_passes_findings_to_summary_screen():
    findings = [_finding("CRON_TMP_PATH", Severity.HIGH)]

    def _override():
        return (findings, [], _stats(high=1, medium=0, low=0))

    async with UbuntilsApp(_scan_override=_override).run_test() as pilot:
        await pilot.pause(delay=0.5)
        assert isinstance(pilot.app.screen, SummaryScreen)
        content = str(pilot.app.screen.query_one("#summary-body", Static).renderable)
        assert "CRON_TMP_PATH" in content
```

- [ ] **Step 5: Remove unused `Label` import if no longer needed**

Check top of `tests/test_tui.py` for:
```python
from textual.widgets import Label, ListView, Static
```

`Label` is still used in `test_findings_panel_first_row_is_high` — keep it.

- [ ] **Step 6: Run all TUI tests**

```bash
python -m pytest tests/test_tui.py --no-cov -v
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add tests/test_tui.py
git commit -m "test: update TUI tests for ScanScreen and SummaryScreen"
```

---

### Task 5: Update `tui/__init__.py` exports and run full suite

**Files:**
- Modify: `ubuntils/tui/__init__.py`
- Modify: `tests/test_tui.py`

- [ ] **Step 1: Check current exports**

```bash
cat ubuntils/tui/__init__.py
```

- [ ] **Step 2: Add new exports**

Open `ubuntils/tui/__init__.py`. Add `ScanScreen` and `SummaryScreen`:

```python
from ubuntils.tui.app import UbuntilsApp
from ubuntils.tui.scan_screen import ScanScreen
from ubuntils.tui.summary_screen import SummaryScreen

__all__ = ["UbuntilsApp", "ScanScreen", "SummaryScreen"]
```

- [ ] **Step 3: Add export test**

Add to `tests/test_tui.py`:

```python
def test_scan_screen_importable_from_tui_package():
    from ubuntils.tui import ScanScreen as _ScanScreen
    assert _ScanScreen is ScanScreen


def test_summary_screen_importable_from_tui_package():
    from ubuntils.tui import SummaryScreen as _SummaryScreen
    assert _SummaryScreen is SummaryScreen
```

- [ ] **Step 4: Run the full test suite with coverage gate**

```bash
python -m pytest -q
```

Expected: all pass, coverage ≥ 80%.

If coverage drops below 80%, add targeted tests for uncovered lines in the new files.

- [ ] **Step 5: Commit**

```bash
git add ubuntils/tui/__init__.py tests/test_tui.py
git commit -m "feat: export ScanScreen and SummaryScreen from tui package"
```

---

### Task 6: Update CLAUDE.md and push

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update CLAUDE.md**

In the "Completed" section add:
```
- **Phase 13** — TUI redesign: ScanScreen (spinner + ticker), SummaryScreen (stats dashboard, fix for blank-findings bug on clean systems), MainScreen back-navigation via Escape
```

In "Known Bugs Fixed" add:
```
- **Blank findings panel on clean systems** | `tui/app.py` transition | Added `SummaryScreen` between `ScanScreen` and `MainScreen`; always displays full scan stats and "System appears clean." when findings list is empty
```

Update "Current test count" to reflect new total.

- [ ] **Step 2: Push everything**

```bash
git push
```
