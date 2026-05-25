# ubuntils TUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the Textual TUI — `LoadingScreen`, `MainScreen`, `FindingsPanel`, `TimelinePanel`, `StatsPanel`, and `UbuntilsApp` with a scan worker.

**Architecture:** `UbuntilsApp` starts, pushes `LoadingScreen`, fires a background worker that runs all 8 collectors → detection → timeline, posting `CollectorProgress` after each collector and `ScanComplete` when done. On `ScanComplete`, the app switches to `MainScreen`, which contains a `ContentSwitcher` wrapping the three panels. Keys `1`/`2`/`3` switch panels; `q` quits.

**Tech Stack:** Python 3.11, Textual ≥ 0.50, pytest, pytest-asyncio ≥ 0.21, pytest-cov.

---

## File Map

| Action | Path | Purpose |
|---|---|---|
| Create | `ubuntils/tui/app.py` | `UbuntilsApp`, `LoadingScreen`, `MainScreen`, `CollectorProgress`, `ScanComplete` |
| Create | `ubuntils/tui/findings_panel.py` | `FindingsPanel`, `sort_findings()`, `format_detail()` |
| Create | `ubuntils/tui/timeline_panel.py` | `TimelinePanel` |
| Create | `ubuntils/tui/stats_panel.py` | `StatsPanel`, `format_stats()`, `get_ubuntu_version()` |
| Modify | `ubuntils/tui/__init__.py` | Export `UbuntilsApp` |
| Create | `tests/test_tui.py` | All TUI tests |
| Modify | `requirements.txt` | Add `pytest-asyncio>=0.21` |
| Create | `pytest.ini` | Set `asyncio_mode = auto` |

---

## Task 1: Dev setup — pytest-asyncio and pytest.ini

Textual's test harness (`app.run_test()`) is async. We need `pytest-asyncio` to run async tests.

**Files:**
- Modify: `requirements.txt`
- Create: `pytest.ini`

- [ ] **Step 1: Add pytest-asyncio to requirements.txt**

Open `requirements.txt`. It currently ends with `pytest-cov>=4.0`. Add one line:

```
click>=8.1.0
textual>=0.50.0
structlog>=24.0.0
pyyaml>=6.0
python-dateutil>=2.8
pytest>=7.0
pytest-cov>=4.0
pytest-asyncio>=0.21
```

- [ ] **Step 2: Install the new dependency**

```bash
pip install pytest-asyncio>=0.21
```

Expected: installs without errors.

- [ ] **Step 3: Create pytest.ini**

Create `/Users/asmitdesai/Portfolio/ubuntils/pytest.ini`:

```ini
[pytest]
asyncio_mode = auto
```

- [ ] **Step 4: Verify existing tests still pass**

```bash
python -m pytest --tb=short -q
```

Expected: `137 passed`

---

## Task 2: Pure helper functions — sort_findings, format_detail, format_stats

These have no Textual dependency. Write and test them first so later widget tasks can rely on them.

**Files:**
- Create: `ubuntils/tui/findings_panel.py` (functions only, no widget yet)
- Create: `ubuntils/tui/stats_panel.py` (functions only, no widget yet)
- Create: `tests/test_tui.py`

- [ ] **Step 1: Write failing tests for sort_findings and format_detail**

Create `tests/test_tui.py`:

```python
import datetime
import platform

import pytest

from ubuntils.detectors.finding import Finding, Severity
from ubuntils.timeline.builder import TimelineEvent
from ubuntils.tui.findings_panel import format_detail, sort_findings
from ubuntils.tui.stats_panel import format_stats


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(rule_id="CRON_TMP_PATH", severity=Severity.HIGH, description="desc",
             artifact_path="/etc/cron.d/evil", raw_value="bad line",
             remediation_available=True, remediation_description=None):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title="Test",
        description=description,
        artifact_path=artifact_path,
        raw_value=raw_value,
        remediation_available=remediation_available,
        remediation_description=remediation_description,
    )


def _stats(ubuntu_version="Ubuntu 22.04.3 LTS", architecture="x86_64",
           duration_s=2.4, collector_count=8, collector_failures=0,
           high=2, medium=1, low=1, timeline_count=47):
    return {
        "ubuntu_version": ubuntu_version,
        "architecture": architecture,
        "duration_s": duration_s,
        "collector_count": collector_count,
        "collector_failures": collector_failures,
        "finding_counts": {"HIGH": high, "MEDIUM": medium, "LOW": low},
        "timeline_count": timeline_count,
    }


# ---------------------------------------------------------------------------
# sort_findings
# ---------------------------------------------------------------------------

def test_sort_findings_high_before_medium_before_low():
    findings = [
        _finding("A", Severity.LOW),
        _finding("B", Severity.HIGH),
        _finding("C", Severity.MEDIUM),
    ]
    result = sort_findings(findings)
    assert result[0].severity == Severity.HIGH
    assert result[1].severity == Severity.MEDIUM
    assert result[2].severity == Severity.LOW


def test_sort_findings_empty_list():
    assert sort_findings([]) == []


def test_sort_findings_all_same_severity_preserves_input_order():
    findings = [_finding("A", Severity.HIGH), _finding("B", Severity.HIGH)]
    result = sort_findings(findings)
    assert [f.rule_id for f in result] == ["A", "B"]


# ---------------------------------------------------------------------------
# format_detail
# ---------------------------------------------------------------------------

def test_format_detail_includes_description_path_raw():
    f = _finding(
        description="A cron job runs from /tmp",
        artifact_path="/etc/cron.d/evil",
        raw_value="* * * * * root /tmp/evil.sh",
        remediation_available=True,
        remediation_description="Remove the cron entry",
    )
    detail = format_detail(f)
    assert "A cron job runs from /tmp" in detail
    assert "/etc/cron.d/evil" in detail
    assert "* * * * * root /tmp/evil.sh" in detail
    assert "Remove the cron entry" in detail


def test_format_detail_no_remediation_description():
    f = _finding(remediation_available=True, remediation_description=None)
    detail = format_detail(f)
    assert "available" in detail.lower()


def test_format_detail_remediation_not_available():
    f = _finding(remediation_available=False)
    detail = format_detail(f)
    assert "not available" in detail.lower()


# ---------------------------------------------------------------------------
# format_stats
# ---------------------------------------------------------------------------

def test_format_stats_all_fields_present():
    text = format_stats(_stats())
    assert "Ubuntu 22.04.3 LTS" in text
    assert "x86_64" in text
    assert "2.4s" in text
    assert "8 (0 failed)" in text
    assert "2 HIGH" in text
    assert "1 MEDIUM" in text
    assert "1 LOW" in text
    assert "47" in text


def test_format_stats_nonzero_failures():
    text = format_stats(_stats(collector_failures=2))
    assert "2 failed" in text
```

- [ ] **Step 2: Run to confirm import errors (tests fail for right reason)**

```bash
python -m pytest tests/test_tui.py -x --tb=short 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'ubuntils.tui.findings_panel'`

- [ ] **Step 3: Create ubuntils/tui/findings_panel.py with pure functions only**

```python
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
```

- [ ] **Step 4: Create ubuntils/tui/stats_panel.py with pure functions only**

```python
import platform


def get_ubuntu_version() -> str:
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "Unknown"


def format_stats(stats: dict) -> str:
    fc = stats.get("finding_counts", {})
    return "\n".join([
        f"Ubuntu Version:   {stats.get('ubuntu_version', 'Unknown')}",
        f"Architecture:     {stats.get('architecture', platform.machine())}",
        f"Scan Duration:    {stats.get('duration_s', 0):.1f}s",
        f"Collectors run:   {stats.get('collector_count', 0)} ({stats.get('collector_failures', 0)} failed)",
        f"Findings:         {fc.get('HIGH', 0)} HIGH  {fc.get('MEDIUM', 0)} MEDIUM  {fc.get('LOW', 0)} LOW",
        f"Timeline events:  {stats.get('timeline_count', 0)}",
    ])
```

- [ ] **Step 5: Run pure-function tests**

```bash
python -m pytest tests/test_tui.py -k "not async" --tb=short -q
```

Expected: `11 passed`

- [ ] **Step 6: Commit**

```bash
git add ubuntils/tui/findings_panel.py ubuntils/tui/stats_panel.py tests/test_tui.py requirements.txt pytest.ini
git commit -m "feat: add sort_findings, format_detail, format_stats helpers and tests"
```

---

## Task 3: StatsPanel widget

**Files:**
- Modify: `ubuntils/tui/stats_panel.py` (add widget class)
- Modify: `tests/test_tui.py` (add widget test)

- [ ] **Step 1: Write failing widget test — append to tests/test_tui.py**

Add at the bottom of `tests/test_tui.py`:

```python
# ---------------------------------------------------------------------------
# StatsPanel widget
# ---------------------------------------------------------------------------

from textual.app import App, ComposeResult
from textual.widgets import Static

from ubuntils.tui.stats_panel import StatsPanel


async def test_stats_panel_renders_all_fields():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield StatsPanel(_stats())

    async with _App().run_test() as pilot:
        await pilot.pause()
        rendered = str(pilot.app.query_one(Static).renderable)
        assert "Ubuntu 22.04.3 LTS" in rendered
        assert "x86_64" in rendered
        assert "2.4s" in rendered
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_tui.py::test_stats_panel_renders_all_fields --tb=short
```

Expected: `ImportError: cannot import name 'StatsPanel'`

- [ ] **Step 3: Add StatsPanel to ubuntils/tui/stats_panel.py**

Append to the existing file (keep the functions above):

```python
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static


class StatsPanel(Widget):
    def __init__(self, stats: dict) -> None:
        super().__init__()
        self._stats = stats

    def compose(self) -> ComposeResult:
        yield Static(format_stats(self._stats))
```

- [ ] **Step 4: Run the test**

```bash
python -m pytest tests/test_tui.py::test_stats_panel_renders_all_fields --tb=short
```

Expected: `1 passed`

- [ ] **Step 5: Run full suite**

```bash
python -m pytest --tb=short -q
```

Expected: all passing (137 + new tests)

- [ ] **Step 6: Commit**

```bash
git add ubuntils/tui/stats_panel.py tests/test_tui.py
git commit -m "feat: add StatsPanel widget"
```

---

## Task 4: TimelinePanel widget

**Files:**
- Create: `ubuntils/tui/timeline_panel.py`
- Modify: `tests/test_tui.py`

- [ ] **Step 1: Write failing test — append to tests/test_tui.py**

```python
# ---------------------------------------------------------------------------
# TimelinePanel widget
# ---------------------------------------------------------------------------

from textual.widgets import ListView

from ubuntils.tui.timeline_panel import TimelinePanel


def _event(source="syslog", description="test event", hour=14, minute=22, second=0):
    ts = datetime.datetime(2024, 1, 15, hour, minute, second, tzinfo=datetime.timezone.utc)
    return TimelineEvent(timestamp=ts, source=source, description=description)


async def test_timeline_panel_row_count_matches_events():
    events = [_event(description=f"event {i}") for i in range(5)]

    class _App(App):
        def compose(self) -> ComposeResult:
            yield TimelinePanel(events)

    async with _App().run_test() as pilot:
        await pilot.pause()
        lv = pilot.app.query_one(ListView)
        assert lv.item_count == 5


async def test_timeline_panel_empty_events():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield TimelinePanel([])

    async with _App().run_test() as pilot:
        await pilot.pause()
        lv = pilot.app.query_one(ListView)
        assert lv.item_count == 0
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_tui.py::test_timeline_panel_row_count_matches_events --tb=short
```

Expected: `ImportError: cannot import name 'TimelinePanel'`

- [ ] **Step 3: Create ubuntils/tui/timeline_panel.py**

```python
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Label, ListItem, ListView

from ubuntils.timeline.builder import TimelineEvent


class TimelinePanel(Widget):
    def __init__(self, timeline: list[TimelineEvent]) -> None:
        super().__init__()
        self._timeline = timeline

    def compose(self) -> ComposeResult:
        items = [
            ListItem(
                Label(
                    f"{e.timestamp.strftime('%H:%M:%S')}  "
                    f"{e.source:<12}  {e.description}"
                )
            )
            for e in self._timeline
        ]
        yield ListView(*items)
```

- [ ] **Step 4: Run the new tests**

```bash
python -m pytest tests/test_tui.py -k "timeline" --tb=short
```

Expected: `2 passed`

- [ ] **Step 5: Commit**

```bash
git add ubuntils/tui/timeline_panel.py tests/test_tui.py
git commit -m "feat: add TimelinePanel widget"
```

---

## Task 5: FindingsPanel widget

**Files:**
- Modify: `ubuntils/tui/findings_panel.py` (add widget class)
- Modify: `tests/test_tui.py`

- [ ] **Step 1: Write failing tests — append to tests/test_tui.py**

```python
# ---------------------------------------------------------------------------
# FindingsPanel widget
# ---------------------------------------------------------------------------

from textual.widgets import Static

from ubuntils.tui.findings_panel import FindingsPanel


def _findings_fixture():
    return [
        _finding("LOW_RULE", Severity.LOW, description="Low severity finding",
                 artifact_path="/home/alice/.bashrc", raw_value="export PATH=$PATH:/tmp"),
        _finding("HIGH_RULE", Severity.HIGH, description="High severity finding",
                 artifact_path="/etc/cron.d/evil", raw_value="* * * * * root /tmp/evil.sh",
                 remediation_description="Remove the cron entry"),
        _finding("MED_RULE", Severity.MEDIUM, description="Medium severity finding",
                 artifact_path="/home/alice/.ssh/authorized_keys",
                 raw_value="ssh-rsa AAAA evil"),
    ]


async def test_findings_panel_list_count_matches_findings():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(_findings_fixture())

    async with _App().run_test() as pilot:
        await pilot.pause()
        lv = pilot.app.query_one(ListView)
        assert lv.item_count == 3


async def test_findings_panel_first_row_is_high():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(_findings_fixture())

    async with _App().run_test() as pilot:
        await pilot.pause()
        lv = pilot.app.query_one(ListView)
        first_item = lv.children[0]
        first_label = str(first_item.query_one(Label).renderable)
        assert "HIGH" in first_label


async def test_findings_panel_detail_pane_shows_first_finding_on_mount():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield FindingsPanel(_findings_fixture())

    async with _App().run_test() as pilot:
        await pilot.pause()
        detail = str(pilot.app.query_one("#detail", Static).renderable)
        assert "High severity finding" in detail
```

- [ ] **Step 2: Run to confirm failures**

```bash
python -m pytest tests/test_tui.py -k "findings_panel" --tb=short
```

Expected: `ImportError` or `NameError` — `FindingsPanel` is not yet a class.

- [ ] **Step 3: Add FindingsPanel to ubuntils/tui/findings_panel.py**

Append to the existing file (keep the functions above):

```python
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widget import Widget
from textual.widgets import Label, ListItem, ListView, Static

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

    def __init__(self, findings: list[Finding]) -> None:
        super().__init__()
        self._findings = sort_findings(findings)

    def compose(self) -> ComposeResult:
        items = []
        for f in self._findings:
            color = _SEVERITY_COLORS[f.severity]
            sev = _SEVERITY_SHORT[f.severity]
            rule = f"{f.rule_id[:20]:<20}"
            path = f.artifact_path[:35]
            items.append(
                ListItem(Label(f"[{color} bold]{sev}[/{color} bold]  {rule}  {path}"))
            )
        yield ListView(*items)
        initial = format_detail(self._findings[0]) if self._findings else "No findings."
        yield Static(initial, id="detail")

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        idx = event.list_view.index
        if idx is not None and 0 <= idx < len(self._findings):
            self.query_one("#detail", Static).update(
                format_detail(self._findings[idx])
            )
```

- [ ] **Step 4: Run the new tests**

```bash
python -m pytest tests/test_tui.py -k "findings_panel" --tb=short
```

Expected: `3 passed`

- [ ] **Step 5: Commit**

```bash
git add ubuntils/tui/findings_panel.py tests/test_tui.py
git commit -m "feat: add FindingsPanel widget with sort and reactive detail pane"
```

---

## Task 6: Custom Textual messages

**Files:**
- Create: `ubuntils/tui/app.py` (messages only, no app yet)
- Modify: `tests/test_tui.py`

- [ ] **Step 1: Write failing tests — append to tests/test_tui.py**

```python
# ---------------------------------------------------------------------------
# Textual messages
# ---------------------------------------------------------------------------

from ubuntils.tui.app import CollectorProgress, ScanComplete


def test_collector_progress_fields():
    msg = CollectorProgress(name="CronCollector", index=3, total=8)
    assert msg.name == "CronCollector"
    assert msg.index == 3
    assert msg.total == 8


def test_scan_complete_fields():
    msg = ScanComplete(findings=[], timeline=[], stats={"key": "val"})
    assert msg.findings == []
    assert msg.timeline == []
    assert msg.stats == {"key": "val"}
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_tui.py -k "collector_progress or scan_complete" --tb=short
```

Expected: `ModuleNotFoundError: No module named 'ubuntils.tui.app'`

- [ ] **Step 3: Create ubuntils/tui/app.py with messages only**

```python
from __future__ import annotations

import platform
import time

import structlog
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.message import Message
from textual.widgets import ContentSwitcher, Footer, Header, Label, ProgressBar, Static

from ubuntils.collectors import ALL_COLLECTORS
from ubuntils.detectors.engine import DetectionEngine
from ubuntils.detectors.finding import Finding, Severity
from ubuntils.timeline.builder import TimelineBuilder, TimelineEvent


logger = structlog.get_logger()


class CollectorProgress(Message):
    def __init__(self, name: str, index: int, total: int) -> None:
        self.name = name
        self.index = index
        self.total = total
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
```

- [ ] **Step 4: Run the new tests**

```bash
python -m pytest tests/test_tui.py -k "collector_progress or scan_complete" --tb=short
```

Expected: `2 passed`

- [ ] **Step 5: Commit**

```bash
git add ubuntils/tui/app.py tests/test_tui.py
git commit -m "feat: add CollectorProgress and ScanComplete Textual messages"
```

---

## Task 7: LoadingScreen and MainScreen

**Files:**
- Modify: `ubuntils/tui/app.py` (add LoadingScreen and MainScreen)
- Modify: `tests/test_tui.py`

- [ ] **Step 1: Write failing tests — append to tests/test_tui.py**

```python
# ---------------------------------------------------------------------------
# LoadingScreen
# ---------------------------------------------------------------------------

from ubuntils.tui.app import LoadingScreen, MainScreen


async def test_loading_screen_updates_progress():
    class _App(App):
        def compose(self) -> ComposeResult:
            yield LoadingScreen()

    async with _App().run_test() as pilot:
        await pilot.pause()
        screen = pilot.app.query_one(LoadingScreen)
        screen.update_progress("CronCollector", 1, 8)
        await pilot.pause()
        label_text = str(pilot.app.query_one("#status", Label).renderable)
        assert "1/8" in label_text


# ---------------------------------------------------------------------------
# MainScreen — panel switching
# ---------------------------------------------------------------------------

async def test_main_screen_starts_on_findings_panel():
    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(MainScreen(findings=[], timeline=[], stats=_stats()))

    async with _App().run_test() as pilot:
        await pilot.pause()
        switcher = pilot.app.query_one(ContentSwitcher)
        assert switcher.current == "findings"


async def test_main_screen_key_2_switches_to_timeline():
    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(MainScreen(findings=[], timeline=[], stats=_stats()))

    async with _App().run_test() as pilot:
        await pilot.pause()
        await pilot.press("2")
        await pilot.pause()
        switcher = pilot.app.query_one(ContentSwitcher)
        assert switcher.current == "timeline"


async def test_main_screen_key_3_switches_to_stats():
    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(MainScreen(findings=[], timeline=[], stats=_stats()))

    async with _App().run_test() as pilot:
        await pilot.pause()
        await pilot.press("3")
        await pilot.pause()
        switcher = pilot.app.query_one(ContentSwitcher)
        assert switcher.current == "stats"


async def test_main_screen_key_1_switches_back_to_findings():
    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(MainScreen(findings=[], timeline=[], stats=_stats()))

    async with _App().run_test() as pilot:
        await pilot.pause()
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("1")
        await pilot.pause()
        switcher = pilot.app.query_one(ContentSwitcher)
        assert switcher.current == "findings"
```

- [ ] **Step 2: Run to confirm failures**

```bash
python -m pytest tests/test_tui.py -k "loading_screen or main_screen" --tb=short
```

Expected: `ImportError: cannot import name 'LoadingScreen'`

- [ ] **Step 3: Add LoadingScreen and MainScreen to ubuntils/tui/app.py**

Append after the message classes:

```python
from textual.screen import Screen

from ubuntils.tui.findings_panel import FindingsPanel
from ubuntils.tui.stats_panel import StatsPanel
from ubuntils.tui.timeline_panel import TimelinePanel


class LoadingScreen(Screen):
    DEFAULT_CSS = """
    LoadingScreen {
        align: center middle;
        layout: vertical;
    }
    LoadingScreen Label {
        margin-bottom: 1;
    }
    LoadingScreen ProgressBar {
        margin-bottom: 1;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._log_lines: list[str] = []

    def compose(self) -> ComposeResult:
        yield Label("Scanning system...", id="status")
        yield ProgressBar(total=8, show_eta=False, id="progress")
        yield Static("", id="checklist")

    def update_progress(self, name: str, index: int, total: int) -> None:
        self.query_one("#progress", ProgressBar).advance(1)
        self._log_lines.append(f"✓ {name}")
        self.query_one("#checklist", Static).update("\n".join(self._log_lines))
        self.query_one("#status", Label).update(
            f"Scanning system... [{index}/{total}]"
        )


class MainScreen(Screen):
    BINDINGS = [
        Binding("1", "switch_to_findings", "Findings"),
        Binding("2", "switch_to_timeline", "Timeline"),
        Binding("3", "switch_to_stats", "Stats"),
        Binding("q", "quit_app", "Quit"),
    ]

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
        with ContentSwitcher(initial="findings"):
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

    def action_quit_app(self) -> None:
        self.app.exit()
```

- [ ] **Step 4: Run the new tests**

```bash
python -m pytest tests/test_tui.py -k "loading_screen or main_screen" --tb=short
```

Expected: all new tests pass.

- [ ] **Step 5: Run full suite**

```bash
python -m pytest --tb=short -q
```

Expected: all passing.

- [ ] **Step 6: Commit**

```bash
git add ubuntils/tui/app.py tests/test_tui.py
git commit -m "feat: add LoadingScreen and MainScreen with panel switching"
```

---

## Task 8: UbuntilsApp with scan worker

**Files:**
- Modify: `ubuntils/tui/app.py` (add UbuntilsApp)
- Modify: `tests/test_tui.py`

- [ ] **Step 1: Write failing tests — append to tests/test_tui.py**

```python
# ---------------------------------------------------------------------------
# UbuntilsApp — full app
# ---------------------------------------------------------------------------

from ubuntils.tui.app import UbuntilsApp


async def test_ubuntils_app_shows_loading_screen_on_mount():
    def _override():
        return ([], [], _stats())

    async with UbuntilsApp(_scan_override=_override).run_test() as pilot:
        # Before the scan worker completes, LoadingScreen should be visible
        assert isinstance(pilot.app.screen, LoadingScreen)


async def test_ubuntils_app_transitions_to_main_screen_after_scan():
    def _override():
        return ([], [], _stats())

    async with UbuntilsApp(_scan_override=_override).run_test() as pilot:
        # Give the worker time to complete and post ScanComplete
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
        lv = pilot.app.query_one(ListView)
        assert lv.item_count == 1


async def test_ubuntils_app_q_exits():
    def _override():
        return ([], [], _stats())

    async with UbuntilsApp(_scan_override=_override).run_test() as pilot:
        await pilot.pause(delay=0.5)
        await pilot.press("q")
        # App should have exited — run_test context manager completes without hanging
```

- [ ] **Step 2: Run to confirm failures**

```bash
python -m pytest tests/test_tui.py -k "ubuntils_app" --tb=short
```

Expected: `ImportError: cannot import name 'UbuntilsApp'`

- [ ] **Step 3: Add UbuntilsApp to ubuntils/tui/app.py**

Append after `MainScreen`:

```python
from ubuntils.tui.stats_panel import get_ubuntu_version


class UbuntilsApp(App):
    TITLE = "ubuntils"
    BINDINGS = [Binding("q", "quit", "Quit")]

    def __init__(self, verbose: bool = False, _scan_override=None) -> None:
        super().__init__()
        self._verbose = verbose
        self._scan_override = _scan_override

    def on_mount(self) -> None:
        self.push_screen(LoadingScreen())
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
            try:
                result = collector.collect()
                artifacts.update(result)
            except Exception as exc:
                logger.error("collector_failed", name=name, error=str(exc))
                failures += 1
            self.post_message(
                CollectorProgress(name=name, index=i + 1, total=len(collectors))
            )

        findings = DetectionEngine().run(artifacts)
        timeline = TimelineBuilder().build()
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
        if isinstance(screen, LoadingScreen):
            screen.update_progress(message.name, message.index, message.total)

    def on_scan_complete(self, message: ScanComplete) -> None:
        self.switch_screen(
            MainScreen(
                findings=message.findings,
                timeline=message.timeline,
                stats=message.stats,
            )
        )
```

- [ ] **Step 4: Run the new tests**

```bash
python -m pytest tests/test_tui.py -k "ubuntils_app" --tb=short -v
```

Expected: all 4 tests pass.

- [ ] **Step 5: Run full suite**

```bash
python -m pytest --tb=short -q
```

Expected: all passing.

- [ ] **Step 6: Commit**

```bash
git add ubuntils/tui/app.py tests/test_tui.py
git commit -m "feat: add UbuntilsApp with background scan worker"
```

---

## Task 9: Wire up exports and __init__.py

**Files:**
- Modify: `ubuntils/tui/__init__.py`

- [ ] **Step 1: Write failing test — append to tests/test_tui.py**

```python
# ---------------------------------------------------------------------------
# Package exports
# ---------------------------------------------------------------------------

def test_ubuntils_app_importable_from_tui_package():
    from ubuntils.tui import UbuntilsApp as _UbuntilsApp
    assert _UbuntilsApp is UbuntilsApp
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_tui.py::test_ubuntils_app_importable_from_tui_package --tb=short
```

Expected: `ImportError: cannot import name 'UbuntilsApp' from 'ubuntils.tui'`

- [ ] **Step 3: Update ubuntils/tui/__init__.py**

```python
from ubuntils.tui.app import UbuntilsApp

__all__ = ["UbuntilsApp"]
```

- [ ] **Step 4: Run the test**

```bash
python -m pytest tests/test_tui.py::test_ubuntils_app_importable_from_tui_package --tb=short
```

Expected: `1 passed`

- [ ] **Step 5: Run full suite**

```bash
python -m pytest --tb=short -q
```

Expected: all passing.

- [ ] **Step 6: Update CLAUDE.md build progress**

In `CLAUDE.md`, move Phase 8 from "Remaining Phases" to "Completed" and update the test count.

- [ ] **Step 7: Commit**

```bash
git add ubuntils/tui/__init__.py tests/test_tui.py CLAUDE.md
git commit -m "feat: complete Phase 8 TUI — FindingsPanel, TimelinePanel, StatsPanel, UbuntilsApp"
```
