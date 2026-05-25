# ubuntils TUI — Phase 8 Design Spec

**Date:** 2026-05-25  
**Phase:** 8 — TUI (FindingsPanel, TimelinePanel, StatsPanel, UbuntilsApp)

---

## 1. Overview

The TUI is the default output mode for `ubuntils scan`. It is a Textual-based interactive terminal UI that shows scan progress during collection, then presents findings, a correlated timeline, and a stats summary in navigable panels.

---

## 2. Architecture

`UbuntilsApp` is the single Textual `App` subclass and owns the full lifecycle:

1. **Mount phase** — renders `LoadingScreen` immediately, then fires a Textual worker (thread pool) that runs collectors → detection → timeline sequentially.
2. **Progress updates** — the worker posts `CollectorProgress(name, index, total)` messages back to the app as each collector finishes. `LoadingScreen` updates its progress bar reactively.
3. **Transition** — when the worker finishes, the app swaps `LoadingScreen` for `MainScreen`, which contains the three panels.
4. **Panel switching** — `MainScreen` uses Textual's `ContentSwitcher`. Keys `1`, `2`, `3` switch panels. The header tab bar reflects the active panel. `q` quits.
5. **Finding detail** — `FindingsPanel` is a vertical split: `ListView` (top, ~60%) and a `Static` detail pane (bottom, ~40%). Cursor movement updates the detail pane reactively.

### Worker→App message boundary

Two custom Textual messages cross the worker→app boundary:

| Message | Fields | Purpose |
|---|---|---|
| `CollectorProgress` | `name: str`, `index: int`, `total: int` | Posted after each collector finishes; drives progress bar |
| `ScanComplete` | `findings`, `timeline`, `stats` | Posted when worker is done; triggers screen transition |

Collector failures are caught per-collector (logged via structlog, empty dict returned). A single failing collector never aborts the worker.

---

## 3. Components

| Widget | File | Responsibility |
|---|---|---|
| `UbuntilsApp` | `tui/app.py` | App root. Workers, keyboard bindings, screen transitions. |
| `LoadingScreen` | `tui/app.py` | Textual `Screen` shown during scan. Progress bar + collector checklist. |
| `MainScreen` | `tui/app.py` | Textual `Screen` shown after scan. Contains `ContentSwitcher` wrapping the three panels. |
| `FindingsPanel` | `tui/findings_panel.py` | `ListView` + detail pane. Findings sorted HIGH→MEDIUM→LOW. |
| `TimelinePanel` | `tui/timeline_panel.py` | Scrollable `ListView` of correlated log events. |
| `StatsPanel` | `tui/stats_panel.py` | Static summary: version, arch, duration, counts. |

`LoadingScreen` lives in `app.py` — it is small and tightly coupled to startup. The three panel files are independently testable.

`UbuntilsApp.__init__` accepts a `_scan_override` callable for testing, allowing fixture data to be injected without running real collectors.

---

## 4. Layout

### Header (always visible)
```
ubuntils  [1:Findings]  2:Timeline  3:Stats     q:quit
```
Active panel name is bold/highlighted.

### FindingsPanel
```
┌─────────────────────────────────────────────────────┐
│ SEV    RULE_ID              PATH                     │
│ ─────────────────────────────────────────────────── │
│ HIGH   CRON_TMP_PATH        /etc/cron.d/evil         │
│►HIGH   LD_PRELOAD_INJECT    /etc/environment         │
│ MED    SSH_UNAUTHORIZED_KEY /home/alice/.ssh         │
│ LOW    SHELL_RC_MODIF...    /home/alice/.bashrc      │
├─────────────────────────────────────────────────────┤
│ LD_PRELOAD=/tmp/evil.so set in /etc/environment.    │
│ This injects an untrusted shared library into every │
│ process at startup.                                 │
│                                                     │
│ Artifact: /etc/environment                          │
│ Raw:      LD_PRELOAD=/tmp/evil.so                   │
│ Remediation: comment out the LD_PRELOAD line        │
└─────────────────────────────────────────────────────┘
```
Severity badge colours: `HIGH` → red, `MEDIUM` → yellow, `LOW` → cyan.

### TimelinePanel
Single `ListView`. Each row: `HH:MM:SS  source  description`. Scrollable with arrow keys.

### StatsPanel
```
Ubuntu Version:   22.04.3 LTS
Architecture:     x86_64 (amd64)
Scan Duration:    2.4s
Collectors run:   8 (0 failed)
Findings:         2 HIGH  1 MEDIUM  1 LOW
Timeline events:  47
```
Architecture sourced from `platform.machine()`. Displayed as-is (raw kernel value).

### LoadingScreen
```
  Scanning system...
  [████████████░░░░░░░░] 6/8
  ✓ ProcessCollector
  ✓ NetworkCollector
  ✓ UserCollector
  ✓ CronCollector
  ✓ SystemdCollector
  ✓ SSHCollector
    SudoersCollector...
```

---

## 5. Data Flow

```
cli.py
  └─ UbuntilsApp(verbose=...).run()
       │
       ├─ on_mount() → push LoadingScreen
       │                      │
       │               worker thread starts
       │                      │
       │               for each collector (8x):
       │                 collector.collect()
       │                 post CollectorProgress → LoadingScreen updates bar
       │                      │
       │               DetectionEngine.run(artifacts) → list[Finding]
       │               TimelineBuilder.build()        → list[TimelineEvent]
       │               collect stats (duration, Ubuntu ver, arch)
       │                      │
       │               post ScanComplete(findings, timeline, stats)
       │                      │
       └─ on_ScanComplete() → pop LoadingScreen
                             → push MainScreen(findings, timeline, stats)
                                      │
                                      ├─ FindingsPanel(findings)
                                      ├─ TimelinePanel(timeline)
                                      └─ StatsPanel(stats)
```

---

## 6. Testing

Tests go in `tests/test_tui.py` using Textual's `Pilot` harness.

| Test | Method |
|---|---|
| App mounts and shows `LoadingScreen` | Construct app, check `LoadingScreen` visible on mount |
| `ScanComplete` transitions to `MainScreen` | Post message manually, assert `MainScreen` visible |
| `1`/`2`/`3` keys switch panels | `pilot.press("1")` etc., assert `ContentSwitcher.current` |
| `FindingsPanel` detail pane updates on cursor move | Move cursor, assert detail pane text |
| `FindingsPanel` sorts HIGH→MEDIUM→LOW | Assert row order in `ListView` |
| `StatsPanel` shows correct counts | Construct with known stats dict, assert rendered text |
| `TimelinePanel` shows all events | Construct with fixture events, assert row count |
| `q` exits the app | `pilot.press("q")`, assert app exits |

The scan worker is not tested here — collectors and detection have dedicated test files. `_scan_override` bypasses real collectors in all TUI tests.
