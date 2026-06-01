# ubuntils TUI Redesign v2 — Tabbed Navigation + Scan Checklist

**Date:** 2026-05-26
**Status:** Approved

---

## Problem

After the v1 redesign (`ScanScreen` → `SummaryScreen` → `MainScreen`), two UX problems remained:

1. **Navigation is confusing.** Two-level model: `SummaryScreen` *pushes* a separate `MainScreen`; inside `MainScreen`, keys `1/2/3` switch panels *in place* while `Escape` *pops back* to the summary. Two redundant navigation mechanisms stacked on each other, and no persistent indication of where you are.
2. **Scan screen feels janky.** A single ticker line grows as collectors finish (`Process · Network · …`) and can overflow the terminal width; the centered spinner and the bottom-docked ticker read as two disconnected things.

> Note: the separate zero-height `ContentSwitcher` bug that made Timeline/Stats render blank was already fixed in commit `4232f53`. This redesign replaces that screen structure entirely, so the fix is carried forward in the new layout.

---

## Design Decisions

| Question | Choice |
|---|---|
| Post-scan navigation | **Single tabbed screen** — one `ResultsScreen` with a persistent tab bar; no screen stacking |
| Scan-in-progress display | **Live checklist** — all collectors listed up front, each resolves to ✓/✗ in place |

---

## Screen Flow

```
UbuntilsApp.on_mount
  └── push ScanScreen(collector_names)        # live checklist
        │ scan worker runs in a thread
        │ each CollectorProgress → mark a row
        ▼
  switch_screen → ResultsScreen(findings, timeline, stats)
        │ tabs: 1 Summary · 2 Findings · 3 Timeline · 4 Stats
        │ Tab / ←→ cycle tab bar; q quits
        ▼
       (no back-navigation; ResultsScreen is the root after scan)
```

---

## Component Specifications

### ScanScreen (rewrite — `tui/scan_screen.py`)

- Constructor: `ScanScreen(collector_names: list[str])`.
- Display name per collector = class name minus the `Collector` suffix
  (`ProcessCollector` → `Process`, `SSHCollector` → `SSH`, etc.).
- Renders **all** collectors as rows immediately on mount, each in `pending` state.
- Row states:
  - `pending` — dim, no marker
  - `running` — animated braille spinner (`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`), advanced by a `set_interval(~0.1s)` timer
  - `done` — `✓`
  - `failed` — `✗`
- Layout: centered "Scanning system…" title above the checklist; a single `Static` re-rendered on each update. Fixed list, nothing scrolls or overflows.
- Method `mark(name: str, success: bool)`:
  - marks the named row `done`/`failed`
  - advances the "running" pointer to the next still-`pending` row
- On mount, the first row starts in `running`.

### ResultsScreen (new — `tui/results_screen.py`, replaces `SummaryScreen` + `MainScreen`)

- Constructor: `ResultsScreen(findings, timeline, stats)`.
- `compose`: `Header()` + `TabbedContent(initial="summary")` + `Footer()`.
- `TabbedContent` panes (each `TabPane(title, id=...)`):
  - `summary` → `Static(_build_summary(findings, timeline, stats))`
  - `findings` → `FindingsPanel(findings)`
  - `timeline` → `TimelinePanel(timeline)`
  - `stats` → `StatsPanel(stats)`
- `BINDINGS`: `1`→summary, `2`→findings, `3`→timeline, `4`→stats (each sets
  `self.query_one(TabbedContent).active = "<id>"`); `q`→quit.
- `Tab` / `←→` tab-bar cycling comes from `TabbedContent` natively.
- Add CSS only if needed so panes fill available height (verify each pane's
  `region.height > 1` in tests).

### summary_screen.py (refactor)

- **Keep** `_build_summary()` and its module-level constants (`_SEV_BULLET`,
  `_SEV_LABEL`, `_MAX_FINDINGS_SHOWN`) — reused by the Summary tab.
- **Remove** the `SummaryScreen` class.

### app.py (modify)

- `on_mount`: `push_screen(ScanScreen(collector_names=[C.__name__ for C in ALL_COLLECTORS]))`.
- `on_collector_progress`: if the current screen is `ScanScreen`, call `screen.mark(message.name, message.success)`.
- `on_scan_complete`: `switch_screen(ResultsScreen(findings, timeline, stats))`.
- **Remove** `MainScreen`.

### tui/__init__.py

- Export `UbuntilsApp`, `ScanScreen`, `ResultsScreen`. Drop `SummaryScreen`.

---

## Data Flow

`ScanComplete(findings, timeline, stats)` and `CollectorProgress(name, index, total, success)`
are unchanged. `ResultsScreen` receives the `(findings, timeline, stats)` tuple.
`ScanScreen.mark` uses only `name` + `success` from `CollectorProgress`.

---

## Empty States

| State | Display |
|---|---|
| 0 findings | Summary tab shows "System appears clean."; `FindingsPanel` shows "No findings." |
| 0 timeline events | `TimelinePanel` shows an empty list |
| Collector failure | Checklist row shows `✗`; Summary tab shows the failure count |

---

## Files

| Action | Path | Responsibility |
|---|---|---|
| Rewrite | `ubuntils/tui/scan_screen.py` | `ScanScreen` live checklist |
| Create | `ubuntils/tui/results_screen.py` | `ResultsScreen` tabbed container |
| Refactor | `ubuntils/tui/summary_screen.py` | keep `_build_summary`, drop `SummaryScreen` class |
| Modify | `ubuntils/tui/app.py` | wire `ScanScreen`/`ResultsScreen`; remove `MainScreen` |
| Modify | `ubuntils/tui/__init__.py` | export `ScanScreen`, `ResultsScreen` |
| Modify | `tests/test_tui.py` | tests for checklist + tabbed nav; remove `MainScreen`/`SummaryScreen` tests |

---

## Testing

- **ScanScreen:** all collectors listed on mount (pending); `mark()` flips the right
  row to ✓ / ✗ and is reflected in the rendered text.
- **ResultsScreen:** default active tab is `summary`; keys `1`–`4` set the active tab;
  each pane renders with `region.height > 1` (carry forward the zero-height regression
  guard).
- **App flow:** `ScanScreen` on mount → `ResultsScreen` after scan; Summary tab shows
  stats and the findings list / clean message.
- Remove obsolete `MainScreen` and `SummaryScreen` tests; keep the panel widget tests
  (`FindingsPanel`, `TimelinePanel`, `StatsPanel`).
