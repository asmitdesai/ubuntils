# ubuntils TUI Redesign — Design Spec
**Date:** 2026-05-26
**Status:** Approved

---

## Problem

The current TUI has two UX bugs:
1. **Blank findings panel on clean systems.** `LoadingScreen` transitions directly to `MainScreen`, which opens on `FindingsPanel`. When no findings exist the panel shows an empty list and "No findings." in a detail pane — indistinguishable from a crash or a render bug.
2. **Ugly loading screen.** The scan shows a progress bar + text checklist that looks unpolished.

---

## Design Decisions

| Question | Choice |
|---|---|
| Layout | **Summary Dashboard** — scan → summary screen → drill into panels |
| Loading screen | **Minimal spinner** — centered spinner + collector ticker at bottom |
| Clean-state display | **Stats-first** — full stats always shown, "System appears clean." when 0 findings |

---

## Screen Flow

```
UbuntilsApp.on_mount
  └── push ScanScreen (replaces LoadingScreen)
        │ scan worker runs in thread
        ▼
  switch to SummaryScreen (new)
        │ press 1 / 2 / 3
        ▼
  push MainScreen (existing, receives panel key)
        │ press q or Escape
        ▼
  pop back to SummaryScreen
```

---

## Screen Specifications

### ScanScreen (replaces LoadingScreen)

- Centered vertically and horizontally
- Single line: `⠋  Scanning system...` with a Textual spinner widget
- Single ticker line at the bottom: collector names append as they complete
  - Format: `Processes · Network · Users · Cron · ...`
  - Failed collectors shown as `✗ Sudoers` in the ticker
- No progress bar, no checklist widget
- Transitions to `SummaryScreen` on `ScanComplete`

### SummaryScreen (new)

Always shown after scan completes, regardless of finding count.

```
┌─ ubuntils ─────────────────────────── scan complete ────┐
│                                                          │
│  Collectors:  8 run · 0 failed                          │
│  Findings:    2 HIGH · 1 MEDIUM · 0 LOW                 │
│  Timeline:    312 events across 7 days                  │
│  Duration:    2.1s                                      │
│                                                          │
│  ● HIGH   CRON_TMP_PATH     /etc/cron.d/cleanup         │  ← only when findings > 0
│  ● HIGH   LD_PRELOAD_INJECT /home/alice/.bashrc         │
│  ○ MED    SSH_UNAUTHORIZED  /home/bob/.ssh/auth_keys    │
│                                                          │
│  System appears clean.                                  │  ← only when findings == 0
│                                                          │
│  [1 Findings]  [2 Timeline]  [3 Stats]     [q Quit]     │
└──────────────────────────────────────────────────────────┘
```

**Behavior:**
- Key `1` → push `MainScreen` opened to findings panel
- Key `2` → push `MainScreen` opened to timeline panel
- Key `3` → push `MainScreen` opened to stats panel
- Key `q` → exit app
- `SummaryScreen` is **not** reachable via back-navigation; it is the root after scan

### MainScreen (existing — minor polish)

- Header shows panel name + count: `Findings (3)`, `Timeline (312)`, `Stats`
- Key `Escape` or `q` → pop back to `SummaryScreen`
- Findings panel: severity badge colors unchanged (red/yellow/cyan), detail pane padding increased to 1 2
- Timeline panel: source column fixed-width 10 chars, timestamp column 16 chars
- Stats panel: unchanged

---

## Component Changes

| File | Change |
|---|---|
| `tui/app.py` | Replace `LoadingScreen` with `ScanScreen`; add `SummaryScreen`; wire key navigation |
| `tui/scan_screen.py` | New file — `ScanScreen` widget |
| `tui/summary_screen.py` | New file — `SummaryScreen` widget |
| `tui/findings_panel.py` | Minor: increase detail pane padding |
| `tui/timeline_panel.py` | Minor: fix column widths |
| `tui/stats_panel.py` | No changes |
| `tests/test_tui.py` | Update/add tests for new screens |
| `CLAUDE.md` | Mark redesign in progress |

---

## Data Flow

`ScanComplete` message carries `(findings, timeline, stats)` — unchanged from today. `SummaryScreen` and `MainScreen` both receive this tuple. No new message types needed.

`MainScreen` gains an `initial_panel: str` constructor parameter (`"findings"` | `"timeline"` | `"stats"`) so `SummaryScreen` can direct which panel opens.

---

## Empty States

| State | Display |
|---|---|
| 0 findings | `System appears clean.` in green on SummaryScreen; FindingsPanel shows "No findings detected." |
| 0 timeline events | TimelinePanel shows "No timeline events found. Try running as root." |
| Collector failure | Ticker shows `✗ CollectorName`; stats show failure count |

---

## Testing

- `ScanScreen` renders and transitions to `SummaryScreen` on `ScanComplete`
- `SummaryScreen` renders correctly with findings and without
- `SummaryScreen` key bindings push `MainScreen` at correct panel
- `MainScreen` `Escape`/`q` pops back to `SummaryScreen`
- Empty-state messages render correctly
