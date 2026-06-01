# Time-Window Filter (`--since`) Design

**Date:** 2026-05-26
**Status:** Approved

## Goal

Add a `--since` flag to `ubuntils scan` that limits artifact collection and timeline parsing to a user-specified time window, reducing scan duration on large systems.

## CLI Interface

```
ubuntils scan --since 24h          # relative: last 24 hours
ubuntils scan --since 7d           # relative: last 7 days
ubuntils scan --since 2026-05-20   # absolute: ISO date (midnight UTC)
ubuntils scan --since "2026-05-20 14:00"  # absolute: ISO datetime
```

**Parsing rules:**
- Relative format: regex `(\d+)(m|h|d|w)` — units `m` (minutes), `h` (hours), `d` (days), `w` (weeks). Subtracted from `datetime.now(tz=timezone.utc)`.
- Absolute format: `dateutil.parser.parse()` (already a dependency). Timezone-naive strings treated as UTC.
- Invalid input → `click.BadParameter` with a message showing accepted formats.
- Omitted → `since=None` → existing behavior, no filtering.

The parsed `datetime` (always timezone-aware UTC) flows into `_run_pipeline()`, all collectors, and `TimelineBuilder`.

## `BaseCollector` Changes

`BaseCollector.__init__()` gains `since: datetime | None = None` stored as `self._since`.

Shared helper added to `BaseCollector`:

```python
def _file_modified_since(self, path: str) -> bool:
    if self._since is None:
        return True
    try:
        return os.stat(path).st_mtime >= self._since.timestamp()
    except OSError:
        return True  # can't stat → don't silently skip
```

## File-Based Collector Changes

| Collector | What gets skipped |
|---|---|
| `CronCollector` | `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/crontabs/*` with mtime before `since` |
| `SSHCollector` | `authorized_keys` files with mtime before `since` |
| `SudoersCollector` | `/etc/sudoers` and `/etc/sudoers.d/*` with mtime before `since` |
| `EnvironmentCollector` | Shell init files (`/etc/profile`, `/etc/profile.d/*.sh`, `~/.*rc`, etc.) with mtime before `since`. `/etc/environment` always read (structural config). |

**Unchanged:** `ProcessCollector`, `NetworkCollector`, `UserCollector`, `SystemdCollector` — all reflect current system state, not file history.

## `TimelineBuilder` Changes

`TimelineBuilder.build()` gains `since: datetime | None = None`.

- **syslog** — parsed line by line; skip entries with timestamp < `since`. Break early on first entry older than `since` (files are chronological).
- **journald** — pass `--since` to `journalctl` command directly so the OS filters at source before any data crosses the pipe.
- **auditd** — skip entries with `msg=audit(timestamp:...)` < `since`. Break early.

## TUI / `UbuntilsApp` Changes

`UbuntilsApp.__init__()` gains `since: datetime | None = None`. Scan worker passes it to each collector constructor and to `TimelineBuilder.build(since=since)`.

`_run_pipeline()` in `cli.py` gains the same parameter and threads it through identically.

## Stats Display

When `--since` is active, the stats panel and Summary tab show:

```
Scan window:  last 24h  (since 2026-05-25 12:00 UTC)
```

Line is omitted entirely when `since=None`.

## Testing

| Test file | Coverage |
|---|---|
| `tests/test_collectors.py` | Each of 4 collectors: file within window → included; file outside → skipped; `since=None` → all included; `OSError` on stat → included |
| `tests/test_timeline.py` | Entries before `since` skipped; entries after included; `since=None` → all returned; journald `--since` flag passed correctly |
| `tests/test_cli.py` | `--since 24h` parses correctly; `--since 2026-05-20` parses correctly; invalid `--since foo` → non-zero exit with error |
| `tests/test_tui.py` | `UbuntilsApp(since=datetime(...))` passes `since` through; stats summary shows "Scan window" when set, omits when `None` |

Coverage gate stays at 80%.
