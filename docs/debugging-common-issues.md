# Debugging Common Issues

This guide covers the problems most users hit when running **ubuntils** and how to
resolve them. If your issue isn't listed here, run with `--verbose` and open an
issue with the structured log output attached.

---

## Installation & environment

### `ubuntils: command not found`
The console script wasn't placed on your `PATH`.

- If you installed with `pip install --user`, ensure `~/.local/bin` is on your `PATH`:
  ```bash
  export PATH="$HOME/.local/bin:$PATH"
  ```
- In a virtual environment, confirm it's activated (`which ubuntils` should point
  inside the venv).
- As a fallback, invoke the module directly:
  ```bash
  python -m ubuntils scan
  ```

### `TypeError: unsupported operand type(s) for |` on import (Python 3.9)
ubuntils supports Python 3.9+, but PEP 604 union syntax (`X | Y`) in type
annotations is evaluated at import time on 3.9 and raises. If you see this after
modifying the source, add `from __future__ import annotations` to the top of the
offending module. On a clean install this should not occur — please report it.

### Dependency version conflicts
ubuntils pins `textual>=0.50.0`, `click>=8.1.0`, and `structlog>=24.0.0`. If another
package in your environment forces older versions, install ubuntils into an
isolated environment:
```bash
python -m venv .venv && source .venv/bin/activate
pip install ubuntils
```

---

## Permissions

### Findings are empty or collectors report `✗`
Most forensic artifacts require elevated access. `/etc/shadow`, other users'
`~/.ssh/authorized_keys`, root-owned cron spools, and full process tables are only
readable as root. Run with `sudo`:
```bash
sudo ubuntils scan
```
A collector marked `✗` in the scan checklist means it could not read its source —
usually a permission error. Run with `--verbose` to see the exact failure per
collector.

### `Permission denied` during remediation
Remediation writes backups to `/var/backups/ubuntils/` and edits system files
(`/etc/sudoers.d/*`, cron spools, shell init files). These all require root. Run the
remediation step with `sudo`. ubuntils never escalates privileges on its own.

---

## The TUI (Textual interface)

### Panels render blank or zero-height
If the Findings, Timeline, or Stats panel shows nothing despite a completed scan,
your terminal may be too small or mis-reporting its size. Try:
- Resizing the terminal to at least 80×24.
- A different terminal emulator (some minimal ones report incorrect dimensions).
- `TERM=xterm-256color ubuntils scan`.

If data clearly exists (e.g. the Stats tab shows a finding count) but a panel is
empty, capture it with `--verbose` and report it.

### Timeline entries look out of order or collapsed onto one day
Timeline timestamps are rendered as `MM-DD HH:MM:SS`. Events are sorted ascending
and deduplicated. If two events share a timestamp, source ordering applies. Use
`--since` to narrow the window:
```bash
ubuntils scan --since "2026-06-01"
```

### TUI is unusable over SSH / in CI / in a pipe
The Textual TUI needs an interactive TTY. For non-interactive contexts use JSON
output instead, which runs inline and prints to stdout:
```bash
ubuntils scan --json
ubuntils scan --json --output report.json
```

### In-TUI remediation key (`R`) does nothing
`R` only acts on a finding whose rule has a remediator
(`CRON_*`, `LD_PRELOAD_INJECT`, `SSH_UNAUTHORIZED_KEY`, `SUDOERS_NOPASSWD`). The
three judgment-required rules (`SUSPICIOUS_SYSTEMD_TIMER`, `PROCESS_MASQUERADE`,
`SHELL_RC_MODIFICATION`) are flag-only by design — they show a `guided_remediation`
command in the detail pane (press `Enter`) for you to review and run yourself,
rather than auto-applying.

---

## Remediation

### Remediation reports `SKIPPED`
The finding's rule has no remediator, or you ran without `--confirm` (dry-run is the
default). To actually apply changes:
```bash
sudo ubuntils scan --remediate --confirm
```
Without `--confirm`, ubuntils only previews what *would* change.

### Remediation reports `FAILED` and leaves the system unchanged
This is intentional. If any step (backup, validate, apply, verify) fails, ubuntils
stops immediately and makes no change. Common causes:
- The target path is a **symlink**. ubuntils refuses to write through symlinks (all
  file I/O uses `O_NOFOLLOW`) to prevent an attacker redirecting a write to, e.g.,
  `/etc/shadow`. Inspect the path manually.
- `visudo -cf` validation failed for a sudoers edit — the file would have been left
  syntactically invalid, so the change was aborted.

### How do I undo a remediation?
Every applied change creates a timestamped backup under
`/var/backups/ubuntils/YYYYMMDD_HHMMSS/` and prints an exact `rollback_command`
(a `cp` of the backup back over the original). Re-run that command as root to revert.

---

## Output & reporting

### JSON report integrity
`--json` output includes a `report_sha256` plus `hostname`, `generated_at`, and
`tool_version` in `scan_metadata`. To verify a report wasn't altered, recompute the
hash over the report body (excluding the `report_sha256` field itself) and compare.

### `--config` vs `--rules` confusion
These are opposite concerns and use separate files:
- `--config FILE` — a YAML **allowlist** that *suppresses* known-good findings.
- `--rules FILE` — custom YAML detection rules that *add* pattern-match detections.

Allowlist suppression still applies to findings produced by custom rules.

---

## Reporting a bug

Run the failing command with `--verbose` and include:
- Your Ubuntu version (`lsb_release -d`)
- Python version (`python --version`)
- ubuntils version (`ubuntils version`)
- The structured log output (redact any sensitive paths/values first)

Note that ubuntils makes **no network calls** — no data leaves your system, so
nothing is transmitted automatically. All diagnostics must be attached manually.
