# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**ubuntils** is a Python CLI tool for Ubuntu incident response forensics. It collects artifacts, detects persistence mechanisms, and remediates threats with rollback support. Requires sudo/root to run.

## Commands

```bash
# Install in editable mode
pip install -e .

# Run tests
pytest tests/

# Run tests with coverage
pytest --cov=ubuntils tests/

# Run the tool (requires sudo on Ubuntu)
sudo ubuntils scan
sudo ubuntils scan --output json
sudo ubuntils scan --remediate --dry-run
sudo ubuntils scan --remediate --confirm
sudo ubuntils rollback /var/backups/ubuntils_<timestamp>/
```

## Architecture

The tool is structured around three phases: **collect → detect → remediate**.

**CLI entry point** (`ubuntils/cli.py`) — Click-based with two subcommands: `scan` and `rollback`.

**Artifact collectors** (`ubuntils/collectors/`) — Each collector is responsible for one artifact type: running processes, network connections, logs, cron jobs, SSH authorized_keys, sudoers config, systemd timers. Collectors require root for some reads (`/var/log/*`, `/etc/cron.d/*`, `/etc/sudoers`).

**Detection engine** (`ubuntils/detectors/`) — Runs rules against collected artifacts and emits `Finding` objects with severity (HIGH/MEDIUM/LOW), category, description, affected path, and a `remediation_available` flag. Eight detection categories: cron root execution, cron /tmp paths, LD_PRELOAD injection, sudoers NOPASSWD, shell init hijacking, SSH key injection, non-standard services, system file modifications.

**Remediation system** (`ubuntils/remediation/`) — Safety-first: always creates a timestamped backup under `/var/backups/ubuntils_<timestamp>/` before modifying any file. Validates sudoers changes with `visudo`. Never removes all sudo access. Never force-deletes (only comments out/disables). Supports dry-run mode (prints plan, no changes). `rollback` subcommand restores from a backup directory.

**Output formatters** (`ubuntils/formatters/`) — Two formats: human-readable (default, with severity headers and timeline section) and JSON (for SIEM/MISP integration via `--output json`).

**Timeline builder** (`ubuntils/timeline.py`) — Correlates events from auth logs, syslog, and cron logs into a chronological narrative. Covers a 48-hour lookback window.

## Key Patterns

- Findings carry a `remediation_available` boolean; only some categories support auto-fix (flag-only findings: non-standard services, system file mods).
- Dry-run and confirm are mutually exclusive flags on `--remediate`.
- Backups use timestamped directory names so multiple scans don't overwrite each other.
- Detection rules are inspired by MITRE ATT&CK; keep category names consistent with the table in README.md.
- Target platforms: Ubuntu 20.04, 22.04, 24.04 (amd64). Do not add macOS or Windows code paths yet.
