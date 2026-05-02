# ubuntils v1.0.0 Design Specification

**Date:** 2026-05-02  
**Author:** Asmit Desai  
**Project:** ubuntils — Ubuntu Incident Response Forensics Tool  
**Target Release:** July/August 2026  

---

## Overview

ubuntils is a Python CLI tool for Ubuntu incident response forensics. It collects artifacts, detects persistence mechanisms via 8 detection rules, builds chronological timelines, and provides safety-first automated remediation with full rollback support.

**Scope for v1.0.0:** All 4 collectors, all 8 detection rules, full remediation system with backups and rollback, both output formatters (human-readable and JSON), lightweight timeline correlator, and 80%+ test coverage.

**Implementation approach:** Collectors-first — build collectors with heavy testing, then detection rules, then remediation, then formatters and timeline.

---

## Architecture

### High-Level Design

ubuntils follows a **pipeline architecture**:

```
CLI flags
  ↓
Collectors (parallel) → Detection rules → Remediation (optional) → Formatters → Output
  ↓
  stdout / file
```

### Directory Structure

```
ubuntils/
├── __init__.py
├── cli.py                           # Click CLI: scan and rollback commands
├── collectors/
│   ├── __init__.py
│   ├── processes.py                 # ps, lsof, netstat
│   ├── logs.py                      # syslog, auth, journal, auditd
│   ├── filesystem.py                # cron, sudoers, SSH, shell, LD_PRELOAD
│   └── users.py                     # passwd, group, login activity
├── detectors/
│   ├── __init__.py
│   ├── persistence.py               # 8 detection rules
│   └── anomalies.py                 # (Defer to v1.5+)
├── remediators/
│   ├── __init__.py
│   ├── cron_remediation.py
│   ├── sudoers_remediation.py
│   ├── ssh_remediation.py
│   ├── ld_preload_remediation.py
│   ├── shell_remediation.py
│   ├── backup_manager.py            # Timestamped backup creation
│   └── rollback_manager.py          # Backup restoration
├── formatters/
│   ├── __init__.py
│   ├── human.py                     # Human-readable report (tabulate)
│   └── json_formatter.py            # JSON output
├── timeline.py                      # Lightweight event correlator
└── utils/
    ├── __init__.py
    ├── shell.py                     # Safe subprocess wrappers
    ├── logging.py                   # loguru setup
    └── validators.py                # Input validation

tests/
├── test_collectors.py
├── test_detectors.py
├── test_remediators.py
├── test_formatters.py
└── test_integration.py

setup.py
requirements.txt
README.md
CLAUDE.md
.github/
└── workflows/
    └── tests.yml
```

---

## Collectors

### Shared Interface

All collectors inherit from `BaseCollector`:

```python
class BaseCollector:
    def collect(self) -> dict:
        """Return artifact dict with collected data"""
```

### Collector Details

#### 1. ProcessCollector
**Artifacts:**
- `processes`: array of running processes (PID, command, parent PID, user)
- `network_connections`: array of active connections (source/dest IP/port, state, owning process)
- `listening_ports`: array of listening sockets (port, protocol, service)

**Sources:** `ps aux --forest`, `lsof -i`, `netstat -tlpn`, `netstat -tnp`

#### 2. LogCollector
**Artifacts:**
- `log_events`: chronologically sorted array of log entries from multiple sources

**Sources:** `/var/log/syslog`, `/var/log/auth.log`, `journalctl`, `/var/log/audit/audit.log` (if auditd running)

**Key requirement:** Parse different formats (text syslog, binary journal, audit records) and unify to common event format with UTC ISO 8601 timestamps.

#### 3. FilesystemCollector
**Artifacts:**
- `cron_jobs`: user and system cron entries
- `sudoers`: /etc/sudoers and /etc/sudoers.d/* entries
- `ssh_keys`: authorized_keys for all users with modification timestamps
- `shell_inits`: .bashrc, .zshrc, .bash_profile, .profile contents per user
- `ld_preload`: /etc/ld.so.preload and LD_PRELOAD environment variables

**Sources:** `/var/spool/cron/crontabs/`, `/etc/cron.d/`, `crontab -u`, `/etc/sudoers*`, `~/.ssh/authorized_keys`, shell init files, `/etc/ld.so.preload`

#### 4. UserCollector
**Artifacts:**
- `users`: UID, GID, shell, home directory for all users
- `login_events`: recent login activity (last, lastlog, who)
- `group_memberships`: groups and their members

**Sources:** `/etc/passwd`, `/etc/group`, `last`, `lastlog`, `who`

### Execution Model

- All collectors run **in parallel** via `concurrent.futures.ThreadPoolExecutor`
- Total collection time bounded by slowest collector, not sum of all
- **Graceful degradation:** If a file is unreadable (permission denied), log the skip and continue (don't crash)
- Works on both root and non-root, but degraded on non-root (some logs/files skipped with notes)
- All timestamps in **UTC ISO 8601 format**

---

## Detection Engine

### Finding Object

Each detection rule returns a `Finding` dict:

```python
{
    "id": "FINDING_001",
    "severity": "HIGH",              # HIGH, MEDIUM, or LOW
    "category": "cron_root_execution",
    "path": "/var/spool/cron/crontabs/ubuntu",
    "why_suspicious": "Non-root user cron executing /tmp path with elevated context",
    "remediation_available": True,   # Can this be auto-fixed?
    "recommendation": "Investigate /tmp/check_disk.sh immediately"
}
```

### The 8 Detection Rules

#### 1. Cron Root Execution (HIGH)
**What:** Non-root user crontabs with entries executing with elevated context or pointing to root-owned paths  
**Auto-fix:** `remediation_available: True` — remove the cron entry  

#### 2. Cron /tmp Paths (HIGH)
**What:** Any cron job referencing `/tmp`, `/var/tmp`, or `/dev/shm`  
**Auto-fix:** `remediation_available: True` — remove the cron entry  

#### 3. LD_PRELOAD Injection (HIGH)
**What:** LD_PRELOAD set in `/etc/ld.so.preload` or shell init files, pointing outside standard system paths (`/lib`, `/usr/lib`, `/lib64`, `/usr/lib64`)  
**Auto-fix:** `remediation_available: True` — comment out the LD_PRELOAD line  

#### 4. Sudoers NOPASSWD (MEDIUM)
**What:** Sudoers entries granting NOPASSWD access to non-root, non-system users  
**Auto-fix:** `remediation_available: True` — remove the NOPASSWD clause (validated with `visudo -cf`)  

#### 5. Shell Init Hijacking (MEDIUM)
**What:** Shell initialization files (`.bashrc`, `.zshrc`, `.bash_profile`, `.profile`) containing suspicious patterns: `curl`/`wget` downloads, LD_PRELOAD exports, base64-decoded execution, reverse shell indicators  
**Auto-fix:** `remediation_available: True` — comment out the suspicious lines  

#### 6. SSH Key Injection (HIGH)
**What:** Entries in `~/.ssh/authorized_keys` for all users added recently (based on file modification timestamps) or not matching a configured whitelist  
**Auto-fix:** `remediation_available: True` — remove the unrecognized key entry  

#### 7. Non-Standard Systemd Services (MEDIUM)
**What:** Systemd service files outside standard locations or whose `ExecStart` points to `/tmp`, `/home`, `/var/tmp`, `/dev/shm`  
**Auto-fix:** `remediation_available: False` — manual review required (disabling services risk breaking legitimate software)  

#### 8. System File Modification Timestamps (MEDIUM)
**What:** Critical system files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts`) whose modification timestamp falls within the last 30 days  
**Auto-fix:** `remediation_available: False` — may be legitimate admin action; manual review required  

### Implementation

Detection rules live in `detectors/persistence.py`. Each rule is a function that:
1. Takes the artifacts dict from collectors
2. Checks for the specific condition
3. Returns a list of Finding dicts (may be empty if no matches)

Rules are conservative — only flag concrete evidence, not heuristics.

---

## Remediation System

### Safety-First Principles

1. **Always backup before modifying** — create timestamped backup under `/var/backups/ubuntils_TIMESTAMP/` before any change
2. **Validate before applying** — e.g., `visudo -cf` for sudoers changes
3. **Never remove all sudo access** — always preserve at least one admin user's full access
4. **Never force-delete** — only comment out or remove specific entries
5. **Require explicit confirmation** — `--remediate --confirm` flag (dry-run is default with `--remediate`)
6. **Log all actions** — timestamp, finding ID, action taken, status, backup path

### Remediation Modules

Each remediation type has its own module (`cron_remediation.py`, `sudoers_remediation.py`, etc.):

- Takes a Finding object
- Creates backup via `backup_manager.BackupManager`
- Applies the fix
- Validates the change
- Logs the action
- Returns result (SUCCESS, FAILED, SKIPPED)

### Rules 7 & 8 Handling

Findings with `remediation_available: False` are **never auto-fixed**. They appear in the report with `[MANUAL REVIEW REQUIRED]` and a recommendation for the analyst.

### Dry-Run Mode

When `--remediate --dry-run` is passed:
- Print the remediation plan (what would be changed)
- Don't create backups or modify anything
- Show what the file would look like after remediation

### Rollback

The `rollback_manager.RollbackManager` restores from a timestamped backup directory:
```bash
sudo ubuntils rollback /var/backups/ubuntils_20260502_143120/
```

Restores all modified files to pre-remediation state.

---

## Output Formatters

### Human-Readable Format

**Structure:**
1. **Header** — timestamp, hostname, kernel, uptime, scan mode, duration
2. **Execution summary** — artifacts collected, findings count by severity, remediation availability
3. **Findings section** — grouped by severity (HIGH → MEDIUM → LOW), each with ID, location, reason, recommendation, auto-fix status
4. **Timeline section** — 48-hour lookback window, chronologically sorted events
5. **Artifact statistics** — counts of processes, network, cron, systemd, auth events, SSH keys, sudoers
6. **Next steps** — suggest `--remediate --dry-run` or `--remediate --confirm`

**Implementation:** Uses `tabulate` for clean table formatting, loguru for logging output.

### JSON Format

**Structure:**

```json
{
  "metadata": {
    "timestamp": "2026-05-02T14:23:45Z",
    "hostname": "web-server-01",
    "kernel": "5.15.0-101-generic",
    "uptime_days": 45,
    "scan_duration_seconds": 4.82,
    "ubuntils_version": "1.0.0",
    "scan_mode": "detection" | "remediation"
  },
  "summary": {
    "artifacts_collected": 847,
    "findings": { "high": 2, "medium": 2, "low": 1, "total": 5 },
    "remediation_available": 4,
    "remediation_applied": 4
  },
  "findings": [
    {
      "id": "FINDING_001",
      "severity": "HIGH",
      "category": "cron_root_execution",
      "path": "/var/spool/cron/crontabs/ubuntu",
      "why_suspicious": "Non-root user cron executing /tmp path with elevated context",
      "remediation": {
        "available": true,
        "type": "cron_removal",
        "action": "Remove cron entry",
        "status": "SKIPPED" | "APPLIED" | "FAILED",
        "backup_path": "/var/backups/ubuntils_TIMESTAMP/crontabs_ubuntu",
        "details": "Removed entry: */5 * * * * /tmp/check_disk.sh"
      },
      "recommendation": "Investigate /tmp/check_disk.sh immediately"
    }
  ],
  "remediation_results": {
    "backup_directory": "/var/backups/ubuntils_20260502_143120/",
    "actions_applied": 4,
    "actions_skipped": 1,
    "actions_failed": 0,
    "applied": [
      {
        "finding_id": "FINDING_001",
        "action": "Removed cron entry",
        "status": "SUCCESS",
        "backup": "crontabs_ubuntu"
      }
    ]
  },
  "timeline": [
    {
      "timestamp": "2026-05-02T14:00:22Z",
      "event_type": "ssh_login",
      "user": "ubuntu",
      "source_ip": "203.0.113.45",
      "status": "success"
    }
  ],
  "artifacts": {
    "processes": { "total": 142, "suspicious": 3 },
    "network": { "total": 24, "listening": 8, "established": 16 },
    "cron_jobs": { "total": 8, "suspicious": 1 },
    "systemd_timers": { "total": 5, "suspicious": 0 },
    "auth_events": { "total": 342, "successful": 87, "failed": 255 },
    "ssh_keys": { "total": 3, "suspicious": 1 },
    "sudoers_entries": { "total": 12, "nopasswd": 1 }
  }
}
```

### Output Destinations

- `--output human` → stdout (default)
- `--output json` → stdout as JSON
- `--output /path/file` → write to file (format auto-detected by extension or defaults to human)

---

## Timeline Builder

**Purpose:** Correlate log events from syslog, auth logs, and audit logs into a chronological narrative that shows attacker progression (login → privilege escalation → file modification → persistence).

**Implementation:** `timeline.py` module that:
1. Takes all log events from LogCollector
2. Sorts by timestamp (UTC)
3. Groups events within time windows (e.g., 5-minute windows)
4. Correlates events by user, process, and affected file
5. Returns timeline with correlated event sequences

**Scope for v1.0:** Lightweight correlator (no anomaly detection). Full anomaly detection deferred to v1.5 (`detectors/anomalies.py`).

---

## CLI Commands

### `scan` Command

```bash
sudo ubuntils scan [OPTIONS]
```

**Flags:**
- `--output human | json | /path/file` — output format (default: human to stdout)
- `--remediate` — enable remediation engine
- `--dry-run` — preview remediation without applying (requires --remediate)
- `--confirm` — apply remediation with backups (requires --remediate)
- `-v / --verbose` — debug-level logging

**Behavior:**
1. Run all collectors in parallel
2. Apply all detection rules
3. Build timeline
4. If `--remediate --dry-run`: print plan, exit
5. If `--remediate --confirm`: apply fixes with backups, log actions
6. Format output (human or JSON)
7. Print or write to file

### `rollback` Command

```bash
sudo ubuntils rollback /var/backups/ubuntils_TIMESTAMP/
```

Restores all files in the backup directory to their pre-remediation state.

---

## Testing Strategy

### Unit Tests

**`test_collectors.py`**
- Each collector with mocked files and subprocess calls
- Test graceful degradation (missing files, permission denied)
- Verify artifact structure and timestamp format

**`test_detectors.py`**
- Each rule with known-bad and known-good artifacts
- Verify correct findings generated
- Test edge cases (empty artifact lists, malformed data)

**`test_remediators.py`**
- Mock file operations (don't actually modify system)
- Verify backup creation, validation syntax checking
- Test backup naming and directory structure
- Ensure no all-sudo-access removal

**`test_formatters.py`**
- Human formatter with sample findings
- JSON formatter with valid structure verification
- Test output to stdout and files

### Integration Tests

**`test_integration.py`**
- Plant test artifacts in temporary directories (not live system)
- Run full scan pipeline on test artifacts
- Verify findings detected correctly
- Mock remediation operations (verify logic, not actual system changes)
- Test rollback logic with mocked filesystem

### Test Coverage

**Target:** 80%+ for v1.0

**CI/CD:**
- Local: pytest on ARM64 Ubuntu (20.04, 22.04, 24.04)
- GitHub Actions: pytest on AMD64 runners for broader coverage
- All tests use mocking/fixtures — no actual system modifications

---

## Constraints & Decisions

1. **No removal of all sudo access** — if a fix would leave an admin user with no sudo, abort the remediation for that user
2. **No force-deletes** — only comment out or remove specific entries, preserving audit trail
3. **Graceful degradation on non-root** — skip unreadable artifacts with notes, don't crash
4. **All timestamps UTC ISO 8601** — no local time, enables consistent timeline correlation
5. **Conservative detection rules** — concrete evidence only, no heuristics that could produce false positives
6. **Mocking of security-critical paths** — even in integration tests, mock actual file modifications to preserve test system integrity

---

## Implementation Sequence

1. **Weeks 1-3:** Build all 4 collectors with heavy unit testing
2. **Weeks 4-6:** Implement all 8 detection rules with unit tests
3. **Weeks 7-8:** Build remediation system (backup manager, rollback manager, all 6 auto-fix modules)
4. **Weeks 9-10:** Build output formatters (human and JSON) and lightweight timeline
5. **Weeks 11-12:** Integration tests, polish, documentation, GitHub Actions CI setup

---

## Success Criteria for v1.0.0

- [ ] All 4 collectors implemented and tested
- [ ] All 8 detection rules implemented and tested
- [ ] Remediation system with backups and rollback working
- [ ] Both output formatters (human and JSON) working
- [ ] Lightweight timeline correlator working
- [ ] 80%+ test coverage
- [ ] GitHub Actions CI passing on ARM64 and AMD64
- [ ] No known false positives in core rules
- [ ] Documentation complete (README, CONTRIBUTING, inline code comments)
