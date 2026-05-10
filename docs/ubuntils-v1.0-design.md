# ubuntils v1.0 — Architecture & Design Reference

---

## 1. Project Overview

ubuntils is a forensic triage tool for live Ubuntu systems. When a system is suspected to be compromised — or when a security team needs a rapid baseline of what is running and what has changed — ubuntils automates the collection of persistence-relevant artifacts, runs a set of detection rules against those artifacts, and correlates log events into a timeline.

The tool exists because incident responders on Ubuntu systems frequently need to answer the same questions: Are there unauthorized cron jobs? Is LD_PRELOAD being abused? Are there new SSH keys? Has sudo been quietly granted to a user? Doing this manually across eight artifact classes is tedious and error-prone under time pressure. ubuntils reduces a 30-minute manual triage to a 90-second automated scan with a clean UI.

Design principles:
- **Read first, change never (by default).** Scan and detect are always safe. Remediation requires explicit opt-in with `--remediate --confirm`.
- **Don't trust the environment.** On a compromised system, common tools may be replaced. ubuntils reads files directly where possible rather than relying on system binary output.
- **Fail loudly per collector, not globally.** A single collector failure should produce a logged warning, not abort the entire scan.
- **Reproducible output.** Both the TUI and `--json` mode must reflect exactly the same findings from the same scan run.

---

## 2. Tech Stack

| Library | Version | Role | Justification |
|---|---|---|---|
| `click` | >=8.1.0 | CLI argument parsing and entry point | Mature, well-tested, decorator-based CLI framework. Used only for argument parsing — no output or formatting. |
| `textual` | >=0.50.0 | All interactive display | Async-native Python TUI framework. Supports panels, keyboard navigation, rich text, and responsive layout without terminal ncurses complexity. |
| `structlog` | >=24.0.0 | All internal logging | Provides structured key-value log events that render human-readably in TUI mode and as JSON objects in `--json` mode with zero code change. |
| `pyyaml` | >=6.0 | Config file support | Standard Python YAML parser. Used to load optional config overrides (e.g. custom rule thresholds). |
| `python-dateutil` | >=2.8 | Timestamp parsing | Handles the wide variety of timestamp formats across syslog, journald, and auditd without manual format strings. |
| `pytest` | >=7.0 | Test runner | Standard Python test framework with fixture, parametrize, and plugin support. |
| `pytest-cov` | >=4.0 | Coverage reporting | Measures test coverage as part of CI. |

---

## 3. Directory Structure

```
ubuntils/
├── ubuntils/
│   ├── __init__.py              # Package version export (e.g. __version__ = "1.0.0")
│   ├── cli.py                   # Click entry point; parses flags, wires them into scan pipeline
│   │
│   ├── collectors/
│   │   ├── __init__.py          # Exports collector registry list for engine iteration
│   │   ├── base.py              # BaseCollector ABC: defines collect() → dict interface
│   │   ├── processes.py         # Reads /proc/*/status + /proc/*/exe for running processes
│   │   ├── network.py           # Invokes ss (or netstat fallback) for connections and listeners
│   │   ├── users.py             # Parses /etc/passwd, /etc/shadow (if root), /etc/group
│   │   ├── cron.py              # Reads /etc/cron.d/*, /etc/crontab, /var/spool/cron/crontabs/*
│   │   ├── systemd.py           # Invokes systemctl list-timers --all and reads unit files
│   │   ├── ssh.py               # Reads ~/.ssh/authorized_keys for every user with a home dir
│   │   ├── sudoers.py           # Reads /etc/sudoers and every file under /etc/sudoers.d/
│   │   └── environment.py       # Reads /etc/environment, /etc/profile.d/*, per-user shell inits
│   │
│   ├── detectors/
│   │   ├── __init__.py          # Exports DetectionEngine
│   │   ├── finding.py           # Finding dataclass, Severity enum, RemediationStatus enum
│   │   ├── rules.py             # All 8 detection rule functions (one function per rule)
│   │   └── engine.py            # Iterates all rules over the artifact dict; returns list[Finding]
│   │
│   ├── timeline/
│   │   ├── __init__.py          # Exports TimelineBuilder
│   │   └── builder.py           # Parses syslog/journald/auditd; sorts and deduplicates events
│   │
│   ├── remediators/
│   │   ├── __init__.py          # Exports remediator registry keyed by rule_id
│   │   ├── base.py              # BaseRemediator ABC: backup() → validate() → apply() → verify()
│   │   ├── cron.py              # Remediator for CRON_ROOT_EXEC and CRON_TMP_PATH
│   │   ├── environment.py       # Remediator for LD_PRELOAD_INJECT
│   │   ├── ssh.py               # Remediator for SSH_UNAUTHORIZED_KEY
│   │   └── sudoers.py           # Remediator for SUDOERS_NOPASSWD (with visudo validation)
│   │
│   ├── formatters/
│   │   ├── __init__.py          # Exports JSONFormatter
│   │   └── json_formatter.py    # Serializes scan results to the documented JSON schema
│   │
│   ├── tui/
│   │   ├── __init__.py          # Exports UbuntilsApp
│   │   ├── app.py               # Textual App root; owns keyboard bindings and panel switching
│   │   ├── findings_panel.py    # DataTable of findings sorted HIGH→MEDIUM→LOW
│   │   ├── timeline_panel.py    # Scrollable list of correlated log events
│   │   └── stats_panel.py       # Summary view: Ubuntu version, scan duration, counts
│   │
│   └── utils/
│       ├── __init__.py
│       ├── shell.py             # run_command(cmd, timeout) — safe subprocess with captured stderr
│       ├── logging.py           # configure_logging(json_mode) sets up structlog processors
│       └── validators.py        # is_safe_path(), is_login_shell(), uid_is_system() helpers
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py              # Pytest fixtures: artifact dicts, tmp dirs, mock shell output
│   ├── test_base_classes.py     # Verifies ABC interfaces cannot be instantiated directly
│   ├── test_collectors.py       # Collector unit tests against mocked file/command output
│   ├── test_detection_rules.py  # Rule tests with hand-crafted known-bad artifact fixtures
│   ├── test_timeline.py         # Timeline builder tests with sample syslog/journald snippets
│   ├── test_remediators.py      # Remediator dry-run and backup/rollback tests on tmp files
│   └── test_json_formatter.py   # JSON output schema validation and field presence tests
│
├── docs/
│   ├── ubuntils-v1.0-design.md         # This file
│   └── ubuntils-v1.0-implementation.md # Build plan and numbered task list
│
├── setup.py          # Package metadata; defines `ubuntils` console_scripts entry point
├── requirements.txt  # Pinned runtime and dev dependencies
├── CLAUDE.md         # Claude Code session memory — not version controlled
└── README.md         # User-facing installation and usage guide
```

---

## 4. Data Flow

### Written Walkthrough

1. **CLI entry** — `cli.py` parses flags via Click. If `--json` is set, it configures structlog for JSON output; otherwise for human-readable. It then instantiates all collectors and calls `scan()`.

2. **Collection** — Each collector's `collect()` method runs independently. If a collector raises an exception, the error is logged via structlog and an empty dict is returned for that collector's slot. The engine never aborts on a single collector failure. Results are merged into a single `artifacts` dict keyed by collector name.

3. **Detection** — `DetectionEngine.run(artifacts)` iterates all 8 rules over the `artifacts` dict. Each rule function receives the full artifact dict and returns zero or more `Finding` objects. All findings are collected into a flat `list[Finding]`.

4. **Timeline** — `TimelineBuilder.build()` reads log sources (syslog, journald, auditd) independently of the collector pipeline. It parses timestamps with python-dateutil, deduplicates events with identical (timestamp, source, message) tuples, and returns a list sorted ascending by timestamp.

5. **Remediation (optional)** — If `--remediate` was passed, the engine looks up a remediator for each finding's `rule_id`. For each match, the remediator runs `backup() → validate() → apply() → verify()`. Without `--confirm`, `apply()` is a no-op (dry run). Results are collected as `list[RemediationResult]`.

6. **Output** — In TUI mode, `UbuntilsApp` receives findings, timeline, and stats and renders three panels. In `--json` mode, `JSONFormatter.format()` serializes all results to stdout.

### ASCII Data Flow Diagram

```
  ┌─────────────────────────────────────────────────┐
  │                    cli.py                        │
  │  parse flags → configure logging → start scan   │
  └───────────────┬─────────────────────────────────┘
                  │
                  ▼
  ┌─────────────────────────────────────────────────┐
  │              Collectors (8x)                     │
  │  processes │ network │ users │ cron │ systemd   │
  │  ssh       │ sudoers │ environment               │
  │  Each returns dict; failures produce {} + log   │
  └───────────────┬─────────────────────────────────┘
                  │  artifacts: dict[str, dict]
                  ▼
  ┌─────────────────────────────────────────────────┐
  │              DetectionEngine                     │
  │  Runs all 8 rules over artifacts                │
  │  Returns list[Finding]                          │
  └──────┬──────────────────────────────────────────┘
         │                        │
         ▼                        ▼
  ┌─────────────┐       ┌──────────────────┐
  │  Timeline   │       │  Remediators     │
  │  Builder    │       │  (if --remediate)│
  │             │       │  backup→validate │
  │  syslog +   │       │  →apply→verify   │
  │  journald + │       │  Returns         │
  │  auditd     │       │  list[Remediation│
  │  → sorted   │       │  Result]         │
  │  events     │       └────────┬─────────┘
  └──────┬──────┘                │
         │                       │
         └───────────┬───────────┘
                     │
                     ▼
  ┌─────────────────────────────────────────────────┐
  │                   Output                         │
  │                                                  │
  │   TUI mode: UbuntilsApp (Textual)               │
  │   ├── FindingsPanel (grouped by severity)        │
  │   ├── TimelinePanel (chronological)              │
  │   └── StatsPanel (counts and metadata)           │
  │                                                  │
  │   JSON mode: JSONFormatter → stdout              │
  └─────────────────────────────────────────────────┘
```

---

## 5. Data Models

### Severity (Enum)

```
HIGH    # Active exploitation or high-confidence persistence mechanism
MEDIUM  # Suspicious but may have legitimate explanations
LOW     # Informational — worth noting but low urgency
```

### RemediationStatus (Enum)

```
SUCCESS  # Change was applied and verified successfully
FAILED   # An error occurred; system was left unchanged
SKIPPED  # Rule has no remediator, or dry-run mode was active
```

### Finding (Dataclass)

| Field | Type | Description |
|---|---|---|
| `rule_id` | `str` | Unique rule identifier (e.g. `"CRON_ROOT_EXEC"`) |
| `severity` | `Severity` | HIGH, MEDIUM, or LOW |
| `title` | `str` | Short human-readable title shown in the TUI findings row |
| `description` | `str` | Full explanation of what was found and why it matters |
| `artifact_path` | `str` | Path to the file or resource that triggered the rule |
| `raw_value` | `str` | The exact line, value, or process name that matched |
| `remediation_available` | `bool` | Whether a remediator is registered for this rule_id |
| `remediation_description` | `Optional[str]` | Human-readable description of what remediation will do |

### RemediationResult (Dataclass)

| Field | Type | Description |
|---|---|---|
| `finding_rule_id` | `str` | The rule_id of the Finding that triggered this remediation |
| `status` | `RemediationStatus` | SUCCESS, FAILED, or SKIPPED |
| `message` | `str` | Human-readable outcome (e.g. "Removed entry from /var/spool/cron/crontabs/alice") |
| `backup_path` | `Optional[str]` | Full path to the timestamped backup created before modification |
| `rollback_command` | `Optional[str]` | Exact shell command to restore from backup (e.g. `cp /var/backups/ubuntils/20240115_143022/sudoers /etc/sudoers`) |

---

## 6. Collectors

Each collector extends `BaseCollector` and implements `collect() -> dict`. On failure, it logs the exception with structlog and returns `{}`.

### ProcessCollector

**Collects:** All running processes with their binary paths.

**Sources:** `/proc/*/status` (name, pid, uid), `/proc/*/exe` (resolved symlink to binary path), `/proc/*/cmdline` (full command line).

**Output schema:**
```
{
  "processes": [
    {
      "pid": int,
      "name": str,           # from /proc/<pid>/status Name field
      "exe_path": str,       # resolved /proc/<pid>/exe symlink
      "cmdline": str,        # space-joined /proc/<pid>/cmdline
      "uid": int             # from /proc/<pid>/status Uid field (real uid)
    },
    ...
  ]
}
```

### NetworkCollector

**Collects:** All open TCP/UDP connections and listening sockets.

**Sources:** `ss -tunap` (Ubuntu 20.04+). Falls back to `netstat -tunap` if ss is unavailable.

**Output schema:**
```
{
  "connections": [
    {
      "proto": str,          # "tcp" | "udp"
      "local_addr": str,
      "local_port": int,
      "remote_addr": str,
      "remote_port": int,
      "state": str,          # "LISTEN" | "ESTABLISHED" | etc.
      "pid": int,
      "process_name": str
    },
    ...
  ]
}
```

### UserCollector

**Collects:** All local user accounts with metadata.

**Sources:** `/etc/passwd` (username, uid, gid, home, shell), `/etc/group` (group memberships), `/etc/shadow` (password field — requires root; presence of `!` or `*` indicates locked account).

**Output schema:**
```
{
  "users": [
    {
      "username": str,
      "uid": int,
      "gid": int,
      "home": str,
      "shell": str,
      "is_login_shell": bool,   # shell is not /sbin/nologin or /bin/false
      "groups": list[str],
      "password_locked": bool   # from /etc/shadow; None if not root
    },
    ...
  ]
}
```

### CronCollector

**Collects:** All cron job definitions across system and user crontabs.

**Sources:** `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/crontabs/*` (one file per user).

**Output schema:**
```
{
  "cron_entries": [
    {
      "source_path": str,        # file the entry was read from
      "owner": str,              # username (for user crontabs) or "root" (for system crontabs)
      "schedule": str,           # the 5-field or @special schedule
      "run_as": str,             # user field in system crontabs; same as owner for user crontabs
      "command": str             # the command string
    },
    ...
  ]
}
```

### SystemdCollector

**Collects:** All systemd timers and their associated service units.

**Sources:** `systemctl list-timers --all --no-pager --output json` (Ubuntu 22.04+). Falls back to parsing `systemctl list-timers --all --no-pager` text output on 20.04. Reads unit files from `/etc/systemd/system/` and `/lib/systemd/system/`.

**Output schema:**
```
{
  "timers": [
    {
      "unit_name": str,
      "service_unit": str,
      "exec_start": str,          # ExecStart= value from service unit file
      "exec_start_owner": str,    # username owning the ExecStart path
      "unit_file_path": str,
      "active": bool
    },
    ...
  ]
}
```

### SSHCollector

**Collects:** All authorized_keys entries for all users.

**Sources:** `~/.ssh/authorized_keys` for every user in `/etc/passwd` that has a home directory. Reads file mtime.

**Output schema:**
```
{
  "authorized_keys": [
    {
      "username": str,
      "key_file_path": str,
      "file_mtime": float,        # Unix timestamp of file mtime
      "entries": [
        {
          "key_type": str,        # e.g. "ssh-rsa", "ecdsa-sha2-nistp256"
          "key_data": str,        # base64 key material (truncated for display)
          "comment": str
        },
        ...
      ]
    },
    ...
  ]
}
```

### SudoersCollector

**Collects:** All sudoers rules.

**Sources:** `/etc/sudoers` and every file under `/etc/sudoers.d/`. Parsed line by line — comment lines and blank lines are skipped.

**Output schema:**
```
{
  "sudoers_rules": [
    {
      "source_path": str,
      "raw_line": str,
      "user_spec": str,           # the user or group the rule applies to
      "hosts": str,
      "run_as": str,
      "options": list[str],       # e.g. ["NOPASSWD"]
      "commands": str
    },
    ...
  ]
}
```

### EnvironmentCollector

**Collects:** Environment variable definitions in system and user shell init files.

**Sources:** `/etc/environment`, `/etc/profile`, `/etc/profile.d/*`, and for each user with a login shell: `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `~/.zprofile`.

**Output schema:**
```
{
  "env_definitions": [
    {
      "source_path": str,
      "variable": str,            # e.g. "LD_PRELOAD"
      "value": str,               # the raw value string
      "owner": str                # "system" or the username
    },
    ...
  ]
}
```

---

## 7. Detection Rules

### Rule 1 — CRON_ROOT_EXEC (HIGH)

**Checks:** Cron entries in user crontabs (non-root user files under `/var/spool/cron/crontabs/`) where the command path begins with a root-owned directory (`/usr/`, `/bin/`, `/sbin/`, `/opt/`) or contains the string `sudo`.

**Why it matters:** A user crontab that runs commands from root-owned paths or escalates via sudo is a common persistence technique — it survives password changes and is easy to overlook in manual audits.

**Example finding:**
```
artifact_path: /var/spool/cron/crontabs/alice
raw_value:     "*/5 * * * * sudo /usr/bin/python3 /tmp/beacon.py"
title:         "User crontab executing with sudo"
remediation_available: true
```

### Rule 2 — CRON_TMP_PATH (HIGH)

**Checks:** Any cron entry (system or user) where the command contains `/tmp`, `/var/tmp`, or `/dev/shm`.

**Why it matters:** Writable world-accessible directories have no persistence across reboots and are prime staging grounds for payloads. A cron job referencing them is a strong indicator of attacker staging.

**Example finding:**
```
artifact_path: /etc/cron.d/cleanup
raw_value:     "0 * * * * root /tmp/.update"
title:         "Cron job references writable temp directory"
remediation_available: true
```

### Rule 3 — LD_PRELOAD_INJECT (HIGH)

**Checks:** `LD_PRELOAD` variable definitions in `/etc/ld.so.preload` or any collected env definition where the value is a path outside `/lib`, `/usr/lib`, `/lib64`, `/usr/lib64`.

**Why it matters:** LD_PRELOAD is the most common Linux userspace rootkit mechanism. A preload pointing to /tmp or a user home directory allows arbitrary code injection into every dynamically-linked process run by that user.

**Example finding:**
```
artifact_path: /home/alice/.bashrc
raw_value:     "export LD_PRELOAD=/tmp/.libssl.so"
title:         "LD_PRELOAD set to non-standard library path"
remediation_available: true
```

### Rule 4 — SUSPICIOUS_SYSTEMD_TIMER (HIGH)

**Checks:** Systemd timers whose associated service unit's `ExecStart` path points to `/tmp`, `/var/tmp`, `/dev/shm`, or a path not owned by root (determined via `stat`).

**Why it matters:** Attackers create systemd timers for persistence because they survive reboots and are harder to notice than crontabs. A timer pointing to a temp directory or a user-owned path is a near-certain indicator.

**Example finding:**
```
artifact_path: /etc/systemd/system/update-check.timer
raw_value:     "ExecStart=/tmp/.sys/update"
title:         "Systemd timer ExecStart points to suspicious path"
remediation_available: true
```

### Rule 5 — SSH_UNAUTHORIZED_KEY (MEDIUM)

**Checks:** SSH `authorized_keys` files whose mtime is within the last 7 days.

**Why it matters:** An SSH key added recently — especially on a system that isn't expected to have new users — is a strong indicator of lateral movement or persistence. The 7-day window catches recent additions without excessive false positives from initial provisioning.

**Example finding:**
```
artifact_path: /home/bob/.ssh/authorized_keys
raw_value:     "ssh-rsa AAAAB3NzaC1... attacker@evil"
title:         "SSH authorized key added in last 7 days"
remediation_available: true
```

### Rule 6 — SUDOERS_NOPASSWD (MEDIUM)

**Checks:** Sudoers rules containing `NOPASSWD` where the user spec applies to a user with UID >= 1000 and a login shell.

**Why it matters:** Password-free sudo access for a regular user account is a privilege escalation vector. Legitimate NOPASSWD grants are typically for service accounts (low UID, no login shell). Human user accounts with NOPASSWD are worth flagging.

**Example finding:**
```
artifact_path: /etc/sudoers.d/alice
raw_value:     "alice ALL=(ALL) NOPASSWD: ALL"
title:         "NOPASSWD sudo grant for regular user"
remediation_available: true
```

### Rule 7 — PROCESS_MASQUERADE (MEDIUM)

**Checks:** Running processes where the process name matches a known system binary name (e.g. `sshd`, `python3`, `bash`, `nginx`) but whose resolved exe path is outside `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`.

**Why it matters:** Replacing or mimicking system binary names is a basic attacker technique to avoid detection in `ps` output. This rule catches processes that look like system tools but are running from unexpected locations.

**Example finding:**
```
artifact_path: /proc/1337/exe
raw_value:     "name=sshd, exe=/tmp/.sshd"
title:         "Process masquerading as system binary"
remediation_available: false
```

**Note:** Flag-only. No auto-remediation — killing a process requires human judgment.

### Rule 8 — SHELL_RC_MODIFICATION (LOW)

**Checks:** Shell init files (`~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `~/.zprofile`) for any user with a login shell that have been modified within the last 48 hours.

**Why it matters:** Shell init modification is a classic persistence technique (e.g. adding a reverse shell one-liner or re-exporting LD_PRELOAD). 48 hours catches recent changes without overwhelming false positives on systems under active development.

**Example finding:**
```
artifact_path: /root/.bashrc
raw_value:     "mtime=2024-01-15 14:22:01 (6 hours ago)"
title:         "Shell init file recently modified"
remediation_available: false
```

**Note:** Flag-only. No auto-remediation — shell RC content requires human review.

---

## 8. Timeline Builder

### Log Sources

- **syslog** — `/var/log/syslog`, `/var/log/auth.log`, `/var/log/kern.log`. Traditional syslog format with BSD timestamps.
- **journald** — `journalctl --no-pager --output json --since "7 days ago"`. Provides structured JSON events with microsecond precision. Preferred when available (Ubuntu 20.04+).
- **auditd** — `/var/log/audit/audit.log`. Parsed for `type=EXECVE`, `type=OPEN`, `type=PROCTITLE` records. Auditd lines have Unix timestamps in the record header.

### Timestamp Parsing

All timestamps are normalized to UTC-aware Python `datetime` objects using `python-dateutil`. The parsing strategy per source:

- **syslog** — `dateutil.parser.parse()` with the current year injected (syslog omits the year). If a parsed timestamp is more than 1 day in the future, subtract one year.
- **journald** — `__REALTIME_TIMESTAMP` field is a Unix microsecond integer — converted directly via `datetime.fromtimestamp(ts / 1e6, tz=timezone.utc)`.
- **auditd** — Record header format `audit(1705329722.123:456)` — Unix timestamp extracted with a regex, subseconds preserved.

### Correlation and Deduplication

Events are stored as `TimelineEvent(timestamp, source, description)` named tuples. Deduplication uses a set of `(timestamp_rounded_to_second, source, description)` tuples to eliminate near-duplicate entries from overlapping log sources. The final timeline is sorted ascending by timestamp.

---

## 9. Remediators

All remediators implement `BaseRemediator` and follow the same four-step pattern: `backup() → validate() → apply() → verify()`. The `apply()` step is a no-op when `dry_run=True`.

### Backup Convention

All backups are written to `/var/backups/ubuntils/YYYYMMDD_HHMMSS/` with the original file's basename. Example:

```
/var/backups/ubuntils/20240115_143022/sudoers
/var/backups/ubuntils/20240115_143022/crontabs_alice
```

### CronRemediator (handles CRON_ROOT_EXEC, CRON_TMP_PATH)

**What it fixes:** Removes the specific offending line from a user crontab or system cron file.

**Pattern:**
1. `backup()` — copies the cron file to the backup directory
2. `validate()` — re-reads the file and locates the exact raw_value line; aborts if not found (system changed)
3. `apply()` — writes the file without the offending line; preserves all other entries
4. `verify()` — re-reads the file and confirms the line is absent

**Rollback command example:**
```
cp /var/backups/ubuntils/20240115_143022/crontabs_alice /var/spool/cron/crontabs/alice
```

### EnvironmentRemediator (handles LD_PRELOAD_INJECT)

**What it fixes:** Comments out the `LD_PRELOAD` export line in the offending file.

**Pattern:**
1. `backup()` — copies the shell init file or `/etc/ld.so.preload` to the backup directory
2. `validate()` — confirms the line is still present
3. `apply()` — replaces the line with `# [ubuntils-removed] <original line>` — never deletes the line, preserving file structure
4. `verify()` — confirms the active (uncommented) LD_PRELOAD definition is no longer present

**Rollback command example:**
```
cp /var/backups/ubuntils/20240115_143022/.bashrc /home/alice/.bashrc
```

### SSHRemediator (handles SSH_UNAUTHORIZED_KEY)

**What it fixes:** Removes the specific key line from the authorized_keys file.

**Pattern:**
1. `backup()` — copies the authorized_keys file to the backup directory
2. `validate()` — confirms the specific key (matched by full key_data string) is still in the file
3. `apply()` — writes the file without the matching key line
4. `verify()` — re-reads the file and confirms the key is absent

**Rollback command example:**
```
cp /var/backups/ubuntils/20240115_143022/authorized_keys /home/bob/.ssh/authorized_keys
```

### SudoersRemediator (handles SUDOERS_NOPASSWD)

**What it fixes:** Removes the NOPASSWD line from the sudoers file or sudoers.d file.

**Pattern:**
1. `backup()` — copies the target sudoers file to the backup directory
2. `validate()` — runs `visudo -cf <file>` to confirm the current file is valid; confirms the line is still present; confirms that removing the line would not leave the system with zero sudo rules (safety check)
3. `apply()` — writes the file without the offending rule; runs `visudo -cf <modified_file>` on the new content before committing it; aborts if visudo rejects the result
4. `verify()` — runs `visudo -cf <file>` on the live file; confirms the NOPASSWD entry is gone

**Rollback command example:**
```
cp /var/backups/ubuntils/20240115_143022/sudoers /etc/sudoers && visudo -cf /etc/sudoers
```

---

## 10. TUI Layout

The TUI is built with Textual. It has three panels switchable via keyboard. The App root in `app.py` owns the `BINDINGS` list and calls `query_one(Panel).focus()` on key press.

### Panel 1 — Findings (key: `1`)

A `DataTable` widget. Columns: `SEVERITY`, `RULE ID`, `TITLE`, `ARTIFACT PATH`, `REMEDIATION`.

Rows are sorted HIGH → MEDIUM → LOW. Within each severity level, rows are sorted alphabetically by rule_id. The `SEVERITY` column uses Rich markup to color badges: HIGH = red, MEDIUM = yellow, LOW = blue. The `REMEDIATION` column shows `✓` if remediation is available.

### Panel 2 — Timeline (key: `2`)

A scrollable `ListView` of timeline events. Each item shows `[TIMESTAMP] SOURCE  description` in a fixed-width monospace format. The panel scrolls to the most recent event on load. Events are presented in ascending chronological order.

### Panel 3 — Stats (key: `3`)

A static summary panel with the following sections:
- **System**: Ubuntu version detected, hostname, kernel version
- **Scan**: start time, end time, duration in seconds
- **Artifacts**: count of entries collected per collector (e.g. "processes: 142", "cron_entries: 7")
- **Findings**: count per severity (HIGH: 2, MEDIUM: 1, LOW: 3)
- **Remediation** (if run): count of SUCCESS / FAILED / SKIPPED results

### Keyboard Navigation

| Key | Action |
|---|---|
| `1` | Switch to Findings panel |
| `2` | Switch to Timeline panel |
| `3` | Switch to Stats panel |
| `Tab` | Cycle to next panel |
| `q` | Quit |
| `Ctrl+C` | Quit |

---

## 11. JSON Output Schema

When `--json` is passed, ubuntils writes a single JSON object to stdout. No other output is produced.

```
{
  "scan_metadata": {
    "ubuntils_version": "1.0.0",
    "scan_start": "2024-01-15T14:30:00Z",      // ISO 8601 UTC
    "scan_end": "2024-01-15T14:31:22Z",
    "duration_seconds": 82.4,
    "ubuntu_version": "22.04",
    "hostname": "prod-web-01",
    "kernel": "5.15.0-91-generic"
  },
  "artifact_counts": {
    "processes": 142,
    "connections": 23,
    "users": 4,
    "cron_entries": 7,
    "timers": 12,
    "authorized_keys": 3,
    "sudoers_rules": 5,
    "env_definitions": 18
  },
  "findings": [
    {
      "rule_id": "CRON_TMP_PATH",
      "severity": "HIGH",
      "title": "Cron job references writable temp directory",
      "description": "...",
      "artifact_path": "/etc/cron.d/cleanup",
      "raw_value": "0 * * * * root /tmp/.update",
      "remediation_available": true,
      "remediation_description": "Will remove the offending cron entry from /etc/cron.d/cleanup"
    }
  ],
  "timeline": [
    {
      "timestamp": "2024-01-15T08:22:01Z",
      "source": "auth.log",
      "description": "sshd: Accepted publickey for alice from 10.0.0.42 port 52341"
    }
  ],
  "remediation_results": [        // present only if --remediate was passed
    {
      "finding_rule_id": "CRON_TMP_PATH",
      "status": "SUCCESS",
      "message": "Removed entry from /etc/cron.d/cleanup",
      "backup_path": "/var/backups/ubuntils/20240115_143022/cleanup",
      "rollback_command": "cp /var/backups/ubuntils/20240115_143022/cleanup /etc/cron.d/cleanup"
    }
  ]
}
```

---

## 12. Ubuntu Version Detection

At scan startup, `cli.py` reads `/etc/os-release` and parses the `VERSION_ID` field. This is a plain text read — no subprocess. The result is stored in a `ScanContext` named tuple passed to all collectors and the timeline builder.

### Adaptation by Version

| Feature | Ubuntu 20.04 | Ubuntu 22.04 | Ubuntu 24.04 |
|---|---|---|---|
| Network tool | `ss` (preferred) or `netstat` fallback | `ss` | `ss` |
| systemctl JSON output | Not supported — parse text | Supported | Supported |
| journald JSON output | Supported | Supported | Supported |
| Python default | 3.8 | 3.10 | 3.12 |

The `NetworkCollector` detects whether `ss` is available by attempting the command and falling back to `netstat` on failure. The `SystemdCollector` detects JSON support by checking the Ubuntu version from `ScanContext` and switches its parsing strategy accordingly.

---

## 13. Error Handling Philosophy

### Collector Failures

If a collector's `collect()` method raises any exception:
- The exception is logged at WARNING level via structlog with the collector name and full traceback
- The collector slot in the artifacts dict is set to `{}`
- Scanning continues with all other collectors
- The Stats panel notes which collectors failed

This means: a permission error reading `/etc/shadow` does not abort the scan. The user sees a warning and continues.

### Rule Errors

If a detection rule raises an exception while processing an artifact:
- The exception is logged at WARNING level with the rule_id
- No Finding is produced for that rule on that artifact
- The scan continues with all other rules and artifacts

Rules are written defensively: they check for key presence before accessing artifact fields.

### Partial Remediation

The remediator engine processes findings sequentially. If one remediator fails:
- The result is recorded as `RemediationStatus.FAILED` with the exception message
- The system is left in its pre-change state (the backup was created but the change was not applied)
- The engine continues to the next finding
- At the end, the user sees a summary of SUCCESS / FAILED / SKIPPED counts

### Dry Run Behavior

Without `--confirm`, `apply()` is never called. The remediator still runs `backup()` and `validate()` in dry-run mode to confirm the remediation would succeed, but writes nothing. The result is `RemediationStatus.SKIPPED` with a message indicating what would have been done.

---

## 14. Security Considerations

### Why Read Files Directly

On a compromised system, binaries like `ps`, `netstat`, and `ls` may have been replaced by rootkit versions that hide attacker processes or files. ubuntils reads `/proc` directly for process data and parses files directly wherever possible, reducing reliance on potentially compromised system binaries.

### Why Never Delete Files

Commenting out rather than deleting lines preserves evidence. If a line in `/etc/sudoers` is deleted, the original content is gone even if the backup exists. Commenting preserves the original file structure and the commented line in place, which aids post-incident review.

### Why visudo Validation Is Mandatory

An invalid sudoers file locks all users out of sudo. Since `apply()` modifies a live sudoers file, ubuntils validates the result with `visudo -cf` before writing and after writing. A failed post-write validation triggers an immediate restore from backup.

### Why --confirm Is Separate from --remediate

`--remediate` alone enables the remediation engine in dry-run mode — it computes what would be done and reports it. `--confirm` is required to actually apply changes. This two-flag design prevents accidental modification on systems where the user only intended to preview remediation.

### Backup Directory Permissions

The backup directory `/var/backups/ubuntils/` is created with mode `0700` owned by root. This prevents other users from reading backed-up credential material (e.g. a backed-up sudoers file or authorized_keys).
