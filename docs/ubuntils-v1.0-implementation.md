# ubuntils v1.0 — Implementation Plan

---

## Dependency Order Summary

The task sequence is strictly ordered by dependency:

```
Phase 1 (scaffold) → Phase 2 (utils) → Phase 3 (base classes)
→ Phase 4 (collectors) → Phase 5 (detectors) → Phase 6 (timeline)
→ Phase 7 (remediators) → Phase 8 (TUI) → Phase 9 (formatters)
→ Phase 10 (CLI wiring) → Phase 11 (testing) → Phase 12 (polish)
```

Within each phase, tasks within that phase are independent of each other and can be done in any order unless otherwise noted.

---

## Phase 1 — Project Scaffold

**Goal:** Establish the installable package skeleton so all subsequent phases have a valid import environment.

---

### Task 1 — Package and entry point

**Files to create:**
- `setup.py`
- `requirements.txt`
- `ubuntils/__init__.py`
- `ubuntils/cli.py` (stub)

**`setup.py` must contain:**
```
name="ubuntils"
version="1.0.0"
packages=find_packages()
install_requires=[click, textual, structlog, pyyaml, python-dateutil]
entry_points={"console_scripts": ["ubuntils=ubuntils.cli:main"]}
python_requires=">=3.8"
```

**`ubuntils/__init__.py` must contain:**
```
__version__ = "1.0.0"
```

**`ubuntils/cli.py` stub must contain:**
- `import click`
- A `@click.group()` function named `main`
- A `@main.command()` named `scan` with `--json`, `--remediate`, `--confirm`, `--verbose` options (all no-ops for now)
- A `@main.command()` named `version` that prints `__version__`

**`requirements.txt` must pin:**
```
click>=8.1.0
textual>=0.50.0
structlog>=24.0.0
pyyaml>=6.0
python-dateutil>=2.8
pytest>=7.0
pytest-cov>=4.0
```

**Tests to write:** None — this phase produces runnable but empty commands. Verify manually: `ubuntils --help` and `ubuntils version` work after `pip install -e .`.

**Commit message:** `feat: scaffold package structure and CLI entry point`

---

### Task 2 — Directory skeleton

**Files to create:**
- `ubuntils/collectors/__init__.py` (empty)
- `ubuntils/detectors/__init__.py` (empty)
- `ubuntils/timeline/__init__.py` (empty)
- `ubuntils/remediators/__init__.py` (empty)
- `ubuntils/formatters/__init__.py` (empty)
- `ubuntils/tui/__init__.py` (empty)
- `ubuntils/utils/__init__.py` (empty)
- `tests/__init__.py` (empty)
- `tests/conftest.py` (stub with a comment placeholder)

**Commit message:** `chore: create package subdirectory skeletons`

---

## Phase 2 — Utilities

**Goal:** Build shared helpers that all other modules depend on. No business logic yet.

---

### Task 3 — Shell utility

**Files to create or modify:** `ubuntils/utils/shell.py`

**Must contain:**
```
def run_command(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """
    Run cmd as a subprocess.
    Returns (stdout, stderr, returncode).
    Never raises — on exception returns ("", str(exception), -1).
    """
```

Implementation uses `subprocess.run` with `capture_output=True`, `text=True`, and the provided timeout. On `TimeoutExpired` or `OSError`, returns the error as stderr and returncode -1.

**Tests to write** (`tests/test_base_classes.py` or a new `tests/test_utils.py`):
- `test_run_command_success`: runs `["echo", "hello"]`, asserts stdout contains "hello" and returncode is 0
- `test_run_command_nonexistent`: runs `["__nonexistent_binary__"]`, asserts returncode is -1 and stderr is non-empty
- `test_run_command_timeout`: runs `["sleep", "60"]` with timeout=0, asserts returncode is -1

**Commit message:** `feat: add safe subprocess shell utility`

---

### Task 4 — Logging configuration

**Files to create or modify:** `ubuntils/utils/logging.py`

**Must contain:**
```
def configure_logging(json_mode: bool, verbose: bool) -> None:
    """
    Configure structlog for the session.
    json_mode=True: JSONRenderer processor chain.
    json_mode=False: ConsoleRenderer processor chain.
    verbose=True: sets log level to DEBUG; False: INFO.
    """
```

The structlog configuration must set up:
- Timestamper processor
- Log level filtering
- `JSONRenderer` if `json_mode=True`, else `ConsoleRenderer`
- Bound to stdlib logging backend

**Tests to write:** None for this task — structlog configuration is integration-level. Covered implicitly by later tests that invoke the logging setup.

**Commit message:** `feat: add structlog configuration for TUI and JSON modes`

---

### Task 5 — Validators

**Files to create or modify:** `ubuntils/utils/validators.py`

**Must contain:**
```
STANDARD_LIB_PATHS = ["/lib", "/usr/lib", "/lib64", "/usr/lib64"]
STANDARD_BIN_PATHS = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
NOLOGIN_SHELLS = ["/sbin/nologin", "/bin/false", "/usr/sbin/nologin"]

def is_login_shell(shell: str) -> bool:
    """Returns True if shell is not in NOLOGIN_SHELLS."""

def uid_is_system(uid: int) -> bool:
    """Returns True if uid < 1000."""

def path_in_standard_libs(path: str) -> bool:
    """Returns True if path starts with any STANDARD_LIB_PATHS entry."""

def path_in_standard_bins(path: str) -> bool:
    """Returns True if path starts with any STANDARD_BIN_PATHS entry."""

def path_in_writable_tmp(path: str) -> bool:
    """Returns True if path starts with /tmp, /var/tmp, or /dev/shm."""
```

**Tests to write** (in `tests/test_base_classes.py` or `tests/test_utils.py`):
- `test_is_login_shell_nologin`: asserts `is_login_shell("/sbin/nologin")` is False
- `test_is_login_shell_bash`: asserts `is_login_shell("/bin/bash")` is True
- `test_uid_is_system`: asserts `uid_is_system(0)` is True, `uid_is_system(1000)` is False
- `test_path_in_standard_libs`: asserts `/usr/lib/x86_64-linux-gnu/libc.so` returns True
- `test_path_in_writable_tmp`: asserts `/tmp/foo.so` returns True, `/usr/lib/foo.so` returns False

**Commit message:** `feat: add path and uid validators`

---

## Phase 3 — Base Classes

**Goal:** Define the ABCs that all collectors and remediators must implement, enforcing the interface before any implementations exist.

---

### Task 6 — BaseCollector

**Files to create or modify:** `ubuntils/collectors/base.py`

**Must contain:**
```
from abc import ABC, abstractmethod

class BaseCollector(ABC):
    @abstractmethod
    def collect(self) -> dict:
        """
        Collect forensic artifacts.
        Returns a dict of collected data.
        Must not raise — log exceptions and return {}.
        """
```

**Tests to write** (`tests/test_base_classes.py`):
- `test_base_collector_cannot_instantiate`: asserts `BaseCollector()` raises `TypeError`
- `test_base_collector_subclass_must_implement_collect`: defines a subclass without `collect`, asserts instantiation raises `TypeError`
- `test_base_collector_subclass_valid`: defines a subclass that implements `collect`, asserts it instantiates and `collect()` is callable

**Commit message:** `feat: add BaseCollector abstract base class`

---

### Task 7 — BaseRemediator

**Files to create or modify:** `ubuntils/remediators/base.py`

**Must contain:**
```
from abc import ABC, abstractmethod
from ubuntils.detectors.finding import Finding, RemediationResult

class BaseRemediator(ABC):
    BACKUP_BASE = "/var/backups/ubuntils"

    @abstractmethod
    def backup(self, finding: Finding) -> str:
        """Create a timestamped backup. Returns the backup path."""

    @abstractmethod
    def validate(self, finding: Finding) -> None:
        """Validate that remediation is safe to apply. Raises ValueError if not."""

    @abstractmethod
    def apply(self, finding: Finding, dry_run: bool) -> str:
        """Apply the remediation. Returns a human-readable message."""

    @abstractmethod
    def verify(self, finding: Finding) -> None:
        """Verify the change was applied. Raises ValueError if verification fails."""

    def remediate(self, finding: Finding, dry_run: bool = True) -> RemediationResult:
        """
        Orchestrates backup → validate → apply → verify.
        Returns RemediationResult.
        On any failure: returns FAILED status, system unchanged.
        """
```

The `remediate()` method must catch all exceptions from each step and return a `RemediationResult` with `status=FAILED` and the exception message.

**Tests to write** (`tests/test_base_classes.py`):
- `test_base_remediator_cannot_instantiate`: asserts `BaseRemediator()` raises `TypeError`
- `test_remediate_skipped_on_dry_run`: creates a concrete subclass where `apply()` raises; asserts that in dry_run mode `apply()` is still called (dry_run is passed through, not suppressed at the orchestrator level — the subclass decides what dry_run means)
- `test_remediate_returns_failed_on_validate_error`: subclass where `validate()` raises `ValueError("unsafe")`; asserts result status is FAILED and message contains "unsafe"

**Commit message:** `feat: add BaseRemediator abstract base class with orchestration`

---

### Task 8 — Finding and enums

**Files to create or modify:** `ubuntils/detectors/finding.py`

**Must contain:**
```
from dataclasses import dataclass
from enum import Enum
from typing import Optional

class Severity(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class RemediationStatus(Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"

@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    artifact_path: str
    raw_value: str
    remediation_available: bool
    remediation_description: Optional[str] = None

@dataclass
class RemediationResult:
    finding_rule_id: str
    status: RemediationStatus
    message: str
    backup_path: Optional[str] = None
    rollback_command: Optional[str] = None
```

**Tests to write** (`tests/test_base_classes.py`):
- `test_finding_creation`: creates a Finding with all fields, asserts field values are accessible
- `test_finding_severity_enum`: asserts `Severity.HIGH.value == "HIGH"`
- `test_remediation_result_creation`: creates a RemediationResult, asserts fields

**Commit message:** `feat: add Finding, RemediationResult dataclasses and enums`

---

## Phase 4 — Collectors

**Goal:** Implement all 8 collectors. Each is independent.

**Test strategy for all collectors:** Use `unittest.mock.patch` to mock:
- `builtins.open` — return a `StringIO` with known file content
- `ubuntils.utils.shell.run_command` — return known command output

Each collector test creates a fixture with realistic sample content containing both normal and suspicious entries, runs `collect()`, and asserts the returned dict has the expected structure and values.

---

### Task 9 — ProcessCollector

**Files to create or modify:** `ubuntils/collectors/processes.py`

**`collect()` must:**
- Iterate `/proc/*/status` (glob)
- For each PID: read `Name` and `Uid` from status file; resolve `/proc/<pid>/exe` symlink; read `/proc/<pid>/cmdline` (null-byte separated)
- Return a dict with key `"processes"` containing a list of process dicts per schema
- Skip PIDs that disappear between glob and read (race condition — catch `FileNotFoundError`)

**Tests to write** (`tests/test_collectors.py`):
- `test_process_collector_parses_status`: mocks `/proc/1/status` with a known Name/Uid; asserts the output includes the correct pid, name, uid
- `test_process_collector_skips_missing_pid`: mocks a PID directory that vanishes mid-read; asserts no exception and the PID is absent from results
- `test_process_collector_returns_empty_on_total_failure`: mocks all /proc reads to raise; asserts returns `{}`

**Commit message:** `feat: implement ProcessCollector`

---

### Task 10 — NetworkCollector

**Files to create or modify:** `ubuntils/collectors/network.py`

**`collect()` must:**
- Try `run_command(["ss", "-tunap"])` first
- If returncode != 0, fall back to `run_command(["netstat", "-tunap"])`
- Parse the output into connection dicts per schema
- Return a dict with key `"connections"`

**Tests to write** (`tests/test_collectors.py`):
- `test_network_collector_parses_ss_output`: mocks `run_command` to return sample `ss` output; asserts correct parsing of proto, local_addr, local_port, state, pid
- `test_network_collector_falls_back_to_netstat`: mocks `ss` to return returncode=1; mocks `netstat` to return valid output; asserts results are populated
- `test_network_collector_both_fail`: mocks both commands to fail; asserts returns `{}`

**Commit message:** `feat: implement NetworkCollector with ss/netstat fallback`

---

### Task 11 — UserCollector

**Files to create or modify:** `ubuntils/collectors/users.py`

**`collect()` must:**
- Parse `/etc/passwd` line by line
- Parse `/etc/group` to build username→groups mapping
- Attempt to read `/etc/shadow` (may fail without root — log and continue)
- Return dict with key `"users"` per schema

**Tests to write** (`tests/test_collectors.py`):
- `test_user_collector_parses_passwd`: mocks `/etc/passwd` with two users; asserts uid, shell, home are correct
- `test_user_collector_marks_nologin`: asserts `is_login_shell` is False for a user with shell `/sbin/nologin`
- `test_user_collector_shadow_permission_error`: mocks `/etc/shadow` open to raise `PermissionError`; asserts collector returns successfully with `password_locked=None`

**Commit message:** `feat: implement UserCollector`

---

### Task 12 — CronCollector

**Files to create or modify:** `ubuntils/collectors/cron.py`

**`collect()` must:**
- Read `/etc/crontab` and `/etc/cron.d/*` (system crontabs — 7-field format with run_as user)
- Read `/var/spool/cron/crontabs/*` (user crontabs — 5-field format)
- Skip comment lines (starting with `#`) and blank lines
- Return dict with key `"cron_entries"` per schema

**Tests to write** (`tests/test_collectors.py`):
- `test_cron_collector_parses_system_crontab`: mocks `/etc/crontab` with a known entry; asserts owner="root", run_as parsed correctly
- `test_cron_collector_parses_user_crontab`: mocks `/var/spool/cron/crontabs/alice`; asserts owner="alice"
- `test_cron_collector_skips_comments`: asserts comment lines are not in results

**Commit message:** `feat: implement CronCollector`

---

### Task 13 — SystemdCollector

**Files to create or modify:** `ubuntils/collectors/systemd.py`

**`collect()` must:**
- Check `scan_context.ubuntu_version` — if 22.04 or 24.04, run `systemctl list-timers --all --no-pager --output json`; if 20.04, run without `--output json` and parse text
- For each timer, locate the associated `.service` unit file and read `ExecStart=` from it
- Stat the ExecStart path to determine owner
- Return dict with key `"timers"` per schema

**Tests to write** (`tests/test_collectors.py`):
- `test_systemd_collector_parses_json_output`: mocks `run_command` returning JSON; asserts timer list populated
- `test_systemd_collector_parses_text_output`: mocks text-format output (20.04 mode); asserts same result shape
- `test_systemd_collector_handles_missing_unit_file`: mocks a timer whose service unit file does not exist; asserts it is skipped with a warning log

**Commit message:** `feat: implement SystemdCollector with 20.04/22.04+ adaptation`

---

### Task 14 — SSHCollector

**Files to create or modify:** `ubuntils/collectors/ssh.py`

**`collect()` must:**
- For every user in `/etc/passwd` with a non-empty home directory, check if `~/.ssh/authorized_keys` exists
- Read the file, get its mtime via `os.stat`, and parse each key line (skip blank lines and comments)
- Return dict with key `"authorized_keys"` per schema

**Tests to write** (`tests/test_collectors.py`):
- `test_ssh_collector_parses_authorized_keys`: mocks an `authorized_keys` file with two entries; asserts both entries are in results with correct key_type and comment
- `test_ssh_collector_skips_missing_file`: user has home dir but no `.ssh/authorized_keys`; asserts no entry for that user
- `test_ssh_collector_records_mtime`: asserts `file_mtime` is a float from `os.stat`

**Commit message:** `feat: implement SSHCollector`

---

### Task 15 — SudoersCollector

**Files to create or modify:** `ubuntils/collectors/sudoers.py`

**`collect()` must:**
- Read `/etc/sudoers`
- Read every file under `/etc/sudoers.d/`
- Parse each rule line into the schema fields; skip `#include`, `@include`, comment lines, and blank lines
- Return dict with key `"sudoers_rules"` per schema

**Tests to write** (`tests/test_collectors.py`):
- `test_sudoers_collector_parses_nopasswd_rule`: mocks a sudoers file with a NOPASSWD line; asserts `options` contains "NOPASSWD"
- `test_sudoers_collector_skips_includes`: asserts `#include` and `@include` lines are not in results
- `test_sudoers_collector_reads_sudoers_d`: mocks a file under `/etc/sudoers.d/`; asserts it is included in results

**Commit message:** `feat: implement SudoersCollector`

---

### Task 16 — EnvironmentCollector

**Files to create or modify:** `ubuntils/collectors/environment.py`

**`collect()` must:**
- Read `/etc/environment` (KEY=value format, no `export` keyword)
- Read `/etc/profile` and `/etc/profile.d/*`
- For every user with a login shell: read `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `~/.zprofile` if they exist
- Parse `export KEY=value` and `KEY=value` lines
- Return dict with key `"env_definitions"` per schema

**Tests to write** (`tests/test_collectors.py`):
- `test_env_collector_parses_ld_preload`: mocks a `.bashrc` containing `export LD_PRELOAD=/tmp/evil.so`; asserts the variable and value are in results
- `test_env_collector_reads_etc_environment`: mocks `/etc/environment`; asserts entries have `owner="system"`
- `test_env_collector_skips_nonexistent_files`: user home has no `.bashrc`; asserts no exception

**Commit message:** `feat: implement EnvironmentCollector`

---

### Task 17 — Collector registry

**Files to create or modify:** `ubuntils/collectors/__init__.py`

**Must contain:**
```
from ubuntils.collectors.processes import ProcessCollector
from ubuntils.collectors.network import NetworkCollector
from ubuntils.collectors.users import UserCollector
from ubuntils.collectors.cron import CronCollector
from ubuntils.collectors.systemd import SystemdCollector
from ubuntils.collectors.ssh import SSHCollector
from ubuntils.collectors.sudoers import SudoersCollector
from ubuntils.collectors.environment import EnvironmentCollector

ALL_COLLECTORS = [
    ProcessCollector,
    NetworkCollector,
    UserCollector,
    CronCollector,
    SystemdCollector,
    SSHCollector,
    SudoersCollector,
    EnvironmentCollector,
]
```

**Tests to write** (`tests/test_collectors.py`):
- `test_all_collectors_registered`: asserts `len(ALL_COLLECTORS) == 8`
- `test_all_collectors_are_base_collector_subclasses`: asserts every class in `ALL_COLLECTORS` is a subclass of `BaseCollector`

**Commit message:** `feat: register all collectors in collector package`

---

## Phase 5 — Detection Engine

**Goal:** Implement all 8 rules and the engine that runs them.

**Test strategy:** Each rule test in `tests/test_detection_rules.py` receives a hand-crafted artifact dict with a known-bad value. The test calls the rule function directly (not via the engine) and asserts the returned findings list is non-empty with the expected `rule_id`, `severity`, and `raw_value`. A companion test provides clean artifact data and asserts an empty findings list (no false positives).

---

### Task 18 — Detection rules

**Files to create or modify:** `ubuntils/detectors/rules.py`

Each rule is a standalone function:
```
def rule_cron_root_exec(artifacts: dict) -> list[Finding]: ...
def rule_cron_tmp_path(artifacts: dict) -> list[Finding]: ...
def rule_ld_preload_inject(artifacts: dict) -> list[Finding]: ...
def rule_suspicious_systemd_timer(artifacts: dict) -> list[Finding]: ...
def rule_ssh_unauthorized_key(artifacts: dict) -> list[Finding]: ...
def rule_sudoers_nopasswd(artifacts: dict) -> list[Finding]: ...
def rule_process_masquerade(artifacts: dict) -> list[Finding]: ...
def rule_shell_rc_modification(artifacts: dict) -> list[Finding]: ...
```

Each function:
- Checks for the relevant key in `artifacts` before accessing it (graceful on empty dict)
- Returns a list of zero or more `Finding` objects
- Sets `remediation_available=False` for rules 7 and 8

**Tests to write** (`tests/test_detection_rules.py`):
- For each of the 8 rules: `test_rule_<name>_detects_bad`: provides known-bad artifact fixture, asserts finding is produced with correct rule_id and severity
- For each of the 8 rules: `test_rule_<name>_clean`: provides clean artifact fixture, asserts no findings
- `test_rule_cron_root_exec_sudo_keyword`: provides a cron entry with inline sudo; asserts HIGH finding
- `test_rule_ld_preload_standard_path_no_finding`: LD_PRELOAD set to `/usr/lib/something.so`; asserts no finding
- `test_rule_sudoers_nopasswd_system_user_no_finding`: NOPASSWD for uid < 1000; asserts no finding
- `test_rule_ssh_key_old_file_no_finding`: mtime is 30 days ago; asserts no finding

**Commit message:** `feat: implement all 8 detection rules`

---

### Task 19 — DetectionEngine

**Files to create or modify:** `ubuntils/detectors/engine.py`

**Must contain:**
```
from ubuntils.detectors.rules import (
    rule_cron_root_exec,
    rule_cron_tmp_path,
    rule_ld_preload_inject,
    rule_suspicious_systemd_timer,
    rule_ssh_unauthorized_key,
    rule_sudoers_nopasswd,
    rule_process_masquerade,
    rule_shell_rc_modification,
)

ALL_RULES = [
    rule_cron_root_exec,
    rule_cron_tmp_path,
    rule_ld_preload_inject,
    rule_suspicious_systemd_timer,
    rule_ssh_unauthorized_key,
    rule_sudoers_nopasswd,
    rule_process_masquerade,
    rule_shell_rc_modification,
]

class DetectionEngine:
    def run(self, artifacts: dict) -> list[Finding]:
        """
        Run all rules over artifacts.
        If a rule raises, log the exception and continue.
        Returns all findings from all rules.
        """
```

**Tests to write** (`tests/test_detection_rules.py`):
- `test_engine_runs_all_rules`: mocks each rule function to return one finding; asserts engine result has 8 findings
- `test_engine_continues_on_rule_error`: one rule raises; asserts engine returns findings from remaining rules and does not raise
- `test_engine_empty_artifacts`: passes `{}` to engine; asserts returns empty list with no exceptions

**Commit message:** `feat: implement DetectionEngine`

---

## Phase 6 — Timeline

**Goal:** Parse log sources and produce a sorted, deduplicated event list.

---

### Task 20 — TimelineBuilder

**Files to create or modify:** `ubuntils/timeline/builder.py`

**Must contain:**
```
from dataclasses import dataclass
from datetime import datetime

@dataclass
class TimelineEvent:
    timestamp: datetime
    source: str
    description: str

class TimelineBuilder:
    def build(self, since_days: int = 7) -> list[TimelineEvent]:
        """
        Read syslog, journald, and auditd.
        Parse and normalize timestamps.
        Deduplicate and sort ascending.
        Returns list[TimelineEvent].
        """

    def _parse_syslog(self, path: str) -> list[TimelineEvent]: ...
    def _parse_journald(self, since_days: int) -> list[TimelineEvent]: ...
    def _parse_auditd(self, path: str) -> list[TimelineEvent]: ...
```

**Tests to write** (`tests/test_timeline.py`):
- `test_parse_syslog_basic`: passes a sample syslog snippet (3 lines, known timestamps); asserts 3 events with correct timestamps and descriptions
- `test_parse_syslog_year_injection`: passes a syslog line with no year; asserts the year is the current year
- `test_parse_journald_json`: mocks `run_command(["journalctl", ...])` returning JSON lines; asserts events parsed with microsecond precision timestamps
- `test_parse_auditd_execve`: passes an auditd `EXECVE` record; asserts event is parsed with correct Unix timestamp
- `test_build_deduplicates`: passes two sources with an overlapping event (same rounded timestamp, source, description); asserts result has one entry
- `test_build_sorted_ascending`: passes events from multiple sources out of order; asserts result is sorted by timestamp

**Commit message:** `feat: implement TimelineBuilder with syslog/journald/auditd parsing`

---

## Phase 7 — Remediators

**Goal:** Implement all 4 remediators. Each depends on BaseRemediator (Task 7) and the Finding model (Task 8).

**Test strategy:** All remediator tests in `tests/test_remediators.py` use `tmp_path` pytest fixtures to create real temporary files. Tests never modify `/etc/`, `/var/spool/`, or any real system path. The `dry_run=True` mode is tested by verifying the file is unchanged after `remediate()` runs. The `dry_run=False` mode is tested against tmp files and verifies the change was applied and a backup was created.

---

### Task 21 — CronRemediator

**Files to create or modify:** `ubuntils/remediators/cron.py`

**Handles:** `CRON_ROOT_EXEC`, `CRON_TMP_PATH`

**`backup()`**: copies `finding.artifact_path` to `BACKUP_BASE/timestamp/basename`
**`validate()`**: reads the file and asserts the `finding.raw_value` line is still present
**`apply(dry_run)`**: if not dry_run, writes the file without the offending line; if dry_run, does nothing
**`verify()`**: reads the file and asserts the `finding.raw_value` line is absent

**Tests to write:**
- `test_cron_remediator_removes_entry_dry_run_false`: creates a tmp cron file with a malicious entry; runs `remediate(dry_run=False)`; asserts the entry is gone and backup exists
- `test_cron_remediator_dry_run_leaves_file_unchanged`: asserts file content is identical after `remediate(dry_run=True)`
- `test_cron_remediator_returns_failed_if_entry_missing`: the offending line has already been removed; asserts FAILED status

**Commit message:** `feat: implement CronRemediator`

---

### Task 22 — EnvironmentRemediator

**Files to create or modify:** `ubuntils/remediators/environment.py`

**Handles:** `LD_PRELOAD_INJECT`

**`apply()`**: replaces the matching line with `# [ubuntils-removed] <original line>` — uses exact string replace, not regex, to avoid modifying surrounding lines
**`verify()`**: reads the file and asserts no uncommented LD_PRELOAD line is present

**Tests to write:**
- `test_env_remediator_comments_out_ld_preload`: tmp `.bashrc` with `export LD_PRELOAD=/tmp/evil.so`; asserts after remediation the line is commented, not deleted
- `test_env_remediator_preserves_surrounding_lines`: asserts all other lines in the file are unchanged
- `test_env_remediator_dry_run_leaves_file_unchanged`: asserts file is unchanged

**Commit message:** `feat: implement EnvironmentRemediator`

---

### Task 23 — SSHRemediator

**Files to create or modify:** `ubuntils/remediators/ssh.py`

**Handles:** `SSH_UNAUTHORIZED_KEY`

**`validate()`**: matches by full key_data string (the base64 portion)
**`apply()`**: writes the file without the line containing the matching key_data
**`verify()`**: reads the file and asserts no line contains the key_data

**Tests to write:**
- `test_ssh_remediator_removes_key`: tmp `authorized_keys` with two keys; removes one; asserts the other remains
- `test_ssh_remediator_does_not_remove_partial_match`: key_data is a substring of another key; asserts wrong key is not removed

**Commit message:** `feat: implement SSHRemediator`

---

### Task 24 — SudoersRemediator

**Files to create or modify:** `ubuntils/remediators/sudoers.py`

**Handles:** `SUDOERS_NOPASSWD`

**`validate()`**: runs `visudo -cf <file>` on the current file; asserts the offending line is present; asserts removing the line would not leave the system with zero sudo rules (counts remaining non-comment rule lines)
**`apply()`**: writes new content without the line; runs `visudo -cf` on the new content via a temp file before renaming; only renames if visudo passes
**`verify()`**: runs `visudo -cf <file>` on the live file

Note: `visudo -cf` in tests will be mocked — we do not require visudo to be installed in the test environment.

**Tests to write:**
- `test_sudoers_remediator_removes_nopasswd_line`: tmp sudoers file; mocks `run_command(["visudo", "-cf", ...])` to return 0; asserts line removed
- `test_sudoers_remediator_aborts_if_visudo_rejects`: mocks visudo to return returncode=1; asserts FAILED status and file unchanged
- `test_sudoers_remediator_aborts_if_last_rule`: sudoers file has only the NOPASSWD line; asserts FAILED with message about not removing all sudo access

**Commit message:** `feat: implement SudoersRemediator`

---

### Task 25 — Remediator registry

**Files to create or modify:** `ubuntils/remediators/__init__.py`

**Must contain:**
```
from ubuntils.remediators.cron import CronRemediator
from ubuntils.remediators.environment import EnvironmentRemediator
from ubuntils.remediators.ssh import SSHRemediator
from ubuntils.remediators.sudoers import SudoersRemediator

REMEDIATOR_REGISTRY = {
    "CRON_ROOT_EXEC": CronRemediator,
    "CRON_TMP_PATH": CronRemediator,
    "LD_PRELOAD_INJECT": EnvironmentRemediator,
    "SSH_UNAUTHORIZED_KEY": SSHRemediator,
    "SUDOERS_NOPASSWD": SudoersRemediator,
}

def get_remediator(rule_id: str):
    """Returns an instantiated remediator for rule_id, or None if no remediator exists."""
```

**Tests to write:**
- `test_remediator_registry_has_four_rules`: asserts `len(REMEDIATOR_REGISTRY) == 5` (5 rule_ids mapped, 4 unique classes)
- `test_get_remediator_unknown_rule`: asserts `get_remediator("PROCESS_MASQUERADE")` returns None

**Commit message:** `feat: register all remediators in remediator package`

---

## Phase 8 — TUI

**Goal:** Build the Textual TUI. This phase depends on Phase 5 (findings list) and Phase 6 (timeline list).

---

### Task 26 — FindingsPanel

**Files to create or modify:** `ubuntils/tui/findings_panel.py`

**Must contain:**
```
from textual.widgets import DataTable
from textual.app import ComposeResult

class FindingsPanel(DataTable):
    def load_findings(self, findings: list[Finding]) -> None:
        """
        Sort findings HIGH→MEDIUM→LOW.
        Populate DataTable with columns: SEVERITY, RULE ID, TITLE, ARTIFACT PATH, REMEDIATION.
        Color SEVERITY cell using Rich markup.
        """
```

**Tests to write:** None in `tests/` — TUI widget tests require a running Textual app. Manual verification: launch with known findings and confirm sort order and colors.

**Commit message:** `feat: implement FindingsPanel TUI widget`

---

### Task 27 — TimelinePanel

**Files to create or modify:** `ubuntils/tui/timeline_panel.py`

**Must contain:**
```
from textual.widgets import ListView, ListItem
from textual.app import ComposeResult

class TimelinePanel(ListView):
    def load_events(self, events: list[TimelineEvent]) -> None:
        """Populate list with formatted [TIMESTAMP] SOURCE  description rows."""
```

**Commit message:** `feat: implement TimelinePanel TUI widget`

---

### Task 28 — StatsPanel

**Files to create or modify:** `ubuntils/tui/stats_panel.py`

**Must contain:**
```
from textual.widgets import Static

class StatsPanel(Static):
    def load_stats(self, scan_metadata: dict, artifact_counts: dict,
                   findings: list[Finding], remediation_results: list[RemediationResult]) -> None:
        """Render static summary text with all stats sections."""
```

**Commit message:** `feat: implement StatsPanel TUI widget`

---

### Task 29 — UbuntilsApp

**Files to create or modify:** `ubuntils/tui/app.py`

**Must contain:**
```
from textual.app import App, ComposeResult
from textual.binding import Binding

class UbuntilsApp(App):
    BINDINGS = [
        Binding("1", "show_findings", "Findings"),
        Binding("2", "show_timeline", "Timeline"),
        Binding("3", "show_stats", "Stats"),
        Binding("tab", "next_panel", "Next"),
        Binding("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult: ...
    def action_show_findings(self) -> None: ...
    def action_show_timeline(self) -> None: ...
    def action_show_stats(self) -> None: ...
    def action_next_panel(self) -> None: ...
```

`compose()` creates and mounts FindingsPanel, TimelinePanel, StatsPanel. Only the active panel is visible (CSS `display: none` on inactive panels).

**Commit message:** `feat: implement UbuntilsApp Textual root with panel switching`

---

## Phase 9 — JSON Formatter

**Goal:** Implement the JSON output path for `--json` mode.

---

### Task 30 — JSONFormatter

**Files to create or modify:** `ubuntils/formatters/json_formatter.py`

**Must contain:**
```
import json
from datetime import datetime

class JSONFormatter:
    def format(self,
               scan_metadata: dict,
               artifact_counts: dict,
               findings: list[Finding],
               timeline: list[TimelineEvent],
               remediation_results: list[RemediationResult]) -> str:
        """
        Serialize all scan results to a JSON string.
        Findings severity and RemediationStatus are serialized as their .value strings.
        Timestamps are ISO 8601 UTC strings.
        Returns a single JSON string suitable for print() to stdout.
        """
```

**Tests to write** (`tests/test_json_formatter.py`):
- `test_json_formatter_produces_valid_json`: passes sample data; asserts `json.loads()` does not raise
- `test_json_formatter_findings_severity_is_string`: asserts findings[0].severity in output is `"HIGH"` not the enum object
- `test_json_formatter_timestamps_are_iso8601`: asserts timeline events have string timestamps matching ISO 8601 format
- `test_json_formatter_remediation_results_absent_when_empty`: passes empty remediation list; asserts `"remediation_results"` key is absent from output (or is an empty list — document which)
- `test_json_formatter_all_top_level_keys_present`: asserts `scan_metadata`, `artifact_counts`, `findings`, `timeline` are all present

**Commit message:** `feat: implement JSONFormatter`

---

## Phase 10 — CLI Wiring

**Goal:** Connect the CLI flags to the full scan pipeline.

---

### Task 31 — Scan pipeline

**Files to create or modify:** `ubuntils/cli.py`

**`scan` command must:**
1. Call `configure_logging(json_mode, verbose)`
2. Read `/etc/os-release` and create a `ScanContext`
3. Instantiate and run all collectors; collect artifacts into a merged dict; record start/end time and per-collector counts
4. Run `DetectionEngine().run(artifacts)`
5. Run `TimelineBuilder().build()`
6. If `--remediate`: iterate findings, look up remediators, call `remediate(dry_run=not confirm)`, collect results
7. If `--json`: print `JSONFormatter().format(...)` to stdout and exit
8. Otherwise: instantiate `UbuntilsApp`, pass all results, call `app.run()`

**Tests to write:** None for the CLI itself — integration-level. The scan pipeline is implicitly tested by prior unit tests. Manual integration test is described in the Definition of Done.

**Commit message:** `feat: wire full scan pipeline into CLI`

---

## Phase 11 — Testing Pass

**Goal:** Ensure all test files are complete, all tests pass, and coverage meets the target.

---

### Task 32 — Test fixtures

**Files to create or modify:** `tests/conftest.py`

**Must provide:**
- `sample_process_artifact`: a dict matching the ProcessCollector schema with one normal and one masquerading process
- `sample_cron_artifact`: a dict with one clean entry and one `/tmp`-referencing entry
- `sample_sudoers_artifact`: a dict with one normal rule and one NOPASSWD rule for uid >= 1000
- `sample_ssh_artifact`: a dict with one key file that has a very recent mtime (within 7 days)
- `sample_env_artifact`: a dict with one LD_PRELOAD pointing outside standard lib paths
- `tmp_cron_file`: a `tmp_path`-based fixture returning a Path to a temporary cron file
- `tmp_sudoers_file`: same for a sudoers file
- `tmp_authorized_keys_file`: same for an authorized_keys file

**Commit message:** `test: add shared pytest fixtures in conftest`

---

### Task 33 — Coverage gate

**Files to create or modify:** `setup.py` (or a new `pytest.ini` / `setup.cfg`)

Add pytest configuration:
```
[tool:pytest]
addopts = --cov=ubuntils --cov-report=term-missing --cov-fail-under=80
```

The `--cov-fail-under=80` flag makes the test suite fail if line coverage drops below 80%.

**Commit message:** `test: add 80% coverage gate to pytest config`

---

## Phase 12 — Polish

**Goal:** Final documentation and presentation layer.

---

### Task 34 — README

**Files to create or modify:** `README.md`

**Must cover:**
- One-paragraph description of what ubuntils does
- Requirements: Ubuntu 20.04/22.04/24.04, Python 3.8+, root
- Installation: `pip install -e .` or package install
- Usage: full CLI reference for `scan` and `version` commands with all flags
- TUI keyboard navigation table
- JSON output note
- A note on remediation safeguards

**Commit message:** `docs: write README with installation and usage guide`

---

### Task 35 — Final integration verification

This task has no code. Before marking v1.0 complete, the developer must run the full integration checklist in the Definition of Done section below and verify every item manually.

**Commit message:** (None — this task produces no commit.)

---

## Test Strategy

### Collectors — Mocking Strategy

Collectors read from the filesystem and run subprocesses. Neither is available in a standard CI environment without root. Tests mock at two levels:

- **File reads**: use `unittest.mock.mock_open` or `unittest.mock.patch("builtins.open", ...)` to return controlled `StringIO` content for known paths. For glob patterns (e.g. `/proc/*/status`), mock `glob.glob` to return a fixed list of fake paths.
- **Subprocess calls**: patch `ubuntils.utils.shell.run_command` to return a tuple of `(stdout_str, "", 0)` with known command output.

Each collector test includes both a "happy path" test (realistic valid content) and an error path test (permission error, missing file, empty output). The error path must assert the collector returns `{}` and does not raise.

### Detection Rules — Fixture Strategy

Each rule test uses a minimal artifact dict containing only the keys relevant to that rule. The known-bad fixture contains exactly one problematic entry — this makes failure messages easy to read. A companion clean fixture contains only valid entries.

Rules 5 (SSH_UNAUTHORIZED_KEY) and 8 (SHELL_RC_MODIFICATION) depend on wall-clock time (mtime comparisons). Tests for these rules must set mtime explicitly via `os.utime` on tmp files, or mock `time.time()` to a known value.

### Remediators — Tmp Directory Strategy

All remediator tests use pytest's `tmp_path` fixture. Tests:
1. Write a temp file with the known-bad content
2. Construct a `Finding` with `artifact_path` pointing to the temp file
3. Run `remediate(dry_run=False)` (or `dry_run=True` for dry-run tests)
4. Assert the temp file content is as expected
5. Assert the backup was created under `tmp_path/backups/`

The `BACKUP_BASE` path in `BaseRemediator` is overridden in tests to point to `tmp_path` rather than `/var/backups/ubuntils/`.

`visudo` calls in `SudoersRemediator` tests are mocked via `patch("ubuntils.utils.shell.run_command")`.

### Timeline — Snippet Strategy

Timeline tests pass raw log content as strings to `_parse_syslog()`, `_parse_journald()`, and `_parse_auditd()` directly (not via the filesystem). Each test snippet contains 3–5 log lines with known timestamps. Tests assert that:
- The correct number of events was parsed
- Timestamps are timezone-aware UTC datetimes
- The sort and deduplication logic works correctly

---

## Definition of Done for v1.0

The following checklist must be fully satisfied before the v1.0 tag is applied. Every item is binary — it either passes or it does not.

### Code

- [ ] All files in the directory structure exist and are non-empty
- [ ] `pip install -e .` succeeds without errors
- [ ] `ubuntils --help` prints usage
- [ ] `ubuntils version` prints `1.0.0`

### Tests

- [ ] `pytest` exits 0 with no failures or errors
- [ ] Coverage is at or above 80% across all `ubuntils/` modules
- [ ] All 8 detection rules have at least one positive and one negative test
- [ ] All 4 remediators have at least a dry-run test and a live-change test against a tmp file
- [ ] Timeline parser tests cover all three log sources

### Functionality (manual, requires root on Ubuntu 20.04/22.04/24.04)

- [ ] `sudo ubuntils scan` launches the TUI with no Python exceptions in output
- [ ] TUI panel switching with `1`, `2`, `3`, and `Tab` works
- [ ] TUI exits cleanly with `q` and `Ctrl+C`
- [ ] `sudo ubuntils scan --json` outputs valid JSON that passes `python3 -m json.tool`
- [ ] On a system with a known suspicious cron entry: the entry appears as a HIGH finding
- [ ] `sudo ubuntils scan --remediate` (no `--confirm`) runs without modifying any files
- [ ] `sudo ubuntils scan --remediate --confirm` on a tmp test cron file creates a backup at `/var/backups/ubuntils/` and removes the entry

### Compatibility

- [ ] All of the above verified on Ubuntu 20.04 (or mocked Ubuntu 20.04 environment)
- [ ] All of the above verified on Ubuntu 22.04 or 24.04

### Security

- [ ] No hardcoded credentials, paths, or IP addresses in any source file
- [ ] No world-readable files created during scan or remediation
- [ ] Backup directory created with mode 0700
