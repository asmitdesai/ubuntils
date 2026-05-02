# ubuntils v1.0.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-quality Ubuntu incident response forensics tool with 4 collectors, 8 detection rules, safety-first remediation, and comprehensive testing.

**Architecture:** Collectors-first approach. Phase 1: collectors + tests. Phase 2: detection rules. Phase 3: remediation. Phase 4: formatters/timeline. Phase 5: CLI integration and full integration tests.

**Tech Stack:** Python 3.9+, Click, pytest, loguru, tabulate, pyyaml, python-dateutil

---

## Phase 1: Project Setup (Week 1)

### Task 1: Initialize project structure

- [ ] Create `setup.py` with package metadata and dependencies
- [ ] Create `requirements.txt` with all dependencies
- [ ] Create `ubuntils/__init__.py` with version info
- [ ] Create `tests/__init__.py` (empty)
- [ ] Create `tests/conftest.py` with pytest fixtures
- [ ] Run `pip install -e .` to install in editable mode
- [ ] Verify `ubuntils --version` works
- [ ] Commit: "chore: initialize project structure"

### Task 2: Create base classes and utilities

- [ ] Create `ubuntils/collectors/base.py` — BaseCollector abstract class
- [ ] Create `ubuntils/detectors/finding.py` — Finding dataclass with Severity enum
- [ ] Create `ubuntils/remediators/base.py` — BaseRemediator abstract class and RemediationResult
- [ ] Create `ubuntils/utils/shell.py` — safe subprocess wrappers (run_command, run_command_quiet)
- [ ] Create `ubuntils/utils/logging.py` — loguru setup with get_logger()
- [ ] Create `ubuntils/utils/validators.py` — is_valid_cron_schedule, is_suspicious_path, is_standard_lib_path
- [ ] Create `ubuntils/collectors/__init__.py` with exports
- [ ] Create `ubuntils/detectors/__init__.py` with exports
- [ ] Create `ubuntils/remediators/__init__.py` with exports
- [ ] Create `ubuntils/formatters/__init__.py` (empty)
- [ ] Create `ubuntils/utils/__init__.py` with exports
- [ ] Write unit tests in `tests/test_base_classes.py` for all base classes
- [ ] Run pytest and verify all tests pass
- [ ] Commit: "feat: add base classes and utilities"

---

## Phase 2: Collectors Implementation (Weeks 1-3)

### Task 3: ProcessCollector

- [ ] Create `ubuntils/collectors/processes.py`
  - Implement ProcessCollector class with collect() method
  - _collect_processes() — parse `ps aux`
  - _collect_network_connections() — parse `lsof -i`
  - _collect_listening_ports() — parse `netstat -tlpn`
  - Return dict with "processes", "network_connections", "listening_ports"
- [ ] Write unit tests in `tests/test_collectors.py`
  - Test initialization
  - Test collect() returns correct structure
  - Test parsing with mock subprocess output
- [ ] Run tests, verify they pass
- [ ] Commit: "feat: implement ProcessCollector"

### Task 4: LogCollector

- [ ] Create `ubuntils/collectors/logs.py`
  - Implement LogCollector class
  - _collect_auth_log() — parse /var/log/auth.log
  - _collect_syslog() — parse /var/log/syslog
  - _collect_journalctl() — run journalctl for last 48 hours
  - _collect_audit_log() — parse /var/log/audit/audit.log
  - Parse functions: _parse_syslog_line(), _parse_journal_line(), _parse_audit_line()
  - All timestamps in UTC ISO 8601 format
  - Gracefully handle missing files and permission errors
  - Return sorted list of log_events
- [ ] Write unit tests in `tests/test_collectors.py`
- [ ] Run tests, verify they pass
- [ ] Commit: "feat: implement LogCollector"

### Task 5: FilesystemCollector

- [ ] Create `ubuntils/collectors/filesystem.py`
  - Implement FilesystemCollector class
  - _collect_cron_jobs() — system cron files + user crontabs via `crontab -u`
  - _collect_sudoers() — /etc/sudoers and /etc/sudoers.d/*
  - _collect_ssh_keys() — authorized_keys for all users
  - _collect_shell_inits() — .bashrc, .zshrc, .bash_profile, .profile for all users
  - _collect_ld_preload() — /etc/ld.so.preload and LD_PRELOAD env vars in shell inits
  - Gracefully handle permission errors
- [ ] Write unit tests in `tests/test_collectors.py`
- [ ] Run tests, verify they pass
- [ ] Commit: "feat: implement FilesystemCollector"

### Task 6: UserCollector

- [ ] Create `ubuntils/collectors/users.py`
  - Implement UserCollector class
  - _collect_users() — read pwd module, return list of users with UID, GID, home, shell
  - _collect_groups() — read grp module, return list of groups with members
  - _collect_login_events() — call _collect_last(), _collect_lastlog(), _collect_who()
  - Parse output from `last`, `lastlog`, `who` commands
- [ ] Write unit tests in `tests/test_collectors.py`
- [ ] Run tests, verify they pass
- [ ] Commit: "feat: implement UserCollector"

### Task 7: Parallel collector orchestrator

- [ ] Create `ubuntils/core.py` — CollectorOrchestrator class
  - __init__(): instantiate all 4 collectors
  - run_collectors() — run all collectors in parallel via ThreadPoolExecutor, return combined artifacts dict
  - Measure and log collection time
- [ ] Write unit tests in `tests/test_collectors.py`
- [ ] Run full pytest suite, verify all collector tests pass
- [ ] Commit: "feat: implement parallel collector orchestrator"

---

## Phase 3: Detection Rules (Weeks 4-6)

### Task 8: Create detection rule framework

- [ ] Create `ubuntils/detectors/persistence.py`
  - Implement PersistenceDetector class with detect(artifacts) method
  - Generate unique Finding IDs (FINDING_001, FINDING_002, etc.)
  - Implement stub methods for all 8 rules, each returning list of Finding objects
  - Rules: cron_root_execution, cron_tmp_paths, ld_preload_injection, sudoers_nopasswd, shell_hijacking, ssh_key_injection, nonstandard_systemd, system_file_mods
- [ ] Write comprehensive unit tests in `tests/test_detectors.py`
  - For each rule: test known-bad inputs (should generate findings) and known-good inputs (should not)
  - Test edge cases (empty artifacts, malformed data)
- [ ] Run tests (they will fail until rules are implemented), commit framework
- [ ] Commit: "feat: add detection rule framework and stubs"

### Task 9-16: Implement each of 8 detection rules

For each rule task:
- [ ] Implement the rule logic in persistence.py
  - Rule 1: Cron Root Execution (HIGH, auto-fix available)
  - Rule 2: Cron /tmp Paths (HIGH, auto-fix available)
  - Rule 3: LD_PRELOAD Injection (HIGH, auto-fix available)
  - Rule 4: Sudoers NOPASSWD (MEDIUM, auto-fix available)
  - Rule 5: Shell Init Hijacking (MEDIUM, auto-fix available)
  - Rule 6: SSH Key Injection (HIGH, auto-fix available)
  - Rule 7: Non-Standard Systemd Services (MEDIUM, no auto-fix)
  - Rule 8: System File Modification Timestamps (MEDIUM, no auto-fix)
- [ ] Run tests for that rule, verify they pass
- [ ] Commit: "feat: implement [rule name] detection rule"

Run full detector test suite after each rule:
```bash
pytest tests/test_detectors.py -v
```

---

## Phase 4: Remediation System (Weeks 7-8)

### Task 17: BackupManager

- [ ] Create `ubuntils/remediators/backup_manager.py`
  - Implement BackupManager class
  - create_backup(file_path, backup_dir) — copy file to backup_dir with original name
  - Verify backup created successfully
  - Return backup path
- [ ] Write unit tests in `tests/test_remediators.py`
- [ ] Commit: "feat: implement BackupManager"

### Task 18: RollbackManager

- [ ] Create `ubuntils/remediators/rollback_manager.py`
  - Implement RollbackManager class
  - restore_from_backup(backup_dir) — restore all files in backup_dir to original locations
  - Validate each file restored
  - Log all restorations
- [ ] Write unit tests in `tests/test_remediators.py`
- [ ] Commit: "feat: implement RollbackManager"

### Task 19-24: Implement remediation modules for each auto-fixable rule

For each remediation task:
- [ ] Create `ubuntils/remediators/[rule]_remediation.py`
  - Implement remediation for: cron, sudoers, ssh, ld_preload, shell
  - Each module: can_remediate(finding), remediate(finding, dry_run)
  - Create backup before modifying
  - Validate changes (e.g., visudo -cf for sudoers)
  - Never remove all sudo access
  - Return RemediationResult with status (SUCCESS/FAILED/SKIPPED)
- [ ] Write unit tests in `tests/test_remediators.py` (mock file operations)
- [ ] Commit: "feat: implement [rule] remediation module"

---

## Phase 5: Output Formatters & Timeline (Weeks 9-10)

### Task 25: Human formatter

- [ ] Create `ubuntils/formatters/human.py`
  - Implement HumanFormatter class
  - format(findings, artifacts, timeline, metadata) — return formatted report string
  - Sections: header, execution summary, findings (grouped by severity), timeline, statistics, next steps
  - Use tabulate for clean formatting
- [ ] Write unit tests in `tests/test_formatters.py`
- [ ] Commit: "feat: implement human-readable formatter"

### Task 26: JSON formatter

- [ ] Create `ubuntils/formatters/json_formatter.py`
  - Implement JSONFormatter class
  - format(findings, artifacts, timeline, metadata) — return JSON string
  - Structure: metadata, summary, findings[], timeline[], artifacts{}, remediation_results{}
- [ ] Write unit tests in `tests/test_formatters.py`
- [ ] Commit: "feat: implement JSON formatter"

### Task 27: Timeline builder

- [ ] Create `ubuntils/timeline.py`
  - Implement TimelineBuilder class
  - build(log_events, findings) — correlate events by timestamp, user, process, file
  - Return list of timeline entries with 48-hour lookback
  - Sort chronologically
- [ ] Write unit tests in `tests/test_formatters.py`
- [ ] Commit: "feat: implement timeline builder"

---

## Phase 6: CLI & Integration (Weeks 11-12)

### Task 28: CLI entry point

- [ ] Create `ubuntils/cli.py`
  - Implement Click CLI with two commands: scan and rollback
  - scan command:
    - --output (human|json|/path/file) — output format
    - --remediate — enable remediation
    - --dry-run — preview remediation without applying
    - --confirm — apply remediation with backups
    - -v / --verbose — debug logging
  - rollback command:
    - Takes backup directory path
    - Restores system to pre-remediation state
  - Main orchestration: collectors → detectors → formatters → output
- [ ] Write unit tests in `tests/test_cli.py`
- [ ] Run `ubuntils scan --help` and verify output
- [ ] Commit: "feat: implement CLI with scan and rollback commands"

### Task 29: Integration tests

- [ ] Create `tests/test_integration.py`
  - Plant test artifacts in temporary directories (not live system)
  - Run full scan pipeline
  - Verify findings detected correctly
  - Mock remediation operations (verify logic, not actual system changes)
  - Test rollback with mocked filesystem
  - Test both output formats (human and JSON)
- [ ] Run full test suite with coverage
- [ ] Verify 80%+ coverage: `pytest --cov=ubuntils tests/`
- [ ] Commit: "test: add integration tests with 80%+ coverage"

### Task 30: GitHub Actions CI setup

- [ ] Create `.github/workflows/tests.yml`
  - Matrix: Ubuntu 20.04, 22.04, 24.04 on AMD64
  - Install dependencies
  - Run pytest with coverage
  - Report coverage
- [ ] Push to GitHub and verify CI passes
- [ ] Commit: "ci: add GitHub Actions workflow"

### Task 31: Documentation polish

- [ ] Update README.md with installation and usage (if needed)
- [ ] Add docstrings to all public classes and methods
- [ ] Update CLAUDE.md with final architecture notes
- [ ] Verify all comments are necessary and clear
- [ ] Commit: "docs: finalize documentation and docstrings"

### Task 32: Final verification and release

- [ ] Local test on ARM64 Ubuntu (20.04, 22.04, 24.04)
- [ ] Verify GitHub Actions CI passes
- [ ] Run full test suite one final time
- [ ] Verify no false positives in detection rules
- [ ] Tag release: `git tag v1.0.0`
- [ ] Commit: "release: ubuntils v1.0.0"

---

## Success Criteria

- [x] All 4 collectors implemented and tested
- [x] All 8 detection rules implemented and tested
- [x] Remediation system with backups and rollback working
- [x] Both output formatters (human and JSON) working
- [x] Timeline correlator working
- [x] 80%+ test coverage
- [x] GitHub Actions CI passing on AMD64
- [x] No known false positives
- [x] Full documentation complete

---

**Plan complete and ready for execution.**

Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration with checkpoints

**2. Inline Execution** — Execute tasks in this session using superpowers:executing-plans, batch execution with progress tracking

**Which approach would you prefer?**
