# ubuntils

Forensic triage for live Ubuntu systems — automated artifact collection, persistence detection, and guided remediation in under 5 seconds.

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Tests](https://img.shields.io/badge/tests-213%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-90%25-green)
![License](https://img.shields.io/badge/license-MIT-blue)
![Arch](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-lightgrey)
![Ubuntu](https://img.shields.io/badge/ubuntu-20.04%20%7C%2022.04%20%7C%2024.04-orange)

---

## The Problem

When you suspect a Linux system is compromised, the first 30-40 minutes are usually spent running the same ten commands in sequence: check running processes, look for weird cron jobs, grep for LD_PRELOAD, scan authorized_keys for new entries, audit sudoers. Each step is manual, context-switching, and error-prone under pressure. Miss one source — say, `/etc/sudoers.d/` instead of just `/etc/sudoers`, or user crontabs in addition to `/etc/cron.d/` — and you have an incomplete picture.

Existing options don't solve this cleanly. `lynis` is a hardening auditor, not a triage tool — it reports configuration weaknesses on a clean system and generates noise on a hot one. `chkrootkit` and `rkhunter` check for known rootkit signatures but are blind to novel persistence techniques like abused systemd timers or legitimate-looking cron entries. Generic SIEM queries require log infrastructure that may not exist on the system you're looking at. And forensic suites like Volatility target memory images, not a live shell on a running host.

The gap is a tool that runs on the live system right now, covers the most common persistence vectors, correlates activity across log sources into a timeline, and tells you exactly what to look at — without requiring an external agent, a database, or an internet connection.

---

## What ubuntils does

ubuntils runs in four sequential stages:

1. **Collection** — Eight collectors gather forensic artifacts concurrently from `/proc`, cron tables, systemd units, SSH keys, sudoers files, and environment definitions. Takes roughly 2.5 seconds on a typical system.
2. **Detection** — A detection engine runs all eight rules over the collected artifacts, producing a ranked findings list in about one second.
3. **Timeline** — A timeline builder reads syslog, journald, and auditd in parallel and correlates events chronologically, adding roughly 0.3 seconds.
4. **Output** — Results appear either in an interactive four-tab TUI (default) or as structured JSON on stdout (`--json`).

No network calls are made. No data leaves the system.

---

## Installation

**From source:**

```bash
git clone https://github.com/asmitdesai/ubuntils.git
cd ubuntils
pip install -e .
```

ubuntils requires root for full artifact access. Running without root will skip `/etc/shadow`, some `/proc` entries, and protected cron files, and will log warnings for each.

---

## Quick start

**Detection only — interactive TUI:**

```bash
sudo ubuntils scan
```

**Detection with JSON output saved to file:**

```bash
sudo ubuntils scan --json > /tmp/triage-$(hostname)-$(date +%Y%m%d).json
```

**Detection with CLI remediation preview (dry run — no changes applied):**

```bash
sudo ubuntils scan --remediate
```

**Detection with CLI remediation applied:**

```bash
sudo ubuntils scan --remediate --confirm
```

**Print version:**

```bash
ubuntils version
```

---

## The TUI

Running `sudo ubuntils scan` (without `--json`) launches a full-terminal interactive TUI.

### Scan screen

While collectors run, ubuntils shows a live checklist — one row per collector. Each row updates in real time as the collector finishes:

```
Scanning system…

  ✓  Process
  ✓  Network
  ✓  Users
  ⠹  Cron
     Systemd
     SSH
     Sudoers
     Environment
```

`✓` marks success, `✗` marks failure, the spinner marks the active collector, and blank rows are pending. Once all collectors finish and detection + timeline complete, the TUI switches automatically to the results screen.

### Results screen

The results screen has four tabs navigated by number keys:

| Key | Tab | Contents |
|-----|-----|----------|
| `1` | Summary | Scan stats + top findings at a glance |
| `2` | Findings | Full findings list with inline detail and remediation |
| `3` | Timeline | Chronological correlated log events |
| `4` | Stats | Ubuntu version, architecture, duration, collector counts |

Press `q` or `Ctrl+C` to exit.

### Summary tab (key `1`)

Shows scan metadata and the top findings on a single screen:

```
Collectors:  8 run · 0 failed
Findings:    2 HIGH · 1 MEDIUM · 0 LOW
Timeline:    47 events
Duration:    2.8s

  ● HIGH  CRON_TMP_PATH           /etc/cron.d/cleanup
  ● HIGH  LD_PRELOAD_INJECT       /home/alice/.bashrc
  ○ MED   SSH_UNAUTHORIZED_KEY    /home/bob/.ssh/authorized_keys
```

On a clean system, this tab shows `System appears clean.`

### Findings tab (key `2`)

A scrollable list of all findings, sorted HIGH → MEDIUM → LOW. Selecting a finding (Enter or arrow keys) expands a detail pane at the bottom showing the full description, artifact path, raw triggering value, and remediation information.

```
HIGH  CRON_TMP_PATH           /etc/cron.d/cleanup
HIGH  LD_PRELOAD_INJECT       /home/alice/.bashrc
MED   SSH_UNAUTHORIZED_KEY    /home/bob/.ssh/authorized_keys
───────────────────────────────────────────────────────
A cron job was found referencing /tmp, /var/tmp, or /dev/shm.
These directories are world-writable and commonly used as
attacker staging grounds.

Artifact:  /etc/cron.d/cleanup
Raw:       0 * * * * root /tmp/.update
Fix:       Will remove the offending cron entry from
           /etc/cron.d/cleanup after creating a timestamped backup.

R: remediate
```

### In-TUI remediation

For findings that have automated remediation available, press `R` while the finding is selected. A confirmation modal appears:

```
┌─────────────────────────────────────────────────┐
│ Remediate CRON_TMP_PATH?                        │
│                                                 │
│ Will remove the offending cron entry from       │
│ /etc/cron.d/cleanup after creating a backup.   │
│ Backup will be created at /var/backups/ubuntils/…│
│                                                 │
│ Y: confirm    Esc: cancel                       │
└─────────────────────────────────────────────────┘
```

Press `Y` to confirm. The remediator runs in a background thread. When it completes, the finding row in the list is updated to `[fixed]` and the detail pane shows the outcome:

```
✓ Remediated
Backup:    /var/backups/ubuntils/20240115_142201/etc_cron.d_cleanup
Rollback:  cp /var/backups/ubuntils/20240115_142201/etc_cron.d_cleanup /etc/cron.d/cleanup
```

On failure, the detail pane shows the error. The backup is always created before any change is attempted.

Press `Esc` to collapse the detail pane.

### Timeline tab (key `3`)

A scrollable chronological list of correlated log events. Each row shows timestamp, source, and description. Events are pulled from syslog, journald, and auditd and deduplicated.

### Stats tab (key `4`)

A summary view of the scan: detected Ubuntu version, architecture, scan duration, collector count and failures, and finding counts per severity alongside total timeline events.

---

## What it detects

| Rule ID | Severity | Remediable | What it checks |
|---|---|---|---|
| CRON_ROOT_EXEC | HIGH | Yes | Non-root user crontabs running commands in root-owned paths or inlining sudo |
| CRON_TMP_PATH | HIGH | Yes | Any cron job referencing /tmp, /var/tmp, or /dev/shm |
| LD_PRELOAD_INJECT | HIGH | Yes | LD_PRELOAD defined in /etc/ld.so.preload or any shell init file pointing outside /lib, /usr/lib, /lib64, /usr/lib64 |
| SUSPICIOUS_SYSTEMD_TIMER | HIGH | No | Systemd timers whose service ExecStart points to a world-writable directory or a path not owned by root |
| SSH_UNAUTHORIZED_KEY | MEDIUM | Yes | authorized_keys files modified within the last 7 days |
| SUDOERS_NOPASSWD | MEDIUM | Yes | NOPASSWD sudoers grants for users with UID ≥ 1000 and a login shell |
| PROCESS_MASQUERADE | MEDIUM | No | Processes whose name matches a known system binary but whose executable path is outside /usr/bin, /usr/sbin, /bin, /sbin |
| SHELL_RC_MODIFICATION | LOW | No | Shell init files (bashrc, profile, zshrc, etc.) modified within the last 48 hours for any user with a login shell |

### Why each rule exists

**CRON_ROOT_EXEC** — User crontabs run as the crontab owner. An entry invoking sudo or a root-owned interpreter means the user has arranged for code to run with root privileges on a schedule, without needing persistent sudo access. This survives password changes.

*Example finding:*
```
[HIGH] CRON_ROOT_EXEC
Title:         User crontab executing with sudo
Artifact:      /var/spool/cron/crontabs/alice
Raw value:     */5 * * * * sudo /usr/bin/python3 /tmp/beacon.py
Remediation:   available
```

**CRON_TMP_PATH** — World-writable directories like /tmp and /dev/shm are standard attacker staging grounds. A cron job pointing there means a payload can be swapped out between invocations without touching any persistent path.

*Example finding:*
```
[HIGH] CRON_TMP_PATH
Title:         Cron job references writable temp directory
Artifact:      /etc/cron.d/cleanup
Raw value:     0 * * * * root /tmp/.update
Remediation:   available
```

**LD_PRELOAD_INJECT** — LD_PRELOAD causes the dynamic linker to load a specified shared library before all others, allowing arbitrary function interception in any dynamically linked binary. A value pointing outside standard library paths is a near-certain userspace rootkit indicator.

*Example finding:*
```
[HIGH] LD_PRELOAD_INJECT
Title:         LD_PRELOAD set to non-standard library path
Artifact:      /home/alice/.bashrc
Raw value:     export LD_PRELOAD=/tmp/.libssl.so
Remediation:   available
```

**SUSPICIOUS_SYSTEMD_TIMER** — Systemd timers are more persistent and less visible than cron jobs to most responders. A timer whose service unit executes from a temp directory or a user-owned path is a sign of attacker-created persistence. Flag-only — systemd unit removal requires human judgment.

*Example finding:*
```
[HIGH] SUSPICIOUS_SYSTEMD_TIMER
Title:         Systemd timer ExecStart points to suspicious path
Artifact:      /etc/systemd/system/update-check.timer
Raw value:     ExecStart=/tmp/.sys/update
Remediation:   not available
```

**SSH_UNAUTHORIZED_KEY** — A newly added SSH key grants persistent remote access independent of passwords. The 7-day window catches recent additions while avoiding noise from initial provisioning on older systems. Note: the rule uses file mtime, which reflects the last write to the authorized_keys file, not the insertion timestamp of each individual key.

*Example finding:*
```
[MEDIUM] SSH_UNAUTHORIZED_KEY
Title:         SSH authorized key added in last 7 days
Artifact:      /home/bob/.ssh/authorized_keys
Raw value:     ssh-rsa AAAAB3NzaC1... attacker@evil
Remediation:   available
```

**SUDOERS_NOPASSWD** — Password-free sudo for a human user account (UID ≥ 1000 with a login shell) is a privilege escalation vector that survives the removal of other persistence mechanisms. Legitimate NOPASSWD grants are almost always for service accounts with no login shell.

*Example finding:*
```
[MEDIUM] SUDOERS_NOPASSWD
Title:         NOPASSWD sudo grant for regular user
Artifact:      /etc/sudoers.d/alice
Raw value:     alice ALL=(ALL) NOPASSWD: ALL
Remediation:   available
```

**PROCESS_MASQUERADE** — Naming a malicious binary after a known system process (sshd, python3, bash) is a basic technique to avoid detection in `ps` output. This rule cross-references the process name from `/proc/<pid>/status` against the resolved exe path from `/proc/<pid>/exe`. Flag-only — killing a process requires human judgment.

*Example finding:*
```
[MEDIUM] PROCESS_MASQUERADE
Title:         Process masquerading as system binary
Artifact:      /proc/1337/exe
Raw value:     name=sshd, exe=/tmp/.sshd
Remediation:   not available
```

**SHELL_RC_MODIFICATION** — Shell init files are a reliable persistence vector because they execute on every user login. This rule surfaces recent modifications for human review. Flag-only — shell RC content requires reading before acting on it.

*Example finding:*
```
[LOW] SHELL_RC_MODIFICATION
Title:         Shell init file recently modified
Artifact:      /root/.bashrc
Raw value:     mtime=2024-01-15 14:22:01 (6 hours ago)
Remediation:   not available
```

---

## JSON output

`--json` writes a single JSON object to stdout. Nothing else is printed.

```json
{
  "scan_metadata": {
    "ubuntu_version": "Ubuntu 22.04.3 LTS",
    "architecture": "x86_64",
    "duration_s": 2.84,
    "collector_failures": 0
  },
  "artifact_counts": {
    "ProcessCollector": 142,
    "NetworkCollector": 23,
    "UserCollector": 4,
    "CronCollector": 7,
    "SystemdCollector": 12,
    "SSHCollector": 3,
    "SudoersCollector": 5,
    "EnvironmentCollector": 18
  },
  "findings": [
    {
      "rule_id": "CRON_TMP_PATH",
      "severity": "HIGH",
      "title": "Cron job references writable temp directory",
      "description": "A cron job was found referencing /tmp, /var/tmp, or /dev/shm. These directories are world-writable and commonly used as attacker staging grounds.",
      "artifact_path": "/etc/cron.d/cleanup",
      "raw_value": "0 * * * * root /tmp/.update",
      "remediation_available": true,
      "remediation_description": "Will remove the offending cron entry from /etc/cron.d/cleanup after creating a timestamped backup."
    }
  ],
  "timeline": [
    {
      "timestamp": "2024-01-15T08:22:01+00:00",
      "source": "syslog",
      "description": "sshd: Accepted publickey for alice from 10.0.0.42 port 52341"
    }
  ]
}
```

`remediation_results` appears as an additional top-level key only when `--remediate` is passed.

---

## Remediation

Five of the eight detection rules have automated remediation: `CRON_ROOT_EXEC`, `CRON_TMP_PATH`, `LD_PRELOAD_INJECT`, `SSH_UNAUTHORIZED_KEY`, and `SUDOERS_NOPASSWD`. The remaining three (`SUSPICIOUS_SYSTEMD_TIMER`, `PROCESS_MASQUERADE`, and `SHELL_RC_MODIFICATION`) are flag-only and will never be auto-remediated.

### In the TUI

Select any finding with a remediation in the Findings tab, then press `R`. A confirmation modal previews the planned action. Press `Y` to apply it — the remediator runs in a background thread so the TUI stays responsive. The finding row updates to `[fixed]` when done, with the backup path and exact rollback command shown inline.

### From the CLI

`--remediate` without `--confirm` is a safe dry run: backups are created and validation runs, but no changes are applied. Pass both flags to actually make changes. The pipeline runs before the TUI launches in this mode.

```bash
sudo ubuntils scan --remediate          # dry run
sudo ubuntils scan --remediate --confirm # apply changes, then open TUI
```

### Safeguards

Every remediation follows the same pattern regardless of how it is triggered:

1. Detect if the artifact path is a symlink — refuse if so (prevents root writing through attacker-controlled symlinks)
2. Create a timestamped backup at `/var/backups/ubuntils/YYYYMMDD_HHMMSS/` with mode `0700`
3. Validate current state (sudoers: `visudo -cf`)
4. Apply the minimum possible change — cron entries removed line by line, LD_PRELOAD lines commented out rather than deleted, sudoers entries validated with `visudo -cf` before and after
5. Verify the result

If any step fails, remediation stops immediately, the system is left unchanged, and the full error is reported with the backup path and rollback command. The sudoers remediator refuses to proceed if removing the entry would leave the system with no sudo rules.

---

## Collectors

| Collector | Artifacts gathered |
|---|---|
| ProcessCollector | Running processes from `/proc` and `ps` output |
| NetworkCollector | Open connections and listeners from `ss`/`netstat` |
| UserCollector | `/etc/passwd`, `/etc/shadow`, `/etc/group` |
| CronCollector | `/etc/cron*` directories and `/var/spool/cron/crontabs/*` |
| SystemdCollector | `systemctl list-timers` and `list-units` output |
| SSHCollector | `~/.ssh/authorized_keys` for all users |
| SudoersCollector | `/etc/sudoers` and all files under `/etc/sudoers.d/` |
| EnvironmentCollector | `/etc/environment`, `/etc/profile.d/*`, user shell init files |

---

## Compatibility

| | Supported |
|---|---|
| **Ubuntu** | 20.04, 22.04, 24.04 |
| **Architecture** | amd64, arm64 |
| **Python** | 3.9+ |
| **Privileges** | Root required for full artifact access |

Running without root produces a partial scan with warnings. Critical paths like `/etc/shadow`, protected crontab directories, and some `/proc` entries will be skipped.

---

## Roadmap

**v1.0.0**
- [x] All 8 collectors
- [x] All 8 detection rules
- [x] Timeline builder (syslog, journald, auditd)
- [x] Live scan progress screen with per-collector ✓/✗
- [x] Interactive four-tab TUI (Summary / Findings / Timeline / Stats)
- [x] In-TUI remediation with confirmation modal and background worker
- [x] JSON output mode
- [x] CLI remediation for 5 rules with backup, rollback, and symlink guard
- [x] Ubuntu 20.04/22.04/24.04 support
- [x] 213 tests at 90% coverage

**v1.5.0**
- VirusTotal hash lookups for suspicious process executables
- MISP IOC export from findings
- Custom detection rules via YAML
- False positive whitelisting by path or user

**v2.0.0**
- Web dashboard for multi-host triage
- Wazuh integration for alert forwarding
- macOS support

---

## Contributing

The most useful contributions right now are new detection rules (added as standalone functions in `detectors/rules.py` with a matching test), additional collectors for artifact types not yet covered, remediation modules for `SUSPICIOUS_SYSTEMD_TIMER` and `SHELL_RC_MODIFICATION` (both currently flag-only by design, but safe auto-remediation paths may exist), test cases for edge cases on specific Ubuntu configurations, and documentation improvements.

Open an issue before starting a large contribution to avoid duplicate work.

---

## License

MIT

---

## Author

Built by Asmit — BTech Computer Science, PES University, Bengaluru. The tool came out of frustration with how long manual Ubuntu triage takes compared to what a well-scoped script can automate.
