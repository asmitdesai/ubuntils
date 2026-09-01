# ubuntils

Forensic triage for live Ubuntu systems — automated artifact collection, persistence detection, and guided remediation in under 5 seconds.

[![CI](https://github.com/asmitdesai/ubuntils/actions/workflows/ci.yml/badge.svg)](https://github.com/asmitdesai/ubuntils/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Tests](https://img.shields.io/badge/tests-357%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-93%25-green)
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
2. **Detection** — A detection engine runs all ten built-in rules — plus any custom rules loaded with `--rules` — over the collected artifacts, producing a ranked findings list in about one second.
3. **Timeline** — A timeline builder reads syslog, journald, and auditd in parallel and correlates events chronologically, adding roughly 0.3 seconds. Each finding is then auto-correlated against the timeline, so it carries the nearby events that relate to it.
4. **Output** — Results appear either in an interactive four-tab TUI (default) or as structured JSON on stdout (`--json`).

No network calls are made. No data leaves the system. This holds for every feature, including custom rules and correlation — all of it runs against locally collected artifacts.

`ubuntils scan` is unchanged by everything below — it is still 100% live, single-host, and every existing flag works identically. Two additional commands, `collect` and `analyze`, split the same detection/timeline pipeline into an offline-friendly acquire-then-analyze workflow for cases where you can't (or don't want to) run detection directly on the host under investigation — see [Offline analysis: collect and analyze](#offline-analysis-collect-and-analyze) below, including its detection-coverage caveats.

---

## Installation

**Ubuntu 22.04+ and any system with PEP 668 (recommended):**

Ubuntu 22.04+ blocks system-wide `pip install`. Use `pipx` — it handles the environment transparently so you never think about it:

```bash
sudo apt install pipx -y
cd ubuntils
pipx install -e .
ubuntils scan
```

**Older systems / manual install:**

```bash
git clone https://github.com/asmitdesai/ubuntils.git
cd ubuntils
pip install -r requirements.txt -e .
ubuntils scan
```

ubuntils requires root for full artifact access. If you run `ubuntils scan` as a non-root user it will automatically re-invoke itself with `sudo`, preserving your PATH so the correct Python environment is used. Running without root will skip `/etc/shadow`, some `/proc` entries, and protected cron files, and will log warnings for each.

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

**Collect a tamper-evident bundle for later or offline analysis:**

```bash
sudo ubuntils collect --output /path/to/bundle.tar.gz
```

**Analyze a previously collected bundle (no root required):**

```bash
ubuntils analyze /path/to/bundle.tar.gz --json
```

**Analyze a mounted forensic image or extracted filesystem tree instead of a bundle:**

```bash
ubuntils analyze --root /mnt/forensic-image --json
```

See [Offline analysis: collect and analyze](#offline-analysis-collect-and-analyze) for the bundle format and — importantly — what offline analysis cannot detect compared to a live `scan`.

---

## Flags and configuration

```
ubuntils scan [OPTIONS]
  --json              Output JSON to stdout instead of launching the TUI
  --output FILE       Write the JSON report to FILE (implies --json)
  --remediate         Run the remediation engine after detection
  --confirm           Required with --remediate to actually apply changes (else dry-run)
  --config FILE       YAML allowlist of findings to suppress (see below)
  --baseline FILE     YAML baseline of environment-specific known-good fingerprints to suppress (see below)
  --since TIME        Limit the timeline to events since TIME (e.g. '24h', '7d', '2026-05-20')
  --rules FILE        YAML file of custom detection rules to add (see below)
  --verbose           Verbose structlog output

ubuntils collect [OPTIONS]
  --output FILE       Bundle path to write (default ./ubuntils-bundle-<timestamp>.tar.gz)
  --verbose           Verbose structlog output

ubuntils analyze (BUNDLE | --root PATH) [OPTIONS]
  --root PATH         Analyze a mounted image / artifact tree instead of a bundle
  --json              Output JSON instead of launching the TUI
  --output FILE       Write the JSON report to FILE (implies --json)
  --config FILE       YAML allowlist of findings to suppress (same format as scan)
  --baseline FILE     YAML baseline of environment-specific known-good fingerprints to suppress (same format as scan)
  --rules FILE        YAML file of custom detection rules to add (same format as scan)
  --since TIME        Limit the timeline to events since TIME (e.g. '24h', '7d', '2026-05-20')
  --verbose           Verbose structlog output

ubuntils version
  Print version string and exit
```

### False-positive allowlisting (`--config`)

A freshly provisioned or CI-managed host generates expected noise — deploy keys, provisioning crontabs, baked-in shell init. Instead of teaching responders to mentally filter it, suppress it explicitly with a YAML allowlist:

```yaml
# allowlist.yaml
allowlist:
  rules:
    - SHELL_RC_MODIFICATION          # suppress this rule entirely
  paths:
    - /home/ci/.ssh/authorized_keys  # suppress any finding on this exact path
```

```bash
sudo ubuntils scan --json --config allowlist.yaml
```

Suppression is always explicit — by rule id and/or exact artifact path. There is no blanket "ignore everything" switch. A sample lives at [`examples/allowlist.yaml`](examples/allowlist.yaml).

### Known-good baselining (`--baseline`)

`--config` suppresses a rule or path *everywhere, for anyone running ubuntils against this codebase*. `--baseline` is narrower and environment-specific: it says "in *this* environment, this exact artifact — this SSH key, this RC file — is known good," without muting the rule or path for every other host you scan with the same tool. Kept as a separate file from `--config` for the same reason `--rules` is separate: suppression and rule-wide allowlisting are different concerns that shouldn't live in one file.

```yaml
# baseline.yaml
baseline:
  - rule_id: SSH_UNAUTHORIZED_KEY
    fingerprint: ci@ci-runner          # substring match against the finding's raw_value
  - rule_id: SHELL_RC_MODIFICATION
    fingerprint: /home/deploy/.bashrc  # exact match against the finding's artifact_path
```

```bash
sudo ubuntils scan --json --baseline baseline.yaml
```

A baseline entry matches by `rule_id` plus a `fingerprint` tested as a substring of the finding's `raw_value` or an exact match against its `artifact_path`. A match drops the finding from the report entirely — suppression is never silent, though: the number of findings a baseline removed is always visible in `scan_metadata.suppressed_by_baseline`. Allowlist (`--config`) suppression still applies on top of baseline suppression. Works identically on `scan` and `analyze`. A sample lives at [`examples/baseline.yaml`](examples/baseline.yaml).

### Custom detection rules (`--rules`)

`--config` *suppresses* findings; `--rules` *adds* them. They are deliberately separate files because they are opposite concerns.

A rules file is pattern-match only — no expressions, no conditionals, and no code execution, so loading one can never run attacker-supplied logic. Each rule names an artifact `source`, a `match` mode, and a `pattern`:

```yaml
# custom_rules.yaml
rules:
  - id: CUSTOM_KNOWN_MINER
    severity: HIGH                     # HIGH | MEDIUM | LOW
    title: Known cryptominer in process cmdline
    description: A running process command line matches a known miner.
    source: process                    # cron | environment | ssh | process | network
    match: substring                   # regex | substring | glob
    pattern: xmrig
```

```bash
sudo ubuntils scan --json --rules custom_rules.yaml
```

| `source` | Matched against |
|---|---|
| `cron` | The cron command (path: the crontab file) |
| `environment` | The raw environment/shell-init line (path: the defining file) |
| `ssh` | Key type, key data, and comment (path: the `authorized_keys` file) |
| `process` | The process cmdline (path: the exe path) |
| `network` | The connection description (path: `remote_addr:remote_port`) |

`regex` and `substring` match the text column; `glob` matches the path column — so a `network` glob such as `203.0.113.*:*` targets the remote endpoint. Custom-rule findings are flag-only (never auto-remediated) and are still subject to `--config` suppression. A sample lives at [`examples/custom_rules.yaml`](examples/custom_rules.yaml).

### Report integrity

Every `--json` report ends with a `report_sha256` field — a SHA-256 over the canonical report content. This makes a collected triage artifact tamper-evident and lets you reference a specific scan by digest in a case file. The report also records `tool_version`, `hostname`, and a UTC `generated_at` timestamp under `scan_metadata`. For `scan` and `analyze --root`, `hostname`/`ubuntu_version` describe the machine `ubuntils` is running on. For `analyze BUNDLE`, they instead come from the bundle's own manifest — the host that was *collected*, not the host running `analyze` — along with `collection_run_id` and the collection's `collected_at_utc_start`/`collected_at_utc_end`, so the report's chain-of-custody record follows the evidence rather than the analyst's workstation.

---

## Offline analysis: collect and analyze

`ubuntils scan` runs collection, detection, and timeline together against the live host. `collect` and `analyze` split that pipeline in two: `collect` acquires a tamper-evident bundle from a host (no detection runs), and `analyze` runs the same detection/timeline pipeline used by `scan` against a bundle, or against a mounted image via `--root`, without requiring root and without touching the original host again. This is for cases where you want to acquire artifacts once and analyze them later, elsewhere, or repeatedly — or where you're triaging a disk image rather than a running system.

### `ubuntils collect`

```bash
sudo ubuntils collect --output /path/to/bundle.tar.gz
```

Requires root, like `scan`. Reads a fixed list of files (`/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/sudoers`, `/etc/ld.so.preload`, `/etc/environment`, `/etc/crontab`, `/etc/profile`, `/var/log/syslog`, `/var/log/messages`, `/var/log/audit/audit.log`) and runs a fixed list of commands (`ss -tunap`, `netstat -tunap`, `systemctl list-timers` in both JSON and text form, and `journalctl -o json` for the last 7 days), hashes each captured item, and writes everything plus a `manifest.json` into a `.tar.gz` bundle. The captured log files and journalctl output are what let `analyze BUNDLE` build a real timeline offline. If `--output` is omitted, the bundle is written to `./ubuntils-bundle-<UTC timestamp>.tar.gz` in the current directory.

### `ubuntils analyze`

```bash
ubuntils analyze BUNDLE.tar.gz [--json] [--output FILE] [--config FILE] [--baseline FILE] [--rules FILE] [--since TIME]
ubuntils analyze --root /mnt/forensic-image [--json] [--output FILE] [--config FILE] [--baseline FILE] [--rules FILE] [--since TIME]
```

Takes either a bundle path as a positional argument or `--root PATH` pointing at a mounted image / extracted filesystem tree — not both. Runs the identical detection engine, custom rules, allowlist, and baseline logic used by `scan`. Does not require root.

Coverage differs between the two offline modes, because a bundle carries *replayed* captured state from `collect` time while `--root` only has whatever is sitting on the mounted filesystem:

- **`analyze BUNDLE`** replays the real `ss`/`systemctl list-timers`/`journalctl` command output captured at `collect` time, so `NetworkCollector` and `SystemdCollector` produce genuine findings from that snapshot — they are not skipped. The timeline is built from the syslog/messages/audit.log/journalctl the bundle captured, so it is fully populated and findings get real `related_events` correlation.
- **`analyze --root PATH`** points at a dead, mounted image with no live process or kernel state to query, so command execution is disabled entirely: `NetworkCollector` and `SystemdCollector` are skipped, recorded in `scan_metadata.command_collectors_skipped`. The timeline is still built, but from the static log files present on the image (`/var/log/syslog`, `/var/log/messages`, `/var/log/audit/audit.log`) — journald replay isn't available here since there's no live `journalctl` to query a dead image.

See [Offline analysis: collect and analyze](#offline-analysis-collect-and-analyze) for the full list of offline detection-coverage gaps.

### Bundle format

A bundle is a gzipped tarball with everything under a `bundle/` prefix:

```
bundle/
├── manifest.json
├── files/
│   ├── etc/passwd
│   ├── etc/shadow
│   ├── var/log/syslog
│   └── ...            # every captured file, path-flattened under files/
└── commands/
    ├── ss.txt
    ├── netstat.txt
    ├── systemctl_list_timers_json.txt
    ├── systemctl_list_timers_text.txt
    └── journalctl.txt
```

`manifest.json` schema:

| Field | Type | Description |
|---|---|---|
| `run_id` | string | UUID generated fresh for each `collect` run |
| `host_id` | string | Reserved for future multi-host correlation; currently empty |
| `hostname` | string | `socket.gethostname()` at collection time |
| `ubuntu_version` | string | Detected Ubuntu release string |
| `collected_at_utc_start` / `collected_at_utc_end` | string (ISO 8601) | Wall-clock bounds of the collection run |
| `tool_version` | string | ubuntils version that produced the bundle |
| `files[]` | array | One entry per captured file: `source_path`, `bundle_path`, `sha256`, `size`, `mtime`, `ctime` (a file absent/unreadable on the source host is recorded with `sha256: ""`, `size: -1` rather than aborting the collection) |
| `commands[]` | array | One entry per captured command: `name`, `argv`, `bundle_path`, `sha256`, `exit_code` |
| `bundle_sha256` | string | SHA-256 over the rest of the manifest (everything above, canonically serialized) — the tamper-evidence anchor for the whole bundle |

### Bundle integrity in JSON output

`analyze`'s `scan_metadata.bundle_integrity` reports one of three values:

- `"live"` — `scan` and `analyze --root` report this; there is no bundle to verify.
- `"ok"` — `analyze BUNDLE` verified `bundle_sha256` against the manifest and every captured file's SHA-256 against its bundle content; nothing has been altered since `collect` wrote it.
- `"mismatch"` — the manifest digest or a file's content hash didn't match. Treat findings from a `"mismatch"` bundle with suspicion — something in the bundle was modified, truncated, or corrupted after collection, and any detection results derived from it should not be trusted as chain-of-custody-clean.

### ⚠️ Offline analysis has real detection gaps — read this before relying on it

**A bundle- or `--root`-sourced `analyze` run does not have detection parity with a live `scan`.** These are not edge cases; they are structural limitations of static, offline acquisition, and they will silently produce fewer (or zero) findings for the affected rules rather than an error — the tool cannot tell the difference between "found nothing" and "couldn't look." (The timeline itself is *not* one of these gaps any more: `analyze BUNDLE` replays the captured syslog/messages/audit.log/journalctl from `collect` time, and `analyze --root` reads the static log files present on the mounted image, so both produce a real timeline and real `related_events` correlation — see [`ubuntils analyze`](#ubuntils-analyze) above.)

- **`PROCESS_MASQUERADE` and `PROCESS_SUSPICIOUS_CONNECTION` will always report zero findings in offline mode.** Both rules key off a process's `exe` field, which is populated by reading the live `/proc/<pid>/exe` symlink target on the running host. A bundle has no live `/proc` to read, and `--root` points at a mounted filesystem tree with no `/proc` either — there is currently no mechanism to capture or reconstruct a resolved exe-symlink target offline, so `exe` is always empty and both rules never fire, regardless of what's actually on the host.
- **Process enumeration doesn't happen at all offline.** `collect` has no per-PID capture step (`/proc/*/status`, `/proc/*/cmdline`), so no processes exist in a bundle to analyze in the first place — this is the same root cause as the point above, from the acquisition side.
- **`CRON_TMP_PATH`, `SUDOERS_NOPASSWD`, and `SSH_UNAUTHORIZED_KEY` are limited or absent from bundle-sourced analysis.** `collect`'s file list is static and cannot glob-expand `/etc/cron.d/*`, `/etc/sudoers.d/*`, `/etc/profile.d/*`, or per-user `~/.ssh/authorized_keys` — only `/etc/crontab`, `/etc/sudoers`, and `/etc/environment`/`/etc/profile` are captured. (`--root` against a full mounted filesystem tree does not have this gap, since the real directories are present on disk.) When `SSH_UNAUTHORIZED_KEY` or `SHELL_RC_MODIFICATION` *do* fire (live scan, or `--root` with the real per-user directories present), they now also score confidence from ctime and file content, not mtime alone — see [Confidence scoring](#json-output) below. That improves how much you should trust a finding that does fire; it doesn't change whether the rule fires offline in the first place.
- **`SUSPICIOUS_SYSTEMD_TIMER` detection is weakened offline.** Timers themselves show up (from the captured `systemctl list-timers` output), but each timer's `ExecStart` command comes from a separate per-unit `systemctl show <service> --property=ExecStart` call that `collect` doesn't make, so the `exec_start` field is empty and the rule can't evaluate what the timer actually runs.

**When it matters:** if you're triaging a live, reachable host, use `sudo ubuntils scan` — it has full detection coverage. Use `collect`/`analyze` when you need to acquire once and analyze elsewhere, need to analyze without root, or are working from a disk image where `scan` isn't an option at all — and treat a clean `analyze` result for the rules above as "not checked," not "checked and clean."

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
Backup:    /var/backups/ubuntils/20260115_142201/etc_cron.d_cleanup
Rollback:  cp /var/backups/ubuntils/20260115_142201/etc_cron.d_cleanup /etc/cron.d/cleanup
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
| USER_UID_ZERO | HIGH | No | Any account other than `root` with UID 0 (a hidden second superuser) |
| SUDOERS_NOPASSWD | MEDIUM | Yes | NOPASSWD sudoers grants for users with UID ≥ 1000 and a login shell |
| PROCESS_MASQUERADE | MEDIUM | No | Processes whose name matches a known system binary but whose executable path is outside /usr/bin, /usr/sbin, /bin, /sbin |
| PROCESS_SUSPICIOUS_CONNECTION | HIGH / MEDIUM | No | Processes holding an outbound connection whose executable sits outside the standard binary directories (HIGH) or whose remote port is non-standard (MEDIUM) |
| SHELL_RC_MODIFICATION | LOW | No | Shell init files (bashrc, profile, zshrc, etc.) modified within the last 48 hours for any user with a login shell |
| PACKAGE_TAMPERED | HIGH | No | System-owned package files modified, missing, or whose content/mode/size mismatches the package manifest (via `dpkg --verify`) |
| IMMUTABLE_FLAG_SET | MEDIUM | No | Immutable (`i`) or append-only (`a`) flags set on sensitive files like /etc/passwd, /etc/sudoers, or /etc/pam.d/* (detected via `lsattr`) |
| PAM_BACKDOOR | HIGH | No | Modified /etc/pam.d/* files or unexpected NSS modules in /etc/nsswitch.conf — indicators of authentication bypass |
| KERNEL_MODULE_SUSPICIOUS | HIGH | No | Loaded kernel modules outside an allowlist of common built-in modules — note: hardware-heavy hosts (GPUs, Wi-Fi cards, proprietary drivers) will see false positives; add expected modules via `--config` |
| SETUID_INVENTORY | LOW | No | Unexpected setuid or setgid binaries outside a known baseline set |

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

**USER_UID_ZERO** — Only `root` should hold UID 0. A second account mapped to UID 0 (CIS Ubuntu Benchmark 6.2.x) is a high-confidence backdoor: it grants full superuser rights without altering root's own credentials, and survives a root password reset. Near-zero false-positive rate. Flag-only — removing a UID-0 account requires human judgment.

*Example finding:*
```
[HIGH] USER_UID_ZERO
Title:         Non-root account with UID 0
Artifact:      /etc/passwd
Raw value:     toor:x:0:0:...:/bin/bash
Remediation:   not available
```

**PROCESS_SUSPICIOUS_CONNECTION** — Persistence is only half the picture; a foothold that never talks to anything is rarely the one you care about. This rule joins the process and network collectors by PID so a flagged process arrives with its current connections attached. An executable staged in `/tmp` holding an established outbound socket is HIGH; a legitimate binary reaching a non-standard remote port is MEDIUM and worth a look. This is a snapshot of current state, not continuous monitoring — a beacon that is sleeping when you scan will not appear. Flag-only.

*Example finding:*
```
[HIGH] PROCESS_SUSPICIOUS_CONNECTION
Title:         Process with suspicious outbound connection
Artifact:      /proc/1337/exe
Raw value:     203.0.113.9:4444
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

**PACKAGE_TAMPERED** — System-owned binaries and configuration files are the foundation of trust. This rule detects when package-owned files have been modified, deleted, or have content/mode/size mismatches using `dpkg --verify`. Conffile-only edits (expected local configuration changes) are excluded from reporting to avoid noise. Flag-only — tampering may be legitimate (custom local edits) or malicious (file replacement); deciding requires human judgment.

*Example finding:*
```
[HIGH] PACKAGE_TAMPERED
Title:         Package-owned file modified since installation
Artifact:      /usr/bin/sshd
Raw value:     ....5..T. (content and mtime differ)
Remediation:   not available
```

**IMMUTABLE_FLAG_SET** — Attackers often set the immutable flag (`i`) or append-only flag (`a`) on files to prevent modification or deletion, even by root. Setting these flags on sensitive system files like /etc/passwd, /etc/sudoers, or /etc/pam.d/* is a strong indicator of attacker hardening. This rule detects immutable and append-only flags via `lsattr`. Flag-only — flag changes require human review.

*Example finding:*
```
[MEDIUM] IMMUTABLE_FLAG_SET
Title:         Immutable or append-only flag set on sensitive file
Artifact:      /etc/ld.so.preload
Raw value:     ----i--------e---
Remediation:   not available
```

**PAM_BACKDOOR** — PAM (Pluggable Authentication Modules) and NSS (Name Service Switch) are the core authentication and identity systems on Linux. Modifications to /etc/pam.d/* or unexpected modules in /etc/nsswitch.conf can bypass authentication entirely. This rule flags any modifications to these files and unexpected NSS module loading. Flag-only — authentication configuration changes require careful verification.

*Example finding:*
```
[HIGH] PAM_BACKDOOR
Title:         PAM or NSS configuration modified
Artifact:      /etc/pam.d/common-auth
Raw value:     mtime within last 7 days
Remediation:   not available
```

**KERNEL_MODULE_SUSPICIOUS** — Kernel modules run in ring 0 with unrestricted access. Attackers frequently load custom kernel modules for rootkits, packet sniffing, or process hiding. This rule compares currently loaded modules against a small allowlist of expected built-in modules (common to most systems). **Note:** hardware-heavy hosts with GPU drivers, Wi-Fi cards, or proprietary drivers will generate false positives. Responders should add their host's expected modules via `--config`, allowlisting by module name (used as the `artifact_path`). Flag-only — kernel module investigation requires forensic tools and human expertise.

*Example finding:*
```
[HIGH] KERNEL_MODULE_SUSPICIOUS
Title:         Unexpected kernel module loaded
Artifact:      implant_rootkit
Raw value:     live (currently loaded)
Remediation:   not available
```

**SETUID_INVENTORY** — Setuid and setgid binaries escalate privileges automatically when executed. Attackers create custom setuid binaries to persist privilege escalation. This rule flags setuid/setgid binaries outside a known baseline set of legitimate system utilities. Flag-only — unexpected setuid binaries require investigation but may be legitimate application-installed binaries.

*Example finding:*
```
[LOW] SETUID_INVENTORY
Title:         Unexpected setuid binary found
Artifact:      /tmp/.sh
Raw value:     -rwsr-xr-x (setuid on suspicious path)
Remediation:   not available
```

---

## JSON output

`--json` writes a single JSON object to stdout. Nothing else is printed.

```json
{
  "scan_metadata": {
    "tool_version": "1.5.0",
    "hostname": "web-01",
    "generated_at": "2026-06-10T08:22:03.114523+00:00",
    "ubuntu_version": "Ubuntu 22.04.3 LTS",
    "architecture": "x86_64",
    "duration_s": 2.84,
    "collector_failures": 0,
    "bundle_integrity": "live",
    "command_collectors_skipped": [],
    "suppressed_by_baseline": 1
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
      "remediation_description": "Will remove the offending cron entry from /etc/cron.d/cleanup after creating a timestamped backup.",
      "related_events": [
        {
          "timestamp": "2024-01-15T08:20:00+00:00",
          "source": "syslog",
          "description": "CRON[2841]: (root) CMD (/tmp/.update)"
        }
      ],
      "confidence": 75,
      "confidence_band": "HIGH",
      "signals": [
        {"name": "timeline_corroboration", "weight": 25, "detail": "1 nearby timeline event(s)"}
      ]
    },
    {
      "rule_id": "PROCESS_MASQUERADE",
      "severity": "MEDIUM",
      "title": "Process masquerading as system binary",
      "description": "Process 'sshd' (pid=1337) has exe path outside standard binary directories: /tmp/.sshd",
      "artifact_path": "/proc/1337/exe",
      "raw_value": "/tmp/.sshd",
      "remediation_available": false,
      "guided_remediation": "Confirm pid 1337 is malicious (`ls -l /proc/1337/exe`, `cat /proc/1337/cmdline`), then terminate it: `kill -9 1337`.",
      "confidence": 50,
      "confidence_band": "MEDIUM",
      "signals": []
    }
  ],
  "timeline": [
    {
      "timestamp": "2024-01-15T08:22:01+00:00",
      "source": "syslog",
      "description": "sshd: Accepted publickey for alice from 10.0.0.42 port 52341"
    }
  ],
  "report_sha256": "a3f1c9…(64 hex chars)"
}
```

`remediation_results` appears as an additional top-level key only when `--remediate` is passed. `report_sha256` is always present and is computed over the rest of the document. `scan_metadata.bundle_integrity` is `"live"` for `scan` and `analyze --root`, `"ok"` for a verified bundle passed to `analyze`, and `"mismatch"` if a bundle's content doesn't match its manifest — see [Bundle integrity in JSON output](#bundle-integrity-in-json-output). `scan_metadata.command_collectors_skipped` names any command-based collectors (`NetworkCollector`, `SystemdCollector`) skipped for a `--root` run — always empty for `scan` and `analyze BUNDLE`. `scan_metadata.suppressed_by_baseline` is the count of findings a `--baseline` file removed from this report — see [Known-good baselining](#known-good-baselining---baseline).

`related_events` and `guided_remediation` appear on a finding only when they have content. `related_events` holds up to five timeline events matched to the finding by artifact path and rule keywords, most recent first — a surfacing aid, not a causal claim. `guided_remediation` is a reviewed command sequence for you to run by hand; ubuntils never executes it.

### Confidence scoring

Every finding carries a `confidence` score (0–100, default 50) and a `confidence_band` (`HIGH` ≥ 75, `MEDIUM` ≥ 40, `LOW` below that), plus a `signals` list showing exactly how that score was reached — each entry is `{"name", "weight", "detail"}`, so the score is always explainable, never a black box. Signals are additive on top of a base confidence of 50 and are applied by whichever rule or pipeline stage produced them:

- Detection rules apply their own signals at finding time — e.g. `SSH_UNAUTHORIZED_KEY` and `SHELL_RC_MODIFICATION` add `content_match` (+30) when the artifact's content matches a known-dangerous pattern (a dangerous SSH key option; a curl/wget-to-shell or base64-decode line in a shell RC file), `ctime_corroborates_mtime` (+20) when the file's ctime is also inside the detection window (harder to forge than mtime alone), or `mtime_only` (−20) when recency is the *only* signal and ctime doesn't corroborate it — a cue the mtime may have been backdated.
- The pipeline applies `timeline_corroboration` (+25) after finding↔timeline correlation, when a finding has one or more `related_events`.

A `LOW`-band finding is not dismissed or hidden — it still appears in the findings list and JSON output exactly like any other — but the band tells you how much weight to put on it before investigating further. This replaces the old mtime-only heuristic for `SSH_UNAUTHORIZED_KEY`/`SHELL_RC_MODIFICATION`, where a stale but legitimately-touched file (e.g. a config management tool rewriting `.bashrc` on every run) looked identical to a genuinely new backdoor.

**Known limitation:** only content-pattern and ctime signals are live today. Ownership/fingerprint-based signals — an unknown SSH key fingerprint, a key's `from=` restriction option, or an RC-file owner/mode mismatch (an `ownership_anomaly` signal) — are not yet implemented. This is a deferred coverage gap, tracked for a future release, not something the current confidence score accounts for.

---

## Remediation

Five of the ten detection rules have automated remediation: `CRON_ROOT_EXEC`, `CRON_TMP_PATH`, `LD_PRELOAD_INJECT`, `SSH_UNAUTHORIZED_KEY`, and `SUDOERS_NOPASSWD`. The rest are flag-only and will never be auto-remediated, because acting on them safely needs a human to look first.

### Guided remediation

`SUSPICIOUS_SYSTEMD_TIMER`, `PROCESS_MASQUERADE`, and `SHELL_RC_MODIFICATION` carry a `guided_remediation` string: the exact commands to run once you have confirmed the finding — `systemctl disable --now <unit>`, `kill -9 <pid>`, or the RC-file review and revert. It shows in the TUI detail pane and in JSON. ubuntils never runs it for you; these rules stay out of the `--remediate --confirm` sweep by design.

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
| PackageCollector | System package integrity via `dpkg --verify`, immutable flag attributes via `lsattr`, and setuid/setgid binaries via `find` |
| PamCollector | `/etc/pam.d/*` files and `/etc/nsswitch.conf` |
| KernelCollector | Loaded kernel modules via `lsmod` |

### Collector dependencies

`PackageCollector` requires three standard Ubuntu tools on the live host (`dpkg`, `lsattr`, `find` — all present on stock Ubuntu installations). If any command is unavailable, `PackageCollector` gracefully produces empty data for that portion rather than crashing. Offline analysis (`analyze BUNDLE`) replays the captured command output from `collect` time, so command availability on the analyzer's host is not required.

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
- [x] 240 tests at 90% coverage

**v1.1.0**
- [x] False-positive allowlisting by rule id or path (`--config`)
- [x] `--output FILE` to write reports directly
- [x] `--since` timeline windowing
- [x] Tamper-evident reports (`report_sha256`, hostname, timestamp)
- [x] `USER_UID_ZERO` detection rule

**v1.5.0**
- [x] Custom pattern-match detection rules via YAML (`--rules`)
- [x] `PROCESS_SUSPICIOUS_CONNECTION` — process↔network correlation by PID
- [x] Automatic finding↔timeline correlation (`related_events`)
- [x] Guided remediation for the three judgment-required rules
- [x] 282 tests at 92% coverage

VirusTotal hash lookups and MISP IOC export were dropped from this release. VirusTotal only answers for *known* hashes — the case `rkhunter` already covers, and the opposite of the novel-technique gap ubuntils targets — and both features would have put a network call inside a tool whose value rests on making none. The offline guarantee stays absolute.

**v2.0.0 — offline collect/analyze split**
- [x] `ubuntils collect` — acquires a tamper-evident bundle (`manifest.json` + hashed files/commands) from a live host, no detection
- [x] `ubuntils analyze (BUNDLE | --root PATH)` — runs the same detection/timeline pipeline as `scan` against a bundle or a mounted image, no root required
- [x] `bundle_integrity` (`live`/`ok`/`mismatch`) surfaced in `scan_metadata`
- [x] Documented detection-coverage gaps in offline mode (`PROCESS_MASQUERADE`, `PROCESS_SUSPICIOUS_CONNECTION`, and reduced coverage for cron/sudoers/SSH glob paths and systemd timer `ExecStart`)
- [x] Trustworthy detection: confidence scoring (`confidence`/`confidence_band`/`signals`), `--baseline` suppression, replacing mtime-only heuristics in `SSH_UNAUTHORIZED_KEY`/`SHELL_RC_MODIFICATION` with ctime + content signals, and a real offline timeline for both `analyze BUNDLE` and `analyze --root`
- [x] Coverage pack: `PACKAGE_TAMPERED`, `IMMUTABLE_FLAG_SET`, `PAM_BACKDOOR`, `KERNEL_MODULE_SUSPICIOUS`, `SETUID_INVENTORY` (via `PackageCollector`, `PamCollector`, `KernelCollector`; all flag-only by design)

**v3.0.0 / v4.0.0 (exploratory)**
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
