# Changelog

Notable changes per release. Earlier releases (1.0.0 through 2.1.0) are summarised in the README's [Roadmap](README.md#roadmap).

## Unreleased

### Fixed
- `CRON_TMP_PATH` and `CRON_ROOT_EXEC` remediation never worked on a real host: the rules report only the cron command, and the remediator looked for a line equal to it, so every fix failed with "Line not found". It now matches the crontab line that parses to that command. Found by running `--remediate --confirm` against the demo lab.
- `PACKAGE_TAMPERED` produced hundreds of HIGH false positives on Docker's Ubuntu images and Ubuntu's minimized cloud images (375 on a stock `ubuntu:24.04` container): their dpkg `path-exclude` filters skip docs, man pages and translations, and `dpkg --verify` reports each skipped file as missing. Missing files matching the host's `path-exclude` filters are now skipped; `collect` captures the filter config for offline analysis.
- `SUDOERS_NOPASSWD` missed passwordless sudo written in valid sudoers syntax other than the common shape: a rule continued over two lines with `\`, a user list or `User_Alias`, `NOPASSWD:` before a later command in the list, and `Defaults:user !authenticate`. All four were confirmed with `sudo -l` and are now detected; findings that removing one line can't safely fix are flag-only.
- `PROCESS_MASQUERADE` reported the userspace `watchdog` daemon as a HIGH fake kernel thread.
- Stock Ubuntu 24.04 and cloud-image components were reported: the polkit 124 setuid helper (`/usr/lib/polkit-1/polkit-agent-helper-1`) and the `extrausers`, `oslogin`/`cache_oslogin` (every Ubuntu image on GCE) and `libvirt` NSS modules.
- Remediation failed with "Line not found" on indented lines, such as an `export LD_PRELOAD=…` inside an `if` block, because the collectors report the line stripped. Lines now match ignoring surrounding whitespace.
- The TUI's Timeline tab built one widget per event: 2,000 events took about 9 seconds to open and 20,000 crashed the app, well under a week of journald on a real host. It is now a table that renders only visible rows.
- A failed TUI remediation still marked the finding `[fixed]` in the list; it now shows `[remediation failed]`, and a fixed finding can't be remediated twice. The finding detail scrolls (`PgUp`/`PgDn`) instead of cutting off long findings, and the Summary tab lists the most severe findings first.
- `--since` further back than 7 days still queried only 7 days of journald.
- `scan --output FILE` run as a normal user (the documented way) wrote a root-owned `0600` report its author couldn't read. A report ubuntils creates is now owned by the user who invoked `sudo`.
- `analyze BUNDLE` reported every captured shell init file (`/etc/profile`) as modified in the last 48 hours: file times came from the extracted copy instead of the times the manifest recorded on the collected host.

## 2.2.0 — 2026-10-16

Validated on a live Ubuntu 26.04 LTS arm64 host. A clean VM that produced 1,243 findings on 2.1.0 produces 13 on 2.2.0, all of them attributable to the Wazuh manager installed on it.

### Security — found in a pre-conference audit
- The `sudo` re-exec ran `python -m ubuntils.cli`, which puts the working directory first on `sys.path`: running `ubuntils scan` from an attacker-controlled directory imported a planted module as root. The re-exec now drops that entry before importing anything.
- `analyze` on a hostile bundle could read the analyst's own files — through manifest paths like `../../home/analyst/.ssh/id_rsa`, or home directories in the bundle's `/etc/passwd`. Manifest entries outside the bundle are now refused and every bundle read is contained.
- Any user could hang or blind the scan by making `~/.bashrc` a FIFO, a `/dev/zero` symlink or a huge sparse file; a symlinked `authorized_keys` copied `/etc/shadow` lines into reports. Files in user-controlled locations are now read non-blocking, must be regular files of at most 1 MiB, and non-key lines are discarded.
- Attacker text was parsed as Rich markup in the TUI: a cron line containing `[/bold]` crashed it when selected, and markup could restyle findings. Findings now render as plain text (which also makes the `[fixed]` marker visible).

### Added — detection
- SSH keys are read from `authorized_keys2` and every `AuthorizedKeysFile` in `sshd_config`/`sshd_config.d`; any key in `authorized_keys2` is reported.
- Systemd drop-in overrides (`<unit>.service.d/*.conf`) are read, and `Exec*=` lines that pipe a download into a shell or decode base64 are flagged.
- `/etc/bash.bashrc`, `/etc/zsh/*`, `.bash_login`, `.zshenv` and `.zlogin` are collected; system shell init files feed `SHELL_RC_MODIFICATION` too.
- `PROCESS_MASQUERADE` reports userspace processes named like kernel threads (`[kworker/0:1]`) as HIGH.

### Fixed — detection and remediation
- `SSH_UNAUTHORIZED_KEY` and `SHELL_RC_MODIFICATION` checked mtime only, so `touch -d` hid a planted key or backdoor. Both now use mtime *or* ctime; a recent ctime behind an old mtime adds a weak `mtime_predates_ctime` signal (copies with preserved timestamps look the same).
- `SHELL_RC_MODIFICATION` ignored download-and-execute lines in files older than 48 hours; suspicious content is now reported at any age (MEDIUM).
- SSH keys with options (`command="…"`) or unusual spacing couldn't be removed — remediation now matches the exact line.
- Every key in a recently changed `authorized_keys` was auto-removable, the admin's included. Plain keys in a multi-key file now score below the remediation gate.
- `--remediate` without `--confirm` wrote backups to `/var/backups/ubuntils`; a dry run now writes nothing.
- A second fix to the same file within a second failed on the backup name; backups now get a numeric suffix. Rollback commands are shell-quoted.

### Changed — reporting
- Wazuh alerts include `confidence` and `confidence_band`; the example rules escalate HIGH-severity, HIGH-confidence findings (rule 100104).
- `--config` allowlist suppressions are counted (`suppressed_by_allowlist`) in the report and the Stats tab.
- Docs no longer overstate bundle/report integrity: the digests are unkeyed and catch corruption and naive edits, not forgery.

### Fixed — false positives
- `PAM_BACKDOOR` no longer fires on every stock Ubuntu install. It flags `pam_permit.so` only when it can decide an auth/account stack on its own — it short-circuits the stack, or the `pam_deny` gate in front of it was removed or demoted.
- `PROCESS_SUSPICIOUS_CONNECTION` treats connections on a listening port as inbound, so the responder's own SSH session is no longer flagged; inbound connections still get the executable-location check, so a bind shell in `/tmp` stays HIGH. IPv4-mapped loopback is ignored and DHCP is a common port.
- `SETUID_INVENTORY` knows sudo-rs, the default sudo on Ubuntu 25.10+ (`/usr/lib/cargo/bin/sudo`, `/usr/lib/cargo/bin/su`, `/usr/bin/sudo.ws`).
- `KERNEL_MODULE_SUSPICIOUS` allowlists stock arm64 crypto, virtio/vsock, HID and sound modules.

### Changed — `PACKAGE_TAMPERED`
- One finding per package instead of one per file, using `dpkg-query -S` to attribute files (captured in bundles too). The artifact is the package name, so a noisy package can be allowlisted in one line.
- MEDIUM when every changed file is under `/var` (package runtime data); LOW when only directories are missing (checked against the package's `.md5sums`).
- Falls back to per-file findings, and records a degraded collector, when ownership can't be determined.
- Missing conffiles keep their conffile marker.
- Packages removed but not purged (`config-files` state) are skipped — their leftover directories going missing isn't tampering. Package state comes from `/var/lib/dpkg/status`, which bundles now capture.
- Descriptions only mention nonzero counts ("has 1 missing directory").

### Changed — confidence scoring and the timeline
- `timeline_corroboration` (+25) is applied only when a timeline event names the finding's artifact alongside the rule's kind of activity. Previously any keyword match counted, and on a real host every finding got the bonus.
- Correlation matches whole words against each event's program and message; keyword-only events are shown as context but never scored.
- Timeline events carry the logging `program` (syslog tag / journald identifier), in JSON and the TUI.
- Copies of journald messages that rsyslog also wrote to syslog are collapsed; repeats within one source are kept.

### Added — hostile-host harness
- `tools/hostile-host/harness.py` runs any IR tool against a hostile host — FIFO, `/dev/zero` and sparse-file traps, symlink leaks of a root-only canary, a trojaned working directory, terminal-escape and forged-line injection, and five stealthy persistence techniques — and tabulates the outcome per tool. Profiles for ubuntils, UAC, chkrootkit, rkhunter and Cat-Scale.
- `SHELL_RC_MODIFICATION` reports the offending line as its raw value instead of the file path, and ignores commented-out lines.

### Added — demo lab
- `tools/lab/seed-lab.sh plant|status|clean` plants inert artifacts that trip 14 of the 16 rules on a disposable Ubuntu VM, and removes them exactly. Nothing it plants can execute or grant access.

### Docs
- `SECURITY.md` describes how ubuntils protects itself on a hostile host, and no longer claims mtime-only rules or zero network egress.
- Install instructions work with pipx: run `ubuntils scan` as your user (it escalates itself) rather than `sudo ubuntils scan`, which can't find a pipx-installed command.
- Scan-time claims corrected to measured numbers.
