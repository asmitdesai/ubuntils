# Changelog

Notable changes per release. Earlier releases (1.0.0 through 2.1.0) are summarised in the README's [Roadmap](README.md#roadmap).

## Unreleased — 3.0.0 in development

Work toward 3.0.0. Everything here is additive unless it says otherwise.

### Added
- **E8-S1 / R-04 — one suspicious-command matcher.** Cron entries, systemd `Exec*=` lines and shell init files are now checked by the same matcher (`ubuntils/analysis/cmdmatch.py`): reverse shells (`/dev/tcp`, `/dev/udp`, `socat … exec:`, `mkfifo` + `nc`, `nc -e`, `bash -i >&`, python/perl/php/ruby socket one-liners), download-and-execute (a download piped to sh/bash/python/perl, `bash <(curl …)`, `sh -c "$(curl …)"`, download → `chmod +x` → run) and encoded payloads (`base64 -d | sh`, `eval` of a decode, `xxd -r | sh`, `openssl enc -d | sh`, `printf '\x..' | sh`). Each finding explains which pattern matched. Content is judged at any file age. Input is capped at 16 KiB and the patterns are checked for catastrophic backtracking.
- **C3 / E8-S2 — `CRON_SUSPICIOUS_COMMAND`** (HIGH, flag-only): any scheduled command the matcher flags, whoever owns it. A root `/etc/cron.d` reverse shell was invisible before: `CRON_ROOT_EXEC` skips root's entries and `CRON_TMP_PATH` only looks for temp paths.
- **RL-01 — `/etc/anacrontab` and queued `at` jobs** are collected as cron entries. For `at` jobs only the job's own commands are read, not atd's generated preamble. Findings on both are flag-only.
- **C8** `bash <(curl …)` and other forms of download-and-execute in a shell init file are now reported, at any age.
- Version fields, so consumers can tell layouts apart from tool versions: the JSON report has `schema_version` (`"3.0"`), each Wazuh line has `schema_version` (`"3"`), and bundles record `format_version: 1` in `manifest.json`. `analyze` refuses a bundle format newer than it knows, instead of misreading it; bundles from 2.x have no `format_version` and verify exactly as before.
- `scan_metadata.collector_durations_s`: wall time per collector.
- Every finding, in the JSON report and on the Wazuh line, carries `category` (`persistence` or `hygiene`) and `attack`, the rule's MITRE ATT&CK technique IDs, from `ubuntils/data/rule_meta.yaml`. A test checks that every built-in rule is mapped.

- **Preserve, then fix.** Before `--remediate --confirm` or the TUI's `R` changes anything, the files about to change are copied into `/var/lib/ubuntils/preserve/<time>-<random>/` with a manifest of their SHA-256, owner, mode, times, inode and parent directory, read through the same symlink-free path as remediation. If any file can't be preserved, nothing is changed. The manifest's SHA-256 is printed and recorded as `scan_metadata.preserve`. `--preserve-full` collects a full bundle first; `--no-preserve --yes` opts out.

### Fixed
- Remediation reading a file through its symlink-free path leaked a file descriptor, and reported a plain `IsADirectoryError`, when a directory sat where the file was expected; it now refuses with "not a regular file" and closes the descriptor.

### Changed
- Releases can be re-run safely: publishing skips files PyPI already has, and the GitHub Release step adds files to a Release that already exists. 2.3.0's run failed on both after PyPI had accepted it.

### Security
- **N-08** The install-trust check before the `sudo` re-exec covered the interpreter, `sys.prefix` and the ubuntils package directory and the directories above them, but not the files inside: a group-writable `site-packages/click/core.py` or `.pth` file under a root-owned prefix let another user change code root was about to run. It now also checks every loaded module file, every file in the ubuntils package, and every `.pth` file in site-packages (about 0.2 s).
- **N-09** A user file read only up to the 64 MiB ceiling now marks its collector degraded, so the scan reads as incomplete, not just the `USER_FILE_OVERSIZED` finding.

## 2.3.0 — 2026-11-05

The bridge to 3.0: it ships every fix from the 2026-11 external review, two more security fixes, and a warning for everything 3.0 will change.

### Security — found while planning 3.0
- **N-01** A failure in the detection stage outside an individual rule (an allowlist or baseline that raised while filtering) produced an empty findings list with nothing in `rules_failed`, which read as a clean host. It's now recorded as `rules_failed: ["DetectionEngine"]` with the error in `scan_metadata.detection_error`, the TUI says detection failed, and `scan`/`analyze` exit 1.
- **N-14** A `--baseline` entry suppressed any finding whose raw value contained the fingerprint as a word, and for SSH keys that includes the key's comment, which whoever adds the key chooses: the README's own `fingerprint: ci@ci-runner` example hid a planted key labelled `ci@ci-runner`. SSH key entries now match the key only (its `SHA256:` fingerprint or its base64 data), and a path entry no longer hides a finding with a content signal, such as a download-and-execute line added to a baselined `.bashrc`. **If you baselined keys by comment, they show up again**: replace those entries with the key's fingerprint (`ssh-keygen -lf key.pub`).

- **N-15** `scan --remediate --confirm` could lock the only admin out of a freshly provisioned host. On a stock Ubuntu cloud image in its first week, the default user's only SSH key scored 70 on recency alone and its cloud-init `NOPASSWD:ALL` rule 50, both over the remediation gate, so both were removed; that user's password is locked, which left nobody able to log in or use sudo. Safety now rests on hard blocks rather than the score. A key whose only evidence is a recent timestamp is `RECENCY_ONLY`. A NOPASSWD rule for an account with no usable password (locked or unreadable) is `SOLE_SUDO_ACCESS`. Neither is applied automatically, at any `--min-confidence`. Keys with content evidence (a forced command, `authorized_keys2`) are still remediated. Findings carry every block in a new `blocked_reasons` list (`{code, detail}`); `auto_remediation_blocked` keeps the first reason's text. In the demo lab, the sudoers fix is now blocked too (its account is locked); press `R` in the TUI to apply it by hand.

### Security — external review 2026-11
- **F-01** The rollback command ubuntils printed, `cp <backup> <artifact>`, followed a symlink at the destination when run as root: an attacker who replaced a remediated file with a link to `/etc/shadow` got it overwritten with the backup's content. The new `ubuntils rollback BACKUP` restores through the same safe path as remediation, and refuses if the file changed since remediation or its directory was replaced (unless `--force`), or if a symlink or non-regular file is in the way (always). It's the only rollback ubuntils prints now. Each backup gets a `<backup>.json` sidecar with the original owner, mode, parent directory identity and post-remediation hash.
- **F-02** An output file someone else had pre-created was reopened and written: they still owned it and could read the bundle, with `/etc/shadow` inside. Bundles are now created exclusively and fail if the path exists. Reports reuse an existing file only if it belongs to root or the sudo user and has a single link. With no `--output`, bundles go to `/var/lib/ubuntils/bundles/` (0700, refused if it's a symlink or someone else's) under a random name, not the working directory.
- **F-03** One `Accepted publickey for alice` log line, routine or forged with `logger -t sshd`, lifted keys in a multi-key `authorized_keys` back over the remediation gate, and `--remediate --confirm` removed every key in the file, the admin's included. Such keys are now `auto_remediation_blocked` whatever their score. Manual removal in the TUI still works, behind a warning. SSH key corroboration needs the key's fingerprint in the log line.
- **F-04** Remediation guarded only the last path component: swapping `~/.ssh` for a link to another user's `.ssh` between detection and remediation redirected root's edit. Every read, backup, temp file, `fchown`/`fchmod` and rename now happens relative to a directory reached from `/` without following any symlink. Remediation also refuses if the directory isn't the one (device, inode, owner) the finding was made on.
- **F-05** `authorized_keys`, shell init files and per-user units over 1 MiB were skipped, but sshd and bash still honour them, so padding hid a key or backdoor. They're now read up to 64 MiB and parsed as usual, and the new `USER_FILE_OVERSIZED` rule (MEDIUM, flag-only) reports the padding.
- **F-06** The first `pid=` on an `ss` line was taken as the socket's owner, and process names (which any user sets) are on that line: a process named `x",pid=1,` had its connection pinned on PID 1. The parser now anchors on `",pid=N,fd=N)` and takes the last match, and drops a PID whose `/proc/<pid>/comm` doesn't match the name `ss` printed.
- **F-07** The `sudo` re-exec ran whatever was installed. A per-user pipx or venv install let anything running as that user change the code root runs. ubuntils now checks that the interpreter, `sys.prefix` and its package (and every directory above them) are root-owned and not group- or world-writable, and refuses to escalate otherwise unless given `--allow-user-install`. The re-exec runs `python -I`. The README leads with root-owned installs, and SECURITY.md no longer claims no caller code can run as root.
- **F-08** Bundle integrity checked only the files the manifest listed with a hash, so an injected `files/etc/cron.d/x`, or a `files/etc/ld.so.preload` the manifest recorded as absent, verified as `ok`. Both now give `mismatch`.
- **F-09** Wazuh alerts carried every field at full length, related log lines included, so one finding could produce a line hundreds of KB long. Strings are now capped (2,048 characters; 1,024 for event descriptions), `related_events` are dropped from any line still over 32 KiB, and `"truncated": true` marks every cut. A scan with degraded collectors also forwards an `UBUNTILS_SCAN_DEGRADED` summary event.
- **F-10** `analyze` extracted any bundle that passed the path checks. It now refuses more than 10,000 members, a member over 512 MiB, or more than 2 GiB in total, checked from the headers before extraction. Bundle reads are capped at 512 MiB.
- **F-11** Supply chain: `requirements.lock` pins every runtime and build dependency by hash (`pip install --require-hashes -r requirements.lock`), all GitHub Actions are pinned to commit SHAs, CI runs `pip-audit` over the lock, and Dependabot watches pip and Actions. The README installs from a release tag or PyPI, not `main`.
- **F-12** `substring` custom rules only searched the first 4,096 characters, so padding a line hid it. The cap now applies to `regex` rules only, where it guards against backtracking.
- **F-13** The TUI's remediation confirm dialog parsed `remediation_description` as markup: `[/bold]` in it crashed the TUI. It now renders plain text, like the rest of the TUI.
- **F-14** An empty-password account with `/usr/bin/false` as its shell was treated as able to log in. The README now lists what isn't covered: `AuthorizedKeysCommand`, `~/.ssh/rc` and `/etc/ssh/sshrc`, sshd `Include` outside `sshd_config.d`, and `pam_exec.so`.

### Fixed
- `CRON_TMP_PATH` and `CRON_ROOT_EXEC` remediation never worked on a real host: the rules report only the cron command, and the remediator looked for a line equal to it, so every fix failed with "Line not found". It now matches the crontab line that parses to that command. Found by running `--remediate --confirm` against the demo lab.
- `PACKAGE_TAMPERED` produced hundreds of HIGH false positives on Docker's Ubuntu images and Ubuntu's minimized cloud images (375 on a stock `ubuntu:24.04` container): their dpkg `path-exclude` filters skip docs, man pages and translations, and `dpkg --verify` reports each skipped file as missing. Missing files matching the host's `path-exclude` filters are now skipped; `collect` captures the filter config for offline analysis.
- `SUDOERS_NOPASSWD` missed passwordless sudo written in valid sudoers syntax other than the common shape: a rule continued over two lines with `\`, a user list or `User_Alias`, `NOPASSWD:` before a later command in the list, and `Defaults:user !authenticate`. All four were confirmed with `sudo -l` and are now detected; findings that removing one line can't safely fix are flag-only.
- `PROCESS_MASQUERADE` reported the userspace `watchdog` daemon as a HIGH fake kernel thread.
- Stock Ubuntu 24.04 and cloud-image components were reported: the polkit 124 setuid helper (`/usr/lib/polkit-1/polkit-agent-helper-1`) and the `extrausers`, `oslogin`/`cache_oslogin` (every Ubuntu image on GCE) and `libvirt` NSS modules.
- Remediation failed with "Line not found" on indented lines, such as an `export LD_PRELOAD=…` inside an `if` block, because the collectors report the line stripped. Lines now match ignoring surrounding whitespace.
- The TUI's Timeline tab built one widget per event: 2,000 events took about 9 seconds to open and 20,000 crashed the app, well under a week of journald on a real host. It is now a table that renders only visible rows.
- A failed TUI remediation still marked the finding `[fixed]` in the list; it now shows `[remediation failed]`, and a fixed finding can't be remediated twice. The finding detail scrolls (`PgUp`/`PgDn`) instead of cutting off long findings, and the Summary tab lists the most severe findings first.
- `KERNEL_MODULE_SUSPICIOUS` reported 26 stock modules on a clean Ubuntu 24.04 KVM guest (`kvm_intel`, `aesni_intel`, `floppy`, …) because it judged modules by name alone. It now reads each module's taint flags from `/proc/modules`: modules built and signed with the running kernel are not reported, and out-of-tree, unsigned, proprietary or force-loaded modules — what an LKM rootkit looks like — are reported MEDIUM. Bundles capture `/proc/modules`; without it the old allowlist check applies.
- `PACKAGE_TAMPERED` listed missing files before modified ones, so a package with many missing files could push a modified binary past the 20-line listing. Modified files outside `/var` now come first.
- `--since` further back than 7 days still queried only 7 days of journald.
- `scan --output FILE` run as a normal user (the documented way) wrote a root-owned `0600` report its author couldn't read. A report ubuntils creates is now owned by the user who invoked `sudo`.
- `analyze BUNDLE` reported every captured shell init file (`/etc/profile`) as modified in the last 48 hours: file times came from the extracted copy instead of the times the manifest recorded on the collected host.
- The demo lab aborted halfway in an unprivileged container: a refused `chattr +a` stopped `plant` under `set -e`, so the package-tamper and kernel-module artifacts were never planted, and a missing `PACKAGE_TAMPERED` looked like a detection miss. Steps the host can't take are now skipped with a reason, and `plant` and `status` list them.
- The debugging guide told users to undo a remediation with "a `cp` of the backup back over the original", the trap F-01 fixed. It now gives `ubuntils rollback`.

### Changed
- CI runs the tests against `requirements-dev.lock`: the runtime pins from `requirements.lock` plus the test tools, all hash-checked, so CI tests what users install. `pip-audit` checks both locks.
- Releases attach `SHA256SUMS`, and the release workflow grants each job only the permissions it needs.
- The coverage floor is 90%.
- Docs: 17 rules (not 16); collectors and timeline sources run one after another (the README said concurrently); Ubuntu 20.04 is no longer listed (its Python 3.8 never met the 3.9 minimum) and 26.04 is; CONTRIBUTING describes the current remediation contract.

### Deprecated — changing in 3.0
- Python 3.9: 3.0 requires 3.10. Each command says so on 3.9. 2.3.x gets security fixes until six months after 3.0.0.
- The interactive TUI becomes the optional `ubuntils[tui]` extra.
- Baselines without a `version` (text matching) print a warning; 3.0 replaces them with hash-keyed entries from `ubuntils baseline create`.
- `--remediate --confirm` will first keep a hashed copy of every file it changes; it says so now.
- `auto_remediation_blocked` (a string) will be joined by `blocked_reasons` (a list of codes); both stay through 3.x.

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
