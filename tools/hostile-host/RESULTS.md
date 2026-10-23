# Lab and hostile-host results — 2026-10-23

ubuntils compared with chkrootkit, rkhunter and UAC on two tests: the demo lab (`tools/lab/seed-lab.sh`) and the hostile-host harness (`tools/hostile-host/harness.py`).

## Setup

| | |
|---|---|
| Host | Disposable cloud container, Ubuntu 24.04.5 LTS, x86-64, run as root. No systemd or syslog running and no kernel modules available |
| ubuntils | `main` @ `96f3c49` |
| chkrootkit | 0.58b (Ubuntu package) |
| rkhunter | 1.4.6 (Ubuntu package), `--propupd` run on the clean host |
| UAC | 3.2.0 release, `-p ir_triage` |

This was a container, not a VM, which differs from a real host in a few ways:
- The lab's kernel-module artifact (`dummy`) could not be loaded, because the container has no `/proc/modules`.
- All tools ran with no init system or syslog running.
- The image strips package docs, which shows up as package-tampering noise (see below).

## 1. Demo lab

`seed-lab.sh plant` planted 16 artifacts. **Flagged** means the tool raised a warning for the artifact. **Collected** means UAC captured the evidence: UAC is a collector and makes no judgement.

| Artifact (ubuntils rule) | ubuntils | rkhunter | chkrootkit | UAC |
|---|---|---|---|---|
| UID-0 alias account (USER_UID_ZERO) | flagged | flagged | – | collected |
| `/etc/cron.d` entry running from `/tmp` (CRON_TMP_PATH) | flagged | – | – | collected |
| User crontab using `sudo` (CRON_ROOT_EXEC) | flagged | – | – | collected |
| `sudoers.d` NOPASSWD rule (SUDOERS_NOPASSWD) | flagged | – | – | collected |
| `authorized_keys` key with `command=` (SSH_UNAUTHORIZED_KEY) | flagged | – | – | collected |
| Key in `authorized_keys2` (SSH_UNAUTHORIZED_KEY) | flagged | – | – | collected |
| `.bashrc` download-and-execute (SHELL_RC_MODIFICATION) | flagged | – | – | collected |
| `.bashrc` `LD_PRELOAD` from `/tmp` (LD_PRELOAD_INJECT) | flagged | – | – | collected |
| Systemd unit with `ExecStart` in `/tmp` (SUSPICIOUS_SYSTEMD_TIMER) | flagged | – | – | collected |
| Systemd drop-in piping `curl` into `bash` (SUSPICIOUS_SYSTEMD_TIMER) | flagged | – | – | collected |
| PAM file with `pam_permit` (PAM_BACKDOOR) | flagged | – | – | collected |
| `kworker` running from `/dev/shm` (PROCESS_MASQUERADE) | flagged | flagged | flagged | collected |
| `sshd` running from `/var/tmp` (PROCESS_MASQUERADE) | flagged | – | – | collected |
| Setuid script in `/opt` (SETUID_INVENTORY) | flagged | – | – | collected |
| Append-only flag on `/var/log/btmp` (IMMUTABLE_FLAG_SET) | flagged | – | – | **not collected** |
| Line appended to a package file (PACKAGE_TAMPERED) | flagged | – | – | collected (`dpkg -V`) |
| **Total of 16** | **16** | **2** | **1** | **15** |

UAC missed the append-only flag because `ir_triage` doesn't record file attributes (`lsattr`). rkhunter also listed the lab accounts in its passwd/group-changes check.

**Noise unrelated to the lab:**
- **ubuntils**: 411 PACKAGE_TAMPERED findings, caused by the container image stripping docs. Also 2 PROCESS_SUSPICIOUS_CONNECTION findings for the container's own agent processes.
- **rkhunter**: warnings for the missing `/proc/modules`, no syslog daemon, a hidden `/etc/.java` directory, and accounts added by packages installed after its baseline.
- **chkrootkit**: hidden files under `/usr/lib`, "Permission denied" from `ifpromisc` on `/proc/1/fd`, and `chkutmp` failing to open utmp.

**Run times:** chkrootkit 15 s, rkhunter 2 min 33 s, UAC 4 min 55 s.

## 2. Hostile-host harness

`harness.py run` ran each tool once with nothing planted (the baseline), then once per trap group. Every baseline counted as a working run.

| Trap | ubuntils | chkrootkit | rkhunter | UAC |
|---|---|---|---|---|
| R1 `~/.bashrc` is a FIFO | PASS | PASS | PASS | PASS |
| R2 `~/.profile` → `/dev/zero` | PASS | PASS | PASS | PASS |
| R3 16 GiB sparse `~/.bash_history` | PASS | PASS | PASS | PASS † |
| I1 symlinks to a root-only secret | PASS | PASS | PASS | PASS |
| I2 trojan commands in the working directory | PASS | PASS | PASS | N/A ‡ |
| I3 terminal escape sequences | PASS | PASS | PASS | withheld † |
| I4 newline-forged report lines | PASS | PASS | PASS | PASS |
| V1 key in `authorized_keys2` | SEEN | MISSED | MISSED | SEEN |
| V2 systemd drop-in piping `curl` into `bash` | SEEN | MISSED | MISSED | SEEN |
| V3 `kworker` running from `/dev/shm` | SEEN | SEEN | SEEN | SEEN |
| V4 cron file backdated a year | SEEN | MISSED | MISSED | SEEN |
| V5 download-and-execute in `/etc/bash.bashrc` | SEEN | MISSED | MISSED | SEEN |

† Details withheld until they have been reported to the UAC maintainers, as the harness README asks.
‡ UAC only runs from its own directory, so I2 can't be tested.

For UAC, SEEN means collected, not detected.

### Do the PASSes mean anything?

The harness README warns that a PASS only counts if the tool actually reads the planted files. So for each tool, the question is whether it touched the traps:

| Tool | Baseline | Trap runs | Read the planted files? |
|---|---|---|---|
| ubuntils | 21.6 s | 8.0–8.1 s | **Yes.** Its reports from the R1–R3 and I1 runs reference the victim account, so it opened those files and handled them. |
| UAC | 129.7 s | 114.6–121.8 s (R3 †) | **Yes.** Its archives contain the victim's dotfiles. It skipped the FIFO and stored the symlinks as links. |
| chkrootkit | 19.6 s | 19.1–20.6 s | **Probably not.** Run times didn't change, and it doesn't read users' shell files or SSH keys. Its R1–R3 and I1 PASSes are untested, not proven safe. |
| rkhunter | 150.3 s | 163.3–175.5 s | **Probably not**, for the same reason. |

### Harness fix made during this run

The first rkhunter results were wrong. For logs a tool writes elsewhere (`extra_outputs`), the harness kept only the bytes past the log's size before the run. rkhunter doesn't append to `/var/log/rkhunter.log`: it copies it to `.old` and then empties it and rewrites it in place. So the capture came back empty in 6 of 7 runs. As a result, V3 read MISSED although the log named the decoy, and I1 and I3 never checked the log.

Commit `b7475bd` records the log's inode, size and first 4 KiB before each run, and reads the whole log if any of them changed. rkhunter was then re-run: all 7 trap runs captured their full log, and V3 changed to SEEN. The table above shows the re-run.

## What this does and doesn't show

- ubuntils caught everything the lab and the harness plant, and it survived every robustness and integrity trap after actually reading the hostile files. The bug classes fixed in 2.2.0 didn't come back.
- Both tests were written around ubuntils's own rules and its 2026-10 audit, so a full score shows the rules fire. It doesn't show what ubuntils would miss. Planting techniques it has no rule for would be the next step.
- rkhunter and chkrootkit look for known rootkits and changed system binaries, not persistence, so their low visibility scores are expected. They aren't directly comparable to ubuntils.
- The noise ubuntils raised on this host (411 package findings, 2 connection findings) would bury real findings on a minimal or container-like system.
- Not covered:
  - the kernel-module artifact (the container can't load one)
  - the `sudo` re-exec path, because the harness starts every tool as root
  - a real VM. These results describe one host and these tool versions.
