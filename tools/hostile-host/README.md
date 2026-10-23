# Hostile-host harness

An incident-response tool runs **as root, on a machine the attacker may still control**. Everything it reads — home directories, process names, file names, cron files — is attacker-supplied input. This harness checks whether a tool survives that: it plants hostile conditions on a disposable Ubuntu VM, runs the tool against them, and records what happened.

It came out of the 2026-10 audit of ubuntils, which turned up exactly these bug classes in ubuntils itself (see `CHANGELOG.md`, v2.2.0). The harness asks whether other tools share them.

## What it checks

Each group runs separately, against a fresh unprivileged "victim" account, so one trap can't mask another.

| ID | Group | Planted condition | Bad outcome |
|---|---|---|---|
| R1 | robustness | victim's `~/.bashrc` is a FIFO | **HANG** — the tool blocks forever opening it |
| R2 | robustness | victim's `~/.profile` is a symlink to `/dev/zero` | **HANG / MEMORY** — an endless read |
| R3 | robustness | victim's `~/.bash_history` is a 16 GiB sparse file | **DISK / MEMORY / HANG** — copying or reading 16 GiB of zeros |
| I1 | integrity | victim's `authorized_keys` and `.bash_history` are symlinks to a root-only canary secret | **LEAK** — the secret appears in the tool's output |
| I2 | integrity | the tool is launched from a directory of trojan commands (`ps`, `ss`, `find`, …) and Python modules (`json`, `subprocess`, …) | **HIJACKED** — a trojan ran as root |
| I3 | integrity | terminal escape sequences in file names (`/tmp`, `/dev`), a cron file and a process's argv | **INJECTED** — raw escapes reach the analyst's terminal; RAW-IN-REPORT if only in output files |
| I4 | integrity | file names containing newlines followed by a fake "nothing suspicious found" line | **FORGED** — the fake line appears as a line of the tool's terminal output; FORGED-IN-REPORT if only in output files |
| V1 | visibility | an SSH key in the legacy `~/.ssh/authorized_keys2` | **MISSED** — no trace of it in the output |
| V2 | visibility | a systemd drop-in override piping `curl` into `bash` | MISSED |
| V3 | visibility | a process named `kworker` running from `/dev/shm` | MISSED |
| V4 | visibility | a cron file whose mtime is backdated a year | MISSED |
| V5 | visibility | a download-and-execute line in `/etc/bash.bashrc` | MISSED |

**How verdicts are decided.** Every trap carries a random marker. The harness searches everything the tool produced — stdout, stderr, its output directory, and inside `.tar`/`.tar.gz`/`.zip`/`.gz` archives, two levels deep — without following symlinks or opening anything but regular files.
- **R:** did the run finish within the timeout, the memory guard (`--max-rss-mb`, default 2048) and the disk guard (`--max-disk-gb`, default 4)?
- **I1:** did the canary secret appear anywhere in the tool's output?
- **I2:** did any trojan create its marker in `/root`, which only root can write?
- **I3:** did the exact escape sequence appear in stdout or stderr?
- **I4:** does a line *begin* with the forged marker — in stdout or stderr, or (a raw newline followed by the marker) in an output file?
- **V:** did the marker appear anywhere in the output?

For a collector (UAC, Cat-Scale), **SEEN** means "collected"; for a detector (chkrootkit, rkhunter, ubuntils) it means "mentioned". Read V results with that in mind — a collector that gathers everything SEEs things it never judged.

## Running it

On a disposable Ubuntu VM, as root, with the tools you want to test installed:

```bash
sudo python3 tools/hostile-host/harness.py list
sudo python3 tools/hostile-host/harness.py run --tool ubuntils --tool chkrootkit --tool rkhunter
sudo python3 tools/hostile-host/harness.py run --tool uac --set uac_dir=/opt/uac
```

Each tool gets a baseline run with nothing planted, then one run per group. Results land in `hh-results/<timestamp>/`: `summary.md` is a trap × tool table, `summary.json` has every run's outcome, duration, peak memory and disk use, and each run's stdout, stderr and output directory are kept beside it. `--group leak --group cwd` runs just those groups; `--timeout` caps each run (default 900 s).

**A run only counts if the tool actually worked.** Profiles list the exit codes a healthy run returns (`ok_returncodes`, default `[0]`) and outputs it always produces (`expect_output`, globs). A run that misses either is reported as **BROKEN-RUN** instead of PASS or MISSED — a tool that dies at startup would otherwise "survive" every trap and "miss" every technique. If the baseline run is broken, that tool is skipped.

Tools are described in `profiles.json`: a command with `{out}` (a per-run output directory), `{cwd}` (the per-run working directory), `{repo}` and any `--set key=value` placeholders, plus optional `env`, `run_from` (a directory the tool must be started from — UAC refuses to run anywhere else; such tools get **N/A** for I2) and `extra_outputs` (log files the tool writes elsewhere; only the part appended during the run is captured). Add a profile to test another tool.

## Safety

The harness is built to be safe on a VM that matters to you, but only run it on one you can throw away.

- **Nothing real is exposed.** The "secret" is a random canary in `/root`. The victim account is locked. The SSH key is a random blob with no private key. Every URL uses the reserved `.invalid` TLD. Systemd units are never enabled. Cron entries fire on 31 February. Decoy processes are renamed copies of `bash` that only sleep.
- **Guards stop runaway tools.** A tool that exceeds the time, memory or disk limit has its whole session killed.
- **Everything is undone.** Every planted file, account, process and edit is recorded in `/var/lib/hh-harness` and undone after each group — the one edited system file, `/etc/bash.bashrc`, is restored from a backup. After a crash, `harness.py clean` replays the record.
- **It refuses to start** if a previous run left anything behind, if the ubuntils demo lab is planted, or if there isn't room for the disk guard.

## Limits

- **A PASS only means something if the tool reads the planted files.** A rootkit scanner that never opens users' shell files or SSH keys "passes" R1–R3 and I1 without being tested. Compare each run's duration with the baseline in `summary.json`, and check what the tool reads, before treating a PASS as "handles this safely".
- **It doesn't exercise every launch path.** Tools that re-exec themselves under `sudo` (like ubuntils when run as a normal user) are launched here already as root, so I2 doesn't exercise that path; test it by hand.
- **Visibility is text matching, not a judgment of quality.** A detector that flags V2 without quoting the URL counts as MISSED.
- **Results describe one tool version on one host.** Record both — `summary.json` keeps each baseline's output for that.

**If a tool fails an integrity trap, that's a vulnerability in the tool.** Report it privately to its maintainers and give them time to fix it before publishing.
