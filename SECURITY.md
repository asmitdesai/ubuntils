# Security Policy

## Scope and intended use

ubuntils is a **defensive** incident-response tool. It is designed to run on a
host you own or are authorized to investigate. It collects local forensic
artifacts, flags likely persistence mechanisms, and — only when explicitly
asked — performs minimal, backed-up remediation. ubuntils itself makes no network
calls. If a Wazuh agent is installed, a live `scan` writes its findings to a
local file that the agent ships to its manager; `--no-wazuh` turns that off.

## Trust model and known limitations

Responders should understand what ubuntils can and cannot guarantee on a host
that may already be compromised:

- **It runs on a potentially hostile host.** Some collectors shell out to system
  utilities (`ps`, `ss`, `systemctl`). On a host with a trojaned binary or a
  loaded rootkit, those tools can lie. Where practical, collectors read `/proc`
  and configuration files directly rather than trusting userland tools, but a
  kernel-level rootkit can defeat any userspace collector. Treat a clean
  ubuntils report as *necessary, not sufficient*.
- **Time-based rules are evadable — less easily than before.**
  `SSH_UNAUTHORIZED_KEY` and `SHELL_RC_MODIFICATION` check both mtime and ctime.
  `touch` can backdate mtime but not ctime, so a backdated file is still caught
  by its ctime (copies made with preserved timestamps look the same, so this
  is scored as weak evidence, not proof). An attacker with root can still reset ctime (by
  changing the system clock), so a quiet timestamp proves nothing. Content
  checks (dangerous key options, download-and-execute lines) don't depend on
  timestamps at all.
- **Remediation mutates the host under investigation.** Before changing
  anything, `--remediate --confirm` keeps hashed evidence copies of the files
  it will change under `/var/lib/ubuntils/preserve/` (`--preserve-full` adds a
  complete bundle), and backups for rollback go to `/var/backups/ubuntils/`,
  all on the same system. That is triage evidence, not an image: if you need a
  forensically pure image, capture it *before* running any remediation. Every report carries a
  `report_sha256` so a collected artifact can be verified later.
- **`--remediate --confirm` won't act on what it can't attribute, or on what
  would lock an admin out.** These are hard blocks (`blocked_reasons`), checked
  before the confidence gate, and no score lifts them (a forgeable
  `Accepted publickey` log line included):
  - `AMBIGUOUS_KEY`: a key in an `authorized_keys` file holding several keys;
    timestamps can't say which key was added.
  - `RECENCY_ONLY`: a key whose only evidence is that its file changed in the
    last 7 days. A freshly provisioned host looks exactly like that: its
    admin's only key, added this week.
  - `SOLE_SUDO_ACCESS`: a NOPASSWD rule for an account with no usable password
    (locked, like Ubuntu's cloud-image default user, or unreadable). Removing
    it leaves that account no sudo at all.

  Each stays fixable by hand in the TUI, behind a warning. Timeline evidence
  counts for a key only when the log line names that key's fingerprint.

## How ubuntils protects itself on a hostile host

ubuntils runs as root on a machine an attacker may still control, so it treats
what it reads there as hostile input:

- **The caller's environment doesn't choose what runs as root, but the
  install location does.** The `sudo` re-exec names the interpreter by
  absolute path and runs it in isolated mode (`python -I`), so the working
  directory, `PYTHON*` variables and user site-packages are ignored. Running
  `ubuntils scan` from inside an attacker's directory can't import a planted
  module. External commands resolve on a fixed, root-owned `PATH`, never the
  caller's. What root *does* run is ubuntils' own code and its interpreter.
  If those are installed where a non-root user can write (pipx's default
  `~/.local`, a venv in a home directory, an editable checkout), that user
  can change them and get root. ubuntils checks for this before escalating:
  the interpreter, `sys.prefix` and its own package and every directory above
  them, and every file root would run code from (each module already loaded,
  so its dependencies too, every file in the ubuntils package, and every
  `.pth` file in site-packages, which Python executes at start-up). Any of
  them owned by another user or writable by group or others makes it refuse,
  unless you pass `--allow-user-install`. Install it root-owned
  instead (see the README).
- **Files users control are read defensively.** Shell init files, SSH key files
  and per-user systemd units are opened non-blocking and must be regular files
  — a FIFO or `/dev/zero` symlink is skipped and reported as a degraded
  collector instead of hanging the scan. Reading stops at 64 MiB, so a 100 GB
  sparse file can't exhaust memory. A file over 1 MiB is still read, since
  sshd and bash honour every line of it, and is reported as
  `USER_FILE_OVERSIZED`: padding can't hide a key or backdoor. Lines that
  aren't SSH keys are discarded, so a symlink to `/etc/shadow` can't copy
  hashes into the report.
- **Attacker text is never interpreted.** Findings render in the TUI as plain
  text, so markup in a cron line or log message can't restyle or crash it.
- **Every root-run write refuses symlinks, in any path component.**
  Remediation reaches the artifact's directory by walking from `/` with
  `O_NOFOLLOW` on each component. It then reads, backs up, writes a random
  `O_EXCL` temp file, `fchown`s/`fchmod`s and renames, all relative to that
  directory handle, so swapping `~/.ssh` (or anything above it) for a symlink
  is refused. It also refuses if the directory isn't the one, by device,
  inode and owner, that the finding was made on. Sudoers changes are
  `visudo`-checked on a copy before the real file is touched.
- **Rollback never trusts the destination.** `ubuntils rollback BACKUP` reads
  the backup's root-owned sidecar and restores through the same symlink-free
  path, with the original owner and mode. It refuses if the file changed
  after remediation or its directory was replaced (unless `--force`), and
  always refuses a symlink or a non-regular file. ubuntils never suggests
  `cp backup original`, which as root follows a symlink planted at the
  destination.
- **Output files can't be pre-planted.** Bundles are created `O_EXCL` and
  fail if the path exists. By default they go to a random name in
  `/var/lib/ubuntils/bundles/`, which must be a root-owned `0700` directory
  and not a symlink. A report reuses an existing file only if it belongs to
  root or the user who ran `sudo` and has a single link; a file someone else
  pre-created, or a hard link to another file, is refused.
- **Bundles are untrusted input.** `analyze` rejects bundles with path-traversal
  members, links or devices, refuses manifest entries that point outside the
  bundle, and never follows a path from the bundle's own files out of the
  extraction directory. It refuses bundles with more than 10,000 members, a
  member over 512 MiB or more than 2 GiB in total, checked from the tar
  headers before extraction. A file in the bundle that the manifest doesn't
  list, or that it recorded as absent on the host, marks the bundle
  `mismatch`. Bundle and report digests are unkeyed SHA-256: they catch
  corruption and naive edits, not a forger who recomputes them — record
  digests out-of-band for chain of custody.
- **SIEM output is bounded.** Each line forwarded to a Wazuh agent is capped at
  32 KiB, with long fields cut and marked `"truncated": true`, so attacker
  text in a finding or log line can't produce an oversized alert. A scan
  with degraded collectors forwards a summary event saying so.

## Reporting a vulnerability

If you find a security issue in ubuntils itself (e.g. a remediation path that
could be abused to damage a host, or a collector that writes where it should
only read), please report it privately:

- Email: asmitdesai02@gmail.com
- Or open a GitHub security advisory on the repository.

Please do not open a public issue for an exploitable vulnerability until a fix
is available. Expect an initial response within a few days.
