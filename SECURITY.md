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
- **Remediation mutates the host under investigation.** Backups are written to
  `/var/backups/ubuntils/` on the same system. If you need a forensically pure
  image, capture it *before* running any remediation. Every report carries a
  `report_sha256` so a collected artifact can be verified later.

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
  can change them and get root. ubuntils checks for this before escalating
  and refuses unless you pass `--allow-user-install`. Install it root-owned
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
- **Every root-run write refuses symlinks** (`O_NOFOLLOW`, `O_EXCL` for backups,
  atomic rename for edits), and sudoers changes are `visudo`-checked on a copy
  before the real file is touched.
- **Bundles are untrusted input.** `analyze` rejects bundles with path-traversal
  members, links or devices, refuses manifest entries that point outside the
  bundle, and never follows a path from the bundle's own files out of the
  extraction directory. Bundle and report digests are unkeyed SHA-256: they
  catch corruption and naive edits, not a forger who recomputes them — record
  digests out-of-band for chain of custody.

## Reporting a vulnerability

If you find a security issue in ubuntils itself (e.g. a remediation path that
could be abused to damage a host, or a collector that writes where it should
only read), please report it privately:

- Email: asmitdesai02@gmail.com
- Or open a GitHub security advisory on the repository.

Please do not open a public issue for an exploitable vulnerability until a fix
is available. Expect an initial response within a few days.
