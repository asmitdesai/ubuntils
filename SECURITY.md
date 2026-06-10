# Security Policy

## Scope and intended use

ubuntils is a **defensive** incident-response tool. It is designed to run on a
host you own or are authorized to investigate. It collects local forensic
artifacts, flags likely persistence mechanisms, and — only when explicitly
asked — performs minimal, backed-up remediation. It makes no network calls and
exfiltrates nothing.

## Trust model and known limitations

Responders should understand what ubuntils can and cannot guarantee on a host
that may already be compromised:

- **It runs on a potentially hostile host.** Some collectors shell out to system
  utilities (`ps`, `ss`, `systemctl`). On a host with a trojaned binary or a
  loaded rootkit, those tools can lie. Where practical, collectors read `/proc`
  and configuration files directly rather than trusting userland tools, but a
  kernel-level rootkit can defeat any userspace collector. Treat a clean
  ubuntils report as *necessary, not sufficient*.
- **Time-based rules are evadable.** `SSH_UNAUTHORIZED_KEY` and
  `SHELL_RC_MODIFICATION` key off file mtime, which an attacker can reset with
  `touch -r`. They catch unsophisticated activity and recent changes, not a
  careful adversary.
- **Remediation mutates the host under investigation.** Backups are written to
  `/var/backups/ubuntils/` on the same system. If you need a forensically pure
  image, capture it *before* running any remediation. Every report carries a
  `report_sha256` so a collected artifact can be verified later.

## Reporting a vulnerability

If you find a security issue in ubuntils itself (e.g. a remediation path that
could be abused to damage a host, or a collector that writes where it should
only read), please report it privately:

- Email: asmitdesai02@gmail.com
- Or open a GitHub security advisory on the repository.

Please do not open a public issue for an exploitable vulnerability until a fix
is available. Expect an initial response within a few days.
