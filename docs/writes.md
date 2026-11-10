# What ubuntils writes on the host

ubuntils runs on a host that is evidence. This page lists every place it writes,
and when. `tests/test_writes.py` fails if the code gains a write location that
isn't listed here, or if a plain scan writes anything at all.

## A scan (`ubuntils scan --json`, the TUI) writes nothing, except:

| Path | When | Why | How to avoid |
|---|---|---|---|
| The `--output FILE` you name | `--output` given | the report (0600, owned by you) | print to stdout instead |
| `/var/log/ubuntils/wazuh-alerts.json` | a Wazuh agent is installed **and** `--no-wazuh` is not given | findings for the local agent to ship (2.x default; opt-in in 3.0, E7-S1) | `--no-wazuh` |

## Remediation (`--remediate --confirm`, or `R` in the TUI) also writes

| Path | Why |
|---|---|
| `/var/lib/ubuntils/preserve/<UTC>-<random>/` | evidence copies of every file about to change, with a hashed manifest (E1-S4); skipped only with `--no-preserve --yes` |
| `/var/lib/ubuntils/bundles/` | with `--preserve-full`: a full bundle before anything changes |
| `/var/backups/ubuntils/<timestamp>/` | backups for `ubuntils rollback`, with a sidecar per file |
| the remediated files themselves | the fix: a minimal, atomic edit (temp file in the same directory, then rename) |
| a temporary copy of the sudoers file in the system temp directory | `visudo -cf` checks it before the real file changes |

A dry run (`--remediate` without `--confirm`) writes nothing.

## `ubuntils collect` writes

| Path | Why |
|---|---|
| `--output FILE`, or `/var/lib/ubuntils/bundles/ubuntils-bundle-<time>-<random>.tar.gz` | the bundle (0600, created exclusively) |
| `/var/lib/ubuntils/staging/ubuntils_collect_*/` | the uncompressed copy while compressing; removed afterwards, also on Ctrl-C (QW-12) |

## `ubuntils analyze` (on the analyst's machine) writes

| Path | Why |
|---|---|
| a directory in the system temp directory | the extracted bundle; removed when the analysis ends |
| `--output FILE` | the report |

## `ubuntils rollback` writes

The file being restored (through the same symlink-free path as remediation).

Everything under `/var/lib/ubuntils` is a root-owned `0700` directory, refused if
it is a symlink or owned by someone else. All of these are on the host's own disk;
put `--output` on removable or network storage if that matters for your case.
