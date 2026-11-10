# Default behaviour: 2.3.0 vs the v3 line

Preflight item 3, 2026-11-10. Compares the `v2.3.0` tag (`3b71b86`) with
`v3/preflight` (= `v3-dev` + preflight). Reproduce with:

```bash
git worktree add --detach /tmp/v23 v2.3.0
python3 tools/release/behaviour_diff.py /tmp/v23 . /tmp/diff-out
```

The script scans the fixture hosts in `tests/fixture_hosts.py` (`clean`, and
`lab`: the file-based artifacts of `seed-lab.sh`) offline with both versions,
with a fixed clock and Wazuh off, and diffs the JSON. It also writes a bundle
with the new version and verifies it with the old one.

## JSON reports: additive

| Host | Findings 2.3.0 → v3 | Removed or changed fields |
|---|---|---|
| clean | 0 → 0 | `tool_version` only |
| lab | 10 → 10, same rule IDs, severities, paths, scores | `tool_version` only |

Added: `schema_version: "3.0"` (top level); `attack` and `category` on every
finding; `scan_metadata.preserve`, `preserve_bundle` (null unless remediation
ran) and `collector_durations_s`. Nothing was removed or renamed.

## Other default-behaviour changes (from the six code commits since 2.3.0)

| Change | ID | Who notices | Kind |
|---|---|---|---|
| `--remediate --confirm` copies every file it will change to `/var/lib/ubuntils/preserve/<UTC>-<random>/` first; if that fails, nothing is changed and each eligible finding is FAILED | E1-S4 | anyone running `--remediate --confirm` | **new write to the evidence host** (announced in 2.3.0's Deprecated list); opt out with `--no-preserve --yes` |
| The install-trust check before the `sudo` re-exec also checks every loaded module file, the whole package and `.pth` files; an install 2.3.0 accepted can now be refused (exit 1) without `--allow-user-install` | N-08 | users with a group- or world-writable file under a root-owned prefix | security tightening |
| A user file read only up to the 64 MiB ceiling marks its collector degraded | N-09 | scans of hosts with padded files | more honest status |
| Wazuh lines gain `schema_version: "3"`, `category`, `attack` | ARCH-SV, E4-S1 | SIEM rules | additive |
| `analyze` refuses a bundle whose `format_version` is newer than it knows | ARCH-SV | nobody yet (only format 1 exists) | new refusal |
| New flags `--preserve-full`, `--no-preserve`, `--yes` | E1-S4 | — | additive |
| **A bundle written by the v3 line fails integrity under 2.3.0 `analyze`** (`mismatch`, red warning, exit 3) | ARCH-SV | anyone who collects with 2.4 and analyzes with 2.3.x | **compatibility break** |

### The bundle break

`collect` on the v3 line writes `format_version: 1` into `manifest.json` and
includes it in `bundle_sha256`. 2.3.0's `Manifest` has no such field, drops it
when it rebuilds the manifest, and computes a different digest, so a genuine
bundle reads as tampered. (The other direction works: v3 reads 2.x bundles.)

## Verdict on "a 2.4.0 cut from v3-dev is additive"

**Corrected: additive for reports, not for bundles.** Two intentional changes
(preserve-then-fix, the stricter trust check) belong in the 2.4.0 release
notes. One unintended break (above) must be resolved before 2.4.0. The
recommended fix is to write no `format_version` for format 1 (absent already
means 1 to every reader) and write it from format 2 on, which is a 3.0 change.
A test would then check that a bundle from the new writer verifies under the
2.3.0 reader. This alters part of ARCH-SV, so it is listed under "Needs Asmit"
in `progress.md` and has not been changed.
