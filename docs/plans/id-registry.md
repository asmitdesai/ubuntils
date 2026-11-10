# ubuntils plan ID registry

The single source of truth for every ID used in the v3.0.0 plan, its commits,
tests and CHANGELOG. Regenerated on 2026-11-10 against `v3-dev` @ `e864eed`
(`origin/feat/v3.0.0` 29fc4e6 + the 2.3.0 release merged in).

**Rules**

1. An ID never changes meaning once a commit, test or CHANGELOG entry cites it.
2. IDs are never reused. Gaps stay gaps (marked *reserved*).
3. New maintainer findings start at **N-16**. New epics start at **E14**
   (E12 and E13 are taken by this plan).
4. Review IDs (R-, C, RL-, QW-) map onto stories; they never replace them.
   Code and tests cite the review with a `review_` prefix
   (`test_review_c3_root_crond_dev_tcp`) because bare `C1`…`C3` already exist
   in the test suite with another meaning (see "Historical namespaces").
5. Every story that closes an ID updates its row here in the same commit.

**Status vocabulary:** done (2.x.y = shipped in that release; v3-dev = merged
to `v3-dev`, unreleased) · partial · open · reserved · won't (3.0).

**Source vocabulary:** lost-plan (cited in code before this regeneration; meaning
recovered from the code), review (2.3.0 practitioner review), sec-review
(2026-11 external security review), maintainer, new (introduced by this plan).

---

## 1. Epics

| ID | Meaning | Source | Status |
|---|---|---|---|
| E1 | Trustworthy remediation | lost-plan | in progress |
| E2 | Zero-install triage | lost-plan (number), new (content) | open |
| E3 | Signal over noise / false-positive control | lost-plan | in progress |
| E4 | Speak the SOC's language | lost-plan | in progress |
| E5 | Offline parity | lost-plan (number), new (content) | open |
| E6 | Fleet triage | lost-plan (number), new (content) | open (recommended: defer to 3.1) |
| E7 | Wazuh for real | lost-plan (number), new (content) | open |
| E8 | Coverage expansion | lost-plan (number), new (content) | open |
| E9 | Beyond Ubuntu | lost-plan (number), new (content) | open |
| E10 | Contributor platform | lost-plan (number), new (content) | open |
| E11 | Proof and docs | lost-plan (number), new (content) | open |
| E12 | Process and timeline depth | new | open |
| E13 | Production readiness | new | open |

## 2. Stories

Fixed IDs are in **bold**. Full Given/When/Then text is in `v3.0.0-prd.md` §8.

| ID | Meaning | Source | Status | Evidence | Closes |
|---|---|---|---|---|---|
| E1-S1 | Remediation is opt-in, dry-run by default, and a dry run writes nothing | new (records shipped work) | done 2.2.0 | `remediators/base.py` dry-run path; 2026-10 audit M1 test | — |
| E1-S2 | Symlink-free remediation I/O and a guarded `ubuntils rollback` | new (records shipped work) | done 2.3.0 | `utils/safe_path.py:31`, `remediators/rollback.py:83`; `test_F01_*`, `test_F04_*` | F-01, F-04 |
| **E1-S3** | Remediation safety rests on hard blocks (`RECENCY_ONLY`, `SOLE_SUDO_ACCESS`, `AMBIGUOUS_KEY`), not the confidence score | lost-plan | done 2.3.0 | `b7e06c4`; `detectors/finding.py:15-17`, `pipeline.py:79-102`; `test_N15_*` | N-15, F-03 |
| **E1-S4** | Preserve-then-fix: copy files to the evidence store before remediation; budget 50 × 1 MiB in ≤ 2 s; `--no-preserve --yes` to opt out | lost-plan | done v3-dev | `edaabe1`; `remediators/preserve.py:38`; `tests/test_preserve.py` | — |
| E1-S5 | Remediation is presented as an advanced, post-scoping step, not a headline feature | new | open | — | review positioning |
| E1-S6 | `--backup-dir` with a same-filesystem warning | new | open | — | R-08 |
| E1-S7 | Remediators act on a structured `RemediationTarget`, not on `raw_value` string matching | new | open | arch 2.2.3 | — |
| E2-S1 | Single-file build that runs on the system `python3` with no pip step | new | open | — | R-01 |
| E2-S2 | The single-file build is signed, checksummed and verifiable offline | new | open | — | R-01, R-09 |
| E2-S3 | A scan from the single file writes nothing outside the report path and the ubuntils state dir | new | open | — | R-08 |
| E3-S1 | Explainable confidence scoring with weighted signals | new (records shipped work) | done 2.0.0–2.2.0 | `detectors/scoring.py` | — |
| E3-S2 | Allowlist and baseline suppression, counted and never silent | new (records shipped work) | done 2.2.0–2.3.0 | `utils/baseline.py`; `test_N14_*`, 2026-10 audit W2 | N-14 |
| E3-S3 | Hash-keyed baselines created with `ubuntils baseline create` | new (announced in 2.3.0) | open | `utils/baseline.py:39` (V1_DEPRECATION) | — |
| E3-S4 | Connection noise control: listener/exe evidence instead of a fixed port list | new | open | `detectors/rules.py:38-40` | R-07 |
| **E3-S5** | Clean-host false-positive suite: stock images, a reviewed baseline per image, target ≤ 3 findings and 0 HIGH | lost-plan | partial | `c8734ee`; `tools/fp-suite/run.sh`, `check.py`; no baselines, no CI; known 7 LOW `SHELL_RC_MODIFICATION` on `ubuntu:24.04` from image-unpack ctime | — |
| E3-S6 | Clean-host corpus on VMs and cloud images (3 clouds, Docker host, Kubernetes node, DB server) with published counts per release | new | open | — | R-07 |
| E3-S7 | Inventory findings (category `inventory`) are reported but excluded from the noise budget | new | open | — | QW-3 interaction |
| **E4-S1** | Persistence vs hygiene category plus ATT&CK IDs per rule (`ubuntils/data/rule_meta.yaml`), reaching JSON and Wazuh | lost-plan | done v3-dev | `b9b9529`; `detectors/rule_meta.py:28`; `tests/test_rule_meta.py` | R-10 (ATT&CK half) |
| E4-S2 | Markdown report | new (decided in README roadmap) | open | README roadmap | — |
| E4-S3 | Stable `finding_id` and SHA-256 of every flagged file | new | open | — | QW-7, QW-8 |
| E4-S4 | `host_id` is populated | new | open | `bundle/manifest.py:36`, `bundle/writer.py:105` (always "") | R-10 |
| E4-S5 | `--fail-on-findings[=SEVERITY]` and a documented exit-code table | new | open | `cli.py:31-34` | QW-9 |
| E4-S6 | Frozen, versioned JSON Schema for report, Wazuh line and bundle manifest | new | open | arch 2.2.9 | R-10 |
| E5-S1 | `collect` captures what the collectors read (read-set recording) | new | open | `cli.py:47-85` | R-02 |
| E5-S2 | `scan` and `analyze BUNDLE` produce the same finding set on a fixture host; live-only findings are labelled | new | open | — | R-02 |
| E5-S3 | `collect --journal-days N` and `auth.log` in bundles | new | open | `cli.py:79` | QW-11, QW-6 |
| E5-S4 | Bundle staging under `/var/lib/ubuntils`, never the system temp dir | new | open | `bundle/writer.py:61` | QW-12, R-08 |
| E5-S5 | Signed bundles (`ssh-keygen -Y sign`) and an offline verify command | new | open | — | R-09 |
| E5-S6 | 3.x `analyze` reads 2.x bundles (format 1) | new | open | `bundle/manifest.py:10` | — |
| E6-S1 | `ubuntils diff A.json B.json` using `finding_id` | new | open | — | QW-8 follow-on |
| E6-S2 | Agentless SSH sweep of several hosts | new | won't (3.0); 3.1 decision | — | — |
| E7-S1 | Wazuh forwarding is opt-in (`--wazuh`) | new | open | `pipeline.py:171`, `pipeline.py:279` | R-08 |
| E7-S2 | Wazuh decoder/rules ship for every rule ID and alias, tested with `wazuh-logtest` in CI | new | open | `examples/wazuh/local_rules.xml` | QW-13 |
| E7-S3 | Supported Wazuh versions documented and tested | new | open | — | — |
| E8-S1 | One shared suspicious-command matcher | new | open | `detectors/rules.py:664-665` | R-04, QW-5, C3, C8 |
| E8-S2 | Cron breadth: root crontabs and `/etc/cron.d` through the matcher, `anacrontab`, `at` jobs | new | open | `detectors/rules.py:94-95`, `collectors/cron.py:41-50` | C3, RL-01 |
| E8-S3 | Systemd breadth: rename `SUSPICIOUS_SYSTEMD_TIMER`; all `Exec*` keys; `.timer`/`.socket`/`.path` bodies; every user-unit dir; generators; unowned + recent units | new | open | `collectors/systemd.py:9-33` | C4, RL-02, QW-13 |
| E8-S4 | SSH breadth: inventory every key; `environment=`/`permitopen=` signals; `AuthorizedKeysCommand`; `~/.ssh/rc`, `/etc/ssh/sshrc` | new | open | `detectors/rules.py:297-302` | C1, QW-3, RL-03, R-03 |
| E8-S5 | Account privilege: service accounts with login shells, recent accounts, privileged groups | new | open | `detectors/rules.py:608-661` | C6, RL-04 |
| E8-S6 | Sudoers: evaluate every account; unowned `sudoers.d` files | new | open | `detectors/rules.py:360-361` | C5, QW-4, RL-05 |
| E8-S7 | Processes by location (writable tmp, deleted, memfd) and listeners | new | open | `detectors/rules.py:535`, `:577-579` | C2, QW-1, QW-2, RL-06, RL-07 |
| E8-S8 | Setuid search widened; file capabilities | new | open | `collectors/packages.py:16-18` | C7, RL-13 |
| E8-S9 | Loader hijacks: `LD_AUDIT`, `LD_LIBRARY_PATH`, `ld.so.conf.d`, unit `Environment=` | new | open | `detectors/rules.py:150-151` | C9, RL-14 |
| E8-S10 | PAM: `pam_exec` and modules no package owns | new | open | `detectors/rules.py:1032-1060` | RL-11, R-03 |
| E8-S11 | Boot and login hook pack: udev, XDG autostart, `update-motd.d`, `rc.local`, init scripts, apt/dpkg hooks, generators, `modules-load.d` | new | open | (no code) | R-03 |
| E8-S12 | Kernel modules: `/proc/modules` vs `/sys/module` cross-check | new | open | `collectors/kernel.py:7,14` | RL-12 |
| E8-S13 | Immutable-flag paths widened | new | open | `collectors/packages.py:6-11` | RL-10 |
| E8-S14 | Shell init hijacks: `alias`, `trap`, `PROMPT_COMMAND` | new | open | `detectors/rules.py:668-682` | RL-08 |
| E8-S15 | `PACKAGE_TAMPERED` says that `dpkg --verify` trusts on-host checksums | new | open | `detectors/rules.py:859-860` | RL-09 |
| E9-S1 | Debian 12 supported and tested | new | open | — | — |
| E9-S2 | RPM-based distributions through the package-manager abstraction | new | won't (3.0); 3.1 decision | — | — |
| E10-S1 | Rule package with decorator registration and metadata | new | open | arch 2.2.2 | — |
| E10-S2 | Allowlists as reviewed data files | new | open | arch 2.2.8 | — |
| E10-S3 | Custom rules gain `systemd`, `users`, `sudoers` and `file` sources | new | open | `detectors/custom_rules.py:21` | QW-10 |
| E10-S4 | "Write your first rule" guide and a rule reference generated from metadata | new | open | `CONTRIBUTING.md` | — |
| E10-S5 | Written stability promise for the custom-rule format (Python rule API stays internal in 3.0) | new | open | — | — |
| E11-S1 | PANIX benchmark harness (`tools/panix/`), misses published | new (decided in README roadmap) | open | README roadmap | review next-step 3 |
| E11-S2 | README first screen; everything else in `docs/` | new | open | `README.md` (1,105 lines on v3-dev) | review positioning |
| E11-S3 | Results published per release (`docs/results/<version>.md`) | new | open | `tools/hostile-host/RESULTS.md` | — |
| E11-S4 | Public response to the 2.3.0 review | new | done v3-dev (this commit) | `docs/reviews/2.3.0-response.md` | — |
| E11-S5 | Troubleshooting page and `--help`/man-page parity check | new | open | `docs/debugging-common-issues.md` | — |
| E12-S1 | Process depth: PPID, start time, cwd, bounded environ, maps | new | open | `collectors/processes.py:28-34` | R-05 |
| E12-S2 | Deleted, memfd and hidden-process checks | new | open | — | R-05, QW-1 |
| E12-S3 | Timeline breadth: `auth.log`, rotated and compressed logs, `wtmp`/`btmp`/`lastlog`, shell history | new | open | `timeline/builder.py:48-61` | R-06, QW-6 |
| E12-S4 | Timeline from an offline image's journal | new | open | `timeline/builder.py:132` | R-06 |
| E13-S1 | Supply chain: SBOM, provenance, signed release artifacts | new | open | `.github/workflows/release.yml` | R-09 |
| E13-S2 | Tested OS/arch support matrix (containers, plus a VM job) | new | open | `.github/workflows/ci.yml` | — |
| E13-S3 | Semantic-versioning scope and deprecation policy | new | open | arch 2.2.9 | R-10 |
| E13-S4 | Output contract enforced in CI (golden outputs validated against the schema) | new | open | — | R-10 |
| E13-S5 | A tested list of everything ubuntils writes on the host | new | open | — | R-08 |
| E13-S6 | Performance and resource budgets in CI | new | open | `pipeline.py:183` | — |
| E13-S7 | Collector failure injection: every failure is degraded, never clean, never a traceback | new | open | `pipeline.py:197-211` | — |
| E13-S8 | Security process: threat model per collector, private reporting, scheduled fuzzing | new | open | `SECURITY.md` | — |
| E13-S9 | Coverage ratchet with branch coverage and 100% on security-critical modules | new | open | `pyproject.toml` addopts | — |
| E13-S10 | Property-based and mutation testing | new | open | — | — |
| E13-S11 | `MAINTAINERS.md`, `CODEOWNERS`, PR template | new | open | `.github/` (no PR template, no CODEOWNERS) | — |
| E13-S12 | `docs/releasing.md` release checklist | new | open | — | — |

## 3. Architecture items and plan sections

Section numbers are fixed; code comments removed in `29fc4e6` cited §2.2.2,
§2.2.9, §2.2.10 and §3.

| ID | Meaning | Source | Status | Evidence |
|---|---|---|---|---|
| §2.2.1 | Typed artifact schemas | new (position fixed) | open | artifacts are untyped dicts: `pipeline.py:177`, collectors' `collect()` |
| §2.2.2 | Rule package with decorator registration and metadata | lost-plan | open | `detectors/rules.py` (1,211 lines), `detectors/engine.py:30` |
| §2.2.3 | Structured `RemediationTarget` on `Finding` | new (position fixed) | open | `detectors/finding.py:33-61` |
| §2.2.4 | Dir-fd-relative safe-I/O module | new (position fixed) | partial (built for F-04 in 2.3.0; not consolidated) | `utils/safe_path.py`, `utils/safe_io.py` |
| §2.2.5 | Hard `auto_remediation_blocked` reasons | new (position fixed) | done 2.3.0 | `b7e06c4`; `detectors/finding.py:15-24,64` |
| §2.2.6 | Package-manager abstraction | new (position fixed) | open | `collectors/packages.py` (dpkg only) |
| §2.2.7 | /proc-based socket ownership | new (position fixed) | open (F-06 deferred item) | `collectors/network.py` |
| §2.2.8 | Data-file allowlists | new (position fixed) | open | `utils/validators.py:16-…`, `detectors/rules.py:25-40` |
| §2.2.9 | Schema versioning policy: a minor bump only adds fields; only a major may remove or rename them | lost-plan | policy; implemented by ARCH-SV | `formatters/json_formatter.py:10-11` |
| §2.2.10 | Measured decision on parallel collection | lost-plan | open; timing data now collected | `pipeline.py:181-206` |
| §2.2.11 | Optional `ubuntils[tui]` extra | new (announced in 2.3.0) | open | `cli.py:21` imports the TUI unconditionally |
| §3 | The 2.3.0 bridge release record | lost-plan | done 2.3.0 | `2304232`, `3a02911` |
| ARCH-SV | Schema/format version fields (`schema_version "3.0"`, Wazuh `"3"`, bundle `format_version: 1`, `analyze` refuses newer bundle formats, `collector_durations_s`) | lost-plan | done v3-dev | `1648f28`; `formatters/json_formatter.py:11`, `integrations/wazuh.py:29`, `bundle/manifest.py:10`; `tests/test_schema_versions.py` |

## 4. Maintainer findings (N-)

| ID | Meaning | Source | Status | Evidence (fix · test) | Story |
|---|---|---|---|---|---|
| N-01 | A detection-stage failure must never read as a clean host | lost-plan | done 2.3.0 | `pipeline.py:218-227`, `cli.py:374-379` · `test_N01_*` (5) | E13-S7 |
| N-02 | — | — | **reserved: unrecovered, do not reuse** | not in any commit, test, comment or CHANGELOG (searched 2026-11-10) | — |
| N-03 | Docs drifted from code (Ubuntu 20.04 claimed) | lost-plan | done 2.3.0 | `ba1fb91` · `test_N03_ubuntu_20_04_is_not_claimed` | E11-S2 |
| N-04 | — | — | **reserved: unrecovered, do not reuse** | as N-02 | — |
| N-05 | CI tests against the hash-pinned lock users install | lost-plan | done 2.3.0 | `87492d7`; `ci.yml` "Install dependencies (hash-pinned)" · `test_N05_*` (2) | E13-S1 |
| N-06 | Unsafe or stale advice in docs (rule-count badge, `cp` rollback) | lost-plan | done 2.3.0 | `ba1fb91` · `test_N06_*` (3) | E11-S2 |
| N-07 | — | — | **reserved: unrecovered, do not reuse** | as N-02 | — |
| N-08 | Install-trust check covers loaded modules, package files and `.pth` files | lost-plan | done v3-dev | `e2b7229`; `cli.py:129-208` · `test_N08_*` (4) | E13-S8 |
| N-09 | A user file read only up to the 64 MiB ceiling marks its collector degraded | lost-plan | done v3-dev | `46d9573`; `collectors/source.py:19-21` · `test_N09_*` | E13-S7 |
| N-10 | Least-privilege release workflow plus published SHA256SUMS | lost-plan | done 2.3.0 | `7274fc5`; `release.yml` `permissions: {}` · `test_N10_*` | E13-S1 |
| N-11 | — | — | **reserved: unrecovered, do not reuse** | as N-02 | — |
| N-12 | Lab script skips what the host cannot support instead of aborting | lost-plan | done 2.3.0 | `1319b5a` · `tests/test_lab_script.py:64` | E11-S3 |
| N-13 | — | — | **reserved: unrecovered, do not reuse** | as N-02 | — |
| N-14 | Baselines cannot be keyed on attacker-chosen text | lost-plan | done 2.3.0 | `utils/baseline.py` · `test_N14_*` (7) | E3-S2 |
| N-15 | `--remediate --confirm` cannot lock out a host's only sudo user | lost-plan | done 2.3.0 | `b7e06c4` · `test_N15_*` (6) | E1-S3 |
| N-16 | *next free* | — | — | — | — |

## 5. Other lost-plan IDs found in the code

| ID | Meaning | Status | Evidence | Note |
|---|---|---|---|---|
| R0-5 | 2.3.0 bridge item: deprecation notices for everything 3.0 changes (Python 3.9, TUI extra) | done 2.3.0 | `cli.py:396-420`; `tests/test_bridge_2_3.py:227` (`test_R05_*`, 4 tests) | **Collides with review R-05** in test names. R0-1…R0-4 were presumably the other bridge items and are reserved, unrecovered. Do not rename the tests (rule 1); new review tests use the `review_` prefix. |

## 6. 2026-11 external security review (F-)

All fourteen were verified on `v3-dev` by reading the fix and running the named
tests (663 passed, 1 skipped, 2026-11-10).

| ID | Finding (short) | Status | Fix | Tests | Story |
|---|---|---|---|---|---|
| F-01 | Printed `cp` rollback followed a destination symlink | done 2.3.0 | `remediators/rollback.py:83`, `cli.py:631-643` | `test_F01_*` (7) | E1-S2 |
| F-02 | Pre-created output files reused; predictable bundle names | done 2.3.0 | `utils/safe_io.py:21-22`, `cli.py:39,328-334` | `test_F02_*` (7) | E13-S5 |
| F-03 | Forgeable login line lifted ambiguous keys over the gate | done 2.3.0 | `detectors/rules.py:337-347`, `timeline/correlator.py` | `test_F03_*` (8) | E1-S3 |
| F-04 | `O_NOFOLLOW` guarded only the last path component | done 2.3.0 | `utils/safe_path.py:31` | `test_F04_*` (3) | E1-S2, §2.2.4 |
| F-05 | Files over 1 MiB skipped but honoured by sshd/bash | done 2.3.0 | `collectors/source.py:19,82,142`, `rules.py:1173` | `test_F05_*` (5) | E13-S7 |
| F-06 | `ss` PID parse steerable by process name | done 2.3.0; **deferred part open** (inode→PID map) | `collectors/network.py:5-9,73-85` | `test_F06_*` (5) | §2.2.7 |
| F-07 | Root re-exec of a user-writable install | done 2.3.0 (extended by N-08) | `cli.py:179-255` | `test_F07_*` (5) | E13-S8 |
| F-08 | Unlisted or recorded-absent bundle files passed integrity | done 2.3.0 | `bundle/reader.py:83,157` | `test_F08_*` (3) | E5-S5 |
| F-09 | Unbounded Wazuh lines | done 2.3.0 | `integrations/wazuh.py:20-22` | `test_F09_*` (5) | E7-S2 |
| F-10 | Unbounded bundle extraction | done 2.3.0 | `bundle/reader.py:17` | `test_F10_*` (3) | E5-S6 |
| F-11 | Supply chain (hash lock, SHA-pinned Actions, pip-audit, Dependabot) | done 2.3.0 | `requirements.lock`, `ci.yml`, `.github/dependabot.yml` | `test_F11_*` (3) | E13-S1 |
| F-12 | Substring custom rules capped at 4,096 chars | done 2.3.0 | `detectors/custom_rules.py:29` | `test_F12_*` (2) | E10-S3 |
| F-13 | Confirm modal parsed markup | done 2.3.0 | `tui/confirm_modal.py:61` | `test_F13_*` (1) | — |
| F-14 | `/usr/bin/false` treated as a login shell; gaps undocumented | done 2.3.0; **documented gaps open** (`AuthorizedKeysCommand`, `pam_exec`, `~/.ssh/rc`, sshd `Include`) | `utils/validators.py:16` | `test_F14_*` (2) | E8-S4, E8-S10 |

## 7. 2.3.0 practitioner review

The review cites commit `3b71b86` for 2.3.0. It is the `v2.3.0` tag (the merge of
PR #32 on `main`); the first version of this registry was written from a stale
clone that did not have it. Verdicts below are against `v3-dev`.

### Adoption blockers (R-)

| ID | Meaning | Verdict | Evidence | Story |
|---|---|---|---|---|
| R-01 | Install needs pip plus 5 PyPI deps on the suspect host | Confirmed | `pyproject.toml` dependencies (5 direct; 15 runtime packages in `requirements.lock`) | E2-S1, E2-S2 |
| R-02 | `collect` captures ~20 fixed files and 10 commands | Confirmed (21 files, 10 commands) | `cli.py:47-85`; limits admitted in `cli.py:517-521` | E5-S1, E5-S2 |
| R-03 | No collector or rule for 14 persistence locations | Confirmed (no reference to any of them in `ubuntils/`) | `grep` of `ubuntils/` | E8-S2…E8-S4, E8-S8…E8-S11 |
| R-04 | Command heuristics partial and per-rule; no reverse-shell patterns | Confirmed | `detectors/rules.py:664-665`; cron rules `:86-145` use neither | E8-S1 |
| R-05 | Process collector shallow | Confirmed | `collectors/processes.py:28-34` | E12-S1, E12-S2 |
| R-06 | Timeline lacks auth.log, rotated logs, wtmp/btmp/lastlog, history; no offline journal | Partly: the log list is confirmed; bundles do replay 7 days of captured journal, so "no journal offline" holds for `--root` only | `timeline/builder.py:48-61,132`; `cli.py:79` | E12-S3, E12-S4, E5-S3 |
| R-07 | 11-port list → MEDIUM; FP control validated on one VM, one container | Partly: port list confirmed; validation was a 26.04 arm64 VM (2.2.0), a 24.04 KVM guest and `ubuntu:24.04` containers (2.3.0), still no corpus | `detectors/rules.py:38-40`; CHANGELOG 2.2.0/2.3.0 | E3-S4, E3-S5, E3-S6 |
| R-08 | Writes to the host by default | Confirmed, and v3-dev adds one more write (`/var/lib/ubuntils/preserve`, only under `--remediate --confirm`) | `pipeline.py:171,279`; `bundle/writer.py:61`; `remediators/base.py:25`; `remediators/preserve.py:38` | E7-S1, E5-S4, E1-S6, E13-S5 |
| R-09 | Bundle integrity is unkeyed SHA-256 | Confirmed (and documented as such) | `SECURITY.md` "Bundles are untrusted input" | E5-S5, E13-S1 |
| R-10 | No schema version, empty `host_id`, no ATT&CK IDs | Changed on v3-dev: schema version done (ARCH-SV), ATT&CK done (E4-S1); `host_id` still empty; no frozen schema | `1648f28`, `b9b9529`; `bundle/writer.py:105` | E4-S4, E4-S6, E13-S3 |

### Missed intrusions (C1–C9, review namespace)

| ID | Case | Verdict | Why it is missed (evidence) | Story | Target |
|---|---|---|---|---|---|
| C1 | Key added to an `authorized_keys` older than 7 days | Confirmed | `detectors/rules.py:297-302` skips non-recent files before options are read | E8-S4 | 2.4.0 |
| C2 | `/dev/shm` implant with an ordinary name, idle or listening | Confirmed | name gate `rules.py:535`; established-only `rules.py:577-579` | E8-S7 | 2.4.0 |
| C3 | Root `/etc/cron.d` `/dev/tcp` reverse shell | Confirmed | `rules.py:94-95` skips root-owned; `rules.py:120` checks temp paths only | E8-S1, E8-S2 | 2.4.0 |
| C4 | Tidy root-owned unit, `ExecStart=/usr/local/sbin/updater` | Confirmed | `rules.py:199-209` (4 triggers, none match) | E8-S3 | 3.0.0-beta.1 |
| C5 | `www-data NOPASSWD: ALL` in `sudoers.d` | Confirmed | `rules.py:360-361` excludes system UIDs | E8-S6 | 2.4.0 |
| C6 | Service account given a login shell, or added to sudo/docker/lxd | Confirmed | only `rules.py:608` (UID 0) and `:636` (empty password) judge accounts | E8-S5 | 3.0.0-beta.1 |
| C7 | Setuid bash in `/var/lib` or `/root`; file capabilities | Confirmed | `collectors/packages.py:16-18`; no capability read anywhere | E8-S8 | 2.4.0 (paths) / 3.0.0-beta.1 (capabilities) |
| C8 | `bash <(curl …)` in `.bashrc`, older than 48 h | Partly: the regex miss is real (`rules.py:664`); the age is not the reason, since content signals fire at any age since 2.2.0 (`rules.py:697-701`) | E8-S1, E8-S14 | 2.4.0 |
| C9 | `LD_PRELOAD` via systemd `Environment=`; `LD_AUDIT` | Confirmed | `rules.py:150-151` reads `env_definitions` only; `collectors/systemd.py:33` ignores `Environment=` | E8-S9 | 3.0.0-beta.1 |

### Rule-level notes (RL-)

Numbered here in the review's rule order. RL-14 comes from the review's
LD_PRELOAD_INJECT row (PDF p. 8).

| ID | Note | Verdict | Evidence | Story |
|---|---|---|---|---|
| RL-01 | Cron: `anacrontab`, `at`, shared matcher | Confirmed | `collectors/cron.py:41-50` | E8-S2 |
| RL-02 | Rename `SUSPICIOUS_SYSTEMD_TIMER`; unowned + recency; `ExecStopPost`/`ExecCondition`; user units everywhere; `.timer`/`.socket`/`.path` bodies | Confirmed | `collectors/systemd.py:9-19,33` | E8-S3 |
| RL-03 | SSH: inventory every key; `environment=`/`permitopen=` signals | Confirmed | `rules.py:77,301` | E8-S4 |
| RL-04 | Users: recent accounts, privileged groups | Confirmed | `rules.py:608-661` | E8-S5 |
| RL-05 | Sudoers: system accounts; unowned `sudoers.d` | Confirmed | `rules.py:360-361` | E8-S6 |
| RL-06 | Process: by location, not name (venv noise) | Confirmed | `rules.py:535-537` | E8-S7 |
| RL-07 | Connections: listeners | Confirmed | `rules.py:577-579` | E8-S7 |
| RL-08 | Shell rc: `alias`/`trap`/`PROMPT_COMMAND` | Confirmed | `rules.py:668-682` | E8-S14 |
| RL-09 | `PACKAGE_TAMPERED` text must say `dpkg --verify` trusts on-host checksums | Confirmed | `rules.py:859-860` | E8-S15 |
| RL-10 | Immutable paths: widen the 14 | Confirmed | `collectors/packages.py:6-11` | E8-S13 |
| RL-11 | PAM: `pam_exec`, unowned modules | Confirmed | `rules.py:1032-1060` | E8-S10 |
| RL-12 | Kernel: `/proc/modules` vs `/sys/module` | Confirmed | `collectors/kernel.py:7,14` | E8-S12 |
| RL-13 | setuid: wider paths, capabilities | Confirmed | `collectors/packages.py:16-18` | E8-S8 |
| RL-14 | LD_PRELOAD: `LD_AUDIT`, `LD_LIBRARY_PATH`, `ld.so.conf.d`, unit `Environment=` | Confirmed | `rules.py:148-196` | E8-S9 |

### Quick wins (QW-)

| ID | Quick win | Verdict | Evidence | Story | Breaking? |
|---|---|---|---|---|---|
| QW-1 | Flag processes by exe location (tmp, deleted, memfd) | Confirmed open | `rules.py:535` | E8-S7 | no (new rule) |
| QW-2 | Report listeners | Confirmed open | `rules.py:577-579` | E8-S7 | no (more findings) |
| QW-3 | Inventory every SSH key at LOW | Confirmed open | `rules.py:301` | E8-S4, E3-S7 | no (new rule) |
| QW-4 | Evaluate all accounts in `SUDOERS_NOPASSWD` | Confirmed open | `rules.py:360-361` | E8-S6 | no (more findings) |
| QW-5 | Shared curl/base64 patterns in the cron rules | Confirmed open | `rules.py:664-665` unused by cron | E8-S1 | no |
| QW-6 | `auth.log` in the timeline and `collect` | Confirmed open (it is on the `lsattr` list, `packages.py:10`) | `timeline/builder.py:48`, `cli.py:47-71` | E12-S3, E5-S3 | no |
| QW-7 | SHA-256 of every flagged file | Confirmed open | `detectors/finding.py:33-61` | E4-S3 | no (new field) |
| QW-8 | Stable finding IDs | Confirmed open | as QW-7 | E4-S3 | no (new field) |
| QW-9 | "Findings present" exit code | Confirmed open (codes 1 and 3 only) | `cli.py:31-34` | E4-S5 | no if opt-in |
| QW-10 | More custom-rule sources | Confirmed open | `detectors/custom_rules.py:21` | E10-S3 | no |
| QW-11 | Journal window flag on `collect` | Confirmed open (fixed 7 days) | `cli.py:79` | E5-S3 | no |
| QW-12 | Stage bundles under `/var/lib/ubuntils` | Partly: the finished bundle already defaults there (F-02, `cli.py:39`); staging is still `tempfile.mkdtemp` | `bundle/writer.py:61` | E5-S4 | no |
| QW-13 | Rename `SUSPICIOUS_SYSTEMD_TIMER` | Confirmed open | 18 references across 8 files | E8-S3, E7-S2 | **yes** in 3.0; alias in 2.4 |

## 8. Historical namespaces (not plan IDs; listed so nobody reuses them)

| Namespace | IDs | Source | Where |
|---|---|---|---|
| Audit 2026-09-23 | C1–C3, H1–H10, M1–M15, L1–L10 | maintainer audit | `tests/test_audit_regressions.py` (`test_C1_…`) |
| Audit 2026-10 (pre-conference) | S1–S3, T1, M1–M5, D1–D6, W1–W2 | maintainer audit | `tests/test_audit_2026_10.py` |
| Audit 2026-10-26 (live 24.04) | D-, M-, T1–T4, W- | maintainer audit | `tests/test_audit_2026_10_26.py` |
| Security review 2026-11 | F-01–F-14 | external | §6 above |

When a document needs to cite one of these unambiguously, prefix the date:
`A0923-C1`, `A10-M3`, `A1026-T2`. Review cases are cited as `C1`…`C9` only
inside review tables, and as `review_c1` in code.
