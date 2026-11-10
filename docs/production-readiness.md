# Production readiness

What "production-ready" means for ubuntils: an offline, single-host tool that runs
as root on a machine that may be compromised, whose output a responder will cite.
It is ready when it can be trusted not to make the host worse, not to hide what it
couldn't see, and to behave the same way release after release.

Status: **done** (in place and tested), **partial**, **missing**. Milestones refer to
`plans/v3.0.0-plan.md` §6. Updated 2026-11-10 on `v3/alpha.1`.

| Area | Done | Partial | Missing |
|---|---|---|---|
| Supply chain and release integrity | 5 | 1 | 4 |
| Compatibility and support | 3 | 2 | 0 |
| Output contract | 5 | 2 | 1 |
| Safety on the evidence host | 3 | 1 | 2 |
| Performance and resource budgets | 0 | 2 | 1 |
| Reliability and error handling | 3 | 1 | 0 |
| Security process | 2 | 2 | 1 |
| Detection-quality evidence | 0 | 2 | 0 |
| Operability and docs | 2 | 2 | 2 |
| Project health | 1 | 2 | 1 |
| **Total** | **24** | **17** | **12** |

## Supply chain and release integrity

| Item | Status | Evidence | Target |
|---|---|---|---|
| Hash-pinned locks | done | `requirements.lock`, `requirements-dev.lock`; CI installs with `--require-hashes` (N-05) | — |
| SHA-pinned Actions | done | every `uses:` pinned; `test_F11_every_action_is_pinned_to_a_commit_sha` | — |
| `pip-audit` | done | CI `audit` job over both locks | — |
| Dependabot | done | `.github/dependabot.yml` (pip and Actions, weekly) | — |
| PyPI Trusted Publishing | done | `release.yml` `id-token: write`, environment `pypi`; re-runnable since preflight | — |
| `docs/releasing.md` checklist | partial | written; first used for 2.4.0 | alpha.1 / 2.4.0 |
| SBOM (CycloneDX) per release | missing | — | beta.2 (E13-S1) |
| Build provenance (GitHub attestations, SLSA build L3 on hosted runners) | missing | — | beta.2 |
| Signed release artifacts | missing | decision D-10: Sigstore keyless via the same attestations (no key to guard on a solo project; verifiable with `gh attestation verify` or `sigstore-python`) | beta.2 |
| Reproducible single-file build | missing | zipapp with fixed mtimes and sorted members, built twice in CI and compared | beta.2 |

## Compatibility and support policy

| Item | Status | Evidence | Target |
|---|---|---|---|
| Supported matrix | partial | README Compatibility: Ubuntu 22.04/24.04/26.04, amd64/arm64, Python 3.9+ (3.10+ in 3.0); Debian 12 tested in a container from alpha.1, not yet claimed | beta.2 (claim Debian 12, E9-S1) |
| CI matrix covers every row | partial | hosted runners 22.04/24.04 × amd64/arm64 × Python 3.9–3.13; 26.04 and Debian 12 in containers; no VM job for systemd/`/proc` paths beyond the `measure` workflow | beta.1 (VM job) |
| Semver scope | done | `docs/versioning.md` | — |
| Deprecation policy | done | `docs/versioning.md`; deprecation lines on stderr (R0-5, QW-13) | — |
| 2.x support window | done | six months of security fixes after 3.0.0 (`docs/versioning.md`) | — |

20.04 is not supported (system Python 3.8). It is a container-only row in CI, which
checks that the tool refuses cleanly rather than half-working.

## Output contract

| Item | Status | Evidence | Target |
|---|---|---|---|
| Versioned outputs | done | `schema_version` (report, Wazuh), `format_version` (bundle): ARCH-SV; policy in `docs/versioning.md` (D-12) | — |
| Exit-code table | done | README "Exit codes"; `--fail-on-findings` (QW-9) | — |
| Stable finding IDs | done | `finding_id` (QW-8), survives the QW-13 rename | — |
| ATT&CK IDs | done | `attack` on every finding (E4-S1) | — |
| `host_id` | done | salted hash of `machine-id` (E4-S4) | — |
| Golden outputs | partial | `tests/golden/*.json` for the clean and lab fixture hosts; no JSON Schema yet to validate them against | beta.2 (E4-S6) |
| JSON Schema checked in and enforced | missing | — | beta.2 |
| 3.x `analyze` reads 2.x bundles | partial | format-1 bundles verify (`tests/test_schema_versions.py`); **but a v3-written bundle fails integrity under 2.3.0** (see `plans/default-behaviour-diff.md`); decision pending | before 2.4.0 |

## Safety on the evidence host

| Item | Status | Evidence | Target |
|---|---|---|---|
| Documented write list, tested | done | `docs/writes.md`; `tests/test_writes.py` (no write during a scan; every write location listed) | — |
| Staging under `/var/lib/ubuntils` | done | QW-12; private dir, symlink refused, removed on Ctrl-C | — |
| Root-run writes symlink-free in every component | done | F-04, `utils/safe_path.py` at 100 % line and branch | — |
| Wazuh forwarding opt-in | partial | `--no-wazuh` exists; default flips to opt-in in 3.0 (E7-S1) | beta.2 |
| `--backup-dir` with a same-filesystem warning | missing | — | beta.2 (E1-S6) |
| Read-only mode proven in CI (read-only bind mount) | missing | in-process write spy exists; the mount test needs a privileged container | beta.2 |

## Performance and resource budgets

| Item | Status | Evidence | Target |
|---|---|---|---|
| Median scan time and peak RSS on a reference host | partial | `measure.yml` `timings` job records both; no run yet (pushing blocked) | alpha.1 (first run) |
| Budgets enforced in CI | partial | `tools/ci/timings.py --budget-s/--budget-rss-mb`; enabled once the baseline exists | alpha.2 |
| Bounded runtime on huge hosts; per-collector timeouts as degraded | missing | commands have timeouts; log reads are not bounded (progress.md, known gaps) | beta.1 (E12-S3, E13-S6) |

## Reliability and error handling

| Item | Status | Evidence | Target |
|---|---|---|---|
| Every collector fails closed | done | `tests/test_failure_injection.py` (11 collectors × 5 error types); fixed `PamCollector` failing open | — |
| No unhandled exception reaches the user | done | pipeline isolates collectors, detection (N-01), timeline, correlation | — |
| Ctrl-C leaves no partial bundle that verifies | done | `test_interrupted_collection_leaves_no_bundle_and_no_staging` | — |
| Error messages say the next step | partial | trust refusal, `--no-preserve`, `--fail-on-findings` do; collector degraded reasons are terse | rc.1 (troubleshooting page) |

## Security process

| Item | Status | Evidence | Target |
|---|---|---|---|
| `SECURITY.md` with a channel and response time | done | email + GitHub advisory; "within a few days" | — |
| Hostile-host harness | partial | exists; CI job written (`measure.yml`), not yet run | alpha.1 (first run) |
| GitHub private vulnerability reporting | partial | **repository setting the owner must turn on** | owner |
| Threat model kept current per collector | done | `SECURITY.md` "How ubuntils protects itself"; plan §2.4 rules for every new reader | — |
| Scheduled fuzzing | missing | `hypothesis` needs adding to the hash-pinned dev lock | alpha.2 (E13-S10) |

## Detection-quality evidence

| Item | Status | Evidence | Target |
|---|---|---|---|
| PANIX benchmark harness, results per release | partial | `tools/panix/`, `panix.yml`; no run yet | alpha.1 (first run), each release |
| Clean-host corpus, counts per image per release | partial | `tools/fp-suite` + `measure.yml` (4 container images); VMs and cloud images by the maintainer | beta.1 (E3-S6) |

## Operability and docs

| Item | Status | Evidence | Target |
|---|---|---|---|
| Changelog discipline | done | every entry cites its ID | — |
| What a clean result does not mean, stated up front | done | README "Not covered" + `SECURITY.md` "necessary, not sufficient" | — |
| README first screen; the rest in `docs/` | partial | first screen rewritten in alpha.1; full move in rc.1 | rc.1 |
| Troubleshooting page | partial | `docs/debugging-common-issues.md` | rc.1 |
| Rule reference generated from metadata | missing | — | rc.1 (E10-S4) |
| `--help` / docs parity check in CI | missing | — | rc.1 (E11-S5) |

## Project health (one maintainer)

| Item | Status | Evidence | Target |
|---|---|---|---|
| Issue templates | done | `.github/ISSUE_TEMPLATE/` | — |
| `CONTRIBUTING.md` with a first-rule path | partial | rule and remediator sections; no walkthrough yet | rc.1 (E10-S4) |
| PR template, `CODEOWNERS` | partial | neither exists yet | alpha.2 (E13-S11) |
| `MAINTAINERS.md` (solo maintainer, realistic response times) | missing | — | alpha.2 |

## Top risks to calling 3.0.0 production-ready

1. **Nothing has run on a real Ubuntu host since 2.3.0.** All alpha.1 work is tested
   locally on fixtures; the lab, harness, fp-suite, timings and PANIX jobs are written but
   unrun, because pushing from the agent session is blocked.
2. **The bundle compatibility break** (v3 bundle → 2.3.0 `analyze` says tampered) must be
   decided before 2.4.0 ships.
3. **Offline parity (R-02)** is the largest piece of 3.0 and the acquire-first story
   depends on it; today `analyze BUNDLE` misses most lab findings.
4. **Unbounded log reads** on very large hosts.
5. **No independent detection number yet**: until PANIX runs, every coverage claim rests
   on tests written around ubuntils's own rules.
