# v3 execution guidance (Workstreams 2–4)

The delivery prompt refers to `ubuntils-v3-execution-prompt.md`, which isn't in the
repository. This file records the Workstream 2–4 instructions from that prompt, as
given in the planning session of 2026-11-10, so that any session can work from it.
Workstream 1 (planning) was done in `95c7593`. Where this file and
`v3.0.0-plan.md` differ, the plan's later decisions win (lean scope, no calendar).

## Principles

- No network calls and no telemetry.
- Never execute host data.
- Everything read from the host is attacker-controlled. Every new reader is bounded,
  size-capped and non-blocking on user files, and reports degraded state into
  `scan_metadata` on any failure. "Could not look" never looks like "clean".
- Remediation stays opt-in, backed up and minimal. No new remediation paths.
- No new runtime dependencies. Dev and test dependencies are hash-pinned.
- Every behaviour change gets a test. Every detection gap gets a failing test before its fix.
- No invented numbers: unknown baselines are written `<BASELINE: how to measure>`.
- Commits: small, one logical change, subject cites the ID (`R-03: …`, `E8-S1: …`).

## Workstream 2 — execute 3.0.0-alpha.1

In this order; close each with tests and a CHANGELOG (Unreleased) entry citing its ID.

1. **C1–C9 regression tests** on the fixture/artifact-source layer, never a live host.
   Each must first fail for the reason the reviewer gave. Name them after the case
   (`test_review_c3_root_crond_dev_tcp`).
2. **Shared suspicious-command matcher** in one module, used by every cron source
   (user, root, `/etc/cron.d`, `anacrontab`), systemd `Exec*` lines, shell init files
   and `at` jobs. Covers download-and-execute (pipes to sh/bash/python/perl, process
   substitution, download→chmod→exec), reverse shells (`/dev/tcp`, `/dev/udp`, `socat`,
   `mkfifo`+`nc`, `nc -e`, python/perl socket one-liners) and encoded payloads
   (`base64 -d |`, `eval "$(...)"`). Returns structured weighted signals into the
   explainable score. Bounded input, with a test proving no catastrophic backtracking.
   Content signals fire at any file age; recency only raises confidence. Closes C3 and C8.
3. **Non-breaking quick wins**, roughly in this order, each closing its C-case:
   QW-1 + QW-2 (C2; a python3 venv under `/opt` or `/home` must not fire); QW-3 (C1);
   QW-4 (C5); QW-6, QW-7, QW-10, QW-11, QW-12; QW-9 behind an opt-in
   `--fail-on-findings[=SEVERITY]`; QW-13 with the old ID kept as a deprecated alias
   and the Wazuh decoder/rules updated; QW-8 as an added field only.
4. **`PACKAGE_TAMPERED` text fix** and the other small, non-breaking RL items.
5. **C4, C6, C7, C9 stay `xfail`** (reason names their milestone) unless trivial.

After each group: full suite, hostile-host harness, lab script. The lab stays 16/16.

## Workstream 3 — coverage that catches regressions

1. Measure honestly: `--cov-branch`; line and branch per package; the 20 least-covered
   functions, marking the security-critical ones.
2. Ratchet, never lower: CI floor = current measured value rounded down, plus a branch
   gate; raise each milestone. GA targets: line ≥ 95 %, branch ≥ 90 %; 100 % line and
   branch, enforced per module, on safe I/O, path validators, bundle writer/verifier,
   remediators and rollback, sudo re-exec and install trust, `ss`/`/proc` parsers, and
   the command matcher.
3. `hypothesis` property tests for every host-text parser (passwd/shadow/group,
   sudoers incl. aliases/continuations/includes, `authorized_keys` options, crontab
   lines, systemd units and drop-ins, `ss` output, the matcher): never raises, never
   reads past the cap, malformed → degraded, not clean.
4. Mutation testing (`mutmut` or `cosmic-ray`) on the rules and the matcher; kill
   survivors in the C1–C9 rules; a scheduled (not per-PR) CI job publishes the score.
5. Golden-output tests: the JSON report frozen per lab fixture host.
6. Offline-parity test: `scan` vs `analyze <bundle>` per fixture host, live-only findings
   listed explicitly; `xfail` until alpha.2.
7. No test theatre: no assert-free tests, no unjustified `# pragma: no cover`, no
   mocking away the safety checks under test.

## Workstream 4 — production readiness

Write `docs/production-readiness.md`: what production-ready means for an offline,
single-host, root-run DFIR tool, as a checklist with status (done / partial / missing),
evidence and target milestone. Cover at least: supply chain and release integrity
(locks, SHA-pinned Actions, pip-audit, Dependabot, SBOM, provenance, signing,
reproducible single file, Trusted Publishing, `docs/releasing.md`); compatibility and
support (Ubuntu 20.04/22.04/24.04/26.04 × amd64/arm64, minimum Python, Debian 12; a CI
matrix that tests every row; semver scope; deprecation policy; 2.x support window);
the output contract (versioned JSON Schema, golden validation, 2.x bundle compatibility,
exit-code table, stable finding IDs, ATT&CK, `host_id`); safety on the evidence host (a
documented write list, Wazuh opt-in, `--backup-dir`, staging under `/var/lib/ubuntils`, a
tested read-only mode); performance budgets; reliability (fail closed into degraded
state, failure injection, actionable errors, Ctrl-C leaves no partial bundle that
verifies); security process (SECURITY.md, private vulnerability reporting, threat model,
hostile-host harness in CI, scheduled fuzzing); detection-quality evidence
(`tools/panix/`, `tools/clean-corpus/`); operability and docs (README first screen,
`docs/`, generated rule reference, troubleshooting, help parity, changelog discipline);
project health (CONTRIBUTING first-rule path, issue/PR templates, CODEOWNERS,
`MAINTAINERS.md`).

Implement in alpha.1: the readiness doc; Dependabot (exists); the CI OS matrix
(containers); branch coverage plus per-module floors; the exit-code table;
`docs/releasing.md`; the versioning and deprecation policy; the "what ubuntils writes"
list with a test; the collector failure-injection test. Schedule the rest in the plan.
