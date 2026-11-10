# v3 delivery progress

**Every session starts here.** Read this file, then `v3.0.0-plan.md`,
`id-registry.md` and `execution-guidance.md`, and resume from "Next".

## Status

| | |
|---|---|
| Milestone | alpha.1 (preflight done locally, not merged: no CI) |
| Branch | `v3/alpha.1`, stacked on `v3/preflight` (both local only; Needs Asmit #1) |
| Last commit | see `git log -1 v3/preflight` |
| CI | **not running**: nothing can be pushed from the agent session yet (Needs Asmit #1) |
| Coverage | 94.76 % line (local, macOS, 2026-11-10; 704 passed, 1 skipped); `safe_path.py` 100 % / 100 % |
| Lab | last known 16/16 (RESULTS.md, `96f3c49`, 2026-10-23); no CI lab job has run yet |
| fp-suite | not run (needs CI) |
| PANIX | not run (needs CI) |

## Needs Asmit

1. **Pushing is blocked in the agent session.** `git push -u origin v3/preflight` was
   refused by Claude Code's auto-mode permission classifier ("out-of-place
   publication"). Without pushes there is no CI, so the lab, hostile-host, fp-suite,
   timings and PANIX jobs can't run, draft PRs can't be opened, and no milestone can
   meet the "CI fully green" merge condition. **Needed:** a permission rule allowing
   `git push origin v3/*`, `v3-dev` and `v3.1-dev` (never `main`), or push the branches
   yourself. *Meanwhile:* all work is committed on local branches and tested locally.
2. **`gh` can't authenticate.** `gh auth status`: "The token in keyring is invalid".
   Also, from inside the sandbox, `gh` (Go TLS) rejects the proxy certificate, while
   `curl` works. **Needed:** `gh auth refresh -h github.com`, plus a way to run `gh`
   for PR creation and CI log reads (a permission rule for `gh pr *` / `gh run *`).
   *Meanwhile:* CI state is read through the public REST API with `curl`
   (unauthenticated: 60 requests/hour, no job logs or artifacts). CI jobs therefore
   also report headline numbers as `::notice::` annotations, which that API can read.
3. **The review PDF is in local history.** `95c7593` (on `v3-dev`, unpushed) added
   `docs/reviews/2.3.0-practitioner-review.pdf`. The file is now untracked and
   git-ignored, but pushing `v3-dev` as-is would publish the PDF through history. I
   tried to amend `95c7593` (safe, since it was never pushed); the classifier refused it
   as a destructive git action. **Needed, before `v3-dev` is first pushed:** either
   allow that amend (then rebuild `v3/preflight` on top), or accept the PDF in history.
4. **Release check (preflight 1): what you need to do.** Findings:
   - PyPI has **1.5.0 and 2.3.0** (2.3.0 uploaded 2026-11-09 14:13 UTC). 2.0.0, 2.1.0
     and 2.2.0 never reached PyPI. 2.0/2.1 were never tagged; the `v2.2.0` Release run
     (2026-10-15, run 38813594573) failed at "Publish to PyPI" and was not re-run.
   - The `v2.3.0` Release run (42631187371) went: attempt 1, publish failed (most likely
     Trusted Publishing not yet configured; it worked 7 minutes later); attempt 2,
     publish succeeded and "Create GitHub Release" failed, because a `v2.3.0` Release had
     already been created by hand on 2026-11-06; attempts 3 and 4 failed re-uploading
     files PyPI already had.
   - Fix on `v3/preflight`: `skip-existing: true` on the publish step, and the release
     step attaches files to an existing Release instead of failing.
   - **Your steps:** (a) PyPI → ubuntils → Publishing: confirm a trusted publisher for
     `asmitdesai/ubuntils`, workflow `release.yml`, environment `pypi`. (b) GitHub →
     Settings → Environments: confirm `pypi` exists. (c) Decide whether 2.2.0 should be
     published. Its tag exists; re-running run 38813594573 would publish 2.2.0 **after**
     2.3.0, which pip handles correctly but looks odd. I recommend leaving it. (d) Don't
     create Releases by hand before the workflow runs; the workflow now tolerates it,
     but its notes would be lost.
5. `ubuntils-v3-execution-prompt.md` is not in the repo or under `~/Portfolio`,
   `~/Downloads`, `~/Desktop` or `~/Documents`. I used the Workstream 2–4 text from the
   planning prompt, saved as `docs/plans/execution-guidance.md`. Replace it if your
   file differs.

6. **Decision before 2.4.0: bundle `format_version`.** A bundle written by the v3 line
   reads as **tampered** (`mismatch`, exit 3) under 2.3.0 `analyze`, because 2.3.0
   drops the new `format_version` key and recomputes a different digest
   (`docs/plans/default-behaviour-diff.md`). Recommended: write no `format_version`
   for format 1 (absent already means 1 everywhere) and write it from format 2 on (a
   3.0 change), with a test that a new bundle verifies under the 2.3.0 reader. This
   changes part of ARCH-SV (`tests/test_schema_versions.py` expects the key), so I
   haven't done it. *Meanwhile:* nothing depends on it until the 2.4.0 release PR.

## Corrections to the brief

- `3b71b86` **exists**: it's the `v2.3.0` tag, the merge of PR #32. The planning clone
  was stale. The registry, plan and response now say so, instead of "doesn't exist".
- PyPI's latest release is 2.3.0, not 1.5.0 (see Needs Asmit #4).

## Next

1. When pushing works: push `v3/preflight`, read the CI and Measure runs, fill the
   `<BASELINE>`s they produce (lab, fp-suite per image, timings), review and commit
   fp-suite baselines, then merge preflight into `v3-dev` (reviewer agent first).
2. alpha.1 (plan §6.2) on `v3/alpha.1`, in the order of `execution-guidance.md`
   Workstream 2: C1–C9 tests → matcher → quick wins → small RL items.

## Log

| Date | ID | What | SHA |
|---|---|---|---|
| 2026-11-10 | WS1 | Plan, PRD, registry and review response | `95c7593` |
| 2026-11-10 | — | Merged `origin/main` (2.3.0 tag `3b71b86`, test fix `17769f2`) into the v3 line | `6869d97` |
| 2026-11-10 | — | Untracked the review PDF; plans public; `3b71b86` corrected | `0f444c1` |
| 2026-11-10 | D-1…D-15 | Lean scope, relative sizes, decisions recorded | `efe2b19` |
| 2026-11-10 | preflight 1 | Release workflow re-runnable (skip-existing; reuse Release) | `90f3c71` |
| 2026-11-10 | E3-S5, E13-S6 | Lab, hostile-host, fp-suite and timings gates (+ tests) | `dda18d3` |
| 2026-11-10 | E11-S1 | PANIX harness: per-technique runner VM, TEST-NET callbacks | `7a709e3` |
| 2026-11-10 | E13-S2 | CI on v3 branches; 26.04/Debian 12 containers; measure + PANIX workflows | `61e9ce8` |
| 2026-11-10 | E13-S4 | Fixture hosts; 2.3.0 vs v3 behaviour diff (bundle break found) | `b35d5dd` |
| 2026-11-10 | E13-S9 | `safe_path.py` 100 %/100 %; fd leak in `read_file_at` fixed | `49eaaf8` |
