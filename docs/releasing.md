# Releasing ubuntils

A checklist for the maintainer (E13-S12). Nothing here is automated away: the
release workflow publishes, but a person decides.

## Before tagging

- [ ] On a release branch (`release/X.Y.Z`) cut from the branch being released;
      `main` is updated only through the release PR.
- [ ] `ubuntils/__init__.py` `__version__` is `X.Y.Z`; the classifier in
      `pyproject.toml` says Beta for pre-releases, Production/Stable for GA.
- [ ] CHANGELOG: the "Unreleased" section is renamed `## X.Y.Z — YYYY-MM-DD`, every
      entry cites its ID, and anything breaking is under "Changed" with a migration note.
- [ ] CI is green on the release PR: tests on every matrix row, containers,
      dependency audit, coverage floors.
- [ ] Measure workflow on the release PR: lab 100 % of planted artifacts, hostile-host
      all PASS/SEEN, fp-suite no HIGH and no unreviewed finding on any image.
- [ ] For a minor or major: a PANIX run (`panix.yml`, dispatched) and its matrix
      saved to `docs/results/panix-X.Y.Z.md`.
- [ ] `tools/release/behaviour_diff.py` against the previous tag: every change in
      the report is either additive or in the CHANGELOG as breaking; a bundle from
      the new version verifies under the old one (or the break is announced).
- [ ] `requirements.lock` and `requirements-dev.lock` regenerated if dependencies
      changed (`make lock`, Python 3.10), and `pip-audit` is clean.
- [ ] README badges and counts (rules, tests) match the code (`test_N06_*`).

## Tag and publish

```bash
git switch main && git pull --ff-only     # after the release PR is merged
git tag -s vX.Y.Z -m "ubuntils X.Y.Z"     # or -a if you don't sign tags
git push origin vX.Y.Z
```

The `Release` workflow builds the sdist and wheel, checks the tag matches
`__version__`, publishes to PyPI with Trusted Publishing (environment `pypi`), and
creates or updates the GitHub Release with the files and `SHA256SUMS`. Re-running a
release is safe: files PyPI already has are skipped, and an existing Release is
updated, not duplicated.

Don't create the GitHub Release by hand first. If you did, the workflow attaches the
files to it, but its generated notes are lost.

## After

- [ ] `pip install --require-hashes -r requirements.lock && pip install --no-deps ubuntils==X.Y.Z`
      in a clean venv; `ubuntils version`.
- [ ] Verify the published `SHA256SUMS` against the downloaded files.
- [ ] Update `docs/reviews/2.3.0-response.md`'s target column if a milestone shipped.
- [ ] Announce (see the PRD's launch section) only once the above hold.

## One-time settings (repository owner)

- PyPI → ubuntils → Publishing: a trusted publisher for `asmitdesai/ubuntils`,
  workflow `release.yml`, environment `pypi`.
- GitHub → Settings → Environments: `pypi` exists (protection rules optional).
- GitHub → Settings → Code security: private vulnerability reporting on (SECURITY.md).
