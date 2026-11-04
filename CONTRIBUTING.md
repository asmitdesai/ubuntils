# Contributing to ubuntils

Thanks for your interest. The most valuable contributions right now are new
detection rules, additional collectors, and real-world validation results.

## Development setup

```bash
git clone https://github.com/asmitdesai/ubuntils.git
cd ubuntils
python -m venv .venv && source .venv/bin/activate
pip install --require-hashes -r requirements-dev.lock   # Python 3.10+; or: pip install -e '.[dev]'
pip install --no-deps --no-build-isolation -e .
pytest
```

Tests run on any platform (collectors are tested against mocked artifacts), so
you do not need an Ubuntu host to develop. The suite enforces a 90% coverage
floor via `pyproject.toml`.

## Adding a detection rule

1. Add a `rule_<name>(artifacts: dict) -> List[Finding]` function in
   `ubuntils/detectors/rules.py`. Rules are pure: they take collected artifacts
   and return findings, with no I/O of their own where avoidable.
2. Register it in `ALL_RULES` in `ubuntils/detectors/engine.py`.
3. Add tests in `tests/test_detection_rules.py` covering both a positive case
   (known-bad fixture) and a clean case (no false positive). Update the
   `test_engine_all_rules_registered` count.
4. Document it in the "What it detects" table and the "Why each rule exists"
   section of `README.md`, including an example finding.
5. Prefer high-signal rules. A rule that fires on a clean, freshly provisioned
   host is worse than no rule. If a rule is inherently noisy, make it suppressible
   via the allowlist and say so.

## Adding a remediator

Remediators follow the backup → validate → apply → verify pattern in
`ubuntils/remediators/base.py`. They run as root on a host the attacker may
control, so they must:

- Do every read and write through `BaseRemediator`'s helpers
  (`_read_lines`, `_write_lines`, `_create_backup`), which reach the file
  relative to a directory opened from `/` without following any symlink, and
  check the directory is the one the finding was made on. Never `open()` a
  path directly.
- Let the base class create the backup and its sidecar; it sets
  `rollback_command` to `ubuntils rollback <backup>`. Never suggest
  `cp backup original` anywhere.
- Make the minimum change (remove/comment a specific entry, never truncate a
  file), and never remove all sudo access.
- Set `auto_remediation_blocked` on any finding a human has to judge, so
  `--remediate --confirm` can't act on it whatever its confidence.

## Pull requests

- Run `pytest` and ensure coverage stays above the floor.
- Keep commit messages descriptive of intent, not just the diff.
- Open an issue before starting a large change to avoid duplicate work.

## Validation contributions

If you can run ubuntils against a host with a known, deliberately planted
persistence mechanism (in a throwaway VM), detection/false-positive results are
extremely welcome — open an issue with the technique, the Ubuntu version, and
whether ubuntils caught it.
