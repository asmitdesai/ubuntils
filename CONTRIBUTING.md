# Contributing to ubuntils

Thanks for your interest. The most valuable contributions right now are new
detection rules, additional collectors, and real-world validation results.

## Development setup

```bash
git clone https://github.com/asmitdesai/ubuntils.git
cd ubuntils
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Tests run on any platform (collectors are tested against mocked artifacts), so
you do not need an Ubuntu host to develop. The suite enforces an 80% coverage
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
`ubuntils/remediators/base.py`. They must:

- Refuse to act on a symlinked artifact path.
- Create a timestamped backup before any change and set `rollback_command`.
- Make the minimum change (remove/comment a specific entry, never truncate a
  file), and never remove all sudo access.

## Pull requests

- Run `pytest` and ensure coverage stays above the floor.
- Keep commit messages descriptive of intent, not just the diff.
- Open an issue before starting a large change to avoid duplicate work.

## Validation contributions

If you can run ubuntils against a host with a known, deliberately planted
persistence mechanism (in a throwaway VM), detection/false-positive results are
extremely welcome — open an issue with the technique, the Ubuntu version, and
whether ubuntils caught it.
