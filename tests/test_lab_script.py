"""Keep tools/lab/seed-lab.sh honest about which rules it exercises."""
import os
import re

LAB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "tools", "lab", "seed-lab.sh")
# Deliberately not planted: one needs live outbound traffic, the other is a
# real passwordless login and is opt-in (--with-empty-password).
NOT_PLANTED_BY_DEFAULT = {"PROCESS_SUSPICIOUS_CONNECTION", "USER_EMPTY_PASSWORD"}


def _built_in_rule_ids():
    rules_py = os.path.join(os.path.dirname(LAB), "..", "..", "ubuntils", "detectors", "rules.py")
    return set(re.findall(r'rule_id="([A-Z_]+)"', open(rules_py).read()))


def _lab_rule_ids():
    return set(re.findall(r"^\s*say ([A-Z_]+) ", open(LAB).read(), re.MULTILINE))


def test_lab_only_names_real_rules():
    assert _lab_rule_ids() <= _built_in_rule_ids()


def test_lab_covers_every_rule_it_does_not_explicitly_skip():
    missing = _built_in_rule_ids() - _lab_rule_ids() - NOT_PLANTED_BY_DEFAULT
    assert missing == set()


def test_lab_artifacts_never_run():
    script = open(LAB).read()
    assert 'NEVER="0 0 31 2 *"' in script               # cron: 31 February
    assert "systemctl enable" not in script and "systemctl start" not in script
    assert re.search(r"curl[^\n]*http://\$MARK\.invalid", script)  # reserved TLD only
