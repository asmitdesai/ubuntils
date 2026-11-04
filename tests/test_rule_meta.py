"""Rule metadata: every built-in rule has a category and ATT&CK mapping (E4-S1)."""
import json
import os
import re

from ubuntils.detectors.engine import DetectionEngine
from ubuntils.detectors.finding import Finding, Severity
from ubuntils.detectors.rule_meta import CATEGORIES, HYGIENE, PERSISTENCE, annotate, rule_meta
from ubuntils.formatters.json_formatter import JSONFormatter
from ubuntils.integrations.wazuh import finding_line

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ATTACK_ID = re.compile(r"T\d{4}(\.\d{3})?")


def _built_in_rule_ids():
    rules_py = os.path.join(_REPO, "ubuntils", "detectors", "rules.py")
    return set(re.findall(r'rule_id="([A-Z_]+)"', open(rules_py).read()))


def test_every_built_in_rule_has_metadata_and_nothing_else_does():
    assert set(rule_meta()) == _built_in_rule_ids()


def test_categories_and_attack_ids_are_well_formed():
    for rule_id, meta in rule_meta().items():
        assert meta["category"] in CATEGORIES, rule_id
        assert meta["attack"] or meta.get("reason"), f"{rule_id}: no ATT&CK ID and no reason"
        for technique in meta["attack"]:
            assert _ATTACK_ID.fullmatch(technique), f"{rule_id}: {technique!r}"


def test_hygiene_is_the_integrity_and_inventory_rules():
    hygiene = {r for r, m in rule_meta().items() if m["category"] == HYGIENE}
    assert hygiene == {"PACKAGE_TAMPERED", "IMMUTABLE_FLAG_SET",
                       "KERNEL_MODULE_SUSPICIOUS", "SETUID_INVENTORY"}


def _finding(rule_id):
    return Finding(rule_id=rule_id, severity=Severity.HIGH, title="t", description="d",
                   artifact_path="/x", raw_value="x", remediation_available=False)


def test_engine_annotates_built_in_and_custom_findings():
    artifacts = {"users": [{"username": "ghost", "uid": 0, "shell": "/bin/bash",
                            "is_login_shell": True}]}
    [f] = DetectionEngine().run(artifacts)
    assert (f.rule_id, f.category, f.attack) == ("USER_UID_ZERO", PERSISTENCE, ["T1136.001"])
    custom = _finding("CUSTOM_MINER")
    annotate(custom)
    assert (custom.category, custom.attack) == (PERSISTENCE, [])


def test_report_and_wazuh_line_carry_category_and_attack():
    f = _finding("PACKAGE_TAMPERED")
    annotate(f)
    d = JSONFormatter()._finding(f)
    assert (d["category"], d["attack"]) == (HYGIENE, ["T1554"])
    line = json.loads(finding_line(f, "h"))
    assert (line["category"], line["attack"]) == (HYGIENE, ["T1554"])


def test_metadata_is_shipped_as_package_data():
    pyproject = open(os.path.join(_REPO, "pyproject.toml")).read()
    assert 'ubuntils = ["data/*.yaml"]' in pyproject
