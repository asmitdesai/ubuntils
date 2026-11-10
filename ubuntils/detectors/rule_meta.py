"""Per-rule metadata (category, ATT&CK) from ubuntils/data/rule_meta.yaml.

Kept as data, not code, so grouping and ATT&CK mapping don't depend on how the
rules are organised, and so the mapping can be reviewed on its own. Read with importlib.resources, which also works when
ubuntils runs from a zip file.
"""
from functools import lru_cache
from importlib import resources

import yaml

PERSISTENCE = "persistence"
HYGIENE = "hygiene"
# Inventory: every instance of something worth knowing about (each SSH key),
# reported so a responder sees the whole set and can baseline the known ones.
# Not counted as noise in clean-host results (D-15).
INVENTORY = "inventory"
CATEGORIES = (PERSISTENCE, HYGIENE, INVENTORY)
# Custom (--rules) findings: written by the responder to catch something
# specific, so treated as likely persistence.
CUSTOM_RULE_META = {"category": PERSISTENCE, "attack": []}


@lru_cache(maxsize=1)
def rule_meta() -> dict:
    text = resources.files("ubuntils").joinpath("data/rule_meta.yaml").read_text(
        encoding="utf-8")
    data = yaml.safe_load(text)
    return data["rules"]


def annotate(finding) -> None:
    """Set ``finding.category`` and ``finding.attack`` from the rule's metadata."""
    meta = rule_meta().get(finding.rule_id, CUSTOM_RULE_META)
    finding.category = meta["category"]
    finding.attack = list(meta.get("attack") or [])
