"""Stable finding IDs (E4-S3, QW-8).

A finding's ID is a hash of its rule, artifact path and raw value, so two scans
of an unchanged host give the same IDs and a scan can be diffed against the
last one. Rules being renamed in 3.0 are hashed under their new name from the
start, so IDs don't change when the rename lands (QW-13).
"""
from __future__ import annotations

import hashlib

# Old rule ID -> the canonical (3.0) one.
CANONICAL_RULE_IDS = {"SUSPICIOUS_SYSTEMD_TIMER": "SUSPICIOUS_SYSTEMD_UNIT"}


def canonical_rule_id(rule_id: str) -> str:
    return CANONICAL_RULE_IDS.get(rule_id, rule_id)


def finding_id(rule_id: str, artifact_path: str, raw_value: str) -> str:
    h = hashlib.sha256()
    # str(): a custom or buggy rule's odd value must not take detection down.
    for part in (canonical_rule_id(str(rule_id)), str(artifact_path), str(raw_value)):
        h.update(part.encode("utf-8", "surrogateescape"))
        h.update(b"\0")
    return h.hexdigest()[:32]
