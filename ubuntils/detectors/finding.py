from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Why `--remediate --confirm` must never apply a fix on its own. These are hard
# blocks, checked before any confidence gate: no signal, forged or real, can
# score its way past one. Manual remediation in the TUI stays possible.
AMBIGUOUS_KEY = "AMBIGUOUS_KEY"        # several keys in the file; which one is new is unknowable
RECENCY_ONLY = "RECENCY_ONLY"          # the only evidence is a recent timestamp
SOLE_SUDO_ACCESS = "SOLE_SUDO_ACCESS"  # removing the rule leaves that account no sudo at all


@dataclass(frozen=True)
class BlockedReason:
    code: str
    detail: str


class RemediationStatus(Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    artifact_path: str
    raw_value: str
    remediation_available: bool
    remediation_description: Optional[str] = None
    related_events: List = field(default_factory=list)
    guided_remediation: Optional[str] = None
    confidence: int = 50
    confidence_band: str = "MEDIUM"
    signals: List[dict] = field(default_factory=list)
    # Why `--remediate --confirm` must never apply this fix on its own, however
    # high the confidence climbs (e.g. which of several keys was added is
    # unknowable). Manual remediation in the TUI stays possible, with a warning.
    auto_remediation_blocked: Optional[str] = None
    # Every hard block, as {code, detail}; auto_remediation_blocked is kept as
    # the first one's detail for 2.x report consumers.
    blocked_reasons: List[BlockedReason] = field(default_factory=list)
    # "persistence" or "hygiene", and MITRE ATT&CK technique IDs; set by the
    # engine from ubuntils/data/rule_meta.yaml.
    category: str = "persistence"
    attack: List[str] = field(default_factory=list)
    # (st_dev, st_ino, st_uid) of the artifact's parent directory when it was
    # collected. Remediation refuses if the directory there now is another
    # one — e.g. ~/.ssh swapped for a symlink or a different directory.
    parent_dir_identity: Optional[tuple] = None


def block_auto_remediation(finding: "Finding", code: str, detail: str) -> None:
    """Keep `finding` out of `--remediate --confirm`, whatever its confidence."""
    if any(r.code == code for r in finding.blocked_reasons):
        return
    finding.blocked_reasons.append(BlockedReason(code=code, detail=detail))
    if finding.auto_remediation_blocked is None:
        finding.auto_remediation_blocked = detail


@dataclass
class RemediationResult:
    finding_rule_id: str
    status: RemediationStatus
    message: str
    backup_path: Optional[str] = None
    rollback_command: Optional[str] = None
