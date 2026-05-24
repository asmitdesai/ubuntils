from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


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


@dataclass
class RemediationResult:
    finding_rule_id: str
    status: RemediationStatus
    message: str
    backup_path: Optional[str] = None
    rollback_command: Optional[str] = None
