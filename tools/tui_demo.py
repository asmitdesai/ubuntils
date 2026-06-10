"""
Driver for manual TUI remediation testing.
Injects three fake findings and patches the remediator registry to
simulate a successful remediation (no real files are touched).
"""
import sys
import time
from unittest.mock import MagicMock

import ubuntils.tui.results_screen as _rs
from ubuntils.detectors.finding import Finding, RemediationResult, RemediationStatus, Severity
from ubuntils.tui.app import UbuntilsApp

# --- mock remediator that always succeeds ---
_mock_rem = MagicMock()
_mock_rem.remediate.return_value = RemediationResult(
    finding_rule_id="CRON_TMP_PATH",
    status=RemediationStatus.SUCCESS,
    message="Removed entry from /etc/cron.d/evil",
    backup_path="/var/backups/ubuntils/20260526_120000/etc_cron.d_evil",
    rollback_command="sudo cp /var/backups/ubuntils/20260526_120000/etc_cron.d_evil /etc/cron.d/evil",
)
_rs.REMEDIATOR_REGISTRY = {"CRON_TMP_PATH": _mock_rem, "CRON_ROOT_EXEC": _mock_rem}

# --- mock findings ---
FINDINGS = [
    Finding(
        rule_id="CRON_TMP_PATH",
        severity=Severity.HIGH,
        title="Cron job references /tmp",
        description="A cron job executes a script from /tmp, which is world-writable.",
        artifact_path="/etc/cron.d/evil",
        raw_value="* * * * * root /tmp/evil.sh",
        remediation_available=True,
        remediation_description="Remove the offending cron entry from /etc/cron.d/evil.",
    ),
    Finding(
        rule_id="SSH_UNAUTHORIZED_KEY",
        severity=Severity.MEDIUM,
        title="Recently added SSH key",
        description="An SSH authorized_keys entry was added within the last 7 days.",
        artifact_path="/home/alice/.ssh/authorized_keys",
        raw_value="ssh-rsa AAAAB3NzaC1yc2E attacker@evil",
        remediation_available=True,
        remediation_description="Remove the unauthorized key from authorized_keys.",
    ),
    Finding(
        rule_id="SHELL_RC_MODIFICATION",
        severity=Severity.LOW,
        title="Shell RC recently modified",
        description=".bashrc modified within the last 48 hours.",
        artifact_path="/home/alice/.bashrc",
        raw_value="export PATH=$PATH:/tmp",
        remediation_available=False,
    ),
]

STATS = {
    "ubuntu_version": "Ubuntu 22.04.3 LTS (test mode)",
    "architecture": "x86_64",
    "duration_s": 0.1,
    "collector_count": 8,
    "collector_failures": 0,
    "finding_counts": {"HIGH": 1, "MEDIUM": 1, "LOW": 1},
    "timeline_count": 0,
}


def _override():
    time.sleep(0.05)  # brief pause so ScanScreen is visible
    return (FINDINGS, [], STATS)


UbuntilsApp(_scan_override=_override).run()
