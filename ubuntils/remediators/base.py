import os
import stat
from abc import ABC, abstractmethod

from ubuntils.detectors.finding import Finding, RemediationResult, RemediationStatus


class BaseRemediator(ABC):
    BACKUP_BASE = "/var/backups/ubuntils"

    @abstractmethod
    def backup(self, finding: Finding) -> str:
        """Create a timestamped backup. Returns the backup path."""

    @abstractmethod
    def validate(self, finding: Finding) -> None:
        """Validate that remediation is safe to apply. Raises ValueError if not."""

    @abstractmethod
    def apply(self, finding: Finding, dry_run: bool) -> str:
        """Apply the remediation. Returns a human-readable message."""

    @abstractmethod
    def verify(self, finding: Finding) -> None:
        """Verify the change was applied. Raises ValueError if verification fails."""

    def remediate(self, finding: Finding, dry_run: bool = True) -> RemediationResult:
        try:
            st = os.lstat(finding.artifact_path)
            if stat.S_ISLNK(st.st_mode):
                return RemediationResult(
                    finding_rule_id=finding.rule_id,
                    status=RemediationStatus.FAILED,
                    message=f"Refusing to remediate symlink: {finding.artifact_path}",
                )
        except OSError:
            pass  # file-not-found will be caught in backup()

        try:
            backup_path = self.backup(finding)
        except Exception as e:
            return RemediationResult(
                finding_rule_id=finding.rule_id,
                status=RemediationStatus.FAILED,
                message=str(e),
            )

        rollback_command = f"cp {backup_path} {finding.artifact_path}"

        try:
            self.validate(finding)
        except Exception as e:
            return RemediationResult(
                finding_rule_id=finding.rule_id,
                status=RemediationStatus.FAILED,
                message=str(e),
                backup_path=backup_path,
            )

        try:
            message = self.apply(finding, dry_run)
        except Exception as e:
            return RemediationResult(
                finding_rule_id=finding.rule_id,
                status=RemediationStatus.FAILED,
                message=str(e),
                backup_path=backup_path,
            )

        try:
            self.verify(finding)
        except Exception as e:
            return RemediationResult(
                finding_rule_id=finding.rule_id,
                status=RemediationStatus.FAILED,
                message=str(e),
                backup_path=backup_path,
            )

        return RemediationResult(
            finding_rule_id=finding.rule_id,
            status=RemediationStatus.SUCCESS,
            message=message,
            backup_path=backup_path,
            rollback_command=rollback_command,
        )
