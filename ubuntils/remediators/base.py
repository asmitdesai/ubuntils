import os
import stat
from abc import ABC, abstractmethod
from datetime import datetime

from ubuntils.detectors.finding import Finding, RemediationResult, RemediationStatus


class BaseRemediator(ABC):
    BACKUP_BASE = "/var/backups/ubuntils"

    # ------------------------------------------------------------------
    # Symlink-safe file I/O.
    #
    # On a compromised host the attacker may still be active and can swap an
    # artifact for a symlink between any check and any use (TOCTOU). Every read
    # and write below opens with O_NOFOLLOW, so the final path component is
    # never traversed through a symlink — an open of a symlink fails outright
    # rather than letting root read or truncate the link target. This is the
    # actual security guarantee; the lstat fast-path in remediate() only exists
    # to return a friendlier message for the common, non-racing case.
    # ------------------------------------------------------------------

    def _read_lines(self, path: str) -> list:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "r") as f:
            return f.readlines()

    def _read_text(self, path: str) -> str:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "r") as f:
            return f.read()

    def _write_lines(self, path: str, lines: list) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
        with os.fdopen(fd, "w") as f:
            f.writelines(lines)

    def _create_backup(self, finding: Finding) -> str:
        """Copy the artifact to a timestamped, 0700 backup dir without ever
        following a symlink on either source or destination."""
        artifact = finding.artifact_path
        if not os.path.exists(artifact):
            raise FileNotFoundError(f"Artifact not found: {artifact}")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest_dir = os.path.join(self._backup_base, ts)
        os.makedirs(dest_dir, mode=0o700, exist_ok=True)
        safe_name = artifact.lstrip("/").replace("/", "_")
        dest = os.path.join(dest_dir, safe_name)

        src_fd = os.open(artifact, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(src_fd, "rb") as src:
            data = src.read()
        # O_EXCL: never overwrite or follow an existing/pre-staged destination.
        # 0o600: backups of shadow/sudoers must not become world-readable.
        dst_fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(dst_fd, "wb") as dst:
            dst.write(data)
        return dest

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
