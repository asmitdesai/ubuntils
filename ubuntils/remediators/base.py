import os
import stat
import tempfile
from abc import ABC, abstractmethod
from datetime import datetime

from ubuntils.detectors.finding import Finding, RemediationResult, RemediationStatus


class BaseRemediator(ABC):
    BACKUP_BASE = "/var/backups/ubuntils"

    def __init__(self, backup_base: str = BACKUP_BASE):
        self._backup_base = backup_base
        self._dry_run = False

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
        """Atomically replace ``path`` with ``lines``.

        The new content goes to a sibling temp file (mkstemp opens it
        O_CREAT|O_EXCL|O_NOFOLLOW) that inherits the original's mode and
        ownership, is fsync'd, and is then rename()d over the original. A crash
        mid-write leaves the original intact instead of a truncated
        /etc/sudoers, and rename() replaces the directory entry itself — it
        never follows a symlink swapped in at ``path``. The original is still
        opened O_NOFOLLOW first, so a symlink there is refused outright.
        """
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
        finally:
            os.close(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Refusing to write non-regular file: {path}")

        directory = os.path.dirname(os.path.abspath(path))
        tmp_fd, tmp_path = tempfile.mkstemp(prefix=".ubuntils-", dir=directory)
        try:
            with os.fdopen(tmp_fd, "w") as f:
                f.writelines(lines)
                f.flush()
                os.fchmod(f.fileno(), stat.S_IMODE(st.st_mode))
                if (st.st_uid, st.st_gid) != (os.geteuid(), os.getegid()):
                    os.fchown(f.fileno(), st.st_uid, st.st_gid)
                os.fsync(f.fileno())
            os.rename(tmp_path, path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    @staticmethod
    def _lines_without(lines: list, raw_value: str) -> list:
        return [line for line in lines if line.rstrip("\n") != raw_value]

    def _line_present(self, path: str, raw_value: str) -> bool:
        """Line-exact membership test — the same comparison apply() uses, so
        verify() can't report FAILED because raw_value happens to be a
        substring of some other surviving line."""
        return any(line.rstrip("\n") == raw_value for line in self._read_lines(path))

    def _require_line(self, finding: Finding, what: str = "Line") -> None:
        if not self._line_present(finding.artifact_path, finding.raw_value):
            raise ValueError(
                f"{what} not found in {finding.artifact_path}: {finding.raw_value!r}"
            )

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

    def backup(self, finding: Finding) -> str:
        """Create a timestamped backup. Returns the backup path."""
        return self._create_backup(finding)

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
