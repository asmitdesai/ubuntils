import json
import os
import shlex
import stat
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from ubuntils.detectors.finding import Finding, RemediationResult, RemediationStatus
from ubuntils.utils.safe_io import ensure_private_dir
from ubuntils.utils.safe_path import (
    UnsafePathError, create_exclusive_at, dir_identity, open_dir_nofollow, open_parent,
    read_file_at, replace_at, sha256_hex, stat_at,
)

# Lines are bytes on disk; surrogateescape round-trips anything that isn't
# UTF-8 unchanged, so removing one line never re-encodes the others.
_ENCODING, _ERRORS = "utf-8", "surrogateescape"


def rollback_command_for(backup_path: str) -> str:
    return f"ubuntils rollback {shlex.quote(backup_path)}"


class BaseRemediator(ABC):
    BACKUP_BASE = "/var/backups/ubuntils"

    def __init__(self, backup_base: str = BACKUP_BASE):
        self._backup_base = backup_base
        self._dry_run = False
        # The artifact being remediated, and the identity (st_dev, st_ino,
        # st_uid) its parent directory had when the finding was made.
        self._artifact = None
        self._expected_parent = None
        self._backup_meta: dict = {}

    # ------------------------------------------------------------------
    # Symlink-safe file I/O.
    #
    # On a compromised host the attacker may still be active and can swap an
    # artifact — or any directory above it — for a symlink between detection
    # and any use (TOCTOU). O_NOFOLLOW only covers the last component, so
    # every operation here goes through open_parent(): the parent directory
    # is reached by walking from "/" with O_NOFOLLOW on each component, and
    # the file, its backup, the temp file, fchmod/fchown and rename all
    # happen relative to that directory fd. A symlink anywhere in the path is
    # refused, and if the parent directory isn't the one the finding was
    # made on (another inode: /home/alice/.ssh swapped for a copy or a
    # bind of someone else's), remediation stops.
    # ------------------------------------------------------------------

    def _open_parent(self, path: str):
        dir_fd, name = open_parent(path)
        if path == self._artifact and self._expected_parent is not None:
            actual = dir_identity(dir_fd)
            if tuple(actual) != tuple(self._expected_parent):
                os.close(dir_fd)
                raise UnsafePathError(
                    f"{os.path.dirname(path)} is not the directory the finding was made "
                    f"on (dev/inode/owner {tuple(self._expected_parent)} then, "
                    f"{actual} now) — refusing to remediate")
        return dir_fd, name

    def _read_bytes(self, path: str) -> tuple:
        dir_fd, name = self._open_parent(path)
        try:
            return read_file_at(dir_fd, name)
        finally:
            os.close(dir_fd)

    def _read_text(self, path: str) -> str:
        return self._read_bytes(path)[0].decode(_ENCODING, _ERRORS)

    def _read_lines(self, path: str) -> list:
        return self._read_text(path).splitlines(keepends=True)

    def _write_lines(self, path: str, lines: list) -> None:
        """Atomically replace ``path`` with ``lines``, keeping its mode and
        owner (see safe_path.replace_at). The original must still be a
        regular file — a symlink swapped in at ``path`` is refused, and
        rename() would replace the link itself rather than follow it."""
        dir_fd, name = self._open_parent(path)
        try:
            st = stat_at(dir_fd, name)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError(f"Refusing to write non-regular file: {path}")
            replace_at(dir_fd, name, "".join(lines).encode(_ENCODING, _ERRORS),
                       st.st_mode, st.st_uid, st.st_gid)
        finally:
            os.close(dir_fd)

    @staticmethod
    def _same_line(line: str, raw_value: str) -> bool:
        """Whole-line match, ignoring surrounding whitespace: collectors report
        some lines stripped (an indented `export LD_PRELOAD=…`, a sudoers rule
        with trailing spaces), and those must still be found."""
        wanted = raw_value.strip()
        return bool(wanted) and line.strip() == wanted

    @classmethod
    def _lines_without(cls, lines: list, raw_value: str) -> list:
        return [line for line in lines if not cls._same_line(line, raw_value)]

    def _line_present(self, path: str, raw_value: str) -> bool:
        """Line-exact membership test — the same comparison apply() uses, so
        verify() can't report FAILED because raw_value happens to be a
        substring of some other surviving line."""
        return any(self._same_line(line, raw_value) for line in self._read_lines(path))

    def _require_line(self, finding: Finding, what: str = "Line") -> None:
        if not self._line_present(finding.artifact_path, finding.raw_value):
            raise ValueError(
                f"{what} not found in {finding.artifact_path}: {finding.raw_value!r}"
            )

    def _create_backup(self, finding: Finding) -> str:
        """Copy the artifact into a timestamped, 0700 backup dir, never
        following a symlink on either side, and remember what the sidecar
        needs to restore it safely later."""
        artifact = finding.artifact_path
        dir_fd, name = self._open_parent(artifact)
        try:
            data, st = read_file_at(dir_fd, name)
            parent = os.fstat(dir_fd)
        finally:
            os.close(dir_fd)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        ensure_private_dir(self._backup_base)
        dest_dir = os.path.join(self._backup_base, ts)
        ensure_private_dir(dest_dir)
        safe_name = artifact.lstrip("/").replace("/", "_")

        dest_fd = open_dir_nofollow(dest_dir)
        try:
            # O_EXCL: never overwrite or follow an existing/pre-staged
            # destination. 0o600: backups of shadow/sudoers must not become
            # world-readable. Two fixes to one file within a second (two bad
            # lines in one crontab) get .1, .2… instead of failing on the
            # second; a name is only used if its sidecar name is free too.
            for attempt in range(100):
                candidate = safe_name if attempt == 0 else f"{safe_name}.{attempt}"
                try:
                    stat_at(dest_fd, candidate + ".json")
                    continue
                except FileNotFoundError:
                    pass
                try:
                    create_exclusive_at(dest_fd, candidate, data)
                except FileExistsError:
                    continue
                break
            else:
                raise FileExistsError(f"too many backups of {artifact} in {dest_dir}")
        finally:
            os.close(dest_fd)
        backup_path = os.path.join(dest_dir, candidate)
        self._backup_meta = {
            "backup_path": backup_path,
            "original_path": artifact,
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mode": stat.S_IMODE(st.st_mode),
            "parent_dev": parent.st_dev,
            "parent_ino": parent.st_ino,
            "parent_uid": parent.st_uid,
            "backup_sha256": sha256_hex(data),
            "rule_id": finding.rule_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        return backup_path

    def _write_sidecar(self, backup_path: str, artifact: str) -> None:
        """<backup>.json: what `ubuntils rollback` checks before restoring —
        the file's original owner/mode, its parent directory's identity, and
        the content remediation left behind (so a rollback never clobbers a
        file that has changed since)."""
        meta = dict(self._backup_meta)
        meta["post_sha256"] = sha256_hex(self._read_bytes(artifact)[0])
        dest_fd = open_dir_nofollow(os.path.dirname(backup_path))
        try:
            create_exclusive_at(dest_fd, os.path.basename(backup_path) + ".json",
                                json.dumps(meta, indent=2, sort_keys=True).encode())
        finally:
            os.close(dest_fd)

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
        self._artifact = finding.artifact_path
        self._expected_parent = getattr(finding, "parent_dir_identity", None)

        def failed(message, backup_path=None):
            return RemediationResult(finding_rule_id=finding.rule_id,
                                     status=RemediationStatus.FAILED,
                                     message=message, backup_path=backup_path)

        if dry_run:
            # A preview must not touch the disk — no backup of /etc/sudoers
            # into /var/backups, and no rollback command for a change that
            # was never made.
            try:
                self.validate(finding)
                message = self.apply(finding, dry_run=True)
            except Exception as e:
                return failed(str(e))
            return RemediationResult(
                finding_rule_id=finding.rule_id,
                status=RemediationStatus.SUCCESS,
                message=message,
            )

        # Friendly fast path for the common case; the real guarantee is that
        # backup() and every later read/write go through _open_parent(), which
        # also reports an unsafe or swapped parent directory.
        try:
            dir_fd, name = self._open_parent(finding.artifact_path)
            try:
                if stat.S_ISLNK(stat_at(dir_fd, name).st_mode):
                    return failed(f"Refusing to remediate symlink: {finding.artifact_path}")
            finally:
                os.close(dir_fd)
        except OSError:
            pass

        try:
            backup_path = self.backup(finding)
        except Exception as e:
            return failed(str(e))

        try:
            self.validate(finding)
        except Exception as e:
            return failed(str(e), backup_path)

        try:
            message = self.apply(finding, dry_run)
        except Exception as e:
            return failed(str(e), backup_path)

        rollback_command = None
        if self._backup_meta.get("backup_path") == backup_path:
            try:
                self._write_sidecar(backup_path, finding.artifact_path)
            except Exception as e:
                return failed(f"changed {finding.artifact_path}, but could not record "
                              f"rollback data: {e} — restore from {backup_path} by hand",
                              backup_path)
            rollback_command = rollback_command_for(backup_path)

        try:
            self.verify(finding)
        except Exception as e:
            return failed(str(e), backup_path)

        return RemediationResult(
            finding_rule_id=finding.rule_id,
            status=RemediationStatus.SUCCESS,
            message=message,
            backup_path=backup_path,
            rollback_command=rollback_command,
        )
