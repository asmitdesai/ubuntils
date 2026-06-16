from __future__ import annotations

from ubuntils.detectors.finding import Finding
from ubuntils.remediators.base import BaseRemediator


class CronRemediator(BaseRemediator):
    def __init__(self, backup_base: str = BaseRemediator.BACKUP_BASE):
        self._backup_base = backup_base
        self._backup_path: str | None = None

    def backup(self, finding: Finding) -> str:
        self._backup_path = self._create_backup(finding)
        return self._backup_path

    def validate(self, finding: Finding) -> None:
        lines = self._read_lines(finding.artifact_path)
        if not any(line.rstrip("\n") == finding.raw_value for line in lines):
            raise ValueError(f"Line not found in {finding.artifact_path}: {finding.raw_value!r}")

    def apply(self, finding: Finding, dry_run: bool) -> str:
        self._dry_run = dry_run
        if dry_run:
            return f"dry-run: would remove line from {finding.artifact_path}"
        lines = self._read_lines(finding.artifact_path)
        new_lines = [l for l in lines if l.rstrip("\n") != finding.raw_value]
        self._write_lines(finding.artifact_path, new_lines)
        return f"Removed cron entry from {finding.artifact_path}"

    def verify(self, finding: Finding) -> None:
        if getattr(self, "_dry_run", False):
            return
        if finding.raw_value in self._read_text(finding.artifact_path):
            raise ValueError("Line still present after removal")
