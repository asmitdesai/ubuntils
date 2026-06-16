import subprocess

from ubuntils.detectors.finding import Finding
from ubuntils.remediators.base import BaseRemediator


class SudoersRemediator(BaseRemediator):
    def __init__(self, backup_base: str = BaseRemediator.BACKUP_BASE):
        self._backup_base = backup_base

    def backup(self, finding: Finding) -> str:
        return self._create_backup(finding)

    def validate(self, finding: Finding) -> None:
        lines = self._read_lines(finding.artifact_path)
        if not any(line.rstrip("\n") == finding.raw_value for line in lines):
            raise ValueError(f"Line not found in {finding.artifact_path}: {finding.raw_value!r}")

    def _run_visudo_check(self, path: str) -> None:
        result = subprocess.run(
            ["visudo", "-cf", path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ValueError(f"visudo check failed: {result.stderr.strip()}")

    def apply(self, finding: Finding, dry_run: bool) -> str:
        self._dry_run = dry_run
        if dry_run:
            return f"dry-run: would remove NOPASSWD entry from {finding.artifact_path}"
        lines = self._read_lines(finding.artifact_path)
        new_lines = [l for l in lines if l.rstrip("\n") != finding.raw_value]
        self._write_lines(finding.artifact_path, new_lines)
        return f"Removed NOPASSWD sudoers entry from {finding.artifact_path}"

    def verify(self, finding: Finding) -> None:
        if getattr(self, "_dry_run", False):
            return
        self._run_visudo_check(finding.artifact_path)
        if finding.raw_value in self._read_text(finding.artifact_path):
            raise ValueError("NOPASSWD line still present after removal")
