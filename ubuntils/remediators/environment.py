from ubuntils.detectors.finding import Finding
from ubuntils.remediators.base import BaseRemediator


class EnvironmentRemediator(BaseRemediator):
    def __init__(self, backup_base: str = BaseRemediator.BACKUP_BASE):
        self._backup_base = backup_base

    def backup(self, finding: Finding) -> str:
        return self._create_backup(finding)

    def validate(self, finding: Finding) -> None:
        lines = self._read_lines(finding.artifact_path)
        if not any(line.rstrip("\n") == finding.raw_value for line in lines):
            raise ValueError(f"Line not found in {finding.artifact_path}: {finding.raw_value!r}")

    def apply(self, finding: Finding, dry_run: bool) -> str:
        self._dry_run = dry_run
        if dry_run:
            return f"dry-run: would comment out LD_PRELOAD line in {finding.artifact_path}"
        lines = self._read_lines(finding.artifact_path)
        new_lines = []
        for line in lines:
            if line.rstrip("\n") == finding.raw_value:
                new_lines.append(f"# {line}" if not line.startswith("#") else line)
            else:
                new_lines.append(line)
        self._write_lines(finding.artifact_path, new_lines)
        return f"Commented out LD_PRELOAD entry in {finding.artifact_path}"

    def verify(self, finding: Finding) -> None:
        if getattr(self, "_dry_run", False):
            return
        for line in self._read_text(finding.artifact_path).splitlines():
            stripped = line.strip()
            if not stripped.startswith("#") and finding.raw_value in stripped:
                raise ValueError("Active LD_PRELOAD line still present after remediation")
