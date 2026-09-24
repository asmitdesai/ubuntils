from ubuntils.detectors.finding import Finding
from ubuntils.remediators.base import BaseRemediator


class CronRemediator(BaseRemediator):
    def validate(self, finding: Finding) -> None:
        self._require_line(finding)

    def apply(self, finding: Finding, dry_run: bool) -> str:
        self._dry_run = dry_run
        if dry_run:
            return f"dry-run: would remove line from {finding.artifact_path}"
        lines = self._read_lines(finding.artifact_path)
        self._write_lines(finding.artifact_path, self._lines_without(lines, finding.raw_value))
        return f"Removed cron entry from {finding.artifact_path}"

    def verify(self, finding: Finding) -> None:
        if self._dry_run:
            return
        if self._line_present(finding.artifact_path, finding.raw_value):
            raise ValueError("Line still present after removal")
