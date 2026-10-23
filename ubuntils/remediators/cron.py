import os

from ubuntils.collectors.cron import _is_variable_assignment, _split_entry
from ubuntils.detectors.finding import Finding
from ubuntils.remediators.base import BaseRemediator

_USER_CRONTAB_DIR = "/var/spool/cron/crontabs"


class CronRemediator(BaseRemediator):
    # The cron rules report only the command as raw_value, not the whole line
    # ("/tmp/x.sh", not "* * * * * root /tmp/x.sh"), so a line matches when
    # CronCollector would parse it to that command — or when it is raw_value
    # verbatim.

    def _matches(self, path: str, line: str, raw_value: str) -> bool:
        line = line.strip()
        if line == raw_value:
            return True
        if not line or line.startswith("#") or _is_variable_assignment(line):
            return False
        has_user_field = os.path.dirname(path) != _USER_CRONTAB_DIR
        split = _split_entry(line, has_user_field)
        return split is not None and split[2] == raw_value

    def _entry_present(self, finding: Finding) -> bool:
        return any(self._matches(finding.artifact_path, line, finding.raw_value)
                   for line in self._read_lines(finding.artifact_path))

    def validate(self, finding: Finding) -> None:
        if not self._entry_present(finding):
            raise ValueError(
                f"Line not found in {finding.artifact_path}: {finding.raw_value!r}"
            )

    def apply(self, finding: Finding, dry_run: bool) -> str:
        self._dry_run = dry_run
        if dry_run:
            return f"dry-run: would remove line from {finding.artifact_path}"
        lines = self._read_lines(finding.artifact_path)
        self._write_lines(finding.artifact_path, [
            line for line in lines
            if not self._matches(finding.artifact_path, line, finding.raw_value)
        ])
        return f"Removed cron entry from {finding.artifact_path}"

    def verify(self, finding: Finding) -> None:
        if self._dry_run:
            return
        if self._entry_present(finding):
            raise ValueError("Line still present after removal")
