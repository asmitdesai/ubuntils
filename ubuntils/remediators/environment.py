from ubuntils.detectors.finding import Finding
from ubuntils.remediators.base import BaseRemediator

# glibc's loader splits /etc/ld.so.preload on whitespace and ':' and has no
# comment syntax — "# /tmp/evil.so" would still preload /tmp/evil.so. Entries
# there must be removed, never commented out.
LD_SO_PRELOAD = "/etc/ld.so.preload"


def _is_ld_so_preload(path: str) -> bool:
    return path == LD_SO_PRELOAD or path.endswith("/etc/ld.so.preload")


class EnvironmentRemediator(BaseRemediator):
    def validate(self, finding: Finding) -> None:
        self._require_line(finding)

    def apply(self, finding: Finding, dry_run: bool) -> str:
        self._dry_run = dry_run
        preload_file = _is_ld_so_preload(finding.artifact_path)
        if dry_run:
            action = "remove" if preload_file else "comment out"
            return f"dry-run: would {action} LD_PRELOAD line in {finding.artifact_path}"
        lines = self._read_lines(finding.artifact_path)
        if preload_file:
            self._write_lines(finding.artifact_path, self._lines_without(lines, finding.raw_value))
            return f"Removed preload entry from {finding.artifact_path}"
        new_lines = []
        for line in lines:
            if line.rstrip("\n") == finding.raw_value and not line.lstrip().startswith("#"):
                new_lines.append(f"# {line}")
            else:
                new_lines.append(line)
        self._write_lines(finding.artifact_path, new_lines)
        return f"Commented out LD_PRELOAD entry in {finding.artifact_path}"

    def verify(self, finding: Finding) -> None:
        if self._dry_run:
            return
        if self._line_present(finding.artifact_path, finding.raw_value):
            raise ValueError("Active LD_PRELOAD line still present after remediation")
