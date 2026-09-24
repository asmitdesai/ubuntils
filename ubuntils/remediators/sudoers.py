import os
import tempfile

from ubuntils.detectors.finding import Finding
from ubuntils.remediators.base import BaseRemediator
from ubuntils.utils.shell import run_command

_VISUDO_TIMEOUT = 30
_NON_RULE_PREFIXES = ("#", "@", "Defaults", "User_Alias", "Runas_Alias", "Host_Alias",
                      "Cmnd_Alias", "Cmd_Alias")


def _is_rule_line(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith(_NON_RULE_PREFIXES) and "=" in stripped


class SudoersRemediator(BaseRemediator):
    def validate(self, finding: Finding) -> None:
        self._require_line(finding)
        # Never remove the last rule from the main sudoers file — that could
        # leave the system with no sudo access at all. (%group rules are
        # already flag-only in the detector for the same reason.)
        if os.path.basename(finding.artifact_path) == "sudoers":
            remaining = self._lines_without(self._read_lines(finding.artifact_path),
                                            finding.raw_value)
            if not any(_is_rule_line(line) for line in remaining):
                raise ValueError(
                    f"Refusing to remove the last sudo rule in {finding.artifact_path}"
                )

    def _run_visudo_check(self, path: str) -> None:
        _stdout, stderr, rc = run_command(["visudo", "-cf", path], timeout=_VISUDO_TIMEOUT)
        if rc != 0:
            raise ValueError(f"visudo check failed: {stderr.strip()}")

    def _check_candidate(self, lines: list) -> None:
        """Syntax-check the prospective sudoers content *before* it touches
        the real file, so a bad edit can never land on disk."""
        fd, candidate = tempfile.mkstemp(prefix="ubuntils-sudoers-")
        try:
            with os.fdopen(fd, "w") as f:
                f.writelines(lines)
            self._run_visudo_check(candidate)
        finally:
            os.unlink(candidate)

    def apply(self, finding: Finding, dry_run: bool) -> str:
        self._dry_run = dry_run
        if dry_run:
            return f"dry-run: would remove NOPASSWD entry from {finding.artifact_path}"
        lines = self._read_lines(finding.artifact_path)
        new_lines = self._lines_without(lines, finding.raw_value)
        self._check_candidate(new_lines)
        self._write_lines(finding.artifact_path, new_lines)
        return f"Removed NOPASSWD sudoers entry from {finding.artifact_path}"

    def verify(self, finding: Finding) -> None:
        if self._dry_run:
            return
        if self._line_present(finding.artifact_path, finding.raw_value):
            raise ValueError("NOPASSWD line still present after removal")
