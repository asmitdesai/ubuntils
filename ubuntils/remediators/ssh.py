import os
import shutil
from datetime import datetime

from ubuntils.detectors.finding import Finding
from ubuntils.remediators.base import BaseRemediator


class SSHRemediator(BaseRemediator):
    def __init__(self, backup_base: str = BaseRemediator.BACKUP_BASE):
        self._backup_base = backup_base

    def backup(self, finding: Finding) -> str:
        artifact = finding.artifact_path
        if not os.path.exists(artifact):
            raise FileNotFoundError(f"Artifact not found: {artifact}")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest_dir = os.path.join(self._backup_base, ts)
        os.makedirs(dest_dir, mode=0o700, exist_ok=True)
        safe_name = artifact.lstrip("/").replace("/", "_")
        dest = os.path.join(dest_dir, safe_name)
        if os.path.exists(dest):
            raise FileExistsError(f"Backup destination already exists: {dest}")
        shutil.copy2(artifact, dest)
        return dest

    def validate(self, finding: Finding) -> None:
        with open(finding.artifact_path) as f:
            lines = f.readlines()
        if not any(line.rstrip("\n") == finding.raw_value for line in lines):
            raise ValueError(f"Key not found in {finding.artifact_path}: {finding.raw_value!r}")

    def apply(self, finding: Finding, dry_run: bool) -> str:
        self._dry_run = dry_run
        if dry_run:
            return f"dry-run: would remove key from {finding.artifact_path}"
        with open(finding.artifact_path) as f:
            lines = f.readlines()
        new_lines = [l for l in lines if l.rstrip("\n") != finding.raw_value]
        with open(finding.artifact_path, "w") as f:
            f.writelines(new_lines)
        return f"Removed unauthorized key from {finding.artifact_path}"

    def verify(self, finding: Finding) -> None:
        if getattr(self, "_dry_run", False):
            return
        with open(finding.artifact_path) as f:
            content = f.read()
        if finding.raw_value in content:
            raise ValueError("Key still present after removal")
