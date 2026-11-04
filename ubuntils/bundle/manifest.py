from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from typing import Optional

# The bundle layout this ubuntils writes. Bundles from 2.x carry no
# format_version and are format 1; a reader refuses formats newer than it knows.
BUNDLE_FORMAT_VERSION = 1
SUPPORTED_BUNDLE_FORMATS = (1,)


@dataclass
class FileEntry:
    source_path: str
    bundle_path: str
    sha256: str
    size: int
    mtime: float
    ctime: float


@dataclass
class CommandEntry:
    name: str
    argv: list
    bundle_path: str
    sha256: str
    exit_code: int


@dataclass
class Manifest:
    run_id: str
    host_id: str
    hostname: str
    ubuntu_version: str
    collected_at_utc_start: str
    collected_at_utc_end: str
    tool_version: str
    files: list
    commands: list
    # None for 2.x bundles: the field is then left out of the digest, so they
    # verify exactly as they did when they were written.
    format_version: Optional[int] = None

    def to_dict(self) -> dict:
        d = {
            "run_id": self.run_id,
            "host_id": self.host_id,
            "hostname": self.hostname,
            "ubuntu_version": self.ubuntu_version,
            "collected_at_utc_start": self.collected_at_utc_start,
            "collected_at_utc_end": self.collected_at_utc_end,
            "tool_version": self.tool_version,
            "files": [asdict(f) for f in self.files],
            "commands": [asdict(c) for c in self.commands],
        }
        if self.format_version is not None:
            d["format_version"] = self.format_version
        return d

    def manifest_sha256(self) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()
