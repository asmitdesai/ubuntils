"""Targeted preserve: evidence copies of the files remediation is about to change.

A backup exists so `ubuntils rollback` can restore a file. Preserve exists so
the evidence survives the fix: before `--remediate --confirm` changes
anything, every file it will touch is copied, hashed and described (owner,
mode, times, inode, parent directory identity) in one manifest, whose SHA-256
the responder records in their case notes. Nothing is ever restored from it.

Reads go through the same symlink-free path as remediation (safe_path), and
the parent directory must be the one each finding was made on. If any file
can't be preserved, nothing is changed. That is the caller's contract: see
pipeline.remediate_findings.

Layout (format_version 1):

    /var/lib/ubuntils/preserve/<UTC>-<random>/     0700 root
        manifest.json                              0600
        files/<path with / as _>                   0600
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from ubuntils import __version__
from ubuntils.utils.safe_io import ensure_private_dir
from ubuntils.utils.safe_path import (
    UnsafePathError, create_exclusive_at, dir_identity, open_dir_nofollow, open_parent,
    read_file_at, sha256_hex,
)

PRESERVE_BASE = "/var/lib/ubuntils/preserve"
PRESERVE_FORMAT_VERSION = 1


class PreserveError(Exception):
    """A file could not be preserved; remediation must not go ahead."""


@dataclass
class PreserveRecord:
    directory: str
    manifest_path: str
    manifest_sha256: str
    files: List[dict] = field(default_factory=list)
    duration_s: float = 0.0

    def to_dict(self) -> dict:
        return {"directory": self.directory, "manifest": self.manifest_path,
                "manifest_sha256": self.manifest_sha256,
                "files": [f["path"] for f in self.files],
                "duration_s": round(self.duration_s, 3)}


def _flat_name(path: str) -> str:
    return path.lstrip("/").replace("/", "_") or "_"


def _read_checked(path: str, expected_parent: Optional[tuple]) -> tuple:
    dir_fd, name = open_parent(path)
    try:
        parent = dir_identity(dir_fd)
        if expected_parent is not None and tuple(parent) != tuple(expected_parent):
            raise PreserveError(
                f"{os.path.dirname(path)} is not the directory the finding was made on "
                f"(dev/inode/owner {tuple(expected_parent)} then, {parent} now)")
        data, st = read_file_at(dir_fd, name)
        return data, st, parent
    finally:
        os.close(dir_fd)


def preserve(findings: list, base: str = PRESERVE_BASE) -> PreserveRecord:
    """Copy each distinct ``artifact_path`` of ``findings`` into a fresh private
    directory under ``base`` and write a hashed manifest. Raises PreserveError
    if any file can't be read safely or written; whatever was written so far
    stays, as a partial record, but the caller must not remediate."""
    start = datetime.now(timezone.utc)
    by_path: dict = {}
    for f in findings:
        by_path.setdefault(f.artifact_path, f)

    ensure_private_dir(base)
    stamp = start.strftime("%Y%m%dT%H%M%SZ")
    directory = os.path.join(base, f"{stamp}-{secrets.token_hex(4)}")
    os.mkdir(directory, 0o700)
    os.mkdir(os.path.join(directory, "files"), 0o700)

    entries = []
    files_fd = open_dir_nofollow(os.path.join(directory, "files"))
    try:
        for path, finding in sorted(by_path.items()):
            try:
                data, st, parent = _read_checked(path, finding.parent_dir_identity)
            except (OSError, UnsafePathError) as exc:
                raise PreserveError(f"cannot preserve {path}: {exc}") from exc
            stored = _flat_name(path)
            n = 0
            while True:
                candidate = stored if n == 0 else f"{stored}.{n}"
                try:
                    create_exclusive_at(files_fd, candidate, data)
                    break
                except FileExistsError:
                    n += 1
            entries.append({
                "path": path,
                "preserved_as": f"files/{candidate}",
                "sha256": sha256_hex(data),
                "size": len(data),
                "uid": st.st_uid, "gid": st.st_gid,
                "mode": oct(stat.S_IMODE(st.st_mode)),
                "mtime": st.st_mtime, "ctime": st.st_ctime,
                "dev": st.st_dev, "inode": st.st_ino,
                "parent": {"dev": parent[0], "inode": parent[1], "uid": parent[2]},
                "findings": sorted({x.rule_id for x in findings if x.artifact_path == path}),
            })
    finally:
        os.close(files_fd)

    manifest = {
        "format_version": PRESERVE_FORMAT_VERSION,
        "tool_version": __version__,
        "hostname": socket.gethostname(),
        "created_at": start.isoformat(),
        "purpose": "evidence copies taken before remediation; never used to restore "
                   "(use `ubuntils rollback`)",
        "files": entries,
    }
    body = json.dumps(manifest, indent=2, sort_keys=True).encode()
    dir_fd = open_dir_nofollow(directory)
    try:
        create_exclusive_at(dir_fd, "manifest.json", body)
    finally:
        os.close(dir_fd)
    duration = (datetime.now(timezone.utc) - start).total_seconds()
    return PreserveRecord(directory=directory,
                          manifest_path=os.path.join(directory, "manifest.json"),
                          manifest_sha256=sha256_hex(body), files=entries, duration_s=duration)
