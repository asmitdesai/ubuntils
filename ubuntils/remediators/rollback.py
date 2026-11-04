"""`ubuntils rollback BACKUP`: restore a remediated file from its backup.

The old advice, `cp <backup> <artifact>` run as root, follows a symlink at
the destination: an attacker who replaced the remediated file (or a
directory above it) with a link to /etc/shadow got root to overwrite it with
the backup's content — which they wrote in the first place.

Rollback instead reads the backup's sidecar (<backup>.json, written by
BaseRemediator), walks to the original's directory without following any
symlink, and only restores if that directory is the one remediated and the
file still holds what remediation left there. The restore is the same atomic
temp-file-and-rename as remediation, with the original owner and mode.
"""
from __future__ import annotations

import json
import os
import stat

from ubuntils.utils.safe_path import (
    UnsafePathError, open_parent, read_file_at, replace_at, sha256_hex, stat_at,
)


class RollbackError(Exception):
    pass


def _read_own_file(dir_fd: int, name: str) -> bytes:
    """A backup or sidecar: must be ours and singly linked, or anyone who
    could plant one could choose what root restores and where."""
    data, st = read_file_at(dir_fd, name)
    if st.st_uid != os.geteuid():
        raise RollbackError(f"{name} is owned by uid {st.st_uid}, not by us — refusing")
    if st.st_nlink != 1:
        raise RollbackError(f"{name} has {st.st_nlink} hard links — refusing")
    return data


def _load(backup_path: str):
    dir_fd, name = open_parent(os.path.abspath(backup_path))
    try:
        backup = _read_own_file(dir_fd, name)
        try:
            meta = json.loads(_read_own_file(dir_fd, name + ".json"))
        except FileNotFoundError:
            raise RollbackError(f"no rollback record ({name}.json) next to {backup_path}")
    finally:
        os.close(dir_fd)
    if sha256_hex(backup) != meta.get("backup_sha256"):
        raise RollbackError(f"{backup_path} doesn't match its rollback record — "
                            "the backup itself has changed; refusing")
    return backup, meta


def _target_problems(meta: dict) -> list:
    """Reasons the target isn't in the state remediation left it in. Unsafe
    states (a symlink in the path or at the target, not a regular file)
    raise instead: --force never overrides those."""
    target = meta["original_path"]
    dir_fd, name = open_parent(target)
    try:
        problems = []
        parent = os.fstat(dir_fd)
        if (parent.st_dev, parent.st_ino) != (meta["parent_dev"], meta["parent_ino"]):
            problems.append(f"{os.path.dirname(target)} is not the directory that was "
                            "remediated (different inode)")
        try:
            st = stat_at(dir_fd, name)
        except FileNotFoundError:
            problems.append(f"{target} no longer exists")
            return problems
        if not stat.S_ISREG(st.st_mode):
            raise UnsafePathError(f"{target} is no longer a regular file — refusing")
        current, _ = read_file_at(dir_fd, name)
        if sha256_hex(current) != meta.get("post_sha256"):
            problems.append(f"{target} has changed since it was remediated")
        return problems
    finally:
        os.close(dir_fd)


def rollback(backup_path: str, force: bool = False) -> str:
    """Restore ``backup_path`` to where it came from. Returns a message;
    raises RollbackError or OSError (UnsafePathError) when it won't."""
    backup, meta = _load(backup_path)
    target = meta["original_path"]
    problems = _target_problems(meta)
    if problems and not force:
        raise RollbackError("; ".join(problems) + " — not restoring. Check it, then rerun "
                            "with --force to restore anyway.")
    # Restore relative to a freshly walked directory fd: the checks above
    # (and with --force, the unsafe-state checks again) hold for this fd,
    # and nothing renamed above it afterwards can redirect the write.
    dir_fd, name = open_parent(target)
    try:
        try:
            st = stat_at(dir_fd, name)
            if not stat.S_ISREG(st.st_mode):
                raise UnsafePathError(f"{target} is no longer a regular file — refusing")
        except FileNotFoundError:
            pass
        replace_at(dir_fd, name, backup, meta["mode"], meta["uid"], meta["gid"])
    finally:
        os.close(dir_fd)
    note = f" (forced past: {'; '.join(problems)})" if problems else ""
    return f"Restored {target} from {backup_path}{note}"
