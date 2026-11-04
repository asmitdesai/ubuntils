"""Symlink-safe creation of output files written as root.

A plain open(path, "w") as root follows a symlink pre-planted at ``path`` and
truncates whatever it points to. Every root-run output write (JSON reports,
bundles) goes through open_private_for_write instead — the same O_NOFOLLOW
standard remediators/base.py holds for remediation I/O.

O_NOFOLLOW alone isn't enough when ``path`` already exists: a file another
user pre-created is still theirs after we fchmod it, so they could read what
root wrote into it; and a hard link to /etc/shadow is a regular file that
O_NOFOLLOW happily opens. Existing files are therefore only reused when they
belong to us (or the user who ran sudo) and have exactly one link, and
callers that write secrets (bundles) never reuse one at all.
"""
from __future__ import annotations

import os
import stat


def open_private_for_write(path: str, mode: int = 0o600, new_owner=None,
                           exclusive: bool = False, trusted_uids=()) -> int:
    """Open ``path`` for writing, owner-only, never following a symlink.

    Refuses symlinks (O_NOFOLLOW) and anything that isn't a regular file
    (FIFOs, devices). Truncation happens only after the opened fd is verified,
    and permissions are set on the fd (fchmod), not the path, so nothing can
    be redirected between check and use.

    A file this call creates is handed to ``new_owner`` (uid, gid) if given.
    An existing file is used only if ``exclusive`` is false, it is owned by
    our euid, ``new_owner``'s uid or one of ``trusted_uids``, and it has a
    single link; it keeps its owner. Otherwise OSError is raised
    (FileExistsError for ``exclusive``) and the file is left untouched.
    Returns a raw fd opened O_WRONLY.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK  # never block on a FIFO planted at `path`
    created = False
    try:
        fd = os.open(path, flags | os.O_EXCL, mode)
        created = True
    except FileExistsError:
        if exclusive:
            raise FileExistsError(
                f"{path} already exists — refusing to write into a file this run "
                "didn't create; choose a new path")
        fd = os.open(path, flags & ~os.O_CREAT, mode)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"refusing to write to non-regular file: {path}")
        if not created:
            allowed = {os.geteuid(), *trusted_uids}
            if new_owner is not None:
                allowed.add(new_owner[0])
            if st.st_uid not in allowed:
                raise OSError(
                    f"refusing to write to {path}: it already exists and is owned by "
                    f"uid {st.st_uid}, who could read what is written to it")
            if st.st_nlink != 1:
                raise OSError(
                    f"refusing to write to {path}: it has {st.st_nlink} hard links, "
                    "so writing it would change another file too")
        if hasattr(os, "O_NONBLOCK"):
            os.set_blocking(fd, True)
        os.fchmod(fd, mode)
        if created and new_owner is not None:
            os.fchown(fd, *new_owner)
        os.ftruncate(fd, 0)
    except BaseException:
        os.close(fd)
        raise
    return fd


def write_private_text(path: str, text: str, mode: int = 0o600, new_owner=None,
                       trusted_uids=()) -> None:
    fd = open_private_for_write(path, mode, new_owner, trusted_uids=trusted_uids)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def ensure_private_dir(path: str, mode: int = 0o700) -> None:
    """Create ``path`` (and missing parents) owned by us with ``mode``, and
    refuse it if it — or any component we'd create into — is a symlink, isn't
    a directory, is owned by someone else, or is writable by group/others.

    Used for root's own output directories (e.g. /var/lib/ubuntils/bundles),
    where an attacker who pre-created the directory or a symlink to their own
    could otherwise read or swap what root writes there.
    """
    path = os.path.abspath(path)
    parent = os.path.dirname(path)
    if parent != path and not os.path.isdir(parent):
        ensure_private_dir(parent, mode)
    try:
        os.mkdir(path, mode)
    except FileExistsError:
        pass
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise OSError(f"refusing to use {path}: not a plain directory ({exc})") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise OSError(f"refusing to use {path}: not a directory")
        if st.st_uid != os.geteuid():
            raise OSError(f"refusing to use {path}: owned by uid {st.st_uid}")
        if st.st_mode & 0o022:
            raise OSError(f"refusing to use {path}: writable by group or others")
        os.fchmod(fd, mode)
    finally:
        os.close(fd)
