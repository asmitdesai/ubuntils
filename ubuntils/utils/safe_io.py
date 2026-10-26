"""Symlink-safe creation of output files written as root.

A plain open(path, "w") as root follows a symlink pre-planted at ``path`` and
truncates whatever it points to. Every root-run output write (JSON reports,
bundles) goes through open_private_for_write instead — the same O_NOFOLLOW
standard remediators/base.py holds for remediation I/O.
"""
from __future__ import annotations

import os
import stat


def open_private_for_write(path: str, mode: int = 0o600, new_owner=None) -> int:
    """Open ``path`` for writing, owner-only, never following a symlink.

    Refuses symlinks (O_NOFOLLOW) and anything that isn't a regular file
    (FIFOs, devices). Truncation happens only after the opened fd is verified
    to be a regular file, and permissions are set on the fd (fchmod), not the
    path, so nothing can be redirected between check and use.
    ``new_owner`` (uid, gid) is applied only when this call creates the
    file — an existing file is never handed to anyone.
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
        fd = os.open(path, flags, mode)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"refusing to write to non-regular file: {path}")
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


def write_private_text(path: str, text: str, mode: int = 0o600, new_owner=None) -> None:
    fd = open_private_for_write(path, mode, new_owner)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
