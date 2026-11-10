"""Path resolution that never follows a symlink, in any component.

O_NOFOLLOW only protects the *last* component of a path. If an attacker can
swap a parent directory — /home/alice/.ssh for a symlink to
/home/admin/.ssh — between detection and remediation, every open(), mkstemp()
and rename() by path silently operates on the admin's files instead.

open_dir_nofollow walks from "/" one component at a time, each opened
relative to the previous directory's fd with O_NOFOLLOW, so a symlink
anywhere in the path is refused. Everything after that (reads, the temp file,
fchmod/fchown, rename) happens relative to the returned directory fd: once
we hold it, renaming or replacing directories above it can't redirect us.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import stat

# Linux has O_PATH (no read permission needed, can't be read from); elsewhere
# (macOS, for tests) a read-only directory open does the same job.
_DIR_FLAGS = (getattr(os, "O_PATH", 0) or os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW


class UnsafePathError(OSError):
    """A path component is a symlink or not a directory, or a file isn't
    the one we expected."""


def open_dir_nofollow(path: str) -> int:
    """Open directory ``path`` without following a symlink in any component.
    Returns a directory fd (caller closes it). Raises UnsafePathError."""
    if not os.path.isabs(path):
        raise UnsafePathError(f"{path!r}: not an absolute path")
    parts = [p for p in path.split("/") if p]
    if ".." in parts:
        raise UnsafePathError(f"{path!r}: '..' is not allowed")
    fd = os.open("/", _DIR_FLAGS)
    try:
        walked = ""
        for part in parts:
            if part == ".":
                continue
            walked += "/" + part
            try:
                next_fd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except OSError as exc:
                raise UnsafePathError(
                    f"{walked} is a symlink or not a directory — refusing to "
                    f"follow it ({exc.strerror})") from exc
            os.close(fd)
            fd = next_fd
            # O_PATH|O_NOFOLLOW can return an fd for the symlink itself on
            # some kernels; make sure we really hold a directory.
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                raise UnsafePathError(f"{walked} is not a directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_parent(path: str):
    """(dir_fd, name) for ``path``'s parent directory, opened with
    open_dir_nofollow. The caller closes dir_fd."""
    parent, name = os.path.split(os.path.normpath(path))
    if not name:
        raise UnsafePathError(f"{path!r} has no file name")
    return open_dir_nofollow(parent or "/"), name


def dir_identity(dir_fd: int) -> tuple:
    st = os.fstat(dir_fd)
    return (st.st_dev, st.st_ino, st.st_uid)


def read_file_at(dir_fd: int, name: str) -> tuple:
    """(bytes, stat) of regular file ``name`` in ``dir_fd``. A symlink or
    anything but a regular file raises UnsafePathError; a missing file
    raises FileNotFoundError."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                     dir_fd=dir_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        if stat.S_ISLNK(stat_at(dir_fd, name).st_mode):
            raise UnsafePathError(f"{name} is a symlink — refusing to follow it") from exc
        raise
    # Check before wrapping the fd: fdopen() of a directory raises
    # IsADirectoryError itself, which skipped this check and leaked the fd.
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise UnsafePathError(f"{name}: not a regular file")
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "rb") as f:
        return f.read(), st


def stat_at(dir_fd: int, name: str) -> os.stat_result:
    """lstat of ``name`` in ``dir_fd``."""
    return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)


def create_exclusive_at(dir_fd: int, name: str, data: bytes, mode: int = 0o600) -> None:
    """Create ``name`` in ``dir_fd`` (O_EXCL: never an existing file or link)."""
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode,
                 dir_fd=dir_fd)
    with os.fdopen(fd, "wb") as f:
        os.fchmod(f.fileno(), mode)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def replace_at(dir_fd: int, name: str, data: bytes, mode: int, uid: int, gid: int) -> None:
    """Atomically replace ``name`` in ``dir_fd`` with ``data``.

    The new content goes to a randomly named sibling created O_EXCL|O_NOFOLLOW
    in the same directory fd, gets ``mode``/owner via fchmod/fchown, is
    fsync'd, and is renamed over ``name`` within that directory fd. A crash
    mid-write leaves the original intact, and rename() replaces the directory
    entry itself — it never follows a symlink swapped in at ``name``.
    """
    for _ in range(100):
        tmp = f".ubuntils-{secrets.token_hex(8)}"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                         dir_fd=dir_fd)
            break
        except FileExistsError:
            continue
    else:
        raise FileExistsError("could not create a temporary file")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fchmod(f.fileno(), stat.S_IMODE(mode))
            if (uid, gid) != (os.geteuid(), os.getegid()):
                os.fchown(f.fileno(), uid, gid)
            os.fsync(f.fileno())
        os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dir_fd)
        except OSError:
            pass
        raise


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
