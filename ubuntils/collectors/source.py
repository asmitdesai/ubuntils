from __future__ import annotations

import glob as _glob
import os
import shutil
import stat
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from ubuntils.utils.shell import run_command

# Files in user-controlled locations (shell init files, authorized_keys,
# per-user units) are a few KB. Above USER_FILE_MAX_BYTES one is reported as
# oversized: sshd and bash still honour every line, so padding a file is a
# way to hide a key or backdoor from tools that skip big files. Reading
# stops at USER_FILE_HARD_MAX_BYTES so a 100 GB sparse file can't exhaust
# memory; the oversized marker says the rest went unread.
USER_FILE_MAX_BYTES = 1024 * 1024
USER_FILE_HARD_MAX_BYTES = 64 * 1024 * 1024
# What a collector records when it hits that ceiling: the scan is incomplete.
UNREAD_TAIL_NOTE = "only the first 64 MiB was read; the rest was not checked"
# Ceiling for any single file or command output read back from a bundle
# (bundle/reader.py refuses to extract larger members in the first place).
BUNDLE_READ_MAX_BYTES = 512 * 1024 * 1024


class UnsafeFileError(OSError):
    """A user-controlled file that isn't safe to read as root: not a regular
    file (FIFO, device, socket)."""


@dataclass
class UserFile:
    """A user-controlled file as read: ``text`` holds at most
    USER_FILE_HARD_MAX_BYTES; ``truncated`` means there was more."""
    text: str
    size: int
    truncated: bool = False

    @property
    def oversized(self) -> bool:
        return self.size > USER_FILE_MAX_BYTES


class ArtifactSource(ABC):
    """Decouples *acquisition* (read a file / run a command) from parsing.

    Collectors call these methods with absolute target paths (e.g. "/etc/passwd")
    and never know whether they are reading a live host or a collected bundle.
    """

    @abstractmethod
    def read_text(self, path: str) -> str:
        ...

    @abstractmethod
    def read_bytes(self, path: str) -> bytes:
        ...

    @abstractmethod
    def exists(self, path: str) -> bool:
        ...

    @abstractmethod
    def lstat(self, path: str) -> os.stat_result:
        ...

    @abstractmethod
    def glob(self, pattern: str) -> list[str]:
        ...

    @abstractmethod
    def readlink(self, path: str) -> str:
        """Return a symlink's target text (never follows it). Raises OSError
        when the link isn't available from this source."""
        ...

    @abstractmethod
    def run(self, name: str, argv: list[str], timeout: int = 30) -> tuple[str, str, int]:
        ...

    def sha256_file(self, path: str, max_bytes: int = USER_FILE_HARD_MAX_BYTES) -> Optional[str]:
        """SHA-256 of ``path`` if it is a regular file of at most ``max_bytes``,
        else None. Never blocks on a FIFO and never raises."""
        return None

    def read_user_file(self, path: str) -> UserFile:
        """Read a file a non-root user controls (anything under a home dir).

        Any user can point ~/.bashrc at /dev/zero, make it a FIFO, or a 100 GB
        sparse file — read as root by a plain read_text(), that hangs or
        exhausts memory and blinds the scan. Symlinks are still followed
        (dotfile managers symlink ~/.bashrc), but the target must be a regular
        file (UnsafeFileError otherwise), and at most
        USER_FILE_HARD_MAX_BYTES of it is read.
        """
        data = self.read_bytes(path)
        return UserFile(text=data[:USER_FILE_HARD_MAX_BYTES].decode("utf-8", errors="replace"),
                        size=len(data), truncated=len(data) > USER_FILE_HARD_MAX_BYTES)

    def read_user_text(self, path: str) -> str:
        return self.read_user_file(path).text


class SourceContainmentError(Exception):
    """Raised when a resolved path would escape the configured root (e.g. via
    a symlink inside a mounted --root image pointing outside the image)."""


class LiveSource(ArtifactSource):
    """Reads from a live filesystem tree (root="/" for the running host,
    or a mounted image path for offline --root analysis) and runs commands live.

    ``offline`` marks a genuinely offline --root analysis (a mounted/extracted
    image, not the live host) — in that mode ``run()`` never executes a real
    command, since there is no live process/kernel state to query against a
    dead image. Live ``scan``/`collect`` (root="/") always leaves this False.
    """

    def __init__(self, root: str = "/", offline: bool = False):
        self.root = root.rstrip("/") or "/"
        self.offline = offline

    def _resolve(self, path: str) -> str:
        # path is a target-absolute path like "/etc/passwd"; join under root.
        resolved = os.path.join(self.root, path.lstrip("/"))
        if self.root != "/":
            # Genuine --root (mounted image) analysis: verify a symlink inside
            # the image can't walk us out to the analyst's real filesystem.
            root_real = os.path.realpath(self.root)
            resolved_real = os.path.realpath(resolved)
            if resolved_real != root_real and not resolved_real.startswith(root_real + os.sep):
                raise SourceContainmentError(
                    f"path {path!r} resolves outside --root {self.root!r} "
                    f"(resolved to {resolved_real!r}) — refusing to follow"
                )
        return resolved

    def read_text(self, path: str) -> str:
        with open(self._resolve(path), encoding="utf-8", errors="replace") as f:
            return f.read()

    def read_bytes(self, path: str) -> bytes:
        with open(self._resolve(path), "rb") as f:
            return f.read()

    def sha256_file(self, path: str, max_bytes: int = USER_FILE_HARD_MAX_BYTES) -> Optional[str]:
        # Symlinks are followed: /proc/<pid>/exe must reach the running
        # binary (even a deleted one). O_NONBLOCK and the fstat check on the
        # opened fd keep a FIFO or device from hanging or flooding the scan.
        try:
            fd = os.open(self._resolve(path), os.O_RDONLY | os.O_NONBLOCK)
        except (OSError, ValueError):
            return None
        return _hash_fd(fd, max_bytes)

    def read_user_file(self, path: str) -> UserFile:
        # O_NONBLOCK: opening a FIFO would otherwise block forever. The type
        # check runs on the opened fd, so a swap after the check can't
        # redirect the read. Lines are streamed up to the hard ceiling.
        fd = os.open(self._resolve(path), os.O_RDONLY | os.O_NONBLOCK)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise UnsafeFileError(f"{path}: not a regular file — not read")
            os.set_blocking(fd, True)
            with os.fdopen(fd, "rb") as f:
                fd = -1  # now owned by f
                chunks, total = [], 0
                # readline(limit): a sparse file of zeros is one endless line.
                while total < USER_FILE_HARD_MAX_BYTES:
                    line = f.readline(USER_FILE_HARD_MAX_BYTES - total)
                    if not line:
                        break
                    chunks.append(line)
                    total += len(line)
                truncated = total >= USER_FILE_HARD_MAX_BYTES and bool(f.read(1))
        finally:
            if fd != -1:
                os.close(fd)
        data = b"".join(chunks)
        # A file that grew after the fstat is as big as what we read.
        size = max(st.st_size, len(data) + (1 if truncated else 0))
        return UserFile(text=data.decode("utf-8", errors="replace"), size=size,
                        truncated=truncated)

    def exists(self, path: str) -> bool:
        try:
            return os.path.exists(self._resolve(path))
        except SourceContainmentError:
            return False

    def lstat(self, path: str) -> os.stat_result:
        return os.lstat(self._resolve(path))

    def glob(self, pattern: str) -> list[str]:
        resolved = self._resolve(pattern)
        prefix = self.root if self.root != "/" else ""
        results = []
        for hit in sorted(_glob.glob(resolved)):
            # Map back to a target-absolute path (strip the root prefix).
            results.append(hit[len(prefix):] if prefix and hit.startswith(prefix) else hit)
        return results

    def readlink(self, path: str) -> str:
        # Resolve (and containment-check) only the parent directory: realpath
        # on the link itself would follow it, e.g. /proc/<pid>/exe.
        parent, name = os.path.split(path.rstrip("/"))
        return os.readlink(os.path.join(self._resolve(parent or "/"), name))

    def run(self, name: str, argv: list[str], timeout: int = 30) -> tuple[str, str, int]:
        if self.offline:
            return "", "command execution disabled for offline --root analysis", -1
        return run_command(argv, timeout=timeout)


_STAT_SEQUENCE_NAMES = {"st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size"}


def _with_times(st: os.stat_result, mtime: float, ctime: float) -> os.stat_result:
    """A copy of ``st`` with its mtime and ctime replaced."""
    seq = list(st)
    seq[8], seq[9] = int(mtime), int(ctime)
    extra = {n: getattr(st, n) for n in dir(st)
             if n.startswith("st_") and n not in _STAT_SEQUENCE_NAMES}
    extra.update(st_mtime=float(mtime), st_ctime=float(ctime),
                 st_mtime_ns=int(mtime * 1e9), st_ctime_ns=int(ctime * 1e9))
    return os.stat_result(seq, extra)


def _hash_fd(fd: int, max_bytes: int) -> Optional[str]:
    import hashlib
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        h, total = hashlib.sha256(), 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                return h.hexdigest()
            total += len(chunk)
            if total > max_bytes:
                return None
            h.update(chunk)
    except OSError:
        return None
    finally:
        os.close(fd)


def _read_capped(path: str) -> bytes:
    """Read a file from an extracted bundle, refusing one over
    BUNDLE_READ_MAX_BYTES."""
    limit = BUNDLE_READ_MAX_BYTES
    with open(path, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise UnsafeFileError(f"{path}: larger than {limit} bytes — not read")
    return data


class BundleSource(ArtifactSource):
    """Reads files captured into a bundle and replays captured command output.
    Never touches the live host or runs a command — pure offline replay."""

    def __init__(self, root_dir: str, command_index: dict, cleanup_dir: str | None = None,
                 file_times: dict | None = None):
        """``command_index`` maps a command name to its captured-output path,
        or to a ``(path, exit_code)`` tuple recording how the command exited at
        collection time. ``cleanup_dir``, if given, is removed by cleanup().
        ``file_times`` maps a captured file's source path to the ``(mtime,
        ctime)`` it had on the collected host."""
        self.root_dir = root_dir.rstrip("/")
        self.command_index = command_index
        self._cleanup_dir = cleanup_dir
        self.file_times = file_times or {}

    def cleanup(self) -> None:
        """Delete the extracted bundle (it may contain /etc/shadow)."""
        if self._cleanup_dir:
            shutil.rmtree(self._cleanup_dir, ignore_errors=True)
            self._cleanup_dir = None

    def _resolve(self, path: str) -> str:
        # Paths come from the bundle itself (home directories in its
        # /etc/passwd, include targets in its sudoers…), so a hostile bundle
        # could otherwise climb out with "/../../home/analyst/.ssh/…" and get
        # the analyst's own files read into the report.
        root = os.path.realpath(self.root_dir)
        resolved = os.path.realpath(os.path.join(root, path.lstrip("/")))
        if resolved != root and not resolved.startswith(root + os.sep):
            raise SourceContainmentError(
                f"path {path!r} resolves outside the bundle — refusing to read it"
            )
        return resolved

    def read_text(self, path: str) -> str:
        return self.read_bytes(path).decode("utf-8", errors="replace")

    def read_bytes(self, path: str) -> bytes:
        return _read_capped(self._resolve(path))

    def sha256_file(self, path: str, max_bytes: int = USER_FILE_HARD_MAX_BYTES) -> Optional[str]:
        # The extracted copy is the collected file; bundles hold no links
        # or devices (reader._safe_extract), but check anyway.
        try:
            fd = os.open(self._resolve(path), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        except (OSError, ValueError):
            return None
        return _hash_fd(fd, max_bytes)

    def exists(self, path: str) -> bool:
        try:
            return os.path.exists(self._resolve(path))
        except SourceContainmentError:
            return False

    def lstat(self, path: str) -> os.stat_result:
        # The extracted copy's times are when it was collected/extracted, not
        # when the host's file last changed — rules that ask "modified in the
        # last 48 hours?" need the times the manifest recorded.
        st = os.lstat(self._resolve(path))
        times = self.file_times.get(os.path.normpath("/" + path.lstrip("/")))
        return _with_times(st, *times) if times else st

    def glob(self, pattern: str) -> list[str]:
        try:
            resolved = self._resolve(pattern)
        except SourceContainmentError:
            return []
        root = os.path.realpath(self.root_dir)
        return ["/" + os.path.relpath(hit, root) for hit in sorted(_glob.glob(resolved))]

    def readlink(self, path: str) -> str:
        # Bundles never contain symlinks (the reader rejects them), and
        # /proc is not captured — there is no link target to replay.
        raise OSError(f"symlink targets are not captured in bundles: {path}")

    def run(self, name: str, argv: list[str], timeout: int = 30) -> tuple[str, str, int]:
        captured = self.command_index.get(name)
        if captured is None:
            return "", f"command '{name}' not captured in bundle", -1
        exit_code = 0
        if isinstance(captured, (tuple, list)):
            captured, exit_code = captured
        # Replay the recorded exit code: a command that timed out during
        # `collect` (-1) must not replay as a successful empty result.
        return _read_capped(captured).decode("utf-8", errors="replace"), "", exit_code
