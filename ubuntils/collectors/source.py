from __future__ import annotations

import glob as _glob
import os
import shutil
import stat
from abc import ABC, abstractmethod

from ubuntils.utils.shell import run_command

# Ceiling for files in user-controlled locations (shell init files,
# authorized_keys, per-user units). Real ones are a few KB.
USER_FILE_MAX_BYTES = 1024 * 1024


class UnsafeFileError(OSError):
    """A user-controlled file that isn't safe to read as root: not a regular
    file (FIFO, device, socket) or larger than USER_FILE_MAX_BYTES."""


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

    def read_user_text(self, path: str, max_bytes: int = USER_FILE_MAX_BYTES) -> str:
        """Read a file a non-root user controls (anything under a home dir).

        Any user can point ~/.bashrc at /dev/zero, make it a FIFO, or a 100 GB
        sparse file — read as root by a plain read_text(), that hangs or
        exhausts memory and blinds the scan. Symlinks are still followed
        (dotfile managers symlink ~/.bashrc), but the target must be a regular
        file of at most ``max_bytes``. Raises UnsafeFileError otherwise.
        """
        text = self.read_text(path)
        if len(text) > max_bytes:
            raise UnsafeFileError(f"{path}: larger than {max_bytes} bytes — not read")
        return text


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

    def read_user_text(self, path: str, max_bytes: int = USER_FILE_MAX_BYTES) -> str:
        # O_NONBLOCK: opening a FIFO would otherwise block forever. The type
        # and size checks run on the opened fd, so a swap after the check
        # can't redirect the read.
        fd = os.open(self._resolve(path), os.O_RDONLY | os.O_NONBLOCK)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise UnsafeFileError(f"{path}: not a regular file — not read")
            if st.st_size > max_bytes:
                raise UnsafeFileError(f"{path}: larger than {max_bytes} bytes — not read")
            os.set_blocking(fd, True)
            with os.fdopen(fd, "rb") as f:
                fd = -1  # now owned by f
                data = f.read(max_bytes + 1)
        finally:
            if fd != -1:
                os.close(fd)
        if len(data) > max_bytes:  # grew after the fstat
            raise UnsafeFileError(f"{path}: larger than {max_bytes} bytes — not read")
        return data.decode("utf-8", errors="replace")

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
        with open(self._resolve(path), encoding="utf-8", errors="replace") as f:
            return f.read()

    def read_bytes(self, path: str) -> bytes:
        with open(self._resolve(path), "rb") as f:
            return f.read()

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
        with open(captured, encoding="utf-8", errors="replace") as f:
            # Replay the recorded exit code: a command that timed out during
            # `collect` (-1) must not replay as a successful empty result.
            return f.read(), "", exit_code
