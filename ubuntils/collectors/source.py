from __future__ import annotations

import glob as _glob
import os
import shutil
from abc import ABC, abstractmethod

from ubuntils.utils.shell import run_command


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


class BundleSource(ArtifactSource):
    """Reads files captured into a bundle and replays captured command output.
    Never touches the live host or runs a command — pure offline replay."""

    def __init__(self, root_dir: str, command_index: dict, cleanup_dir: str | None = None):
        """``command_index`` maps a command name to its captured-output path,
        or to a ``(path, exit_code)`` tuple recording how the command exited at
        collection time. ``cleanup_dir``, if given, is removed by cleanup()."""
        self.root_dir = root_dir.rstrip("/")
        self.command_index = command_index
        self._cleanup_dir = cleanup_dir

    def cleanup(self) -> None:
        """Delete the extracted bundle (it may contain /etc/shadow)."""
        if self._cleanup_dir:
            shutil.rmtree(self._cleanup_dir, ignore_errors=True)
            self._cleanup_dir = None

    def _resolve(self, path: str) -> str:
        return os.path.join(self.root_dir, path.lstrip("/"))

    def read_text(self, path: str) -> str:
        with open(self._resolve(path), encoding="utf-8", errors="replace") as f:
            return f.read()

    def read_bytes(self, path: str) -> bytes:
        with open(self._resolve(path), "rb") as f:
            return f.read()

    def exists(self, path: str) -> bool:
        return os.path.exists(self._resolve(path))

    def lstat(self, path: str) -> os.stat_result:
        return os.lstat(self._resolve(path))

    def glob(self, pattern: str) -> list[str]:
        resolved = self._resolve(pattern)
        results = []
        for hit in sorted(_glob.glob(resolved)):
            results.append("/" + os.path.relpath(hit, self.root_dir))
        return results

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
