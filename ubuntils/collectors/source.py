from __future__ import annotations

import glob as _glob
import os
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
    def exists(self, path: str) -> bool:
        ...

    @abstractmethod
    def lstat(self, path: str) -> os.stat_result:
        ...

    @abstractmethod
    def glob(self, pattern: str) -> list[str]:
        ...

    @abstractmethod
    def run(self, name: str, argv: list[str], timeout: int = 30) -> tuple[str, str, int]:
        ...


class LiveSource(ArtifactSource):
    """Reads from a live filesystem tree (root="/" for the running host,
    or a mounted image path for offline --root analysis) and runs commands live."""

    def __init__(self, root: str = "/"):
        self.root = root.rstrip("/") or "/"

    def _resolve(self, path: str) -> str:
        # path is a target-absolute path like "/etc/passwd"; join under root.
        return os.path.join(self.root, path.lstrip("/"))

    def read_text(self, path: str) -> str:
        with open(self._resolve(path), encoding="utf-8", errors="replace") as f:
            return f.read()

    def exists(self, path: str) -> bool:
        return os.path.exists(self._resolve(path))

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

    def run(self, name: str, argv: list[str], timeout: int = 30) -> tuple[str, str, int]:
        return run_command(argv, timeout=timeout)
