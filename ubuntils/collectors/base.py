from __future__ import annotations

import os
from abc import ABC, abstractmethod

from ubuntils.collectors.source import ArtifactSource, LiveSource


class BaseCollector(ABC):
    def __init__(self, source: ArtifactSource | None = None):
        self.source = source if source is not None else LiveSource()
        # Human-readable reasons this collector's output is incomplete (a
        # command that failed, an unreadable file). The pipeline reports these
        # as `collectors_degraded`, so "couldn't look" never reads as "clean".
        self.degraded: list[str] = []
        self._parent_ids: dict = {}

    def tag_parent_dirs(self, entries: list, key: str) -> list:
        """Record [st_dev, st_ino, st_uid] of each entry's file's parent
        directory as ``parent_dir_id``, so remediation can tell whether the
        directory it is about to write in is still the one that was read."""
        for entry in entries:
            path = entry.get(key)
            if not path:
                continue
            directory = os.path.dirname(path)
            if directory not in self._parent_ids:
                try:
                    st = self.source.lstat(directory)
                    self._parent_ids[directory] = [st.st_dev, st.st_ino, st.st_uid]
                except Exception:
                    self._parent_ids[directory] = None
            entry["parent_dir_id"] = self._parent_ids[directory]
        return entries

    @abstractmethod
    def collect(self) -> dict:
        """
        Collect forensic artifacts.
        Returns a dict of collected data.
        Must not raise — log exceptions and return {}.
        """
