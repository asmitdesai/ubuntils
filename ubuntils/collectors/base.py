from __future__ import annotations

from abc import ABC, abstractmethod

from ubuntils.collectors.source import ArtifactSource, LiveSource


class BaseCollector(ABC):
    def __init__(self, source: ArtifactSource | None = None):
        self.source = source if source is not None else LiveSource()
        # Human-readable reasons this collector's output is incomplete (a
        # command that failed, an unreadable file). The pipeline reports these
        # as `collectors_degraded`, so "couldn't look" never reads as "clean".
        self.degraded: list[str] = []

    @abstractmethod
    def collect(self) -> dict:
        """
        Collect forensic artifacts.
        Returns a dict of collected data.
        Must not raise — log exceptions and return {}.
        """
