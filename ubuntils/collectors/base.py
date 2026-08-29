from __future__ import annotations

from abc import ABC, abstractmethod

from ubuntils.collectors.source import ArtifactSource, LiveSource


class BaseCollector(ABC):
    def __init__(self, source: ArtifactSource | None = None):
        self.source = source if source is not None else LiveSource()

    @abstractmethod
    def collect(self) -> dict:
        """
        Collect forensic artifacts.
        Returns a dict of collected data.
        Must not raise — log exceptions and return {}.
        """
