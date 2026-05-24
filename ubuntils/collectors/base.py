from abc import ABC, abstractmethod


class BaseCollector(ABC):
    @abstractmethod
    def collect(self) -> dict:
        """
        Collect forensic artifacts.
        Returns a dict of collected data.
        Must not raise — log exceptions and return {}.
        """
