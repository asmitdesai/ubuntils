from __future__ import annotations

import platform
import time

import structlog
from textual import work
from textual.app import App, ComposeResult
from textual.message import Message

from ubuntils.collectors import ALL_COLLECTORS
from ubuntils.detectors.engine import DetectionEngine
from ubuntils.detectors.finding import Finding, Severity
from ubuntils.timeline.builder import TimelineBuilder, TimelineEvent
from ubuntils.tui.results_screen import ResultsScreen
from ubuntils.tui.scan_screen import ScanScreen
from ubuntils.tui.stats_panel import get_ubuntu_version

logger = structlog.get_logger()


class CollectorProgress(Message):
    def __init__(self, name: str, index: int, total: int, success: bool = True) -> None:
        self.name = name
        self.index = index
        self.total = total
        self.success = success
        super().__init__()


class ScanComplete(Message):
    def __init__(
        self,
        findings: list[Finding],
        timeline: list[TimelineEvent],
        stats: dict,
    ) -> None:
        self.findings = findings
        self.timeline = timeline
        self.stats = stats
        super().__init__()


class UbuntilsApp(App):
    TITLE = "ubuntils"

    def __init__(self, verbose: bool = False, _scan_override=None) -> None:
        super().__init__()
        self._verbose = verbose
        self._scan_override = _scan_override

    def on_mount(self) -> None:
        self.push_screen(
            ScanScreen(collector_names=[C.__name__ for C in ALL_COLLECTORS])
        )
        self._run_scan()

    @work(thread=True)
    def _run_scan(self) -> None:
        if self._scan_override is not None:
            findings, timeline, stats = self._scan_override()
            self.post_message(ScanComplete(findings=findings, timeline=timeline, stats=stats))
            return

        start = time.monotonic()
        artifacts: dict = {}
        failures = 0
        collectors = [C() for C in ALL_COLLECTORS]

        for i, collector in enumerate(collectors):
            name = type(collector).__name__
            success = True
            try:
                result = collector.collect()
                artifacts.update(result)
            except Exception as exc:
                logger.error("collector_failed", name=name, error=str(exc))
                failures += 1
                success = False
            self.post_message(
                CollectorProgress(name=name, index=i + 1, total=len(collectors), success=success)
            )

        try:
            findings = DetectionEngine().run(artifacts)
            timeline = TimelineBuilder().build()
        except Exception as exc:
            logger.error("scan_engine_failed", error=str(exc))
            findings = []
            timeline = []

        duration = time.monotonic() - start

        stats = {
            "ubuntu_version": get_ubuntu_version(),
            "architecture": platform.machine(),
            "duration_s": duration,
            "collector_count": len(collectors),
            "collector_failures": failures,
            "finding_counts": {
                "HIGH": sum(1 for f in findings if f.severity == Severity.HIGH),
                "MEDIUM": sum(1 for f in findings if f.severity == Severity.MEDIUM),
                "LOW": sum(1 for f in findings if f.severity == Severity.LOW),
            },
            "timeline_count": len(timeline),
        }
        self.post_message(
            ScanComplete(findings=findings, timeline=timeline, stats=stats)
        )

    def on_collector_progress(self, message: CollectorProgress) -> None:
        screen = self.screen
        if isinstance(screen, ScanScreen):
            screen.mark(message.name, message.success)

    def on_scan_complete(self, message: ScanComplete) -> None:
        self.switch_screen(
            ResultsScreen(
                findings=message.findings,
                timeline=message.timeline,
                stats=message.stats,
            )
        )
