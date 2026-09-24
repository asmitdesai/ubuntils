from __future__ import annotations

import structlog
from textual import work
from textual.app import App, ComposeResult
from textual.message import Message

from ubuntils.collectors import ALL_COLLECTORS
from ubuntils.collectors.source import LiveSource
from ubuntils.detectors.finding import Finding, RemediationResult
from ubuntils.pipeline import run_scan
from ubuntils.timeline.builder import TimelineEvent
from ubuntils.tui.results_screen import ResultsScreen
from ubuntils.tui.scan_screen import ScanScreen

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
        remediation_results: list[RemediationResult] | None = None,
    ) -> None:
        self.findings = findings
        self.timeline = timeline
        self.stats = stats
        self.remediation_results = remediation_results or []
        super().__init__()


class UbuntilsApp(App):
    TITLE = "ubuntils"

    def __init__(self, verbose: bool = False, _scan_override=None,
                 allowlist=None, since=None, custom_rules=None, baseline=None,
                 forward_wazuh: bool = True) -> None:
        super().__init__()
        self._verbose = verbose
        self._scan_override = _scan_override
        self._allowlist = allowlist
        self._since = since
        self._custom_rules = custom_rules
        self._baseline = baseline
        self._forward_wazuh = forward_wazuh

    def on_mount(self) -> None:
        self.push_screen(
            ScanScreen(collector_names=[C.__name__ for C in ALL_COLLECTORS])
        )
        self._run_scan()

    @work(thread=True)
    def _run_scan(self) -> None:
        if self._scan_override is not None:
            # Overrides return (findings, timeline, stats[, remediation_results]).
            result = tuple(self._scan_override())
            findings, timeline, stats = result[:3]
            remediation_results = result[3] if len(result) > 3 else []
            self.post_message(ScanComplete(findings=findings, timeline=timeline, stats=stats,
                                           remediation_results=remediation_results))
            return

        def _progress(name: str, index: int, total: int, success: bool) -> None:
            self.post_message(
                CollectorProgress(name=name, index=index, total=total, success=success)
            )

        result = run_scan(
            LiveSource(root="/"),
            allowlist=self._allowlist,
            since=self._since,
            custom_rules=self._custom_rules,
            baseline=self._baseline,
            forward_wazuh=self._forward_wazuh,
            on_progress=_progress,
        )
        self.post_message(
            ScanComplete(findings=result.findings, timeline=result.timeline, stats=result.stats)
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
                remediation_results=message.remediation_results,
            )
        )
