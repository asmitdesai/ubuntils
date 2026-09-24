"""The one scan pipeline: collect → detect → timeline → correlate → (remediate).

Shared by the CLI (`scan --json`, `scan --remediate`, `analyze`) and the TUI's
live scan worker, so the two can never drift apart again.

Failure isolation is deliberate: a collector, a rule, or the timeline can each
fail without zeroing anything else, and every such failure is recorded in the
report (`collectors_degraded`, `rules_failed`, `timeline_error`) — for an IR
tool, "collection failed" must never look the same as "clean".
"""
from __future__ import annotations

import platform
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, List, Optional

import structlog

from ubuntils import __version__
from ubuntils.collectors import ALL_COLLECTORS
from ubuntils.collectors.source import ArtifactSource, LiveSource
from ubuntils.detectors.engine import DetectionEngine
from ubuntils.detectors.finding import (
    Finding, RemediationResult, RemediationStatus, Severity,
)
from ubuntils.detectors.scoring import apply_signal
from ubuntils.integrations.wazuh import is_wazuh_agent_present, write_wazuh_alerts
from ubuntils.remediators import REMEDIATOR_REGISTRY
from ubuntils.timeline.builder import TimelineBuilder
from ubuntils.timeline.correlator import correlate
from ubuntils.utils.host import get_hostname, get_ubuntu_version

logger = structlog.get_logger()

# Collectors that acquire artifacts by shelling out to a command (as opposed
# to reading files) — these cannot produce meaningful data against a dead,
# mounted image (there is no live process/kernel state to query with `ss` or
# `systemctl`), so they are skipped with a note rather than silently
# contaminating the report with the analyst's own host's live state.
COMMAND_BASED_COLLECTOR_NAMES = [
    "NetworkCollector", "SystemdCollector", "PackageCollector", "KernelCollector",
]

# Findings below this confidence are never auto-remediated by
# `scan --remediate --confirm` (the LOW band is < 40).
DEFAULT_MIN_REMEDIATION_CONFIDENCE = 40

ProgressCallback = Callable[[str, int, int, bool], None]


@dataclass
class ScanResult:
    findings: List[Finding]
    timeline: list
    stats: dict
    scan_metadata: dict
    artifact_counts: dict
    remediation_results: List[RemediationResult] = field(default_factory=list)


def _is_live(source: ArtifactSource) -> bool:
    return isinstance(source, LiveSource) and not getattr(source, "offline", False)


def _count_artifacts(result: dict) -> int:
    # bool values are status flags (e.g. dpkg_verify_collection_failed), not
    # artifacts — counting them as 1 inflated the totals.
    return sum(
        len(v) if isinstance(v, (list, dict)) else 1
        for v in result.values()
        if not isinstance(v, bool)
    )


def remediate_findings(findings: List[Finding], confirm: bool,
                       min_confidence: int = DEFAULT_MIN_REMEDIATION_CONFIDENCE
                       ) -> List[RemediationResult]:
    results = []
    for finding in findings:
        remediator_cls = REMEDIATOR_REGISTRY.get(finding.rule_id)
        if remediator_cls is None or not finding.remediation_available:
            continue
        if finding.confidence < min_confidence:
            result = RemediationResult(
                finding_rule_id=finding.rule_id,
                status=RemediationStatus.SKIPPED,
                message=(
                    f"confidence {finding.confidence} is below the remediation gate "
                    f"({min_confidence}) — review manually or lower --min-confidence"
                ),
            )
        else:
            result = remediator_cls().remediate(finding, dry_run=not confirm)
        results.append(result)
        logger.info(
            "remediation",
            rule_id=finding.rule_id,
            status=result.status.value,
            message=result.message,
            confidence=finding.confidence,
            confidence_band=finding.confidence_band,
            backup_path=result.backup_path,
            rollback_command=result.rollback_command,
        )
    return results


def run_scan(
    source: ArtifactSource,
    *,
    allowlist=None,
    since=None,
    custom_rules=None,
    baseline=None,
    bundle_info: Optional[dict] = None,
    remediate: bool = False,
    confirm: bool = False,
    min_confidence: int = DEFAULT_MIN_REMEDIATION_CONFIDENCE,
    forward_wazuh: bool = True,
    on_progress: Optional[ProgressCallback] = None,
) -> ScanResult:
    start = time.monotonic()
    artifacts: dict = {}
    artifact_counts: dict = {}
    failures = 0
    collectors_degraded: dict = {}
    collectors = [C(source=source) for C in ALL_COLLECTORS]

    # Only a genuine --root (offline LiveSource over a mounted/extracted
    # image) has *no* command output available — LiveSource.run() disables
    # execution entirely in that mode. A BundleSource replays real captured
    # command output, so its collectors are NOT "skipped".
    is_offline_root = isinstance(source, LiveSource) and getattr(source, "offline", False)
    command_collectors_skipped = list(COMMAND_BASED_COLLECTOR_NAMES) if is_offline_root else []

    for i, collector in enumerate(collectors):
        name = type(collector).__name__
        success = True
        try:
            result = collector.collect()
            artifacts.update(result)
            artifact_counts[name] = _count_artifacts(result)
        except Exception as exc:
            logger.error("collector_failed", name=name, error=str(exc))
            failures += 1
            success = False
            collectors_degraded[name] = [f"collector raised: {exc}"]
        reasons = list(getattr(collector, "degraded", []) or [])
        if reasons and name not in command_collectors_skipped:
            collectors_degraded.setdefault(name, []).extend(reasons)
        if on_progress is not None:
            on_progress(name, i + 1, len(collectors), success)

    # Detection and timeline are isolated: a timeline failure must never
    # discard findings (that would report a compromised host as clean).
    engine = None
    findings: List[Finding] = []
    try:
        engine = DetectionEngine(allowlist=allowlist, custom_rules=custom_rules, baseline=baseline)
        findings = engine.run(artifacts)
    except Exception as exc:
        logger.error("detection_failed", error=str(exc))

    timeline: list = []
    timeline_error = None
    try:
        timeline = TimelineBuilder(source=source).build()
        if since is not None:
            timeline = [e for e in timeline if e.timestamp >= since]
    except Exception as exc:
        timeline_error = str(exc)
        logger.error("timeline_failed", error=timeline_error)

    try:
        correlate(findings, timeline)
        for finding in findings:
            if finding.related_events:
                apply_signal(finding, "timeline_corroboration", 25,
                             f"{len(finding.related_events)} nearby timeline event(s)")
    except Exception as exc:
        logger.error("correlation_failed", error=str(exc))

    duration = time.monotonic() - start

    remediation_results: List[RemediationResult] = []
    if remediate:
        remediation_results = remediate_findings(findings, confirm, min_confidence)

    # A bundle's manifest records the *collected* host's identity; the report
    # must describe that host, not the analyst's machine running `analyze`.
    manifest = (bundle_info or {}).get("manifest")
    live = _is_live(source)
    local_version = get_ubuntu_version(source)
    if manifest:
        report_hostname = manifest.get("hostname") or "unknown"
        report_ubuntu_version = manifest.get("ubuntu_version") or local_version
    elif live:
        report_hostname = socket.gethostname()
        report_ubuntu_version = local_version
    else:
        report_hostname = get_hostname(source) or "unknown (offline --root)"
        report_ubuntu_version = local_version
    # platform.machine() describes whatever machine is running ubuntils —
    # only meaningful for a live scan.
    arch = platform.machine() if live else "unknown (offline analysis)"

    # Only a genuinely live scan describes the host the local Wazuh agent is
    # watching; offline analysis must never forward findings here.
    if forward_wazuh and live and is_wazuh_agent_present():
        write_wazuh_alerts(findings, report_hostname)

    bundle_integrity = (bundle_info or {}).get("bundle_integrity", "live")
    rules_failed = list(engine.rules_failed) if engine else ["DetectionEngine"]
    suppressed = engine.suppressed_by_baseline if engine else 0

    stats = {
        "ubuntu_version": report_ubuntu_version,
        "architecture": arch,
        "duration_s": duration,
        "collector_count": len(collectors),
        "collector_failures": failures,
        "finding_counts": {
            "HIGH": sum(1 for f in findings if f.severity == Severity.HIGH),
            "MEDIUM": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "LOW": sum(1 for f in findings if f.severity == Severity.LOW),
        },
        "timeline_count": len(timeline),
        "suppressed_by_baseline": suppressed,
        "bundle_integrity": bundle_integrity,
        "collectors_degraded": collectors_degraded,
        "rules_failed": rules_failed,
        "timeline_error": timeline_error,
    }

    scan_metadata = {
        "tool_version": __version__,
        "hostname": report_hostname,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ubuntu_version": report_ubuntu_version,
        "architecture": arch,
        "duration_s": duration,
        "collector_failures": failures,
        "collectors_degraded": collectors_degraded,
        "rules_failed": rules_failed,
        "timeline_error": timeline_error,
        "bundle_integrity": bundle_integrity,
        "command_collectors_skipped": command_collectors_skipped,
        "suppressed_by_baseline": suppressed,
        "baseline_suppressed": (
            [{"rule_id": f.rule_id, "artifact_path": f.artifact_path}
             for f in engine.baseline_suppressed_findings] if engine else []
        ),
    }
    if manifest:
        scan_metadata["collection_run_id"] = manifest.get("run_id", "")
        scan_metadata["collected_at_utc_start"] = manifest.get("collected_at_utc_start", "")
        scan_metadata["collected_at_utc_end"] = manifest.get("collected_at_utc_end", "")

    return ScanResult(
        findings=findings,
        timeline=timeline,
        stats=stats,
        scan_metadata=scan_metadata,
        artifact_counts=artifact_counts,
        remediation_results=remediation_results,
    )
