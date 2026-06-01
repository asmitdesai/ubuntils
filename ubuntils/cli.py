import os
import platform
import sys
import time

import click
import structlog

from ubuntils import __version__
from ubuntils.collectors import ALL_COLLECTORS
from ubuntils.detectors.engine import DetectionEngine
from ubuntils.detectors.finding import Severity
from ubuntils.formatters.json_formatter import JSONFormatter
from ubuntils.remediators import REMEDIATOR_REGISTRY
from ubuntils.timeline.builder import TimelineBuilder
from ubuntils.tui.app import UbuntilsApp
from ubuntils.tui.stats_panel import get_ubuntu_version
from ubuntils.utils.logging import configure_logging

logger = structlog.get_logger()


def _ensure_root() -> None:
    """Re-exec under sudo if not running as root, preserving the active venv/conda PATH."""
    if os.geteuid() == 0:
        return
    current_path = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")
    # Pass PATH through so sudo finds this venv's Python and ubuntils script.
    args = ["sudo", "env", f"PATH={current_path}", sys.argv[0]] + sys.argv[1:]
    print("ubuntils requires root — re-invoking with sudo…", file=sys.stderr)
    try:
        os.execvp("sudo", args)
    except FileNotFoundError:
        print("Error: sudo not found. Please run as root.", file=sys.stderr)
        sys.exit(1)


def _run_pipeline(remediate: bool, confirm: bool) -> tuple:
    """Run collectors → detection → timeline → optional remediation.

    Returns (findings, timeline, stats, scan_metadata, artifact_counts, remediation_results).
    """
    start = time.monotonic()
    artifacts: dict = {}
    failures = 0
    artifact_counts: dict = {}
    collectors = [C() for C in ALL_COLLECTORS]

    for collector in collectors:
        name = type(collector).__name__
        try:
            result = collector.collect()
            artifacts.update(result)
            artifact_counts[name] = sum(
                len(v) if isinstance(v, (list, dict)) else 1
                for v in result.values()
            )
        except Exception as exc:
            logger.error("collector_failed", name=name, error=str(exc))
            failures += 1

    try:
        findings = DetectionEngine().run(artifacts)
        timeline = TimelineBuilder().build()
    except Exception as exc:
        logger.error("scan_engine_failed", error=str(exc))
        findings = []
        timeline = []

    duration = time.monotonic() - start

    remediation_results = []
    if remediate:
        for finding in findings:
            remediator_cls = REMEDIATOR_REGISTRY.get(finding.rule_id)
            if remediator_cls is None:
                continue
            result = remediator_cls().remediate(finding, dry_run=not confirm)
            remediation_results.append(result)
            logger.info(
                "remediation",
                rule_id=finding.rule_id,
                status=result.status.value,
                message=result.message,
            )

    ubuntu_version = get_ubuntu_version()
    arch = platform.machine()

    stats = {
        "ubuntu_version": ubuntu_version,
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
    }

    scan_metadata = {
        "ubuntu_version": ubuntu_version,
        "architecture": arch,
        "duration_s": duration,
        "collector_failures": failures,
    }

    return findings, timeline, stats, scan_metadata, artifact_counts, remediation_results


@click.group()
def main():
    """ubuntils - Ubuntu incident response tool."""
    pass


@main.command()
@click.option("--json", "output_json", is_flag=True, help="Output JSON instead of launching TUI")
@click.option("--remediate", is_flag=True, help="Run remediation engine after detection")
@click.option("--confirm", is_flag=True, help="Required with --remediate to apply changes")
@click.option("--verbose", is_flag=True, help="Enable verbose logging")
def scan(output_json, remediate, confirm, verbose):
    """Scan the system for forensic artifacts and suspicious activity."""
    _ensure_root()
    configure_logging(json_mode=output_json, verbose=verbose)

    if output_json or remediate:
        findings, timeline, stats, scan_metadata, artifact_counts, remediation_results = \
            _run_pipeline(remediate=remediate, confirm=confirm)

        if output_json:
            click.echo(
                JSONFormatter().format(
                    scan_metadata, artifact_counts, findings, timeline, remediation_results
                )
            )
            return

        # --remediate without --json: launch TUI with pre-computed results
        def _override():
            return (findings, timeline, stats)

        UbuntilsApp(verbose=verbose, _scan_override=_override).run()
        return

    # Plain TUI mode: let the app run its own scan with live progress
    UbuntilsApp(verbose=verbose).run()


@main.command()
def version():
    """Print version and exit."""
    click.echo(__version__)


if __name__ == "__main__":
    main()
