import os
import platform
import socket
import sys
import time
from datetime import datetime, timezone

import click
import structlog

from ubuntils import __version__
from ubuntils.collectors import ALL_COLLECTORS
from ubuntils.collectors.source import LiveSource
from ubuntils.detectors.custom_rules import load_custom_rules
from ubuntils.detectors.engine import DetectionEngine
from ubuntils.detectors.finding import Severity
from ubuntils.formatters.json_formatter import JSONFormatter
from ubuntils.remediators import REMEDIATOR_REGISTRY
from ubuntils.timeline.builder import TimelineBuilder
from ubuntils.timeline.correlator import correlate
from ubuntils.tui.app import UbuntilsApp
from ubuntils.tui.stats_panel import get_ubuntu_version
from ubuntils.utils.config import load_allowlist
from ubuntils.utils.logging import configure_logging
from ubuntils.utils.since_parser import parse_since

logger = structlog.get_logger()

# Canonical capture lists for `ubuntils collect`. These are the files/commands
# that can be captured as a *static* list — glob-expanded and per-PID/per-timer
# dynamic paths cannot be represented here (see cli.py collect() docstring and
# task-10-report.md "Known limitations" for the full list of gaps).
COLLECT_FILES = [
    "/etc/passwd",
    "/etc/group",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ld.so.preload",
    "/etc/environment",
    "/etc/crontab",
    "/etc/profile",
]
COLLECT_COMMANDS = [
    ("ss", ["ss", "-tunap"]),
    ("netstat", ["netstat", "-tunap"]),
    ("systemctl_list_timers_json",
     ["systemctl", "list-timers", "--all", "--no-pager", "--output", "json"]),
    ("systemctl_list_timers_text",
     ["systemctl", "list-timers", "--all", "--no-pager"]),
]


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


def _run_pipeline(source, remediate: bool, confirm: bool, allowlist=None, since=None,
                  custom_rules=None, bundle_info=None) -> tuple:
    """Run collectors → detection → timeline → optional remediation.

    Returns (findings, timeline, stats, scan_metadata, artifact_counts, remediation_results).
    """
    start = time.monotonic()
    artifacts: dict = {}
    failures = 0
    artifact_counts: dict = {}
    collectors = [C(source=source) for C in ALL_COLLECTORS]

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
        findings = DetectionEngine(allowlist=allowlist, custom_rules=custom_rules).run(artifacts)
        timeline = TimelineBuilder().build()
        if since is not None:
            timeline = [e for e in timeline if e.timestamp >= since]
        correlate(findings, timeline)
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
        "tool_version": __version__,
        "hostname": socket.gethostname(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ubuntu_version": ubuntu_version,
        "architecture": arch,
        "duration_s": duration,
        "collector_failures": failures,
        "bundle_integrity": (bundle_info or {}).get("bundle_integrity", "live"),
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
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False),
              help="YAML config with false-positive allowlist (rules/paths to suppress)")
@click.option("--output", "output_path", type=click.Path(dir_okay=False),
              help="Write JSON report to FILE instead of stdout (implies --json)")
@click.option("--since", "since_value",
              help="Limit timeline to events since this time (e.g. '24h', '7d', '2026-05-20')")
@click.option("--rules", "rules_path", type=click.Path(exists=True, dir_okay=False),
              help="YAML file of custom pattern-match detection rules (adds detections)")
@click.option("--verbose", is_flag=True, help="Enable verbose logging")
def scan(output_json, remediate, confirm, config_path, output_path, since_value,
         rules_path, verbose):
    """Scan the system for forensic artifacts and suspicious activity."""
    _ensure_root()
    if output_path:
        output_json = True
    configure_logging(json_mode=output_json, verbose=verbose)

    since = None
    if since_value:
        try:
            since = parse_since(since_value)
        except ValueError as exc:
            raise click.ClickException(str(exc))

    allowlist = None
    if config_path:
        try:
            allowlist = load_allowlist(config_path)
        except (ValueError, OSError) as exc:
            raise click.ClickException(f"Invalid config {config_path}: {exc}")

    custom_rules = None
    if rules_path:
        try:
            custom_rules = load_custom_rules(rules_path)
        except (ValueError, OSError) as exc:
            raise click.ClickException(f"Invalid rules file {rules_path}: {exc}")

    if output_json or remediate:
        findings, timeline, stats, scan_metadata, artifact_counts, remediation_results = \
            _run_pipeline(source=LiveSource(root="/"), remediate=remediate, confirm=confirm,
                          allowlist=allowlist, since=since, custom_rules=custom_rules)

        if output_json:
            report = JSONFormatter().format(
                scan_metadata, artifact_counts, findings, timeline, remediation_results
            )
            if output_path:
                with open(output_path, "w") as f:
                    f.write(report + "\n")
                click.echo(f"Report written to {output_path}", err=True)
            else:
                click.echo(report)
            return

        # --remediate without --json: launch TUI with pre-computed results
        def _override():
            return (findings, timeline, stats)

        UbuntilsApp(verbose=verbose, _scan_override=_override).run()
        return

    # Plain TUI mode: let the app run its own scan with live progress
    UbuntilsApp(verbose=verbose, allowlist=allowlist, since=since,
                custom_rules=custom_rules).run()


@main.command()
@click.option("--output", "output_path", type=click.Path(dir_okay=False),
              help="Bundle path to write (default ./ubuntils-bundle-<timestamp>.tar.gz)")
@click.option("--verbose", is_flag=True, help="Enable verbose logging")
def collect(output_path, verbose):
    """Acquire a portable, tamper-evident artifact bundle from this host.

    Captures the statically-listed files/commands in COLLECT_FILES/COLLECT_COMMANDS.
    Known limitations (dynamic paths that cannot be captured as a fixed list):
    glob-expanded paths (/etc/cron.d/*, /etc/sudoers.d/*, /etc/profile.d/*,
    per-user ~/.ssh/authorized_keys), per-PID /proc/*/status and /proc/*/cmdline,
    and the per-timer `systemctl show <service> --property=ExecStart` lookup.
    """
    _ensure_root()
    configure_logging(json_mode=False, verbose=verbose)
    from ubuntils.bundle.writer import write_bundle

    if not output_path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = f"ubuntils-bundle-{stamp}.tar.gz"

    source = LiveSource(root="/")
    written = write_bundle(
        source=source,
        files_to_capture=COLLECT_FILES,
        commands_to_capture=COLLECT_COMMANDS,
        out_path=output_path,
        metadata={
            "hostname": socket.gethostname(),
            "ubuntu_version": get_ubuntu_version(),
            "tool_version": __version__,
        },
    )
    click.echo(f"Bundle written to {written}", err=True)


@main.command()
@click.argument("bundle", required=False, type=click.Path(exists=True, dir_okay=False))
@click.option("--root", "root_path", type=click.Path(exists=True, file_okay=False),
              help="Analyze a mounted image / artifact tree instead of a bundle")
@click.option("--json", "output_json", is_flag=True, help="Output JSON instead of launching TUI")
@click.option("--output", "output_path", type=click.Path(dir_okay=False),
              help="Write JSON report to FILE (implies --json)")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False),
              help="YAML allowlist to suppress findings")
@click.option("--rules", "rules_path", type=click.Path(exists=True, dir_okay=False),
              help="YAML file of custom pattern-match detection rules (adds detections)")
@click.option("--since", "since_value",
              help="Limit timeline to events since this time (e.g. '24h', '7d', '2026-05-20')")
@click.option("--verbose", is_flag=True, help="Enable verbose logging")
def analyze(bundle, root_path, output_json, output_path, config_path, rules_path,
            since_value, verbose):
    """Run detection + timeline against a collected bundle or a mounted image (--root)."""
    if not bundle and not root_path:
        raise click.UsageError("provide a BUNDLE path or --root PATH")
    if bundle and root_path:
        raise click.UsageError("provide either a BUNDLE or --root, not both")

    if output_path:
        output_json = True
    configure_logging(json_mode=output_json, verbose=verbose)

    from ubuntils.bundle import read_bundle

    bundle_info = None
    if bundle:
        source, bundle_info = read_bundle(bundle)
    else:
        source = LiveSource(root=root_path)

    since = None
    if since_value:
        try:
            since = parse_since(since_value)
        except ValueError as exc:
            raise click.ClickException(str(exc))

    allowlist = None
    if config_path:
        try:
            allowlist = load_allowlist(config_path)
        except (ValueError, OSError) as exc:
            raise click.ClickException(f"Invalid config {config_path}: {exc}")

    custom_rules = None
    if rules_path:
        try:
            custom_rules = load_custom_rules(rules_path)
        except (ValueError, OSError) as exc:
            raise click.ClickException(f"Invalid rules file {rules_path}: {exc}")

    findings, timeline, stats, scan_metadata, artifact_counts, remediation_results = \
        _run_pipeline(source=source, remediate=False, confirm=False,
                      allowlist=allowlist, since=since, custom_rules=custom_rules,
                      bundle_info=bundle_info)

    if output_json:
        report = JSONFormatter().format(
            scan_metadata, artifact_counts, findings, timeline, remediation_results
        )
        if output_path:
            with open(output_path, "w") as f:
                f.write(report + "\n")
            click.echo(f"Report written to {output_path}", err=True)
        else:
            click.echo(report)
        return

    # Not --json: launch TUI with pre-computed results, mirroring scan --remediate's override.
    def _override():
        return (findings, timeline, stats)

    UbuntilsApp(verbose=verbose, _scan_override=_override).run()


@main.command()
def version():
    """Print version and exit."""
    click.echo(__version__)


if __name__ == "__main__":
    main()
