import os
import socket
import sys
import tarfile
from datetime import datetime, timezone

import click
import structlog

from ubuntils import __version__
from ubuntils.collectors.packages import SENSITIVE_ATTR_PATHS, SETUID_FIND_ARGS
from ubuntils.collectors.source import LiveSource
from ubuntils.detectors.custom_rules import load_custom_rules
from ubuntils.formatters.json_formatter import JSONFormatter
from ubuntils.pipeline import DEFAULT_MIN_REMEDIATION_CONFIDENCE, run_scan
from ubuntils.tui.app import UbuntilsApp
from ubuntils.utils.baseline import load_baseline
from ubuntils.utils.config import load_allowlist
from ubuntils.utils.host import get_ubuntu_version
from ubuntils.utils.logging import configure_logging
from ubuntils.utils.safe_io import write_private_text
from ubuntils.utils.shell import resolve_command
from ubuntils.utils.since_parser import parse_since

# Exit status for `analyze` when the bundle fails integrity verification.
EXIT_BUNDLE_TAMPERED = 3

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
    "/etc/nsswitch.conf",
    "/etc/os-release",
    "/usr/lib/os-release",
    "/etc/hostname",
    "/etc/timezone",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/audit/audit.log",
]
COLLECT_COMMANDS = [
    ("ss", ["ss", "-tunap"]),
    ("netstat", ["netstat", "-tunap"]),
    ("systemctl_list_timers_json",
     ["systemctl", "list-timers", "--all", "--no-pager", "--output", "json"]),
    ("systemctl_list_timers_text",
     ["systemctl", "list-timers", "--all", "--no-pager"]),
    ("journalctl", ["journalctl", "-o", "json", "--since=7 days ago", "--no-pager"]),
    ("dpkg_verify", ["dpkg", "--verify"]),
    ("lsattr_sensitive", ["lsattr", "-d", *SENSITIVE_ATTR_PATHS]),
    ("find_setuid", ["find", *SETUID_FIND_ARGS]),
    ("lsmod", ["lsmod"]),
]

def _ensure_root() -> None:
    """Re-exec under sudo if not running as root.

    The re-exec names this interpreter by absolute path (sys.executable) and
    runs the CLI as a module, so the caller's PATH is never needed — and is
    deliberately *not* forwarded: `sudo env PATH=<caller's PATH>` would defeat
    sudo's secure_path. External commands are separately pinned to
    utils.shell.SECURE_PATH.
    """
    if os.geteuid() == 0:
        return
    args = ["sudo", sys.executable, "-m", "ubuntils.cli"] + sys.argv[1:]
    print("ubuntils requires root — re-invoking with sudo…", file=sys.stderr)
    try:
        os.execv(resolve_command("sudo"), args)
    except FileNotFoundError:
        print("Error: sudo not found. Please run as root.", file=sys.stderr)
        sys.exit(1)


def _run_pipeline(source, remediate: bool, confirm: bool, allowlist=None, since=None,
                  custom_rules=None, bundle_info=None, baseline=None,
                  min_confidence: int = DEFAULT_MIN_REMEDIATION_CONFIDENCE,
                  forward_wazuh: bool = True) -> tuple:
    """Run collectors → detection → timeline → optional remediation.

    Returns (findings, timeline, stats, scan_metadata, artifact_counts, remediation_results).
    """
    r = run_scan(
        source, allowlist=allowlist, since=since, custom_rules=custom_rules,
        baseline=baseline, bundle_info=bundle_info, remediate=remediate,
        confirm=confirm, min_confidence=min_confidence, forward_wazuh=forward_wazuh,
    )
    return (r.findings, r.timeline, r.stats, r.scan_metadata, r.artifact_counts,
            r.remediation_results)


def _load_inputs(config_path, baseline_path, rules_path, since_value) -> tuple:
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

    baseline = None
    if baseline_path:
        try:
            baseline = load_baseline(baseline_path)
        except (ValueError, OSError) as exc:
            raise click.ClickException(f"Invalid baseline {baseline_path}: {exc}")

    custom_rules = None
    if rules_path:
        try:
            custom_rules = load_custom_rules(rules_path)
        except (ValueError, OSError) as exc:
            raise click.ClickException(f"Invalid rules file {rules_path}: {exc}")

    return since, allowlist, baseline, custom_rules


def _emit_report(report: str, output_path) -> None:
    if output_path:
        try:
            write_private_text(output_path, report + "\n")
        except OSError as exc:
            raise click.ClickException(f"Cannot write report to {output_path}: {exc}")
        click.echo(f"Report written to {output_path}", err=True)
    else:
        click.echo(report)


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
@click.option("--baseline", "baseline_path", type=click.Path(exists=True, dir_okay=False),
              help="YAML baseline of environment-specific known-good fingerprints to suppress")
@click.option("--output", "output_path", type=click.Path(dir_okay=False),
              help="Write JSON report to FILE instead of stdout (implies --json)")
@click.option("--since", "since_value",
              help="Limit timeline to events since this time (e.g. '24h', '7d', '2026-05-20')")
@click.option("--rules", "rules_path", type=click.Path(exists=True, dir_okay=False),
              help="YAML file of custom pattern-match detection rules (adds detections)")
@click.option("--min-confidence", "min_confidence", type=click.IntRange(0, 100),
              default=DEFAULT_MIN_REMEDIATION_CONFIDENCE, show_default=True,
              help="Only auto-remediate findings at or above this confidence score")
@click.option("--no-wazuh", "no_wazuh", is_flag=True,
              help="Never forward findings to a local Wazuh agent, even if one is installed")
@click.option("--verbose", is_flag=True, help="Enable verbose logging")
def scan(output_json, remediate, confirm, config_path, baseline_path, output_path, since_value,
         rules_path, min_confidence, no_wazuh, verbose):
    """Scan the system for forensic artifacts and suspicious activity."""
    _ensure_root()
    if output_path:
        output_json = True
    configure_logging(json_mode=output_json, verbose=verbose)

    since, allowlist, baseline, custom_rules = _load_inputs(
        config_path, baseline_path, rules_path, since_value
    )

    if output_json or remediate:
        findings, timeline, stats, scan_metadata, artifact_counts, remediation_results = \
            _run_pipeline(source=LiveSource(root="/"), remediate=remediate, confirm=confirm,
                          allowlist=allowlist, since=since, custom_rules=custom_rules,
                          baseline=baseline, min_confidence=min_confidence,
                          forward_wazuh=not no_wazuh)

        if output_json:
            report = JSONFormatter().format(
                scan_metadata, artifact_counts, findings, timeline, remediation_results
            )
            _emit_report(report, output_path)
            return

        # --remediate without --json: launch TUI with pre-computed results,
        # including what remediation actually changed.
        def _override():
            return (findings, timeline, stats, remediation_results)

        UbuntilsApp(verbose=verbose, _scan_override=_override).run()
        return

    # Plain TUI mode: let the app run its own scan with live progress
    UbuntilsApp(verbose=verbose, allowlist=allowlist, since=since,
                custom_rules=custom_rules, baseline=baseline,
                forward_wazuh=not no_wazuh).run()


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
@click.option("--baseline", "baseline_path", type=click.Path(exists=True, dir_okay=False),
              help="YAML baseline of environment-specific known-good fingerprints to suppress")
@click.option("--rules", "rules_path", type=click.Path(exists=True, dir_okay=False),
              help="YAML file of custom pattern-match detection rules (adds detections)")
@click.option("--since", "since_value",
              help="Limit timeline to events since this time (e.g. '24h', '7d', '2026-05-20')")
@click.option("--verbose", is_flag=True, help="Enable verbose logging")
def analyze(bundle, root_path, output_json, output_path, config_path, baseline_path, rules_path,
            since_value, verbose):
    """Run detection + timeline against a collected bundle or a mounted image (--root)."""
    if not bundle and not root_path:
        raise click.UsageError("provide a BUNDLE path or --root PATH")
    if bundle and root_path:
        raise click.UsageError("provide either a BUNDLE or --root, not both")

    if output_path:
        output_json = True
    configure_logging(json_mode=output_json, verbose=verbose)

    since, allowlist, baseline, custom_rules = _load_inputs(
        config_path, baseline_path, rules_path, since_value
    )

    from ubuntils.bundle import BundleError, read_bundle

    bundle_info = None
    if bundle:
        try:
            source, bundle_info = read_bundle(bundle)
        except (BundleError, OSError, tarfile.TarError, ValueError, KeyError) as exc:
            raise click.ClickException(f"Cannot read bundle {bundle}: {exc}")
    else:
        # A --root path is a mounted/extracted image, not the live host — no
        # command-based collector may run live against it (see
        # LiveSource.offline / pipeline's command_collectors_skipped).
        source = LiveSource(root=root_path, offline=True)

    try:
        findings, timeline, stats, scan_metadata, artifact_counts, remediation_results = \
            _run_pipeline(source=source, remediate=False, confirm=False,
                          allowlist=allowlist, since=since, custom_rules=custom_rules,
                          bundle_info=bundle_info, baseline=baseline)
    finally:
        # The extracted bundle (which can include /etc/shadow) must not
        # outlive the analysis in /tmp.
        cleanup = getattr(source, "cleanup", None)
        if cleanup is not None:
            cleanup()

    tampered = (bundle_info or {}).get("bundle_integrity") == "mismatch"
    if tampered:
        click.secho(
            "WARNING: bundle integrity check FAILED — its contents do not match the "
            "manifest digests. Treat every result below as untrusted.",
            err=True, fg="red", bold=True,
        )

    if output_json:
        report = JSONFormatter().format(
            scan_metadata, artifact_counts, findings, timeline, remediation_results
        )
        _emit_report(report, output_path)
    else:
        # Not --json: launch TUI with pre-computed results.
        def _override():
            return (findings, timeline, stats, remediation_results)

        UbuntilsApp(verbose=verbose, _scan_override=_override).run()

    if tampered:
        sys.exit(EXIT_BUNDLE_TAMPERED)


@main.command()
def version():
    """Print version and exit."""
    click.echo(__version__)


if __name__ == "__main__":
    main()
