import os
import secrets
import socket
import sys
import tarfile
import warnings
from datetime import datetime, timezone

import click
import structlog

from ubuntils import __version__
from ubuntils.collectors.packages import (
    DPKG_CFG_FILE, DPKG_OWNERS_ARGV, SENSITIVE_ATTR_PATHS, SETUID_FIND_ARGS,
)
from ubuntils.collectors.source import LiveSource
from ubuntils.detectors.custom_rules import load_custom_rules
from ubuntils.formatters.json_formatter import JSONFormatter
from ubuntils.pipeline import DEFAULT_MIN_REMEDIATION_CONFIDENCE, run_scan
from ubuntils.tui.app import UbuntilsApp
from ubuntils.utils.baseline import load_baseline
from ubuntils.utils.config import load_allowlist
from ubuntils.utils.host import get_ubuntu_version
from ubuntils.utils.logging import configure_logging
from ubuntils.utils.safe_io import ensure_private_dir, write_private_text
from ubuntils.utils.shell import resolve_command
from ubuntils.utils.since_parser import parse_since

# Exit status for `analyze` when the bundle fails integrity verification.
EXIT_BUNDLE_TAMPERED = 3
# Exit status when the detection stage itself failed: the (empty) findings
# list says nothing about the host.
EXIT_DETECTION_FAILED = 1

# Where `collect` writes when no --output is given. A bundle holds
# /etc/shadow; the working directory may belong to the attacker, and a name
# predictable to the second lets them pre-create it.
DEFAULT_BUNDLE_DIR = "/var/lib/ubuntils/bundles"

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
    "/var/lib/dpkg/status",
    DPKG_CFG_FILE,
    # Where Docker's and Ubuntu's minimized images put their path-exclude
    # filters (the directory itself can't be globbed into a static list).
    "/etc/dpkg/dpkg.cfg.d/excludes",
    # Per-module taint flags (out-of-tree, unsigned) for KERNEL_MODULE_SUSPICIOUS.
    "/proc/modules",
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
    ("dpkg_owners", DPKG_OWNERS_ARGV),
    ("lsattr_sensitive", ["lsattr", "-d", *SENSITIVE_ATTR_PATHS]),
    ("find_setuid", ["find", *SETUID_FIND_ARGS]),
    ("lsmod", ["lsmod"]),
]

# What the root re-exec runs: `python -I -c REEXEC_BOOTSTRAP`. `python -m
# ubuntils.cli` (and plain `-c`) put the current directory first on sys.path,
# so running `ubuntils scan` from inside /tmp or a compromised user's home
# would import a planted ubuntils/ (or click.py, yaml.py, …) *as root*. -I
# (isolated mode: no cwd or script dir on sys.path, no PYTHON* variables, no
# user site-packages) closes that on every supported Python; a venv's own
# site-packages still load, since they are found from pyvenv.cfg next to the
# interpreter, not the environment (checked on 3.9 and 3.11). The bootstrap
# also drops a leading "" entry, for anyone running it without -I — but only
# that entry: under -I on 3.9/3.10, sys.path[0] is the stdlib zip.
REEXEC_BOOTSTRAP = (
    "import sys; "
    "sys.path[:1] == [''] and sys.path.pop(0); "
    "sys.argv[0] = 'ubuntils'; "
    "from ubuntils.cli import main; main()"
)


def _untrusted(path: str) -> list:
    """Why root shouldn't run code from ``path``: it, or a directory above
    it, isn't root-owned or is writable by group/others (a sticky,
    root-owned directory like /tmp is fine — only its owner can rename
    entries in it)."""
    problems = []
    current = os.path.realpath(path)
    while True:
        try:
            st = os.stat(current)
        except OSError as exc:
            problems.append(f"{current}: cannot stat ({exc.strerror})")
            break
        if st.st_uid != 0:
            problems.append(f"{current} is owned by uid {st.st_uid}")
        elif st.st_mode & 0o022 and not (os.path.isdir(current) and st.st_mode & 0o1000):
            problems.append(f"{current} is writable by group or others")
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return problems


def install_trust_problems(paths=None) -> list:
    """Reasons the code `sudo` is about to run as root could be changed by
    someone other than root: the interpreter, sys.prefix and the ubuntils
    package directory, and every directory above them."""
    if paths is None:
        import ubuntils
        paths = [sys.executable, sys.prefix, os.path.dirname(ubuntils.__file__)]
    seen, problems = set(), []
    for path in paths:
        for problem in _untrusted(path):
            if problem not in seen:
                seen.add(problem)
                problems.append(problem)
    return problems


def _allow_user_install() -> bool:
    ctx = click.get_current_context(silent=True)
    return bool(ctx and ctx.find_root().params.get("allow_user_install"))


def _ensure_root() -> None:
    """Re-exec under sudo if not running as root.

    The re-exec names this interpreter by absolute path (sys.executable) and
    runs REEXEC_BOOTSTRAP in isolated mode, so neither the caller's PATH nor
    their working directory can influence what runs as root. PATH is
    deliberately *not* forwarded: `sudo env PATH=<caller's PATH>` would
    defeat sudo's secure_path. External commands are separately pinned to
    utils.shell.SECURE_PATH.

    What it can't fix: if the interpreter or ubuntils itself is installed
    somewhere the invoking user can write (pipx in ~/.local, a venv in a home
    directory, an editable checkout), whoever controls that user controls
    the code root runs. That needs --allow-user-install.
    """
    if os.geteuid() == 0:
        return
    problems = install_trust_problems()
    if problems and not _allow_user_install():
        print(
            "ubuntils will not escalate to root: it would run code that a non-root user "
            "can modify.\n  " + "\n  ".join(problems[:6]) + "\n"
            "Anything running as that user (on a host you are investigating, possibly the "
            "attacker) could change ubuntils or its interpreter and get root the next time "
            "you run it. Install it root-owned instead (`sudo pipx install --global "
            "ubuntils`, or a root-owned venv under /opt; see the README), or accept the "
            "risk with `ubuntils --allow-user-install " + " ".join(sys.argv[1:]) + "`.",
            file=sys.stderr,
        )
        sys.exit(1)
    if problems:
        print("warning: running a user-writable ubuntils install as root "
              "(--allow-user-install)", file=sys.stderr)
    args = ["sudo", sys.executable, "-I", "-c", REEXEC_BOOTSTRAP] + sys.argv[1:]
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
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", FutureWarning)
                baseline = load_baseline(baseline_path)
        except (ValueError, OSError) as exc:
            raise click.ClickException(f"Invalid baseline {baseline_path}: {exc}")
        for w in caught:
            click.echo(f"warning: {w.message}", err=True)

    custom_rules = None
    if rules_path:
        try:
            custom_rules = load_custom_rules(rules_path)
        except (ValueError, OSError) as exc:
            raise click.ClickException(f"Invalid rules file {rules_path}: {exc}")

    return since, allowlist, baseline, custom_rules


def _sudo_invoker():
    """(uid, gid) of the user who ran us through sudo, or None.

    `scan` re-executes itself under sudo, so without this a report written to
    `--output ~/report.json` is root-owned 0600 and its own author can't read it.
    """
    if os.geteuid() != 0:
        return None
    try:
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    except (KeyError, ValueError):
        return None
    return (uid, gid) if uid != 0 else None


def _default_bundle_path() -> str:
    """A fresh, unguessable path in root's own 0700 bundle directory."""
    ensure_private_dir(os.path.dirname(DEFAULT_BUNDLE_DIR))
    ensure_private_dir(DEFAULT_BUNDLE_DIR)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return os.path.join(DEFAULT_BUNDLE_DIR,
                        f"ubuntils-bundle-{stamp}-{secrets.token_hex(4)}.tar.gz")


def _detection_failed(scan_metadata: dict) -> bool:
    error = scan_metadata.get("detection_error")
    if error:
        click.secho(f"ERROR: detection failed ({error}). The report has no findings, "
                    "which says nothing about this host.", err=True, fg="red", bold=True)
    return bool(error)


def _emit_report(report: str, output_path) -> None:
    if output_path:
        try:
            # Owner-only either way; a report ubuntils creates belongs to the
            # user who asked for it. An existing file is reused only if it is
            # already ours or theirs (and not a hard link to something else).
            write_private_text(output_path, report + "\n", new_owner=_sudo_invoker())
        except OSError as exc:
            raise click.ClickException(f"Cannot write report to {output_path}: {exc}")
        click.echo(f"Report written to {output_path}", err=True)
    else:
        click.echo(report)


@click.group()
@click.option("--allow-user-install", is_flag=True,
              help="Escalate to root even though ubuntils or its interpreter is installed "
                   "where a non-root user can modify it")
def main(allow_user_install):
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
            if _detection_failed(scan_metadata):
                sys.exit(EXIT_DETECTION_FAILED)
            return

        # --remediate without --json: launch TUI with pre-computed results,
        # including what remediation actually changed.
        def _override():
            return (findings, timeline, stats, remediation_results)

        UbuntilsApp(verbose=verbose, _scan_override=_override).run()
        if _detection_failed(scan_metadata):
            sys.exit(EXIT_DETECTION_FAILED)
        return

    # Plain TUI mode: let the app run its own scan with live progress
    UbuntilsApp(verbose=verbose, allowlist=allowlist, since=since,
                custom_rules=custom_rules, baseline=baseline,
                forward_wazuh=not no_wazuh).run()


@main.command()
@click.option("--output", "output_path", type=click.Path(dir_okay=False),
              help="Bundle path to write; must not exist yet (default "
                   "/var/lib/ubuntils/bundles/ubuntils-bundle-<timestamp>-<random>.tar.gz)")
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

    try:
        if not output_path:
            output_path = _default_bundle_path()
        written = write_bundle(
            source=LiveSource(root="/"),
            files_to_capture=COLLECT_FILES,
            commands_to_capture=COLLECT_COMMANDS,
            out_path=output_path,
            metadata={
                "hostname": socket.gethostname(),
                "ubuntu_version": get_ubuntu_version(),
                "tool_version": __version__,
            },
        )
    except OSError as exc:
        raise click.ClickException(f"Cannot write bundle: {exc}")
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

    detection_failed = _detection_failed(scan_metadata)
    if tampered:
        sys.exit(EXIT_BUNDLE_TAMPERED)
    if detection_failed:
        sys.exit(EXIT_DETECTION_FAILED)


@main.command()
@click.argument("backup_path", type=click.Path(dir_okay=False))
@click.option("--force", is_flag=True,
              help="Restore even if the file or its directory changed since remediation "
                   "(symlinks and non-regular files are still refused)")
def rollback(backup_path, force):
    """Undo a remediation by restoring BACKUP_PATH to the file it was taken from."""
    _ensure_root()
    from ubuntils.remediators.rollback import RollbackError, rollback as do_rollback
    try:
        click.echo(do_rollback(backup_path, force=force))
    except (RollbackError, OSError, ValueError, KeyError) as exc:
        raise click.ClickException(f"Rollback refused: {exc}")


@main.command()
def version():
    """Print version and exit."""
    click.echo(__version__)


if __name__ == "__main__":
    main()
