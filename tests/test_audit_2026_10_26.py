"""Regression tests for the 2026-10-26 audit (live runs on Ubuntu 24.04).

D = detection, M = remediation, T = TUI, W = reporting.
"""
import datetime
import os
from unittest import mock

from ubuntils.collectors.packages import PackageCollector
from ubuntils.collectors.source import LiveSource
from ubuntils.collectors.sudoers import SudoersCollector
from ubuntils.detectors import rules
from ubuntils.detectors.finding import (
    Finding, RemediationResult, RemediationStatus, Severity,
)


def _tree(tmp_path, files: dict) -> str:
    for path, content in files.items():
        dest = tmp_path / path.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content)
    return str(tmp_path)


class _ReplaySource(LiveSource):
    """Files from a tmp tree, commands from a dict of canned output."""

    def __init__(self, root, outputs):
        super().__init__(root=root)
        self.outputs = outputs

    def run(self, name, argv, timeout=30):
        return self.outputs.get(name, ("", "", -1))


def _user(name, uid=1001, groups=()):
    return {"username": name, "uid": uid, "gid": uid, "shell": "/bin/bash",
            "groups": list(groups), "primary_group": name}


# ─── D1: dpkg path-exclude filters (Docker / minimized cloud images) ─────────

_EXCLUDES = (
    "# Drop all man pages\n"
    "path-exclude=/usr/share/man/*\n"
    "path-exclude=/usr/share/doc/*\n"
    "path-include=/usr/share/doc/*/copyright\n"
)
_VERIFY = (
    "missing     /usr/share/doc/bash/README.gz\n"
    "missing     /usr/share/man/man1/bash.1.gz\n"
    "missing     /usr/share/doc/bash/copyright\n"
    "missing     /usr/bin/bash\n"
    "??5??????   /usr/share/doc/bash/NEWS.gz\n"
)
_OWNERS = "\n".join(f"bash: {p}" for p in (
    "/usr/share/doc/bash/README.gz", "/usr/share/man/man1/bash.1.gz",
    "/usr/share/doc/bash/copyright", "/usr/bin/bash", "/usr/share/doc/bash/NEWS.gz",
))


def _package_findings(tmp_path, files):
    src = _ReplaySource(_tree(tmp_path, files), {
        "dpkg_verify": (_VERIFY, "", 1),
        "dpkg_owners": (_OWNERS, "", 0),
    })
    artifacts = PackageCollector(source=src).collect()
    return artifacts, rules.rule_package_tampered(artifacts)


def test_D1_missing_files_dpkg_was_told_not_to_install_are_not_tampering(tmp_path):
    artifacts, findings = _package_findings(
        tmp_path, {"/etc/dpkg/dpkg.cfg.d/excludes": _EXCLUDES})
    excluded = {e["path"] for e in artifacts["dpkg_verify_entries"] if e.get("path_excluded")}
    assert excluded == {"/usr/share/doc/bash/README.gz", "/usr/share/man/man1/bash.1.gz"}
    [finding] = findings
    # Re-included copyright, a real binary, and a modified file are still reported.
    assert "/usr/share/doc/bash/copyright" in finding.raw_value
    assert "/usr/bin/bash" in finding.raw_value
    assert "/usr/share/doc/bash/NEWS.gz" in finding.raw_value
    assert "README.gz" not in finding.raw_value and "bash.1.gz" not in finding.raw_value


def test_D1_without_filters_every_missing_file_is_reported(tmp_path):
    artifacts, [finding] = _package_findings(tmp_path, {"/etc/hostname": "h\n"})
    assert not any(e.get("path_excluded") for e in artifacts["dpkg_verify_entries"])
    assert "README.gz" in finding.raw_value


def test_D1_space_separated_options_in_dpkg_cfg_are_read(tmp_path):
    artifacts, _ = _package_findings(
        tmp_path, {"/etc/dpkg/dpkg.cfg": "path-exclude /usr/share/man/*\n"})
    excluded = {e["path"] for e in artifacts["dpkg_verify_entries"] if e.get("path_excluded")}
    assert excluded == {"/usr/share/man/man1/bash.1.gz"}


def test_D1_bundles_capture_dpkg_filter_config():
    from ubuntils.cli import COLLECT_FILES
    assert "/etc/dpkg/dpkg.cfg" in COLLECT_FILES
    assert "/etc/dpkg/dpkg.cfg.d/excludes" in COLLECT_FILES


# ─── D2: sudoers NOPASSWD evasions ───────────────────────────────────────────

def _sudo_findings(tmp_path, sudoers_d: str, users):
    root = _tree(tmp_path, {
        "/etc/sudoers": "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n",
        "/etc/sudoers.d/t": sudoers_d,
    })
    collected = SudoersCollector(source=LiveSource(root=root)).collect()
    return rules.rule_sudoers_nopasswd({**collected, "users": users})


def test_D2_line_continuation_does_not_hide_nopasswd(tmp_path):
    [f] = _sudo_findings(tmp_path, "alice ALL=(ALL) \\\n    NOPASSWD: ALL\n", [_user("alice")])
    assert "alice" in f.description
    # Spans two physical lines: removing "the line" can't work — flag-only.
    assert f.remediation_available is False and f.guided_remediation


def test_D2_user_list_reports_each_user(tmp_path):
    findings = _sudo_findings(tmp_path, "alice, bob ALL=(ALL) NOPASSWD: ALL\n",
                              [_user("alice"), _user("bob", 1002)])
    assert sorted(f.description.split("'")[1] for f in findings) == ["alice", "bob"]
    # Deleting the line would also revoke the other user's grant.
    assert not any(f.remediation_available for f in findings)


def test_D2_user_alias_is_resolved(tmp_path):
    [f] = _sudo_findings(tmp_path, "User_Alias OPS = alice\nOPS ALL=(ALL) NOPASSWD: ALL\n",
                         [_user("alice")])
    assert "alice" in f.description


def test_D2_nopasswd_later_in_the_command_list(tmp_path):
    [f] = _sudo_findings(tmp_path, "alice ALL=(ALL) /usr/bin/id, NOPASSWD: /bin/bash\n",
                         [_user("alice")])
    assert f.remediation_available is True


def test_D2_defaults_not_authenticate_is_passwordless(tmp_path):
    [f] = _sudo_findings(tmp_path, "Defaults:alice !authenticate\nalice ALL=(ALL) ALL\n",
                         [_user("alice")])
    assert "!authenticate" in f.description
    # Removing the rule would revoke sudo, not just the password exemption.
    assert f.remediation_available is False


def test_D2_defaults_user_list_with_spaces(tmp_path):
    findings = _sudo_findings(
        tmp_path, "Defaults:alice, bob !lecture, !authenticate\nalice, bob ALL=(ALL) ALL\n",
        [_user("alice"), _user("bob", 1002)])
    assert len(findings) == 2


def test_D2_ordinary_password_rules_stay_quiet(tmp_path):
    assert _sudo_findings(tmp_path, "alice ALL=(ALL) ALL\nbob ALL=(ALL) PASSWD: ALL\n",
                          [_user("alice"), _user("bob", 1002)]) == []


def test_D2_all_users_rule_is_flag_only(tmp_path):
    [f] = _sudo_findings(tmp_path, "ALL ALL=(ALL) NOPASSWD: ALL\n", [_user("alice")])
    assert "every user" in f.title and f.remediation_available is False


def test_D2_old_rule_dicts_without_principals_still_work():
    findings = rules.rule_sudoers_nopasswd({
        "sudoers_rules": [{"user": "alice", "options": "NOPASSWD", "source": "/etc/sudoers",
                           "raw_line": "alice ALL=(ALL) NOPASSWD: ALL"}],
        "users": [_user("alice")],
    })
    assert len(findings) == 1 and findings[0].remediation_available


# ─── D3: userspace `watchdog` daemon is not a fake kernel thread ─────────────

def _masquerade(name, cmdline, exe):
    return rules.rule_process_masquerade({"processes": [
        {"pid": 42, "name": name, "cmdline": cmdline, "exe": exe, "uid": 0}]})


def test_D3_watchdog_daemon_is_not_flagged():
    assert _masquerade("watchdog", "/usr/sbin/watchdog", "/usr/sbin/watchdog") == []


def test_D3_kernel_watchdog_names_are_still_caught():
    assert _masquerade("watchdogd", "watchdogd", "/tmp/x")
    assert _masquerade("watchdog/0", "watchdog/0", "/tmp/x")


# ─── D4: stock Ubuntu 24.04 / cloud image baselines ──────────────────────────

def test_D4_polkit_124_helper_is_known_setuid():
    assert rules.rule_setuid_inventory({"setuid_binaries": [
        {"path": "/usr/lib/polkit-1/polkit-agent-helper-1", "setuid": True, "setgid": False},
    ]}) == []


def test_D4_cloud_image_nss_modules_are_not_backdoors():
    nss = ("passwd: files systemd extrausers cache_oslogin oslogin\n"
           "hosts: files libvirt libvirt_guest dns\n")
    assert rules.rule_pam_backdoor({"pam_files": [], "nsswitch_content": nss}) == []


# ─── M1: remediation finds lines the collectors reported stripped ────────────

def _finding(rule_id, path, raw):
    return Finding(rule_id=rule_id, severity=Severity.HIGH, title="t", description="d",
                   artifact_path=str(path), raw_value=raw, remediation_available=True)


def test_M1_indented_ld_preload_export_is_commented_out(tmp_path):
    from ubuntils.remediators.environment import EnvironmentRemediator
    rc = tmp_path / ".bashrc"
    rc.write_text("if true; then\n    export LD_PRELOAD=/tmp/x.so\nfi\n")
    result = EnvironmentRemediator(backup_base=str(tmp_path / "b")).remediate(
        _finding("LD_PRELOAD_INJECT", rc, "export LD_PRELOAD=/tmp/x.so"), dry_run=False)
    assert result.status == RemediationStatus.SUCCESS, result.message
    assert "# " in rc.read_text().splitlines()[1]


def test_M1_empty_raw_value_never_matches_blank_lines(tmp_path):
    from ubuntils.remediators.ssh import SSHRemediator
    keys = tmp_path / "authorized_keys"
    keys.write_text("ssh-ed25519 AAAA a\n\nssh-ed25519 BBBB b\n")
    result = SSHRemediator(backup_base=str(tmp_path / "b")).remediate(
        _finding("SSH_UNAUTHORIZED_KEY", keys, ""), dry_run=False)
    assert result.status == RemediationStatus.FAILED
    assert keys.read_text() == "ssh-ed25519 AAAA a\n\nssh-ed25519 BBBB b\n"


# ─── W1: --since older than 7 days widens the journald query ─────────────────

def test_W1_since_beyond_seven_days_widens_journal_window(tmp_path):
    from ubuntils import pipeline
    seen = {}

    class _Builder:
        def __init__(self, source):
            pass

        def build(self, since_days=7):
            seen["days"] = since_days
            return []

    since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
    with mock.patch.object(pipeline, "TimelineBuilder", _Builder), \
            mock.patch.object(pipeline, "ALL_COLLECTORS", []):
        pipeline.run_scan(LiveSource(root=str(tmp_path), offline=True), since=since)
    assert seen["days"] >= 30


# ─── W2: a report written via sudo belongs to the user who asked for it ──────

def test_W2_new_report_is_handed_to_the_sudo_user(tmp_path, monkeypatch):
    from ubuntils import cli
    from ubuntils.utils import safe_io
    calls = []
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1234")
    monkeypatch.setenv("SUDO_GID", "1235")
    monkeypatch.setattr(safe_io.os, "fchown", lambda fd, uid, gid: calls.append((uid, gid)))
    out = tmp_path / "r.json"
    cli._emit_report("{}", str(out))
    assert calls == [(1234, 1235)]
    assert oct(os.stat(out).st_mode & 0o777) == "0o600"


def test_W2_an_existing_file_is_never_chowned(tmp_path, monkeypatch):
    from ubuntils.utils import safe_io
    calls = []
    monkeypatch.setattr(safe_io.os, "fchown", lambda *a: calls.append(a))
    existing = tmp_path / "existing"
    existing.write_text("old")
    safe_io.write_private_text(str(existing), "new", new_owner=(1234, 1235))
    assert calls == [] and existing.read_text() == "new"


def test_W2_no_sudo_environment_means_no_chown(monkeypatch):
    from ubuntils import cli
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.delenv("SUDO_UID", raising=False)
    assert cli._sudo_invoker() is None


# ─── T1-T4: TUI ──────────────────────────────────────────────────────────────

def _f(severity, confidence, path):
    f = Finding(rule_id="CRON_TMP_PATH", severity=severity, title="t", description="d",
                artifact_path=path, raw_value="r", remediation_available=True)
    f.confidence = confidence
    return f


async def test_T1_failed_remediation_is_not_shown_as_fixed():
    from textual.app import App
    from textual.widgets import Label
    from ubuntils.tui.findings_panel import FindingsPanel
    finding = _f(Severity.HIGH, 50, "/etc/cron.d/x")

    class _App(App):
        def compose(self):
            yield FindingsPanel([finding])

    async with _App().run_test() as pilot:
        panel = pilot.app.query_one(FindingsPanel)
        panel.mark_fixed(finding, RemediationResult(
            finding_rule_id="CRON_TMP_PATH", status=RemediationStatus.FAILED,
            message="Line not found"))
        await pilot.pause()
        row = str(pilot.app.query_one("#finding-0").query_one(Label).content)
        assert "fixed" not in row and "remediation failed" in row
        assert 0 not in panel._fixed


async def test_T2_remediated_finding_is_not_remediated_twice():
    from textual.app import App
    from ubuntils.tui.findings_panel import FindingsPanel
    finding = _f(Severity.HIGH, 50, "/etc/cron.d/x")

    class _App(App):
        def compose(self):
            yield FindingsPanel([finding])

    async with _App().run_test() as pilot:
        panel = pilot.app.query_one(FindingsPanel)
        panel._selected = finding
        panel.mark_fixed(finding, RemediationResult(
            finding_rule_id="CRON_TMP_PATH", status=RemediationStatus.SUCCESS,
            message="ok"))
        screens = len(pilot.app.screen_stack)
        panel.action_remediate()
        await pilot.pause()
        assert len(pilot.app.screen_stack) == screens  # no confirm modal


def test_T3_summary_lists_the_most_severe_findings_first():
    from ubuntils.tui.summary_screen import _build_summary
    findings = [_f(Severity.LOW, 90, f"/low{i}") for i in range(6)]
    findings.append(_f(Severity.HIGH, 50, "/the-high-one"))
    text = _build_summary(findings, [], {"finding_counts": {}})
    listed = [line for line in text.splitlines() if line.startswith("  ") and "/" in line]
    assert "/the-high-one" in listed[0]


async def test_T4_timeline_panel_handles_a_large_journal():
    import time
    from textual.app import App
    from textual.widgets import DataTable
    from ubuntils.timeline.builder import TimelineEvent
    from ubuntils.tui.timeline_panel import TimelinePanel
    now = datetime.datetime.now(datetime.timezone.utc)
    events = [TimelineEvent(now, "journald", f"[bold]m{i}", "sshd") for i in range(20000)]

    class _App(App):
        def compose(self):
            yield TimelinePanel(events)

    start = time.monotonic()
    async with _App().run_test() as pilot:
        await pilot.pause()
        assert pilot.app.query_one(DataTable).row_count == 20000
    # One widget per event took minutes (or never finished) at this size.
    assert time.monotonic() - start < 30
