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
