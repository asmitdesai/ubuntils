import os
import time
from unittest.mock import MagicMock, patch

import pytest

from ubuntils.detectors.engine import ALL_RULES, DetectionEngine
from ubuntils.detectors.finding import Severity
from ubuntils.detectors.rules import (
    rule_cron_root_exec,
    rule_cron_tmp_path,
    rule_ld_preload_inject,
    rule_process_masquerade,
    rule_shell_rc_modification,
    rule_ssh_unauthorized_key,
    rule_sudoers_nopasswd,
    rule_suspicious_systemd_timer,
)

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

    artifacts = {"env_definitions": [{
        "owner": "alice",
        "source": str(bashrc),
        "variable": "PATH",
        "value": "/usr/local/bin:$PATH",
        "raw_line": "export PATH=/usr/local/bin:$PATH",
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


def test_rule_shell_rc_modification_deduplicates(tmp_path):
    bashrc = tmp_path / ".bashrc"
    bashrc.write_text("export A=1\nexport B=2\n")
    recent_mtime = time.time() - 3600
    os.utime(bashrc, (recent_mtime, recent_mtime))

    artifacts = {"env_definitions": [
        {"owner": "alice", "source": str(bashrc), "variable": "A", "value": "1", "raw_line": "export A=1"},
        {"owner": "alice", "source": str(bashrc), "variable": "B", "value": "2", "raw_line": "export B=2"},
    ]}
    findings = rule_shell_rc_modification(artifacts)
    assert len(findings) == 1


def test_rule_shell_rc_modification_empty_artifacts():
    assert rule_shell_rc_modification({}) == []


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


def test_engine_all_rules_registered():
    assert len(ALL_RULES) == 8
