import os
import re
import time
from typing import List

from ubuntils.detectors.finding import Finding, Severity
from ubuntils.utils.validators import (
    is_login_shell,
    path_in_standard_bins,
    path_in_standard_libs,
    path_in_writable_tmp,
    uid_is_system,
)

KNOWN_SYSTEM_BINARIES = frozenset({
    "sshd", "init", "systemd", "cron", "bash", "sh", "python", "python3",
    "perl", "ruby", "nc", "netcat", "curl", "wget", "ps", "ls", "cat",
    "grep", "find", "top", "nginx", "apache2", "httpd", "mysqld", "postgres",
    "docker", "containerd", "kubelet", "ssh", "gpg", "su", "sudo",
})

SHELL_INIT_FILENAMES = frozenset({
    ".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile",
})

# Common destination ports for legitimate outbound traffic. A connection to a
# port outside this set from a flagged process is more interesting.
_COMMON_REMOTE_PORTS = frozenset({
    "22", "53", "80", "123", "443", "465", "587", "853", "993", "995",
})
_OUTBOUND_STATES = frozenset({"ESTAB", "ESTABLISHED", "SYN-SENT", "SYN_SENT"})
_NON_REMOTE_ADDRS = frozenset({"", "*", "0.0.0.0", "::", "127.0.0.1", "::1"})


def _is_outbound(conn: dict) -> bool:
    if conn.get("state", "").upper() not in _OUTBOUND_STATES:
        return False
    return conn.get("remote_addr", "") not in _NON_REMOTE_ADDRS


_7_DAYS_SECONDS = 7 * 24 * 3600
_48_HOURS_SECONDS = 48 * 3600


def rule_cron_root_exec(artifacts: dict) -> List[Finding]:
    findings = []
    for entry in artifacts.get("cron_entries", []):
        owner = entry.get("owner", "")
        run_as = entry.get("run_as", "")
        command = entry.get("command", "")
        source = entry.get("source", "")

        if owner == "root":
            continue

        triggered = run_as == "root" or bool(re.search(r"\bsudo\b", command))
        if triggered:
            findings.append(Finding(
                rule_id="CRON_ROOT_EXEC",
                severity=Severity.HIGH,
                title="Cron entry escalates to root",
                description=(
                    f"Non-root user '{owner}' has a cron entry that runs as root or uses sudo"
                ),
                artifact_path=source,
                raw_value=command,
                remediation_available=True,
                remediation_description="Remove the offending cron entry and create a backup",
            ))
    return findings


def rule_cron_tmp_path(artifacts: dict) -> List[Finding]:
    findings = []
    for entry in artifacts.get("cron_entries", []):
        command = entry.get("command", "")
        source = entry.get("source", "")
        if path_in_writable_tmp(command) or any(
            f" {p}" in command or command.startswith(p)
            for p in ("/tmp", "/var/tmp", "/dev/shm")
        ):
            findings.append(Finding(
                rule_id="CRON_TMP_PATH",
                severity=Severity.HIGH,
                title="Cron job references writable temp path",
                description="A cron job references a world-writable temporary directory",
                artifact_path=source,
                raw_value=command,
                remediation_available=True,
                remediation_description="Remove the offending cron entry and create a backup",
            ))
    return findings


def rule_ld_preload_inject(artifacts: dict) -> List[Finding]:
    findings = []
    for defn in artifacts.get("env_definitions", []):
        if defn.get("variable") != "LD_PRELOAD":
            continue
        value = defn.get("value", "")
        source = defn.get("source", "")
        if not path_in_standard_libs(value):
            findings.append(Finding(
                rule_id="LD_PRELOAD_INJECT",
                severity=Severity.HIGH,
                title="LD_PRELOAD injection detected",
                description=(
                    "LD_PRELOAD is set to a path outside standard library directories"
                ),
                artifact_path=source,
                raw_value=defn.get("raw_line", value),
                remediation_available=True,
                remediation_description="Comment out the LD_PRELOAD line with a backup",
            ))
    return findings


def rule_suspicious_systemd_timer(artifacts: dict) -> List[Finding]:
    findings = []
    for timer in artifacts.get("timers", []):
        exec_start = timer.get("exec_start", "")
        if not exec_start:
            continue
        if path_in_writable_tmp(exec_start):
            findings.append(Finding(
                rule_id="SUSPICIOUS_SYSTEMD_TIMER",
                severity=Severity.HIGH,
                title="Systemd timer with suspicious ExecStart path",
                description=(
                    f"Systemd timer '{timer.get('unit', '')}' has ExecStart "
                    "in a world-writable temp directory"
                ),
                artifact_path=timer.get("unit", ""),
                raw_value=exec_start,
                remediation_available=False,
                remediation_description=None,
            ))
    return findings


def rule_ssh_unauthorized_key(artifacts: dict) -> List[Finding]:
    findings = []
    cutoff = time.time() - _7_DAYS_SECONDS
    for key_entry in artifacts.get("authorized_keys", []):
        file_mtime = key_entry.get("file_mtime", 0.0)
        if file_mtime >= cutoff:
            key_repr = " ".join(filter(None, [
                key_entry.get("key_type", ""),
                key_entry.get("key_data", ""),
                key_entry.get("comment", ""),
            ]))
            findings.append(Finding(
                rule_id="SSH_UNAUTHORIZED_KEY",
                severity=Severity.MEDIUM,
                title="Recently added SSH authorized key",
                description=(
                    f"authorized_keys file for '{key_entry.get('username', '')}' "
                    "was modified within the last 7 days"
                ),
                artifact_path=f"{key_entry.get('home', '')}/.ssh/authorized_keys",
                raw_value=key_repr,
                remediation_available=True,
                remediation_description="Remove the unauthorized key entry from authorized_keys",
            ))
    return findings


def rule_sudoers_nopasswd(artifacts: dict) -> List[Finding]:
    findings = []
    users_by_name = {u["username"]: u for u in artifacts.get("users", [])}

    for rule in artifacts.get("sudoers_rules", []):
        options = rule.get("options", "")
        if "NOPASSWD" not in options:
            continue
        username = rule.get("user", "")
        user_info = users_by_name.get(username)
        if user_info is None:
            continue
        uid = user_info.get("uid", 0)
        shell = user_info.get("shell", "")
        if uid_is_system(uid) or not is_login_shell(shell):
            continue
        findings.append(Finding(
            rule_id="SUDOERS_NOPASSWD",
            severity=Severity.MEDIUM,
            title="NOPASSWD sudoers entry for non-system user",
            description=f"User '{username}' (uid={uid}) has NOPASSWD sudo access",
            artifact_path=rule.get("source", ""),
            raw_value=rule.get("raw_line", ""),
            remediation_available=True,
            remediation_description="Remove the NOPASSWD sudoers entry and create a backup",
        ))
    return findings


def rule_process_masquerade(artifacts: dict) -> List[Finding]:
    findings = []
    for proc in artifacts.get("processes", []):
        name = proc.get("name", "")
        exe = proc.get("exe", "")
        if name not in KNOWN_SYSTEM_BINARIES:
            continue
        if not exe:
            continue
        if not path_in_standard_bins(exe):
            findings.append(Finding(
                rule_id="PROCESS_MASQUERADE",
                severity=Severity.MEDIUM,
                title="Process masquerading as system binary",
                description=(
                    f"Process '{name}' (pid={proc.get('pid', '')}) has exe path "
                    f"outside standard binary directories: {exe}"
                ),
                artifact_path=f"/proc/{proc.get('pid', '')}/exe",
                raw_value=exe,
                remediation_available=False,
                remediation_description=None,
            ))
    return findings


def rule_process_suspicious_connection(artifacts: dict) -> List[Finding]:
    """Join processes and network connections by PID.

    Flags a process that holds an outbound connection when either its exe sits
    in a suspicious path, or the connection targets a non-standard remote port.
    Snapshot only — this is current artifact state, not behavioral monitoring.
    """
    findings = []
    conns_by_pid: dict = {}
    for conn in artifacts.get("connections", []):
        pid = str(conn.get("pid", ""))
        if pid:
            conns_by_pid.setdefault(pid, []).append(conn)

    for proc in artifacts.get("processes", []):
        pid = str(proc.get("pid", ""))
        exe = proc.get("exe", "")
        outbound = [c for c in conns_by_pid.get(pid, []) if _is_outbound(c)]
        if not outbound:
            continue
        suspicious_exe = bool(exe) and (
            path_in_writable_tmp(exe) or not path_in_standard_bins(exe)
        )
        nonstandard = [c for c in outbound if c.get("remote_port", "") not in _COMMON_REMOTE_PORTS]
        if not (suspicious_exe or nonstandard):
            continue
        target = outbound[0]
        remote = f"{target.get('remote_addr', '')}:{target.get('remote_port', '')}"
        findings.append(Finding(
            rule_id="PROCESS_SUSPICIOUS_CONNECTION",
            severity=Severity.HIGH if suspicious_exe else Severity.MEDIUM,
            title="Process with suspicious outbound connection",
            description=(
                f"Process '{proc.get('name', '')}' (pid={pid}, exe={exe}) has an "
                f"outbound connection to {remote}"
            ),
            artifact_path=f"/proc/{pid}/exe",
            raw_value=remote,
            remediation_available=False,
            remediation_description=None,
        ))
    return findings


def rule_uid_zero_account(artifacts: dict) -> List[Finding]:
    """Any account other than 'root' with UID 0 has full superuser rights.

    Only root should hold UID 0 (CIS Ubuntu Benchmark 6.2.x). A second UID-0
    account is a classic, high-confidence persistence backdoor — it grants root
    without touching root's own credentials. Near-zero false-positive rate.
    """
    findings = []
    for user in artifacts.get("users", []):
        username = user.get("username", "")
        uid = user.get("uid", -1)
        if uid == 0 and username != "root":
            findings.append(Finding(
                rule_id="USER_UID_ZERO",
                severity=Severity.HIGH,
                title="Non-root account with UID 0",
                description=(
                    f"Account '{username}' has UID 0, granting it full root "
                    "privileges. Only 'root' should have UID 0."
                ),
                artifact_path="/etc/passwd",
                raw_value=f"{username}:x:{uid}:{user.get('gid', '')}:...:{user.get('shell', '')}",
                remediation_available=False,
                remediation_description=None,
            ))
    return findings


def rule_shell_rc_modification(artifacts: dict) -> List[Finding]:
    findings = []
    cutoff = time.time() - _48_HOURS_SECONDS
    seen_paths: set = set()

    for defn in artifacts.get("env_definitions", []):
        owner = defn.get("owner", "")
        source = defn.get("source", "")
        if owner == "system":
            continue
        if os.path.basename(source) not in SHELL_INIT_FILENAMES:
            continue
        if source in seen_paths:
            continue
        seen_paths.add(source)
        try:
            mtime = os.stat(source).st_mtime
        except OSError:
            continue
        if mtime >= cutoff:
            findings.append(Finding(
                rule_id="SHELL_RC_MODIFICATION",
                severity=Severity.LOW,
                title="Shell init file recently modified",
                description=(
                    f"Shell init file '{source}' for user '{owner}' "
                    "was modified within the last 48 hours"
                ),
                artifact_path=source,
                raw_value=source,
                remediation_available=False,
                remediation_description=None,
            ))
    return findings
