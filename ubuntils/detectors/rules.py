import ipaddress
import os
import re
import time
from typing import List

from ubuntils.detectors.finding import Finding, Severity
from ubuntils.detectors.scoring import apply_signal
from ubuntils.utils.validators import (
    command_references_writable_tmp,
    is_login_shell,
    path_in_standard_bins,
    path_in_standard_libs,
    path_in_writable_tmp,
    uid_is_system,
    KNOWN_SETGID_BINARIES,
    KNOWN_SETUID_BINARIES,
    ALLOWED_NSS_MODULES,
    ALLOWED_KERNEL_MODULES,
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
    "22", "53", "67", "80", "123", "443", "465", "587", "853", "993", "995",
})
_ESTABLISHED_STATES = frozenset({"ESTAB", "ESTABLISHED", "SYN-SENT", "SYN_SENT"})
_NON_REMOTE_ADDRS = frozenset({"", "*", "0.0.0.0", "::"})


def _is_loopback(addr: str) -> bool:
    # ss prints IPv4-mapped sockets as "[::ffff:127.0.0.1]"
    addr = addr.strip("[]").split("%", 1)[0]
    if addr.lower().startswith("::ffff:"):
        addr = addr[len("::ffff:"):]
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def _is_remote_established(conn: dict) -> bool:
    if conn.get("state", "").upper() not in _ESTABLISHED_STATES:
        return False
    remote = conn.get("remote_addr", "")
    return remote not in _NON_REMOTE_ADDRS and not _is_loopback(remote)


def _listening_tcp_ports(connections: list) -> set:
    return {c.get("local_port", "") for c in connections
            if c.get("state", "").upper() == "LISTEN" and c.get("proto", "").startswith("tcp")}


def _is_inbound(conn: dict, listening_ports: set) -> bool:
    # An accepted TCP connection sits on a listening port (whoever owns the
    # listener — sshd-session's port 22 is held by ssh.socket/pid 1).
    return conn.get("proto", "").startswith("tcp") and conn.get("local_port", "") in listening_ports


_7_DAYS_SECONDS = 7 * 24 * 3600
_48_HOURS_SECONDS = 48 * 3600

_DANGEROUS_KEY_OPTIONS = ("command=", "no-pty")


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
        if command_references_writable_tmp(command):
            # Lines inside /etc/cron.{hourly,...} scripts are flag-only:
            # deleting one line from a shell script isn't a safe auto-fix.
            is_script = entry.get("kind") == "script"
            findings.append(Finding(
                rule_id="CRON_TMP_PATH",
                severity=Severity.HIGH,
                title="Cron job references writable temp path",
                description=(
                    f"A {'cron script' if is_script else 'cron job'} "
                    f"({entry.get('schedule', '')}) references a world-writable "
                    "temporary directory"
                ),
                artifact_path=source,
                raw_value=command,
                remediation_available=not is_script,
                remediation_description=(
                    None if is_script else "Remove the offending cron entry and create a backup"
                ),
                guided_remediation=(
                    f"Review {source} and remove or fix the offending line by hand."
                    if is_script else None
                ),
            ))
    return findings


def rule_ld_preload_inject(artifacts: dict) -> List[Finding]:
    findings = []
    for defn in artifacts.get("env_definitions", []):
        if defn.get("variable") != "LD_PRELOAD":
            continue
        value = defn.get("value", "")
        source = defn.get("source", "")
        # LD_PRELOAD is a space/colon separated list — every element must be
        # checked, or "/lib/ok.so:/tmp/evil.so" slips through on the first.
        libs = [p for p in re.split(r"[\s:]+", value) if p]
        outside = [p for p in libs if not path_in_standard_libs(p)]
        preload_file = defn.get("kind") == "ld.so.preload"
        # /etc/ld.so.preload is empty on stock Ubuntu and injects into every
        # process, so any entry is reported; a library planted inside /lib
        # (a common rootkit trick) must not hide it.
        if not outside and not preload_file:
            continue
        if preload_file:
            description = (
                "/etc/ld.so.preload loads a library into every process on the system"
                + (f" (outside standard library directories: {', '.join(outside)})"
                   if outside else "")
            )
            remediation = "Remove the entry from /etc/ld.so.preload with a backup"
        else:
            description = (
                "LD_PRELOAD is set to a path outside standard library directories: "
                + ", ".join(outside)
            )
            remediation = "Comment out the LD_PRELOAD line with a backup"
        finding = Finding(
            rule_id="LD_PRELOAD_INJECT",
            severity=Severity.HIGH,
            title="LD_PRELOAD injection detected",
            description=description,
            artifact_path=source,
            raw_value=defn.get("raw_line", value),
            remediation_available=True,
            remediation_description=remediation,
        )
        if outside:
            apply_signal(finding, "outside_standard_libs", 20,
                         f"preloaded from a non-library directory: {', '.join(outside)}")
        if any(path_in_writable_tmp(p) for p in libs):
            apply_signal(finding, "writable_tmp_location", 15,
                         "preloaded library sits in a world-writable temp directory")
        findings.append(finding)
    return findings


def _systemd_exec_reasons(exec_start: str, owner_uid) -> list:
    reasons = []
    if path_in_writable_tmp(exec_start) or command_references_writable_tmp(exec_start):
        reasons.append("references a world-writable temp directory")
    if _CURL_TO_SHELL_RE.search(exec_start):
        reasons.append("downloads and executes code (curl/wget piped to a shell)")
    if _BASE64_DECODE_RE.search(exec_start):
        reasons.append("decodes base64 at runtime")
    if owner_uid is not None and owner_uid != 0:
        reasons.append(f"runs a binary owned by uid {owner_uid}, not root")
    return reasons


def rule_suspicious_systemd_timer(artifacts: dict) -> List[Finding]:
    """Timers (via systemctl) and service units (read from the unit dirs)
    whose Exec* line runs from a writable temp dir or a non-root-owned binary."""
    findings = []
    timer_services = set()
    candidates = []
    for timer in artifacts.get("timers", []):
        timer_services.add(timer.get("activates", ""))
        candidates.append((timer.get("unit", ""), timer.get("unit", ""), timer, "timer"))
    for svc in artifacts.get("services", []):
        if svc.get("unit", "") in timer_services:
            continue  # already reported via its timer
        candidates.append((svc.get("unit", ""), svc.get("unit_path", ""), svc, "service"))

    reported = set()
    for unit, artifact_path, entry, kind in candidates:
        exec_start = entry.get("exec_start", "")
        if not exec_start:
            continue
        reasons = _systemd_exec_reasons(exec_start, entry.get("exec_owner_uid"))
        if not reasons or (unit, exec_start) in reported:
            continue
        reported.add((unit, exec_start))
        dropin = entry.get("dropin", False)
        where = f" (drop-in override {artifact_path})" if dropin else ""
        finding = Finding(
            rule_id="SUSPICIOUS_SYSTEMD_TIMER",
            severity=Severity.HIGH,
            title=f"Systemd {kind} with suspicious ExecStart",
            description=f"Systemd {kind} '{unit}'{where} ExecStart {'; '.join(reasons)}",
            artifact_path=artifact_path,
            raw_value=exec_start,
            remediation_available=False,
            remediation_description=None,
            guided_remediation=(
                f"Inspect the unit, then disable it: "
                f"`systemctl disable --now {unit}` "
                f"(review `systemctl cat {unit}` first)."
            ),
        )
        for reason in reasons:
            apply_signal(finding, "content_match", 15, f"ExecStart {reason}")
        if dropin:
            apply_signal(finding, "dropin_override", 10,
                         "set in a drop-in, where it overrides the unit file's own command")
        findings.append(finding)
    return findings


def _apply_timestamp_signals(finding: Finding, mtime: float, ctime: float, cutoff: float,
                             has_content_signal: bool) -> None:
    """Score a file's recency. ctime can't be set from userspace, so a recent
    ctime behind an old mtime is the signature of `touch -d` timestomping."""
    mtime_recent, ctime_recent = mtime >= cutoff, ctime >= cutoff
    if mtime_recent and ctime_recent:
        apply_signal(finding, "ctime_corroborates_mtime", 20,
                     "ctime is also within the window — harder to forge than mtime alone")
    elif ctime_recent:
        apply_signal(finding, "mtime_backdated", 25,
                     "ctime is recent but mtime is older — the modification time looks "
                     "deliberately backdated (timestomped)")
    elif mtime_recent and not has_content_signal:
        apply_signal(finding, "mtime_only", -20,
                     "recency is the only signal; ctime is not recent (mtime may be forged)")


def rule_ssh_unauthorized_key(artifacts: dict) -> List[Finding]:
    findings = []
    cutoff = time.time() - _7_DAYS_SECONDS
    keys = artifacts.get("authorized_keys", [])

    def _path(entry):
        return entry.get("path") or f"{entry.get('home', '')}/.ssh/authorized_keys"

    keys_per_file: dict = {}
    for entry in keys:
        keys_per_file[_path(entry)] = keys_per_file.get(_path(entry), 0) + 1

    for key_entry in keys:
        path = _path(key_entry)
        mtime = key_entry.get("file_mtime", 0.0)
        ctime = key_entry.get("file_ctime", 0.0)
        recent = mtime >= cutoff or ctime >= cutoff
        # authorized_keys2 has been deprecated since OpenSSH 3.0 but is still
        # read by default — a key there is a hiding place, whatever its age.
        legacy_file = path.endswith("/authorized_keys2")
        if not (recent or legacy_file):
            continue
        key_repr = " ".join(filter(None, [
            key_entry.get("key_type", ""),
            key_entry.get("key_data", ""),
            key_entry.get("comment", ""),
        ]))
        finding = Finding(
            rule_id="SSH_UNAUTHORIZED_KEY",
            severity=Severity.MEDIUM,
            title="Recently added SSH authorized key" if recent else
                  "SSH key in the legacy authorized_keys2 file",
            description=(
                f"{path} (user '{key_entry.get('username', '')}') "
                + ("changed within the last 7 days" if recent else
                   "holds a key — a file few admins check, still honoured by sshd")
            ),
            artifact_path=path,
            # The exact line, so remediation can find it (options and all).
            raw_value=key_entry.get("raw_line") or key_repr,
            remediation_available=True,
            remediation_description=f"Remove this key line from {path}",
        )

        options = key_entry.get("options", "")
        has_dangerous_option = any(opt in options for opt in _DANGEROUS_KEY_OPTIONS)
        if has_dangerous_option:
            apply_signal(finding, "content_match", 30,
                         f"dangerous key option present: {options!r}")
        if legacy_file:
            apply_signal(finding, "legacy_keys_file", 20,
                         "key lives in authorized_keys2, deprecated since OpenSSH 3.0")
        if recent:
            _apply_timestamp_signals(finding, mtime, ctime, cutoff,
                                     has_dangerous_option or legacy_file)
        n_keys = keys_per_file[path]
        if n_keys > 1 and not (has_dangerous_option or legacy_file):
            # File timestamps say *that* the file changed, not which key was
            # added — every key in it would otherwise be auto-removed, the
            # admin's own included. Keep these below the remediation gate.
            apply_signal(finding, "ambiguous_key", -40,
                         f"{path} holds {n_keys} keys; its timestamps can't tell "
                         "which one was added")
        findings.append(finding)
    return findings


def _qualifies_for_nopasswd_check(user_info: dict) -> bool:
    return not uid_is_system(user_info.get("uid", 0)) and is_login_shell(user_info.get("shell", ""))


def rule_sudoers_nopasswd(artifacts: dict) -> List[Finding]:
    findings = []
    users = artifacts.get("users", [])
    users_by_name = {u["username"]: u for u in users}

    for rule in artifacts.get("sudoers_rules", []):
        options = rule.get("options", "")
        if "NOPASSWD" not in options:
            continue
        principal = rule.get("user", "")

        if principal.startswith("%"):
            # Group rule: resolve members (supplementary or primary group).
            group = principal[1:]
            members = sorted(
                u["username"] for u in users
                if (group in u.get("groups", []) or u.get("primary_group") == group)
                and _qualifies_for_nopasswd_check(u)
            )
            if not members:
                continue
            # Flag-only: deleting a group-wide rule like %sudo can strip all
            # sudo access from the system, which remediation must never do.
            findings.append(Finding(
                rule_id="SUDOERS_NOPASSWD",
                severity=Severity.MEDIUM,
                title="NOPASSWD sudoers entry for a group with non-system members",
                description=(
                    f"Group '{group}' has NOPASSWD sudo access; members: {', '.join(members)}"
                ),
                artifact_path=rule.get("source", ""),
                raw_value=rule.get("raw_line", ""),
                remediation_available=False,
                remediation_description=None,
                guided_remediation=(
                    f"Edit with `visudo -f {rule.get('source', '')}` and drop the NOPASSWD tag "
                    f"(or narrow the rule) — do not delete a group rule that may be the "
                    f"system's only sudo access."
                ),
            ))
            continue

        user_info = users_by_name.get(principal)
        if user_info is None or not _qualifies_for_nopasswd_check(user_info):
            continue
        uid = user_info.get("uid", 0)
        findings.append(Finding(
            rule_id="SUDOERS_NOPASSWD",
            severity=Severity.MEDIUM,
            title="NOPASSWD sudoers entry for non-system user",
            description=f"User '{principal}' (uid={uid}) has NOPASSWD sudo access",
            artifact_path=rule.get("source", ""),
            raw_value=rule.get("raw_line", ""),
            remediation_available=True,
            remediation_description="Remove the NOPASSWD sudoers entry and create a backup",
        ))
    return findings


# Kernel-thread names. A userspace implant renaming itself "[kworker/0:1]" is
# the most common Linux masquerade (MITRE T1036.004) — and easy to catch:
# real kernel threads have no executable, so /proc/<pid>/exe doesn't resolve.
_KTHREAD_NAME_RE = re.compile(
    r"^\[?(kworker|kthreadd|ksoftirqd|kswapd\d*|migration|rcu_\w+|watchdogd?|kauditd|"
    r"khungtaskd|kcompactd\d*|khugepaged|kdevtmpfs|kblockd|jbd2|irq|cpuhp|oom_reaper|"
    r"writeback|kintegrityd|ksmd|kthrotld|scsi_eh_\d+)\b"
)


def _impersonates_kernel_thread(name: str, cmdline: str) -> bool:
    bracketed = cmdline.startswith("[") and cmdline.endswith("]")
    return bracketed or bool(_KTHREAD_NAME_RE.match(name)) or bool(_KTHREAD_NAME_RE.match(cmdline))


def rule_process_masquerade(artifacts: dict) -> List[Finding]:
    findings = []
    for proc in artifacts.get("processes", []):
        name = proc.get("name", "")
        exe = proc.get("exe", "")
        cmdline = proc.get("cmdline", "")
        pid = proc.get("pid", "")
        if not exe:
            # Kernel threads have no exe; neither does anything read offline.
            continue
        guided = (
            f"Confirm pid {pid} is malicious "
            f"(`ls -l /proc/{pid}/exe`, `cat /proc/{pid}/cmdline`), "
            f"then terminate it: `kill -9 {pid}`."
        )
        if _impersonates_kernel_thread(name, cmdline):
            finding = Finding(
                rule_id="PROCESS_MASQUERADE",
                severity=Severity.HIGH,
                title="Userspace process disguised as a kernel thread",
                description=(
                    f"Process '{name}' (pid={pid}, cmdline={cmdline!r}) looks like a kernel "
                    f"thread but runs the executable {exe} — real kernel threads have none"
                ),
                artifact_path=f"/proc/{pid}/exe",
                raw_value=exe,
                remediation_available=False,
                remediation_description=None,
                guided_remediation=guided,
            )
            apply_signal(finding, "content_match", 30,
                         "kernel-thread name with a userspace executable cannot be legitimate")
            findings.append(finding)
            continue
        if name not in KNOWN_SYSTEM_BINARIES:
            continue
        if not path_in_standard_bins(exe):
            findings.append(Finding(
                rule_id="PROCESS_MASQUERADE",
                severity=Severity.MEDIUM,
                title="Process masquerading as system binary",
                description=(
                    f"Process '{name}' (pid={pid}) has exe path "
                    f"outside standard binary directories: {exe}"
                ),
                artifact_path=f"/proc/{pid}/exe",
                raw_value=exe,
                remediation_available=False,
                remediation_description=None,
                guided_remediation=guided,
            ))
    return findings


def rule_process_suspicious_connection(artifacts: dict) -> List[Finding]:
    """Join processes and network connections by PID.

    Flags a process holding a non-loopback connection when either its exe sits
    in a suspicious path, or an outbound connection targets a non-standard
    remote port. Inbound (accepted) connections only count toward the exe check:
    their "remote port" is the client's ephemeral port, so the port heuristic
    would flag every SSH login. Snapshot only — this is current artifact state,
    not behavioral monitoring.
    """
    findings = []
    connections = artifacts.get("connections", [])
    listening_ports = _listening_tcp_ports(connections)
    conns_by_pid: dict = {}
    for conn in connections:
        pid = str(conn.get("pid", ""))
        if pid:
            conns_by_pid.setdefault(pid, []).append(conn)

    for proc in artifacts.get("processes", []):
        pid = str(proc.get("pid", ""))
        exe = proc.get("exe", "")
        established = [c for c in conns_by_pid.get(pid, []) if _is_remote_established(c)]
        if not established:
            continue
        outbound = [c for c in established if not _is_inbound(c, listening_ports)]
        # HIGH only for exes in writable temp dirs or deleted from disk;
        # an unusual-but-plausible install location (e.g. /opt) is MEDIUM.
        exe_path = exe[:-len(" (deleted)")] if exe.endswith(" (deleted)") else exe
        high_risk_exe = bool(exe) and (path_in_writable_tmp(exe_path) or exe != exe_path)
        suspicious_exe = high_risk_exe or (bool(exe) and not path_in_standard_bins(exe_path))
        nonstandard = [c for c in outbound if c.get("remote_port", "") not in _COMMON_REMOTE_PORTS]
        if not (suspicious_exe or nonstandard):
            continue
        target = (nonstandard or outbound or established)[0]
        remote = f"{target.get('remote_addr', '')}:{target.get('remote_port', '')}"
        direction = "outbound connection to" if target in outbound else "inbound connection from"
        findings.append(Finding(
            rule_id="PROCESS_SUSPICIOUS_CONNECTION",
            severity=Severity.HIGH if high_risk_exe else Severity.MEDIUM,
            title="Process with suspicious network connection",
            description=(
                f"Process '{proc.get('name', '')}' (pid={pid}, exe={exe}) has an "
                f"{direction} {remote}"
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


def rule_user_empty_password(artifacts: dict) -> List[Finding]:
    """An account with an empty /etc/shadow password field and a login shell.

    Ubuntu's default PAM stack (pam_unix ... nullok) accepts an empty
    password, so anyone can log in to such an account without credentials.
    """
    findings = []
    for user in artifacts.get("users", []):
        if user.get("password_empty") is not True or not user.get("is_login_shell", False):
            continue
        username = user.get("username", "")
        findings.append(Finding(
            rule_id="USER_EMPTY_PASSWORD",
            severity=Severity.HIGH,
            title="Login account with no password",
            description=(
                f"Account '{username}' has an empty password field in /etc/shadow and a "
                "login shell — with PAM's default nullok, it can log in with no password."
            ),
            artifact_path="/etc/shadow",
            raw_value=f"{username}::",
            remediation_available=False,
            remediation_description=None,
            guided_remediation=f"Lock the account until reviewed: `passwd -l {username}`",
        ))
    return findings


_CURL_TO_SHELL_RE = re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b")
_BASE64_DECODE_RE = re.compile(r"\bbase64\b\s+(-d|--decode)\b")


def _rc_content_is_suspicious(content: str) -> bool:
    if _CURL_TO_SHELL_RE.search(content):
        return True
    if _BASE64_DECODE_RE.search(content):
        return True
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("export "):
            stripped = stripped[len("export "):].strip()
        if not stripped.startswith("PATH="):
            continue
        value = stripped[len("PATH="):].strip().strip("\"'")
        if any(path_in_writable_tmp(p) for p in value.split(":")):
            return True
    return False


def rule_shell_rc_modification(artifacts: dict) -> List[Finding]:
    findings = []
    cutoff = time.time() - _48_HOURS_SECONDS

    for entry in artifacts.get("shell_init_files", []):
        mtime = entry.get("mtime", 0.0)
        ctime = entry.get("ctime", 0.0)
        recent = mtime >= cutoff or ctime >= cutoff
        # Suspicious content is reported however old the file is — a
        # curl|bash planted three days ago is no less of a backdoor.
        content_suspicious = _rc_content_is_suspicious(entry.get("content", ""))
        if not (recent or content_suspicious):
            continue
        source = entry.get("source", "")
        owner = entry.get("owner", "")
        finding = Finding(
            rule_id="SHELL_RC_MODIFICATION",
            severity=Severity.MEDIUM if content_suspicious else Severity.LOW,
            title=("Shell init file contains a suspicious command" if content_suspicious
                   else "Shell init file recently modified"),
            description=(
                f"Shell init file '{source}' for user '{owner}' "
                + ("contains a download-and-execute, base64-decode, or writable-tmp PATH line"
                   if content_suspicious else "was modified within the last 48 hours")
            ),
            artifact_path=source,
            raw_value=source,
            remediation_available=False,
            remediation_description=None,
            guided_remediation=(
                f"Review recent additions to {source} "
                f"(`diff` it against a known-good copy or `/etc/skel`), "
                f"then revert any malicious lines by hand."
            ),
        )
        if content_suspicious:
            apply_signal(finding, "content_match", 30,
                         "content matches a known-suspicious pattern "
                         "(curl/wget-to-shell, base64 -d, or a writable-tmp PATH prepend)")
        if recent:
            _apply_timestamp_signals(finding, mtime, ctime, cutoff, content_suspicious)
        findings.append(finding)
    return findings


_PACKAGE_LISTING_CAP = 20


def _is_reportable_dpkg_entry(entry: dict) -> bool:
    if entry.get("missing", False):
        return True
    # Conffiles are expected to be user-edited; only their content hash (5) matters
    # for tamper detection, and even then it's routine — skip conffiles entirely to
    # avoid drowning responders in expected local config edits.
    if entry.get("is_conffile", False):
        return False
    return any(ch in entry.get("flags", "") for ch in ("5", "M", "S"))


def _apply_var_only_downgrade(finding: Finding, paths: list) -> None:
    # Packages keep runtime state under /var (queues, databases, caches) that
    # dpkg still lists in their manifest; a Wazuh manager alone reports 1000+.
    if finding.severity == Severity.HIGH and \
            all(p == "/var" or p.startswith("/var/") for p in paths):
        finding.severity = Severity.MEDIUM
        apply_signal(finding, "mutable_data_path", -20,
                     "every changed file is under /var, where packages keep runtime data "
                     "that changes in normal operation")


def _package_file_finding(entry: dict) -> Finding:
    """One finding per file — used when the owning package is unknown."""
    path = entry.get("path", "")
    if entry.get("missing", False):
        finding = Finding(
            rule_id="PACKAGE_TAMPERED",
            severity=Severity.HIGH,
            title="Package-owned file is missing",
            description=(
                f"'{path}' is owned by an installed package but is missing from disk "
                "(dpkg --verify reports it as absent)"
            ),
            artifact_path=path,
            raw_value="missing",
            remediation_available=False,
            remediation_description=None,
            guided_remediation=(
                f"Reinstall the owning package to restore '{path}': "
                f"dpkg -S {path} 2>/dev/null | cut -d: -f1 | xargs -r apt-get install --reinstall -y"
            ),
        )
        apply_signal(finding, "missing_file", 35,
                     "package-owned file absent from disk — cannot be an incidental edit")
    else:
        flags = entry.get("flags", "")
        finding = Finding(
            rule_id="PACKAGE_TAMPERED",
            severity=Severity.HIGH,
            title="Package-owned file modified since installation",
            description=(
                f"'{path}' differs from the package manifest (dpkg --verify flags: '{flags}')"
            ),
            artifact_path=path,
            raw_value=flags,
            remediation_available=False,
            remediation_description=None,
            guided_remediation=(
                f"Compare against the package's known-good copy and reinstall if tampered: "
                f"dpkg -S {path} 2>/dev/null | cut -d: -f1 | xargs -r apt-get install --reinstall -y"
            ),
        )
        apply_signal(finding, "content_match", 30,
                     f"dpkg --verify reports a real content/mode/size mismatch (flags: '{flags}')")
    _apply_var_only_downgrade(finding, [path])
    return finding


def _package_group_finding(package: str, entries: list) -> Finding:
    """One finding for every reportable file of a package.

    artifact_path is the package name (like KERNEL_MODULE_SUSPICIOUS uses the
    module name), so `--config` can allowlist a known-noisy package in one line.
    """
    missing = [e for e in entries if e.get("missing", False)]
    missing_dirs = [e for e in missing if e.get("is_directory") is True]
    missing_files = [e for e in missing if e.get("is_directory") is not True]
    modified = [e for e in entries if not e.get("missing", False)]
    lines = [f"missing     {e['path']}" for e in missing_files]
    lines += [f"{e.get('flags', '')}   {e['path']}" for e in modified]
    lines += [f"missing     {e['path']}  (directory)" for e in missing_dirs]
    if len(lines) > _PACKAGE_LISTING_CAP:
        extra = len(lines) - _PACKAGE_LISTING_CAP
        lines = lines[:_PACKAGE_LISTING_CAP] + [f"… and {extra} more"]
    finding = Finding(
        rule_id="PACKAGE_TAMPERED",
        # An empty directory going away (removed by hand, or by the package's
        # own scripts) is housekeeping, not tampering.
        severity=Severity.HIGH if modified or missing_files else Severity.LOW,
        title="Package files modified or missing since installation",
        description=(
            f"Package '{package}' has {len(modified)} modified and {len(missing_files)} missing "
            "file(s) compared to its dpkg manifest"
            + (f", plus {len(missing_dirs)} missing director{'y' if len(missing_dirs) == 1 else 'ies'}"
               if missing_dirs else "")
        ),
        artifact_path=package,
        raw_value="\n".join(lines),
        remediation_available=False,
        remediation_description=None,
        guided_remediation=(
            f"Review every difference with `dpkg --verify {package}`; if the files were "
            f"tampered with, restore them: apt-get install --reinstall {package}"
        ),
    )
    if modified:
        apply_signal(finding, "content_match", 30,
                     "dpkg --verify reports a real content/mode/size mismatch")
    if missing_files:
        apply_signal(finding, "missing_file", 35,
                     "package-owned file absent from disk — cannot be an incidental edit")
    if missing_dirs:
        apply_signal(finding, "missing_directory", 10,
                     "package-owned directory (or symlink) absent — usually housekeeping")
    _apply_var_only_downgrade(finding, [e["path"] for e in entries])
    return finding


def rule_package_tampered(artifacts: dict) -> List[Finding]:
    findings = []
    by_package: dict = {}
    for entry in artifacts.get("dpkg_verify_entries", []):
        if not _is_reportable_dpkg_entry(entry):
            continue
        package = entry.get("package")
        if package:
            by_package.setdefault(package, []).append(entry)
        else:
            findings.append(_package_file_finding(entry))
    for package, entries in by_package.items():
        findings.append(_package_group_finding(package, entries))
    return findings


def rule_immutable_flag_set(artifacts: dict) -> List[Finding]:
    findings = []
    for entry in artifacts.get("immutable_flags", []):
        path = entry.get("path", "")
        attrs = entry.get("attrs", "")
        if "i" in attrs or "a" in attrs:
            flag_name = "immutable (i)" if "i" in attrs else "append-only (a)"
            finding = Finding(
                rule_id="IMMUTABLE_FLAG_SET",
                severity=Severity.MEDIUM,
                title="Sensitive file has an unexpected chattr flag",
                description=(
                    f"'{path}' has the {flag_name} attribute set — attackers use this to protect "
                    "implants or hide tampering from further edits/log rotation"
                ),
                artifact_path=path,
                raw_value=attrs,
                remediation_available=False,
                remediation_description=None,
                guided_remediation=f"Review then clear the flag if unexpected: chattr -i -a {path}",
            )
            apply_signal(finding, "content_match", 25,
                         f"chattr attribute string '{attrs}' actually carries {flag_name} — "
                         "stock Ubuntu does not set this on this file by default")
            findings.append(finding)
    return findings


def rule_setuid_inventory(artifacts: dict) -> List[Finding]:
    findings = []
    for entry in artifacts.get("setuid_binaries", []):
        if isinstance(entry, str):  # legacy shape: bare path, bit unknown
            entry = {"path": entry, "setuid": True, "setgid": False}
        path = entry.get("path", "")
        unexpected = []
        if entry.get("setuid") and path not in KNOWN_SETUID_BINARIES:
            unexpected.append("setuid")
        if entry.get("setgid") and path not in KNOWN_SETGID_BINARIES \
                and path not in KNOWN_SETUID_BINARIES:
            unexpected.append("setgid")
        if not unexpected:
            continue
        bits = "+".join(unexpected)
        in_tmp = path_in_writable_tmp(path)
        chmod_flags = ",".join({"setuid": "u-s", "setgid": "g-s"}[bit] for bit in unexpected)
        finding = Finding(
            rule_id="SETUID_INVENTORY",
            severity=Severity.LOW,
            title=f"Unexpected {bits} binary",
            description=(
                f"'{path}' has the {bits} bit set and is not in the known-good baseline"
                + (" (and is located in a world-writable temp directory)" if in_tmp else "")
            ),
            artifact_path=path,
            raw_value=bits,
            remediation_available=False,
            remediation_description=None,
            guided_remediation=(
                f"Review and, if unauthorized, remove the bit: chmod {chmod_flags} {path}"
            ),
        )
        apply_signal(finding, "baseline_deviation", 15,
                     f"{bits} binary not present in ubuntils' known-good baseline")
        if in_tmp:
            apply_signal(finding, "writable_tmp_location", 25,
                         "located under a world-writable temp directory — a common drop location "
                         "for attacker-planted setuid binaries")
        findings.append(finding)
    return findings


def _parse_pam_stacks(content: str) -> dict:
    """Group a pam.d file's auth/account lines by type as (control, module, line).

    Only auth and account matter for a bypass: pam_permit in session/password
    stacks can't grant a login. ``@include`` and ``include``/``substack`` lines
    are kept with an "include" control — the included file is checked on its own.
    """
    stacks: dict = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("@include"):
            for ptype in ("auth", "account"):
                stacks.setdefault(ptype, []).append(("include", "", stripped))
            continue
        tokens = stripped.split()
        ptype = tokens[0].lstrip("-")
        if ptype not in ("auth", "account") or len(tokens) < 3:
            continue
        if tokens[1].startswith("["):
            # Bracketed controls can contain spaces: [success=1 default=ignore]
            end = next((i for i, t in enumerate(tokens[1:], 1) if t.endswith("]")), None)
            if end is None or end + 1 >= len(tokens):
                continue
            control, module = " ".join(tokens[1:end + 1]), tokens[end + 1]
        else:
            control, module = tokens[1], tokens[2]
        if control in ("include", "substack"):
            control = "include"
        stacks.setdefault(ptype, []).append((control, os.path.basename(module), stripped))
    return stacks


def _pam_control_gates(control: str) -> bool:
    # A control that can make the stack fail: stock Ubuntu's gate is
    # `requisite pam_deny.so`; `[... default=die]` does the same job.
    if control in ("required", "requisite", "include"):
        return True
    return control.startswith("[") and ("default=die" in control or "default=bad" in control)


def _pam_permit_bypass_line(content: str):
    """Return the pam_permit.so line that can grant auth/account on its own, else None.

    Stock Ubuntu ends every common-* stack with `required pam_permit.so` behind a
    `requisite pam_deny.so` gate — harmless. It becomes a bypass when pam_permit
    short-circuits the stack (sufficient / success=done), or when nothing else
    in that stack can fail it (the deny gate was removed or demoted).
    """
    for stack in _parse_pam_stacks(content).values():
        permits = [e for e in stack if e[1] == "pam_permit.so"]
        if not permits:
            continue
        for control, _module, line in permits:
            if control == "sufficient" or (control.startswith("[") and "success=done" in control):
                return line
        if not any(_pam_control_gates(c) for c, m, _ in stack if m != "pam_permit.so"):
            return permits[0][2]
    return None


def rule_pam_backdoor(artifacts: dict) -> List[Finding]:
    findings = []
    for entry in artifacts.get("pam_files", []):
        path = entry.get("path", "")
        line = _pam_permit_bypass_line(entry.get("content", ""))
        if line is None:
            continue
        finding = Finding(
            rule_id="PAM_BACKDOOR",
            severity=Severity.HIGH,
            title="PAM config unconditionally permits authentication",
            description=(
                f"'{path}' uses pam_permit.so in a way that can grant authentication on its "
                "own (it short-circuits the stack, or no other module can fail it) — a common "
                "backdoor technique to bypass authentication for a service"
            ),
            artifact_path=path,
            raw_value=line,
            remediation_available=False,
            remediation_description=None,
            guided_remediation=(
                f"Review {path}: remove the pam_permit.so line, or restore the "
                "`requisite pam_deny.so` gate in front of it"
            ),
        )
        apply_signal(finding, "content_match", 30,
                     "pam_permit.so can decide the auth/account stack — read from the PAM config, "
                     "not inferred")
        findings.append(finding)  # one finding per file is enough signal

    nsswitch = artifacts.get("nsswitch_content", "")
    reported_modules = set()
    for line in nsswitch.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        _database, _sep, modules_str = stripped.partition(":")
        # Strip trailing inline comments (anything after an unquoted #)
        if "#" in modules_str:
            modules_str = modules_str[:modules_str.index("#")]
        for token in modules_str.split():
            # Skip action clauses (tokens starting with [, like [NOTFOUND=return])
            if token.startswith("["):
                continue
            module = token.split("=")[0]  # Extract module name (before any = option)
            if not module or module in ALLOWED_NSS_MODULES or module in reported_modules:
                continue
            # One finding per unknown module, not one per database line.
            reported_modules.add(module)
            finding = Finding(
                rule_id="PAM_BACKDOOR",
                severity=Severity.HIGH,
                title="Unexpected NSS module in nsswitch.conf",
                description=(
                    f"nsswitch.conf references NSS module '{module}', which is not in the "
                    "standard Ubuntu module set — unexpected NSS modules can intercept lookups "
                    "(e.g. name resolution or user auth) system-wide"
                ),
                artifact_path="/etc/nsswitch.conf",
                raw_value=stripped,
                remediation_available=False,
                remediation_description=None,
                guided_remediation="Review /etc/nsswitch.conf and remove the unexpected module",
            )
            # Deliberately a lower weight than the pam_permit.so branch above: this
            # allowlist can't anticipate every legitimate environment (see README
            # caveat), so an unrecognized-but-legitimate NSS module (e.g. a module
            # this build's allowlist doesn't know about) shouldn't land at the same
            # confidence as a literal, unambiguous pam_permit.so backdoor match.
            apply_signal(finding, "content_match", 18,
                         f"module name '{module}' is present verbatim in nsswitch.conf but is not "
                         "in ubuntils' built-in NSS module allowlist")
            findings.append(finding)
    return findings


def rule_kernel_module_suspicious(artifacts: dict) -> List[Finding]:
    findings = []
    for module in artifacts.get("kernel_modules", []):
        name = module.get("name", "")
        if name in ALLOWED_KERNEL_MODULES:
            continue
        finding = Finding(
            rule_id="KERNEL_MODULE_SUSPICIOUS",
            # LOW: the baseline is intentionally narrow and legitimate
            # hardware/vendor drivers miss it constantly — HIGH flooded every
            # laptop/desktop scan. Allowlist known modules via --config.
            severity=Severity.LOW,
            title="Loaded kernel module not in the expected set",
            description=(
                f"Module '{name}' is loaded but is not in ubuntils' baseline of common built-in "
                "modules. This may be a legitimate hardware/vendor driver (see README) or an "
                "unexpected/malicious module — verify manually"
            ),
            artifact_path=name,
            raw_value=str(module),
            remediation_available=False,
            remediation_description=None,
            guided_remediation=(
                f"Inspect the module and unload if unauthorized: modinfo {name} && rmmod {name}"
            ),
        )
        # Deliberately a small weight: this baseline is intentionally narrow (see the README
        # caveat and Global Constraints), so being unallowlisted alone is weak evidence —
        # legitimate hardware/vendor drivers hit this constantly. Keep the finding at MEDIUM
        # confidence by default; a responder's --config allowlist is the real fix for noise,
        # not an inflated confidence score here.
        apply_signal(finding, "unallowlisted_module", 10,
                     "module name is not present in ubuntils' built-in module baseline")
        findings.append(finding)
    return findings
