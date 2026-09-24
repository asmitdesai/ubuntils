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
        finding = Finding(
            rule_id="SUSPICIOUS_SYSTEMD_TIMER",
            severity=Severity.HIGH,
            title=f"Systemd {kind} with suspicious ExecStart",
            description=f"Systemd {kind} '{unit}' ExecStart {'; '.join(reasons)}",
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
        findings.append(finding)
    return findings


def rule_ssh_unauthorized_key(artifacts: dict) -> List[Finding]:
    findings = []
    now = time.time()
    cutoff = now - _7_DAYS_SECONDS
    for key_entry in artifacts.get("authorized_keys", []):
        file_mtime = key_entry.get("file_mtime", 0.0)
        if file_mtime < cutoff:
            continue
        key_repr = " ".join(filter(None, [
            key_entry.get("key_type", ""),
            key_entry.get("key_data", ""),
            key_entry.get("comment", ""),
        ]))
        finding = Finding(
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
        )

        options = key_entry.get("options", "")
        has_dangerous_option = any(opt in options for opt in _DANGEROUS_KEY_OPTIONS)
        if has_dangerous_option:
            apply_signal(finding, "content_match", 30,
                         f"dangerous key option present: {options!r}")

        file_ctime = key_entry.get("file_ctime", 0.0)
        ctime_also_recent = file_ctime >= cutoff
        if ctime_also_recent:
            apply_signal(finding, "ctime_corroborates_mtime", 20,
                         "ctime is also within the window — harder to forge than mtime alone")
        elif not has_dangerous_option:
            apply_signal(finding, "mtime_only", -20,
                         "recency is the only signal; ctime is not recent (mtime may be forged)")

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
                guided_remediation=(
                    f"Confirm pid {proc.get('pid', '')} is malicious "
                    f"(`ls -l /proc/{proc.get('pid', '')}/exe`, "
                    f"`cat /proc/{proc.get('pid', '')}/cmdline`), "
                    f"then terminate it: `kill -9 {proc.get('pid', '')}`."
                ),
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
        # HIGH only for exes in writable temp dirs or deleted from disk;
        # an unusual-but-plausible install location (e.g. /opt) is MEDIUM.
        exe_path = exe[:-len(" (deleted)")] if exe.endswith(" (deleted)") else exe
        high_risk_exe = bool(exe) and (path_in_writable_tmp(exe_path) or exe != exe_path)
        suspicious_exe = high_risk_exe or (bool(exe) and not path_in_standard_bins(exe_path))
        nonstandard = [c for c in outbound if c.get("remote_port", "") not in _COMMON_REMOTE_PORTS]
        if not (suspicious_exe or nonstandard):
            continue
        target = outbound[0]
        remote = f"{target.get('remote_addr', '')}:{target.get('remote_port', '')}"
        findings.append(Finding(
            rule_id="PROCESS_SUSPICIOUS_CONNECTION",
            severity=Severity.HIGH if high_risk_exe else Severity.MEDIUM,
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
        if mtime < cutoff:
            continue
        source = entry.get("source", "")
        owner = entry.get("owner", "")
        finding = Finding(
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
            guided_remediation=(
                f"Review recent additions to {source} "
                f"(`diff` it against a known-good copy or `/etc/skel`), "
                f"then revert any malicious lines by hand."
            ),
        )

        content = entry.get("content", "")
        content_suspicious = _rc_content_is_suspicious(content)
        if content_suspicious:
            apply_signal(finding, "content_match", 30,
                         "content matches a known-suspicious pattern "
                         "(curl/wget-to-shell, base64 -d, or a writable-tmp PATH prepend)")

        ctime = entry.get("ctime", 0.0)
        ctime_also_recent = ctime >= cutoff
        if ctime_also_recent:
            apply_signal(finding, "ctime_corroborates_mtime", 20,
                         "ctime is also within the window — harder to forge than mtime alone")
        elif not content_suspicious:
            apply_signal(finding, "mtime_only", -20,
                         "recency is the only signal; ctime is not recent (mtime may be forged)")

        findings.append(finding)
    return findings


def rule_package_tampered(artifacts: dict) -> List[Finding]:
    findings = []
    for entry in artifacts.get("dpkg_verify_entries", []):
        path = entry.get("path", "")
        flags = entry.get("flags", "")
        missing = entry.get("missing", False)
        is_conffile = entry.get("is_conffile", False)

        if missing:
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
            findings.append(finding)
            continue

        # Conffiles are expected to be user-edited; only their content hash (5) matters
        # for tamper detection, and even then it's routine — skip conffiles entirely to
        # avoid drowning responders in expected local config edits.
        if is_conffile:
            continue

        if any(ch in flags for ch in ("5", "M", "S")):
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
            findings.append(finding)
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


def rule_pam_backdoor(artifacts: dict) -> List[Finding]:
    findings = []
    for entry in artifacts.get("pam_files", []):
        path = entry.get("path", "")
        content = entry.get("content", "")
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "pam_permit.so" in stripped:
                finding = Finding(
                    rule_id="PAM_BACKDOOR",
                    severity=Severity.HIGH,
                    title="PAM config unconditionally permits authentication",
                    description=(
                        f"'{path}' loads pam_permit.so, which always succeeds — a common backdoor "
                        "technique to bypass authentication for a service"
                    ),
                    artifact_path=path,
                    raw_value=stripped,
                    remediation_available=False,
                    remediation_description=None,
                    guided_remediation=f"Review and remove the pam_permit.so line from {path}",
                )
                apply_signal(finding, "content_match", 30,
                             "pam_permit.so is present verbatim in the PAM stack — not inferred")
                findings.append(finding)
                break  # one finding per file is enough signal

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
