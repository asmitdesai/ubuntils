from ubuntils.collectors.base import BaseCollector


SENSITIVE_ATTR_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers",
    "/etc/ld.so.preload", "/etc/crontab", "/etc/environment",
    "/etc/pam.d/common-auth", "/etc/pam.d/sshd", "/etc/nsswitch.conf",
    "/var/log/auth.log", "/var/log/syslog", "/var/log/wtmp", "/var/log/btmp",
]

# find's start-point list for the setuid/setgid scan. Deliberately -xdev
# (bounded runtime; see README) but includes the paths a real attacker is
# most likely to drop a binary into (/opt, /home, /srv), not just system dirs.
SETUID_FIND_PATHS = [
    "/usr", "/bin", "/sbin", "/opt", "/home", "/srv", "/tmp", "/var/tmp", "/dev/shm",
]

# Full find(1) argument list for the setuid/setgid scan, shared with
# `ubuntils collect` (cli.COLLECT_COMMANDS) so live and bundle runs match.
# -printf emits the octal mode so setuid (4000) and setgid (2000) can be told
# apart — both are searched for, but they are different risks.
SETUID_FIND_ARGS = [
    *SETUID_FIND_PATHS,
    "-xdev", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-type", "f",
    "-printf", "%m %p\\n",
]

# dpkg --verify walks every installed package's file manifest and can take
# well over the default 30s command timeout on a real host with a large
# package database; find_setuid similarly walks large directory trees.
# Both must use the SAME timeout value live (PackageCollector) and during
# `ubuntils collect` bundle capture (see bundle/writer.py's COMMAND_TIMEOUTS)
# — kept in cli.py alongside COLLECT_COMMANDS so the two never drift apart.
DPKG_VERIFY_TIMEOUT = 600
FIND_SETUID_TIMEOUT = 300


class PackageCollector(BaseCollector):
    def collect(self) -> dict:
        dpkg_entries, dpkg_failed = self._dpkg_verify_entries()
        setuid_entries, setuid_failed = self._setuid_binaries()
        if dpkg_failed:
            self.degraded.append("`dpkg --verify` failed or timed out")
        if setuid_failed:
            self.degraded.append("setuid/setgid `find` failed or timed out")
        return {
            "dpkg_verify_entries": dpkg_entries,
            "immutable_flags": self._immutable_flag_entries(),
            "setuid_binaries": setuid_entries,
            # Distinguishes "collection timed out / failed to run" (rc == -1,
            # per utils/shell.run_command's convention) from "ran successfully
            # and genuinely found nothing" (rc == 0, empty stdout) — the two
            # are otherwise indistinguishable once collapsed to an empty list.
            "dpkg_verify_collection_failed": dpkg_failed,
            "setuid_collection_failed": setuid_failed,
        }

    def _dpkg_verify_entries(self) -> tuple:
        stdout, _stderr, rc = self.source.run(
            "dpkg_verify", ["dpkg", "--verify"], timeout=DPKG_VERIFY_TIMEOUT
        )
        # dpkg --verify exits non-zero when it finds ANY discrepancy — that is
        # the expected/interesting case, not a failure to treat as "no data".
        # rc == -1 is shell.run_command's convention for a timeout/OSError —
        # that IS a failure, distinct from a clean run with empty output.
        if rc == -1:
            return [], True
        if not stdout:
            return [], False
        entries = []
        for line in stdout.splitlines():
            line = line.rstrip()
            if not line:
                continue
            if line.startswith("missing"):
                # "missing   /usr/bin/sshd" -> ["missing", "/usr/bin/sshd"] (extra
                # whitespace collapses via split(None, 2))
                parts = line.split(None, 2)
                path = parts[-1].strip()
                entries.append({"path": path, "flags": "", "is_conffile": False, "missing": True})
                continue
            flags_and_rest = line.split(" ", 1)
            if len(flags_and_rest) != 2:
                continue
            flags, rest = flags_and_rest
            rest = rest.strip()
            is_conffile = rest.startswith("c ")
            path = rest[2:].strip() if is_conffile else rest
            entries.append({"path": path, "flags": flags, "is_conffile": is_conffile, "missing": False})
        return entries, False

    def _immutable_flag_entries(self) -> list:
        stdout, _stderr, rc = self.source.run(
            "lsattr_sensitive", ["lsattr", "-d", *SENSITIVE_ATTR_PATHS]
        )
        if not stdout:
            return []
        entries = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("lsattr:"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            attrs, path = parts
            entries.append({"path": path.strip(), "attrs": attrs})
        return entries

    def _setuid_binaries(self) -> tuple:
        stdout, _stderr, rc = self.source.run(
            "find_setuid",
            ["find", *SETUID_FIND_ARGS],
            timeout=FIND_SETUID_TIMEOUT,
        )
        if rc == -1:
            return [], True
        if not stdout:
            return [], False
        return [_parse_setuid_line(line) for line in stdout.splitlines() if line.strip()], False


def _parse_setuid_line(line: str) -> dict:
    """"4755 /usr/bin/sudo" -> {"path", "setuid", "setgid"}.

    Bundles collected before -printf was added hold bare paths; for those the
    bit is unknown and the entry is treated as setuid (the old behaviour).
    """
    line = line.strip()
    mode_str, _, path = line.partition(" ")
    if path and mode_str.isdigit():
        mode = int(mode_str, 8)
        return {"path": path.strip(), "setuid": bool(mode & 0o4000),
                "setgid": bool(mode & 0o2000)}
    return {"path": line, "setuid": True, "setgid": False}
