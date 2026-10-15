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

# dpkg --verify doesn't name the owning package, so PACKAGE_TAMPERED can't
# group its output without this. dpkg-query does the '/*' glob matching itself
# (no shell), and it's a fixed argv so `ubuntils collect` captures the exact
# same output for offline analysis. Shared with cli.COLLECT_COMMANDS.
DPKG_OWNERS_ARGV = ["dpkg-query", "-S", "/*"]
DPKG_OWNERS_TIMEOUT = 120


class PackageCollector(BaseCollector):
    def collect(self) -> dict:
        dpkg_entries, dpkg_failed = self._dpkg_verify_entries()
        if dpkg_entries:
            self._attribute_packages(dpkg_entries)
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
                # "missing   /usr/bin/sshd" or, for a conffile,
                # "missing   c /etc/init.d/foo" (whitespace collapses via split)
                parts = line.split(None, 2)
                is_conffile = len(parts) == 3 and parts[1] == "c"
                path = (parts[2] if is_conffile else " ".join(parts[1:])).strip()
                entries.append({"path": path, "flags": "", "is_conffile": is_conffile,
                                "missing": True})
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

    def _attribute_packages(self, entries: list) -> None:
        """Set each entry's "package" to its owning package, or None if unknown."""
        stdout, _stderr, rc = self.source.run(
            "dpkg_owners", DPKG_OWNERS_ARGV, timeout=DPKG_OWNERS_TIMEOUT
        )
        wanted = {e["path"] for e in entries}
        owners = {}
        for line in stdout.splitlines() if rc != -1 else []:
            # "pkg: /path", "libc6:arm64: /path", or "pkg-a, pkg-b: /shared/dir".
            # Diversion lines ("diversion by dash from: /bin/sh") aren't ownership.
            if line.startswith("diversion "):
                continue
            packages, sep, path = line.partition(": ")
            if sep and path in wanted:
                owners[path] = packages.split(",")[0].strip()
        if not owners:
            self.degraded.append(
                "package ownership lookup (`dpkg-query -S`) unavailable — "
                "PACKAGE_TAMPERED reported per file"
            )
        states = self._package_states()
        md5sums_cache: dict = {}
        for entry in entries:
            entry["package"] = owners.get(entry["path"])
            entry["package_state"] = states.get(entry["package"]) if entry["package"] else None
            entry["is_directory"] = self._missing_is_directory(entry, md5sums_cache)

    def _package_states(self) -> dict:
        """Package name -> dpkg state ("installed", "config-files", …).

        A package removed but not purged ("config-files") keeps its .list, so
        dpkg --verify still checks — and reports missing — the directory
        skeleton it left behind; that's not tampering. Read from the status
        file rather than a command so offline analysis gets it too. Both
        "libc6" and the Multi-Arch form dpkg-query prints ("libc6:arm64") map.
        """
        try:
            text = self.source.read_text("/var/lib/dpkg/status")
        except Exception:
            return {}
        states: dict = {}
        for stanza in text.split("\n\n"):
            fields = {}
            for line in stanza.splitlines():
                key, sep, value = line.partition(":")
                if sep and not line.startswith((" ", "\t")):
                    fields[key] = value.strip()
            name, status = fields.get("Package"), fields.get("Status", "")
            if not name or not status:
                continue
            state = status.split()[-1]  # "install ok installed" -> "installed"
            states[name] = state
            if fields.get("Architecture"):
                states[f"{name}:{fields['Architecture']}"] = state
        return states

    def _missing_is_directory(self, entry: dict, cache: dict):
        """True if a missing, owned, non-conffile path is a directory (or
        symlink), False if it's a regular file, None if unknown.

        dpkg's <pkg>.md5sums lists every regular file the package ships and
        nothing else, so an owned path absent from it isn't a regular file.
        Bundles don't capture /var/lib/dpkg/info, so offline this is None.
        """
        package = entry.get("package")
        if not entry.get("missing") or not package:
            return None
        if entry.get("is_conffile"):
            return False
        if package not in cache:
            cache[package] = self._read_md5sums_paths(package)
        regular_files = cache[package]
        if regular_files is None:
            return None
        return entry["path"].lstrip("/") not in regular_files

    def _read_md5sums_paths(self, package: str):
        # Multi-Arch: same packages are "libc6:arm64.md5sums"; others drop the arch.
        candidates = [package] + ([package.split(":", 1)[0]] if ":" in package else [])
        for name in candidates:
            try:
                content = self.source.read_text(f"/var/lib/dpkg/info/{name}.md5sums")
            except Exception:
                continue
            # "<md5>  usr/bin/foo" — the path may itself contain spaces.
            return {line.split(None, 1)[1].strip() for line in content.splitlines()
                    if len(line.split(None, 1)) == 2}
        return None

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
