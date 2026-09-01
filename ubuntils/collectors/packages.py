from ubuntils.collectors.base import BaseCollector


class PackageCollector(BaseCollector):
    def collect(self) -> dict:
        return {
            "dpkg_verify_entries": self._dpkg_verify_entries(),
            "immutable_flags": self._immutable_flag_entries(),
            "setuid_binaries": self._setuid_binaries(),
        }

    def _dpkg_verify_entries(self) -> list:
        stdout, _stderr, rc = self.source.run("dpkg_verify", ["dpkg", "--verify"])
        # dpkg --verify exits non-zero when it finds ANY discrepancy — that is
        # the expected/interesting case, not a failure to treat as "no data".
        if stdout is None:
            return []
        entries = []
        for line in stdout.splitlines():
            line = line.rstrip()
            if not line:
                continue
            parts = line.split(None, 2) if line.startswith("missing") else line.split(" ", 1)
            if line.startswith("missing"):
                # "missing   /usr/bin/sshd" -> ["missing", "/usr/bin/sshd"] (extra
                # whitespace collapses via split(None, 2))
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
        return entries

    def _immutable_flag_entries(self) -> list:
        return []  # implemented in Task 2

    def _setuid_binaries(self) -> list:
        return []  # implemented in Task 3
