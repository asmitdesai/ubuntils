import os
import re

from ubuntils.collectors.base import BaseCollector

_INCLUDE_RE = re.compile(r"^[#@](include|includedir)\s+(\S.*)$")
_TAG_RE = re.compile(r"^\s*([A-Z_]+)\s*:")
_ALIAS_PREFIXES = ("User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias", "Cmd_Alias")
_MAX_INCLUDE_DEPTH = 8


class SudoersCollector(BaseCollector):
    def collect(self) -> dict:
        rules = []
        seen: set = set()
        if not self.source.exists("/etc/sudoers"):
            self.degraded.append("/etc/sudoers not readable")
        # /etc/sudoers.d is also scanned directly (not only via includedir) so
        # a file there is reported even if the include line was tampered with.
        paths = ["/etc/sudoers"] + self.source.glob("/etc/sudoers.d/*")
        for path in paths:
            rules.extend(self._parse_sudoers_file(path, seen, depth=0))
        return {"sudoers_rules": rules}

    def _parse_sudoers_file(self, path: str, seen: set, depth: int) -> list:
        if path in seen or depth > _MAX_INCLUDE_DEPTH:
            return []
        seen.add(path)
        try:
            text = self.source.read_text(path)
        except Exception:
            return []

        rules = []
        for line in text.splitlines():
            raw = line.strip()
            if not raw:
                continue
            # Include directives look like comments, so they must be checked
            # *before* the comment skip (previously they were unreachable).
            m = _INCLUDE_RE.match(raw)
            if m:
                rules.extend(self._follow_include(path, m.group(1), m.group(2).strip(),
                                                  seen, depth))
                continue
            if raw.startswith("#") or raw.startswith("Defaults") \
                    or raw.startswith(_ALIAS_PREFIXES):
                continue
            parsed = self._parse_rule_line(raw, path)
            if parsed:
                rules.append(parsed)
        return rules

    def _follow_include(self, current: str, kind: str, target: str, seen: set,
                        depth: int) -> list:
        if not target.startswith("/"):
            target = os.path.join(os.path.dirname(current), target)
        if kind == "include":
            return self._parse_sudoers_file(target, seen, depth + 1)
        rules = []
        for path in self.source.glob(target.rstrip("/") + "/*"):
            name = os.path.basename(path)
            # sudo skips includedir files ending in '~' or containing '.'.
            if name.endswith("~") or "." in name:
                continue
            rules.extend(self._parse_sudoers_file(path, seen, depth + 1))
        return rules

    def _parse_rule_line(self, line: str, source: str):
        # user host = [(run_as)] [TAG: ...] commands
        user_and_rest = line.split(None, 1)
        if len(user_and_rest) < 2:
            return None
        user, rest = user_and_rest
        host, eq, spec = rest.partition("=")
        if not eq:
            return None
        spec = spec.strip()

        run_as = ""
        if spec.startswith("("):
            end = spec.find(")")
            if end != -1:
                run_as = spec[1:end]
                spec = spec[end + 1:].strip()

        # Tags may be stacked: "NOPASSWD: SETENV: /bin/x" or "NOPASSWD:SETENV:ALL".
        tags = []
        while True:
            m = _TAG_RE.match(spec)
            if not m:
                break
            tags.append(m.group(1))
            spec = spec[m.end():]

        return {
            "source": source,
            "user": user,
            "is_group": user.startswith("%"),
            "host": host.strip(),
            "run_as": run_as,
            "options": ", ".join(tags),
            "commands": spec.strip(),
            "raw_line": line,
        }
