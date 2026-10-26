import os
import re

from ubuntils.collectors.base import BaseCollector

_INCLUDE_RE = re.compile(r"^[#@](include|includedir)\s+(\S.*)$")
_TAG_RE = re.compile(r"^\s*([A-Z_]+)\s*:")
# sudoers command tags. A tag may appear before *any* command in the list
# ("/usr/bin/id, NOPASSWD: /bin/bash"), not only the first.
_KNOWN_TAGS = (
    "NOPASSWD", "PASSWD", "NOEXEC", "EXEC", "SETENV", "NOSETENV", "LOG_INPUT",
    "NOLOG_INPUT", "LOG_OUTPUT", "NOLOG_OUTPUT", "MAIL", "NOMAIL", "FOLLOW",
    "NOFOLLOW", "INTERCEPT", "NOINTERCEPT",
)
_ANY_TAG_RE = re.compile(r"(?<![\w/.-])(" + "|".join(_KNOWN_TAGS) + r")\s*:")
_DEFAULTS_RE = re.compile(r"^Defaults(?:([:@>!])\s*(\S+))?\s+(.*)$")
_ALIAS_PREFIXES = ("User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias", "Cmd_Alias")
_MAX_INCLUDE_DEPTH = 8
_MAX_ALIAS_DEPTH = 8


def _split_list(text: str) -> list:
    return [item.strip() for item in text.split(",") if item.strip()]


class SudoersCollector(BaseCollector):
    def collect(self) -> dict:
        seen: set = set()
        if not self.source.exists("/etc/sudoers"):
            self.degraded.append("/etc/sudoers not readable")
        # /etc/sudoers.d is also scanned directly (not only via includedir) so
        # a file there is reported even if the include line was tampered with.
        paths = ["/etc/sudoers"] + self.source.glob("/etc/sudoers.d/*")
        lines = []
        for path in paths:
            lines.extend(self._read_logical_lines(path, seen, depth=0))

        # Aliases and Defaults can be defined in any file and apply to rules
        # everywhere, so collect them before parsing a single rule.
        user_aliases = self._user_aliases(lines)
        no_auth = self._authenticate_disabled(lines, user_aliases)

        rules = []
        for path, raw, continued in lines:
            if raw.startswith("Defaults") or raw.startswith(_ALIAS_PREFIXES):
                continue
            parsed = self._parse_rule_line(raw, path)
            if not parsed:
                continue
            parsed["continued"] = continued
            parsed["principals"] = self._expand_users(_split_list(parsed["user"]),
                                                      user_aliases)
            parsed["authenticate_disabled_by"] = sorted(
                src for principal, src in no_auth
                if principal == "*" or principal in parsed["principals"]
            )
            rules.append(parsed)
        return {"sudoers_rules": rules}

    def _read_logical_lines(self, path: str, seen: set, depth: int) -> list:
        """[(path, line, continued)] for a file and everything it includes.

        A line ending in a backslash continues on the next one, as in sudo —
        splitting "alice ALL=(ALL) \\" / "NOPASSWD: ALL" over two lines must
        not hide the NOPASSWD. ``continued`` records that the logical line
        spans several physical ones (remediation removes single lines only).
        """
        if path in seen or depth > _MAX_INCLUDE_DEPTH:
            return []
        seen.add(path)
        try:
            text = self.source.read_text(path)
        except Exception:
            return []

        out = []
        pending, parts = "", 0
        for line in text.splitlines() + [""]:
            stripped = line.strip()
            if stripped.endswith("\\") and not stripped.startswith("#"):
                pending += stripped[:-1] + " "
                parts += 1
                continue
            raw = (pending + stripped).strip()
            continued = parts > 0
            pending, parts = "", 0
            if not raw:
                continue
            # Include directives look like comments, so they must be checked
            # *before* the comment skip (previously they were unreachable).
            m = _INCLUDE_RE.match(raw)
            if m:
                out.extend(self._follow_include(path, m.group(1), m.group(2).strip(),
                                                seen, depth))
                continue
            if raw.startswith("#"):
                continue
            out.append((path, re.sub(r"\s+", " ", raw) if continued else raw, continued))
        return out

    def _follow_include(self, current: str, kind: str, target: str, seen: set,
                        depth: int) -> list:
        if not target.startswith("/"):
            target = os.path.join(os.path.dirname(current), target)
        if kind == "include":
            return self._read_logical_lines(target, seen, depth + 1)
        lines = []
        for path in self.source.glob(target.rstrip("/") + "/*"):
            name = os.path.basename(path)
            # sudo skips includedir files ending in '~' or containing '.'.
            if name.endswith("~") or "." in name:
                continue
            lines.extend(self._read_logical_lines(path, seen, depth + 1))
        return lines

    @staticmethod
    def _user_aliases(lines: list) -> dict:
        """User_Alias name -> its member list ("User_Alias A = x, y : B = z")."""
        aliases: dict = {}
        for _path, raw, _continued in lines:
            if not raw.startswith("User_Alias"):
                continue
            for definition in raw[len("User_Alias"):].split(":"):
                name, eq, members = definition.partition("=")
                if eq and name.strip():
                    aliases[name.strip()] = _split_list(members)
        return aliases

    @staticmethod
    def _expand_users(items: list, aliases: dict, depth: int = 0) -> list:
        """Resolve User_Alias names; negated items ("!bob") grant nothing."""
        out = []
        for item in items:
            if item.startswith("!"):
                continue
            if item in aliases and depth < _MAX_ALIAS_DEPTH:
                out.extend(SudoersCollector._expand_users(aliases[item], aliases, depth + 1))
            elif item not in out:
                out.append(item)
        return out

    def _authenticate_disabled(self, lines: list, aliases: dict) -> list:
        """[(principal, source)] for each Defaults line setting !authenticate.

        "Defaults:alice !authenticate" makes every sudo rule for alice
        passwordless, exactly like NOPASSWD. Scoped to a user list it applies to
        those users; unscoped, or scoped to a host, runas user or command, it
        can apply to anyone ("*").
        """
        out = []
        for path, raw, _continued in lines:
            m = _DEFAULTS_RE.match(re.sub(r"\s*,\s*", ",", raw))
            if not m or "!authenticate" not in [p.replace(" ", "") for p in
                                                _split_list(m.group(3))]:
                continue
            source = f"{path}: {raw}"
            if m.group(1) == ":":
                for principal in self._expand_users(_split_list(m.group(2)), aliases):
                    out.append((principal, source))
            else:
                out.append(("*", source))
        return out

    def _parse_rule_line(self, line: str, source: str):
        # user_list host_list = [(run_as)] [TAG: ...] commands
        lhs, eq, spec = line.partition("=")
        if not eq:
            return None
        # "alice, bob ALL" -> ["alice,bob", "ALL"]
        lhs_tokens = re.sub(r"\s*,\s*", ",", lhs.strip()).split()
        if len(lhs_tokens) < 2:
            return None
        user, host = lhs_tokens[0], " ".join(lhs_tokens[1:])
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
        # ...and may also precede a later command in the list.
        for tag in _ANY_TAG_RE.findall(spec):
            if tag not in tags:
                tags.append(tag)

        return {
            "source": source,
            "user": user,
            "is_group": user.startswith("%"),
            "host": host,
            "run_as": run_as,
            "options": ", ".join(tags),
            "commands": spec.strip(),
            "raw_line": line,
        }
