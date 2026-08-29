from ubuntils.collectors.base import BaseCollector


class SudoersCollector(BaseCollector):
    def collect(self) -> dict:
        rules = []
        paths = ["/etc/sudoers"] + self.source.glob("/etc/sudoers.d/*")
        for path in paths:
            rules.extend(self._parse_sudoers_file(path))
        return {"sudoers_rules": rules}

    def _parse_sudoers_file(self, path: str) -> list:
        rules = []
        try:
            for line in self.source.read_text(path).splitlines():
                raw = line.strip()
                if not raw or raw.startswith("#") or raw.startswith("@"):
                    continue
                if raw.startswith("#include") or raw.startswith("@include"):
                    continue
                if "=" not in raw and raw.startswith("Defaults"):
                    continue
                parsed = self._parse_rule_line(raw, path)
                if parsed:
                    rules.append(parsed)
        except Exception:
            pass
        return rules

    def _parse_rule_line(self, line: str, source: str):
        # Basic sudoers rule: user host=(run_as) [options:] commands
        # Skip Defaults lines
        if line.startswith("Defaults"):
            return None
        parts = line.split(None, 2)
        if len(parts) < 3:
            return None
        user = parts[0]
        host_runas_cmds = parts[2] if len(parts) > 2 else parts[1]

        # Extract run_as from (...)
        run_as = ""
        if "(" in host_runas_cmds and ")" in host_runas_cmds:
            start = host_runas_cmds.index("(")
            end = host_runas_cmds.index(")")
            run_as = host_runas_cmds[start + 1:end]
            rest = host_runas_cmds[end + 1:].strip()
        else:
            rest = host_runas_cmds

        # Extract options (NOPASSWD, PASSWD, etc.)
        options = ""
        if ":" in rest:
            maybe_options, _, commands = rest.partition(":")
            maybe_options = maybe_options.strip()
            if any(kw in maybe_options for kw in ("NOPASSWD", "PASSWD", "NOEXEC", "EXEC")):
                options = maybe_options
                commands = commands.strip()
            else:
                commands = rest
        else:
            commands = rest

        return {
            "source": source,
            "user": user,
            "host": parts[1],
            "run_as": run_as,
            "options": options,
            "commands": commands.strip(),
            "raw_line": line,
        }
