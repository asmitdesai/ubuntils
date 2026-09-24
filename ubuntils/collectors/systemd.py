import json
import os

from ubuntils.collectors.base import BaseCollector

# Where enabled/installable units live. Read as files through the source, so
# this also works for offline bundle/--root analysis where `systemctl` can't run.
UNIT_GLOBS = [
    "/etc/systemd/system/*.service",
    "/etc/systemd/system/*/*.service",
    "/run/systemd/system/*.service",
    "/usr/local/lib/systemd/system/*.service",
    "/usr/lib/systemd/system/*.service",
    "/lib/systemd/system/*.service",
    "/etc/systemd/user/*.service",
    "/root/.config/systemd/user/*.service",
    "/home/*/.config/systemd/user/*.service",
]
_EXEC_KEYS = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop")
# systemd executable prefixes: @ - : + ! !!
_EXEC_PREFIX_CHARS = "@-:+!"


def exec_binary(exec_line: str) -> str:
    """First token of an Exec*= value, minus systemd's special prefixes."""
    tokens = exec_line.strip().split()
    if not tokens:
        return ""
    return tokens[0].lstrip(_EXEC_PREFIX_CHARS)


class SystemdCollector(BaseCollector):
    def collect(self) -> dict:
        timers = self._list_timers_json()
        if timers is None:
            timers = self._list_timers_text()
        if timers is None:
            self.degraded.append("`systemctl list-timers` produced no output")
            timers = []

        result = []
        for t in timers:
            unit = t.get("unit", "")
            activates = t.get("activates", "")
            exec_start = self._get_exec_start(activates) if activates else ""
            result.append({
                "unit": unit,
                "activates": activates,
                "exec_start": exec_start,
                "exec_owner_uid": self._owner_uid(exec_binary(exec_start)),
            })

        return {"timers": result, "services": self._service_units()}

    def _owner_uid(self, path: str):
        """UID owning ``path`` on the analyzed host, or None if unknown."""
        if not path.startswith("/"):
            return None
        try:
            return self.source.lstat(path).st_uid
        except Exception:
            return None

    def _service_units(self) -> list:
        units = []
        seen: set = set()
        for pattern in UNIT_GLOBS:
            try:
                paths = self.source.glob(pattern)
            except Exception:
                continue
            for path in paths:
                try:
                    text = self.source.read_text(path)
                except Exception:
                    continue
                unit = os.path.basename(path)
                for line in text.splitlines():
                    key, eq, value = line.strip().partition("=")
                    if not eq or key.strip() not in _EXEC_KEYS:
                        continue
                    value = value.strip()
                    binary = exec_binary(value)
                    # The same unit is often visible via several dirs/.wants links.
                    if not binary or (unit, value) in seen:
                        continue
                    seen.add((unit, value))
                    units.append({
                        "unit": unit,
                        "unit_path": path,
                        "exec_key": key.strip(),
                        "exec_start": value,
                        "exec_owner_uid": self._owner_uid(binary),
                    })
        return units

    def _list_timers_json(self):
        stdout, _, rc = self.source.run(
            "systemctl_list_timers_json",
            ["systemctl", "list-timers", "--all", "--no-pager", "--output", "json"],
        )
        if rc != 0:
            return None
        try:
            return json.loads(stdout)
        except Exception:
            return None

    def _list_timers_text(self):
        stdout, _, rc = self.source.run(
            "systemctl_list_timers_text",
            ["systemctl", "list-timers", "--all", "--no-pager"],
        )
        if rc != 0:
            return None
        timers = []
        lines = stdout.splitlines()
        for line in lines[1:]:  # skip header
            parts = line.split()
            if not parts:
                continue
            # Find UNIT column by looking for a token ending in .timer
            for i, token in enumerate(parts):
                if token.endswith(".timer"):
                    unit = token
                    activates = parts[i + 1] if i + 1 < len(parts) else ""
                    timers.append({"unit": unit, "activates": activates})
                    break
        return timers if timers else None

    def _get_exec_start(self, service: str) -> str:
        stdout, _, rc = self.source.run(
            "systemctl_show_execstart",
            ["systemctl", "show", service, "--property=ExecStart", "--no-pager"],
        )
        if rc != 0 or not stdout.strip():
            return ""
        line = stdout.strip()
        if "=" in line:
            _, _, value = line.partition("=")
            # ExecStart value may look like: { path=/usr/bin/foo ; argv[]=... }
            # Extract just the path
            value = value.strip()
            if value.startswith("{"):
                for part in value.split(";"):
                    part = part.strip().lstrip("{").strip()
                    if part.startswith("path="):
                        return part[5:].strip()
                return value
            return value
        return stdout.strip()
