import json

from ubuntils.collectors.base import BaseCollector


class SystemdCollector(BaseCollector):
    def collect(self) -> dict:
        timers = self._list_timers_json()
        if timers is None:
            timers = self._list_timers_text()
        if timers is None:
            return {}

        result = []
        for t in timers:
            unit = t.get("unit", "")
            activates = t.get("activates", "")
            exec_start = self._get_exec_start(activates) if activates else ""
            result.append({
                "unit": unit,
                "activates": activates,
                "exec_start": exec_start,
            })

        return {"timers": result}

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
