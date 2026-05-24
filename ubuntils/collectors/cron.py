import glob
import os

from ubuntils.collectors.base import BaseCollector


class CronCollector(BaseCollector):
    def collect(self) -> dict:
        entries = []

        # System crontab (7-field: min hour dom mon dow user command)
        for path in ["/etc/crontab"] + glob.glob("/etc/cron.d/*"):
            entries.extend(self._parse_system_crontab(path))

        # User crontabs (5-field: min hour dom mon dow command)
        for path in glob.glob("/var/spool/cron/crontabs/*"):
            owner = os.path.basename(path)
            entries.extend(self._parse_user_crontab(path, owner))

        return {"cron_entries": entries}

    def _parse_system_crontab(self, path: str) -> list:
        entries = []
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line and not line[0].isdigit() and not line[0] == "*":
                        continue  # skip variable assignments
                    parts = line.split(None, 6)
                    if len(parts) < 7:
                        continue
                    schedule = " ".join(parts[:5])
                    run_as = parts[5]
                    command = parts[6]
                    entries.append({
                        "owner": "root",
                        "run_as": run_as,
                        "schedule": schedule,
                        "command": command,
                        "source": path,
                    })
        except Exception:
            pass
        return entries

    def _parse_user_crontab(self, path: str, owner: str) -> list:
        entries = []
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line and not line[0].isdigit() and not line[0] == "*":
                        continue
                    parts = line.split(None, 5)
                    if len(parts) < 6:
                        continue
                    schedule = " ".join(parts[:5])
                    command = parts[5]
                    entries.append({
                        "owner": owner,
                        "run_as": owner,
                        "schedule": schedule,
                        "command": command,
                        "source": path,
                    })
        except Exception:
            pass
        return entries
