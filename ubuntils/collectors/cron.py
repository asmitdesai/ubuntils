import os

from ubuntils.collectors.base import BaseCollector

# run-parts directories: every executable in them runs as root on the
# directory's schedule.
CRON_SCRIPT_DIRS = {
    "/etc/cron.hourly": "@hourly",
    "/etc/cron.daily": "@daily",
    "/etc/cron.weekly": "@weekly",
    "/etc/cron.monthly": "@monthly",
}


def _split_entry(line: str, has_user_field: bool):
    """Split a crontab line into (schedule, run_as, command).

    Handles both 5-field schedules and the @reboot/@daily/... specials (one
    schedule token). run_as is None for user crontabs. Returns None for lines
    that aren't a schedule entry.
    """
    schedule_fields = 1 if line.startswith("@") else 5
    extra = 1 if has_user_field else 0
    parts = line.split(None, schedule_fields + extra)
    if len(parts) < schedule_fields + extra + 1:
        return None
    schedule = " ".join(parts[:schedule_fields])
    run_as = parts[schedule_fields] if has_user_field else None
    return schedule, run_as, parts[-1]


def _is_variable_assignment(line: str) -> bool:
    return "=" in line and not line[0].isdigit() and line[0] not in "*@"


class CronCollector(BaseCollector):
    def collect(self) -> dict:
        entries = []

        # System crontab (min hour dom mon dow user command)
        for path in ["/etc/crontab"] + self.source.glob("/etc/cron.d/*"):
            entries.extend(self._parse_crontab(path, owner="root", has_user_field=True))

        # User crontabs (min hour dom mon dow command)
        for path in self.source.glob("/var/spool/cron/crontabs/*"):
            owner = os.path.basename(path)
            entries.extend(self._parse_crontab(path, owner=owner, has_user_field=False))

        for directory, schedule in CRON_SCRIPT_DIRS.items():
            for path in self.source.glob(f"{directory}/*"):
                entries.extend(self._parse_script(path, schedule))

        return {"cron_entries": entries}

    def _parse_crontab(self, path: str, owner: str, has_user_field: bool) -> list:
        entries = []
        try:
            text = self.source.read_text(path)
        except Exception:
            return entries
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or _is_variable_assignment(line):
                continue
            split = _split_entry(line, has_user_field)
            if split is None:
                continue
            schedule, run_as, command = split
            entries.append({
                "owner": owner,
                "run_as": run_as if has_user_field else owner,
                "schedule": schedule,
                "command": command,
                "source": path,
                "kind": "crontab",
            })
        return entries

    def _parse_script(self, path: str, schedule: str) -> list:
        """Each non-comment line of a run-parts script, as a root cron entry.

        kind="script" tells rules these are shell-script lines, not crontab
        entries: deleting one line out of a script is not a safe automatic
        remediation, so findings on them are flag-only.
        """
        entries = []
        try:
            text = self.source.read_text(path)
        except Exception:
            return entries
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entries.append({
                "owner": "root",
                "run_as": "root",
                "schedule": schedule,
                "command": line,
                "source": path,
                "kind": "script",
            })
        return entries
