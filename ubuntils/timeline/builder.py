import datetime
import json
import re
from dataclasses import dataclass

import structlog
from dateutil import parser as dateutil_parser

from ubuntils.utils.shell import run_command

logger = structlog.get_logger()

_SYSLOG_RE = re.compile(
    r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+\S+:\s+(.+)$"
)
_AUDITD_RE = re.compile(r"^type=(\S+) msg=audit\((\d+\.\d+):\d+\): (.+)$")


@dataclass(frozen=True)
class TimelineEvent:
    timestamp: datetime.datetime
    source: str
    description: str


class TimelineBuilder:
    def build(self, since_days: int = 7) -> list[TimelineEvent]:
        events: list[TimelineEvent] = []
        for path in ("/var/log/syslog", "/var/log/messages"):
            try:
                with open(path) as f:
                    events.extend(self._parse_syslog(f.read()))
            except OSError:
                pass
        events.extend(self._parse_journald(since_days))
        try:
            with open("/var/log/audit/audit.log") as f:
                events.extend(self._parse_auditd(f.read()))
        except OSError:
            pass
        return self._deduplicate(events)

    def _parse_syslog(self, content: str) -> list[TimelineEvent]:
        events = []
        current_year = datetime.datetime.now().year
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _SYSLOG_RE.match(line)
            if not m:
                continue
            raw_ts, description = m.group(1), m.group(2).strip()
            try:
                ts = dateutil_parser.parse(f"{raw_ts} {current_year}")
                ts = ts.replace(tzinfo=datetime.timezone.utc)
            except Exception:
                logger.warning("syslog_parse_failed", line=line)
                continue
            events.append(TimelineEvent(timestamp=ts, source="syslog", description=description))
        return events

    def _parse_journald(self, since_days: int) -> list[TimelineEvent]:
        since = f"{since_days} days ago"
        stdout, _, returncode = run_command(
            ["journalctl", "-o", "json", f"--since={since}", "--no-pager"]
        )
        if returncode != 0 or not stdout.strip():
            return []
        events = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                micros = int(record.get("__REALTIME_TIMESTAMP", 0))
                ts = datetime.datetime.fromtimestamp(
                    micros / 1_000_000, tz=datetime.timezone.utc
                )
                description = str(record.get("MESSAGE", ""))
                events.append(TimelineEvent(timestamp=ts, source="journald", description=description))
            except Exception:
                logger.warning("journald_parse_failed", line=line)
        return events

    def _parse_auditd(self, content: str) -> list[TimelineEvent]:
        events = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _AUDITD_RE.match(line)
            if not m:
                continue
            record_type, raw_ts, rest = m.group(1), m.group(2), m.group(3)
            try:
                ts = datetime.datetime.fromtimestamp(float(raw_ts), tz=datetime.timezone.utc)
            except Exception:
                logger.warning("auditd_parse_failed", line=line)
                continue
            description = f"{record_type}: {rest}"
            events.append(TimelineEvent(timestamp=ts, source="auditd", description=description))
        return events

    def _deduplicate(self, events: list[TimelineEvent]) -> list[TimelineEvent]:
        seen: set[tuple] = set()
        unique: list[TimelineEvent] = []
        for e in sorted(events, key=lambda x: x.timestamp):
            key = (e.timestamp, e.source, e.description)
            if key not in seen:
                seen.add(key)
                unique.append(e)
        return unique
