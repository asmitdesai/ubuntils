from __future__ import annotations

import datetime
import json
import re
from dataclasses import dataclass

import structlog
from dateutil import parser as dateutil_parser

from ubuntils.collectors.source import ArtifactSource, LiveSource

logger = structlog.get_logger()

_SYSLOG_RE = re.compile(
    r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+\S+:\s+(.+)$"
)
# rsyslog's high-precision (RFC 3339) format, the default on newer Ubuntu:
# "2026-09-23T10:00:00.123456+01:00 host prog[1]: message"
_SYSLOG_RFC3339_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))"
    r"\s+\S+\s+\S+:\s+(.+)$"
)
_AUDITD_RE = re.compile(r"^type=(\S+) msg=audit\((\d+\.\d+):\d+\): (.+)$")


@dataclass(frozen=True)
class TimelineEvent:
    timestamp: datetime.datetime
    source: str
    description: str


class TimelineBuilder:
    def __init__(self, source: ArtifactSource | None = None):
        self.source = source if source is not None else LiveSource()

    def build(self, since_days: int = 7) -> list[TimelineEvent]:
        events: list[TimelineEvent] = []
        # Each log source is isolated: one unreadable/escaping/garbled source
        # (e.g. SourceContainmentError, which is not an OSError) must not
        # take the rest of the timeline down with it.
        for path in ("/var/log/syslog", "/var/log/messages"):
            try:
                if self.source.exists(path):
                    events.extend(self._parse_syslog(self.source.read_text(path),
                                                     reference=self._mtime(path)))
            except Exception as exc:
                logger.warning("timeline_source_failed", path=path, error=str(exc))
        try:
            events.extend(self._parse_journald(since_days))
        except Exception as exc:
            logger.warning("timeline_source_failed", path="journald", error=str(exc))
        try:
            if self.source.exists("/var/log/audit/audit.log"):
                events.extend(self._parse_auditd(self.source.read_text("/var/log/audit/audit.log")))
        except Exception as exc:
            logger.warning("timeline_source_failed", path="auditd", error=str(exc))
        return self._deduplicate(events)

    def _mtime(self, path: str) -> datetime.datetime | None:
        try:
            return datetime.datetime.fromtimestamp(self.source.lstat(path).st_mtime,
                                                   tz=datetime.timezone.utc)
        except Exception:
            return None

    def _host_timezone(self) -> datetime.tzinfo:
        """Timezone of the host whose logs these are (syslog stamps are local
        time with no offset). /etc/timezone is read through the source so an
        offline bundle uses the collected host's zone, not the analyst's."""
        try:
            name = self.source.read_text("/etc/timezone").strip()
            if name:
                from zoneinfo import ZoneInfo
                return ZoneInfo(name)
        except Exception:
            pass
        if isinstance(self.source, LiveSource) and not self.source.offline:
            return datetime.datetime.now().astimezone().tzinfo
        return datetime.timezone.utc

    def _parse_syslog(self, content: str,
                      reference: datetime.datetime | None = None) -> list[TimelineEvent]:
        """Traditional syslog stamps carry no year: assume the year of
        ``reference`` (the log's mtime, i.e. its newest entry), and roll back a
        year for any stamp that would land after it — so December entries read
        in January stay in December of the previous year."""
        events = []
        tz = self._host_timezone()
        reference = reference or datetime.datetime.now(datetime.timezone.utc)
        latest_allowed = reference + datetime.timedelta(days=1)
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _SYSLOG_RFC3339_RE.match(line)
            if m:
                try:
                    ts = dateutil_parser.isoparse(m.group(1))
                except Exception:
                    logger.warning("syslog_parse_failed", line=line)
                    continue
                events.append(TimelineEvent(timestamp=ts.astimezone(datetime.timezone.utc),
                                            source="syslog", description=m.group(2).strip()))
                continue
            m = _SYSLOG_RE.match(line)
            if not m:
                continue
            raw_ts, description = m.group(1), m.group(2).strip()
            try:
                naive = dateutil_parser.parse(f"{raw_ts} {reference.year}")
                ts = naive.replace(tzinfo=tz)
                if ts > latest_allowed:
                    ts = naive.replace(year=naive.year - 1, tzinfo=tz)
                ts = ts.astimezone(datetime.timezone.utc)
            except Exception:
                logger.warning("syslog_parse_failed", line=line)
                continue
            events.append(TimelineEvent(timestamp=ts, source="syslog", description=description))
        return events

    def _parse_journald(self, since_days: int) -> list[TimelineEvent]:
        stdout, _stderr, returncode = self.source.run(
            "journalctl",
            ["journalctl", "-o", "json", f"--since={since_days} days ago", "--no-pager"],
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
