import json
import os
from datetime import datetime, timezone

import structlog

from ubuntils.detectors.finding import Finding

logger = structlog.get_logger()

WAZUH_AGENT_MARKERS = [
    "/var/ossec/bin/wazuh-agentd",
    "/var/ossec/etc/ossec.conf",
]
DEFAULT_WAZUH_LOG_PATH = "/var/log/ubuntils/wazuh-alerts.json"

# Every string in an event can carry attacker text (a log line, a cron
# command, a padded file's path). The agent drops or splits oversized lines,
# and one unbounded event could bury the rest, so each line is bounded.
MAX_FIELD_CHARS = 2048
MAX_EVENT_DESCRIPTION_CHARS = 1024
MAX_LINE_BYTES = 32 * 1024
# Last resort when escaping (\u0000 is six bytes per character) still
# leaves a line over MAX_LINE_BYTES without related_events.
_FALLBACK_FIELD_CHARS = 256

DEGRADED_RULE_ID = "UBUNTILS_SCAN_DEGRADED"
# Layout of each forwarded line; Wazuh rules can match on data.schema_version.
WAZUH_SCHEMA_VERSION = "3"


def is_wazuh_agent_present(markers: list = None) -> bool:
    """True if any known Wazuh agent marker path exists on this (live) host."""
    for marker in (markers if markers is not None else WAZUH_AGENT_MARKERS):
        if os.path.exists(marker):
            return True
    return False


def _cut(value, limit: int, cut: list):
    if isinstance(value, str) and len(value) > limit:
        cut.append(True)
        return value[:limit]
    return value


def _event_to_dict(event, cut: list) -> dict:
    ts = event.timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return {
        "timestamp": ts.isoformat(),
        "source": _cut(event.source, MAX_FIELD_CHARS, cut),
        "program": _cut(getattr(event, "program", ""), MAX_FIELD_CHARS, cut),
        "description": _cut(event.description, MAX_EVENT_DESCRIPTION_CHARS, cut),
    }


def _bounded_line(d: dict, cut: list) -> str:
    """Serialize ``d`` to at most MAX_LINE_BYTES: drop related_events if the
    line is still too long, then shrink string fields as a last resort.
    Sets "truncated": true whenever anything was cut."""
    def dump():
        if cut:
            d["truncated"] = True
        return json.dumps(d)

    line = dump()
    if len(line.encode()) > MAX_LINE_BYTES and "related_events" in d:
        del d["related_events"]
        cut.append(True)
        line = dump()
    if len(line.encode()) > MAX_LINE_BYTES:
        for key, value in d.items():
            d[key] = _cut(value, _FALLBACK_FIELD_CHARS, cut)
        line = dump()
    return line


def _finding_to_dict(finding: Finding, hostname: str, cut: list = None) -> dict:
    cut = [] if cut is None else cut
    d = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": hostname,
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "title": finding.title,
        "description": finding.description,
        "artifact_path": finding.artifact_path,
        "raw_value": finding.raw_value,
        "remediation_available": finding.remediation_available,
        # Lets a Wazuh rule alert on HIGH-confidence findings only.
        "confidence": finding.confidence,
        "confidence_band": finding.confidence_band,
    }
    d = {k: _cut(v, MAX_FIELD_CHARS, cut) for k, v in d.items()}
    d["schema_version"] = WAZUH_SCHEMA_VERSION
    # Short, from our own data file (never host text), so not cut.
    d["category"] = finding.category
    d["attack"] = list(finding.attack)
    if finding.related_events:
        d["related_events"] = [_event_to_dict(e, cut) for e in finding.related_events]
    if cut:
        d["truncated"] = True
    return d


def finding_line(finding: Finding, hostname: str) -> str:
    """One bounded JSON line for ``finding``."""
    cut: list = []
    return _bounded_line(_finding_to_dict(finding, hostname, cut), cut)


def degraded_line(collectors_degraded: dict, hostname: str) -> str:
    """A summary event saying the scan couldn't see everything — on a
    compromised host, "couldn't look" must not read as "nothing found"."""
    cut: list = []
    reasons = "; ".join(f"{name}: {', '.join(map(str, why))}"
                        for name, why in sorted(collectors_degraded.items()))
    d = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": _cut(hostname, MAX_FIELD_CHARS, cut),
        "rule_id": DEGRADED_RULE_ID,
        "severity": "MEDIUM",
        "title": "ubuntils scan incomplete: some collectors were degraded",
        "description": _cut(reasons, MAX_FIELD_CHARS, cut),
        "collectors_degraded": sorted(collectors_degraded),
        "remediation_available": False,
        "schema_version": WAZUH_SCHEMA_VERSION,
    }
    return _bounded_line(d, cut)


def write_wazuh_alerts(findings: list, hostname: str,
                       log_path: str = DEFAULT_WAZUH_LOG_PATH,
                       collectors_degraded: dict = None):
    """Append one JSON line per finding (each at most MAX_LINE_BYTES) to
    log_path for the Wazuh agent to tail, plus a summary event if any
    collector was degraded.

    Returns the path written on success, None if there was nothing to write
    or the write failed. Never raises -- this is a best-effort side channel,
    not primary scan output.
    """
    if not findings and not collectors_degraded:
        return None

    try:
        log_dir = os.path.dirname(log_path)
        os.makedirs(log_dir, mode=0o750, exist_ok=True)
        lines = [finding_line(f, hostname) for f in findings]
        if collectors_degraded:
            lines.append(degraded_line(collectors_degraded, hostname))
        fd = os.open(
            log_path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
            0o640,
        )
        with os.fdopen(fd, "a") as f:
            f.write("\n".join(lines) + "\n")
        logger.info("wazuh_forwarded", count=len(lines), log_path=log_path)
        return log_path
    except Exception as exc:
        logger.warning("wazuh_forward_failed", log_path=log_path, error=str(exc))
        return None
