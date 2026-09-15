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


def is_wazuh_agent_present(markers: list = None) -> bool:
    """True if any known Wazuh agent marker path exists on this (live) host."""
    for marker in (markers if markers is not None else WAZUH_AGENT_MARKERS):
        if os.path.exists(marker):
            return True
    return False


def _event_to_dict(event) -> dict:
    ts = event.timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return {
        "timestamp": ts.isoformat(),
        "source": event.source,
        "description": event.description,
    }


def _finding_to_dict(finding: Finding, hostname: str) -> dict:
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
    }
    if finding.related_events:
        d["related_events"] = [_event_to_dict(e) for e in finding.related_events]
    return d


def write_wazuh_alerts(findings: list, hostname: str,
                       log_path: str = DEFAULT_WAZUH_LOG_PATH):
    """Append one JSON line per finding to log_path for the Wazuh agent to tail.

    Returns the path written on success, None if there was nothing to write
    or the write failed. Never raises -- this is a best-effort side channel,
    not primary scan output.
    """
    if not findings:
        return None

    try:
        log_dir = os.path.dirname(log_path)
        os.makedirs(log_dir, mode=0o750, exist_ok=True)
        lines = [json.dumps(_finding_to_dict(f, hostname)) for f in findings]
        fd = os.open(
            log_path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
            0o640,
        )
        with os.fdopen(fd, "a") as f:
            f.write("\n".join(lines) + "\n")
        logger.info("wazuh_forwarded", count=len(findings), log_path=log_path)
        return log_path
    except Exception as exc:
        logger.warning("wazuh_forward_failed", log_path=log_path, error=str(exc))
        return None
