import datetime
import json
import re

from ubuntils.detectors.finding import Finding, RemediationResult, RemediationStatus, Severity
from ubuntils.formatters.json_formatter import JSONFormatter
from ubuntils.timeline.builder import TimelineEvent


def _finding(**kwargs):
    defaults = dict(
        rule_id="CRON_TMP_PATH",
        severity=Severity.HIGH,
        title="Test finding",
        description="A cron job references /tmp",
        artifact_path="/etc/cron.d/evil",
        raw_value="* * * * * root /tmp/evil.sh",
        remediation_available=True,
        remediation_description="Remove the cron entry",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _event(**kwargs):
    defaults = dict(
        timestamp=datetime.datetime(2024, 1, 15, 14, 22, 0, tzinfo=datetime.timezone.utc),
        source="syslog",
        description="test event",
    )
    defaults.update(kwargs)
    return TimelineEvent(**defaults)


def _remediation(**kwargs):
    defaults = dict(
        finding_rule_id="CRON_TMP_PATH",
        status=RemediationStatus.SUCCESS,
        message="Entry removed",
        backup_path="/var/backups/ubuntils/20240115_142200/crontab",
        rollback_command="cp /var/backups/ubuntils/20240115_142200/crontab /etc/cron.d/evil",
    )
    defaults.update(kwargs)
    return RemediationResult(**defaults)


_METADATA = {"scan_id": "abc123", "started_at": "2024-01-15T14:22:00Z"}
_ARTIFACT_COUNTS = {"processes": 42, "cron_entries": 5}

_FMT = JSONFormatter()


def test_json_formatter_produces_valid_json():
    out = _FMT.format(_METADATA, _ARTIFACT_COUNTS, [_finding()], [_event()], [])
    parsed = json.loads(out)
    assert isinstance(parsed, dict)


def test_json_formatter_findings_severity_is_string():
    out = _FMT.format(_METADATA, _ARTIFACT_COUNTS, [_finding(severity=Severity.HIGH)], [], [])
    parsed = json.loads(out)
    assert parsed["findings"][0]["severity"] == "HIGH"


def test_json_formatter_timestamps_are_iso8601():
    out = _FMT.format(_METADATA, _ARTIFACT_COUNTS, [], [_event()], [])
    parsed = json.loads(out)
    ts = parsed["timeline"][0]["timestamp"]
    assert isinstance(ts, str)
    # ISO 8601 basic check: parseable and contains T separator
    assert "T" in ts
    datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))


def test_json_formatter_remediation_results_absent_when_empty():
    out = _FMT.format(_METADATA, _ARTIFACT_COUNTS, [], [], [])
    parsed = json.loads(out)
    assert "remediation_results" not in parsed


def test_json_formatter_all_top_level_keys_present():
    out = _FMT.format(_METADATA, _ARTIFACT_COUNTS, [_finding()], [_event()], [_remediation()])
    parsed = json.loads(out)
    assert "scan_metadata" in parsed
    assert "artifact_counts" in parsed
    assert "findings" in parsed
    assert "timeline" in parsed
    assert "remediation_results" in parsed


def test_json_formatter_remediation_status_is_string():
    out = _FMT.format(_METADATA, _ARTIFACT_COUNTS, [], [], [_remediation(status=RemediationStatus.FAILED)])
    parsed = json.loads(out)
    assert parsed["remediation_results"][0]["status"] == "FAILED"


def test_json_formatter_naive_timestamp_treated_as_utc():
    naive_ts = datetime.datetime(2024, 1, 15, 10, 0, 0)
    out = _FMT.format(_METADATA, _ARTIFACT_COUNTS, [], [_event(timestamp=naive_ts)], [])
    parsed = json.loads(out)
    ts = parsed["timeline"][0]["timestamp"]
    assert "+00:00" in ts or ts.endswith("Z")
