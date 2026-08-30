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


def test_finding_emits_related_events_and_guided_remediation():
    event = TimelineEvent(
        timestamp=datetime.datetime(2026, 6, 1, 12, 0, 0, tzinfo=datetime.timezone.utc),
        source="journald",
        description="sshd: Accepted publickey for alice",
    )
    finding = Finding(
        rule_id="SSH_UNAUTHORIZED_KEY",
        severity=Severity.MEDIUM,
        title="Recently added SSH key",
        description="authorized_keys changed.",
        artifact_path="/home/alice/.ssh/authorized_keys",
        raw_value="ssh-rsa AAAA...",
        remediation_available=True,
        related_events=[event],
        guided_remediation="systemctl disable --now foo.service",
    )
    out = json.loads(JSONFormatter().format({}, {}, [finding], [], []))
    f = out["findings"][0]
    assert f["related_events"][0]["source"] == "journald"
    assert f["related_events"][0]["description"] == "sshd: Accepted publickey for alice"
    assert f["guided_remediation"] == "systemctl disable --now foo.service"


def test_finding_emits_confidence_and_signals():
    finding = Finding(
        rule_id="SSH_UNAUTHORIZED_KEY", severity=Severity.MEDIUM, title="t",
        description="d", artifact_path="/x", raw_value="v",
        remediation_available=False,
    )
    from ubuntils.detectors.scoring import apply_signal
    apply_signal(finding, "content_match", 30, "dangerous option present")
    f = json.loads(JSONFormatter().format({}, {}, [finding], [], []))["findings"][0]
    assert f["confidence"] == finding.confidence
    assert f["confidence_band"] == finding.confidence_band
    assert f["signals"] == [{"name": "content_match", "weight": 30, "detail": "dangerous option present"}]


def test_finding_omits_empty_correlation_fields():
    finding = Finding(
        rule_id="CRON_TMP_PATH", severity=Severity.HIGH, title="t",
        description="d", artifact_path="/etc/crontab", raw_value="x",
        remediation_available=False,
    )
    f = json.loads(JSONFormatter().format({}, {}, [finding], [], []))["findings"][0]
    assert "related_events" not in f
    assert "guided_remediation" not in f
