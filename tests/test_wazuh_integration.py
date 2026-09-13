"""
Tests for the Wazuh forwarding integration (ubuntils/integrations/wazuh.py).

write_wazuh_alerts never touches the real /var/log/ubuntils path in tests --
every test passes an explicit tmp_path-based log_path.
"""
import json
import os
import stat

import pytest

from ubuntils.detectors.finding import Finding, Severity
from ubuntils.integrations.wazuh import (
    is_wazuh_agent_present,
    write_wazuh_alerts,
)


def _finding(rule_id="CRON_ROOT_EXEC", severity=Severity.HIGH, related_events=None):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title="Test finding",
        description="Test description",
        artifact_path="/etc/crontab",
        raw_value="* * * * * root /tmp/evil.sh",
        remediation_available=True,
        related_events=related_events or [],
    )


class TestIsWazuhAgentPresent:
    def test_true_when_marker_exists(self, tmp_path):
        marker = tmp_path / "wazuh-agentd"
        marker.write_text("")
        assert is_wazuh_agent_present(markers=[str(marker)]) is True

    def test_false_when_no_marker_exists(self, tmp_path):
        missing = tmp_path / "does-not-exist"
        assert is_wazuh_agent_present(markers=[str(missing)]) is False

    def test_true_if_any_of_multiple_markers_exists(self, tmp_path):
        present = tmp_path / "ossec.conf"
        present.write_text("")
        missing = tmp_path / "does-not-exist"
        assert is_wazuh_agent_present(markers=[str(missing), str(present)]) is True


class TestWriteWazuhAlerts:
    def test_returns_none_and_creates_no_file_for_empty_findings(self, tmp_path):
        log_path = tmp_path / "wazuh" / "alerts.json"
        result = write_wazuh_alerts([], hostname="host1", log_path=str(log_path))
        assert result is None
        assert not log_path.exists()

    def test_writes_one_json_line_per_finding(self, tmp_path):
        log_path = tmp_path / "wazuh" / "alerts.json"
        findings = [_finding("CRON_ROOT_EXEC"), _finding("SSH_UNAUTHORIZED_KEY", Severity.MEDIUM)]

        result = write_wazuh_alerts(findings, hostname="host1", log_path=str(log_path))

        assert result == str(log_path)
        lines = log_path.read_text().splitlines()
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["rule_id"] == "CRON_ROOT_EXEC"
        assert first["severity"] == "HIGH"
        assert first["hostname"] == "host1"
        assert first["title"] == "Test finding"
        assert first["description"] == "Test description"
        assert first["artifact_path"] == "/etc/crontab"
        assert first["raw_value"] == "* * * * * root /tmp/evil.sh"
        assert first["remediation_available"] is True
        assert "timestamp" in first
        second = json.loads(lines[1])
        assert second["rule_id"] == "SSH_UNAUTHORIZED_KEY"
        assert second["severity"] == "MEDIUM"

    def test_appends_rather_than_truncates_on_repeated_calls(self, tmp_path):
        log_path = tmp_path / "wazuh" / "alerts.json"
        write_wazuh_alerts([_finding("CRON_ROOT_EXEC")], hostname="host1", log_path=str(log_path))
        write_wazuh_alerts([_finding("SSH_UNAUTHORIZED_KEY")], hostname="host1", log_path=str(log_path))

        lines = log_path.read_text().splitlines()
        assert len(lines) == 2

    def test_creates_log_dir_and_file_with_hardened_permissions(self, tmp_path):
        log_dir = tmp_path / "wazuh"
        log_path = log_dir / "alerts.json"

        write_wazuh_alerts([_finding()], hostname="host1", log_path=str(log_path))

        dir_mode = stat.S_IMODE(os.stat(log_dir).st_mode)
        file_mode = stat.S_IMODE(os.stat(log_path).st_mode)
        assert dir_mode == 0o750
        assert file_mode == 0o640

    def test_write_failure_is_caught_and_returns_none(self, tmp_path, monkeypatch):
        log_path = tmp_path / "wazuh" / "alerts.json"

        def _boom(*args, **kwargs):
            raise PermissionError("denied")

        monkeypatch.setattr("os.open", _boom)

        result = write_wazuh_alerts([_finding()], hostname="host1", log_path=str(log_path))

        assert result is None

    def test_symlinked_log_file_is_rejected_not_followed(self, tmp_path):
        real_target = tmp_path / "real_secret_file"
        real_target.write_text("do not touch")
        log_dir = tmp_path / "wazuh"
        log_dir.mkdir(mode=0o750)
        log_path = log_dir / "alerts.json"
        log_path.symlink_to(real_target)

        result = write_wazuh_alerts([_finding()], hostname="host1", log_path=str(log_path))

        assert result is None
        assert real_target.read_text() == "do not touch"

    def test_related_events_are_serialized(self, tmp_path):
        from ubuntils.timeline.builder import TimelineEvent
        from datetime import datetime, timezone

        event = TimelineEvent(
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            source="auth.log",
            description="sshd login",
        )
        log_path = tmp_path / "wazuh" / "alerts.json"

        write_wazuh_alerts([_finding(related_events=[event])], hostname="host1", log_path=str(log_path))

        line = json.loads(log_path.read_text().splitlines()[0])
        assert line["related_events"] == [
            {"timestamp": "2026-01-01T00:00:00+00:00", "source": "auth.log", "description": "sshd login"}
        ]
