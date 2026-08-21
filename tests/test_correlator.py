import datetime

from ubuntils.detectors.finding import Finding, Severity
from ubuntils.timeline.builder import TimelineEvent
from ubuntils.timeline.correlator import correlate


def _ev(desc, source="journald", minute=0):
    return TimelineEvent(
        timestamp=datetime.datetime(2026, 6, 1, 12, minute, 0, tzinfo=datetime.timezone.utc),
        source=source, description=desc,
    )


def _finding(rule_id, path):
    return Finding(
        rule_id=rule_id, severity=Severity.MEDIUM, title="t", description="d",
        artifact_path=path, raw_value="x", remediation_available=False,
    )


def test_correlate_matches_username_for_ssh_key():
    finding = _finding("SSH_UNAUTHORIZED_KEY", "/home/alice/.ssh/authorized_keys")
    timeline = [
        _ev("sshd: Accepted publickey for alice from 1.2.3.4", minute=5),
        _ev("kernel: usb disconnect", minute=6),
    ]
    correlate([finding], timeline)
    assert len(finding.related_events) == 1
    assert "alice" in finding.related_events[0].description


def test_correlate_matches_rule_keyword():
    finding = _finding("SUDOERS_NOPASSWD", "/etc/sudoers.d/alice")
    timeline = [_ev("sudo: alice : COMMAND=/bin/bash", minute=1)]
    correlate([finding], timeline)
    assert len(finding.related_events) == 1


def test_correlate_caps_and_orders_most_recent_first():
    finding = _finding("CRON_TMP_PATH", "/etc/cron.d/job")
    timeline = [_ev(f"CRON job ran iteration {i}", minute=i) for i in range(8)]
    correlate([finding], timeline)
    assert len(finding.related_events) == 5
    times = [e.timestamp for e in finding.related_events]
    assert times == sorted(times, reverse=True)


def test_correlate_no_match_leaves_empty():
    finding = _finding("CRON_TMP_PATH", "/etc/cron.d/job")
    correlate([finding], [_ev("unrelated kernel message", minute=2)])
    assert finding.related_events == []


def test_correlate_returns_findings():
    findings = [_finding("CRON_TMP_PATH", "/etc/cron.d/job")]
    assert correlate(findings, []) is findings
