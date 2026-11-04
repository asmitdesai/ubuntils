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


def _ev_prog(desc, program, minute=0, source="journald"):
    return TimelineEvent(
        timestamp=datetime.datetime(2026, 6, 1, 12, minute, 0, tzinfo=datetime.timezone.utc),
        source=source, description=desc, program=program,
    )


def _signal_names(finding):
    return [s["name"] for s in finding.signals]


def test_correlate_scores_events_naming_the_artifact_and_rule_activity():
    # An SSH key's artifact is the key itself: the login must name its
    # fingerprint (the way sshd logs it) to corroborate.
    import base64
    import hashlib
    key_data = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + b"k" * 36).decode()
    fp = "SHA256:" + base64.b64encode(
        hashlib.sha256(base64.b64decode(key_data)).digest()).decode().rstrip("=")
    finding = _finding("SSH_UNAUTHORIZED_KEY", "/home/alice/.ssh/authorized_keys")
    finding.raw_value = f"ssh-ed25519 {key_data} alice@laptop"
    correlate([finding], [_ev_prog(f"Accepted publickey for alice from 1.2.3.4 ssh2: "
                                   f"ED25519 {fp}", "sshd")])
    assert "timeline_corroboration" in _signal_names(finding)
    assert finding.confidence == 75

    # Naming only the user (a line any user can forge with `logger -t sshd`)
    # is context, not corroboration.
    by_user = _finding("SSH_UNAUTHORIZED_KEY", "/home/alice/.ssh/authorized_keys")
    by_user.raw_value = f"ssh-ed25519 {key_data} alice@laptop"
    correlate([by_user], [_ev_prog("Accepted publickey for alice from 1.2.3.4", "sshd")])
    assert "timeline_corroboration" not in _signal_names(by_user)
    assert len(by_user.related_events) == 1


def test_correlate_keywords_match_whole_words_only():
    # Real 26.04 noise: "connect" inside "Disconnected", "install" inside
    # "Installing", "apt" inside "apt-daily" must not count.
    conn = _finding("PROCESS_SUSPICIOUS_CONNECTION", "/proc/96376/exe")
    pkg = _finding("PACKAGE_TAMPERED", "python3-twisted")
    timeline = [
        _ev_prog("Disconnected from user parallels 10.211.55.2 port 52649", "sshd-session"),
        _ev_prog('Installing snap "ollama" revision unset', "snapd"),
        _ev_prog("Finished apt-daily-upgrade.service", "systemd"),
    ]
    correlate([conn, pkg], timeline)
    assert conn.related_events == [] and pkg.related_events == []
    assert conn.signals == [] and pkg.signals == []


def test_correlate_does_not_score_keyword_only_matches():
    # PROCESS_* artifacts (/proc/<pid>/exe) carry no identifying token, so
    # any match is keyword-only: shown for context, never scored.
    finding = _finding("PROCESS_MASQUERADE", "/proc/53213/exe")
    correlate([finding], [_ev_prog("execve called", "audit")])
    assert len(finding.related_events) == 1
    assert finding.signals == []


def test_correlate_package_needs_package_manager_activity_not_just_its_name():
    finding = _finding("PACKAGE_TAMPERED", "apparmor")
    timeline = [
        _ev_prog('apparmor="AUDIT" operation="userns_create"', "kernel", minute=1),
        # Seen on 26.04: snap hooks named "*.install" and apt-daily units.
        _ev_prog('apparmor="STATUS" operation="profile_load" name="snap.firefox.hook.install"',
                 "kernel", minute=3),
        _ev_prog("apparmor profiles reloaded by apt-daily-upgrade.service", "systemd", minute=4),
        _ev_prog("status installed apparmor:arm64 4.1.0", "dpkg", minute=2),
    ]
    correlate([finding], timeline)
    assert [e.program for e in finding.related_events] == ["dpkg"]
    assert "timeline_corroboration" in _signal_names(finding)


def test_correlate_user_findings_use_the_username_not_passwd():
    finding = Finding(
        rule_id="USER_UID_ZERO", severity=Severity.HIGH, title="t", description="d",
        artifact_path="/etc/passwd", raw_value="ghost:x:0:0:...:/bin/bash",
        remediation_available=False,
    )
    timeline = [
        _ev_prog("pam_unix(passwd:chauthtok): password changed for alice", "passwd", minute=1),
        _ev_prog("new user: name=ghost, UID=0, GID=0", "useradd", minute=2),
    ]
    correlate([finding], timeline)
    assert [e.program for e in finding.related_events] == ["useradd"]
    assert "timeline_corroboration" in _signal_names(finding)
