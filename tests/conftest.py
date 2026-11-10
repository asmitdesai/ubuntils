import datetime
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from ubuntils.detectors.finding import Finding, Severity
from ubuntils.remediators.base import RemediationResult, RemediationStatus
from ubuntils.timeline.builder import TimelineEvent


@pytest.fixture(autouse=True)
def _no_deprecation_notices(request, monkeypatch):
    """The CLI prints version-dependent deprecation notices on stderr (the
    Python 3.9 one fires only on 3.9). Under click 8.1, the newest click 3.9
    can install, CliRunner folds stderr into result.output, so the notice would
    break every test that parses JSON output. Silence it everywhere; the tests
    that cover notices opt out with @pytest.mark.real_deprecation_notices."""
    if request.node.get_closest_marker("real_deprecation_notices"):
        return
    from ubuntils import cli
    monkeypatch.setattr(cli, "_deprecation_notices", lambda: [])


@pytest.fixture
def split_runner():
    """A CliRunner whose result.stdout and result.stderr are kept apart.
    click 8.2+ always does this; click 8.1 (the newest on Python 3.9) mixes
    them unless mix_stderr=False, and then result.stderr raises."""
    try:
        return CliRunner(mix_stderr=False)
    except TypeError:
        return CliRunner()


@pytest.fixture
def sample_finding_high():
    return Finding(
        rule_id="CRON_TMP_PATH",
        severity=Severity.HIGH,
        title="Cron job references /tmp",
        description="A cron job references a writable temp directory.",
        artifact_path="/etc/crontab",
        raw_value="* * * * * root /tmp/evil.sh",
        remediation_available=True,
        remediation_description="Remove the offending crontab entry.",
    )


@pytest.fixture
def sample_finding_medium():
    return Finding(
        rule_id="SSH_UNAUTHORIZED_KEY",
        severity=Severity.MEDIUM,
        title="Recently added SSH key",
        description="authorized_keys was modified within the last 7 days.",
        artifact_path="/home/alice/.ssh/authorized_keys",
        raw_value="ssh-rsa AAAA...",
        remediation_available=True,
    )


@pytest.fixture
def sample_finding_low():
    return Finding(
        rule_id="SHELL_RC_MODIFICATION",
        severity=Severity.LOW,
        title="Shell RC modified recently",
        description=".bashrc was modified within the last 48 hours.",
        artifact_path="/home/alice/.bashrc",
        raw_value="/home/alice/.bashrc",
        remediation_available=False,
    )


@pytest.fixture
def sample_findings(sample_finding_high, sample_finding_medium, sample_finding_low):
    return [sample_finding_high, sample_finding_medium, sample_finding_low]


@pytest.fixture
def sample_timeline_events():
    base = datetime.datetime(2024, 5, 24, 10, 0, 0, tzinfo=datetime.timezone.utc)
    return [
        TimelineEvent(timestamp=base, source="syslog", description="cron job ran"),
        TimelineEvent(
            timestamp=base + datetime.timedelta(seconds=30),
            source="journald",
            description="SSH session opened",
        ),
        TimelineEvent(
            timestamp=base + datetime.timedelta(minutes=5),
            source="auditd",
            description="EXECVE: /bin/bash -i",
        ),
    ]


@pytest.fixture
def sample_remediation_results():
    return [
        RemediationResult(
            finding_rule_id="CRON_TMP_PATH",
            status=RemediationStatus.SUCCESS,
            message="Entry removed.",
            backup_path="/var/backups/ubuntils/20240524_103000/crontab",
            rollback_command="cp /var/backups/ubuntils/20240524_103000/crontab /etc/crontab",
        ),
        RemediationResult(
            finding_rule_id="SSH_UNAUTHORIZED_KEY",
            status=RemediationStatus.SKIPPED,
            message="Dry run — no changes applied.",
        ),
    ]


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def mock_artifact_data():
    return {
        "processes": [
            {"pid": 1234, "name": "bash", "exe": "/bin/bash", "cmdline": "bash -i"},
            {"pid": 5678, "name": "sshd", "exe": "/usr/sbin/sshd", "cmdline": "sshd -D"},
        ],
        "cron_entries": [
            {
                "source": "/etc/crontab",
                "user": "root",
                "schedule": "* * * * *",
                "command": "/tmp/evil.sh",
            }
        ],
        "environment_vars": {
            "/etc/environment": {"LD_PRELOAD": "/tmp/hook.so"},
        },
        "authorized_keys": {
            "/home/alice/.ssh/authorized_keys": {
                "keys": ["ssh-rsa AAAA..."],
                "mtime_days_ago": 2,
            }
        },
        "sudoers_entries": [
            {"user": "alice", "host": "ALL", "runas": "ALL", "nopasswd": True, "commands": "ALL"}
        ],
        "systemd_timers": [
            {"unit": "evil.timer", "exec_start": "/tmp/payload.sh", "active": True}
        ],
        "users": [
            {"username": "alice", "uid": 1001, "shell": "/bin/bash", "home": "/home/alice"},
            {"username": "root", "uid": 0, "shell": "/bin/bash", "home": "/root"},
        ],
        "network_connections": [
            {"proto": "tcp", "local": "0.0.0.0:4444", "remote": "10.0.0.1:54321", "state": "ESTABLISHED"}
        ],
    }


@pytest.fixture(autouse=True)
def _preserve_in_tmp(tmp_path_factory, monkeypatch):
    """Never let a test write evidence copies under /var/lib/ubuntils."""
    from ubuntils.remediators import preserve
    monkeypatch.setattr(preserve, "PRESERVE_BASE",
                        str(tmp_path_factory.mktemp("preserve") / "p"))
