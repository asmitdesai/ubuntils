import datetime
from unittest.mock import patch

import pytest

from ubuntils.collectors.source import BundleSource, LiveSource
from ubuntils.timeline.builder import TimelineBuilder, TimelineEvent


SYSLOG_SNIPPET = """\
May 24 10:30:01 myhost cron[1234]: (root) CMD (/usr/local/bin/backup.sh)
May 24 10:30:02 myhost sshd[5678]: Accepted publickey for alice from 10.0.0.1 port 54321
May 24 10:30:03 myhost sudo[9012]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
"""

SYSLOG_NO_YEAR_LINE = "Jan 15 08:00:00 myhost kernel: USB disconnect"

JOURNALD_JSON_OUTPUT = """\
{"__REALTIME_TIMESTAMP": "1716548401000000", "MESSAGE": "Started session 42 of user alice.", "_SYSTEMD_UNIT": "session-42.scope", "SYSLOG_IDENTIFIER": "systemd"}
{"__REALTIME_TIMESTAMP": "1716548402500000", "MESSAGE": "pam_unix(sudo:session): session opened for user root", "SYSLOG_IDENTIFIER": "sudo"}
"""

AUDITD_SNIPPET = """\
type=EXECVE msg=audit(1716548400.123:456): argc=2 a0="/bin/bash" a1="-i"
type=SYSCALL msg=audit(1716548401.456:789): arch=c000003e syscall=59 success=yes exit=0 a0=7f1234 a1=0 a2=0 a3=0 items=2 ppid=1000 pid=1001 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="bash" exe="/bin/bash" subj=unconfined key=(null)
"""


def test_parse_syslog_basic():
    builder = TimelineBuilder()
    events = builder._parse_syslog(SYSLOG_SNIPPET)
    assert len(events) == 3
    assert all(isinstance(e, TimelineEvent) for e in events)
    assert events[0].source == "syslog"
    assert "backup.sh" in events[0].description
    assert events[1].description.startswith("Accepted publickey")
    assert events[2].description.startswith("alice")


def test_parse_syslog_year_injection():
    builder = TimelineBuilder()
    events = builder._parse_syslog(SYSLOG_NO_YEAR_LINE)
    assert len(events) == 1
    assert events[0].timestamp.year == datetime.datetime.now().year


def test_parse_syslog_timestamps_are_aware():
    builder = TimelineBuilder()
    events = builder._parse_syslog(SYSLOG_SNIPPET)
    for e in events:
        assert e.timestamp.tzinfo is not None


def test_parse_journald_json():
    builder = TimelineBuilder()
    with patch.object(LiveSource, "run") as mock_run:
        mock_run.return_value = (JOURNALD_JSON_OUTPUT, "", 0)
        events = builder._parse_journald(since_days=7)

    assert len(events) == 2
    assert events[0].source == "journald"
    assert "alice" in events[0].description
    assert events[0].timestamp.microsecond == 0
    assert events[1].timestamp.microsecond == 500000


def test_parse_journald_returns_empty_on_failure():
    builder = TimelineBuilder()
    with patch.object(LiveSource, "run") as mock_run:
        mock_run.return_value = ("", "journalctl not found", -1)
        events = builder._parse_journald(since_days=7)
    assert events == []


def test_parse_auditd_execve():
    builder = TimelineBuilder()
    events = builder._parse_auditd(AUDITD_SNIPPET)
    assert len(events) == 2
    assert events[0].source == "auditd"
    assert events[0].timestamp == datetime.datetime.fromtimestamp(
        1716548400.123, tz=datetime.timezone.utc
    )
    assert "/bin/bash" in events[0].description


def test_build_deduplicates():
    builder = TimelineBuilder()
    t = datetime.datetime(2024, 5, 24, 10, 30, 0, tzinfo=datetime.timezone.utc)
    e1 = TimelineEvent(timestamp=t, source="syslog", description="duplicate event")
    e2 = TimelineEvent(timestamp=t, source="syslog", description="duplicate event")
    merged = builder._deduplicate([e1, e2])
    assert len(merged) == 1


def test_parse_syslog_skips_empty_lines():
    builder = TimelineBuilder()
    content = "\n\n" + SYSLOG_SNIPPET + "\n\n"
    events = builder._parse_syslog(content)
    assert len(events) == 3


def test_parse_syslog_skips_non_matching_lines():
    builder = TimelineBuilder()
    events = builder._parse_syslog("this line does not match the regex\n" + SYSLOG_NO_YEAR_LINE)
    assert len(events) == 1


def test_parse_syslog_skips_bad_timestamp():
    builder = TimelineBuilder()
    bad_line = "Xxx 99 99:99:99 myhost sshd[1]: connected"
    events = builder._parse_syslog(bad_line)
    assert events == []


def test_parse_journald_skips_empty_lines():
    builder = TimelineBuilder()
    content = "\n" + JOURNALD_JSON_OUTPUT + "\n"
    with patch.object(LiveSource, "run") as mock_run:
        mock_run.return_value = (content, "", 0)
        events = builder._parse_journald(since_days=7)
    assert len(events) == 2


def test_parse_journald_skips_bad_json():
    builder = TimelineBuilder()
    bad_json = "not-json\n" + JOURNALD_JSON_OUTPUT
    with patch.object(LiveSource, "run") as mock_run:
        mock_run.return_value = (bad_json, "", 0)
        events = builder._parse_journald(since_days=7)
    assert len(events) == 2


def test_parse_auditd_skips_empty_lines():
    builder = TimelineBuilder()
    content = "\n\n" + AUDITD_SNIPPET
    events = builder._parse_auditd(content)
    assert len(events) == 2


def test_parse_auditd_skips_non_matching_lines():
    builder = TimelineBuilder()
    content = "this line does not match\n" + AUDITD_SNIPPET
    events = builder._parse_auditd(content)
    assert len(events) == 2


def test_parse_auditd_skips_bad_timestamp():
    builder = TimelineBuilder()
    bad_line = "type=EXECVE msg=audit(not_a_float:456): argc=1 a0=ls"
    events = builder._parse_auditd(bad_line)
    assert events == []


def test_build_reads_syslog_and_auditd(tmp_path):
    (tmp_path / "var" / "log" / "audit").mkdir(parents=True)
    (tmp_path / "var" / "log" / "syslog").write_text(SYSLOG_SNIPPET)
    (tmp_path / "var" / "log" / "audit" / "audit.log").write_text(AUDITD_SNIPPET)

    builder = TimelineBuilder(source=LiveSource(root=str(tmp_path)))
    with patch.object(LiveSource, "run") as mock_run:
        mock_run.return_value = (JOURNALD_JSON_OUTPUT, "", 0)
        events = builder.build()

    assert len(events) > 0
    sources = {e.source for e in events}
    assert "syslog" in sources


def test_build_handles_missing_log_files(tmp_path):
    builder = TimelineBuilder(source=LiveSource(root=str(tmp_path)))
    with patch.object(LiveSource, "run") as mock_run:
        mock_run.return_value = ("", "", -1)
        events = builder.build()

    assert events == []


def test_timeline_builder_reads_syslog_via_source(tmp_path):
    files = tmp_path / "files"
    (files / "var" / "log").mkdir(parents=True)
    (files / "var" / "log" / "syslog").write_text(
        "Jan  5 10:00:00 host sshd[123]: Accepted password for alice\n"
    )
    src = BundleSource(root_dir=str(files), command_index={})

    events = TimelineBuilder(source=src).build()

    assert any("Accepted password for alice" in e.description for e in events)


def test_timeline_builder_replays_captured_journalctl(tmp_path):
    import json
    files = tmp_path / "files"
    cmds = tmp_path / "commands"
    cmds.mkdir()
    files.mkdir()
    record = json.dumps({"__REALTIME_TIMESTAMP": "1735646400000000", "MESSAGE": "sudo: alice ran /bin/su"})
    (cmds / "journalctl.txt").write_text(record + "\n")
    src = BundleSource(root_dir=str(files), command_index={"journalctl": str(cmds / "journalctl.txt")})

    events = TimelineBuilder(source=src).build()

    assert any("sudo: alice ran /bin/su" in e.description for e in events)


def test_build_sorted_ascending():
    builder = TimelineBuilder()
    t1 = datetime.datetime(2024, 5, 24, 10, 0, 0, tzinfo=datetime.timezone.utc)
    t2 = datetime.datetime(2024, 5, 24, 9, 0, 0, tzinfo=datetime.timezone.utc)
    t3 = datetime.datetime(2024, 5, 24, 11, 0, 0, tzinfo=datetime.timezone.utc)
    events = [
        TimelineEvent(timestamp=t1, source="syslog", description="middle"),
        TimelineEvent(timestamp=t2, source="syslog", description="earliest"),
        TimelineEvent(timestamp=t3, source="syslog", description="latest"),
    ]
    sorted_events = builder._deduplicate(events)
    assert sorted_events[0].description == "earliest"
    assert sorted_events[1].description == "middle"
    assert sorted_events[2].description == "latest"
