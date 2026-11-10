"""QW-6 (auth.log) and QW-11 (collect --journal-days)."""
from click.testing import CliRunner

from tests import fixture_hosts as fh
from ubuntils import cli
from ubuntils.timeline.builder import TimelineBuilder


def test_auth_log_events_are_in_the_timeline(tmp_path):
    root = fh.build(tmp_path / "h", {
        "/etc/timezone": "Etc/UTC\n",
        "/var/log/auth.log": (
            "2026-11-09T10:15:02.123456+00:00 web01 sshd[812]: Accepted publickey for admin "
            "from 203.0.113.9 port 51522 ssh2: ED25519 SHA256:abc\n"
            "2026-11-09T10:16:40.000001+00:00 web01 sudo:    admin : TTY=pts/0 ; PWD=/home/admin ; "
            "USER=root ; COMMAND=/usr/bin/bash\n")})
    events = TimelineBuilder(source=fh.fixture_source(root)).build()
    programs = [e.program for e in events]
    assert "sshd" in programs and "sudo" in programs
    assert any("Accepted publickey" in e.description for e in events)


def test_auth_log_is_collected():
    assert "/var/log/auth.log" in cli.COLLECT_FILES


def test_journal_window_changes_only_the_journalctl_argv():
    default = dict(cli.collect_commands())
    wide = dict(cli.collect_commands(30))
    assert "--since=7 days ago" in default["journalctl"]
    assert "--since=30 days ago" in wide["journalctl"]
    assert {k: v for k, v in wide.items() if k != "journalctl"} == \
        {k: v for k, v in default.items() if k != "journalctl"}
    assert dict(cli.COLLECT_COMMANDS) == default  # the static list is the 7-day default


def test_collect_journal_days_reaches_the_bundle_writer(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(cli, "_ensure_root", lambda: None)

    def fake_write_bundle(**kwargs):
        seen.update(kwargs)
        return kwargs["out_path"]

    monkeypatch.setattr("ubuntils.bundle.writer.write_bundle", fake_write_bundle)
    r = CliRunner().invoke(cli.main, ["collect", "--journal-days", "45",
                                      "--output", str(tmp_path / "b.tar.gz")])
    assert r.exit_code == 0, r.output
    assert "--since=45 days ago" in dict(seen["commands_to_capture"])["journalctl"]
    bad = CliRunner().invoke(cli.main, ["collect", "--journal-days", "0"])
    assert bad.exit_code == 2
