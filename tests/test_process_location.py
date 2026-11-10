"""QW-1/QW-2, C2: processes judged by where they run from, and listeners."""
from tests import fixture_hosts as fh
from ubuntils.detectors.rules import (
    rule_process_masquerade, rule_process_suspicious_connection, rule_process_suspicious_exe,
)


def _p(pid, name, exe):
    return {"pid": pid, "name": name, "uid": 0, "exe": exe, "cmdline": name}


def _sev(f):
    return f.severity.value


def test_location_decides_whatever_the_name():
    found = rule_process_suspicious_exe({"processes": [
        _p(1, "httpd", "/opt/web/httpd"),               # odd but not suspicious by location
        _p(2, "cache-sync", "/dev/shm/.c/cache-sync"),  # temp dir
        _p(3, "x", "/memfd:x (deleted)"),               # fileless
        _p(4, "agent", "/opt/agent/agent (deleted)"),   # deleted outside system dirs
        _p(5, "sshd", "/usr/sbin/sshd (deleted)"),      # upgrade awaiting restart
        _p(6, "kthread", ""),                           # kernel thread / offline
    ]})
    by_pid = {f.description.split("pid=")[1].split(")")[0]: f for f in found}
    assert set(by_pid) == {"2", "3", "4", "5"}
    assert [_sev(by_pid[p]) for p in "234"] == ["HIGH", "HIGH", "HIGH"]
    assert _sev(by_pid["5"]) == "LOW" and "package upgrade" in by_pid["5"].description
    assert any(s["name"] == "memfd_exe" for s in by_pid["3"].signals)
    assert "deleted" in by_pid["4"].description


def test_venv_python_under_opt_and_home_does_not_fire(tmp_path):
    # A venv's python3 is a symlink: /proc/<pid>/exe names the real interpreter.
    # `python -m venv --copies` puts a real binary under /opt or /home: still
    # not a temp dir, deleted or memfd, so still quiet.
    procs = [_p(10, "python3", "/usr/bin/python3.12"),
             _p(11, "python3", "/opt/app/venv/bin/python3"),
             _p(12, "python3", "/home/dev/.venv/bin/python3")]
    assert rule_process_suspicious_exe({"processes": procs}) == []
    root = fh.build(tmp_path / "h", fh.CLEAN)
    fh.add_process(root, 11, "python3", "/opt/app/venv/bin/python3")
    fh.add_process(root, 12, "python3", "/home/dev/.venv/bin/python3")
    assert fh.scan(root, {"ss": ("", 0)}).findings == []


def test_masquerades_are_not_reported_twice():
    procs = [_p(1, "sshd", "/var/tmp/sshd"), _p(2, "[kworker/0:1]", "/dev/shm/kworker")]
    assert rule_process_suspicious_exe({"processes": procs}) == []
    found = rule_process_masquerade({"processes": procs})
    assert [_sev(f) for f in found] == ["HIGH", "HIGH"]


def test_listeners_by_location():
    procs = [_p(1, "a", "/tmp/a"), _p(2, "b", "/opt/b/b"), _p(3, "c", "/usr/sbin/c"),
             _p(4, "d", "/tmp/d")]
    conns = [
        {"proto": "tcp", "local_addr": "0.0.0.0", "local_port": "4444", "remote_addr": "0.0.0.0",
         "remote_port": "*", "state": "LISTEN", "pid": "1"},
        {"proto": "udp", "local_addr": "[::]", "local_port": "53", "remote_addr": "*",
         "remote_port": "*", "state": "UNCONN", "pid": "2"},
        {"proto": "tcp", "local_addr": "0.0.0.0", "local_port": "80", "remote_addr": "0.0.0.0",
         "remote_port": "*", "state": "LISTEN", "pid": "3"},
        {"proto": "tcp", "local_addr": "[::1]", "local_port": "5555", "remote_addr": "[::]",
         "remote_port": "*", "state": "LISTEN", "pid": "4"},
    ]
    found = rule_process_suspicious_connection({"processes": procs, "connections": conns})
    got = {f.description.split("pid=")[1].split(",")[0]: _sev(f) for f in found}
    assert got == {"1": "HIGH", "2": "MEDIUM"}  # standard dir and loopback stay quiet


def test_listener_count_is_in_the_description():
    procs = [_p(1, "a", "/tmp/a")]
    conns = [{"proto": "tcp", "local_addr": "0.0.0.0", "local_port": p, "remote_addr": "0.0.0.0",
              "remote_port": "*", "state": "LISTEN", "pid": "1"} for p in ("1", "2", "3")]
    f = rule_process_suspicious_connection({"processes": procs, "connections": conns})[0]
    assert "and 2 more" in f.description


def test_interpreter_in_a_temp_dir_is_still_reported_once():
    procs = [_p(1, "python3", "/tmp/.x/python3"), _p(2, "perl", "/opt/perlbrew/bin/perl")]
    masq = rule_process_masquerade({"processes": procs})
    loc = rule_process_suspicious_exe({"processes": procs})
    assert [f.raw_value for f in masq] == ["/tmp/.x/python3"] and loc == []
