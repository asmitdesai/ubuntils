"""QW-10 / E10-S3: custom rules can match systemd, users, sudoers and file sources."""
from ubuntils.detectors.custom_rules import apply_custom_rules, load_custom_rules

ARTIFACTS = {
    "services": [{"unit": "x.service", "unit_path": "/etc/systemd/system/x.service",
                  "exec_start": "/usr/local/sbin/updater --quiet"}],
    "timers": [{"unit": "t.timer", "exec_start": "/usr/bin/true"}],
    "users": [{"username": "alice", "uid": 1001, "gid": 1001, "home": "/home/alice",
               "shell": "/bin/bash", "groups": ["sudo", "docker"]}],
    "sudoers_rules": [{"source": "/etc/sudoers.d/x", "raw_line": "alice ALL=(ALL) NOPASSWD: ALL"}],
    "shell_init_files": [{"source": "/home/alice/.bashrc", "content": "alias ll='ls'\nexport X=1\n"}],
    "pam_files": [{"path": "/etc/pam.d/sshd", "content": "auth optional pam_exec.so /x\n"}],
    "nsswitch_content": "passwd: files evil\n",
}


def _run(tmp_path, source, match, pattern):
    p = tmp_path / "r.yaml"
    p.write_text(f"rules:\n  - id: T\n    severity: LOW\n    title: t\n    description: d\n"
                 f"    source: {source}\n    match: {match}\n    pattern: '{pattern}'\n")
    return [(f.artifact_path, f.raw_value) for f in apply_custom_rules(load_custom_rules(str(p)), ARTIFACTS)]


def test_systemd_source(tmp_path):
    assert _run(tmp_path, "systemd", "substring", "/usr/local/sbin") == \
        [("/etc/systemd/system/x.service", "/usr/local/sbin/updater --quiet")]
    assert _run(tmp_path, "systemd", "glob", "t.timer") == [("t.timer", "/usr/bin/true")]


def test_users_source(tmp_path):
    hits = _run(tmp_path, "users", "regex", "groups=([^ ]*,)?docker(,|$)")
    assert hits == [("/etc/passwd", "alice:1001:1001:/home/alice:/bin/bash groups=sudo,docker")]


def test_sudoers_source(tmp_path):
    assert _run(tmp_path, "sudoers", "substring", "NOPASSWD") == \
        [("/etc/sudoers.d/x", "alice ALL=(ALL) NOPASSWD: ALL")]


def test_file_source_matches_lines_of_shell_pam_and_nsswitch_files(tmp_path):
    assert _run(tmp_path, "file", "substring", "pam_exec") == \
        [("/etc/pam.d/sshd", "auth optional pam_exec.so /x")]
    assert _run(tmp_path, "file", "regex", "^export ") == [("/home/alice/.bashrc", "export X=1")]
    assert _run(tmp_path, "file", "substring", "evil") == [("/etc/nsswitch.conf", "passwd: files evil")]


def test_the_shipped_example_file_loads_and_matches():
    import os
    rules = load_custom_rules(os.path.join(os.path.dirname(__file__), "..", "examples",
                                           "custom_rules.yaml"))
    hits = apply_custom_rules([r for r in rules if r.id == "CUSTOM_DOCKER_GROUP_MEMBER"], ARTIFACTS)
    assert len(hits) == 1
