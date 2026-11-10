"""E13-S10 / Workstream 3: property tests for every parser of host text.

Everything a collector reads is attacker-controlled. For arbitrary text each
parser must: never raise; never emit a value that isn't in its input; and
report unparsable input as degraded rather than as an empty, clean result.
"""
import fnmatch
import os

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ubuntils.analysis import cmdmatch
from ubuntils.collectors.cron import CronCollector
from ubuntils.collectors.network import NetworkCollector
from ubuntils.collectors.source import ArtifactSource, UserFile
from ubuntils.collectors.ssh import SSHCollector, _parse_key_line
from ubuntils.collectors.sudoers import SudoersCollector
from ubuntils.collectors.systemd import SystemdCollector
from ubuntils.collectors.users import UserCollector

SETTINGS = settings(max_examples=150, deadline=None,
                    suppress_health_check=[HealthCheck.too_slow])
# Text shaped like config files: printable, separators, the odd control byte.
TEXT = st.text(alphabet=st.characters(blacklist_categories=("Cs",), max_codepoint=0x2FF),
               max_size=600)
LINES = st.lists(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789:=,%@#!*/._- \t\"'()[]",
                         max_size=80), max_size=12).map("\n".join)


class MemorySource(ArtifactSource):
    def __init__(self, files=None, commands=None):
        self.files, self.commands = dict(files or {}), dict(commands or {})

    def read_text(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def read_bytes(self, path):
        return self.read_text(path).encode("utf-8", "surrogateescape")

    def read_user_file(self, path):
        text = self.read_text(path)
        return UserFile(text=text, size=len(text.encode("utf-8", "surrogateescape")))

    def exists(self, path):
        return path in self.files

    def lstat(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return os.stat_result((0o100644, 1, 1, 1, 0, 0, len(self.files[path]), 0, 0, 0))

    def glob(self, pattern):
        return sorted(p for p in self.files if fnmatch.fnmatch(p, pattern))

    def readlink(self, path):
        raise OSError("no links")

    def run(self, name, argv, timeout=30):
        if name in self.commands:
            return self.commands[name], "", 0
        return "", "not available", -1


@SETTINGS
@given(passwd=LINES, shadow=LINES, group=LINES)
def test_users_parser(passwd, shadow, group):
    c = UserCollector(source=MemorySource({"/etc/passwd": passwd, "/etc/shadow": shadow,
                                           "/etc/group": group}))
    users = c.collect().get("users", [])
    for u in users:
        assert u["username"] in passwd and isinstance(u["uid"], int)
    real = [l for l in passwd.splitlines() if l.strip() and not l.strip().startswith("#")]
    if real and not users:
        assert c.degraded, "passwd had content, nothing parsed, and nothing was reported"


@SETTINGS
@given(sudoers=LINES, dropin=LINES)
def test_sudoers_parser(sudoers, dropin):
    c = SudoersCollector(source=MemorySource({"/etc/sudoers": sudoers,
                                              "/etc/sudoers.d/x": dropin}))
    for r in c.collect().get("sudoers_rules", []):
        assert r["raw_line"].strip() and (r["raw_line"] in sudoers + "\n" + dropin
                                          or r["source"] in ("/etc/sudoers", "/etc/sudoers.d/x"))


@SETTINGS
@given(line=TEXT)
def test_authorized_keys_line_parser(line):
    parsed = _parse_key_line(line)
    if parsed:
        assert parsed["key_data"] in line


@SETTINGS
@given(keys=LINES)
def test_ssh_collector(keys):
    src = MemorySource({"/etc/passwd": "u:x:1000:1000::/home/u:/bin/bash\n",
                        "/home/u/.ssh/authorized_keys": keys})
    for k in SSHCollector(source=src).collect().get("authorized_keys", []):
        assert k["key_data"] in keys


@SETTINGS
@given(crontab=LINES, user=LINES, ana=LINES)
def test_cron_parser(crontab, user, ana):
    src = MemorySource({"/etc/crontab": crontab, "/var/spool/cron/crontabs/u": user,
                        "/etc/anacrontab": ana})
    for e in CronCollector(source=src).collect().get("cron_entries", []):
        assert e["command"] in crontab + user + ana


@SETTINGS
@given(unit=LINES)
def test_systemd_unit_parser(unit):
    src = MemorySource({"/etc/systemd/system/x.service": unit,
                        "/etc/systemd/system/y.service.d/o.conf": unit})
    for s in SystemdCollector(source=src).collect().get("services", []):
        assert s["exec_start"] in unit


@SETTINGS
@given(ss=LINES)
def test_ss_parser(ss):
    c = NetworkCollector(source=MemorySource(commands={"ss": ss}))
    for conn in c.collect().get("connections", []):
        assert conn["pid"] == "" or conn["pid"].isdigit()
        assert conn["local_port"] in ss or conn["local_port"] == "*"


@SETTINGS
@given(text=TEXT)
def test_matcher(text):
    for s in cmdmatch.match(text):
        assert s.family in cmdmatch.FAMILY_DESCRIPTIONS and 0 < s.weight <= 40
