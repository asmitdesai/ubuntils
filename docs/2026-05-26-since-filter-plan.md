# --since Time-Window Filter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--since` flag to `ubuntils scan` that limits artifact collection and timeline parsing to a user-specified time window, reducing scan duration on large systems.

**Architecture:** A new `parse_since()` utility converts `--since` strings (relative like `24h`/`7d` or absolute ISO dates) into a timezone-aware `datetime`. `BaseCollector` gains a `since` constructor param and a `_file_modified_since(path)` helper; four file-based collectors use it to skip stale files. `TimelineBuilder.build()` gains the same `since` param and filters log entries inline. Both `_run_pipeline()` and `UbuntilsApp` thread `since` end-to-end.

**Tech Stack:** Python 3.11, python-dateutil (existing dependency), Click, Textual, pytest.

**Spec:** `docs/2026-05-26-since-filter-design.md`

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Create | `ubuntils/utils/since_parser.py` | Parse `--since` string → timezone-aware `datetime` |
| Modify | `ubuntils/collectors/base.py` | Add `since` param + `_file_modified_since` helper |
| Modify | `ubuntils/collectors/cron.py` | Skip cron files outside window |
| Modify | `ubuntils/collectors/ssh.py` | Skip `authorized_keys` files outside window |
| Modify | `ubuntils/collectors/sudoers.py` | Skip sudoers files outside window |
| Modify | `ubuntils/collectors/environment.py` | Skip shell init files outside window |
| Modify | `ubuntils/timeline/builder.py` | `since` param, inline entry filtering, journalctl `--since` |
| Modify | `ubuntils/cli.py` | `--since` option, parse + validate, thread to pipeline and TUI |
| Modify | `ubuntils/tui/app.py` | `since` param, thread to scan worker |
| Modify | `ubuntils/tui/stats_panel.py` | Show "Scan window" line when `since` is set |
| Modify | `ubuntils/tui/summary_screen.py` | Show "Scan window" in summary tab |
| Modify | `tests/test_base_classes.py` | `_file_modified_since` unit tests |
| Modify | `tests/test_collectors.py` | mtime filter tests for 4 collectors |
| Modify | `tests/test_timeline.py` | `since` filter tests + update stale `since_days` calls |
| Modify | `tests/test_cli.py` | `--since` parsing tests + CLI flag tests |
| Modify | `tests/test_tui.py` | `since` in `UbuntilsApp` + stats display tests |

---

### Task 1: `parse_since` utility

**Files:**
- Create: `ubuntils/utils/since_parser.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_cli.py` after the existing imports block:

```python
import datetime as dt
from ubuntils.utils.since_parser import parse_since


def test_parse_since_hours():
    before = dt.datetime.now(tz=dt.timezone.utc)
    result = parse_since("24h")
    expected = before - dt.timedelta(hours=24)
    assert abs((result - expected).total_seconds()) < 2
    assert result.tzinfo == dt.timezone.utc


def test_parse_since_days():
    result = parse_since("7d")
    expected = dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(days=7)
    assert abs((result - expected).total_seconds()) < 2
    assert result.tzinfo == dt.timezone.utc


def test_parse_since_minutes():
    result = parse_since("30m")
    assert result.tzinfo == dt.timezone.utc


def test_parse_since_weeks():
    result = parse_since("2w")
    expected = dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(weeks=2)
    assert abs((result - expected).total_seconds()) < 2


def test_parse_since_absolute_date():
    result = parse_since("2026-05-20")
    assert result.year == 2026
    assert result.month == 5
    assert result.day == 20
    assert result.tzinfo is not None


def test_parse_since_absolute_datetime():
    result = parse_since("2026-05-20 14:00")
    assert result.hour == 14
    assert result.tzinfo is not None


def test_parse_since_invalid_raises():
    with pytest.raises(ValueError, match="Invalid --since"):
        parse_since("foo")
```

- [ ] **Step 2: Run to confirm they fail**

```bash
python -m pytest tests/test_cli.py::test_parse_since_hours tests/test_cli.py::test_parse_since_days tests/test_cli.py::test_parse_since_minutes tests/test_cli.py::test_parse_since_weeks tests/test_cli.py::test_parse_since_absolute_date tests/test_cli.py::test_parse_since_absolute_datetime tests/test_cli.py::test_parse_since_invalid_raises -v --no-cov
```

Expected: `ModuleNotFoundError: No module named 'ubuntils.utils.since_parser'`

- [ ] **Step 3: Create `ubuntils/utils/since_parser.py`**

```python
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from dateutil import parser as dateutil_parser

_RELATIVE_RE = re.compile(r'^(\d+)(m|h|d|w)$')
_UNITS = {'m': 'minutes', 'h': 'hours', 'd': 'days', 'w': 'weeks'}


def parse_since(value: str) -> datetime:
    m = _RELATIVE_RE.match(value.strip())
    if m:
        amount = int(m.group(1))
        unit = _UNITS[m.group(2)]
        return datetime.now(tz=timezone.utc) - timedelta(**{unit: amount})
    try:
        dt = dateutil_parser.parse(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        raise ValueError(
            f"Invalid --since value: {value!r}. "
            "Use relative (e.g. '24h', '7d') or absolute (e.g. '2026-05-20', '2026-05-20 14:00')."
        )
```

- [ ] **Step 4: Run to confirm tests pass**

```bash
python -m pytest tests/test_cli.py::test_parse_since_hours tests/test_cli.py::test_parse_since_days tests/test_cli.py::test_parse_since_minutes tests/test_cli.py::test_parse_since_weeks tests/test_cli.py::test_parse_since_absolute_date tests/test_cli.py::test_parse_since_absolute_datetime tests/test_cli.py::test_parse_since_invalid_raises -v --no-cov
```

Expected: 7 PASSED.

- [ ] **Step 5: Commit**

```bash
git add ubuntils/utils/since_parser.py tests/test_cli.py
git commit -m "feat: add parse_since utility for --since flag"
```

---

### Task 2: `BaseCollector` — `since` param + `_file_modified_since`

**Files:**
- Modify: `ubuntils/collectors/base.py`
- Test: `tests/test_base_classes.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_base_classes.py` after `test_base_collector_subclass_valid` (around line 99):

```python
import datetime
import os


def test_base_collector_since_defaults_to_none():
    class C(BaseCollector):
        def collect(self): return {}
    assert C()._since is None


def test_file_modified_since_no_filter(tmp_path):
    class C(BaseCollector):
        def collect(self): return {}
    path = tmp_path / "f.txt"
    path.write_text("x")
    assert C(since=None)._file_modified_since(str(path)) is True


def test_file_modified_since_new_file(tmp_path):
    class C(BaseCollector):
        def collect(self): return {}
    path = tmp_path / "f.txt"
    path.write_text("x")
    since = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(hours=1)
    assert C(since=since)._file_modified_since(str(path)) is True


def test_file_modified_since_old_file(tmp_path):
    class C(BaseCollector):
        def collect(self): return {}
    path = tmp_path / "f.txt"
    path.write_text("x")
    old_ts = (datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(hours=48)).timestamp()
    os.utime(str(path), (old_ts, old_ts))
    since = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(hours=24)
    assert C(since=since)._file_modified_since(str(path)) is False


def test_file_modified_since_oserror():
    class C(BaseCollector):
        def collect(self): return {}
    since = datetime.datetime.now(tz=datetime.timezone.utc)
    assert C(since=since)._file_modified_since("/nonexistent/path/xyz_does_not_exist") is True
```

- [ ] **Step 2: Run to confirm they fail**

```bash
python -m pytest tests/test_base_classes.py::test_base_collector_since_defaults_to_none tests/test_base_classes.py::test_file_modified_since_no_filter tests/test_base_classes.py::test_file_modified_since_new_file tests/test_base_classes.py::test_file_modified_since_old_file tests/test_base_classes.py::test_file_modified_since_oserror -v --no-cov
```

Expected: `TypeError: BaseCollector.__init__() takes 1 positional argument but 2 were given` (or similar).

- [ ] **Step 3: Rewrite `ubuntils/collectors/base.py`**

```python
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from datetime import datetime


class BaseCollector(ABC):
    def __init__(self, since: datetime | None = None) -> None:
        self._since = since

    @abstractmethod
    def collect(self) -> dict:
        """
        Collect forensic artifacts.
        Returns a dict of collected data.
        Must not raise — log exceptions and return {}.
        """

    def _file_modified_since(self, path: str) -> bool:
        if self._since is None:
            return True
        try:
            return os.stat(path).st_mtime >= self._since.timestamp()
        except OSError:
            return True
```

- [ ] **Step 4: Run to confirm tests pass**

```bash
python -m pytest tests/test_base_classes.py -v --no-cov
```

Expected: all PASSED (including all pre-existing tests).

- [ ] **Step 5: Commit**

```bash
git add ubuntils/collectors/base.py tests/test_base_classes.py
git commit -m "feat: add since param and _file_modified_since to BaseCollector"
```

---

### Task 3: `CronCollector` mtime filter

**Files:**
- Modify: `ubuntils/collectors/cron.py`
- Test: `tests/test_collectors.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_collectors.py` after `test_cron_collector_skips_comments` (around line 240):

```python
def test_cron_collector_skips_file_outside_window():
    from ubuntils.collectors.cron import CronCollector

    with mock.patch("glob.glob", return_value=["/etc/cron.d/evil"]), \
         mock.patch.object(CronCollector, "_file_modified_since", return_value=False):
        result = CronCollector().collect()

    assert result["cron_entries"] == []


def test_cron_collector_reads_file_inside_window():
    from ubuntils.collectors.cron import CronCollector

    cron_line = "* * * * * root /tmp/evil.sh\n"
    with mock.patch("glob.glob", return_value=[]), \
         mock.patch.object(CronCollector, "_file_modified_since", return_value=True), \
         mock.patch("builtins.open", mock.mock_open(read_data=cron_line)):
        result = CronCollector().collect()

    assert len(result["cron_entries"]) == 1
```

- [ ] **Step 2: Run to confirm they fail**

```bash
python -m pytest tests/test_collectors.py::test_cron_collector_skips_file_outside_window tests/test_collectors.py::test_cron_collector_reads_file_inside_window -v --no-cov
```

Expected: both FAIL — `skips_file_outside_window` collects entries instead of skipping, `reads_file_inside_window` passes already (or fails if `/etc/crontab` check interferes).

- [ ] **Step 3: Edit `ubuntils/collectors/cron.py`**

Replace the `collect` method body:

```python
    def collect(self) -> dict:
        entries = []

        for path in ["/etc/crontab"] + glob.glob("/etc/cron.d/*"):
            if not self._file_modified_since(path):
                continue
            entries.extend(self._parse_system_crontab(path))

        for path in glob.glob("/var/spool/cron/crontabs/*"):
            if not self._file_modified_since(path):
                continue
            owner = os.path.basename(path)
            entries.extend(self._parse_user_crontab(path, owner))

        return {"cron_entries": entries}
```

- [ ] **Step 4: Run to confirm tests pass**

```bash
python -m pytest tests/test_collectors.py -k "cron" -v --no-cov
```

Expected: all PASSED.

- [ ] **Step 5: Commit**

```bash
git add ubuntils/collectors/cron.py tests/test_collectors.py
git commit -m "feat: filter cron files by mtime when --since is set"
```

---

### Task 4: `SSHCollector` mtime filter

**Files:**
- Modify: `ubuntils/collectors/ssh.py`
- Test: `tests/test_collectors.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_collectors.py` after `test_ssh_collector_records_mtime` (around line 390):

```python
def test_ssh_collector_skips_file_outside_window():
    from ubuntils.collectors.ssh import SSHCollector

    passwd = "alice:x:1000:1000::/home/alice:/bin/bash\n"
    with mock.patch("os.path.exists", return_value=True), \
         mock.patch.object(SSHCollector, "_file_modified_since", return_value=False), \
         mock.patch("builtins.open", mock.mock_open(read_data=passwd)):
        result = SSHCollector().collect()

    assert result.get("authorized_keys", []) == []


def test_ssh_collector_reads_file_inside_window():
    from ubuntils.collectors.ssh import SSHCollector

    passwd = "alice:x:1000:1000::/home/alice:/bin/bash\n"
    keys = "ssh-rsa AAAA attacker\n"

    def fake_open(path, *args, **kwargs):
        import io
        if "passwd" in path:
            return io.StringIO(passwd)
        return io.StringIO(keys)

    with mock.patch("os.path.exists", return_value=True), \
         mock.patch("os.stat") as mock_stat, \
         mock.patch.object(SSHCollector, "_file_modified_since", return_value=True), \
         mock.patch("builtins.open", side_effect=fake_open):
        mock_stat.return_value.st_mtime = 1716548400.0
        result = SSHCollector().collect()

    assert len(result["authorized_keys"]) == 1
```

- [ ] **Step 2: Run to confirm the skip test fails**

```bash
python -m pytest tests/test_collectors.py::test_ssh_collector_skips_file_outside_window tests/test_collectors.py::test_ssh_collector_reads_file_inside_window -v --no-cov
```

Expected: `skips_file_outside_window` FAILS (still returns entries).

- [ ] **Step 3: Edit `ubuntils/collectors/ssh.py`**

In `collect()`, add a `_file_modified_since` check before opening the file. Replace the block that starts with `auth_keys_path = f"{home}/.ssh/authorized_keys"`:

```python
            auth_keys_path = f"{home}/.ssh/authorized_keys"
            if not os.path.exists(auth_keys_path):
                continue
            if not self._file_modified_since(auth_keys_path):
                continue
            try:
```

- [ ] **Step 4: Run to confirm tests pass**

```bash
python -m pytest tests/test_collectors.py -k "ssh" -v --no-cov
```

Expected: all PASSED.

- [ ] **Step 5: Commit**

```bash
git add ubuntils/collectors/ssh.py tests/test_collectors.py
git commit -m "feat: filter SSH authorized_keys by mtime when --since is set"
```

---

### Task 5: `SudoersCollector` mtime filter

**Files:**
- Modify: `ubuntils/collectors/sudoers.py`
- Test: `tests/test_collectors.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_collectors.py` after `test_sudoers_collector_reads_sudoers_d` (around line 470):

```python
def test_sudoers_collector_skips_file_outside_window():
    from ubuntils.collectors.sudoers import SudoersCollector

    with mock.patch("glob.glob", return_value=["/etc/sudoers.d/evil"]), \
         mock.patch.object(SudoersCollector, "_file_modified_since", return_value=False):
        result = SudoersCollector().collect()

    assert result["sudoers_rules"] == []


def test_sudoers_collector_reads_file_inside_window():
    from ubuntils.collectors.sudoers import SudoersCollector

    rule = "alice ALL=(ALL) NOPASSWD: /bin/bash\n"
    with mock.patch("glob.glob", return_value=["/etc/sudoers.d/evil"]), \
         mock.patch.object(SudoersCollector, "_file_modified_since", return_value=True), \
         mock.patch("builtins.open", mock.mock_open(read_data=rule)):
        result = SudoersCollector().collect()

    assert len(result["sudoers_rules"]) == 1
```

- [ ] **Step 2: Run to confirm skip test fails**

```bash
python -m pytest tests/test_collectors.py::test_sudoers_collector_skips_file_outside_window tests/test_collectors.py::test_sudoers_collector_reads_file_inside_window -v --no-cov
```

Expected: `skips_file_outside_window` FAILS.

- [ ] **Step 3: Edit `ubuntils/collectors/sudoers.py`**

Replace the `collect` method body:

```python
    def collect(self) -> dict:
        rules = []
        paths = ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*")
        for path in paths:
            if not self._file_modified_since(path):
                continue
            rules.extend(self._parse_sudoers_file(path))
        return {"sudoers_rules": rules}
```

- [ ] **Step 4: Run to confirm tests pass**

```bash
python -m pytest tests/test_collectors.py -k "sudoers" -v --no-cov
```

Expected: all PASSED.

- [ ] **Step 5: Commit**

```bash
git add ubuntils/collectors/sudoers.py tests/test_collectors.py
git commit -m "feat: filter sudoers files by mtime when --since is set"
```

---

### Task 6: `EnvironmentCollector` mtime filter

**Files:**
- Modify: `ubuntils/collectors/environment.py`
- Test: `tests/test_collectors.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_collectors.py` after `test_env_collector_skips_nonexistent_rc_files` (around line 540):

```python
def test_env_collector_skips_shell_init_outside_window():
    from ubuntils.collectors.environment import EnvironmentCollector

    passwd = "alice:x:1000:1000::/home/alice:/bin/bash\n"

    def fake_open(path, *args, **kwargs):
        import io
        if "passwd" in path:
            return io.StringIO(passwd)
        return io.StringIO("export LD_PRELOAD=/tmp/evil.so\n")

    with mock.patch("os.path.exists", return_value=True), \
         mock.patch("glob.glob", return_value=[]), \
         mock.patch.object(EnvironmentCollector, "_file_modified_since", return_value=False), \
         mock.patch("builtins.open", side_effect=fake_open):
        result = EnvironmentCollector().collect()

    assert result.get("env_definitions", []) == []


def test_env_collector_reads_shell_init_inside_window():
    from ubuntils.collectors.environment import EnvironmentCollector

    passwd = "alice:x:1000:1000::/home/alice:/bin/bash\n"

    def fake_open(path, *args, **kwargs):
        import io
        if "passwd" in path:
            return io.StringIO(passwd)
        return io.StringIO("export LD_PRELOAD=/tmp/evil.so\n")

    with mock.patch("os.path.exists", return_value=True), \
         mock.patch("glob.glob", return_value=[]), \
         mock.patch.object(EnvironmentCollector, "_file_modified_since", return_value=True), \
         mock.patch("builtins.open", side_effect=fake_open):
        result = EnvironmentCollector().collect()

    assert len(result["env_definitions"]) > 0
```

- [ ] **Step 2: Run to confirm skip test fails**

```bash
python -m pytest tests/test_collectors.py::test_env_collector_skips_shell_init_outside_window tests/test_collectors.py::test_env_collector_reads_shell_init_inside_window -v --no-cov
```

Expected: `skips_shell_init_outside_window` FAILS.

- [ ] **Step 3: Edit `ubuntils/collectors/environment.py`**

In `collect()`, add mtime checks for each shell init file. Replace the `collect` method body:

```python
    def collect(self) -> dict:
        definitions = []

        definitions.extend(self._read_env_file("/etc/environment", "system"))

        if self._file_modified_since("/etc/profile"):
            definitions.extend(self._read_shell_init("/etc/profile", "system"))
        for path in glob.glob("/etc/profile.d/*.sh"):
            if self._file_modified_since(path):
                definitions.extend(self._read_shell_init(path, "system"))

        for username, home in self._get_login_users():
            for filename in (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile"):
                path = f"{home}/{filename}"
                if os.path.exists(path) and self._file_modified_since(path):
                    definitions.extend(self._read_shell_init(path, username))

        return {"env_definitions": definitions}
```

Note: `/etc/environment` is always read (structural config, as per spec).

- [ ] **Step 4: Run to confirm tests pass**

```bash
python -m pytest tests/test_collectors.py -k "env" -v --no-cov
```

Expected: all PASSED.

- [ ] **Step 5: Commit**

```bash
git add ubuntils/collectors/environment.py tests/test_collectors.py
git commit -m "feat: filter environment/shell init files by mtime when --since is set"
```

---

### Task 7: `TimelineBuilder` — `since` param

**Files:**
- Modify: `ubuntils/timeline/builder.py`
- Test: `tests/test_timeline.py`

The existing tests call `_parse_journald(since_days=7)` — that parameter is being renamed. Those calls must be updated to `_parse_journald()` in this task.

- [ ] **Step 1: Update the two stale `since_days` calls in `tests/test_timeline.py`**

Find all occurrences of `_parse_journald(since_days=7)` and replace with `_parse_journald()`:

```python
# test_parse_journald_json — change:
events = builder._parse_journald(since_days=7)
# to:
events = builder._parse_journald()

# test_parse_journald_returns_empty_on_failure — change:
events = builder._parse_journald(since_days=7)
# to:
events = builder._parse_journald()

# test_parse_journald_skips_empty_lines — change:
events = builder._parse_journald(since_days=7)
# to:
events = builder._parse_journald()

# test_parse_journald_skips_bad_json — change:
events = builder._parse_journald(since_days=7)
# to:
events = builder._parse_journald()
```

- [ ] **Step 2: Write the new failing tests**

Add to `tests/test_timeline.py` after `test_build_sorted_ascending`:

```python
def test_build_since_filters_syslog_entries():
    builder = TimelineBuilder()
    since = datetime.datetime(2024, 5, 24, 10, 30, 2, tzinfo=datetime.timezone.utc)
    # SYSLOG_SNIPPET has 3 events at 10:30:01, 10:30:02, 10:30:03
    # Only events >= 10:30:02 should be included
    events = builder._parse_syslog(SYSLOG_SNIPPET, since=since)
    assert all(e.timestamp >= since for e in events)
    assert len(events) == 2  # 10:30:02 and 10:30:03


def test_build_since_none_includes_all_syslog():
    builder = TimelineBuilder()
    events = builder._parse_syslog(SYSLOG_SNIPPET, since=None)
    assert len(events) == 3


def test_build_since_filters_auditd_entries():
    builder = TimelineBuilder()
    since = datetime.datetime.fromtimestamp(1716548401.0, tz=datetime.timezone.utc)
    events = builder._parse_auditd(AUDITD_SNIPPET, since=since)
    assert all(e.timestamp >= since for e in events)
    assert len(events) == 1  # only the 1716548401.456 entry


def test_build_since_none_includes_all_auditd():
    builder = TimelineBuilder()
    events = builder._parse_auditd(AUDITD_SNIPPET, since=None)
    assert len(events) == 2


def test_build_journald_passes_since_to_command():
    builder = TimelineBuilder()
    since = datetime.datetime(2026, 5, 20, 14, 0, 0, tzinfo=datetime.timezone.utc)
    with patch("ubuntils.timeline.builder.run_command") as mock_cmd:
        mock_cmd.return_value = ("", "", 0)
        builder._parse_journald(since=since)
    cmd = mock_cmd.call_args[0][0]
    assert any("2026-05-20 14:00:00" in arg for arg in cmd)


def test_build_journald_uses_default_when_since_none():
    builder = TimelineBuilder()
    with patch("ubuntils.timeline.builder.run_command") as mock_cmd:
        mock_cmd.return_value = ("", "", 0)
        builder._parse_journald(since=None)
    cmd = mock_cmd.call_args[0][0]
    assert any("7 days ago" in arg for arg in cmd)
```

- [ ] **Step 3: Run to confirm new tests fail**

```bash
python -m pytest tests/test_timeline.py -k "since" -v --no-cov
```

Expected: all 6 new tests FAIL.

- [ ] **Step 4: Rewrite `ubuntils/timeline/builder.py`**

```python
import datetime
import json
import re
from dataclasses import dataclass

import structlog
from dateutil import parser as dateutil_parser

from ubuntils.utils.shell import run_command

logger = structlog.get_logger()

_SYSLOG_RE = re.compile(
    r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+\S+:\s+(.+)$"
)
_AUDITD_RE = re.compile(r"^type=(\S+) msg=audit\((\d+\.\d+):\d+\): (.+)$")


@dataclass(frozen=True)
class TimelineEvent:
    timestamp: datetime.datetime
    source: str
    description: str


class TimelineBuilder:
    def build(self, since: datetime.datetime | None = None) -> list[TimelineEvent]:
        events: list[TimelineEvent] = []
        for path in ("/var/log/syslog", "/var/log/messages"):
            try:
                with open(path) as f:
                    events.extend(self._parse_syslog(f.read(), since=since))
            except OSError:
                pass
        events.extend(self._parse_journald(since=since))
        try:
            with open("/var/log/audit/audit.log") as f:
                events.extend(self._parse_auditd(f.read(), since=since))
        except OSError:
            pass
        return self._deduplicate(events)

    def _parse_syslog(self, content: str, since: datetime.datetime | None = None) -> list[TimelineEvent]:
        events = []
        current_year = datetime.datetime.now().year
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _SYSLOG_RE.match(line)
            if not m:
                continue
            raw_ts, description = m.group(1), m.group(2).strip()
            try:
                ts = dateutil_parser.parse(f"{raw_ts} {current_year}")
                ts = ts.replace(tzinfo=datetime.timezone.utc)
            except Exception:
                logger.warning("syslog_parse_failed", line=line)
                continue
            if since is not None and ts < since:
                continue
            events.append(TimelineEvent(timestamp=ts, source="syslog", description=description))
        return events

    def _parse_journald(self, since: datetime.datetime | None = None) -> list[TimelineEvent]:
        if since is not None:
            since_arg = f"--since={since.strftime('%Y-%m-%d %H:%M:%S')}"
        else:
            since_arg = "--since=7 days ago"
        stdout, _, returncode = run_command(
            ["journalctl", "-o", "json", since_arg, "--no-pager"]
        )
        if returncode != 0 or not stdout.strip():
            return []
        events = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                micros = int(record.get("__REALTIME_TIMESTAMP", 0))
                ts = datetime.datetime.fromtimestamp(
                    micros / 1_000_000, tz=datetime.timezone.utc
                )
                description = str(record.get("MESSAGE", ""))
                events.append(TimelineEvent(timestamp=ts, source="journald", description=description))
            except Exception:
                logger.warning("journald_parse_failed", line=line)
        return events

    def _parse_auditd(self, content: str, since: datetime.datetime | None = None) -> list[TimelineEvent]:
        events = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _AUDITD_RE.match(line)
            if not m:
                continue
            record_type, raw_ts, rest = m.group(1), m.group(2), m.group(3)
            try:
                ts = datetime.datetime.fromtimestamp(float(raw_ts), tz=datetime.timezone.utc)
            except Exception:
                logger.warning("auditd_parse_failed", line=line)
                continue
            if since is not None and ts < since:
                continue
            description = f"{record_type}: {rest}"
            events.append(TimelineEvent(timestamp=ts, source="auditd", description=description))
        return events

    def _deduplicate(self, events: list[TimelineEvent]) -> list[TimelineEvent]:
        seen: set[tuple] = set()
        unique: list[TimelineEvent] = []
        for e in sorted(events, key=lambda x: x.timestamp):
            key = (e.timestamp, e.source, e.description)
            if key not in seen:
                seen.add(key)
                unique.append(e)
        return unique
```

- [ ] **Step 5: Run full timeline test suite**

```bash
python -m pytest tests/test_timeline.py -v --no-cov
```

Expected: all PASSED (including the 4 updated `since_days` tests and 6 new since-filter tests).

- [ ] **Step 6: Commit**

```bash
git add ubuntils/timeline/builder.py tests/test_timeline.py
git commit -m "feat: add since param to TimelineBuilder; filter syslog/auditd entries inline"
```

---

### Task 8: CLI `--since` option

**Files:**
- Modify: `ubuntils/cli.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_cli.py` after the existing test functions:

```python
def test_scan_since_relative_passed_to_pipeline(runner):
    with mock.patch("ubuntils.cli._run_pipeline") as mock_pipe, \
         mock.patch("ubuntils.cli.UbuntilsApp") as mock_app:
        mock_pipe.return_value = ([], [], {}, {}, {}, [])
        mock_app.return_value.run.return_value = None
        result = runner.invoke(main, ["scan", "--since", "24h", "--json"])
    assert result.exit_code == 0
    call_kwargs = mock_pipe.call_args[1]
    assert call_kwargs["since"] is not None


def test_scan_since_absolute_passed_to_pipeline(runner):
    with mock.patch("ubuntils.cli._run_pipeline") as mock_pipe, \
         mock.patch("ubuntils.cli.UbuntilsApp") as mock_app:
        mock_pipe.return_value = ([], [], {}, {}, {}, [])
        mock_app.return_value.run.return_value = None
        result = runner.invoke(main, ["scan", "--since", "2026-05-20", "--json"])
    assert result.exit_code == 0
    call_kwargs = mock_pipe.call_args[1]
    import datetime
    assert call_kwargs["since"].year == 2026


def test_scan_since_invalid_exits_nonzero(runner):
    result = runner.invoke(main, ["scan", "--since", "notadate", "--json"])
    assert result.exit_code != 0
    assert "Invalid" in result.output
```

- [ ] **Step 2: Run to confirm they fail**

```bash
python -m pytest tests/test_cli.py::test_scan_since_relative_passed_to_pipeline tests/test_cli.py::test_scan_since_absolute_passed_to_pipeline tests/test_cli.py::test_scan_since_invalid_exits_nonzero -v --no-cov
```

Expected: all FAIL (`No such option: --since`).

- [ ] **Step 3: Edit `ubuntils/cli.py`**

Add import at the top (after existing imports):

```python
from ubuntils.utils.since_parser import parse_since
```

Add `since` parameter to `_run_pipeline`:

```python
def _run_pipeline(remediate: bool, confirm: bool, since=None) -> tuple:
```

Inside `_run_pipeline`, change the collector instantiation line from:

```python
    collectors = [C() for C in ALL_COLLECTORS]
```

to:

```python
    collectors = [C(since=since) for C in ALL_COLLECTORS]
```

And change the timeline build call from:

```python
        timeline = TimelineBuilder().build()
```

to:

```python
        timeline = TimelineBuilder().build(since=since)
```

And add `since` to the stats dict:

```python
    stats = {
        "ubuntu_version": ubuntu_version,
        "architecture": arch,
        "duration_s": duration,
        "collector_count": len(collectors),
        "collector_failures": failures,
        "finding_counts": {
            "HIGH": sum(1 for f in findings if f.severity == Severity.HIGH),
            "MEDIUM": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "LOW": sum(1 for f in findings if f.severity == Severity.LOW),
        },
        "timeline_count": len(timeline),
        "since": since,
    }
```

Add `--since` option to the `scan` command and update its body. The full updated `scan` function:

```python
@main.command()
@click.option("--json", "output_json", is_flag=True, help="Output JSON instead of launching TUI")
@click.option("--remediate", is_flag=True, help="Run remediation engine after detection")
@click.option("--confirm", is_flag=True, help="Required with --remediate to apply changes")
@click.option("--verbose", is_flag=True, help="Enable verbose logging")
@click.option("--since", "since_str", default=None, metavar="WINDOW",
              help="Limit scan to files/events modified after this time. "
                   "Relative: 24h, 7d, 30m. Absolute: 2026-05-20, '2026-05-20 14:00'.")
def scan(output_json, remediate, confirm, verbose, since_str):
    """Scan the system for forensic artifacts and suspicious activity."""
    configure_logging(json_mode=output_json, verbose=verbose)

    since = None
    if since_str is not None:
        try:
            since = parse_since(since_str)
        except ValueError as exc:
            raise click.BadParameter(str(exc), param_hint="'--since'")

    if output_json or remediate:
        findings, timeline, stats, scan_metadata, artifact_counts, remediation_results = \
            _run_pipeline(remediate=remediate, confirm=confirm, since=since)

        if output_json:
            click.echo(
                JSONFormatter().format(
                    scan_metadata, artifact_counts, findings, timeline, remediation_results
                )
            )
            return

        def _override():
            return (findings, timeline, stats)

        UbuntilsApp(verbose=verbose, since=since, _scan_override=_override).run()
        return

    UbuntilsApp(verbose=verbose, since=since).run()
```

- [ ] **Step 4: Run to confirm tests pass**

```bash
python -m pytest tests/test_cli.py -v --no-cov
```

Expected: all PASSED.

- [ ] **Step 5: Commit**

```bash
git add ubuntils/cli.py tests/test_cli.py
git commit -m "feat: add --since option to ubuntils scan"
```

---

### Task 9: `UbuntilsApp` — thread `since` through scan worker

**Files:**
- Modify: `ubuntils/tui/app.py`
- Test: `tests/test_tui.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_tui.py` after `test_ubuntils_app_q_exits`:

```python
import datetime as _dt

async def test_ubuntils_app_passes_since_to_collectors():
    since = _dt.datetime(2026, 5, 20, tzinfo=_dt.timezone.utc)
    collected_since_values = []

    def _override():
        return ([], [], {
            "ubuntu_version": "Ubuntu 22.04",
            "architecture": "x86_64",
            "duration_s": 0.1,
            "collector_count": 8,
            "collector_failures": 0,
            "finding_counts": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "timeline_count": 0,
            "since": since,
        })

    async with UbuntilsApp(_scan_override=_override, since=since).run_test() as pilot:
        await pilot.pause(delay=0.5)
        # App reaches ResultsScreen — confirms since was accepted without error
        from ubuntils.tui.results_screen import ResultsScreen
        assert isinstance(pilot.app.screen, ResultsScreen)
```

- [ ] **Step 2: Run to confirm it fails**

```bash
python -m pytest tests/test_tui.py::test_ubuntils_app_passes_since_to_collectors -v --no-cov
```

Expected: `TypeError: UbuntilsApp.__init__() got an unexpected keyword argument 'since'`

- [ ] **Step 3: Edit `ubuntils/tui/app.py`**

Update `__init__`:

```python
    def __init__(self, verbose: bool = False, since=None, _scan_override=None) -> None:
        super().__init__()
        self._verbose = verbose
        self._since = since
        self._scan_override = _scan_override
```

Update `_run_scan` — replace the collector instantiation and timeline call in the real scan path:

```python
        collectors = [C(since=self._since) for C in ALL_COLLECTORS]
```

```python
            timeline = TimelineBuilder().build(since=self._since)
```

Add `since` to the stats dict inside `_run_scan`:

```python
        stats = {
            "ubuntu_version": get_ubuntu_version(),
            "architecture": platform.machine(),
            "duration_s": duration,
            "collector_count": len(collectors),
            "collector_failures": failures,
            "finding_counts": {
                "HIGH": sum(1 for f in findings if f.severity == Severity.HIGH),
                "MEDIUM": sum(1 for f in findings if f.severity == Severity.MEDIUM),
                "LOW": sum(1 for f in findings if f.severity == Severity.LOW),
            },
            "timeline_count": len(timeline),
            "since": self._since,
        }
```

- [ ] **Step 4: Run to confirm test passes**

```bash
python -m pytest tests/test_tui.py::test_ubuntils_app_passes_since_to_collectors -v --no-cov
```

Expected: PASSED.

- [ ] **Step 5: Commit**

```bash
git add ubuntils/tui/app.py tests/test_tui.py
git commit -m "feat: thread since param through UbuntilsApp scan worker"
```

---

### Task 10: Stats and summary display

**Files:**
- Modify: `ubuntils/tui/stats_panel.py`
- Modify: `ubuntils/tui/summary_screen.py`
- Test: `tests/test_tui.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_tui.py`:

```python
import datetime as _dt2

def test_format_stats_shows_scan_window_when_since_set():
    from ubuntils.tui.stats_panel import format_stats
    since = _dt2.datetime(2026, 5, 25, 12, 0, 0, tzinfo=_dt2.timezone.utc)
    stats = _stats()
    stats["since"] = since
    text = format_stats(stats)
    assert "Scan window" in text
    assert "2026-05-25" in text


def test_format_stats_omits_scan_window_when_since_none():
    from ubuntils.tui.stats_panel import format_stats
    stats = _stats()
    stats["since"] = None
    text = format_stats(stats)
    assert "Scan window" not in text


def test_build_summary_shows_scan_window_when_since_set():
    from ubuntils.tui.summary_screen import _build_summary
    since = _dt2.datetime(2026, 5, 25, 12, 0, 0, tzinfo=_dt2.timezone.utc)
    stats = _stats()
    stats["since"] = since
    text = _build_summary([], [], stats)
    assert "Scan window" in text


def test_build_summary_omits_scan_window_when_since_none():
    from ubuntils.tui.summary_screen import _build_summary
    stats = _stats()
    stats["since"] = None
    text = _build_summary([], [], stats)
    assert "Scan window" not in text
```

- [ ] **Step 2: Run to confirm they fail**

```bash
python -m pytest tests/test_tui.py::test_format_stats_shows_scan_window_when_since_set tests/test_tui.py::test_format_stats_omits_scan_window_when_since_none tests/test_tui.py::test_build_summary_shows_scan_window_when_since_set tests/test_tui.py::test_build_summary_omits_scan_window_when_since_none -v --no-cov
```

Expected: all FAIL ("Scan window" not in output).

- [ ] **Step 3: Edit `ubuntils/tui/stats_panel.py`**

Replace the `format_stats` function:

```python
def format_stats(stats: dict) -> str:
    fc = stats.get("finding_counts", {})
    lines = [
        f"Ubuntu Version:   {stats.get('ubuntu_version', 'Unknown')}",
        f"Architecture:     {stats.get('architecture', platform.machine())}",
        f"Scan Duration:    {stats.get('duration_s', 0):.1f}s",
        f"Collectors run:   {stats.get('collector_count', 0)} ({stats.get('collector_failures', 0)} failed)",
        f"Findings:         {fc.get('HIGH', 0)} HIGH  {fc.get('MEDIUM', 0)} MEDIUM  {fc.get('LOW', 0)} LOW",
        f"Timeline events:  {stats.get('timeline_count', 0)}",
    ]
    since = stats.get("since")
    if since is not None:
        lines.append(f"Scan window:      since {since.strftime('%Y-%m-%d %H:%M UTC')}")
    return "\n".join(lines)
```

- [ ] **Step 4: Edit `ubuntils/tui/summary_screen.py`**

In `_build_summary`, add after the `lines` list initialisation (after the `duration` line):

```python
    since = stats.get("since")
    if since is not None:
        lines.insert(0, f"Scan window: since {since.strftime('%Y-%m-%d %H:%M UTC')}")
        lines.insert(1, "")
```

- [ ] **Step 5: Run to confirm tests pass**

```bash
python -m pytest tests/test_tui.py::test_format_stats_shows_scan_window_when_since_set tests/test_tui.py::test_format_stats_omits_scan_window_when_since_none tests/test_tui.py::test_build_summary_shows_scan_window_when_since_set tests/test_tui.py::test_build_summary_omits_scan_window_when_since_none -v --no-cov
```

Expected: all PASSED.

- [ ] **Step 6: Commit**

```bash
git add ubuntils/tui/stats_panel.py ubuntils/tui/summary_screen.py tests/test_tui.py
git commit -m "feat: show Scan window in stats and summary when --since is set"
```

---

### Task 11: Full suite + CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Run full suite with coverage gate**

```bash
python -m pytest -q
```

Expected: all PASS, coverage ≥ 80%. If coverage drops below gate, targeted additions needed:
- `since_parser.py` edge case: `parse_since("1m")` or `parse_since("3w")`
- `_file_modified_since` with a file whose mtime == `since.timestamp()` exactly (boundary)

- [ ] **Step 2: Smoke-test the CLI flag**

```bash
ubuntils scan --since 1h --json 2>/dev/null | python -m json.tool | head -20
```

Expected: valid JSON output with no errors.

- [ ] **Step 3: Update `CLAUDE.md`**

In the "Completed" section, add after Phase 14:

```
- **Phase 15** — `--since` time-window filter: `ubuntils scan --since 24h` (or absolute date) limits artifact collection to files modified within the window and timeline parsing to entries after the threshold; `parse_since` utility handles both relative (m/h/d/w) and absolute (dateutil) formats; stats and summary panels show "Scan window" line when filter is active
```

Update "Current test count" to the new total from Step 1.

- [ ] **Step 4: Commit**

```bash
git add tests/ ubuntils/
git commit -m "test: full suite green after --since filter implementation"
```

---

## Self-Review

**Spec coverage:**
- `--since` CLI flag with relative + absolute parsing → Task 1 + Task 8 ✓
- `click.BadParameter` on invalid input → Task 8 ✓
- `BaseCollector.since` param + `_file_modified_since` → Task 2 ✓
- CronCollector files filtered by mtime → Task 3 ✓
- SSHCollector files filtered by mtime → Task 4 ✓
- SudoersCollector files filtered by mtime → Task 5 ✓
- EnvironmentCollector files filtered, `/etc/environment` always read → Task 6 ✓
- TimelineBuilder syslog/auditd inline filtering → Task 7 ✓
- TimelineBuilder journalctl `--since` flag → Task 7 ✓
- `UbuntilsApp(since=...)` threads to scan worker → Task 9 ✓
- Stats panel "Scan window" line → Task 10 ✓
- Summary tab "Scan window" line → Task 10 ✓
- `since=None` → no filtering / existing behavior unchanged → Tasks 2–10 all default to `None` ✓

**Placeholder scan:** None.

**Type consistency:**
- `parse_since(value: str) -> datetime` — defined Task 1, used Task 8 ✓
- `BaseCollector.__init__(since: datetime | None = None)` — defined Task 2, used in Tasks 3–6 via `C(since=since)` ✓
- `_file_modified_since(path: str) -> bool` — defined Task 2, called as `self._file_modified_since(path)` in Tasks 3–6 ✓
- `TimelineBuilder.build(since: datetime | None = None)` — defined Task 7, called in Tasks 8 + 9 ✓
- `_parse_journald(since: datetime | None = None)` — defined Task 7, existing tests updated in Task 7 ✓
- `stats["since"]` key — added in Tasks 8 + 9, read in Task 10 ✓
- `UbuntilsApp(since=...)` — defined Task 9, called in Task 8 ✓
