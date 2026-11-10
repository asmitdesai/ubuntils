"""E13-S5: docs/writes.md lists everywhere ubuntils writes, and a scan writes nothing."""
import builtins
import os
import re

from tests import fixture_hosts as fh

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WRITES = open(os.path.join(_REPO, "docs", "writes.md")).read()


def _shipped(module_file, name):
    """The value a constant ships with (tests monkeypatch several of them)."""
    m = re.search(rf'^\s*{name} = "([^"]+)"', open(module_file).read(), re.M)
    assert m, f"{name} not found in {module_file}"
    return m.group(1)


def test_every_write_location_in_the_code_is_documented():
    from ubuntils import cli
    from ubuntils.integrations import wazuh
    from ubuntils.remediators import base, preserve
    for module, name in ((cli, "DEFAULT_BUNDLE_DIR"), (cli, "STAGING_DIR"),
                         (base, "BACKUP_BASE"), (preserve, "PRESERVE_BASE"),
                         (wazuh, "DEFAULT_WAZUH_LOG_PATH")):
        path = _shipped(module.__file__, name)
        assert path in WRITES, f"{path} is written but not listed in docs/writes.md"


def test_no_other_absolute_write_location_hides_in_the_code():
    # Any string constant naming a directory under /var/lib, /var/log or
    # /var/backups for ubuntils itself must be one of the documented ones.
    pattern = re.compile(r'(/var/(?:lib|log|backups)/ubuntils[\w./-]*)')
    found = set()
    for dirpath, _, files in os.walk(os.path.join(_REPO, "ubuntils")):
        for f in files:
            if f.endswith(".py"):
                found |= set(pattern.findall(open(os.path.join(dirpath, f)).read()))
    undocumented = {p for p in (f.rstrip("/.") for f in found) if p not in WRITES}
    assert not undocumented, f"undocumented write locations: {sorted(undocumented)}"


def test_a_scan_writes_nothing(tmp_path, monkeypatch):
    root = fh.build_host("lab", tmp_path / "host")
    writes = []
    real_open, real_os_open = builtins.open, os.open

    def spy_open(file, mode="r", *a, **k):
        if any(c in mode for c in "wax+"):
            writes.append(str(file))
        return real_open(file, mode, *a, **k)

    def spy_os_open(path, flags, *a, **k):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT):
            writes.append(str(path))
        return real_os_open(path, flags, *a, **k)

    for name in ("mkdir", "makedirs", "rename", "replace", "unlink", "rmdir"):
        real = getattr(os, name)
        monkeypatch.setattr(os, name, lambda *a, _n=name, _r=real, **k: (writes.append(
            f"{_n} {a[0]}"), _r(*a, **k))[1])
    monkeypatch.setattr(builtins, "open", spy_open)
    monkeypatch.setattr(os, "open", spy_os_open)
    with open(tmp_path / "probe", "w"):  # the spies must see a real write
        pass
    os.mkdir(tmp_path / "probe-dir")
    assert len(writes) == 2
    writes.clear()
    fh.scan(root)  # Wazuh off, no --output: a plain scan
    monkeypatch.undo()
    assert writes == [], f"a scan wrote: {writes}"
