"""QW-12 / E5-S4: bundles are staged in a private directory, never left behind."""
import os
import stat

import pytest

from tests import fixture_hosts as fh
from ubuntils import cli
from ubuntils.bundle import read_bundle
from ubuntils.bundle.writer import write_bundle

META = {"hostname": "h", "ubuntu_version": "24.04", "tool_version": "x"}


def _src(tmp_path):
    return fh.fixture_source(fh.build_host("lab", tmp_path / "host"))


def test_staging_happens_in_the_given_private_directory_and_is_removed(tmp_path, monkeypatch):
    staging = tmp_path / "var" / "lib" / "ubuntils" / "staging"
    seen = []
    real_mkdtemp = __import__("tempfile").mkdtemp

    def spy(*a, **k):
        d = real_mkdtemp(*a, **k)
        seen.append(d)
        return d

    monkeypatch.setattr("ubuntils.bundle.writer.tempfile.mkdtemp", spy)
    out = write_bundle(source=_src(tmp_path), files_to_capture=cli.COLLECT_FILES,
                       commands_to_capture=[], out_path=str(tmp_path / "b.tar.gz"),
                       metadata=META, staging_dir=str(staging))
    assert seen and os.path.dirname(seen[0]) == str(staging)
    assert stat.S_IMODE(os.stat(staging).st_mode) == 0o700
    assert os.listdir(staging) == []  # nothing left behind
    _, info = read_bundle(out)
    assert info["bundle_integrity"] == "ok"


def test_a_planted_symlink_staging_dir_is_refused_and_no_bundle_is_left(tmp_path):
    os.makedirs(tmp_path / "elsewhere")
    os.symlink(tmp_path / "elsewhere", tmp_path / "staging")
    out = tmp_path / "b.tar.gz"
    with pytest.raises(OSError, match="refusing"):
        write_bundle(source=_src(tmp_path), files_to_capture=cli.COLLECT_FILES,
                     commands_to_capture=[], out_path=str(out), metadata=META,
                     staging_dir=str(tmp_path / "staging"))
    assert not out.exists() and os.listdir(tmp_path / "elsewhere") == []


def test_interrupted_collection_leaves_no_bundle_and_no_staging(tmp_path):
    src = _src(tmp_path)

    def interrupted(path):
        raise KeyboardInterrupt

    src.read_bytes = interrupted
    staging = tmp_path / "staging"
    out = tmp_path / "b.tar.gz"
    with pytest.raises(KeyboardInterrupt):
        write_bundle(source=src, files_to_capture=["/etc/passwd"], commands_to_capture=[],
                     out_path=str(out), metadata=META, staging_dir=str(staging))
    assert not out.exists()          # no partial bundle that could pass for a real one
    assert os.listdir(staging) == []


def test_collect_stages_under_var_lib_ubuntils():
    # conftest points STAGING_DIR at a temp dir for every test; check the
    # value the module ships with.
    import re
    shipped = re.search(r'^STAGING_DIR = "([^"]+)"', open(cli.__file__).read(), re.M).group(1)
    assert shipped == "/var/lib/ubuntils/staging"
    assert os.path.dirname(shipped) == os.path.dirname(cli.DEFAULT_BUNDLE_DIR)
