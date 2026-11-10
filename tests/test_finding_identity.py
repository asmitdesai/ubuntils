"""E4-S3/E4-S4: finding_id, artifact_sha256 and host_id (QW-7, QW-8, R-10)."""
import hashlib
import json
import os

from tests import fixture_hosts as fh
from ubuntils.collectors.source import LiveSource
from ubuntils.detectors.identity import canonical_rule_id, finding_id
from ubuntils.formatters.json_formatter import JSONFormatter
from ubuntils.utils.host import get_host_id


def test_finding_id_is_stable_and_distinguishes_inputs():
    a = finding_id("CRON_TMP_PATH", "/etc/cron.d/x", "/tmp/a")
    assert a == finding_id("CRON_TMP_PATH", "/etc/cron.d/x", "/tmp/a") and len(a) == 32
    assert a != finding_id("CRON_TMP_PATH", "/etc/cron.d/x", "/tmp/b")
    # "ab"+"c" vs "a"+"bc": the separator keeps fields apart.
    assert finding_id("R", "ab", "c") != finding_id("R", "a", "bc")


def test_finding_id_survives_the_systemd_rule_rename():
    assert canonical_rule_id("SUSPICIOUS_SYSTEMD_TIMER") == "SUSPICIOUS_SYSTEMD_UNIT"
    assert finding_id("SUSPICIOUS_SYSTEMD_TIMER", "/u", "x") == \
        finding_id("SUSPICIOUS_SYSTEMD_UNIT", "/u", "x")


def test_two_scans_of_the_same_host_give_the_same_ids(tmp_path):
    root = fh.build_host("lab", tmp_path / "h")
    ids = [sorted(f.finding_id for f in fh.scan(root).findings) for _ in range(2)]
    assert ids[0] == ids[1] and len(ids[0]) > 5 and all(ids[0])


def test_flagged_files_are_hashed_through_the_source(tmp_path):
    root = fh.build_host("lab", tmp_path / "h")
    findings = fh.scan(root).findings
    cron = next(f for f in findings if f.artifact_path == "/etc/cron.d/ubuntils-lab")
    content = open(os.path.join(root, "etc/cron.d/ubuntils-lab"), "rb").read()
    assert cron.artifact_sha256 == hashlib.sha256(content).hexdigest()
    # Package names and /etc/passwd lines with no file of their own: None or a real hash.
    for f in findings:
        assert f.artifact_sha256 is None or len(f.artifact_sha256) == 64


def test_hashing_refuses_fifos_big_files_and_missing_paths(tmp_path):
    os.mkfifo(tmp_path / "fifo")
    (tmp_path / "big").write_bytes(b"x" * 2048)
    (tmp_path / "small").write_bytes(b"abc")
    src = LiveSource(root=str(tmp_path), offline=True)
    assert src.sha256_file("/fifo") is None
    assert src.sha256_file("/big", max_bytes=1024) is None
    assert src.sha256_file("/missing") is None
    assert src.sha256_file("/small") == hashlib.sha256(b"abc").hexdigest()
    os.mkdir(tmp_path / "dir")
    assert src.sha256_file("/dir") is None


def test_host_id_is_a_salted_hash_never_the_machine_id(tmp_path):
    root = fh.build(tmp_path / "h", {"/etc/machine-id": "0123456789abcdef0123456789abcdef\n"})
    host_id = get_host_id(fh.fixture_source(root))
    assert len(host_id) == 32 and "0123456789abcdef" not in host_id
    assert host_id == get_host_id(fh.fixture_source(root))
    empty = fh.build(tmp_path / "e", {"/etc/hostname": "x\n"})
    assert get_host_id(fh.fixture_source(empty)) == ""


def test_report_carries_the_new_fields(tmp_path):
    files = dict(fh.LAB)
    files["/etc/machine-id"] = "0123456789abcdef0123456789abcdef\n"
    r = fh.scan(fh.build(tmp_path / "h", files))
    rep = json.loads(JSONFormatter().format(r.scan_metadata, r.artifact_counts, r.findings,
                                            r.timeline, r.remediation_results))
    assert len(rep["scan_metadata"]["host_id"]) == 32
    assert all(set(f) >= {"finding_id", "artifact_sha256"} for f in rep["findings"])


def test_wazuh_line_carries_finding_id_and_hash(tmp_path):
    from ubuntils.integrations.wazuh import finding_line
    f = next(f for f in fh.scan(fh.build_host("lab", tmp_path / "h")).findings
             if f.artifact_path == "/etc/cron.d/ubuntils-lab")
    line = json.loads(finding_line(f, "h"))
    assert line["finding_id"] == f.finding_id and line["artifact_sha256"] == f.artifact_sha256


def test_a_file_larger_than_its_reported_size_is_not_hashed(tmp_path, monkeypatch):
    # /proc and some FUSE files report st_size 0 but return data; the cap is
    # enforced on what is actually read, not on what fstat claims.
    from ubuntils.collectors import source as src_mod
    (tmp_path / "f").write_bytes(b"x" * 4096)
    real_fstat = os.fstat

    def size_zero(fd):
        st = real_fstat(fd)
        return os.stat_result(tuple(st[:6]) + (0,) + tuple(st[7:]))

    monkeypatch.setattr(src_mod.os, "fstat", size_zero)
    assert LiveSource(root=str(tmp_path), offline=True).sha256_file("/f", max_bytes=1024) is None


def test_a_read_error_while_hashing_gives_none(tmp_path, monkeypatch):
    from ubuntils.collectors import source as src_mod
    (tmp_path / "f").write_bytes(b"abc")

    def eio(fd, n):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(src_mod.os, "read", eio)
    assert LiveSource(root=str(tmp_path), offline=True).sha256_file("/f") is None


def test_sources_that_cannot_hash_say_none():
    from ubuntils.collectors.source import ArtifactSource

    class Minimal(ArtifactSource):
        def read_text(self, p): return ""
        def read_bytes(self, p): return b""
        def exists(self, p): return False
        def lstat(self, p): raise OSError
        def glob(self, p): return []
        def readlink(self, p): raise OSError
        def run(self, n, a, timeout=30): return "", "", -1

    assert Minimal().sha256_file("/etc/passwd") is None


def test_bundle_source_hashes_the_collected_copy(tmp_path):
    from ubuntils import cli
    from ubuntils.bundle import read_bundle
    from ubuntils.bundle.writer import write_bundle
    root = fh.build_host("lab", tmp_path / "h")
    out = write_bundle(source=fh.fixture_source(root), files_to_capture=cli.COLLECT_FILES,
                       commands_to_capture=[], out_path=str(tmp_path / "b.tar.gz"),
                       metadata={"hostname": "h"})
    src, _ = read_bundle(out)
    try:
        expected = hashlib.sha256(open(os.path.join(root, "etc/passwd"), "rb").read()).hexdigest()
        assert src.sha256_file("/etc/passwd") == expected
        assert src.sha256_file("/etc/not-collected") is None
    finally:
        src.cleanup()
