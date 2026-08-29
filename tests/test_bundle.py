import tarfile
import json
from ubuntils.bundle.manifest import Manifest, FileEntry, CommandEntry
from ubuntils.bundle import write_bundle
from ubuntils.collectors.source import LiveSource


def _sample_manifest():
    return Manifest(
        run_id="11111111-1111-1111-1111-111111111111",
        host_id="abc",
        hostname="host1",
        ubuntu_version="Ubuntu 22.04.3 LTS",
        collected_at_utc_start="2026-07-01T00:00:00+00:00",
        collected_at_utc_end="2026-07-01T00:00:05+00:00",
        tool_version="2.0.0",
        files=[FileEntry("/etc/passwd", "files/etc/passwd", "deadbeef", 42, 1.0, 2.0)],
        commands=[CommandEntry("ss", ["ss", "-tlnp"], "commands/ss.txt", "cafef00d", 0)],
    )


def test_manifest_to_dict_round_trips_fields():
    m = _sample_manifest()
    d = m.to_dict()
    assert d["run_id"] == "11111111-1111-1111-1111-111111111111"
    assert d["files"][0]["source_path"] == "/etc/passwd"
    assert d["commands"][0]["name"] == "ss"


def test_manifest_sha256_is_stable_and_order_independent():
    m1 = _sample_manifest()
    m2 = _sample_manifest()
    assert m1.manifest_sha256() == m2.manifest_sha256()
    assert len(m1.manifest_sha256()) == 64


def test_write_bundle_captures_files_and_commands(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")

    out = tmp_path / "bundle.tar.gz"
    src = LiveSource(root=str(root))

    result = write_bundle(
        source=src,
        files_to_capture=["/etc/passwd"],
        commands_to_capture=[("echo", ["echo", "listening"])],
        out_path=str(out),
        metadata={"hostname": "h1", "ubuntu_version": "Ubuntu 22.04", "tool_version": "2.0.0"},
    )

    assert result == str(out)
    assert out.exists()

    with tarfile.open(out, "r:gz") as tf:
        names = tf.getnames()
        assert any(n.endswith("manifest.json") for n in names)
        assert any("files/etc/passwd" in n for n in names)
        assert any("commands/echo" in n for n in names)
        manifest_member = next(n for n in names if n.endswith("manifest.json"))
        manifest = json.loads(tf.extractfile(manifest_member).read())

    assert manifest["bundle_sha256"]
    assert manifest["files"][0]["source_path"] == "/etc/passwd"
    assert len(manifest["files"][0]["sha256"]) == 64
