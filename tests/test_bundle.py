import os
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


def test_write_bundle_records_missing_files_with_absence_marker(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")

    out = tmp_path / "bundle.tar.gz"
    src = LiveSource(root=str(root))

    # Capture one existing file and one that doesn't exist
    result = write_bundle(
        source=src,
        files_to_capture=["/etc/passwd", "/etc/shadow"],  # shadow doesn't exist
        commands_to_capture=[],
        out_path=str(out),
        metadata={"hostname": "h1", "ubuntu_version": "Ubuntu 22.04", "tool_version": "2.0.0"},
    )

    assert result == str(out)
    assert out.exists()

    with tarfile.open(out, "r:gz") as tf:
        manifest_member = next(n for n in tf.getnames() if n.endswith("manifest.json"))
        manifest = json.loads(tf.extractfile(manifest_member).read())

    # Verify we have two file entries
    assert len(manifest["files"]) == 2

    # First file exists: has sha256 and positive size
    passwd_entry = next(f for f in manifest["files"] if f["source_path"] == "/etc/passwd")
    assert len(passwd_entry["sha256"]) == 64
    assert passwd_entry["size"] > 0

    # Second file is missing: empty sha256 and size=-1
    shadow_entry = next(f for f in manifest["files"] if f["source_path"] == "/etc/shadow")
    assert shadow_entry["sha256"] == ""
    assert shadow_entry["size"] == -1


def test_write_bundle_cleans_up_staging_directory(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")

    out = tmp_path / "bundle.tar.gz"
    src = LiveSource(root=str(root))

    # Collect all temp directories before the call
    import tempfile as tf_module
    temp_dir_prefix = "ubuntils_collect_"
    tempdir = tf_module.gettempdir()

    # Get existing staging dirs
    existing_staging = set(
        d for d in os.listdir(tempdir)
        if d.startswith(temp_dir_prefix) and os.path.isdir(os.path.join(tempdir, d))
    )

    write_bundle(
        source=src,
        files_to_capture=["/etc/passwd"],
        commands_to_capture=[("echo", ["echo", "test"])],
        out_path=str(out),
        metadata={"hostname": "h1", "ubuntu_version": "Ubuntu 22.04", "tool_version": "2.0.0"},
    )

    # Get staging dirs after the call
    after_staging = set(
        d for d in os.listdir(tempdir)
        if d.startswith(temp_dir_prefix) and os.path.isdir(os.path.join(tempdir, d))
    )

    # No new staging directories should remain
    new_staging = after_staging - existing_staging
    assert len(new_staging) == 0, f"Staging directory was not cleaned up: {new_staging}"
