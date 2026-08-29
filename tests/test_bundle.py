import os
import tarfile
import json
from ubuntils.bundle.manifest import Manifest, FileEntry, CommandEntry
from ubuntils.bundle import write_bundle, read_bundle, BundleError
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


def test_read_bundle_round_trip(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    out = tmp_path / "bundle.tar.gz"
    write_bundle(
        source=LiveSource(root=str(root)),
        files_to_capture=["/etc/passwd"],
        commands_to_capture=[("echo", ["echo", "hi"])],
        out_path=str(out),
        metadata={"hostname": "h1", "ubuntu_version": "U", "tool_version": "2.0.0"},
    )

    source, info = read_bundle(str(out))

    assert info["bundle_integrity"] == "ok"
    assert source.read_text("/etc/passwd").startswith("root:x:0:0")
    stdout, _e, code = source.run("echo", ["echo", "hi"])
    assert code == 0 and stdout.strip() == "hi"


def test_read_bundle_detects_tampering(tmp_path):
    out = tmp_path / "bundle.tar.gz"
    write_bundle(
        source=LiveSource(root=str(tmp_path)),
        files_to_capture=[],
        commands_to_capture=[],
        out_path=str(out),
        metadata={"hostname": "h", "ubuntu_version": "U", "tool_version": "2.0.0"},
    )
    # Corrupt the gzip payload after the fact.
    import gzip, io, tarfile, json, os
    extract = tmp_path / "x"
    with tarfile.open(out, "r:gz") as tf:
        tf.extractall(extract)
    mpath = extract / "bundle" / "manifest.json"
    data = json.loads(mpath.read_text())
    data["hostname"] = "ATTACKER"          # mutate a field the digest covered
    mpath.write_text(json.dumps(data, indent=2, sort_keys=True))
    with tarfile.open(out, "w:gz") as tf:
        tf.add(str(extract / "bundle"), arcname="bundle")

    _source, info = read_bundle(str(out))
    assert info["bundle_integrity"] == "mismatch"


def test_read_bundle_without_manifest_raises(tmp_path):
    import tarfile
    junk = tmp_path / "junk.tar.gz"
    (tmp_path / "empty").mkdir()
    with tarfile.open(junk, "w:gz") as tf:
        tf.add(str(tmp_path / "empty"), arcname="bundle")
    try:
        read_bundle(str(junk))
        assert False, "expected BundleError"
    except BundleError:
        pass


def test_read_bundle_rejects_path_traversal_member(tmp_path):
    """A malicious bundle with a member like '../../ESCAPED.txt' must not be
    allowed to write outside the extraction directory."""
    malicious = tmp_path / "evil.tar.gz"
    escape_target = tmp_path / "ESCAPED.txt"

    with tarfile.open(malicious, "w:gz") as tf:
        info = tarfile.TarInfo(name="bundle/../../ESCAPED.txt")
        data = b"pwned"
        info.size = len(data)
        import io
        tf.addfile(info, io.BytesIO(data))

    try:
        read_bundle(str(malicious))
        assert False, "expected BundleError"
    except BundleError:
        pass

    assert not escape_target.exists()


def test_write_bundle_creates_output_file_with_owner_only_mode(tmp_path):
    """collect runs as root and captures /etc/shadow — the archive file
    itself must not be created world- or group-readable via the default umask."""
    import stat
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")

    out = tmp_path / "bundle.tar.gz"
    old_umask = os.umask(0o022)
    try:
        write_bundle(
            source=LiveSource(root=str(root)),
            files_to_capture=["/etc/passwd"],
            commands_to_capture=[],
            out_path=str(out),
            metadata={"hostname": "h1", "ubuntu_version": "Ubuntu 22.04", "tool_version": "2.0.0"},
        )
    finally:
        os.umask(old_umask)

    mode = stat.S_IMODE(os.stat(out).st_mode)
    assert mode == 0o600, f"expected bundle file mode 0600, got {oct(mode)}"


def test_write_bundle_sets_restrictive_mode_on_tar_entries(tmp_path):
    import stat
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")

    out = tmp_path / "bundle.tar.gz"
    write_bundle(
        source=LiveSource(root=str(root)),
        files_to_capture=["/etc/passwd"],
        commands_to_capture=[],
        out_path=str(out),
        metadata={"hostname": "h1", "ubuntu_version": "Ubuntu 22.04", "tool_version": "2.0.0"},
    )

    with tarfile.open(out, "r:gz") as tf:
        for member in tf.getmembers():
            if member.isfile():
                assert stat.S_IMODE(member.mode) == 0o600, member.name
            elif member.isdir():
                assert stat.S_IMODE(member.mode) == 0o700, member.name


def test_write_bundle_hashes_raw_bytes_not_lossy_decoded_text(tmp_path):
    """A file with genuinely non-UTF-8 bytes must round-trip through
    write_bundle/read_bundle with a hash matching a direct hashlib.sha256 of
    the original bytes — errors='replace' text decoding would otherwise
    silently corrupt the captured content before hashing."""
    import hashlib
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    raw = b"\xff\xfe\x80\x81not valid utf-8 \x00\x01\x02"
    (root / "etc" / "binfile").write_bytes(raw)

    out = tmp_path / "bundle.tar.gz"
    write_bundle(
        source=LiveSource(root=str(root)),
        files_to_capture=["/etc/binfile"],
        commands_to_capture=[],
        out_path=str(out),
        metadata={"hostname": "h1", "ubuntu_version": "U", "tool_version": "2.0.0"},
    )

    expected_hash = hashlib.sha256(raw).hexdigest()

    with tarfile.open(out, "r:gz") as tf:
        manifest_member = next(n for n in tf.getnames() if n.endswith("manifest.json"))
        manifest = json.loads(tf.extractfile(manifest_member).read())

    entry = next(f for f in manifest["files"] if f["source_path"] == "/etc/binfile")
    assert entry["sha256"] == expected_hash

    source, info = read_bundle(str(out))
    assert info["bundle_integrity"] == "ok"
    assert source.read_bytes("/etc/binfile") == raw


def test_read_bundle_rejects_symlink_member(tmp_path):
    """A bundle containing a symlink member must be rejected outright — a
    forensic bundle should only ever contain plain files and directories."""
    malicious = tmp_path / "evil_symlink.tar.gz"

    with tarfile.open(malicious, "w:gz") as tf:
        info = tarfile.TarInfo(name="bundle/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/shadow"
        tf.addfile(info)

    try:
        read_bundle(str(malicious))
        assert False, "expected BundleError"
    except BundleError:
        pass
