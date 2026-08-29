from ubuntils.bundle.manifest import Manifest, FileEntry, CommandEntry


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
