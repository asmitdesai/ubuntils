import os
from ubuntils.collectors.source import LiveSource, BundleSource, SourceContainmentError


def test_livesource_reads_relative_to_root(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")

    src = LiveSource(root=str(tmp_path))

    assert src.exists("/etc/passwd") is True
    assert src.read_text("/etc/passwd").startswith("root:x:0:0")


def test_livesource_missing_file_reports_absent(tmp_path):
    src = LiveSource(root=str(tmp_path))
    assert src.exists("/etc/passwd") is False


def test_livesource_glob_is_root_relative(tmp_path):
    d = tmp_path / "etc" / "cron.d"
    d.mkdir(parents=True)
    (d / "job1").write_text("* * * * * root echo hi\n")

    src = LiveSource(root=str(tmp_path))
    matches = src.glob("/etc/cron.d/*")

    assert matches == ["/etc/cron.d/job1"]


def test_livesource_run_executes_command():
    src = LiveSource(root="/")
    stdout, stderr, code = src.run("echo", ["echo", "hello"])
    assert code == 0
    assert stdout.strip() == "hello"


def test_bundlesource_reads_captured_file(tmp_path):
    files = tmp_path / "files"
    (files / "etc").mkdir(parents=True)
    (files / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")

    src = BundleSource(root_dir=str(files), command_index={})

    assert src.exists("/etc/passwd") is True
    assert src.read_text("/etc/passwd").startswith("root:x:0:0")


def test_bundlesource_replays_captured_command(tmp_path):
    cmds = tmp_path / "commands"
    cmds.mkdir()
    (cmds / "ss.txt").write_text("LISTEN 0 128 0.0.0.0:22\n")

    src = BundleSource(root_dir=str(tmp_path / "files"),
                       command_index={"ss": str(cmds / "ss.txt")})

    stdout, stderr, code = src.run("ss", ["ss", "-tlnp"])
    assert code == 0
    assert "0.0.0.0:22" in stdout


def test_bundlesource_unknown_command_returns_skip(tmp_path):
    src = BundleSource(root_dir=str(tmp_path / "files"), command_index={})
    stdout, stderr, code = src.run("ss", ["ss", "-tlnp"])
    assert code == -1
    assert stdout == ""
    assert "not captured" in stderr


def test_livesource_read_bytes_returns_raw_bytes(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "bin").write_bytes(b"\xff\xfe\x00binary")

    src = LiveSource(root=str(tmp_path))
    assert src.read_bytes("/etc/bin") == b"\xff\xfe\x00binary"


def test_bundlesource_read_bytes_returns_raw_bytes(tmp_path):
    files = tmp_path / "files"
    (files / "etc").mkdir(parents=True)
    (files / "etc" / "bin").write_bytes(b"\x80\x81binary")

    src = BundleSource(root_dir=str(files), command_index={})
    assert src.read_bytes("/etc/bin") == b"\x80\x81binary"


def test_livesource_offline_never_executes_command():
    """analyze --root sets offline=True — run() must never actually shell out,
    it just reports command execution as disabled."""
    src = LiveSource(root="/", offline=True)
    stdout, stderr, code = src.run("echo", ["echo", "hello"])
    assert code == -1
    assert stdout == ""
    assert "offline" in stderr


def test_livesource_root_mode_blocks_symlink_escape(tmp_path):
    """A --root mounted-image symlink pointing outside the image (e.g.
    etc/passwd -> ../../../../etc/shadow) must not let analyze read the
    analyst's real host file under the image's identity."""
    image = tmp_path / "image"
    (image / "etc").mkdir(parents=True)

    outside_secret = tmp_path / "outside_secret.txt"
    outside_secret.write_text("ANALYST HOST SECRET\n")

    # Symlink inside the image that escapes to a file outside the image root.
    escape_link = image / "etc" / "passwd"
    os.symlink(os.path.relpath(outside_secret, image / "etc"), escape_link)

    src = LiveSource(root=str(image))

    assert src.exists("/etc/passwd") is False
    try:
        src.read_text("/etc/passwd")
        assert False, "expected SourceContainmentError"
    except SourceContainmentError:
        pass


def test_livesource_live_root_skips_containment_check(tmp_path):
    """root='/' is the genuinely live case — there's no 'escape' concept when
    the whole filesystem is fair game, so the containment check must not
    change behavior there."""
    src = LiveSource(root="/")
    stdout, _stderr, code = src.run("echo", ["echo", "hi"])
    assert code == 0
