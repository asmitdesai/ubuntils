import os
from ubuntils.collectors.source import LiveSource


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
