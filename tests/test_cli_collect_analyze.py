import os
from click.testing import CliRunner
from ubuntils.cli import main


def test_collect_writes_a_bundle(tmp_path, monkeypatch):
    # Avoid sudo re-exec in tests.
    monkeypatch.setattr("ubuntils.cli._ensure_root", lambda: None)
    out = tmp_path / "b.tar.gz"
    runner = CliRunner()
    result = runner.invoke(main, ["collect", "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()
