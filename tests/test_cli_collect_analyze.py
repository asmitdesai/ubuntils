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


import json as _json


def test_analyze_bundle_emits_json(tmp_path, monkeypatch):
    monkeypatch.setattr("ubuntils.cli._ensure_root", lambda: None)
    # Build a bundle first.
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    out = tmp_path / "b.tar.gz"
    from ubuntils.bundle import write_bundle
    from ubuntils.collectors.source import LiveSource
    write_bundle(
        source=LiveSource(root=str(tmp_path)),
        files_to_capture=["/etc/passwd"],
        commands_to_capture=[],
        out_path=str(out),
        metadata={"hostname": "h", "ubuntu_version": "U", "tool_version": "2.0.0"},
    )

    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(out), "--json"])
    assert result.exit_code == 0, result.output
    report = _json.loads(result.output)
    assert report["scan_metadata"]["bundle_integrity"] == "ok"


def test_analyze_requires_bundle_or_root(monkeypatch):
    monkeypatch.setattr("ubuntils.cli._ensure_root", lambda: None)
    runner = CliRunner()
    result = runner.invoke(main, ["analyze"])
    assert result.exit_code != 0
    assert "bundle" in result.output.lower() or "root" in result.output.lower()


def test_analyze_rejects_both_bundle_and_root(tmp_path, monkeypatch):
    monkeypatch.setattr("ubuntils.cli._ensure_root", lambda: None)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    out = tmp_path / "b.tar.gz"
    from ubuntils.bundle import write_bundle
    from ubuntils.collectors.source import LiveSource
    write_bundle(
        source=LiveSource(root=str(tmp_path)),
        files_to_capture=["/etc/passwd"],
        commands_to_capture=[],
        out_path=str(out),
        metadata={"hostname": "h", "ubuntu_version": "U", "tool_version": "2.0.0"},
    )
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(out), "--root", str(tmp_path)])
    assert result.exit_code != 0


def test_analyze_bundle_with_custom_rules(tmp_path, monkeypatch):
    """--rules must load custom detection rules and thread them into the pipeline,
    mirroring scan's --rules handling."""
    monkeypatch.setattr("ubuntils.cli._ensure_root", lambda: None)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    (tmp_path / "etc" / "environment").write_text('FOO="totally_evil_marker"\n')
    out = tmp_path / "b.tar.gz"
    from ubuntils.bundle import write_bundle
    from ubuntils.collectors.source import LiveSource
    write_bundle(
        source=LiveSource(root=str(tmp_path)),
        files_to_capture=["/etc/passwd", "/etc/environment"],
        commands_to_capture=[],
        out_path=str(out),
        metadata={"hostname": "h", "ubuntu_version": "U", "tool_version": "2.0.0"},
    )

    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "rules:\n"
        "  - id: CUSTOM_EVIL_ENV\n"
        "    source: environment\n"
        "    match: substring\n"
        "    pattern: totally_evil_marker\n"
        "    severity: HIGH\n"
        "    title: Evil env var present\n"
        "    description: Found the evil marker\n"
    )

    runner = CliRunner()
    result = runner.invoke(
        main, ["analyze", str(out), "--json", "--rules", str(rules_file)]
    )
    assert result.exit_code == 0, result.output
    report = _json.loads(result.output)
    rule_ids = {f["rule_id"] for f in report["findings"]}
    assert "CUSTOM_EVIL_ENV" in rule_ids


def test_analyze_bundle_with_bad_rules_file_errors(tmp_path, monkeypatch):
    monkeypatch.setattr("ubuntils.cli._ensure_root", lambda: None)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    out = tmp_path / "b.tar.gz"
    from ubuntils.bundle import write_bundle
    from ubuntils.collectors.source import LiveSource
    write_bundle(
        source=LiveSource(root=str(tmp_path)),
        files_to_capture=["/etc/passwd"],
        commands_to_capture=[],
        out_path=str(out),
        metadata={"hostname": "h", "ubuntu_version": "U", "tool_version": "2.0.0"},
    )

    bad_rules = tmp_path / "bad_rules.yaml"
    bad_rules.write_text("not: [valid, - rules\n")

    runner = CliRunner()
    result = runner.invoke(
        main, ["analyze", str(out), "--json", "--rules", str(bad_rules)]
    )
    assert result.exit_code != 0
