from ubuntils.bundle import write_bundle, read_bundle
from ubuntils.collectors.source import LiveSource
from ubuntils.cli import _run_pipeline


def test_collect_then_analyze_offline(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\nattacker:x:0:0::/home/a:/bin/bash\n"
    )
    (root / "etc" / "group").write_text("root:x:0:\n")
    (root / "etc" / "shadow").write_text("root:!:0:0:::::\nattacker:$6$x:0:0:::::\n")

    bundle = tmp_path / "b.tar.gz"
    write_bundle(
        source=LiveSource(root=str(root)),
        files_to_capture=["/etc/passwd", "/etc/group", "/etc/shadow"],
        commands_to_capture=[],
        out_path=str(bundle),
        metadata={"hostname": "victim", "ubuntu_version": "U", "tool_version": "2.0.0"},
    )

    source, info = read_bundle(str(bundle))
    findings, timeline, stats, meta, counts, _rem = _run_pipeline(
        source=source, remediate=False, confirm=False, bundle_info=info
    )

    assert meta["bundle_integrity"] == "ok"
    # The second UID-0 account should be flagged offline (USER_UID_ZERO rule).
    assert any(f.rule_id == "USER_UID_ZERO" for f in findings)
