from ubuntils.bundle import write_bundle, read_bundle
from ubuntils.collectors.source import LiveSource
from ubuntils.cli import _run_pipeline
from ubuntils.utils.baseline import Baseline


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


def test_collect_then_analyze_offline_with_timeline_correlation_and_baseline(tmp_path):
    """End-to-end: a bundle capturing a UID-0 backdoor account AND a syslog
    line that correlates to it, analyzed with a baseline that does NOT match
    the UID-0 finding (so it survives baseline filtering). Proves the
    Task 2/5/6/7 combination — bundle analysis, correlation, and baseline
    suppression — actually compose together end-to-end."""
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\nghost:x:0:0::/home/ghost:/bin/bash\n"
    )
    (root / "etc" / "group").write_text("root:x:0:\n")
    (root / "etc" / "shadow").write_text("root:!:0:0:::::\nghost:$6$x:0:0:::::\n")
    (root / "var" / "log").mkdir(parents=True)
    # "passwd" is the /etc/passwd basename (correlator path token) and also
    # matches USER_UID_ZERO's rule keywords ("useradd"/"passwd"/"groupadd").
    (root / "var" / "log" / "syslog").write_text(
        "Aug 30 12:00:00 victim useradd[123]: new account 'ghost' created "
        "uid=0 in passwd file\n"
    )

    bundle = tmp_path / "b.tar.gz"
    write_bundle(
        source=LiveSource(root=str(root)),
        files_to_capture=["/etc/passwd", "/etc/group", "/etc/shadow", "/var/log/syslog"],
        commands_to_capture=[],
        out_path=str(bundle),
        metadata={"hostname": "victim", "ubuntu_version": "U", "tool_version": "2.0.0"},
    )

    # Baseline matches a different rule entirely, so the UID-0 finding survives.
    baseline = Baseline(entries=[{"rule_id": "SSH_UNAUTHORIZED_KEY", "fingerprint": "unrelated"}])

    source, info = read_bundle(str(bundle))
    findings, timeline, stats, meta, counts, _rem = _run_pipeline(
        source=source, remediate=False, confirm=False, bundle_info=info, baseline=baseline,
    )

    assert timeline != []
    uid_zero = next(f for f in findings if f.rule_id == "USER_UID_ZERO")
    assert uid_zero.related_events != []
    assert "timeline_corroboration" in [s["name"] for s in uid_zero.signals]
