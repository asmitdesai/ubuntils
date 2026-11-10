"""The CI measurement tools must judge correctly: a gate that can't fail is worse than none."""
import importlib.util
import json
import os

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(rel, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lab = _load("tools/lab/check.py", "lab_check")

PLANT_LOG = """Planting (rule it should trip → artifact):
  USER_UID_ZERO                creating locked, nologin UID-0 alias ubuntils-lab-root
  CRON_TMP_PATH                /etc/cron.d/ubuntils-lab (never fires)
  SSH_UNAUTHORIZED_KEY         key with command= option in authorized_keys
  SSH_UNAUTHORIZED_KEY         key hidden in authorized_keys2
  KERNEL_MODULE_SUSPICIOUS     loaded the harmless 'dummy' network module
warning: not planting KERNEL_MODULE_SUSPICIOUS: no module support

Not planted on this host (expect no finding for these):
  KERNEL_MODULE_SUSPICIOUS     no module support

Done. Not planted on purpose:
  PROCESS_SUSPICIOUS_CONNECTION  needs a real outbound connection
"""


def _f(rule, path, raw="", sev="HIGH"):
    return {"rule_id": rule, "artifact_path": path, "raw_value": raw, "description": "",
            "severity": sev}


def test_lab_parse_separates_planted_from_skipped_and_ignores_the_trailer():
    planted, skipped = lab.parse_plant_log(PLANT_LOG)
    assert [r for r, _ in planted] == ["USER_UID_ZERO", "CRON_TMP_PATH", "SSH_UNAUTHORIZED_KEY",
                                       "SSH_UNAUTHORIZED_KEY", "KERNEL_MODULE_SUSPICIOUS"]
    assert skipped == [("KERNEL_MODULE_SUSPICIOUS", "no module support")]


def test_lab_one_finding_cannot_satisfy_two_artifacts_of_the_same_rule():
    planted, skipped = lab.parse_plant_log(PLANT_LOG)
    findings = [_f("USER_UID_ZERO", "/etc/passwd", "ubuntils-lab-root:x:0:0"),
                _f("CRON_TMP_PATH", "/etc/cron.d/ubuntils-lab"),
                _f("SSH_UNAUTHORIZED_KEY", "/home/ubuntils-lab/.ssh/authorized_keys2")]
    rows = lab.evaluate(planted, skipped, findings)
    by = {(r["rule"], r["artifact"]): r["flagged"] for r in rows}
    assert by[("SSH_UNAUTHORIZED_KEY", "key hidden in authorized_keys2")] is True
    assert by[("SSH_UNAUTHORIZED_KEY", "key with command= option in authorized_keys")] is False
    assert all(r["rule"] != "KERNEL_MODULE_SUSPICIOUS" for r in rows)  # skipped, not missed


def test_lab_gate_fails_on_a_miss_and_passes_when_everything_is_flagged(tmp_path):
    log = tmp_path / "plant.txt"
    log.write_text(PLANT_LOG)
    report = tmp_path / "r.json"
    findings = [_f("USER_UID_ZERO", "/etc/passwd", "ubuntils-lab-root:x:0:0"),
                _f("CRON_TMP_PATH", "/etc/cron.d/ubuntils-lab"),
                _f("SSH_UNAUTHORIZED_KEY", "/home/ubuntils-lab/.ssh/authorized_keys2")]
    report.write_text(json.dumps({"findings": findings}))
    assert lab.main([str(log), str(report)]) == 1
    findings.append(_f("SSH_UNAUTHORIZED_KEY", "/home/ubuntils-lab/.ssh/authorized_keys"))
    report.write_text(json.dumps({"findings": findings}))
    assert lab.main([str(log), str(report)]) == 0


def test_lab_renamed_systemd_rule_still_counts():
    planted = [("SUSPICIOUS_SYSTEMD_TIMER", "drop-in override piping curl into bash (not enabled)")]
    rows = lab.evaluate(planted, [], [_f("SUSPICIOUS_SYSTEMD_UNIT", "/etc/systemd/system/x.service.d/o.conf")])
    assert rows[0]["flagged"]


def test_lab_bad_input_is_an_error_not_a_pass(tmp_path):
    log = tmp_path / "plant.txt"
    log.write_text("nothing here\n")
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"findings": []}))
    assert lab.main([str(log), str(report)]) == 2
    assert lab.main([str(log), str(tmp_path / "missing.json")]) == 2


def test_lab_checker_knows_every_artifact_the_lab_plants():
    script = open(os.path.join(_REPO, "tools", "lab", "seed-lab.sh")).read()
    import re
    lines = re.findall(r'^\s*say ([A-Z_]+) "([^"]*)"', script, re.MULTILINE)
    for rule, detail in lines:
        assert lab._artifact_for(rule, detail.replace("$LAB_ROOT_USER", "ubuntils-lab-root")) \
            is not None, (rule, detail)


hh = _load("tools/ci/hh_gate.py", "hh_gate")
timings = _load("tools/ci/timings.py", "timings")


def _hh(tmp_path, baseline, rows):
    (tmp_path / "summary.json").write_text(json.dumps({"baselines": baseline, "results": rows}))
    return str(tmp_path)


def test_hh_gate_passes_only_when_every_trap_is_pass_or_seen(tmp_path):
    rows = [{"tool": "ubuntils", "trap": "R1", "verdict": "PASS"},
            {"tool": "ubuntils", "trap": "V1", "verdict": "SEEN"},
            {"tool": "uac", "trap": "R1", "verdict": "HANG"}]
    d = _hh(tmp_path, {"ubuntils": {"outcome": "exited"}}, rows)
    assert hh.main([d]) == 0
    rows.append({"tool": "ubuntils", "trap": "I1", "verdict": "LEAK"})
    assert hh.main([_hh(tmp_path, {"ubuntils": {"outcome": "exited"}}, rows)]) == 1


def test_hh_gate_fails_on_a_broken_or_missing_baseline(tmp_path):
    assert hh.main([_hh(tmp_path, {"ubuntils": {"outcome": "broken: rc 1"}}, [])]) == 1
    assert hh.main([_hh(tmp_path, {}, [])]) == 1
    assert hh.main([str(tmp_path / "nowhere")]) == 2


def test_timings_reports_medians_and_enforces_budgets(tmp_path):
    dirs = []
    for i, (dur, rss) in enumerate([(30.0, 100000), (20.0, 120000), (25.0, 110000)]):
        d = tmp_path / f"run{i}"
        d.mkdir()
        (d / "report.json").write_text(json.dumps({"scan_metadata": {
            "duration_s": dur, "collector_durations_s": {"PackageCollector": dur - 5}}}))
        (d / "time.txt").write_text(f"\tMaximum resident set size (kbytes): {rss}\n")
        dirs.append(str(d))
    out = str(tmp_path / "t.json")
    assert timings.main([out] + dirs) == 0
    result = json.load(open(out))
    assert result["median_duration_s"] == 25.0
    assert result["collector_median_s"] == {"PackageCollector": 20.0}
    assert result["peak_rss_mb"] == round(120000 / 1024, 1)
    assert timings.main([out] + dirs + ["--budget-s", "24"]) == 1
    assert timings.main([out] + dirs + ["--budget-rss-mb", "100"]) == 1
    assert timings.main([out] + dirs + ["--budget-s", "60", "--budget-rss-mb", "300"]) == 0


compare = _load("tools/panix/compare.py", "panix_compare")
aggregate = _load("tools/panix/aggregate.py", "panix_aggregate")


def _rep(findings, **meta):
    return {"findings": findings, "scan_metadata": meta}


def test_panix_caught_needs_a_new_medium_or_high_finding():
    old = _f("SETUID_INVENTORY", "/usr/bin/x", sev="LOW")
    before = _rep([old])
    meta = {"technique": "suid", "attack": "T1548.001", "plant_rc": 0}
    assert compare.judge(before, _rep([old]), meta)["outcome"] == "missed"
    assert compare.judge(before, _rep([old, _f("SETUID_INVENTORY", "/tmp/s", sev="LOW")]),
                         meta)["outcome"] == "low only"
    hit = compare.judge(before, _rep([old, _f("CRON_SUSPICIOUS_COMMAND", "/etc/cron.d/x")]), meta)
    assert hit["outcome"] == "caught" and hit["best_severity"] == "HIGH"
    inv = dict(_f("SSH_KEY_INVENTORY", "/root/.ssh/authorized_keys", sev="MEDIUM"),
               category="inventory")
    assert compare.judge(before, _rep([old, inv]), meta)["outcome"] == "low only"


def test_panix_failed_plant_or_scan_is_never_a_miss():
    meta = {"technique": "lkm", "attack": "T1547.006", "plant_rc": 1}
    assert compare.judge(_rep([]), _rep([]), meta)["outcome"] == "not planted"
    meta["plant_rc"] = 0
    assert compare.judge(None, _rep([]), meta)["outcome"] == "scan failed"
    assert compare.judge(_rep([]), _rep([], detection_error="boom"), meta)["outcome"] == "scan failed"


def test_panix_headline_counts_only_applicable_techniques():
    s = aggregate.aggregate([
        {"technique": "a", "attack": "T1", "outcome": "caught"},
        {"technique": "b", "attack": "T2", "outcome": "missed"},
        {"technique": "c", "attack": "T3", "outcome": "not planted"}])
    assert (s["caught"], s["applicable"], s["not_run"]) == (1, 2, 1)
    assert "caught 1 of 2" in aggregate.render(s)


def test_panix_techniques_only_call_back_to_test_net():
    rows = [l.split("\t") for l in open(os.path.join(_REPO, "tools/panix/techniques.tsv"))
            if l.strip() and not l.startswith("#")]
    assert rows and all(len(r) == 3 for r in rows)
    script = open(os.path.join(_REPO, "tools/panix/run_one.sh")).read()
    assert "IP=192.0.2.1" in script and "GITHUB_ACTIONS" in script
    import re
    for _, _, args in rows:
        assert not re.search(r"\b\d+\.\d+\.\d+\.\d+\b", args)  # only the {IP} placeholder
        for banned in ("--rootkit", "--malicious-container", "--grub", "--initramfs", "--module"):
            assert banned not in args


fp = _load("tools/fp-suite/check.py", "fp_check")


def _fp_report(tmp_path, findings, degraded=None):
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"findings": findings, "scan_metadata": {
        "ubuntu_version": "Ubuntu 24.04", "tool_version": "x",
        "collectors_degraded": degraded or {}, "rules_failed": []}}))
    return str(p)


def test_fp_inventory_is_counted_apart_and_never_fails_the_budget(tmp_path, capsys):
    inv = [dict(_f("SSH_KEY_INVENTORY", f"/home/u{i}/.ssh/authorized_keys", sev="LOW"),
                category="inventory") for i in range(5)]
    base = tmp_path / "b.json"
    rep = _fp_report(tmp_path, inv)
    assert fp.main([rep, "--baseline", str(base), "--write-baseline"]) == 0
    assert json.load(open(base))["findings"] == []
    summary = tmp_path / "s.md"
    assert fp.main([rep, "--baseline", str(base), "--enforce-target",
                    "--summary", str(summary), "--image", "ubuntu:24.04"]) == 0
    assert "0 findings (0 HIGH), 5 inventory" in capsys.readouterr().out
    assert summary.read_text().startswith("| ubuntu:24.04 | 0 | 0 | 5 |")


def test_fp_without_a_reviewed_baseline_still_fails_on_high(tmp_path):
    missing = str(tmp_path / "none.json")
    assert fp.main([_fp_report(tmp_path, [_f("CRON_TMP_PATH", "/etc/cron.d/x", sev="LOW")]),
                    "--baseline", missing]) == 0
    assert fp.main([_fp_report(tmp_path, [_f("CRON_TMP_PATH", "/etc/cron.d/x")]),
                    "--baseline", missing]) == 1


def test_fp_reviewed_baseline_fails_on_a_new_finding(tmp_path):
    known = _f("SHELL_RC_MODIFICATION", "/etc/bash.bashrc", sev="LOW")
    base = tmp_path / "b.json"
    assert fp.main([_fp_report(tmp_path, [known]), "--baseline", str(base),
                    "--write-baseline"]) == 0
    assert fp.main([_fp_report(tmp_path, [known]), "--baseline", str(base)]) == 0
    new = _f("SETUID_INVENTORY", "/opt/x", sev="LOW")
    assert fp.main([_fp_report(tmp_path, [known, new]), "--baseline", str(base)]) == 1
