"""Targeted preserve-then-fix (E1-S4, docs/plans/v3.0.0-prd.md)."""
import hashlib
import json
import os
import stat
import time
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from ubuntils import cli
from ubuntils.collectors.source import LiveSource
from ubuntils.detectors.finding import Finding, RemediationStatus, Severity
from ubuntils.pipeline import remediate_findings, run_scan
from ubuntils.remediators import preserve as preserve_mod
from ubuntils.remediators.base import BaseRemediator
from ubuntils.utils.safe_path import dir_identity, open_dir_nofollow

LINE = "* * * * * root /tmp/evil.sh\n"


@pytest.fixture(autouse=True)
def backups_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(BaseRemediator.__init__, "__defaults__", (str(tmp_path / "backups"),))


def _cron_finding(path, **kw):
    return Finding(rule_id="CRON_TMP_PATH", severity=Severity.HIGH, title="t", description="d",
                   artifact_path=str(path), raw_value=LINE.strip(),
                   remediation_available=True, **kw)


def _crontab(tmp_path, name="cleanup"):
    d = tmp_path / "cron.d"
    d.mkdir(exist_ok=True)
    f = d / name
    f.write_text("# keep me\n" + LINE)
    return f


def _preserve_dirs():
    base = preserve_mod.PRESERVE_BASE
    return sorted(os.listdir(base)) if os.path.isdir(base) else []


def test_preserve_copies_hashes_and_describes_each_file(tmp_path):
    crontab = _crontab(tmp_path)
    record = preserve_mod.preserve([_cron_finding(crontab)], base=preserve_mod.PRESERVE_BASE)
    manifest_bytes = open(record.manifest_path, "rb").read()
    assert hashlib.sha256(manifest_bytes).hexdigest() == record.manifest_sha256
    manifest = json.loads(manifest_bytes)
    [entry] = manifest["files"]
    original = crontab.read_bytes()
    assert entry["path"] == str(crontab)
    assert entry["sha256"] == hashlib.sha256(original).hexdigest()
    assert entry["findings"] == ["CRON_TMP_PATH"]
    copy = os.path.join(record.directory, entry["preserved_as"])
    assert open(copy, "rb").read() == original
    assert stat.S_IMODE(os.stat(record.directory).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(copy).st_mode) == 0o600
    assert manifest["format_version"] == preserve_mod.PRESERVE_FORMAT_VERSION


def test_files_are_preserved_before_any_change(tmp_path):
    crontab = _crontab(tmp_path)
    out = []
    [result] = remediate_findings([_cron_finding(crontab)], confirm=True, preserve_out=out)
    assert result.status == RemediationStatus.SUCCESS
    assert LINE not in crontab.read_text()
    [record] = out
    copy = os.path.join(record.directory, record.files[0]["preserved_as"])
    assert LINE in open(copy).read()  # the evidence, as it was before the fix


def test_preserve_failure_changes_nothing(tmp_path):
    good = _crontab(tmp_path, "good")
    real = tmp_path / "real"
    real.mkdir()
    (real / "x").write_text(LINE)
    (tmp_path / "linked").symlink_to(real)
    bad = _cron_finding(tmp_path / "linked" / "x")
    results = remediate_findings([_cron_finding(good), bad], confirm=True)
    assert [r.status for r in results] == [RemediationStatus.FAILED] * 2
    assert all("nothing was changed" in r.message for r in results)
    assert LINE in good.read_text() and LINE in (real / "x").read_text()


def test_parent_directory_swapped_since_detection_is_refused(tmp_path):
    crontab = _crontab(tmp_path)
    fd = open_dir_nofollow(str(tmp_path))
    try:
        other = dir_identity(fd)  # tmp_path, not cron.d: a different directory
    finally:
        os.close(fd)
    with pytest.raises(preserve_mod.PreserveError, match="not the directory"):
        preserve_mod.preserve([_cron_finding(crontab, parent_dir_identity=other)],
                              base=preserve_mod.PRESERVE_BASE)


def test_dry_run_preserves_nothing(tmp_path):
    crontab = _crontab(tmp_path)
    remediate_findings([_cron_finding(crontab)], confirm=False)
    assert _preserve_dirs() == []


def test_blocked_findings_are_not_preserved_or_changed(tmp_path):
    crontab = _crontab(tmp_path)
    f = _cron_finding(crontab, auto_remediation_blocked="human must look")
    [result] = remediate_findings([f], confirm=True)
    assert result.status == RemediationStatus.SKIPPED
    assert _preserve_dirs() == []


def test_no_preserve_opt_out(tmp_path):
    crontab = _crontab(tmp_path)
    [result] = remediate_findings([_cron_finding(crontab)], confirm=True,
                                  preserve_evidence=False)
    assert result.status == RemediationStatus.SUCCESS
    assert _preserve_dirs() == []


def test_preserve_meets_its_time_budget(tmp_path):
    # PRD E1-S4: 50 files of 1 MiB in at most 2 s.
    d = tmp_path / "many"
    d.mkdir()
    findings = []
    blob = ("#" * 1023 + "\n") * 1024
    for i in range(50):
        f = d / f"f{i}"
        f.write_text(blob)
        findings.append(_cron_finding(f))
    start = time.monotonic()
    record = preserve_mod.preserve(findings, base=preserve_mod.PRESERVE_BASE)
    assert time.monotonic() - start <= 2.0
    assert len(record.files) == 50


def test_scan_metadata_records_the_preserve(tmp_path):
    crontab = _crontab(tmp_path)
    with patch("ubuntils.pipeline.ALL_COLLECTORS", []), \
            patch("ubuntils.pipeline.DetectionEngine") as engine, \
            patch("ubuntils.pipeline.TimelineBuilder") as tl:
        engine.return_value.run.return_value = [_cron_finding(crontab)]
        engine.return_value.rules_failed = []
        engine.return_value.suppressed_by_baseline = 0
        engine.return_value.suppressed_by_allowlist = 0
        engine.return_value.baseline_suppressed_findings = []
        tl.return_value.build.return_value = []
        r = run_scan(LiveSource(), remediate=True, confirm=True, forward_wazuh=False)
    meta = r.scan_metadata["preserve"]
    assert meta["files"] == [str(crontab)]
    assert len(meta["manifest_sha256"]) == 64


@pytest.mark.parametrize("args, message", [
    (["--no-preserve"], "add --yes"),
    (["--no-preserve", "--yes", "--preserve-full"], "contradict"),
])
def test_cli_preserve_flags_are_checked(monkeypatch, args, message):
    monkeypatch.setattr(cli, "_ensure_root", lambda: None)
    result = CliRunner().invoke(cli.main, ["scan", "--json", "--remediate", "--confirm", *args])
    assert result.exit_code == 2
    assert message in result.output
