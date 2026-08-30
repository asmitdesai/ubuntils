import pytest

from ubuntils.detectors.finding import Finding, Severity
from ubuntils.utils.baseline import Baseline, load_baseline


def _finding(rule_id="SSH_UNAUTHORIZED_KEY", raw_value="ssh-ed25519 AAAA... ci@runner",
             artifact_path="/home/ci/.ssh/authorized_keys"):
    return Finding(
        rule_id=rule_id, severity=Severity.MEDIUM, title="t", description="d",
        artifact_path=artifact_path, raw_value=raw_value, remediation_available=False,
    )


def test_baseline_matches_by_rule_id_and_fingerprint_substring():
    b = Baseline(entries=[{"rule_id": "SSH_UNAUTHORIZED_KEY", "fingerprint": "ci@runner"}])
    assert b.matches(_finding()) is True


def test_baseline_matches_by_artifact_path():
    b = Baseline(entries=[{
        "rule_id": "SHELL_RC_MODIFICATION", "fingerprint": "/home/deploy/.bashrc",
    }])
    f = _finding(rule_id="SHELL_RC_MODIFICATION", raw_value="unrelated",
                 artifact_path="/home/deploy/.bashrc")
    assert b.matches(f) is True


def test_baseline_does_not_match_different_rule_id():
    b = Baseline(entries=[{"rule_id": "SSH_UNAUTHORIZED_KEY", "fingerprint": "ci@runner"}])
    f = _finding(rule_id="SHELL_RC_MODIFICATION", raw_value="ci@runner mentioned")
    assert b.matches(f) is False


def test_baseline_filter_drops_matches_and_counts_them():
    b = Baseline(entries=[{"rule_id": "SSH_UNAUTHORIZED_KEY", "fingerprint": "ci@runner"}])
    kept, suppressed = b.filter([_finding(), _finding(raw_value="unrelated key")])
    assert len(kept) == 1
    assert suppressed == 1


def test_load_baseline_parses_yaml(tmp_path):
    p = tmp_path / "baseline.yaml"
    p.write_text(
        "baseline:\n"
        "  - rule_id: SSH_UNAUTHORIZED_KEY\n"
        "    fingerprint: ci@runner\n"
    )
    b = load_baseline(str(p))
    assert b.entries == [{"rule_id": "SSH_UNAUTHORIZED_KEY", "fingerprint": "ci@runner"}]


def test_load_baseline_rejects_non_mapping(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("- just\n- a\n- list\n")
    with pytest.raises(ValueError):
        load_baseline(str(p))
