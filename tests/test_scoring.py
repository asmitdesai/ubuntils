from ubuntils.detectors.finding import Finding, Severity
from ubuntils.detectors.scoring import BASE_CONFIDENCE, apply_signal, confidence_band, score


def _finding(**overrides):
    defaults = dict(
        rule_id="TEST_RULE", severity=Severity.MEDIUM, title="t", description="d",
        artifact_path="/x", raw_value="v", remediation_available=False,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_finding_defaults_to_base_confidence_and_medium_band():
    f = _finding()
    assert f.confidence == BASE_CONFIDENCE
    assert f.confidence_band == "MEDIUM"
    assert f.signals == []


def test_confidence_band_thresholds():
    assert confidence_band(0) == "LOW"
    assert confidence_band(39) == "LOW"
    assert confidence_band(40) == "MEDIUM"
    assert confidence_band(74) == "MEDIUM"
    assert confidence_band(75) == "HIGH"
    assert confidence_band(100) == "HIGH"


def test_score_clamps_to_0_100():
    conf, band = score([{"name": "a", "weight": -1000, "detail": ""}])
    assert conf == 0 and band == "LOW"
    conf, band = score([{"name": "a", "weight": 1000, "detail": ""}])
    assert conf == 100 and band == "HIGH"


def test_apply_signal_recomputes_from_full_signal_list():
    f = _finding()
    apply_signal(f, "content_match", 30, "dangerous option present")
    assert f.confidence == BASE_CONFIDENCE + 30
    assert f.confidence_band == "HIGH"
    apply_signal(f, "mtime_only", -20, "recency is the only signal")
    assert f.confidence == BASE_CONFIDENCE + 30 - 20
    assert f.signals == [
        {"name": "content_match", "weight": 30, "detail": "dangerous option present"},
        {"name": "mtime_only", "weight": -20, "detail": "recency is the only signal"},
    ]
