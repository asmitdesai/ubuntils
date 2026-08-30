from __future__ import annotations

BASE_CONFIDENCE = 50


def confidence_band(confidence: int) -> str:
    if confidence >= 75:
        return "HIGH"
    if confidence >= 40:
        return "MEDIUM"
    return "LOW"


def score(signals: list, base: int = BASE_CONFIDENCE) -> tuple:
    total = base + sum(s["weight"] for s in signals)
    total = max(0, min(100, total))
    return total, confidence_band(total)


def apply_signal(finding, name: str, weight: int, detail: str) -> None:
    """Append an explainable signal and recompute the finding's confidence
    from its full signal list. Safe to call multiple times, in any order,
    by different producers (a rule at detection time, the pipeline after
    timeline correlation) — the score is always derived fresh, never
    incrementally drifted."""
    finding.signals.append({"name": name, "weight": weight, "detail": detail})
    finding.confidence, finding.confidence_band = score(finding.signals)
