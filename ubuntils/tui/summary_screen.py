from __future__ import annotations

from ubuntils.detectors.finding import Finding, RemediationResult, Severity
from ubuntils.timeline.builder import TimelineEvent

_SEV_BULLET = {Severity.HIGH: "●", Severity.MEDIUM: "○", Severity.LOW: "○"}
_SEV_LABEL = {Severity.HIGH: "HIGH", Severity.MEDIUM: "MED ", Severity.LOW: "LOW "}
_MAX_FINDINGS_SHOWN = 5


def _health_lines(stats: dict) -> list:
    """Warnings that change how far the results can be trusted."""
    lines = []
    if stats.get("bundle_integrity") == "mismatch":
        lines.append("!! BUNDLE INTEGRITY FAILED — contents do not match the manifest; "
                     "treat all results as untrusted")
    degraded = stats.get("collectors_degraded") or {}
    if degraded:
        lines.append(f"!! Degraded collection: {', '.join(sorted(degraded))} "
                     "(missing data is NOT evidence of a clean host)")
    rules_failed = stats.get("rules_failed") or []
    if rules_failed:
        lines.append(f"!! Detection rules failed: {', '.join(rules_failed)}")
    if stats.get("timeline_error"):
        lines.append(f"!! Timeline unavailable: {stats['timeline_error']}")
    return lines


def _build_summary(
    findings: list[Finding],
    timeline: list[TimelineEvent],
    stats: dict,
    remediation_results: list[RemediationResult] | None = None,
) -> str:
    fc = stats.get("finding_counts", {})
    failures = stats.get("collector_failures", 0)
    collector_count = stats.get("collector_count", 0)
    duration = stats.get("duration_s", 0.0)
    timeline_count = stats.get("timeline_count", len(timeline))

    lines = _health_lines(stats)
    if lines:
        lines.append("")
    lines += [
        f"Collectors:  {collector_count} run · {failures} failed",
        f"Findings:    {fc.get('HIGH', 0)} HIGH · {fc.get('MEDIUM', 0)} MEDIUM · {fc.get('LOW', 0)} LOW",
        f"Timeline:    {timeline_count} events",
        f"Duration:    {duration:.1f}s",
        "",
    ]

    if findings:
        shown = findings[:_MAX_FINDINGS_SHOWN]
        for f in shown:
            bullet = _SEV_BULLET[f.severity]
            sev = _SEV_LABEL[f.severity]
            rule = f"{f.rule_id[:22]:<22}"
            path = f.artifact_path[:30]
            lines.append(f"  {bullet} {sev}  {rule}  {path}")
        if len(findings) > _MAX_FINDINGS_SHOWN:
            lines.append(f"  … and {len(findings) - _MAX_FINDINGS_SHOWN} more")
    elif _health_lines(stats):
        lines.append("  No findings — but see the warnings above.")
    else:
        lines.append("  System appears clean.")

    if remediation_results:
        lines += ["", "Remediation:"]
        for r in remediation_results:
            lines.append(f"  [{r.status.value}] {r.finding_rule_id}: {r.message}")
            if r.backup_path:
                lines.append(f"      backup:   {r.backup_path}")
            if r.rollback_command:
                lines.append(f"      rollback: {r.rollback_command}")

    return "\n".join(lines)
