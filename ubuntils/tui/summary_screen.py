from ubuntils.detectors.finding import Finding, Severity
from ubuntils.timeline.builder import TimelineEvent

_SEV_BULLET = {Severity.HIGH: "●", Severity.MEDIUM: "○", Severity.LOW: "○"}
_SEV_LABEL = {Severity.HIGH: "HIGH", Severity.MEDIUM: "MED ", Severity.LOW: "LOW "}
_MAX_FINDINGS_SHOWN = 5


def _build_summary(
    findings: list[Finding],
    timeline: list[TimelineEvent],
    stats: dict,
) -> str:
    fc = stats.get("finding_counts", {})
    failures = stats.get("collector_failures", 0)
    collector_count = stats.get("collector_count", 0)
    duration = stats.get("duration_s", 0.0)
    timeline_count = stats.get("timeline_count", len(timeline))

    lines = [
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
    else:
        lines.append("  System appears clean.")

    return "\n".join(lines)
