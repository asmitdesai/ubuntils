import hashlib
import json
from datetime import datetime, timezone

from ubuntils.detectors.finding import Finding, RemediationResult
from ubuntils.timeline.builder import TimelineEvent


class JSONFormatter:
    def format(
        self,
        scan_metadata: dict,
        artifact_counts: dict,
        findings: list[Finding],
        timeline: list[TimelineEvent],
        remediation_results: list[RemediationResult],
    ) -> str:
        output: dict = {
            "scan_metadata": scan_metadata,
            "artifact_counts": artifact_counts,
            "findings": [self._finding(f) for f in findings],
            "timeline": [self._event(e) for e in timeline],
        }
        if remediation_results:
            output["remediation_results"] = [self._remediation(r) for r in remediation_results]
        # Tamper-evidence: a SHA-256 over the canonical report content, so a
        # collected triage artifact can be verified later. Computed over the
        # report with the digest field absent, then injected.
        digest = hashlib.sha256(
            json.dumps(output, indent=2, sort_keys=True).encode("utf-8")
        ).hexdigest()
        output["report_sha256"] = digest
        return json.dumps(output, indent=2)

    def _finding(self, f: Finding) -> dict:
        d = {
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "artifact_path": f.artifact_path,
            "raw_value": f.raw_value,
            "remediation_available": f.remediation_available,
        }
        if f.remediation_description is not None:
            d["remediation_description"] = f.remediation_description
        return d

    def _event(self, e: TimelineEvent) -> dict:
        ts = e.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return {
            "timestamp": ts.isoformat(),
            "source": e.source,
            "description": e.description,
        }

    def _remediation(self, r: RemediationResult) -> dict:
        d = {
            "finding_rule_id": r.finding_rule_id,
            "status": r.status.value,
            "message": r.message,
        }
        if r.backup_path is not None:
            d["backup_path"] = r.backup_path
        if r.rollback_command is not None:
            d["rollback_command"] = r.rollback_command
        return d
