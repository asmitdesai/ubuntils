import logging
from typing import List

from ubuntils.detectors.custom_rules import apply_custom_rules
from ubuntils.detectors.finding import Finding
from ubuntils.detectors.rules import (
    rule_cron_root_exec,
    rule_cron_tmp_path,
    rule_ld_preload_inject,
    rule_package_tampered,
    rule_process_masquerade,
    rule_process_suspicious_connection,
    rule_shell_rc_modification,
    rule_ssh_unauthorized_key,
    rule_sudoers_nopasswd,
    rule_suspicious_systemd_timer,
    rule_uid_zero_account,
)
from ubuntils.utils.baseline import Baseline
from ubuntils.utils.config import Allowlist

ALL_RULES = [
    rule_cron_root_exec,
    rule_cron_tmp_path,
    rule_ld_preload_inject,
    rule_suspicious_systemd_timer,
    rule_ssh_unauthorized_key,
    rule_sudoers_nopasswd,
    rule_process_masquerade,
    rule_process_suspicious_connection,
    rule_uid_zero_account,
    rule_shell_rc_modification,
    rule_package_tampered,
]

_log = logging.getLogger(__name__)


class DetectionEngine:
    def __init__(self, allowlist: Allowlist = None, custom_rules=None, baseline: Baseline = None):
        self.allowlist = allowlist
        self.custom_rules = custom_rules or []
        self.baseline = baseline
        self.suppressed_by_baseline = 0
        self.baseline_suppressed_findings: List[Finding] = []

    def run(self, artifacts: dict) -> List[Finding]:
        findings = []
        for rule in ALL_RULES:
            try:
                findings.extend(rule(artifacts))
            except Exception as exc:
                _log.exception("Rule %s raised: %s", rule.__name__, exc)
        if self.custom_rules:
            try:
                findings.extend(apply_custom_rules(self.custom_rules, artifacts))
            except Exception as exc:
                _log.exception("Custom rules raised: %s", exc)
        self.baseline_suppressed_findings = []
        if self.baseline is not None:
            findings, self.baseline_suppressed_findings = self.baseline.filter(findings)
        self.suppressed_by_baseline = len(self.baseline_suppressed_findings)
        if self.allowlist is not None:
            findings = self.allowlist.filter(findings)
        return findings
