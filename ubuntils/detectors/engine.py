from typing import List

import structlog

from ubuntils.detectors.custom_rules import apply_custom_rules
from ubuntils.detectors.finding import Finding
from ubuntils.detectors.rules import (
    rule_cron_root_exec,
    rule_cron_tmp_path,
    rule_ld_preload_inject,
    rule_process_masquerade,
    rule_process_suspicious_connection,
    rule_shell_rc_modification,
    rule_ssh_unauthorized_key,
    rule_sudoers_nopasswd,
    rule_suspicious_systemd_timer,
    rule_uid_zero_account,
    rule_user_empty_password,
    rule_package_tampered,
    rule_immutable_flag_set,
    rule_setuid_inventory,
    rule_pam_backdoor,
    rule_kernel_module_suspicious,
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
    rule_user_empty_password,
    rule_shell_rc_modification,
    rule_package_tampered,
    rule_immutable_flag_set,
    rule_setuid_inventory,
    rule_pam_backdoor,
    rule_kernel_module_suspicious,
]

logger = structlog.get_logger()


class DetectionEngine:
    def __init__(self, allowlist: Allowlist = None, custom_rules=None, baseline: Baseline = None):
        self.allowlist = allowlist
        self.custom_rules = custom_rules or []
        self.baseline = baseline
        self.suppressed_by_baseline = 0
        self.baseline_suppressed_findings: List[Finding] = []
        # Names of rules that raised during run() — surfaced in scan_metadata
        # so a crashed rule can't masquerade as "nothing found".
        self.rules_failed: List[str] = []

    def run(self, artifacts: dict) -> List[Finding]:
        findings = []
        self.rules_failed = []
        for rule in ALL_RULES:
            try:
                findings.extend(rule(artifacts))
            except Exception as exc:
                logger.exception("rule_failed", rule=rule.__name__, error=str(exc))
                self.rules_failed.append(rule.__name__)
        if self.custom_rules:
            try:
                findings.extend(apply_custom_rules(self.custom_rules, artifacts))
            except Exception as exc:
                logger.exception("custom_rules_failed", error=str(exc))
                self.rules_failed.append("custom_rules")
        self.baseline_suppressed_findings = []
        if self.baseline is not None:
            findings, self.baseline_suppressed_findings = self.baseline.filter(findings)
        self.suppressed_by_baseline = len(self.baseline_suppressed_findings)
        if self.allowlist is not None:
            findings = self.allowlist.filter(findings)
        return findings
