import logging
from typing import List

from ubuntils.detectors.finding import Finding
from ubuntils.detectors.rules import (
    rule_cron_root_exec,
    rule_cron_tmp_path,
    rule_ld_preload_inject,
    rule_process_masquerade,
    rule_shell_rc_modification,
    rule_ssh_unauthorized_key,
    rule_sudoers_nopasswd,
    rule_suspicious_systemd_timer,
)

ALL_RULES = [
    rule_cron_root_exec,
    rule_cron_tmp_path,
    rule_ld_preload_inject,
    rule_suspicious_systemd_timer,
    rule_ssh_unauthorized_key,
    rule_sudoers_nopasswd,
    rule_process_masquerade,
    rule_shell_rc_modification,
]

_log = logging.getLogger(__name__)


class DetectionEngine:
    def run(self, artifacts: dict) -> List[Finding]:
        findings = []
        for rule in ALL_RULES:
            try:
                findings.extend(rule(artifacts))
            except Exception as exc:
                _log.exception("Rule %s raised: %s", rule.__name__, exc)
        return findings
