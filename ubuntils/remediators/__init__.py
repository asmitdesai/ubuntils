from ubuntils.remediators.cron import CronRemediator
from ubuntils.remediators.environment import EnvironmentRemediator
from ubuntils.remediators.ssh import SSHRemediator
from ubuntils.remediators.sudoers import SudoersRemediator

# Maps rule_id -> remediator *class*. Consumers instantiate one per
# remediation: remediators carry per-run state (_dry_run), so a shared
# module-level instance would race when the TUI remediates on worker threads.
REMEDIATOR_REGISTRY = {
    "CRON_ROOT_EXEC": CronRemediator,
    "CRON_TMP_PATH": CronRemediator,
    "LD_PRELOAD_INJECT": EnvironmentRemediator,
    "SSH_UNAUTHORIZED_KEY": SSHRemediator,
    "SUDOERS_NOPASSWD": SudoersRemediator,
}
