from ubuntils.remediators.cron import CronRemediator
from ubuntils.remediators.environment import EnvironmentRemediator
from ubuntils.remediators.ssh import SSHRemediator
from ubuntils.remediators.sudoers import SudoersRemediator

REMEDIATOR_REGISTRY = {
    "CRON_ROOT_EXEC": CronRemediator(),
    "CRON_TMP_PATH": CronRemediator(),
    "LD_PRELOAD_INJECT": EnvironmentRemediator(),
    "SSH_UNAUTHORIZED_KEY": SSHRemediator(),
    "SUDOERS_NOPASSWD": SudoersRemediator(),
}
