from ubuntils.collectors.processes import ProcessCollector
from ubuntils.collectors.network import NetworkCollector
from ubuntils.collectors.users import UserCollector
from ubuntils.collectors.cron import CronCollector
from ubuntils.collectors.systemd import SystemdCollector
from ubuntils.collectors.ssh import SSHCollector
from ubuntils.collectors.sudoers import SudoersCollector
from ubuntils.collectors.environment import EnvironmentCollector

ALL_COLLECTORS = [
    ProcessCollector,
    NetworkCollector,
    UserCollector,
    CronCollector,
    SystemdCollector,
    SSHCollector,
    SudoersCollector,
    EnvironmentCollector,
]
