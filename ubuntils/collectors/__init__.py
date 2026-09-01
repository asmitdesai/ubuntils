from ubuntils.collectors.processes import ProcessCollector
from ubuntils.collectors.network import NetworkCollector
from ubuntils.collectors.users import UserCollector
from ubuntils.collectors.cron import CronCollector
from ubuntils.collectors.systemd import SystemdCollector
from ubuntils.collectors.ssh import SSHCollector
from ubuntils.collectors.sudoers import SudoersCollector
from ubuntils.collectors.environment import EnvironmentCollector
from ubuntils.collectors.packages import PackageCollector
from ubuntils.collectors.pam import PamCollector
from ubuntils.collectors.kernel import KernelCollector

ALL_COLLECTORS = [
    ProcessCollector,
    NetworkCollector,
    UserCollector,
    CronCollector,
    SystemdCollector,
    SSHCollector,
    SudoersCollector,
    EnvironmentCollector,
    PackageCollector,
    PamCollector,
    KernelCollector,
]
