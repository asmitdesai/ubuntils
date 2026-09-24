import os
import shutil
import subprocess

# Commands always resolve against this fixed, root-owned search path — never
# the caller's $PATH. ubuntils runs as root, so resolving a bare "ss" or
# "visudo" through a user-controlled PATH would hand root code execution to
# anyone who can plant an executable earlier in that PATH.
SECURE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def resolve_command(name: str) -> str:
    """Return the absolute path of ``name`` on SECURE_PATH.

    Raises FileNotFoundError if it isn't there. An already-absolute name is
    returned unchanged.
    """
    if os.path.isabs(name):
        return name
    resolved = shutil.which(name, path=SECURE_PATH)
    if resolved is None:
        raise FileNotFoundError(f"command not found on secure path: {name}")
    return resolved


def run_command(cmd: list, timeout: int = 30) -> tuple:
    try:
        argv = [resolve_command(cmd[0])] + list(cmd[1:])
        env = dict(os.environ, PATH=SECURE_PATH)
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
        return result.stdout, result.stderr, result.returncode
    except (subprocess.TimeoutExpired, OSError) as e:
        return "", str(e), -1
