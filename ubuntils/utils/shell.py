import subprocess


def run_command(cmd: list, timeout: int = 30) -> tuple:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except (subprocess.TimeoutExpired, OSError) as e:
        return "", str(e), -1
