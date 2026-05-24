STANDARD_LIB_PATHS = ["/lib", "/usr/lib", "/lib64", "/usr/lib64"]
STANDARD_BIN_PATHS = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
NOLOGIN_SHELLS = ["/sbin/nologin", "/bin/false", "/usr/sbin/nologin"]


def is_login_shell(shell: str) -> bool:
    return shell not in NOLOGIN_SHELLS


def uid_is_system(uid: int) -> bool:
    return uid < 1000


def path_in_standard_libs(path: str) -> bool:
    return any(path.startswith(p) for p in STANDARD_LIB_PATHS)


def path_in_standard_bins(path: str) -> bool:
    return any(path.startswith(p) for p in STANDARD_BIN_PATHS)


def path_in_writable_tmp(path: str) -> bool:
    return any(path.startswith(p) for p in ("/tmp", "/var/tmp", "/dev/shm"))
