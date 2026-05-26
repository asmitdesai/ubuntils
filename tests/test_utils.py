import structlog

from ubuntils.utils.logging import configure_logging
from ubuntils.utils.shell import run_command
from ubuntils.utils.validators import (
    is_login_shell,
    uid_is_system,
    path_in_standard_libs,
    path_in_standard_bins,
    path_in_writable_tmp,
)


def test_run_command_success():
    stdout, stderr, returncode = run_command(["echo", "hello"])
    assert "hello" in stdout
    assert returncode == 0


def test_run_command_nonexistent():
    stdout, stderr, returncode = run_command(["__nonexistent_binary__"])
    assert returncode == -1
    assert stderr


def test_run_command_timeout():
    stdout, stderr, returncode = run_command(["sleep", "60"], timeout=0)
    assert returncode == -1


def test_is_login_shell_nologin():
    assert is_login_shell("/sbin/nologin") is False


def test_is_login_shell_bin_false():
    assert is_login_shell("/bin/false") is False


def test_is_login_shell_bash():
    assert is_login_shell("/bin/bash") is True


def test_is_login_shell_sh():
    assert is_login_shell("/bin/sh") is True


def test_uid_is_system_root():
    assert uid_is_system(0) is True


def test_uid_is_system_below_threshold():
    assert uid_is_system(999) is True


def test_uid_is_system_at_threshold():
    assert uid_is_system(1000) is False


def test_uid_is_system_regular_user():
    assert uid_is_system(1001) is False


def test_path_in_standard_libs_usr_lib():
    assert path_in_standard_libs("/usr/lib/x86_64-linux-gnu/libc.so") is True


def test_path_in_standard_libs_lib():
    assert path_in_standard_libs("/lib/x86_64-linux-gnu/libz.so") is True


def test_path_in_standard_libs_tmp():
    assert path_in_standard_libs("/tmp/evil.so") is False


def test_path_in_standard_bins_usr_bin():
    assert path_in_standard_bins("/usr/bin/python3") is True


def test_path_in_standard_bins_sbin():
    assert path_in_standard_bins("/sbin/init") is True


def test_path_in_standard_bins_tmp():
    assert path_in_standard_bins("/tmp/fake_python") is False


def test_path_in_writable_tmp_tmp():
    assert path_in_writable_tmp("/tmp/foo.so") is True


def test_path_in_writable_tmp_var_tmp():
    assert path_in_writable_tmp("/var/tmp/bar") is True


def test_path_in_writable_tmp_dev_shm():
    assert path_in_writable_tmp("/dev/shm/payload") is True


def test_path_in_writable_tmp_usr_lib():
    assert path_in_writable_tmp("/usr/lib/foo.so") is False


def test_configure_logging_json_mode():
    configure_logging(json_mode=True, verbose=False)
    logger = structlog.get_logger()
    assert logger is not None


def test_configure_logging_console_mode():
    configure_logging(json_mode=False, verbose=False)
    logger = structlog.get_logger()
    assert logger is not None


def test_configure_logging_verbose():
    import logging
    # Clear existing handlers so basicConfig can update the root level
    root = logging.getLogger()
    root.handlers.clear()
    configure_logging(json_mode=False, verbose=True)
    assert root.level == logging.DEBUG
