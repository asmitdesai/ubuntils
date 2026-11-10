"""One suspicious-command matcher for every place a host stores a command (E8-S1, R-04).

Cron entries, systemd ``Exec*=`` lines, shell init files and ``at`` jobs all
hold shell text an intruder can write. Before 3.0 each rule had its own partial
pattern (curl piped straight into sh, base64 -d), so ``bash <(curl …)``, a
``/dev/tcp`` reverse shell or a download-then-chmod passed everywhere.

``match(text)`` returns weighted, explainable signals for the score model:

| family              | weight | examples                                                     |
|---------------------|--------|--------------------------------------------------------------|
| reverse_shell       | 40     | /dev/tcp, /dev/udp, socat exec:, mkfifo + nc, nc -e, bash -i >&, python/perl/php/ruby socket one-liners |
| download_exec       | 35     | curl|sh (and python/perl…), bash <(curl), sh -c "$(curl)", download → chmod +x |
| encoded_payload     | 30     | base64 -d | sh, eval of a decode, xxd -r | sh, openssl enc -d | sh, printf '\\x..' | sh |
| encoded_payload     | 15     | base64 -d on its own                                         |
| writable_tmp        | 15     | a path in /tmp, /var/tmp or /dev/shm                          |

The text is attacker-controlled and is never executed, parsed with ``shlex`` (it
raises on unbalanced quotes) or evaluated. Input is capped at
``MAX_INPUT_CHARS``; every regex has bounded gaps and no nested quantifiers
(checked at import), and the multi-part one-liners are matched with substring
tests instead of stacked regex gaps, so a 1 MiB pathological line costs
milliseconds. Content signals don't depend on file age; recency is the
caller's business.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ubuntils.utils.validators import command_references_writable_tmp

MAX_INPUT_CHARS = 16 * 1024
MAX_SIGNALS = 64
_GAP = 512  # longest stretch a pattern will skip between two of its parts

REVERSE_SHELL, DOWNLOAD_EXEC, ENCODED, WRITABLE_TMP, LIMITS = (
    "reverse_shell", "download_exec", "encoded_payload", "writable_tmp", "limits")

FAMILY_DESCRIPTIONS = {
    REVERSE_SHELL: "opens a reverse or bind shell",
    DOWNLOAD_EXEC: "downloads and executes code",
    ENCODED: "decodes or evaluates a hidden payload",
    WRITABLE_TMP: "runs from or references a world-writable temp directory",
    LIMITS: "was too long to check completely",
}


@dataclass(frozen=True)
class CommandSignal:
    code: str
    family: str
    weight: int
    excerpt: str
    offset: int


_DL = r"(?:curl|wget|fetch|busybox\s{1,8}wget)"
_HEX4 = r"\\x[0-9a-fA-F][0-9a-fA-F]" * 4  # four \xNN escapes, no nested quantifier
_INTERP = r"(?:sudo\s{1,8})?(?:env\s{1,8})?(?:ba|da|z|k|a)?sh|python[23]?|perl|ruby|php|node"

# (code, family, weight, regex). Bounded gaps only: {0,_GAP}, never .* or (x+)+.
_PATTERNS = [
    ("dev_tcp", REVERSE_SHELL, 40, r"/dev/(?:tcp|udp)/[^\s/]{1,255}/\d{1,5}"),
    ("socat_exec", REVERSE_SHELL, 40, rf"\bsocat\b[^\n]{{0,{_GAP}}}?\b(?:exec|system):"),
    ("mkfifo_nc", REVERSE_SHELL, 40,
     rf"\bmkfifo\b[^\n]{{0,{_GAP}}}?\b(?:nc|ncat|netcat|telnet|openssl\s{{1,8}}s_client)\b"),
    ("nc_exec", REVERSE_SHELL, 40,
     rf"\b(?:nc|ncat|netcat)\b[^|;&\n]{{0,{_GAP}}}?\s-[a-zA-Z]{{0,6}}[ec](?:\s|$)"),
    ("interactive_redirect", REVERSE_SHELL, 40, r"\b(?:ba)?sh\s{1,8}-i\b[^\n]{0,64}?[<>]&"),
    ("pipe_to_interpreter", DOWNLOAD_EXEC, 35,
     rf"\b{_DL}\b[^|\n]{{0,{_GAP}}}\|\s{{0,8}}(?:{_INTERP})\b"),
    ("process_substitution", DOWNLOAD_EXEC, 35,
     rf"(?:\b(?:{_INTERP}|source)|(?:^|[\s;&|(])\.)\s{{1,8}}<\(\s{{0,8}}{_DL}\b"),
    ("command_substitution", DOWNLOAD_EXEC, 35,
     rf"\b(?:{_INTERP})\s{{1,8}}-c\s{{1,8}}[\"']?\$\(\s{{0,8}}{_DL}\b"),
    ("eval_download", DOWNLOAD_EXEC, 35, rf"\beval\s{{1,8}}[\"']?(?:\$\(|`)\s{{0,8}}{_DL}\b"),
    ("base64_to_interpreter", ENCODED, 30,
     rf"\bbase64\s{{1,8}}(?:-d|--decode|-D)\b[^|\n]{{0,{_GAP}}}\|\s{{0,8}}(?:{_INTERP})\b"),
    # Not a bare eval "$(…)": stock Ubuntu .bashrc runs eval "$(dircolors -b)"
    # and eval "$(lesspipe)". Only an eval of something decoded counts.
    ("eval_decode", ENCODED, 30,
     rf"\beval\s{{1,8}}[\"']?(?:\$\(|`)[^)`\n]{{0,{_GAP}}}\b(?:base64\s{{1,8}}(?:-d|--decode|-D)|xxd\s{{1,8}}-r|openssl\s{{1,8}}(?:enc|base64))\b"),
    ("hex_to_interpreter", ENCODED, 30,
     rf"\bxxd\s{{1,8}}-r\b[^|\n]{{0,{_GAP}}}\|\s{{0,8}}(?:{_INTERP})\b"),
    ("openssl_to_interpreter", ENCODED, 30,
     rf"\bopenssl\s{{1,8}}(?:enc|base64)\b[^|\n]{{0,{_GAP}}}\s-d\b[^|\n]{{0,{_GAP}}}\|\s{{0,8}}(?:{_INTERP})\b"),
    ("printf_escapes_to_interpreter", ENCODED, 30,
     rf"\bprintf\s{{1,8}}[\"']?{_HEX4}[^|\n]{{0,{_GAP}}}\|\s{{0,8}}(?:{_INTERP})\b"),
    ("base64_decode", ENCODED, 15, r"\bbase64\s{1,8}(?:-d|--decode|-D)\b"),
]

# '(a+)+', '(a*)*', '(a|b)+' over quantified groups: the shapes that backtrack
# exponentially. Same check custom rules get (audit M11).
_NESTED_QUANTIFIER_RE = re.compile(r"\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)\s*[+*{]")


def _compile():
    compiled = []
    for code, family, weight, pattern in _PATTERNS:
        if _NESTED_QUANTIFIER_RE.search(pattern):
            raise AssertionError(f"cmdmatch pattern {code} nests quantifiers")
        compiled.append((code, family, weight, re.compile(pattern)))
    return compiled


_COMPILED = _compile()

# One-liners recognised by substrings, not regex gaps: (code, interpreter
# marker regex, required substrings (all), any-of substrings).
_ONE_LINERS = [
    ("python_socket", re.compile(r"\bpython[23]?(?:\.\d{1,2})?\s{1,8}-c\b"),
     ("socket",), ("connect", "dup2", "pty.spawn", "subprocess")),
    ("perl_socket", re.compile(r"\bperl\s{1,8}-[a-zA-Z]{0,4}e\b"),
     ("socket",), ("connect", "exec", "open(")),
    ("php_socket", re.compile(r"\bphp\s{1,8}-r\b"), ("fsockopen",), ("exec", "shell_exec", "proc_open", "system", "popen")),
    ("ruby_socket", re.compile(r"\bruby\s{1,8}-[a-zA-Z]{0,4}(?:rsocket|e)\b"),
     ("socket",), ("exec", "spawn", "popen", "tcpsocket")),
]

_DOWNLOAD_TO_FILE = re.compile(
    r"\b(?:curl|wget)\b[^;&|\n]{0,256}?\s(?:-o|-O|--output|--output-document)(?:\s{1,8}|=)[\"']?([^\s\"';&|]{1,255})")
_CHMOD_X = re.compile(r"\bchmod\s{1,8}(?:[ugoa]{0,3}\+[rwx]{0,2}x|[0-7]{0,1}[0-7][1357][0-7]{0,2})\s{1,8}[\"']?([^\s\"';&|]{1,255})")


def _normalise(text: str) -> str:
    # Join backslash-newline continuations; leave everything else as written
    # (offsets point into the normalised text, which is what we show).
    return text.replace("\\\r\n", " ").replace("\\\n", " ")


def _excerpt(text: str, start: int, end: int) -> str:
    snippet = text[max(0, start - 20):min(len(text), end + 20)].replace("\n", " ")
    return snippet if len(snippet) <= 200 else snippet[:197] + "..."


def match(text: str) -> list:
    """Signals for one command, script line or file body. Never raises on str input."""
    if not text:
        return []
    signals: list = []
    if len(text) > MAX_INPUT_CHARS:
        signals.append(CommandSignal("input_truncated", LIMITS, 5,
                                     f"{len(text)} characters; only the first {MAX_INPUT_CHARS} "
                                     "were checked", MAX_INPUT_CHARS))
        text = text[:MAX_INPUT_CHARS]
    text = _normalise(text)

    for code, family, weight, rx in _COMPILED:
        for m in rx.finditer(text):
            signals.append(CommandSignal(code, family, weight, _excerpt(text, m.start(), m.end()),
                                         m.start()))
            break  # one per pattern is enough to explain the score
    lowered = text.lower()
    for code, marker, required, any_of in _ONE_LINERS:
        m = marker.search(text)
        if m and all(r in lowered for r in required) and any(a in lowered for a in any_of):
            signals.append(CommandSignal(code, REVERSE_SHELL, 40,
                                         _excerpt(text, m.start(), m.end()), m.start()))
    # Download to a file, chmod +x that file, then name it again (run it).
    # Each list is built once: rescanning per download was quadratic.
    downloads: dict = {}
    for d in _DOWNLOAD_TO_FILE.finditer(text):
        downloads.setdefault(d.group(1).rsplit("/", 1)[-1], d)
    if downloads:
        for c in _CHMOD_X.finditer(text):
            name = c.group(1).rsplit("/", 1)[-1]
            d = downloads.get(name)
            if d is not None and d.end() <= c.start() and text.find(name, c.end()) != -1:
                signals.append(CommandSignal("download_chmod_exec", DOWNLOAD_EXEC, 35,
                                             _excerpt(text, d.start(), c.end()), d.start()))
                break
    if command_references_writable_tmp(text):
        signals.append(CommandSignal("tmp_path", WRITABLE_TMP, 15,
                                     "references /tmp, /var/tmp or /dev/shm", 0))
    return signals[:MAX_SIGNALS]


def strongest_per_family(signals: list) -> list:
    """The highest-weight signal of each family, strongest first — what a rule
    applies to a finding, so the explanation stays one line per family."""
    best: dict = {}
    for s in signals:
        if s.family not in best or s.weight > best[s.family].weight:
            best[s.family] = s
    return sorted(best.values(), key=lambda s: (-s.weight, s.family))


def is_suspicious(signals: list) -> bool:
    """True if any signal is in a family that marks a command as malicious on its
    own (not just a temp path, a bare decode or truncation)."""
    return any(s.family in (REVERSE_SHELL, DOWNLOAD_EXEC) or
               (s.family == ENCODED and s.weight >= 30) for s in signals)


def apply_to_finding(finding, signals: list, where: str) -> None:
    """Apply one explainable signal per family to ``finding``."""
    from ubuntils.detectors.scoring import apply_signal
    for s in strongest_per_family(signals):
        apply_signal(finding, s.family, s.weight,
                     f"{where} {FAMILY_DESCRIPTIONS[s.family]} ({s.code}: {s.excerpt})")
