from ubuntils.collectors.base import BaseCollector

_KEY_TYPE_PREFIXES = (
    "ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
)


def _parse_key_line(key_line: str) -> dict:
    """Split an authorized_keys line into (options, key_type, key_data, comment).

    An authorized_keys line may be prefixed with a comma-separated options
    string (e.g. command="...",no-pty) before the key type. Options are
    identified by scanning for the first token that looks like a known key
    type; everything before it is the options string.
    """
    tokens = key_line.split()
    for i, tok in enumerate(tokens):
        if tok.startswith(_KEY_TYPE_PREFIXES):
            options = " ".join(tokens[:i])
            rest = tokens[i:]
            return {
                "options": options,
                "key_type": rest[0],
                "key_data": rest[1] if len(rest) > 1 else "",
                "comment": " ".join(rest[2:]),
            }
    # No recognized key type found — fall back to the old positional parse.
    parts = key_line.split(None, 2)
    return {
        "options": "",
        "key_type": parts[0] if parts else "",
        "key_data": parts[1] if len(parts) > 1 else "",
        "comment": parts[2] if len(parts) > 2 else "",
    }


# OpenSSH's built-in default: authorized_keys2 is still honoured, which makes
# it a favourite place to hide a key from tools that only check
# authorized_keys (MITRE T1098.004).
DEFAULT_AUTHORIZED_KEYS_FILES = (".ssh/authorized_keys", ".ssh/authorized_keys2")
SSHD_CONFIG_PATHS = ("/etc/ssh/sshd_config",)
SSHD_CONFIG_DROPIN_GLOB = "/etc/ssh/sshd_config.d/*.conf"


def _expand_keys_file(pattern: str, home: str, username: str) -> str:
    """Expand sshd's %h / %u / %% tokens; relative paths are under the home dir."""
    out, i = [], 0
    while i < len(pattern):
        if pattern[i] == "%" and i + 1 < len(pattern):
            token = pattern[i + 1]
            out.append({"h": home, "u": username, "%": "%"}.get(token, "%" + token))
            i += 2
        else:
            out.append(pattern[i])
            i += 1
    path = "".join(out)
    return path if path.startswith("/") else f"{home.rstrip('/')}/{path}"


class SSHCollector(BaseCollector):
    def collect(self) -> dict:
        entries = []
        try:
            passwd_lines = self.source.read_text("/etc/passwd").splitlines()
        except Exception as exc:
            self.degraded.append(f"cannot read /etc/passwd: {exc}")
            return {}

        patterns = self._authorized_keys_patterns()
        seen_files: set = set()
        for line in passwd_lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 6:
                continue
            username, home = parts[0], parts[5]
            if not home:
                continue
            for pattern in patterns:
                path = _expand_keys_file(pattern, home, username)
                if path in seen_files:
                    continue
                seen_files.add(path)
                entries.extend(self._read_keys_file(path, username, home))

        return {"authorized_keys": entries}

    def _authorized_keys_patterns(self) -> list:
        """Every AuthorizedKeysFile pattern sshd could use, plus the defaults.

        Taking the union over the main config, its drop-ins and Match blocks
        over-approximates sshd (which uses the first match per connection) —
        for a triage tool, reading a file sshd might ignore beats missing one
        it honours.
        """
        patterns = list(DEFAULT_AUTHORIZED_KEYS_FILES)
        configs = list(SSHD_CONFIG_PATHS)
        try:
            configs += self.source.glob(SSHD_CONFIG_DROPIN_GLOB)
        except Exception:
            pass
        for config in configs:
            try:
                text = self.source.read_text(config)
            except Exception:
                continue
            for raw in text.splitlines():
                tokens = raw.split("#", 1)[0].split()
                if len(tokens) < 2 or tokens[0].lower() != "authorizedkeysfile":
                    continue
                for value in tokens[1:]:
                    if value.lower() != "none" and value not in patterns:
                        patterns.append(value)
        return patterns

    def _read_keys_file(self, path: str, username: str, home: str) -> list:
        if not self.source.exists(path):
            return []
        try:
            st = self.source.lstat(path)
            content = self.source.read_user_text(path)
        except Exception as exc:
            self.degraded.append(f"skipped {path}: {exc}")
            return []
        entries = []
        for key_line in content.splitlines():
            stripped = key_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parsed = _parse_key_line(stripped)
            # sshd ignores lines without a key type; so do we. Accepting them
            # let a symlink to /etc/shadow put password hashes in the report.
            if not parsed["key_type"].startswith(_KEY_TYPE_PREFIXES):
                continue
            entries.append({
                "username": username,
                "home": home,
                "path": path,
                "key_type": parsed["key_type"],
                "key_data": parsed["key_data"],
                "comment": parsed["comment"],
                "options": parsed["options"],
                # Exactly as in the file, so remediation can match the line —
                # including any options="…" prefix and odd spacing.
                "raw_line": key_line,
                "file_mtime": float(st.st_mtime),
                "file_ctime": float(st.st_ctime),
            })
        return entries
