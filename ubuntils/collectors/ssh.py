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


class SSHCollector(BaseCollector):
    def collect(self) -> dict:
        entries = []
        try:
            passwd_lines = self.source.read_text("/etc/passwd").splitlines()
        except Exception:
            return {}

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
            auth_keys_path = f"{home}/.ssh/authorized_keys"
            if not self.source.exists(auth_keys_path):
                continue
            try:
                st = self.source.lstat(auth_keys_path)
                for key_line in self.source.read_text(auth_keys_path).splitlines():
                    key_line = key_line.strip()
                    if not key_line or key_line.startswith("#"):
                        continue
                    parsed = _parse_key_line(key_line)
                    if not parsed["key_type"]:
                        continue
                    entries.append({
                        "username": username,
                        "home": home,
                        "key_type": parsed["key_type"],
                        "key_data": parsed["key_data"],
                        "comment": parsed["comment"],
                        "options": parsed["options"],
                        "file_mtime": float(st.st_mtime),
                        "file_ctime": float(st.st_ctime),
                    })
            except Exception:
                continue

        return {"authorized_keys": entries}
