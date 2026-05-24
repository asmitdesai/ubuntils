import os

from ubuntils.collectors.base import BaseCollector


class SSHCollector(BaseCollector):
    def collect(self) -> dict:
        entries = []
        try:
            with open("/etc/passwd") as f:
                passwd_lines = f.readlines()
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
            if not os.path.exists(auth_keys_path):
                continue
            try:
                file_mtime = os.stat(auth_keys_path).st_mtime
                with open(auth_keys_path) as f:
                    for key_line in f:
                        key_line = key_line.strip()
                        if not key_line or key_line.startswith("#"):
                            continue
                        key_parts = key_line.split(None, 2)
                        if len(key_parts) < 2:
                            continue
                        key_type = key_parts[0]
                        key_data = key_parts[1]
                        comment = key_parts[2] if len(key_parts) > 2 else ""
                        entries.append({
                            "username": username,
                            "home": home,
                            "key_type": key_type,
                            "key_data": key_data,
                            "comment": comment,
                            "file_mtime": float(file_mtime),
                        })
            except Exception:
                continue

        return {"authorized_keys": entries}
