import glob
import os

from ubuntils.collectors.base import BaseCollector
from ubuntils.utils.validators import is_login_shell


class EnvironmentCollector(BaseCollector):
    def collect(self) -> dict:
        definitions = []

        definitions.extend(self._read_env_file("/etc/environment", "system"))
        definitions.extend(self._read_shell_init("/etc/profile", "system"))
        for path in glob.glob("/etc/profile.d/*.sh"):
            definitions.extend(self._read_shell_init(path, "system"))

        for username, home in self._get_login_users():
            for filename in (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile"):
                path = f"{home}/{filename}"
                if os.path.exists(path):
                    definitions.extend(self._read_shell_init(path, username))

        return {"env_definitions": definitions}

    def _get_login_users(self):
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) < 7:
                        continue
                    username, home, shell = parts[0], parts[5], parts[6]
                    if is_login_shell(shell) and home:
                        yield username, home
        except Exception:
            return

    def _read_env_file(self, path: str, owner: str) -> list:
        entries = []
        try:
            with open(path) as f:
                for line in f:
                    raw = line.strip()
                    if not raw or raw.startswith("#"):
                        continue
                    if "=" in raw:
                        var, _, val = raw.partition("=")
                        entries.append({
                            "owner": owner,
                            "source": path,
                            "variable": var.strip(),
                            "value": val.strip().strip("\"'"),
                            "raw_line": raw,
                        })
        except Exception:
            pass
        return entries

    def _read_shell_init(self, path: str, owner: str) -> list:
        entries = []
        try:
            with open(path) as f:
                for line in f:
                    raw = line.strip()
                    if not raw or raw.startswith("#"):
                        continue
                    actual = raw
                    if actual.startswith("export "):
                        actual = actual[7:].strip()
                    if "=" in actual:
                        var, _, val = actual.partition("=")
                        var = var.strip()
                        if var and all(c.isalnum() or c == "_" for c in var):
                            entries.append({
                                "owner": owner,
                                "source": path,
                                "variable": var,
                                "value": val.strip().strip("\"'"),
                                "raw_line": raw,
                            })
        except Exception:
            pass
        return entries
