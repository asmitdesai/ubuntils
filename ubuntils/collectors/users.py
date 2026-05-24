from ubuntils.collectors.base import BaseCollector
from ubuntils.utils.validators import is_login_shell


class UserCollector(BaseCollector):
    def collect(self) -> dict:
        groups = self._parse_groups()
        shadow_locked = self._parse_shadow()

        users = []
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) < 7:
                        continue
                    username, uid, gid, home, shell = (
                        parts[0], int(parts[2]), int(parts[3]), parts[5], parts[6]
                    )
                    users.append({
                        "username": username,
                        "uid": uid,
                        "gid": gid,
                        "home": home,
                        "shell": shell,
                        "is_login_shell": is_login_shell(shell),
                        "groups": groups.get(username, []),
                        "password_locked": shadow_locked.get(username),
                    })
        except Exception:
            return {}

        return {"users": users}

    def _parse_groups(self) -> dict:
        mapping = {}
        try:
            with open("/etc/group") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) < 4:
                        continue
                    group_name = parts[0]
                    members = [m for m in parts[3].split(",") if m]
                    for member in members:
                        mapping.setdefault(member, []).append(group_name)
        except Exception:
            pass
        return mapping

    def _parse_shadow(self) -> dict:
        locked = {}
        try:
            with open("/etc/shadow") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) < 2:
                        continue
                    username, pw_hash = parts[0], parts[1]
                    locked[username] = pw_hash.startswith("!") or pw_hash == "*"
        except PermissionError:
            pass
        except Exception:
            pass
        return locked
