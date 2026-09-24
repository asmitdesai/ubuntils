from ubuntils.collectors.base import BaseCollector
from ubuntils.utils.validators import is_login_shell


class UserCollector(BaseCollector):
    def collect(self) -> dict:
        groups, group_names_by_gid = self._parse_groups()
        shadow = self._parse_shadow()

        try:
            passwd_lines = self.source.read_text("/etc/passwd").splitlines()
        except Exception as exc:
            self.degraded.append(f"cannot read /etc/passwd: {exc}")
            return {}

        users = []
        for line in passwd_lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            # One malformed line must not blind every user-based rule: skip
            # just that line (an attacker could otherwise inject junk to hide
            # a UID-0 account).
            try:
                uid, gid = int(parts[2]), int(parts[3])
            except ValueError:
                self.degraded.append(f"skipped malformed /etc/passwd line for {parts[0]!r}")
                continue
            username, home, shell = parts[0], parts[5], parts[6]
            pw = shadow.get(username)
            users.append({
                "username": username,
                "uid": uid,
                "gid": gid,
                "home": home,
                "shell": shell,
                "is_login_shell": is_login_shell(shell),
                "groups": groups.get(username, []),
                "primary_group": group_names_by_gid.get(gid, ""),
                "password_locked": None if pw is None else (pw.startswith("!") or pw == "*"),
                "password_empty": None if pw is None else pw == "",
            })

        return {"users": users}

    def _parse_groups(self) -> tuple:
        mapping: dict = {}
        names_by_gid: dict = {}
        try:
            for line in self.source.read_text("/etc/group").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 4:
                    continue
                group_name = parts[0]
                try:
                    names_by_gid[int(parts[2])] = group_name
                except ValueError:
                    pass
                members = [m for m in parts[3].split(",") if m]
                for member in members:
                    mapping.setdefault(member, []).append(group_name)
        except Exception:
            pass
        return mapping, names_by_gid

    def _parse_shadow(self) -> dict:
        """username -> raw password field ("" means no password at all)."""
        hashes = {}
        try:
            for line in self.source.read_text("/etc/shadow").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 2:
                    continue
                hashes[parts[0]] = parts[1]
        except Exception as exc:
            self.degraded.append(f"cannot read /etc/shadow: {exc}")
        return hashes
