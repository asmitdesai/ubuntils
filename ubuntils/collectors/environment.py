from ubuntils.collectors.base import BaseCollector
from ubuntils.utils.validators import is_login_shell

# System-wide files every login or interactive shell sources (MITRE
# T1546.004). /etc/profile.d/*.sh is globbed separately.
SYSTEM_SHELL_INIT_FILES = (
    "/etc/profile", "/etc/bash.bashrc",
    "/etc/zsh/zshenv", "/etc/zsh/zprofile", "/etc/zsh/zshrc", "/etc/zsh/zlogin",
)
USER_SHELL_INIT_FILES = (
    ".bashrc", ".bash_profile", ".bash_login", ".profile",
    ".zshenv", ".zprofile", ".zshrc", ".zlogin",
)


class EnvironmentCollector(BaseCollector):
    def collect(self) -> dict:
        definitions = []
        shell_init_files = []

        definitions.extend(self._read_ld_so_preload())
        definitions.extend(self._read_env_file("/etc/environment", "system"))

        system_files = list(SYSTEM_SHELL_INIT_FILES)
        try:
            system_files += self.source.glob("/etc/profile.d/*.sh")
        except Exception:
            pass
        for path in system_files:
            self._add_shell_init(path, "system", definitions, shell_init_files,
                                 user_controlled=False)

        for username, home in self._get_login_users():
            for filename in USER_SHELL_INIT_FILES:
                self._add_shell_init(f"{home.rstrip('/')}/{filename}", username,
                                     definitions, shell_init_files, user_controlled=True)

        return {"env_definitions": definitions, "shell_init_files": shell_init_files}

    def _add_shell_init(self, path: str, owner: str, definitions: list,
                        shell_init_files: list, user_controlled: bool) -> None:
        if not self.source.exists(path):
            return
        try:
            st = self.source.lstat(path)
            # A user's own files can be a FIFO, /dev/zero, or a huge sparse
            # file planted to hang the scan; read those defensively.
            content = (self.source.read_user_text(path) if user_controlled
                       else self.source.read_text(path))
        except Exception as exc:
            self.degraded.append(f"skipped {path}: {exc}")
            return
        definitions.extend(self._shell_init_definitions(content, path, owner))
        shell_init_files.append({
            "owner": owner,
            "source": path,
            "mtime": float(st.st_mtime),
            "ctime": float(st.st_ctime),
            "content": content,
        })

    def _get_login_users(self):
        try:
            for line in self.source.read_text("/etc/passwd").splitlines():
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

    def _read_ld_so_preload(self) -> list:
        """/etc/ld.so.preload is a bare list of libraries (no VAR= syntax)
        that the loader injects into *every* process — the primary LD_PRELOAD
        rootkit vector. glibc splits it on whitespace and ':' and has no
        comment syntax, so every non-blank line is live, including ones
        starting with '#'. Each line becomes an LD_PRELOAD definition."""
        path = "/etc/ld.so.preload"
        entries = []
        try:
            text = self.source.read_text(path)
        except Exception:
            return entries
        for line in text.splitlines():
            raw = line.strip()
            if not raw:
                continue
            entries.append({
                "owner": "system",
                "source": path,
                "variable": "LD_PRELOAD",
                "value": raw,
                "raw_line": line.rstrip("\n"),
                "kind": "ld.so.preload",
            })
        return entries

    def _read_env_file(self, path: str, owner: str) -> list:
        entries = []
        try:
            for line in self.source.read_text(path).splitlines():
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

    @staticmethod
    def _shell_init_definitions(content: str, path: str, owner: str) -> list:
        entries = []
        try:
            for line in content.splitlines():
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
