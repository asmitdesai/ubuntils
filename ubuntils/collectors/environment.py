import hashlib

from ubuntils.collectors.base import BaseCollector
from ubuntils.collectors.source import UNREAD_TAIL_NOTE
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


DPKG_STATUS = "/var/lib/dpkg/status"
# base-files' postinst *copies* these into place (they are not conffiles), so
# dpkg has no record of the installed copy; it does have the template's md5.
BASE_FILES_TEMPLATES = {
    "/etc/profile": "/usr/share/base-files/profile",
    "/root/.bashrc": "/usr/share/base-files/dot.bashrc",
    "/root/.profile": "/usr/share/base-files/dot.profile",
}
BASE_FILES_MD5SUMS_GLOB = "/var/lib/dpkg/info/base-files*.md5sums"


def _md5(data: bytes) -> str:
    # Compared with dpkg's own record; not a security boundary.
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def _is_md5(value: str) -> bool:
    return len(value) == 32 and all(c in "0123456789abcdef" for c in value)


class EnvironmentCollector(BaseCollector):
    _known_md5s = None

    def _dpkg_md5s(self) -> dict:
        """path -> md5 dpkg recorded: every conffile (/var/lib/dpkg/status)
        plus base-files' shipped files (its .md5sums)."""
        if self._known_md5s is not None:
            return self._known_md5s
        known = {}
        try:
            status = self.source.read_text(DPKG_STATUS)
        except Exception:
            status = ""
        in_block = False
        for line in status.splitlines():
            if line.startswith("Conffiles:"):
                in_block = True
                continue
            if in_block and line.startswith(" "):
                parts = line.split()
                # An `obsolete` entry for a path another package now owns
                # must not shadow the live one.
                if (len(parts) >= 2 and parts[0].startswith("/") and _is_md5(parts[1])
                        and not (parts[0] in known and "obsolete" in parts[2:])):
                    known[parts[0]] = parts[1]
                continue
            in_block = False
        try:
            md5sums = self.source.glob(BASE_FILES_MD5SUMS_GLOB)
        except Exception:
            md5sums = []
        for md5sums_path in md5sums:
            try:
                text = self.source.read_text(md5sums_path)
            except Exception:
                continue
            for line in text.splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2 and _is_md5(parts[0]):
                    known.setdefault("/" + parts[1].strip().lstrip("/"), parts[0])
        self._known_md5s = known
        return known

    def _matches_dpkg(self, path: str):
        """True/False if dpkg recorded an md5 for ``path`` (unmodified or not); None if not."""
        md5 = self._dpkg_md5s().get(path)
        if md5 is None:
            return None
        try:
            return _md5(self.source.read_bytes(path)) == md5
        except Exception:
            return None

    def _stock_copy(self, path: str, content: str, user_controlled: bool) -> bool:
        """The file is byte-for-byte what the system shipped: a package
        conffile matching dpkg's md5, or a copy of a shipped template
        (/etc/skel for user dotfiles, /usr/share/base-files for /etc/profile
        and root's dotfiles) that is itself unmodified. In a fresh container
        every file's ctime is the image's unpack time, so recency alone said
        all of these were 'recently modified' (E3-S5)."""
        if not user_controlled and self._matches_dpkg(path) is True:
            return True
        template = BASE_FILES_TEMPLATES.get(path)
        if template is not None:
            # Checked against base-files' md5sums: unverifiable is untrusted.
            if self._matches_dpkg(template) is not True:
                return False
        elif user_controlled:
            template = "/etc/skel/" + path.rsplit("/", 1)[-1]
            if self._matches_dpkg(template) is False:
                return False  # /etc/skel itself was changed: not a trusted reference
        else:
            return False
        try:
            return self.source.read_text(template) == content
        except Exception:
            return False

    def collect(self) -> dict:
        self._known_md5s = None
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

        return {"env_definitions": self.tag_parent_dirs(definitions, "source"),
                "shell_init_files": shell_init_files}

    def _add_shell_init(self, path: str, owner: str, definitions: list,
                        shell_init_files: list, user_controlled: bool) -> None:
        if not self.source.exists(path):
            return
        try:
            st = self.source.lstat(path)
            # A user's own files can be a FIFO, /dev/zero, or a huge sparse
            # file planted to hang the scan; read those defensively.
            user_file = self.source.read_user_file(path) if user_controlled else None
            content = user_file.text if user_file else self.source.read_text(path)
        except Exception as exc:
            self.degraded.append(f"skipped {path}: {exc}")
            return
        if user_file and user_file.truncated:
            self.degraded.append(f"{path}: {UNREAD_TAIL_NOTE}")
        definitions.extend(self._shell_init_definitions(content, path, owner))
        shell_init_files.append({
            "owner": owner,
            "source": path,
            "mtime": float(st.st_mtime),
            "ctime": float(st.st_ctime),
            "content": content,
            "size": user_file.size if user_file else len(content),
            # bash sources every byte, so padding can't hide a line from it.
            "oversized": bool(user_file and user_file.oversized),
            "truncated": bool(user_file and user_file.truncated),
            "stock_copy": self._stock_copy(path, content, user_controlled),
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
