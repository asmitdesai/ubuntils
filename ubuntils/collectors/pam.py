from ubuntils.collectors.base import BaseCollector


class PamCollector(BaseCollector):
    def collect(self) -> dict:
        pam_files = []
        try:
            paths = self.source.glob("/etc/pam.d/*")
        except Exception as exc:
            paths = []
            self.degraded.append(f"cannot list /etc/pam.d: {exc}")
        for path in paths:
            try:
                content = self.source.read_text(path)
            except Exception as exc:
                # One unreadable file must not discard the rest, and must not
                # read as "no backdoor in this file".
                self.degraded.append(f"{path}: {exc}")
                continue
            pam_files.append({"path": path, "content": content})
        if not paths and not self.degraded:
            # Every Ubuntu system has PAM configuration; none at all means it
            # wasn't collected (e.g. a bundle that doesn't hold /etc/pam.d),
            # so PAM_BACKDOOR had nothing to look at.
            self.degraded.append("no files in /etc/pam.d: PAM configuration was not checked")

        nsswitch_content = ""
        try:
            nsswitch_content = self.source.read_text("/etc/nsswitch.conf")
        except FileNotFoundError:
            pass
        except Exception as exc:
            self.degraded.append(f"/etc/nsswitch.conf: {exc}")

        return {"pam_files": pam_files, "nsswitch_content": nsswitch_content}
