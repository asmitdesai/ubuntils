from ubuntils.collectors.base import BaseCollector


class PamCollector(BaseCollector):
    def collect(self) -> dict:
        pam_files = []
        try:
            for path in self.source.glob("/etc/pam.d/*"):
                try:
                    content = self.source.read_text(path)
                except (OSError, ValueError):
                    continue
                pam_files.append({"path": path, "content": content})
        except Exception:
            # A failure partway through the loop (e.g. glob() itself raising,
            # or a read failure outside the (OSError, ValueError) the inner
            # handler expects) must not discard files already read
            # successfully — preserve pam_files as gathered so far.
            pass

        nsswitch_content = ""
        try:
            nsswitch_content = self.source.read_text("/etc/nsswitch.conf")
        except (OSError, ValueError):
            pass

        return {"pam_files": pam_files, "nsswitch_content": nsswitch_content}
