from ubuntils.collectors.base import BaseCollector


class ProcessCollector(BaseCollector):
    def collect(self) -> dict:
        processes = []
        try:
            status_paths = self.source.glob("/proc/*/status")
        except Exception as exc:
            self.degraded.append(f"cannot enumerate /proc: {exc}")
            return {}

        for status_path in status_paths:
            try:
                pid = int(status_path.split("/")[2])
                name, uid = self._parse_status(status_path)
            except FileNotFoundError:
                continue
            except Exception:
                continue

            # Read through the source, never the analyst's own /proc — a PID
            # collision would otherwise attribute the analyst's exe to a
            # process from the analyzed host. Degrades to "" when the source
            # has no link target (bundles).
            exe = self._read_exe(pid)
            cmdline = self._read_cmdline(f"/proc/{pid}/cmdline")
            processes.append({
                "pid": pid,
                "name": name,
                "uid": uid,
                "exe": exe,
                "cmdline": cmdline,
            })

        return {"processes": processes}

    def _parse_status(self, path: str):
        name, uid = "", 0
        text = self.source.read_text(path)
        for line in text.splitlines():
            if line.startswith("Name:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Uid:"):
                uid = int(line.split(":", 1)[1].split()[0])
        return name, uid

    def _read_exe(self, pid: int) -> str:
        try:
            return self.source.readlink(f"/proc/{pid}/exe")
        except Exception:
            return ""

    def _read_cmdline(self, path: str) -> str:
        try:
            text = self.source.read_text(path)
        except Exception:
            return ""
        return text.replace("\x00", " ").strip()
