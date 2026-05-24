import glob
import os

from ubuntils.collectors.base import BaseCollector


class ProcessCollector(BaseCollector):
    def collect(self) -> dict:
        processes = []
        try:
            status_paths = glob.glob("/proc/*/status")
        except Exception:
            return {}

        for status_path in status_paths:
            try:
                pid = int(status_path.split("/")[2])
                name, uid = self._parse_status(status_path)
                exe = os.readlink(f"/proc/{pid}/exe")
                cmdline = self._read_cmdline(f"/proc/{pid}/cmdline")
                processes.append({
                    "pid": pid,
                    "name": name,
                    "uid": uid,
                    "exe": exe,
                    "cmdline": cmdline,
                })
            except FileNotFoundError:
                continue
            except Exception:
                continue

        return {"processes": processes}

    def _parse_status(self, path: str):
        name, uid = "", 0
        with open(path) as f:
            for line in f:
                if line.startswith("Name:"):
                    name = line.split(":", 1)[1].strip()
                elif line.startswith("Uid:"):
                    uid = int(line.split(":", 1)[1].split()[0])
        return name, uid

    def _read_cmdline(self, path: str) -> str:
        with open(path, "rb") as f:
            data = f.read()
        return data.replace(b"\x00", b" ").decode(errors="replace").strip()
