from ubuntils.collectors.base import BaseCollector
from ubuntils.utils.shell import run_command


class NetworkCollector(BaseCollector):
    def collect(self) -> dict:
        stdout, _, returncode = run_command(["ss", "-tunap"])
        if returncode != 0:
            stdout, _, returncode = run_command(["netstat", "-tunap"])
        if returncode != 0:
            return {}

        known_protos = {"tcp", "tcp6", "udp", "udp6", "raw", "raw6"}
        connections = []
        for line in stdout.splitlines():
            parts = line.split()
            if not parts or parts[0].lower() not in known_protos:
                continue
            if len(parts) < 5:
                continue
            proto = parts[0]
            state = parts[1] if len(parts) > 5 else ""
            local = parts[4] if len(parts) > 5 else parts[3]
            remote = parts[5] if len(parts) > 5 else parts[4]

            local_addr, local_port = self._split_addr(local)
            remote_addr, remote_port = self._split_addr(remote)

            pid = self._extract_pid(line)

            connections.append({
                "proto": proto,
                "local_addr": local_addr,
                "local_port": local_port,
                "remote_addr": remote_addr,
                "remote_port": remote_port,
                "state": state,
                "pid": pid,
            })

        return {"connections": connections}

    def _split_addr(self, addr_port: str):
        if addr_port in ("*", "0.0.0.0:*", ":::*"):
            return addr_port, "*"
        addr, _, port = addr_port.rpartition(":")
        return addr or addr_port, port or "*"

    def _extract_pid(self, line: str) -> str:
        if "pid=" in line:
            start = line.index("pid=") + 4
            end = line.find(",", start)
            return line[start:end] if end != -1 else line[start:].rstrip(")")
        parts = line.split()
        last = parts[-1] if parts else ""
        if "/" in last:
            return last.split("/")[0]
        return ""
