from ubuntils.collectors.base import BaseCollector


class NetworkCollector(BaseCollector):
    def collect(self) -> dict:
        tool = "ss"
        stdout, _, returncode = self.source.run("ss", ["ss", "-tunap"])
        if returncode != 0:
            tool = "netstat"
            stdout, _, returncode = self.source.run("netstat", ["netstat", "-tunap"])
        if returncode != 0:
            self.degraded.append("neither `ss` nor `netstat` produced output")
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
            if tool == "ss":
                # Netid State Recv-Q Send-Q Local Peer [Process]
                if len(parts) < 6:
                    continue
                state, local, remote = parts[1], parts[4], parts[5]
            else:
                # Proto Recv-Q Send-Q Local Foreign [State] PID/Program —
                # UDP rows have no State column.
                local, remote = parts[3], parts[4]
                state = ""
                if len(parts) > 5 and "/" not in parts[5] and parts[5] != "-":
                    state = parts[5]

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
