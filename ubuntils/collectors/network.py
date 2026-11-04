import re

from ubuntils.collectors.base import BaseCollector

# ss prints each socket owner as ("<name>",pid=<n>,fd=<n>). The name is the
# process's comm, which any user sets with prctl(PR_SET_NAME) — up to 15
# bytes, enough for `x",pid=1,` — so a naive "pid=" search can be pointed at
# any PID. Anchor on the closing quote AND the trailing fd=: text injected
# into a name always comes before its process's real pid=…,fd=…).
_SS_OWNER_RE = re.compile(r'",pid=(\d+),fd=\d+\)')


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

            pid = self._extract_pid(line) if tool == "ss" else self._netstat_pid(parts)

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
        """PID owning an ss socket line, or "" if it can't be trusted.

        Takes the last pid=…,fd=…) group (always a real one), then checks the
        name ss printed before it against /proc/<pid>/comm. A mismatch means
        the line was shaped by a process name, so the PID is dropped rather
        than pinned on an innocent process. Without /proc (bundles, --root)
        the anchored parse stands on its own.
        """
        users = line[line.find("users:(("):] if "users:((" in line else ""
        matches = list(_SS_OWNER_RE.finditer(users))
        if not matches:
            return ""
        last = matches[-1]
        pid = last.group(1)
        try:
            comm = self.source.read_text(f"/proc/{pid}/comm").rstrip("\n")
        except Exception:
            return pid
        if not users[:last.start()].endswith('("' + comm):
            self.degraded.append(f"dropped pid {pid}: ss process name doesn't match its "
                                 f"/proc comm {comm!r}")
            return ""
        return pid

    @staticmethod
    def _netstat_pid(parts: list) -> str:
        # PID/Program: the PID comes before the (attacker-named) program.
        last = parts[-1] if parts else ""
        pid = last.split("/", 1)[0] if "/" in last else ""
        return pid if pid.isdigit() else ""
