import re

from ubuntils.collectors.base import BaseCollector

# The kernel's own record of loaded modules. A tainted module ends its line
# with its taint flags: "vboxdrv 696320 2 vboxnetflt, Live 0xffff... (OE)".
PROC_MODULES = "/proc/modules"
_TAINT_RE = re.compile(r"\(([A-Z]+)\)\s*$")


class KernelCollector(BaseCollector):
    def collect(self) -> dict:
        taints = self._module_taints()
        stdout, _stderr, rc = self.source.run("lsmod", ["lsmod"])
        if not stdout:
            if rc != 0:
                self.degraded.append("`lsmod` failed")
            return {"kernel_modules": []}

        modules = []
        lines = stdout.splitlines()
        for line in lines[1:]:  # skip "Module  Size  Used by" header
            parts = line.split()
            if len(parts) < 2:
                continue
            name, size = parts[0], parts[1]
            used_by = []
            if len(parts) >= 4:
                used_by = [n for n in parts[3].split(",") if n]
            modules.append({
                "name": name, "size": size, "used_by": used_by,
                # "" = untainted (shipped with the kernel, signed), "OE" etc.
                # for out-of-tree/unsigned/…, None when /proc/modules wasn't
                # available (offline analysis, older bundles).
                "taint": taints.get(name) if taints is not None else None,
            })
        return {"kernel_modules": modules}

    def _module_taints(self):
        """module name -> taint flags ("" if untainted), or None if unknown."""
        try:
            text = self.source.read_text(PROC_MODULES)
        except Exception:
            return None
        taints = {}
        for line in text.splitlines():
            parts = line.split()
            if not parts:
                continue
            m = _TAINT_RE.search(line)
            taints[parts[0]] = m.group(1) if m else ""
        # An empty file (a dead image's /proc) says nothing either way.
        return taints or None
