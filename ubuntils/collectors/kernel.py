from ubuntils.collectors.base import BaseCollector


class KernelCollector(BaseCollector):
    def collect(self) -> dict:
        stdout, _stderr, rc = self.source.run("lsmod", ["lsmod"])
        if not stdout:
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
            modules.append({"name": name, "size": size, "used_by": used_by})
        return {"kernel_modules": modules}
