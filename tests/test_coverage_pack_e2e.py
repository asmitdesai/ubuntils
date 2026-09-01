from ubuntils.bundle import write_bundle, read_bundle
from ubuntils.collectors.source import LiveSource
from ubuntils.cli import _run_pipeline


def test_collect_then_analyze_surfaces_all_coverage_pack_findings(tmp_path):
    root = tmp_path / "root"
    (root / "etc" / "pam.d").mkdir(parents=True)
    (root / "etc" / "pam.d" / "sshd").write_text("auth sufficient pam_permit.so\n")
    (root / "etc" / "nsswitch.conf").write_text("passwd: files systemd\n")

    bundle = tmp_path / "b.tar.gz"

    class FakeSource(LiveSource):
        """Live-style source whose file reads are root-relative like normal, but whose
        `run()` replays fixed command output — used only to build a deterministic
        bundle for this test without depending on dpkg/lsattr/find/lsmod being
        installed on the test runner."""

        _COMMANDS = {
            "dpkg_verify": "missing   /usr/bin/sshd\n",
            "lsattr_sensitive": "----i--------e--- /etc/ld.so.preload\n",
            "find_setuid": "/tmp/.hidden/backdoor\n",
            "lsmod": "Module  Size  Used by\nevil_rootkit  12288  0\n",
        }

        def run(self, name, argv, timeout=30):
            if name in self._COMMANDS:
                return self._COMMANDS[name], "", 0
            return "", "", -1

    source = FakeSource(root=str(root))

    write_bundle(
        source=source,
        files_to_capture=["/etc/pam.d/sshd", "/etc/nsswitch.conf"],
        commands_to_capture=[
            ("dpkg_verify", ["dpkg", "--verify"]),
            ("lsattr_sensitive", ["lsattr", "-d", "/etc/ld.so.preload"]),
            ("find_setuid", ["find", "/", "-perm", "-4000"]),
            ("lsmod", ["lsmod"]),
        ],
        out_path=str(bundle),
        metadata={"hostname": "victim", "ubuntu_version": "U", "tool_version": "2.0.0"},
    )

    analyzed_source, info = read_bundle(str(bundle))
    findings, _timeline, _stats, meta, _counts, _rem = _run_pipeline(
        source=analyzed_source, remediate=False, confirm=False, bundle_info=info,
    )

    assert meta["bundle_integrity"] == "ok"
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {
        "PACKAGE_TAMPERED", "IMMUTABLE_FLAG_SET", "SETUID_INVENTORY",
        "PAM_BACKDOOR", "KERNEL_MODULE_SUSPICIOUS",
    }
