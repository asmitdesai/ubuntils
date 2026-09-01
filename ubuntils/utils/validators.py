STANDARD_LIB_PATHS = ["/lib", "/usr/lib", "/lib64", "/usr/lib64"]
STANDARD_BIN_PATHS = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
NOLOGIN_SHELLS = ["/sbin/nologin", "/bin/false", "/usr/sbin/nologin"]

KNOWN_SETUID_BINARIES = frozenset({
    "/usr/bin/sudo", "/usr/bin/su", "/bin/su",
    "/usr/bin/passwd", "/usr/bin/gpasswd", "/usr/bin/chsh", "/usr/bin/chfn",
    "/usr/bin/newgrp", "/usr/bin/mount", "/bin/mount", "/usr/bin/umount", "/bin/umount",
    "/usr/bin/pkexec", "/usr/bin/at", "/usr/bin/crontab",
    "/usr/bin/fusermount", "/usr/bin/fusermount3", "/usr/bin/ntfs-3g",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/sbin/pppd",
})

ALLOWED_NSS_MODULES = frozenset({
    "files", "compat", "systemd", "mymachines", "myhostname",
    "resolve", "dns", "nis", "nisplus", "db",
    "mdns4", "mdns4_minimal", "mdns6", "mdns6_minimal",
})

# Common built-in modules on stock Ubuntu server/container hosts (networking,
# filesystem overlay, virtualization). Deliberately NOT exhaustive for desktop/
# hardware drivers (GPU, Wi-Fi, proprietary vendor modules) — see README caveat;
# responders on such hosts should allowlist their host's modules via --config.
ALLOWED_KERNEL_MODULES = frozenset({
    "overlay", "br_netfilter", "veth", "xt_conntrack", "xt_nat", "xt_tcpudp",
    "xt_MASQUERADE", "xt_addrtype", "xt_comment", "xt_mark", "xt_multiport",
    "iptable_filter", "iptable_nat", "ip_tables", "ip6_tables", "nf_conntrack",
    "nf_nat", "nf_defrag_ipv4", "nf_defrag_ipv6", "sch_fq_codel",
    "vboxdrv", "vboxnetflt", "vboxnetadp",
    "virtio_net", "virtio_blk", "virtio_pci", "virtio_ring",
})


def is_login_shell(shell: str) -> bool:
    return shell not in NOLOGIN_SHELLS


def uid_is_system(uid: int) -> bool:
    return uid < 1000


def path_in_standard_libs(path: str) -> bool:
    return any(path.startswith(p) for p in STANDARD_LIB_PATHS)


def path_in_standard_bins(path: str) -> bool:
    return any(path.startswith(p) for p in STANDARD_BIN_PATHS)


def path_in_writable_tmp(path: str) -> bool:
    return any(path.startswith(p) for p in ("/tmp", "/var/tmp", "/dev/shm"))
