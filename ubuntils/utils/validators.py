import re

STANDARD_LIB_PATHS = ["/lib", "/usr/lib", "/lib64", "/usr/lib64"]
# Root-owned locations legitimate binaries run from on stock Ubuntu: daemons
# under /usr/lib and /usr/libexec (e.g. /usr/lib/systemd/systemd), locally
# installed tools under /usr/local, and every snap under /snap.
STANDARD_BIN_PATHS = [
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/usr/local/bin", "/usr/local/sbin",
    "/usr/lib", "/usr/libexec", "/lib",
    "/snap",
]
WRITABLE_TMP_PATHS = ["/tmp", "/var/tmp", "/dev/shm"]
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
    "/usr/lib/policykit-1/polkit-agent-helper-1", "/usr/libexec/polkit-agent-helper-1",
    "/usr/lib/snapd/snap-confine", "/usr/lib/eject/dmcrypt-get-device",
    "/usr/lib/xorg/Xorg.wrap", "/usr/sbin/mount.nfs", "/usr/sbin/mount.cifs",
    "/usr/bin/vmware-user-suid-wrapper", "/usr/bin/traceroute6.iputils",
})

# Stock setgid binaries (group shadow/tty/crontab/_ssh/mlocate/utmp/mail).
# Checked separately from KNOWN_SETUID_BINARIES: a known setgid binary that
# unexpectedly gains the setuid bit is still reported.
KNOWN_SETGID_BINARIES = frozenset({
    "/usr/bin/wall", "/usr/bin/write", "/usr/bin/write.ul", "/usr/bin/bsd-write",
    "/usr/bin/ssh-agent", "/usr/bin/chage", "/usr/bin/expiry", "/usr/bin/crontab",
    "/usr/sbin/unix_chkpwd", "/sbin/unix_chkpwd", "/usr/sbin/pam_extrausers_chkpwd",
    "/usr/bin/dotlockfile", "/usr/bin/mlocate", "/usr/bin/plocate",
    "/usr/lib/x86_64-linux-gnu/utempter/utempter",
    "/usr/lib/aarch64-linux-gnu/utempter/utempter",
    "/usr/libexec/camel-lock-helper-1.2", "/usr/bin/screen",
})

ALLOWED_NSS_MODULES = frozenset({
    "files", "compat", "systemd", "mymachines", "myhostname",
    "resolve", "dns", "nis", "nisplus", "db",
    "mdns", "mdns4", "mdns4_minimal", "mdns6", "mdns6_minimal",
    # Domain-joined/LDAP-integrated hosts: SSSD, LDAP, and Samba/Winbind are
    # extremely common on real Ubuntu fleets and are routine, not suspicious.
    "sss", "ldap", "winbind", "wins",
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


def _under(path: str, prefixes) -> bool:
    # Separator-bounded: "/usr/bin.evil/x" is NOT under "/usr/bin", and
    # "/var/tmpfiles" is NOT under "/var/tmp".
    return any(path == p or path.startswith(p + "/") for p in prefixes)


def path_in_standard_libs(path: str) -> bool:
    return _under(path, STANDARD_LIB_PATHS)


def path_in_standard_bins(path: str) -> bool:
    return _under(path, STANDARD_BIN_PATHS)


def path_in_writable_tmp(path: str) -> bool:
    return _under(path, WRITABLE_TMP_PATHS)


# A writable-tmp path appearing anywhere in a shell command line, as its own
# path (preceded by start/whitespace/quote/shell punctuation and followed by
# '/' or a delimiter), e.g. "bash /tmp/x.sh", "cd /dev/shm && ./a", ">/tmp/o".
_TMP_IN_COMMAND_RE = re.compile(
    r"""(?:^|[\s'"=:;|&(<>`])(?:/tmp|/var/tmp|/dev/shm)(?=$|[/\s'";|&)<>`])"""
)


def command_references_writable_tmp(command: str) -> bool:
    return bool(_TMP_IN_COMMAND_RE.search(command))
