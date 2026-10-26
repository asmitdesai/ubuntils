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
    "/usr/lib/polkit-1/polkit-agent-helper-1",  # polkit 124+ (Ubuntu 24.04)
    "/usr/lib/snapd/snap-confine", "/usr/lib/eject/dmcrypt-get-device",
    "/usr/lib/xorg/Xorg.wrap", "/usr/sbin/mount.nfs", "/usr/sbin/mount.cifs",
    "/usr/bin/vmware-user-suid-wrapper", "/usr/bin/traceroute6.iputils",
    # Ubuntu 25.10+/26.04 default to sudo-rs; the C sudo stays installed as sudo.ws
    "/usr/lib/cargo/bin/sudo", "/usr/lib/cargo/bin/su", "/usr/bin/sudo.ws",
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
    # Stock on Ubuntu cloud images: libnss-extrausers (Ubuntu Core and
    # minimized images) and Google OS Login (every Ubuntu image on GCE).
    "extrausers", "oslogin", "cache_oslogin",
    # libvirt's guest name resolution (libnss-libvirt).
    "libvirt", "libvirt_guest",
})

# Common built-in modules on stock Ubuntu server/desktop/VM hosts (networking,
# filesystem, virtualization, generic input/sound, x86 and arm64 crypto).
# Exact names only. Deliberately NOT exhaustive for hardware drivers (GPU,
# Wi-Fi chipsets, proprietary vendor modules) — see README caveat; responders
# on such hosts should allowlist their host's modules via --config.
ALLOWED_KERNEL_MODULES = frozenset({
    "overlay", "br_netfilter", "veth", "xt_conntrack", "xt_nat", "xt_tcpudp",
    "xt_MASQUERADE", "xt_addrtype", "xt_comment", "xt_mark", "xt_multiport",
    "iptable_filter", "iptable_nat", "ip_tables", "ip6_tables", "nf_conntrack",
    "nf_nat", "nf_defrag_ipv4", "nf_defrag_ipv6", "sch_fq_codel",
    "nf_tables", "nfnetlink", "tcp_diag", "udp_diag", "inet_diag", "qrtr",
    "binfmt_misc", "autofs4", "nls_iso8859_1", "efi_pstore", "dmi_sysfs",
    "acpi_tad", "ahci_platform", "cfg80211",
    "vboxdrv", "vboxnetflt", "vboxnetadp",
    "virtio_net", "virtio_blk", "virtio_pci", "virtio_ring",
    "virtio_gpu", "virtio_dma_buf", "virtio_console", "virtio_balloon", "virtio_rng",
    "virtio_scsi", "virtio_input", "virtiofs",
    "vsock", "vmw_vsock_virtio_transport", "vmw_vsock_virtio_transport_common",
    "hid", "hid_generic", "usbhid", "input_leds", "joydev",
    "snd", "soundcore", "snd_timer", "snd_pcm", "snd_hwdep", "snd_rawmidi",
    "snd_seq", "snd_seq_device", "snd_seq_dummy", "snd_seq_midi", "snd_seq_midi_event",
    "snd_hrtimer", "snd_hda_core", "snd_hda_codec", "snd_hda_codec_generic",
    "snd_hda_intel", "snd_intel_dspcfg",
    # arm64 crypto extensions (aarch64 hosts and VMs)
    "aes_neon_bs", "aes_neon_blk", "aes_ce_blk", "aes_ce_cipher", "ghash_ce",
    "polyval_ce", "sha1_ce", "sha2_ce", "sha3_ce", "sha512_ce", "sm4", "crct10dif_ce",
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
