"""utils/safe_path.py: every branch, with real symlinks and directory swaps.

This module is what stops root's remediation writes from following a symlink
an attacker swaps into any path component (F-04). It must be fully covered,
and the tests use the real filesystem wherever it can produce the condition.
Patching is used only where a kernel can't be made to produce the case on
demand, and each patch says why.
"""
import errno
import os
import stat

import pytest

from ubuntils.utils import safe_path as sp
from ubuntils.utils.safe_path import UnsafePathError


@pytest.fixture
def root(tmp_path):
    # realpath: on macOS tmp_path sits under /var, itself a symlink to
    # /private/var, which open_dir_nofollow (correctly) refuses.
    return os.path.realpath(str(tmp_path))


def _close(fd):
    os.close(fd)


# ── open_dir_nofollow ─────────────────────────────────────────────────────────

def test_relative_and_dotdot_paths_are_refused(root):
    with pytest.raises(UnsafePathError, match="not an absolute path"):
        sp.open_dir_nofollow("etc")
    with pytest.raises(UnsafePathError, match="'..' is not allowed"):
        sp.open_dir_nofollow(root + "/a/../b")


def test_dot_components_are_skipped(root):
    os.mkdir(os.path.join(root, "d"))
    fd = sp.open_dir_nofollow(root + "/./d/.")
    try:
        assert sp.dir_identity(fd)[:2] == (os.stat(root + "/d").st_dev, os.stat(root + "/d").st_ino)
    finally:
        _close(fd)


def test_symlink_in_a_middle_component_is_refused(root):
    os.makedirs(os.path.join(root, "real", "inner"))
    os.symlink(os.path.join(root, "real"), os.path.join(root, "link"))
    with pytest.raises(UnsafePathError, match="link is a symlink or not a directory"):
        sp.open_dir_nofollow(root + "/link/inner")


def test_symlink_as_the_last_component_is_refused(root):
    os.mkdir(os.path.join(root, "real"))
    os.symlink(os.path.join(root, "real"), os.path.join(root, "link"))
    with pytest.raises(UnsafePathError):
        sp.open_dir_nofollow(root + "/link")


def test_regular_file_component_is_refused(root):
    open(os.path.join(root, "f"), "w").close()
    with pytest.raises(UnsafePathError):
        sp.open_dir_nofollow(root + "/f")


def test_fd_that_is_not_a_directory_is_refused_and_closed(root, monkeypatch):
    # With O_PATH|O_NOFOLLOW some kernels hand back an fd for the symlink
    # itself instead of failing. No filesystem here does that on demand, so
    # fstat reports a non-directory for the walked component.
    os.mkdir(os.path.join(root, "d"))
    real_fstat = os.fstat
    seen = []

    def fake_fstat(fd):
        st = real_fstat(fd)
        seen.append(fd)
        return os.stat_result((stat.S_IFREG | 0o644,) + tuple(st)[1:])

    monkeypatch.setattr(sp.os, "fstat", fake_fstat)
    with pytest.raises(UnsafePathError, match="is not a directory"):
        sp.open_dir_nofollow(root + "/d")
    with pytest.raises(OSError):
        real_fstat(seen[-1])  # the fd we were handed was closed, not leaked


def test_held_directory_fd_survives_a_parent_swap(root):
    """The F-04 attack: after we open ~/.ssh, the attacker renames it and puts
    a symlink to someone else's .ssh in its place. Work through the held fd
    must still land in the original directory."""
    victim = os.path.join(root, "home", "alice", ".ssh")
    admin = os.path.join(root, "home", "admin", ".ssh")
    os.makedirs(victim)
    os.makedirs(admin)
    with open(os.path.join(victim, "authorized_keys"), "w") as f:
        f.write("alice-key\n")
    with open(os.path.join(admin, "authorized_keys"), "w") as f:
        f.write("admin-key\n")

    fd = sp.open_dir_nofollow(victim)
    try:
        os.rename(victim, victim + ".moved")
        os.symlink(admin, victim)
        data, _ = sp.read_file_at(fd, "authorized_keys")
        assert data == b"alice-key\n"
        sp.replace_at(fd, "authorized_keys", b"", 0o600, os.geteuid(), os.getegid())
    finally:
        _close(fd)
    assert open(os.path.join(admin, "authorized_keys")).read() == "admin-key\n"
    assert open(os.path.join(victim + ".moved", "authorized_keys")).read() == ""
    # And a fresh walk now refuses the swapped-in symlink outright.
    with pytest.raises(UnsafePathError):
        sp.open_dir_nofollow(victim)


# ── open_parent ───────────────────────────────────────────────────────────────

def test_open_parent_returns_the_directory_and_name(root):
    os.mkdir(os.path.join(root, "d"))
    fd, name = sp.open_parent(root + "/d/file")
    try:
        assert name == "file"
        assert sp.dir_identity(fd)[1] == os.stat(root + "/d").st_ino
    finally:
        _close(fd)


def test_open_parent_of_the_root_has_no_name():
    with pytest.raises(UnsafePathError, match="has no file name"):
        sp.open_parent("/")


# ── read_file_at ──────────────────────────────────────────────────────────────

def test_read_file_at_returns_content_and_stat(root):
    with open(os.path.join(root, "f"), "wb") as f:
        f.write(b"data")
    fd = sp.open_dir_nofollow(root)
    try:
        data, st = sp.read_file_at(fd, "f")
    finally:
        _close(fd)
    assert data == b"data" and stat.S_ISREG(st.st_mode) and st.st_size == 4


def test_read_file_at_refuses_a_symlink(root):
    secret = os.path.join(root, "secret")
    with open(secret, "w") as f:
        f.write("root-only")
    os.symlink(secret, os.path.join(root, "authorized_keys"))
    fd = sp.open_dir_nofollow(root)
    try:
        with pytest.raises(UnsafePathError, match="is a symlink"):
            sp.read_file_at(fd, "authorized_keys")
    finally:
        _close(fd)


def test_read_file_at_refuses_a_fifo_without_blocking(root):
    os.mkfifo(os.path.join(root, "pipe"))
    fd = sp.open_dir_nofollow(root)
    try:
        with pytest.raises(UnsafePathError, match="not a regular file"):
            sp.read_file_at(fd, "pipe")
    finally:
        _close(fd)


def _open_fds():
    for d in ("/dev/fd", "/proc/self/fd"):
        if os.path.isdir(d):
            return len(os.listdir(d))
    return None


def test_read_file_at_refuses_a_directory_and_closes_its_fd(root):
    # Regression: fdopen() of a directory raised IsADirectoryError before the
    # regular-file check, and the descriptor leaked.
    os.mkdir(os.path.join(root, "sub"))
    fd = sp.open_dir_nofollow(root)
    try:
        before = _open_fds()
        for _ in range(5):
            with pytest.raises(UnsafePathError, match="not a regular file"):
                sp.read_file_at(fd, "sub")
        assert _open_fds() == before
    finally:
        _close(fd)


def test_read_file_at_missing_file_is_file_not_found(root):
    fd = sp.open_dir_nofollow(root)
    try:
        with pytest.raises(FileNotFoundError):
            sp.read_file_at(fd, "nope")
    finally:
        _close(fd)


def test_read_file_at_other_open_errors_propagate_unchanged(root, monkeypatch):
    # A permission error on a regular file must surface as itself, not be
    # reported as a symlink. chmod 000 doesn't stop root (CI containers run
    # as root), so the open is made to fail with EACCES directly.
    open(os.path.join(root, "f"), "w").close()
    fd = sp.open_dir_nofollow(root)

    def deny(*a, **k):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(sp.os, "open", deny)
    try:
        with pytest.raises(PermissionError) as info:
            sp.read_file_at(fd, "f")
        assert not isinstance(info.value, UnsafePathError)
    finally:
        monkeypatch.undo()
        _close(fd)


# ── create_exclusive_at ───────────────────────────────────────────────────────

def test_create_exclusive_at_writes_with_the_mode(root):
    fd = sp.open_dir_nofollow(root)
    try:
        sp.create_exclusive_at(fd, "new", b"x", 0o640)
    finally:
        _close(fd)
    st = os.stat(os.path.join(root, "new"))
    assert open(os.path.join(root, "new"), "rb").read() == b"x"
    assert stat.S_IMODE(st.st_mode) == 0o640


def test_create_exclusive_at_never_reuses_a_file_or_a_planted_link(root):
    open(os.path.join(root, "exists"), "w").close()
    os.symlink(os.path.join(root, "target"), os.path.join(root, "planted"))
    fd = sp.open_dir_nofollow(root)
    try:
        with pytest.raises(FileExistsError):
            sp.create_exclusive_at(fd, "exists", b"x")
        with pytest.raises(FileExistsError):
            sp.create_exclusive_at(fd, "planted", b"x")
    finally:
        _close(fd)
    assert not os.path.exists(os.path.join(root, "target"))


# ── replace_at ────────────────────────────────────────────────────────────────

def _entries(root):
    return sorted(os.listdir(root))


def test_replace_at_replaces_atomically_with_mode_and_leaves_no_temp(root):
    path = os.path.join(root, "f")
    with open(path, "w") as f:
        f.write("old")
    fd = sp.open_dir_nofollow(root)
    try:
        sp.replace_at(fd, "f", b"new", 0o100640, os.geteuid(), os.getegid())
    finally:
        _close(fd)
    assert open(path).read() == "new"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o640
    assert _entries(root) == ["f"]


def test_replace_at_replaces_a_swapped_in_symlink_never_its_target(root):
    target = os.path.join(root, "shadow")
    with open(target, "w") as f:
        f.write("root:hash")
    os.symlink(target, os.path.join(root, "f"))
    fd = sp.open_dir_nofollow(root)
    try:
        sp.replace_at(fd, "f", b"new", 0o600, os.geteuid(), os.getegid())
    finally:
        _close(fd)
    assert open(target).read() == "root:hash"
    assert not os.path.islink(os.path.join(root, "f"))
    assert open(os.path.join(root, "f")).read() == "new"


def test_replace_at_changes_owner_when_asked(root):
    path = os.path.join(root, "f")
    open(path, "w").close()
    other_uid, other_gid = os.geteuid() + 1, os.getegid() + 1
    fd = sp.open_dir_nofollow(root)
    try:
        if os.geteuid() == 0:
            sp.replace_at(fd, "f", b"x", 0o600, other_uid, other_gid)
            assert (os.stat(path).st_uid, os.stat(path).st_gid) == (other_uid, other_gid)
        else:
            # Without root, fchown to another user fails; the original must
            # be untouched and the temp file gone.
            with pytest.raises(PermissionError):
                sp.replace_at(fd, "f", b"x", 0o600, other_uid, other_gid)
            assert open(path).read() == ""
            assert _entries(root) == ["f"]
    finally:
        _close(fd)


def test_replace_at_failure_removes_the_temp_and_keeps_the_original(root):
    # rename() of a file over a non-empty directory fails for every user.
    os.makedirs(os.path.join(root, "d", "child"))
    fd = sp.open_dir_nofollow(root)
    try:
        with pytest.raises(OSError):
            sp.replace_at(fd, "d", b"x", 0o600, os.geteuid(), os.getegid())
    finally:
        _close(fd)
    assert _entries(root) == ["d"]
    assert os.listdir(os.path.join(root, "d")) == ["child"]


def test_replace_at_cleanup_failure_still_raises_the_original_error(root, monkeypatch):
    # If the temp file can't be removed during cleanup, the error that
    # matters (the failed rename) must still be what the caller sees.
    os.makedirs(os.path.join(root, "d", "child"))
    fd = sp.open_dir_nofollow(root)

    def no_unlink(*a, **k):
        raise PermissionError(errno.EPERM, "unlink refused")

    monkeypatch.setattr(sp.os, "unlink", no_unlink)
    try:
        with pytest.raises(OSError) as info:
            sp.replace_at(fd, "d", b"x", 0o600, os.geteuid(), os.getegid())
        assert "unlink refused" not in str(info.value)
    finally:
        monkeypatch.undo()
        _close(fd)


def test_replace_at_retries_a_temp_name_that_already_exists(root, monkeypatch):
    names = iter(["aaaa", "aaaa", "bbbb"])
    monkeypatch.setattr(sp.secrets, "token_hex", lambda n: next(names))
    fd = sp.open_dir_nofollow(root)
    try:
        open(os.path.join(root, "f"), "w").close()
        open(os.path.join(root, ".ubuntils-aaaa"), "w").close()  # an attacker's file
        sp.replace_at(fd, "f", b"new", 0o600, os.geteuid(), os.getegid())
    finally:
        _close(fd)
    assert open(os.path.join(root, "f")).read() == "new"
    assert open(os.path.join(root, ".ubuntils-aaaa")).read() == ""  # never written


def test_replace_at_gives_up_after_100_collisions(root, monkeypatch):
    monkeypatch.setattr(sp.secrets, "token_hex", lambda n: "same")
    open(os.path.join(root, ".ubuntils-same"), "w").close()
    fd = sp.open_dir_nofollow(root)
    try:
        with pytest.raises(FileExistsError, match="could not create a temporary file"):
            sp.replace_at(fd, "f", b"x", 0o600, os.geteuid(), os.getegid())
    finally:
        _close(fd)


def test_sha256_hex():
    assert sp.sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
