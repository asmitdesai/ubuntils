from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import tempfile

from ubuntils.bundle.manifest import Manifest, FileEntry, CommandEntry
from ubuntils.bundle import BundleError
from ubuntils.collectors.source import BUNDLE_READ_MAX_BYTES, BundleSource

# A bundle is untrusted input: a few KB of gzip can declare millions of
# members or terabytes of zeros. Real bundles hold a few dozen files and
# well under 1 GiB (journalctl output is the big one).
MAX_BUNDLE_MEMBERS = 10_000
MAX_MEMBER_BYTES = BUNDLE_READ_MAX_BYTES  # 512 MiB
MAX_BUNDLE_BYTES = 2 * 1024 * 1024 * 1024


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_extract(tf: tarfile.TarFile, work: str) -> None:
    """Validate every tar member before extraction.

    Rejects members whose resolved destination would escape ``work`` (path
    traversal via e.g. "../../ESCAPED.txt") and members that are not plain
    files or directories (symlinks, hardlinks, device/fifo nodes, etc.) — a
    forensic bundle should never legitimately contain those.
    """
    work_real = os.path.realpath(work)
    # Iterate rather than getmembers(): each header is checked before
    # tarfile decompresses its way past that member's data to the next one.
    count = total = 0
    for member in tf:
        count += 1
        total += max(member.size, 0)
        if count > MAX_BUNDLE_MEMBERS:
            raise BundleError(f"bundle has more than {MAX_BUNDLE_MEMBERS} members — refusing")
        if member.size > MAX_MEMBER_BYTES:
            raise BundleError(f"bundle member {member.name!r} declares {member.size} bytes "
                              f"(limit {MAX_MEMBER_BYTES}) — refusing")
        if total > MAX_BUNDLE_BYTES:
            raise BundleError(f"bundle contents exceed {MAX_BUNDLE_BYTES} bytes — refusing")
        dest = os.path.realpath(os.path.join(work, member.name))
        if dest != work_real and not dest.startswith(work_real + os.sep):
            raise BundleError(
                f"bundle member {member.name!r} would extract outside the "
                f"target directory (path traversal)"
            )
        if not (member.isfile() or member.isdir()):
            raise BundleError(
                f"bundle member {member.name!r} is not a regular file or "
                f"directory (type={member.type!r}) — refusing to extract"
            )

    try:
        tf.extractall(work, filter="data")
    except TypeError:
        # Python < 3.12 (or a tarfile shim) without the `filter` kwarg —
        # the manual member validation above is the primary defense here.
        tf.extractall(work)


def _inside(base: str, bundle_path: str) -> str:
    """Absolute path of a manifest entry, which must stay inside the bundle.
    The manifest is attacker-controlled when analyzing a hostile host's bundle,
    and its digest is unkeyed — it can't be trusted to name safe paths."""
    base_real = os.path.realpath(base)
    resolved = os.path.realpath(os.path.join(base_real, bundle_path))
    if not resolved.startswith(base_real + os.sep):
        raise BundleError(f"manifest entry {bundle_path!r} points outside the bundle")
    return resolved


def _unaccounted_files(base: str, manifest: Manifest) -> list:
    """Files on disk the manifest doesn't vouch for: not listed at all (an
    injected files/etc/cron.d/x), or listed as absent at collection time
    (sha256 "") yet present (an injected files/etc/ld.so.preload). Hashes
    only cover what's listed, so either would otherwise be analyzed as if it
    came from the host."""
    vouched = {os.path.normpath(e.bundle_path)
               for e in [*manifest.files, *manifest.commands]
               if getattr(e, "sha256", "") != "" or isinstance(e, CommandEntry)}
    extra = []
    for top in ("files", "commands"):
        for dirpath, _dirs, names in os.walk(os.path.join(base, top)):
            for name in names:
                rel = os.path.normpath(os.path.relpath(os.path.join(dirpath, name), base))
                if rel not in vouched:
                    extra.append(rel)
    return extra


def read_bundle(path: str) -> tuple:
    """Extract and verify a bundle. The returned BundleSource owns the
    extraction directory — callers must call ``source.cleanup()`` when done."""
    work = tempfile.mkdtemp(prefix="ubuntils_analyze_")
    try:
        return _read_extracted(path, work)
    except BaseException:
        shutil.rmtree(work, ignore_errors=True)
        raise


def _read_extracted(path: str, work: str) -> tuple:
    with tarfile.open(path, "r:gz") as tf:
        _safe_extract(tf, work)

    base = os.path.join(work, "bundle")
    manifest_path = os.path.join(base, "manifest.json")
    if not os.path.exists(manifest_path):
        raise BundleError(f"no manifest.json in bundle {path}")

    with open(manifest_path, encoding="utf-8") as f:
        stored = json.load(f)

    expected_digest = stored.pop("bundle_sha256", None)
    manifest = Manifest(
        run_id=stored["run_id"], host_id=stored["host_id"], hostname=stored["hostname"],
        ubuntu_version=stored["ubuntu_version"],
        collected_at_utc_start=stored["collected_at_utc_start"],
        collected_at_utc_end=stored["collected_at_utc_end"],
        tool_version=stored["tool_version"],
        files=[FileEntry(**e) for e in stored["files"]],
        commands=[CommandEntry(**c) for c in stored["commands"]],
    )
    for entry in [*manifest.files, *manifest.commands]:
        _inside(base, entry.bundle_path)

    integrity = "ok"
    if expected_digest != manifest.manifest_sha256():
        integrity = "mismatch"
    else:
        captured = [(fe.bundle_path, fe.sha256) for fe in manifest.files if fe.sha256 != ""]
        # Command outputs are hashed at collection time too — a tampered
        # dpkg_verify.txt must fail verification just like a tampered file.
        captured += [(ce.bundle_path, ce.sha256) for ce in manifest.commands]
        for bundle_path, digest in captured:
            disk = os.path.join(base, bundle_path)
            if not os.path.exists(disk) or _sha256_file(disk) != digest:
                integrity = "mismatch"
                break
        if integrity == "ok" and _unaccounted_files(base, manifest):
            integrity = "mismatch"

    command_index = {
        c.name: (os.path.join(base, c.bundle_path), c.exit_code)
        for c in manifest.commands
    }
    file_times = {fe.source_path: (fe.mtime, fe.ctime) for fe in manifest.files if fe.sha256 != ""}
    source = BundleSource(root_dir=os.path.join(base, "files"), command_index=command_index,
                          cleanup_dir=work, file_times=file_times)
    info = {"bundle_integrity": integrity, "manifest": stored, "bundle_sha256": expected_digest}
    return source, info
