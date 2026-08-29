from __future__ import annotations

import hashlib
import json
import os
import tarfile
import tempfile

from ubuntils.bundle.manifest import Manifest, FileEntry, CommandEntry
from ubuntils.bundle import BundleError
from ubuntils.collectors.source import BundleSource


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_bundle(path: str) -> tuple:
    work = tempfile.mkdtemp(prefix="ubuntils_analyze_")
    with tarfile.open(path, "r:gz") as tf:
        tf.extractall(work)

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

    integrity = "ok"
    if expected_digest != manifest.manifest_sha256():
        integrity = "mismatch"
    else:
        for fe in manifest.files:
            if fe.sha256 == "":
                continue
            disk = os.path.join(base, fe.bundle_path)
            if not os.path.exists(disk) or _sha256_file(disk) != fe.sha256:
                integrity = "mismatch"
                break

    command_index = {
        c.name: os.path.join(base, c.bundle_path)
        for c in manifest.commands
    }
    source = BundleSource(root_dir=os.path.join(base, "files"), command_index=command_index)
    info = {"bundle_integrity": integrity, "manifest": stored, "bundle_sha256": expected_digest}
    return source, info
