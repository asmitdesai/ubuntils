from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import uuid
from datetime import datetime, timezone

from ubuntils.bundle.manifest import Manifest, FileEntry, CommandEntry
from ubuntils.collectors.packages import DPKG_VERIFY_TIMEOUT, FIND_SETUID_TIMEOUT
from ubuntils.collectors.source import ArtifactSource

# Per-command timeouts for `collect`'s bundle-capture step. MUST match the
# timeouts PackageCollector uses live (see collectors/packages.py) — a bundle
# captures the exact same commands, so a mismatch here would mean `collect`
# times out (or wastes time) differently than a live `scan` for the same
# command. Any command not listed here uses the ArtifactSource.run default (30s).
COMMAND_TIMEOUTS: dict = {
    "dpkg_verify": DPKG_VERIFY_TIMEOUT,
    "find_setuid": FIND_SETUID_TIMEOUT,
}


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _restrict_tarinfo_permissions(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo:
    """Force restrictive permissions on every entry written into the archive
    (a bundle can contain /etc/shadow — it must not be world-readable inside
    the tarball, regardless of the staging directory's own permissions)."""
    tarinfo.mode = 0o700 if tarinfo.isdir() else 0o600
    return tarinfo


def write_bundle(
    source: ArtifactSource,
    files_to_capture: list,
    commands_to_capture: list,
    out_path: str,
    *,
    metadata: dict,
) -> str:
    start = datetime.now(timezone.utc).isoformat()
    work = tempfile.mkdtemp(prefix="ubuntils_collect_")
    try:
        files_dir = os.path.join(work, "files")
        cmds_dir = os.path.join(work, "commands")
        os.makedirs(files_dir, exist_ok=True)
        os.makedirs(cmds_dir, exist_ok=True)

        file_entries = []
        for path in files_to_capture:
            bundle_rel = os.path.join("files", path.lstrip("/"))
            dest = os.path.join(work, bundle_rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            try:
                data = source.read_bytes(path)
                st = source.lstat(path)
                with open(dest, "wb") as f:
                    f.write(data)
                file_entries.append(FileEntry(
                    source_path=path, bundle_path=bundle_rel, sha256=_sha256_bytes(data),
                    size=len(data), mtime=st.st_mtime, ctime=st.st_ctime,
                ))
            except (OSError, ValueError):
                # File absent/unreadable — record absence, do not abort.
                file_entries.append(FileEntry(
                    source_path=path, bundle_path=bundle_rel, sha256="", size=-1,
                    mtime=0.0, ctime=0.0,
                ))

        command_entries = []
        for name, argv in commands_to_capture:
            stdout, _stderr, code = source.run(name, argv, timeout=COMMAND_TIMEOUTS.get(name, 30))
            bundle_rel = os.path.join("commands", f"{name}.txt")
            dest = os.path.join(work, bundle_rel)
            data = stdout.encode("utf-8")
            with open(dest, "wb") as f:
                f.write(data)
            command_entries.append(CommandEntry(
                name=name, argv=argv, bundle_path=bundle_rel,
                sha256=_sha256_bytes(data), exit_code=code,
            ))

        manifest = Manifest(
            run_id=str(uuid.uuid4()),
            host_id=metadata.get("host_id", ""),
            hostname=metadata.get("hostname", ""),
            ubuntu_version=metadata.get("ubuntu_version", ""),
            collected_at_utc_start=start,
            collected_at_utc_end=datetime.now(timezone.utc).isoformat(),
            tool_version=metadata.get("tool_version", ""),
            files=file_entries,
            commands=command_entries,
        )
        manifest_dict = manifest.to_dict()
        manifest_dict["bundle_sha256"] = manifest.manifest_sha256()

        with open(os.path.join(work, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest_dict, f, indent=2, sort_keys=True)

        # Create the archive with owner-only permissions up front — the default
        # umask-derived mode (typically 0644) would otherwise make a bundle
        # containing /etc/shadow world-readable the instant it's created.
        fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.chmod(out_path, 0o600)
        with os.fdopen(fd, "wb") as fh:
            with tarfile.open(fileobj=fh, mode="w:gz") as tf:
                tf.add(work, arcname="bundle", filter=_restrict_tarinfo_permissions)

        return out_path
    finally:
        # Always clean up the staging directory to prevent sensitive data
        # from persisting unencrypted in /tmp after collection.
        shutil.rmtree(work, ignore_errors=True)
