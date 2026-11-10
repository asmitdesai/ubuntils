"""Host identity read through an ArtifactSource.

Reading these via the source (not the local filesystem) is what keeps an
offline `analyze` from stamping the analyst's own OS/hostname on a report
about a different machine.
"""
from __future__ import annotations

from typing import Optional

OS_RELEASE_PATHS = ("/etc/os-release", "/usr/lib/os-release")


def _local_source():
    from ubuntils.collectors.source import LiveSource
    return LiveSource(root="/")


def get_ubuntu_version(source=None) -> str:
    source = source if source is not None else _local_source()
    for path in OS_RELEASE_PATHS:
        try:
            text = source.read_text(path)
        except Exception:
            continue
        for line in text.splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    return "Unknown"


MACHINE_ID_PATHS = ("/etc/machine-id", "/var/lib/dbus/machine-id")
# Salted so the report never carries the raw machine-id, which other software
# uses as a secret-ish identifier (it's documented as "should not be exposed").
_HOST_ID_SALT = b"ubuntils-host-id-v1\0"


def get_host_id(source) -> str:
    """A stable, non-reversible host ID from the machine-id (E4-S4, R-10), or
    "" when the host has none."""
    import hashlib
    for path in MACHINE_ID_PATHS:
        try:
            machine_id = source.read_text(path).strip()
        except Exception:
            continue
        if machine_id:
            return hashlib.sha256(_HOST_ID_SALT + machine_id.encode()).hexdigest()[:32]
    return ""


def get_hostname(source) -> Optional[str]:
    try:
        name = source.read_text("/etc/hostname").strip()
    except Exception:
        return None
    return name or None
