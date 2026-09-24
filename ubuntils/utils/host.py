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


def get_hostname(source) -> Optional[str]:
    try:
        name = source.read_text("/etc/hostname").strip()
    except Exception:
        return None
    return name or None
