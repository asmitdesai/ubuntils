from ubuntils.bundle.manifest import Manifest, FileEntry, CommandEntry


class BundleError(Exception):
    """Raised when a bundle cannot be written or fails integrity verification."""


from ubuntils.bundle.writer import write_bundle
from ubuntils.bundle.reader import read_bundle


__all__ = ["Manifest", "FileEntry", "CommandEntry", "BundleError", "write_bundle", "read_bundle"]
