from ubuntils.bundle.manifest import Manifest, FileEntry, CommandEntry


class BundleError(Exception):
    """Raised when a bundle cannot be written or fails integrity verification."""


__all__ = ["Manifest", "FileEntry", "CommandEntry", "BundleError"]
