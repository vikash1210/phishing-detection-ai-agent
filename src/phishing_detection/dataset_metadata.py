
"""Record dataset provenance and verify file integrity."""

from __future__ import annotations

import hashlib
from pathlib import Path


def calculate_sha256(path: str | Path) -> str:
    """Return the SHA-256 checksum of a file.

    Reading the file in chunks keeps memory usage predictable for large datasets.
    The checksum helps detect whether a dataset file has changed.
    """
    file_path = Path(path)

    # Read the file in chunks instead of loading the entire dataset into memory.
    digest = hashlib.sha256()
    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()
