"""Content-addressed evidence store on disk.

Files live at <evidence_dir>/<sha[:2]>/<sha>. The path is derived only from
the content hash, never from an uploader-supplied filename, so there is no
path traversal surface and identical uploads dedupe for free. The original
filename is kept in the DB as untrusted display text.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

# Magic-byte sniffing for the few image types we're willing to serve inline.
# Anything else (including SVG, which can carry script) is served as a download.
_IMAGE_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
)


def store(evidence_dir: Path, content: bytes) -> tuple[str, str]:
    """Write content (if new) and return (sha256, path relative to evidence_dir)."""
    sha = hashlib.sha256(content).hexdigest()
    rel = f"{sha[:2]}/{sha}"
    dest = evidence_dir / rel
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        # Write to a temp file in the same dir, then atomically rename, so a
        # crash mid-write never leaves a truncated file under a valid hash.
        fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(content)
            os.replace(tmp, dest)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
    return sha, rel


def sweep_orphans(evidence_dir: Path, referenced: set[str]) -> int:
    """Delete on-disk blobs no evidence row points at. Returns count removed.

    Content is addressed by sha256 and deduped, so a blob is removed only when
    *no* surviving evidence row references its relative path — deleting one of
    two rows that share a file keeps the file. Called after deletes/cascades.
    """
    removed = 0
    if not evidence_dir.exists():
        return 0
    for sub in evidence_dir.iterdir():
        if not sub.is_dir():
            continue
        for f in sub.iterdir():
            rel = f"{sub.name}/{f.name}"
            if rel not in referenced:
                f.unlink(missing_ok=True)
                removed += 1
    return removed


def resolve(evidence_dir: Path, rel: str) -> Path:
    """Map a stored relative path back to an absolute one, refusing escapes."""
    base = evidence_dir.resolve()
    p = (base / rel).resolve()
    if base not in p.parents:
        raise ValueError(f"evidence path escapes store: {rel!r}")
    return p


def sniff_image_type(head: bytes) -> str | None:
    """Return an image MIME type if `head` starts with a known raster signature."""
    for magic, mime in _IMAGE_MAGIC:
        if head.startswith(magic):
            return mime
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    return None
