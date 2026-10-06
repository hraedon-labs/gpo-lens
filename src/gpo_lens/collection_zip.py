"""Shared, bounded collector ZIP extraction for CLI and web ingestion.

Callers supply a private temporary destination. Partial content is removed on
failure, and the caller owns the destination's lifetime.
"""

from __future__ import annotations

import logging
import shutil
import stat
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

MAX_ARCHIVE_BYTES = 500 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1000
# Allow more than 20 times a measured large export (~5,400 files, depth <= 8).
# Directories include implicit parents, so empty files cannot exhaust inodes.
MAX_MEMBERS = 120_000
MAX_DIRECTORIES = 60_000
MAX_FILENAME_BYTES = 32 * 1024 * 1024
MAX_PATH_DEPTH = 24
_WINDOWS_DEVICES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"}
    | {f"{prefix}{suffix}" for prefix in ("COM", "LPT") for suffix in "123456789¹²³"}
)
_logger = logging.getLogger(__name__)


def safe_extract(
    zip_path: Path,
    dest: Path,
    *,
    max_archive_bytes: int = MAX_ARCHIVE_BYTES,
    max_uncompressed_bytes: int = MAX_UNCOMPRESSED_BYTES,
    max_ratio: int = MAX_COMPRESSION_RATIO,
) -> None:
    """Extract a zip to *dest* with defense-in-depth safety checks.

    Four layers of protection:
    1. Symlink check (pre-extract, from header ``external_attr``)
    2. Path traversal check (pre-extract, resolves member path)
    3. Streaming decompression size cap via :class:`SizeLimitedReader`
       — counts *actual* decompressed bytes, immune to ``file_size``
       header spoofing
    4. Post-extract symlink and path traversal re-check

    If any check fails (or an error occurs during extraction), all
    partially-extracted files and directories are removed from *dest*
    before the exception is re-raised, ensuring no tainted artifacts
    remain on disk.

    **Memory tradeoff:** Unlike :func:`~gpo_lens.ingest._streaming_zip_read`
    which buffers decompressed bytes in memory, this function writes
    directly to disk during extraction — no in-memory buffering of the
    full content.
    """
    from gpo_lens.ingest import SizeLimitedReader

    try:
        if zip_path.stat().st_size > max_archive_bytes:
            raise ValueError("zip archive size exceeds limit (500MB)")
        with zipfile.ZipFile(zip_path, "r") as zf:
            dest_root = dest.resolve()
            total_bytes_read = 0
            targets: set[str] = set()
            members = zf.infolist()
            if len(members) > MAX_MEMBERS:
                raise ValueError("zip member count exceeds limit")
            if sum(len(info.filename.encode("utf-8")) for info in members) > MAX_FILENAME_BYTES:
                raise ValueError("zip total filename bytes exceeds limit")
            directories: set[str] = set()
            # Preflight the entire directory before creating/opening anything.
            for info in members:
                parts = info.filename.replace("\\", "/").rstrip("/").split("/")
                if len(parts) > MAX_PATH_DEPTH:
                    raise ValueError("zip path depth exceeds limit")
                parent_count = (
                    len(parts) if info.is_dir() or info.filename.endswith("\\") else len(parts) - 1
                )
                for depth in range(1, parent_count + 1):
                    directories.add("/".join(parts[:depth]).casefold())
                if len(directories) > MAX_DIRECTORIES:
                    raise ValueError("zip directory count exceeds limit")
            for info in members:
                # Normalize before checking paths: Compress-Archive on PS 5.1
                # emits backslashes. Reject Windows drives, UNC and ADS paths
                # on every platform, including Linux.
                member = info.filename.replace("\\", "/")
                if member.startswith("/") or ":" in member or ".." in member.split("/"):
                    raise ValueError(f"zip-slip blocked: {info.filename}")
                components = member.removesuffix("/").split("/")
                if any(
                    not part
                    or part in {".", ".."}
                    or part.rstrip(" .") != part
                    or part.split(".", 1)[0].upper() in _WINDOWS_DEVICES
                    or any(ord(char) < 32 or char in '<>"|?*' for char in part)
                    for part in components
                ):
                    raise ValueError(f"zip-slip blocked: {info.filename}")
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ValueError(f"zip symlink blocked: {member}")
                if info.file_size > max_ratio * max(1, info.compress_size):
                    raise ValueError("zip compression ratio exceeds limit")
                target = (dest / member).resolve()
                if not target.is_relative_to(dest_root):
                    raise ValueError(f"zip-slip blocked: {member}")
                key = target.relative_to(dest_root).as_posix().casefold()
                if key in targets:
                    raise ValueError(f"zip duplicate path blocked: {member}")
                targets.add(key)
                if member.endswith("/"):
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src:
                    wrapped = SizeLimitedReader(src, max_uncompressed_bytes - total_bytes_read)
                    with open(target, "wb") as out:
                        while True:
                            chunk = wrapped.read(65536)
                            if not chunk:
                                break
                            out.write(chunk)
                    total_bytes_read += wrapped._total
                    if total_bytes_read > max_uncompressed_bytes:
                        raise ValueError("zip uncompressed size exceeds limit")
                if target.is_symlink():
                    raise ValueError(f"zip symlink blocked: {member}")
                extracted = target.resolve()
                if not extracted.is_relative_to(dest_root):
                    raise ValueError(f"zip-slip blocked: {member}")
    except BaseException:
        # Clean up any partially extracted files/dirs before re-raising.
        # Cleanup errors are warned, not raised, so the *original* extraction
        # failure (zip-slip, decompression bomb, symlink) propagates — without
        # this guard a failing ``rmtree`` would mask the root cause. The
        # outer ``iterdir`` guard is needed because ``dest`` may not exist
        # (extraction failed before any file was written) or may have been
        # removed mid-extraction by a concurrent process.
        if dest.is_dir():
            for child in dest.iterdir():
                try:
                    if child.is_symlink() or not child.is_dir():
                        child.unlink()
                    else:
                        shutil.rmtree(child)
                except OSError as cleanup_exc:
                    _logger.warning(
                        "cleanup of %s after extraction failure failed: %s",
                        child,
                        cleanup_exc,
                    )
        raise


def collector_root(dest: Path) -> Path:
    """Accept flat exports or a single wrapped folder; reject ambiguous estates."""
    reports = sorted(dest.rglob("AllGPOs.xml"))
    if len(reports) != 1:
        raise ValueError("Collector ZIP must contain exactly one AllGPOs.xml estate report")
    return reports[0].parent


@contextmanager
def collector_source(source: str | Path) -> Iterator[Path]:
    """Keep extracted files alive through parsing, persistence and evaluation."""
    path = Path(source)
    if path.is_dir() or path.suffix.lower() != ".zip":
        yield path
        return
    with TemporaryDirectory(prefix="gpo-lens-ingest-") as temporary:
        dest = Path(temporary)
        safe_extract(path, dest)
        yield collector_root(dest)
