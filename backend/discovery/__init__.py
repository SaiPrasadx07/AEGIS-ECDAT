"""
Aegis PQC — discovery adapters.

Every discovery surface named in PS 26164 — source repositories, dependency
manifests, binaries, container images, certificate and key files — is
implemented as an adapter behind one interface, producing the canonical
:class:`~backend.model.CryptoFinding`.

THE INTERFACE ENFORCES TWO THINGS
---------------------------------
**Coverage honesty.** :meth:`DiscoveryAdapter.coverage` is part of the
protocol, not documentation. An adapter must state what it does *not* detect,
and the dashboard renders that alongside its results. This makes "we do not
scan everything" structural rather than a promise someone remembers to keep.

**Safety limits.** Aegis analyses artefacts that may be hostile — a repository
under review, an uploaded archive, an unknown binary. :class:`ScanLimits`
carries the bounds every adapter must respect, and :func:`safe_walk` applies
them centrally so no adapter has to reimplement traversal safety.

A rule with no exceptions: **adapters never execute what they scan.** Source is
parsed, never imported or run. Binaries are inspected, never loaded. Archives
are extracted under containment, never trusted.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Protocol, runtime_checkable

from backend.model import CoverageStatement, ScanResult

# ==========================================================================
# Limits
# ==========================================================================


@dataclass(slots=True)
class ScanLimits:
    """Bounds applied to every scan.

    Defaults are sized for a demonstration estate and a laptop. They exist to
    stop three specific failures: a scan that never terminates during a live
    demo, a decompression bomb, and a traversal that escapes the scan root.

    Attributes:
        max_file_bytes: Skip any single file larger than this.
        max_total_bytes: Abort once cumulative examined bytes exceed this.
        max_files: Abort after this many files.
        max_depth: Maximum directory depth below the scan root.
        follow_symlinks: Never enable for untrusted input. A symlink to ``/``
            turns a bounded scan into a filesystem crawl.
        timeout_seconds: Wall-clock ceiling for a single adapter run.
        skip_directories: Directory names never descended into.
    """

    max_file_bytes: int = 8 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024
    max_files: int = 20_000
    max_depth: int = 25
    follow_symlinks: bool = False
    timeout_seconds: float = 120.0
    skip_directories: frozenset[str] = frozenset(
        {
            ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
            ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".idea",
            ".gradle", "target", ".next", ".cache",
        }
    )


@dataclass(slots=True)
class WalkStats:
    """What a traversal actually did, including what it refused to do.

    Returned alongside findings so the UI can report skips rather than
    presenting a truncated scan as a complete one.
    """

    files_examined: int = 0
    bytes_examined: int = 0
    skipped_too_large: int = 0
    skipped_symlink: int = 0
    skipped_unreadable: int = 0
    limit_reached: str = ""

    def notes(self) -> list[str]:
        """Human-readable notes for any non-empty skip category."""
        out: list[str] = []
        if self.skipped_too_large:
            out.append(f"{self.skipped_too_large} file(s) skipped: exceeded size limit")
        if self.skipped_symlink:
            out.append(f"{self.skipped_symlink} symlink(s) skipped")
        if self.skipped_unreadable:
            out.append(f"{self.skipped_unreadable} file(s) skipped: unreadable")
        if self.limit_reached:
            out.append(f"Scan stopped early: {self.limit_reached}")
        return out


# ==========================================================================
# Safe traversal
# ==========================================================================


def is_within(root: Path, candidate: Path) -> bool:
    """True if ``candidate`` resolves inside ``root``.

    The containment check for every path Aegis touches. Resolving both sides
    first is what defeats ``../`` sequences and symlinks that point outward —
    comparing unresolved strings would not.
    """
    try:
        root_resolved = root.resolve(strict=False)
        candidate_resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    try:
        candidate_resolved.relative_to(root_resolved)
        return True
    except ValueError:
        return False


def safe_walk(
    root: Path,
    limits: ScanLimits,
    suffixes: frozenset[str] | None = None,
    filenames: frozenset[str] | None = None,
) -> Iterator[tuple[Path, WalkStats]]:
    """Walk ``root`` under the given limits, yielding files that pass.

    Applied centrally so every adapter inherits identical traversal safety.
    Guards, in order: symlinks are refused, escapes from the root are refused,
    oversized files are skipped, and the file/byte/depth ceilings abort the walk
    with the reason recorded.

    Args:
        root: Directory to scan.
        limits: Bounds to enforce.
        suffixes: If given, only files with these lowercase suffixes.
        filenames: If given, also match these exact filenames regardless of
            suffix — needed for manifests like ``pom.xml`` and ``go.mod``.

    Yields:
        ``(path, stats)`` where ``stats`` is the live, mutating walk record.
    """
    stats = WalkStats()
    root = Path(root)
    if not root.exists():
        return

    if root.is_file():
        if _accepts(root, suffixes, filenames):
            size = _safe_size(root, stats)
            if size is not None and size <= limits.max_file_bytes:
                stats.files_examined += 1
                stats.bytes_examined += size
                yield root, stats
        return

    root_depth = len(root.resolve(strict=False).parts)

    for dirpath, dirnames, files in os.walk(root, followlinks=False):
        current = Path(dirpath)

        # Prune skip-listed and hidden directories in place — os.walk honours
        # mutation of dirnames, which avoids descending into them at all.
        dirnames[:] = [
            d for d in dirnames
            if d not in limits.skip_directories and not d.startswith(".")
        ]

        if len(current.resolve(strict=False).parts) - root_depth > limits.max_depth:
            dirnames[:] = []
            continue

        for name in sorted(files):
            path = current / name

            if not _accepts(path, suffixes, filenames):
                continue

            if path.is_symlink():
                stats.skipped_symlink += 1
                continue

            if not is_within(root, path):
                stats.skipped_symlink += 1
                continue

            size = _safe_size(path, stats)
            if size is None:
                continue
            if size > limits.max_file_bytes:
                stats.skipped_too_large += 1
                continue

            if stats.files_examined >= limits.max_files:
                stats.limit_reached = f"file limit ({limits.max_files}) reached"
                return
            if stats.bytes_examined + size > limits.max_total_bytes:
                stats.limit_reached = f"total size limit ({limits.max_total_bytes} bytes) reached"
                return

            stats.files_examined += 1
            stats.bytes_examined += size
            yield path, stats


def _accepts(path: Path, suffixes: frozenset[str] | None, filenames: frozenset[str] | None) -> bool:
    """Whether a path matches the requested suffix or filename filters."""
    if suffixes is None and filenames is None:
        return True
    if filenames and path.name in filenames:
        return True
    if suffixes and path.suffix.lower() in suffixes:
        return True
    return False


def _safe_size(path: Path, stats: WalkStats) -> int | None:
    """File size, or ``None`` if it cannot be read. Records the skip."""
    try:
        return path.stat().st_size
    except OSError:
        stats.skipped_unreadable += 1
        return None


def read_bytes_safely(path: Path, limits: ScanLimits) -> bytes | None:
    """Read a file, returning ``None`` instead of raising on any failure.

    Adapters run across estates containing unreadable, locked, and malformed
    files. A scanner that dies on the first bad file is useless, so failure is
    a normal, reported outcome rather than an exception.
    """
    try:
        if path.stat().st_size > limits.max_file_bytes:
            return None
        return path.read_bytes()
    except (OSError, ValueError):
        return None


def read_text_safely(path: Path, limits: ScanLimits) -> str | None:
    """Read a file as UTF-8 text with replacement, or ``None`` on failure."""
    raw = read_bytes_safely(path, limits)
    if raw is None:
        return None
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


# ==========================================================================
# Adapter protocol
# ==========================================================================


@runtime_checkable
class DiscoveryAdapter(Protocol):
    """Contract every discovery surface implements.

    Implementations must be side-effect free with respect to the target: read
    only, never execute, never modify.
    """

    name: str

    def coverage(self) -> CoverageStatement:
        """What this adapter detects, and what it explicitly does not."""
        ...

    def supports(self, target: Path) -> bool:
        """Whether this adapter can meaningfully scan ``target``."""
        ...

    def scan(self, target: Path, scan_id: str, limits: ScanLimits) -> ScanResult:
        """Scan ``target`` and return findings plus coverage and errors."""
        ...


#: Adapter registry, populated by each adapter module at import time. Keeps the
#: service layer from importing every adapter directly.
_REGISTRY: dict[str, DiscoveryAdapter] = {}


def register(adapter: DiscoveryAdapter) -> DiscoveryAdapter:
    """Register an adapter under its ``name``."""
    _REGISTRY[adapter.name] = adapter
    return adapter


def get_adapter(name: str) -> DiscoveryAdapter | None:
    """Look up a registered adapter."""
    return _REGISTRY.get(name)


def available_adapters() -> list[str]:
    """Names of every registered adapter, sorted."""
    return sorted(_REGISTRY)


def all_coverage() -> list[dict]:
    """Coverage statements for every registered adapter.

    Backs the Discovery surface's coverage panel, so a reviewer can see the
    tool's declared limits without reading the source.
    """
    return [_REGISTRY[name].coverage().to_dict() for name in available_adapters()]
