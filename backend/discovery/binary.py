"""
Aegis PQC — compiled binary cryptographic discovery adapter.

Identifies cryptographic usage in compiled artefacts by reading their
structure: the dynamic dependency table, the import table, and embedded
version banners.

WHAT THIS ADAPTER ADDS
----------------------
Phase 2 established what a project *declares*. Phase 3 established what its
*source* calls. Neither reaches a vendored ``.so``, a third-party ``.dll``, or
a service whose source is unavailable — and those are exactly where an
enterprise estate hides cryptography nobody remembers deploying.

This adapter reads the artefact that actually ships.

EVIDENCE IS GRADED, AND NEVER REACHES HIGH
------------------------------------------
Three levels, in ascending strength:

* ``LINKED_LIBRARY`` — a cryptographic library is in the dependency table.
* ``IMPORTED_SYMBOL`` — a specific primitive is named in the import table.
* ``EMBEDDED_STRING`` — a version banner appears in the string data.

**No binary finding is HIGH confidence.** Establishing that a symbol is
actually reached would require disassembly and call-graph analysis, which this
adapter does not perform. An import table proves a reference was linked, not
that the code path executes. Claiming HIGH would overstate what structural
analysis can support, so the ceiling is MEDIUM and the coverage statement says
why.

NOTHING IS EXECUTED
-------------------
Binaries are parsed, never loaded, never run. LIEF reads the file format the
way a debugger reads a core dump — as data. No subprocess is spawned, no
library is dlopened, no entry point is invoked.

DEGRADES RATHER THAN FAILS
--------------------------
LIEF is an optional import. Where it is unavailable the adapter reports that
binary analysis is unavailable and the rest of the platform is unaffected —
a scan missing one surface is better than a platform that will not start.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backend import discovery
from backend.discovery import ScanLimits, safe_walk
from backend.discovery.attribution import ComponentResolver
from backend.knowledge import binaries as kb
from backend.model import (
    ArtefactType,
    BinaryEvidenceLevel,
    BinaryFormat,
    Confidence,
    CoverageStatement,
    CryptoFinding,
    DetectionMethod,
    ScanResult,
    ScanStatus,
    SourceType,
    utc_now,
)

# LIEF is optional. Its absence disables this adapter rather than the platform.
try:  # pragma: no cover - import guard
    import lief

    LIEF_AVAILABLE = True
    LIEF_VERSION = getattr(lief, "__version__", "unknown")
    # LIEF logs parse warnings to stderr by default, which would clutter a scan
    # of an estate containing malformed artefacts.
    try:
        lief.logging.disable()
    except Exception:
        pass
except ImportError:  # pragma: no cover - import guard
    lief = None  # type: ignore[assignment]
    LIEF_AVAILABLE = False
    LIEF_VERSION = ""

#: Suffixes examined. Extension-less files are handled by magic-byte sniffing,
#: because Linux executables commonly carry no suffix at all.
BINARY_SUFFIXES: frozenset[str] = frozenset(
    {".so", ".dll", ".dylib", ".exe", ".bin", ".node", ".pyd", ".a", ".o", ""}
)

#: Format magic numbers, used to decide whether a file is worth parsing.
_MAGIC: tuple[tuple[bytes, BinaryFormat], ...] = (
    (b"\x7fELF", BinaryFormat.ELF),
    (b"MZ", BinaryFormat.PE),
    (b"\xfe\xed\xfa\xce", BinaryFormat.MACHO),
    (b"\xfe\xed\xfa\xcf", BinaryFormat.MACHO),
    (b"\xce\xfa\xed\xfe", BinaryFormat.MACHO),
    (b"\xcf\xfa\xed\xfe", BinaryFormat.MACHO),
    (b"\xca\xfe\xba\xbe", BinaryFormat.MACHO),
)

#: Minimum run length for a printable string extracted from binary data.
MIN_STRING_LENGTH = 6

#: Cap on strings examined per binary. A large artefact can hold hundreds of
#: thousands; version banners appear early and this bounds the work.
MAX_STRINGS_EXAMINED = 40_000


def detect_format(header: bytes) -> BinaryFormat:
    """Identify an executable format from its leading bytes.

    Sniffing magic bytes rather than trusting the file extension means a
    stripped Linux executable with no suffix is still recognised, and a
    ``.dll`` that is actually a text file is not handed to the parser.
    """
    for magic, fmt in _MAGIC:
        if header.startswith(magic):
            return fmt
    return BinaryFormat.UNKNOWN


@dataclass(slots=True)
class BinaryDetection:
    """One cryptographic structure located in a binary.

    An intermediate shape. It never leaves this module — every detection
    becomes a canonical :class:`~backend.model.CryptoFinding`.
    """

    evidence_level: BinaryEvidenceLevel
    detail: str
    algorithm: str = ""
    family: str = ""
    role: str = ""
    mode: str = ""
    key_size: int | None = None
    library: str = ""
    library_version: str = ""
    legacy: bool = False
    note: str = ""
    provides: tuple[str, ...] = ()


# ==========================================================================
# Extraction
# ==========================================================================


def extract_printable_strings(data: bytes, minimum: int = MIN_STRING_LENGTH) -> list[str]:
    """Pull printable ASCII runs out of binary data.

    Equivalent to the classic ``strings`` utility. Bounded by
    :data:`MAX_STRINGS_EXAMINED` so a large artefact cannot make a scan
    unbounded.
    """
    found: list[str] = []
    current: list[str] = []

    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
            continue
        if len(current) >= minimum:
            found.append("".join(current))
            if len(found) >= MAX_STRINGS_EXAMINED:
                return found
        current = []

    if len(current) >= minimum:
        found.append("".join(current))
    return found


def _parsed_libraries(binary: Any) -> list[str]:
    """Dependency entries, across the three formats LIEF handles."""
    names: list[str] = []
    try:
        for entry in getattr(binary, "libraries", []) or []:
            # ELF yields strings; PE yields import objects with a name.
            names.append(entry if isinstance(entry, str) else getattr(entry, "name", ""))
    except Exception:
        return []
    return [name for name in names if name]


def _parsed_symbols(binary: Any) -> list[str]:
    """Imported symbol names, across the three formats LIEF handles."""
    names: set[str] = set()

    try:
        for symbol in getattr(binary, "imported_symbols", []) or []:
            name = getattr(symbol, "name", "")
            if name:
                names.add(name)
    except Exception:
        pass

    # PE exposes imports through a separate structure.
    try:
        for entry in getattr(binary, "imports", []) or []:
            for imported in getattr(entry, "entries", []) or []:
                name = getattr(imported, "name", "")
                if name:
                    names.add(name)
    except Exception:
        pass

    return sorted(names)


def analyse_binary(data: bytes, fmt: BinaryFormat) -> tuple[list[BinaryDetection], str]:
    """Analyse one binary's structure.

    Args:
        data: Full file contents.
        fmt: Format identified from the magic bytes.

    Returns:
        ``(detections, error)``. An unparseable artefact yields an empty list
        and a message rather than raising — estates contain corrupt and
        truncated files, and one must not end a scan.
    """
    if not LIEF_AVAILABLE:
        return [], "binary analysis unavailable: LIEF is not installed"

    try:
        # LIEF accepts the raw bytes positionally. Parsing from memory rather
        # than by path means the adapter never reopens a file it has already
        # read, and never hands a path to a library that might act on it.
        binary = lief.parse(data)
    except Exception as exc:
        return [], f"unparseable binary ({type(exc).__name__})"

    if binary is None:
        return [], "unparseable binary (format not recognised)"

    detections: list[BinaryDetection] = []

    # ---- linked libraries ----
    for soname in _parsed_libraries(binary):
        profile = kb.match_library(soname)
        if profile is None:
            continue
        detections.append(
            BinaryDetection(
                evidence_level=BinaryEvidenceLevel.LINKED_LIBRARY,
                detail=soname,
                library=profile.name,
                family=profile.role,
                role=profile.role,
                note=profile.capability_note(),
                provides=profile.provides,
            )
        )

    # ---- imported symbols ----
    for symbol in _parsed_symbols(binary):
        match = kb.match_symbol(symbol)
        if match is None:
            continue
        detections.append(
            BinaryDetection(
                evidence_level=BinaryEvidenceLevel.IMPORTED_SYMBOL,
                detail=symbol,
                algorithm=match.algorithm,
                family=match.family,
                role=match.role,
                mode=match.mode,
                key_size=match.key_size,
                legacy=match.legacy,
                note=match.note,
            )
        )

    # ---- embedded version banners ----
    seen_versions: set[tuple[str, str]] = set()
    for text in extract_printable_strings(data):
        version = kb.match_version_banner(text)
        if version is None:
            continue
        identity = (version.library, version.version)
        if identity in seen_versions:
            continue
        seen_versions.add(identity)
        detections.append(
            BinaryDetection(
                evidence_level=BinaryEvidenceLevel.EMBEDDED_STRING,
                detail=version.banner,
                library=version.library,
                library_version=version.version,
                note=(
                    "Version recovered from an embedded banner. This is the only "
                    "structure that reveals which library release the artefact "
                    "was built against."
                ),
            )
        )

    return detections, ""


# ==========================================================================
# Confidence
# ==========================================================================


def assess_confidence(detection: BinaryDetection) -> Confidence:
    """Grade a binary detection.

    **Nothing here reaches HIGH.** Proving a symbol is actually reached needs
    disassembly and call-graph analysis, which this adapter does not perform.
    An import table shows the linker resolved a reference; it does not show
    the code path runs.

    IMPORTED_SYMBOL earns MEDIUM: the binary names that primitive specifically.
    LINKED_LIBRARY and EMBEDDED_STRING earn LOW: a library may be linked
    without its cryptographic functions being used, and a string may be inert
    data.
    """
    if detection.evidence_level is BinaryEvidenceLevel.IMPORTED_SYMBOL:
        return Confidence.MEDIUM
    return Confidence.LOW


#: Plain-language meaning of each level, carried into every finding so the
#: distinction survives into the UI and the exported report.
_EVIDENCE_MEANING: dict[BinaryEvidenceLevel, str] = {
    BinaryEvidenceLevel.LINKED_LIBRARY: (
        "A cryptographic library is linked into this binary. Which of its "
        "functions the program reaches is shown by the imported symbols."
    ),
    BinaryEvidenceLevel.IMPORTED_SYMBOL: (
        "This cryptographic function is named in the binary's import table. "
        "The reference was resolved at link time; whether the call path "
        "executes would require disassembly to establish."
    ),
    BinaryEvidenceLevel.EMBEDDED_STRING: (
        "A version banner appears in the binary's string data. This identifies "
        "the library release but may be inert data rather than evidence of use."
    ),
}


def _build_variant(algorithm: str, key_size: int | None) -> str:
    """Compose a variant only where the symbol named a key size.

    ``EVP_aes_256_gcm`` yields ``AES-256`` because the symbol says 256.
    ``RSA_generate_key_ex`` yields ``RSA`` — the key size is a runtime
    argument, invisible to structural analysis, and inventing one would
    fabricate the most consequential detail in the finding.
    """
    if not algorithm or key_size is None:
        return algorithm
    return f"{algorithm}-{key_size}"


def to_finding(
    detection: BinaryDetection,
    scan_id: str,
    path: str,
    component: str,
    fmt: BinaryFormat,
) -> CryptoFinding:
    """Build a canonical finding from a binary detection."""
    confidence = assess_confidence(detection)
    evidence = f"{Path(path).name} → {detection.evidence_level.value}: {detection.detail}"
    if len(evidence) > 200:
        evidence = evidence[:197] + "..."

    detail: dict[str, Any] = {
        "binary_format": fmt.value,
        "evidence_level": detection.evidence_level.value,
        "evidence_meaning": _EVIDENCE_MEANING[detection.evidence_level],
        "structure": detection.detail,
    }
    if detection.provides:
        detail["provides_algorithms"] = list(detection.provides)
    if detection.role:
        detail["role"] = detection.role
    if detection.legacy:
        detail["legacy_primitive"] = True
    if detection.note:
        detail["note"] = detection.note
    if detection.algorithm and detection.key_size is None:
        detail["key_size_status"] = "not determinable from binary structure"

    return CryptoFinding(
        finding_id=CryptoFinding.compute_id(
            scan_id,
            path,
            detection.algorithm or detection.library or detection.detail,
            None,
            f"{detection.evidence_level.value}|{detection.mode}|{detection.detail}",
        ),
        scan_id=scan_id,
        artefact_type=(
            ArtefactType.ALGORITHM if detection.algorithm else ArtefactType.LIBRARY
        ),
        algorithm=detection.algorithm,
        algorithm_family=detection.family,
        variant=_build_variant(detection.algorithm, detection.key_size),
        key_size=detection.key_size,
        mode=detection.mode,
        library=detection.library,
        library_version=detection.library_version,
        source_type=SourceType.BINARY,
        location=path,
        component=component,
        detection_method=(
            DetectionMethod.STRING_MATCH
            if detection.evidence_level is BinaryEvidenceLevel.EMBEDDED_STRING
            else DetectionMethod.SYMBOL_TABLE
        ),
        evidence=evidence,
        confidence=confidence,
        raw_detail=detail,
    )


# ==========================================================================
# Adapter
# ==========================================================================


class BinaryAdapter:
    """Discovery adapter for compiled artefacts."""

    name = "binary"

    def coverage(self) -> CoverageStatement:
        """Declared scope, rendered in the dashboard beside the results."""
        if not LIEF_AVAILABLE:
            return CoverageStatement(
                adapter=self.name,
                supported=[],
                not_supported=[
                    "Binary analysis is unavailable: the LIEF library is not "
                    "installed. Install it to enable this surface.",
                ],
                confidence_notes="No binary findings can be produced.",
            )

        return CoverageStatement(
            adapter=self.name,
            supported=[
                "ELF executables and shared objects",
                "Linked cryptographic libraries from the dependency table",
                f"{kb.known_symbol_count()} cryptographic symbols and symbol families",
                "Key size and mode read from symbol names, such as EVP_aes_256_gcm",
                f"{kb.known_library_count()} cryptographic libraries recognised",
                "Library versions recovered from embedded banners",
                "Format identified by magic bytes, so extension-less binaries "
                "are still analysed",
            ],
            not_supported=[
                "Binaries are parsed, never executed or loaded",
                "No disassembly — whether a symbol's call path executes is not "
                "determined, which is why no binary finding is HIGH confidence",
                "Statically linked cryptography with symbols stripped",
                "Obfuscated or packed binaries",
                "Key sizes supplied as runtime arguments",
                "PE and Mach-O are parsed by the same library but are not "
                "exercised by the bundled demonstration estate",
            ],
            confidence_notes=(
                "An imported symbol is MEDIUM: the binary names that primitive, "
                "but structural analysis cannot show the call path runs. A "
                "linked library or an embedded string is LOW. No binary finding "
                "reaches HIGH — that would require disassembly this adapter "
                "does not perform."
            ),
        )

    def supports(self, target: Path) -> bool:
        """True for a directory, or a file that looks like a binary."""
        target = Path(target)
        if target.is_dir():
            return True
        if target.suffix.lower() in BINARY_SUFFIXES:
            return True
        return False

    def scan(
        self,
        target: Path,
        scan_id: str,
        limits: ScanLimits | None = None,
        resolver: ComponentResolver | None = None,
    ) -> ScanResult:
        """Scan ``target`` for cryptographic structures in compiled artefacts.

        Args:
            target: Directory or a single binary.
            scan_id: Scan this run belongs to.
            limits: Traversal and size bounds. Defaults applied if omitted.
            resolver: Component attribution.

        Returns:
            Findings, coverage, and any errors. Where LIEF is unavailable the
            result is a clean, explained empty scan rather than a failure.
        """
        limits = limits or ScanLimits()
        resolver = resolver or ComponentResolver()
        target = Path(target)
        started = utc_now()

        if not target.exists():
            return ScanResult(
                scan_id=scan_id,
                adapter=self.name,
                target=str(target),
                status=ScanStatus.FAILED,
                coverage=self.coverage(),
                errors=[f"Target does not exist: {target}"],
                started_at=started,
                completed_at=utc_now(),
            )

        if not LIEF_AVAILABLE:
            return ScanResult(
                scan_id=scan_id,
                adapter=self.name,
                target=str(target),
                status=ScanStatus.PARTIAL,
                coverage=self.coverage(),
                errors=[
                    "Binary analysis skipped: the LIEF library is not installed."
                ],
                started_at=started,
                completed_at=utc_now(),
            )

        findings: list[CryptoFinding] = []
        errors: list[str] = []
        files_examined = 0
        walk_stats = None

        attribution_root = target if target.is_dir() else target.parent

        for path, stats in safe_walk(target, limits, suffixes=BINARY_SUFFIXES):
            walk_stats = stats

            try:
                data = path.read_bytes()
            except OSError:
                errors.append(f"{path.name}: unreadable")
                continue

            fmt = detect_format(data[:8])
            if fmt is BinaryFormat.UNKNOWN:
                # Not an executable. Source files, text, and archives all reach
                # here and are skipped without comment.
                continue

            files_examined += 1

            try:
                detections, error = analyse_binary(data, fmt)
            except Exception as exc:
                errors.append(f"{path.name}: analysis failed ({exc})")
                continue

            if error:
                errors.append(f"{path.name}: {error}")
                continue

            component = resolver.attribute(attribution_root, path).component
            location = str(path)

            for detection in detections:
                findings.append(
                    to_finding(detection, scan_id, location, component, fmt)
                )

        if walk_stats:
            errors.extend(walk_stats.notes())

        return ScanResult(
            scan_id=scan_id,
            adapter=self.name,
            target=str(target),
            status=ScanStatus.PARTIAL if errors else ScanStatus.COMPLETED,
            findings=findings,
            coverage=self.coverage(),
            errors=errors,
            files_examined=files_examined,
            started_at=started,
            completed_at=utc_now(),
        )


#: Module-level instance, registered for lookup by name.
BINARY_ADAPTER = discovery.register(BinaryAdapter())
