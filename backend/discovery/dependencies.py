"""
Aegis PQC — dependency and library discovery adapter.

Discovers cryptographic libraries declared in application manifests:
``requirements.txt``, ``package.json``, ``pom.xml``, and ``go.mod``.

WHAT THIS ADAPTER CLAIMS, AND WHAT IT DOES NOT
----------------------------------------------
It reports that a project **declares a dependency on** a cryptographic library.
That is a strong, checkable fact — the package name and version are written in
a file under version control.

It does **not** claim the application uses any algorithm that library provides.
A project depending on ``cryptography`` can perform RSA; whether any code does
is a question only source scanning answers. Every finding carries that
distinction in its evidence and its capability note, and the algorithm field is
deliberately left empty so no downstream consumer can mistake a capability for
a located algorithm.

That restraint is the whole reason dependency scanning is credible. A tool that
reported "RSA detected" because ``requirements.txt`` mentions ``cryptography``
would produce a confident inventory of things that may not exist.

WHAT IS NEVER EXECUTED
----------------------
No package manager runs. No dependency is downloaded, installed, imported, or
resolved. No build system is invoked. ``pip``, ``npm``, ``mvn``, and ``go`` are
never called. Manifests are read as text and parsed deterministically — the
same file always yields the same findings, offline, on any machine.

UNKNOWN PACKAGES PRODUCE NOTHING
--------------------------------
A package absent from the knowledge base yields no finding at all. A web
framework is not cryptographic material, and inventing a classification for an
unrecognised package would be exactly the false positive that makes a scanner
untrustworthy. Coverage is stated openly instead.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ElementTree
from pathlib import Path

from backend import discovery, knowledge
from backend.discovery import ScanLimits, read_text_safely, safe_walk
from backend.discovery.attribution import ComponentResolver
from backend.knowledge import LibraryProfile
from backend.model import (
    ArtefactType,
    Confidence,
    CoverageStatement,
    CryptoFinding,
    DetectionMethod,
    ScanResult,
    ScanStatus,
    SourceType,
    utc_now,
)

#: Manifest filenames this adapter parses, mapped to their ecosystem.
MANIFEST_FILES: dict[str, str] = {
    "requirements.txt": "pypi",
    "package.json": "npm",
    "pom.xml": "maven",
    "go.mod": "go",
}

#: Filenames passed to :func:`safe_walk`.
MANIFEST_FILENAMES: frozenset[str] = frozenset(MANIFEST_FILES)

#: Maven's POM namespace. Files may or may not declare it.
_MAVEN_NS = {"m": "http://maven.apache.org/POM/4.0.0"}


# ==========================================================================
# Parsed dependency
# ==========================================================================


class DeclaredDependency:
    """One dependency as written in a manifest, before knowledge lookup.

    An intermediate shape, not a second data model: it never leaves this module
    and never reaches the database. Every dependency that survives knowledge
    lookup becomes a canonical :class:`CryptoFinding`.
    """

    __slots__ = ("package", "version", "ecosystem", "line", "raw", "scope")

    def __init__(
        self,
        package: str,
        version: str,
        ecosystem: str,
        line: int | None,
        raw: str,
        scope: str = "",
    ) -> None:
        self.package = package
        self.version = version
        self.ecosystem = ecosystem
        self.line = line
        self.raw = raw
        self.scope = scope


# ==========================================================================
# Manifest parsers
# ==========================================================================


def parse_requirements_txt(text: str) -> list[DeclaredDependency]:
    """Parse a pip requirements file.

    Handles pinned, ranged, and unpinned requirements, extras, environment
    markers, and inline comments. Skips ``-r`` includes, ``-e`` editable
    installs, VCS URLs, and option lines — each would need resolution the
    scanner deliberately does not perform.
    """
    found: list[DeclaredDependency] = []

    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            continue
        if "://" in line or line.startswith(("git+", "hg+", "svn+")):
            continue

        # Drop inline comments and environment markers.
        working = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not working:
            continue

        # Strip extras: cryptography[ssh]==42.0 -> cryptography
        working = re.sub(r"\[[^\]]*\]", "", working, count=1)

        match = re.match(r"^([A-Za-z0-9._-]+)\s*(.*)$", working)
        if not match:
            continue

        package = match.group(1)
        remainder = match.group(2).strip()

        version = ""
        if remainder.startswith("=="):
            # Only an exact pin is a concrete version. Anything else is a range,
            # and reporting a range's bound as "the version" would be a guess.
            version = remainder[2:].strip()
        elif remainder:
            version = remainder.strip()

        found.append(
            DeclaredDependency(package, version, "pypi", number, line)
        )

    return found


def parse_package_json(text: str) -> list[DeclaredDependency]:
    """Parse an npm manifest.

    Reads ``dependencies``, ``devDependencies``, ``peerDependencies``, and
    ``optionalDependencies``, recording which section each came from. A
    malformed file yields nothing rather than raising.
    """
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []

    if not isinstance(document, dict):
        return []

    found: list[DeclaredDependency] = []
    lines = text.splitlines()

    for section in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        block = document.get(section)
        if not isinstance(block, dict):
            continue
        for package, version in block.items():
            if not isinstance(package, str):
                continue
            version_text = version if isinstance(version, str) else ""
            found.append(
                DeclaredDependency(
                    package=package,
                    version=version_text,
                    ecosystem="npm",
                    line=_find_line(lines, f'"{package}"'),
                    raw=f'"{package}": "{version_text}"',
                    scope=section,
                )
            )

    return found


def parse_pom_xml(text: str) -> list[DeclaredDependency]:
    """Parse a Maven POM.

    Handles namespaced and bare POMs. A version given as an unresolved property
    (``${bouncycastle.version}``) is attempted against the file's own
    ``<properties>`` block; if it cannot be resolved there, the version is left
    empty rather than reported as a literal placeholder.
    """
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return []

    def find_all(element, tag: str):
        """Find children by tag with or without the Maven namespace."""
        namespaced = element.findall(f".//m:{tag}", _MAVEN_NS)
        return namespaced if namespaced else element.findall(f".//{tag}")

    # Collect <properties> so common ${...} placeholders can be resolved.
    properties: dict[str, str] = {}
    for block in find_all(root, "properties"):
        for child in block:
            tag = child.tag.split("}")[-1]
            if child.text:
                properties[tag] = child.text.strip()

    def resolve(value: str) -> str:
        """Resolve a ${property} reference against the POM's own properties."""
        match = re.fullmatch(r"\$\{([^}]+)\}", value.strip())
        if not match:
            return value.strip()
        return properties.get(match.group(1), "")

    found: list[DeclaredDependency] = []
    lines = text.splitlines()

    for dependency in find_all(root, "dependency"):
        def child_text(tag: str) -> str:
            node = dependency.find(f"m:{tag}", _MAVEN_NS)
            if node is None:
                node = dependency.find(tag)
            return (node.text or "").strip() if node is not None else ""

        group = child_text("groupId")
        artifact = child_text("artifactId")
        if not group or not artifact:
            continue

        version = resolve(child_text("version"))
        scope = child_text("scope")
        coordinate = f"{group}:{artifact}"

        found.append(
            DeclaredDependency(
                package=coordinate,
                version=version,
                ecosystem="maven",
                line=_find_line(lines, artifact),
                raw=f"{coordinate}:{version}" if version else coordinate,
                scope=scope,
            )
        )

    return found


def parse_go_mod(text: str) -> list[DeclaredDependency]:
    """Parse a Go module file.

    Handles single-line ``require`` statements and parenthesised blocks, and
    records the ``// indirect`` marker as scope. Module paths are truncated at
    a major-version suffix (``/v2``) so they match knowledge-base keys.
    """
    found: list[DeclaredDependency] = []
    in_block = False

    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue

        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue

        if in_block:
            entry = line
        elif line.startswith("require "):
            entry = line[len("require ") :].strip()
        else:
            continue

        indirect = "// indirect" in entry
        entry = entry.split("//", 1)[0].strip()
        if not entry:
            continue

        parts = entry.split()
        if len(parts) < 2:
            continue

        module = parts[0]
        version = parts[1].lstrip("v")

        # Trim a major-version path suffix: example.com/pkg/v2 -> example.com/pkg
        module = re.sub(r"/v\d+$", "", module)

        found.append(
            DeclaredDependency(
                package=module,
                version=version,
                ecosystem="go",
                line=number,
                raw=entry,
                scope="indirect" if indirect else "direct",
            )
        )

    return found


def _find_line(lines: list[str], needle: str) -> int | None:
    """Locate the first line containing ``needle``, for evidence.

    Best-effort: JSON and XML parsing discard position, so the line number is
    recovered by search. Returning ``None`` when not found is acceptable — the
    evidence string still identifies the dependency.
    """
    for number, line in enumerate(lines, start=1):
        if needle in line:
            return number
    return None


#: Parser dispatch by manifest filename.
PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "package.json": parse_package_json,
    "pom.xml": parse_pom_xml,
    "go.mod": parse_go_mod,
}


# ==========================================================================
# Finding construction
# ==========================================================================


def _assess_confidence(dependency: DeclaredDependency) -> Confidence:
    """How much weight the detection deserves.

    HIGH requires an exact version pin: the manifest then establishes precisely
    which release is declared. A caret, tilde, or comparator range admits many
    releases, so the deployed version is genuinely unknown and the finding drops
    to MEDIUM — the dependency is real either way, but the version is not.

    Note this is confidence in the *declaration*, not in the algorithms the
    library provides. That second, weaker claim is carried separately in the
    capability note.
    """
    if knowledge.is_exact_version(dependency.version):
        return Confidence.HIGH
    return Confidence.MEDIUM


def _build_evidence(dependency: DeclaredDependency, manifest: str) -> str:
    """The literal manifest text that produced this finding.

    Truncated, and drawn only from a dependency declaration — never from
    arbitrary file content — so no manifest can leak a secret into a finding.
    """
    raw = dependency.raw.strip()
    if len(raw) > 160:
        raw = raw[:157] + "..."
    location = f"{manifest}:{dependency.line}" if dependency.line else manifest
    return f"{location} → {raw}"


def to_finding(
    dependency: DeclaredDependency,
    profile: LibraryProfile,
    scan_id: str,
    manifest_path: str,
    component: str,
) -> CryptoFinding:
    """Build a canonical finding from a known cryptographic dependency.

    The ``algorithm`` field is deliberately left empty. The artefact discovered
    is a *library*, and the algorithms it provides are a capability recorded in
    ``raw_detail``. Populating ``algorithm`` would let a downstream consumer
    treat a declared dependency as a located algorithm, which is a different and
    much stronger claim than the evidence supports.
    """
    evidence = _build_evidence(dependency, Path(manifest_path).name)
    confidence = _assess_confidence(dependency)

    below = (
        knowledge.is_below_recommended(dependency.version, profile.min_recommended)
        if profile.min_recommended
        else None
    )

    detail: dict[str, object] = {
        "package": dependency.package,
        "ecosystem": dependency.ecosystem,
        "declared_version": dependency.version or "unspecified",
        "manifest": Path(manifest_path).name,
        "provides_algorithms": list(profile.provides),
        "capability_note": profile.capability_note(),
        "library_role": profile.role,
        "library_status": profile.status,
        "pqc_capable": profile.pqc_capable,
    }
    if dependency.scope:
        detail["dependency_scope"] = dependency.scope
    if profile.superseded_by:
        detail["superseded_by"] = profile.superseded_by
    if profile.advisory:
        detail["advisory"] = profile.advisory
    if profile.is_legacy:
        detail["legacy_status"] = profile.status
    if below is True:
        detail["below_recommended_version"] = profile.min_recommended
    elif below is None and profile.min_recommended and dependency.version:
        # An unreadable version means no claim in either direction, said plainly
        # rather than left as a silent absence.
        detail["version_comparison"] = (
            f"Declared version could not be compared against the "
            f"{profile.min_recommended} recommendation."
        )

    return CryptoFinding(
        finding_id=CryptoFinding.compute_id(
            scan_id, manifest_path, dependency.package, dependency.line, evidence
        ),
        scan_id=scan_id,
        artefact_type=ArtefactType.LIBRARY,
        algorithm="",
        algorithm_family="",
        variant="",
        library=profile.name,
        library_version=dependency.version,
        source_type=SourceType.DEPENDENCY,
        location=manifest_path,
        line=dependency.line,
        component=component,
        detection_method=DetectionMethod.MANIFEST_PARSE,
        evidence=evidence,
        confidence=confidence,
        raw_detail=detail,
    )


# ==========================================================================
# Adapter
# ==========================================================================


class DependencyAdapter:
    """Discovery adapter for declared cryptographic dependencies."""

    name = "dependencies"

    def coverage(self) -> CoverageStatement:
        """Declared scope, rendered in the dashboard beside the results."""
        counts = knowledge.coverage_by_ecosystem()
        summary = ", ".join(f"{eco} {count}" for eco, count in counts.items())

        return CoverageStatement(
            adapter=self.name,
            supported=[
                "Python requirements.txt (pinned, ranged, extras, markers)",
                "npm package.json (dependencies, dev, peer, optional)",
                "Maven pom.xml (namespaced and bare, with property resolution)",
                "Go go.mod (single-line and block require)",
                f"Knowledge base covers {knowledge.known_package_count()} "
                f"cryptographic packages ({summary})",
                "Deprecated and unmaintained package identification",
                "Version comparison against a recommended floor",
            ],
            not_supported=[
                "Packages absent from the knowledge base produce no finding",
                "Transitive dependencies are not resolved — only declared ones",
                "Lock files (package-lock.json, poetry.lock, go.sum) are not read",
                "VCS, editable, and URL requirements are skipped",
                "Version ranges are not resolved to a concrete release",
                "Whether the application actually calls the library is not "
                "determined — that requires source scanning",
            ],
            confidence_notes=(
                "A declared dependency with a concrete version is HIGH "
                "confidence. An unpinned or ranged version is MEDIUM, because "
                "the deployed release is genuinely unknown. Confidence applies "
                "to the declaration, not to the algorithms the library "
                "provides — those are capabilities, not observed usage."
            ),
        )

    def supports(self, target: Path) -> bool:
        """True for a directory, or a file that is a recognised manifest."""
        target = Path(target)
        if target.is_dir():
            return True
        return target.name in MANIFEST_FILENAMES

    def scan(
        self,
        target: Path,
        scan_id: str,
        limits: ScanLimits | None = None,
        resolver: ComponentResolver | None = None,
    ) -> ScanResult:
        """Scan ``target`` for declared cryptographic dependencies.

        Args:
            target: Repository root or a single manifest file.
            scan_id: Scan this run belongs to.
            limits: Traversal and size bounds. Defaults applied if omitted.
            resolver: Component attribution. Falls back to the directory
                heuristic when no declared mapping is supplied.

        Returns:
            Findings, coverage, and any errors. No package manager is invoked
            at any point.
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

        findings: list[CryptoFinding] = []
        errors: list[str] = []
        files_examined = 0
        walk_stats = None

        # A scan root that is itself a manifest still needs a directory for
        # attribution, so resolve against its parent.
        attribution_root = target if target.is_dir() else target.parent

        for path, stats in safe_walk(target, limits, filenames=MANIFEST_FILENAMES):
            walk_stats = stats
            files_examined = stats.files_examined

            parser = PARSERS.get(path.name)
            if parser is None:
                continue

            text = read_text_safely(path, limits)
            if text is None:
                errors.append(f"{path.name}: unreadable")
                continue

            try:
                declared = parser(text)
            except Exception as exc:
                # The parsers are defensive, but this runs against untrusted
                # repositories — one hostile manifest must not end the scan.
                errors.append(f"{path.name}: parse failed ({exc})")
                continue

            if not declared:
                continue

            component = resolver.attribute(attribution_root, path).component
            location = str(path)

            seen: set[tuple[str, str]] = set()
            for dependency in declared:
                profile = knowledge.lookup(dependency.ecosystem, dependency.package)
                if profile is None:
                    # Not a cryptographic package. Emitting a finding here would
                    # be a false classification.
                    continue

                # A package declared in several sections of one manifest is one
                # dependency, not several.
                identity = (dependency.package, dependency.version)
                if identity in seen:
                    continue
                seen.add(identity)

                findings.append(
                    to_finding(dependency, profile, scan_id, location, component)
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
DEPENDENCY_ADAPTER = discovery.register(DependencyAdapter())
