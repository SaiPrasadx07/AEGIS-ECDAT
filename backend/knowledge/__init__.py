"""
Aegis PQC — cryptographic library knowledge base.

Loads ``crypto_libraries.yaml`` and answers one question: *does this declared
dependency provide cryptography, and if so what?*

WHY THERE IS A PARSER HERE INSTEAD OF A DEPENDENCY
--------------------------------------------------
The knowledge base is data a security reviewer should be able to read and edit
without touching Python, which argues for YAML. Pulling in PyYAML for a single
static file argues against it.

The file uses a small, fixed subset of YAML — nested mappings, inline lists,
scalars, comments — so :func:`parse_simple_yaml` handles it in about eighty
lines. That keeps installation unchanged and the knowledge base reviewable.

The parser is deliberately strict about what it supports and silent about what
it does not: an unrecognised construct is skipped rather than raising. A
malformed knowledge base must degrade to fewer known libraries, never abort a
scan.

WHAT "PROVIDES" MEANS
---------------------
Every capability in this knowledge base is what a library *makes available*,
not what an application *uses*. A project depending on ``cryptography`` can
perform RSA; whether any code does is a question only source scanning answers.
:meth:`LibraryProfile.capability_note` states that distinction, and it is
carried into every finding the dependency scanner emits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

#: Location of the knowledge base, alongside this module.
KNOWLEDGE_PATH = Path(__file__).resolve().parent / "crypto_libraries.yaml"

#: Ecosystems the knowledge base is organised by.
ECOSYSTEMS = ("pypi", "npm", "maven", "go")


# ==========================================================================
# Minimal YAML subset parser
# ==========================================================================


def _coerce_scalar(raw: str) -> Any:
    """Convert a scalar token to bool, int, float, or str.

    Quoted scalars are taken **literally** — no escape processing is performed.
    That matters for knowledge-base entries containing regular expressions: a
    pattern must be written with single backslashes inside single quotes
    (``'OpenSSL\\s+'``), which is also the YAML-correct form. Writing doubled
    backslashes produces a pattern matching a literal backslash, which silently
    never fires.
    """
    text = raw.strip()
    if text.startswith(("'", '"')) and text.endswith(("'", '"')) and len(text) >= 2:
        return text[1:-1]
    lowered = text.lower()
    if lowered in ("true", "yes"):
        return True
    if lowered in ("false", "no"):
        return False
    if lowered in ("null", "~", ""):
        return None
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d+\.\d+", text):
        return float(text)
    return text


def _parse_inline_list(raw: str) -> list[Any]:
    """Parse a flow-style list, e.g. ``[RSA, AES, SHA-2]``."""
    inner = raw.strip()[1:-1].strip()
    if not inner:
        return []
    return [_coerce_scalar(part) for part in inner.split(",") if part.strip()]


def parse_simple_yaml(text: str) -> dict[str, Any]:
    """Parse the YAML subset the knowledge base uses.

    Supports nested mappings by indentation, inline lists, scalars with type
    coercion, comments, and blank lines. Anything else is skipped.

    Keys may contain colons — Maven coordinates like
    ``org.bouncycastle:bcprov-jdk15on`` are ordinary keys here — so a line is
    split on the *last* colon when it ends one, and on the first colon followed
    by whitespace otherwise.

    Args:
        text: Raw file contents.

    Returns:
        Nested dictionary. Malformed lines are ignored rather than raising.
    """
    root: dict[str, Any] = {}
    # Stack of (indent, container) pairs; the last entry is the active mapping.
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue

        # Strip trailing comments, but not a '#' inside quotes.
        line = raw_line
        if "#" in line:
            quote_count = 0
            for index, char in enumerate(line):
                if char in "\"'":
                    quote_count += 1
                elif char == "#" and quote_count % 2 == 0:
                    line = line[:index]
                    break

        line = line.rstrip()
        if not line.strip():
            continue

        indent = len(line) - len(line.lstrip())
        content = line.strip()

        if ":" not in content:
            continue

        # A line ending in ':' opens a new mapping; its key may itself contain
        # colons, so split on the final one.
        if content.endswith(":"):
            key = content[:-1].strip().strip("\"'")
            value_text = ""
            opens_mapping = True
        else:
            match = re.match(r"^(.*?):\s+(.*)$", content)
            if not match:
                continue
            key = match.group(1).strip().strip("\"'")
            value_text = match.group(2).strip()
            opens_mapping = False

        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            stack = [(-1, root)]

        parent = stack[-1][1]

        if opens_mapping:
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        elif value_text.startswith("["):
            parent[key] = _parse_inline_list(value_text)
        else:
            parent[key] = _coerce_scalar(value_text)

    return root


# ==========================================================================
# Profiles
# ==========================================================================

STATUS_CURRENT = "current"
STATUS_DEPRECATED = "deprecated"
STATUS_UNMAINTAINED = "unmaintained"

#: Statuses that warrant surfacing in the UI.
LEGACY_STATUSES = frozenset({STATUS_DEPRECATED, STATUS_UNMAINTAINED})


@dataclass(frozen=True, slots=True)
class LibraryProfile:
    """What the knowledge base knows about one package.

    Attributes:
        key: Lookup key as it appears in a manifest.
        name: Display name.
        ecosystem: One of :data:`ECOSYSTEMS`.
        provides: Algorithm families the library makes available. A capability,
            not evidence of use.
        role: Primary cryptographic role.
        status: ``current``, ``deprecated``, or ``unmaintained``.
        superseded_by: Replacement package, where one exists.
        min_recommended: Lowest version not flagged as outdated.
        advisory: One-line note for the UI.
        pqc_capable: True only where the library ships a NIST post-quantum
            algorithm.
    """

    key: str
    name: str
    ecosystem: str
    provides: tuple[str, ...] = ()
    role: str = ""
    status: str = STATUS_CURRENT
    superseded_by: str = ""
    min_recommended: str = ""
    advisory: str = ""
    pqc_capable: bool = False

    @property
    def is_legacy(self) -> bool:
        """True if the package itself is deprecated or unmaintained."""
        return self.status in LEGACY_STATUSES

    def capability_note(self) -> str:
        """The sentence that keeps a capability from reading as a usage claim."""
        if not self.provides:
            return "No cryptographic capability recorded for this package."
        return (
            f"{self.name} provides {', '.join(self.provides)}. This is a library "
            "capability, not evidence that the application uses these algorithms."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "ecosystem": self.ecosystem,
            "provides": list(self.provides),
            "role": self.role,
            "status": self.status,
            "superseded_by": self.superseded_by,
            "min_recommended": self.min_recommended,
            "advisory": self.advisory,
            "pqc_capable": self.pqc_capable,
            "is_legacy": self.is_legacy,
        }


# ==========================================================================
# Version comparison
# ==========================================================================


def is_exact_version(raw: str) -> bool:
    """Whether a version string pins one concrete release.

    ``1.3.0`` and ``42.0.5rc1`` are exact. ``^1.3.0``, ``~1.3``, ``>=49.0.0``,
    and ``>=1.0,<2`` are not — each admits a range of releases, so the version
    actually deployed is unknown.

    This drives confidence rather than correctness: a ranged dependency is still
    a real finding, but claiming HIGH confidence in a version nobody has pinned
    would overstate what the manifest establishes.
    """
    if not raw:
        return False
    text = raw.strip()
    if any(char in text for char in "^~<>*|,"):
        return False
    if "${" in text or "://" in text:
        return False
    return re.fullmatch(r"v?\d+(?:\.\d+)*[A-Za-z0-9.\-+]*", text) is not None


def parse_version(raw: str) -> tuple[int, ...] | None:
    """Extract a comparable numeric version tuple.

    Deliberately simple: leading numeric components only. ``1.3.0`` becomes
    ``(1, 3, 0)``; ``2.0.0rc1`` becomes ``(2, 0, 0)``; ``^1.2.3`` becomes
    ``(1, 2, 3)``.

    Returns ``None`` for anything it cannot read as a single concrete version —
    a range, a git URL, an unresolved Maven property, a wildcard. Returning
    ``None`` matters: the caller must then make no claim rather than guess.

    Ranges are refused rather than reduced to their lower bound. ``>=1.0,<2``
    permits 1.9, so treating it as 1.0 and reporting it as below a 1.3 floor
    would be a false positive — and a scanner that cries wolf about versions is
    a scanner a reviewer stops believing.
    """
    if not raw:
        return None

    text = raw.strip()

    # Range and multi-constraint syntax across the four ecosystems.
    if any(token in text for token in (",", "||", " - ", "*", "x", "X")):
        return None
    # Two comparators means a bounded range, e.g. ">=1.0 <2.0".
    if len(re.findall(r"[<>]=?", text)) > 1:
        return None
    # Maven property placeholders and VCS references resolve to nothing here.
    if "${" in text or "://" in text:
        return None

    cleaned = text.lstrip("^~>=<v ").strip()
    match = re.match(r"^(\d+(?:\.\d+)*)", cleaned)
    if not match:
        return None
    try:
        return tuple(int(part) for part in match.group(1).split("."))
    except ValueError:
        return None


def is_below_recommended(version: str, minimum: str) -> bool | None:
    """Whether ``version`` is older than ``minimum``.

    Returns ``None`` when either side cannot be parsed, so an unreadable version
    produces no claim in either direction.
    """
    current = parse_version(version)
    floor = parse_version(minimum)
    if current is None or floor is None:
        return None
    length = max(len(current), len(floor))
    padded_current = current + (0,) * (length - len(current))
    padded_floor = floor + (0,) * (length - len(floor))
    return padded_current < padded_floor


# ==========================================================================
# Loading and lookup
# ==========================================================================


@lru_cache(maxsize=1)
def _load_raw(path_str: str) -> dict[str, Any]:
    """Read and parse the knowledge base, cached per path."""
    path = Path(path_str)
    try:
        return parse_simple_yaml(path.read_text(encoding="utf-8"))
    except OSError:
        return {}


def load_library_profiles(path: Path | None = None) -> dict[tuple[str, str], LibraryProfile]:
    """Load every profile, keyed by ``(ecosystem, lowercased package key)``.

    Args:
        path: Override the knowledge base location, for tests.

    Returns:
        Mapping of ecosystem and package key to profile. An unreadable or
        malformed knowledge base yields an empty mapping rather than raising —
        the scanner then finds no known libraries, which is a visible and
        recoverable outcome.
    """
    raw = _load_raw(str(path or KNOWLEDGE_PATH))
    profiles: dict[tuple[str, str], LibraryProfile] = {}

    for ecosystem in ECOSYSTEMS:
        section = raw.get(ecosystem)
        if not isinstance(section, dict):
            continue
        for key, values in section.items():
            if not isinstance(values, dict):
                continue
            provides = values.get("provides") or []
            if isinstance(provides, str):
                provides = [provides]
            profiles[(ecosystem, key.lower())] = LibraryProfile(
                key=key,
                name=str(values.get("name", key)),
                ecosystem=ecosystem,
                provides=tuple(str(item) for item in provides),
                role=str(values.get("role", "")),
                status=str(values.get("status", STATUS_CURRENT)),
                superseded_by=str(values.get("superseded_by", "")),
                min_recommended=str(values.get("min_recommended", "")),
                advisory=str(values.get("advisory", "")),
                pqc_capable=bool(values.get("pqc_capable", False)),
            )

    return profiles


def lookup(ecosystem: str, package: str, path: Path | None = None) -> LibraryProfile | None:
    """Find a profile for a package.

    Lookup is case-insensitive, and treats ``_`` and ``-`` as equivalent because
    PyPI does. A package absent from the knowledge base returns ``None``, and the
    caller must then emit nothing — guessing at an unknown package is exactly the
    false classification this design avoids.
    """
    profiles = load_library_profiles(path)
    normalised = package.strip().lower()

    direct = profiles.get((ecosystem, normalised))
    if direct is not None:
        return direct

    # PyPI treats underscore and hyphen as equivalent in distribution names.
    if "_" in normalised or "-" in normalised:
        alternate = normalised.replace("_", "-")
        found = profiles.get((ecosystem, alternate))
        if found is not None:
            return found
        alternate = normalised.replace("-", "_")
        found = profiles.get((ecosystem, alternate))
        if found is not None:
            return found

    return None


def known_package_count(path: Path | None = None) -> int:
    """How many packages the knowledge base covers. Shown in the UI."""
    return len(load_library_profiles(path))


def coverage_by_ecosystem(path: Path | None = None) -> dict[str, int]:
    """Package counts per ecosystem, for the coverage statement."""
    counts: dict[str, int] = {}
    for ecosystem, _ in load_library_profiles(path):
        counts[ecosystem] = counts.get(ecosystem, 0) + 1
    return dict(sorted(counts.items()))
