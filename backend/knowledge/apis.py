"""
Aegis PQC — source-level cryptographic API knowledge.

Loads ``crypto_apis.yaml`` and resolves source constructs to the cryptographic
primitives they reference.

WHAT THIS KNOWS
---------------
Four kinds of construct, matching how cryptography actually appears in source:

* **modules** — import paths. Referencing a module is not calling it.
* **calls** — dotted call expressions, the strongest static evidence.
* **constants** — named modes and parameters such as ``AES.MODE_ECB``.
* **factories** — methods whose *string argument* names the algorithm, which is
  how the Java Cryptography Architecture works throughout.

Plus two resolution tables: ``algorithm_strings`` maps the names that appear
inside factory arguments, and ``cipher_modes`` maps the mode segment of a
cipher specification.

WHAT IT DELIBERATELY DOES NOT KNOW
----------------------------------
Bare algorithm names. There is no entry that matches the word "RSA" on its own,
because that word appears in comments, README prose, variable names, and
unrelated identifiers far more often than it marks a cryptographic operation.
Every entry is a structured construct, and that is the single most important
false-positive control in the source scanner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from backend.knowledge import parse_simple_yaml

#: Location of the source API knowledge base.
API_KNOWLEDGE_PATH = Path(__file__).resolve().parent / "crypto_apis.yaml"

#: Languages with entries in the knowledge base.
SOURCE_LANGUAGES = ("python", "javascript", "java", "go")

#: Construct categories, in descending evidence strength.
CONSTRUCT_CALLS = "calls"
CONSTRUCT_CONSTANTS = "constants"
CONSTRUCT_FACTORIES = "factories"
CONSTRUCT_MODULES = "modules"


@dataclass(frozen=True, slots=True)
class ApiProfile:
    """What the knowledge base knows about one source construct.

    Attributes:
        pattern: The construct as written in source.
        language: Language this entry belongs to.
        category: One of the ``CONSTRUCT_*`` values.
        algorithm: Canonical algorithm name. Empty when only a string argument
            can determine it — a Java factory, or Node's ``createHash``.
        family: Grouping for reporting.
        role: Cryptographic role.
        mode: Mode of operation, when the construct fixes one.
        key_size_arg: Argument carrying an explicit key size, when one exists.
        legacy: True where the primitive is unsuitable for new work for reasons
            unrelated to quantum computing.
        note: One line shown in the UI.
    """

    pattern: str
    language: str
    category: str
    algorithm: str = ""
    family: str = ""
    role: str = ""
    mode: str = ""
    key_size_arg: str = ""
    legacy: bool = False
    note: str = ""

    @property
    def resolves_from_argument(self) -> bool:
        """True when the algorithm comes from a string argument, not the name.

        ``Cipher.getInstance(...)`` says nothing until its argument is read.
        Treating such a construct as a concrete algorithm finding would be an
        invention.
        """
        return not self.algorithm

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern,
            "language": self.language,
            "category": self.category,
            "algorithm": self.algorithm,
            "family": self.family,
            "role": self.role,
            "mode": self.mode,
            "legacy": self.legacy,
            "note": self.note,
        }


def _build_profile(
    pattern: str, language: str, category: str, values: dict[str, Any]
) -> ApiProfile:
    """Construct a profile from one knowledge-base entry."""
    return ApiProfile(
        pattern=pattern,
        language=language,
        category=category,
        algorithm=str(values.get("algorithm", "")),
        family=str(values.get("family", "")),
        role=str(values.get("role", "")),
        mode=str(values.get("mode", "")),
        key_size_arg=str(values.get("key_size_arg", "")),
        legacy=bool(values.get("legacy", False)),
        note=str(values.get("note", "")),
    )


@lru_cache(maxsize=1)
def _load_raw(path_str: str) -> dict[str, Any]:
    """Read and parse the API knowledge base, cached per path."""
    try:
        return parse_simple_yaml(Path(path_str).read_text(encoding="utf-8"))
    except OSError:
        return {}


@lru_cache(maxsize=4)
def load_api_profiles(path_str: str | None = None) -> dict[tuple[str, str, str], ApiProfile]:
    """Load every construct, keyed by ``(language, category, pattern)``.

    A malformed or missing knowledge base yields an empty mapping rather than
    raising. The scanner then finds nothing — a visible, recoverable outcome
    rather than a crashed scan.
    """
    raw = _load_raw(path_str or str(API_KNOWLEDGE_PATH))
    profiles: dict[tuple[str, str, str], ApiProfile] = {}

    for language in SOURCE_LANGUAGES:
        section = raw.get(language)
        if not isinstance(section, dict):
            continue
        for category in (
            CONSTRUCT_MODULES,
            CONSTRUCT_CALLS,
            CONSTRUCT_CONSTANTS,
            CONSTRUCT_FACTORIES,
        ):
            entries = section.get(category)
            if not isinstance(entries, dict):
                continue
            for pattern, values in entries.items():
                if isinstance(values, dict):
                    profiles[(language, category, pattern)] = _build_profile(
                        pattern, language, category, values
                    )

    return profiles


@lru_cache(maxsize=4)
def load_algorithm_strings(path_str: str | None = None) -> dict[str, dict[str, Any]]:
    """Algorithm names that appear inside factory and cipher-spec arguments.

    Keyed in lowercase with separators removed, so ``SHA-256``, ``SHA256``, and
    ``sha_256`` all resolve to one entry.
    """
    raw = _load_raw(path_str or str(API_KNOWLEDGE_PATH))
    section = raw.get("algorithm_strings")
    if not isinstance(section, dict):
        return {}

    table: dict[str, dict[str, Any]] = {}
    for name, values in section.items():
        if isinstance(values, dict):
            table[_normalise_token(name)] = {**values, "_source_name": name}
    return table


@lru_cache(maxsize=4)
def load_cipher_modes(path_str: str | None = None) -> dict[str, dict[str, Any]]:
    """Modes of operation appearing in cipher specification strings."""
    raw = _load_raw(path_str or str(API_KNOWLEDGE_PATH))
    section = raw.get("cipher_modes")
    if not isinstance(section, dict):
        return {}
    return {
        _normalise_token(name): values
        for name, values in section.items()
        if isinstance(values, dict)
    }


def _normalise_token(token: str) -> str:
    """Lowercase and strip separators so naming variants collapse to one key."""
    return re.sub(r"[-_\s]", "", token.strip().lower())


def lookup_construct(
    language: str, category: str, pattern: str, path: Path | None = None
) -> ApiProfile | None:
    """Find a profile for an exact construct."""
    profiles = load_api_profiles(str(path) if path else None)
    return profiles.get((language, category, pattern))


def constructs_for(
    language: str, category: str, path: Path | None = None
) -> dict[str, ApiProfile]:
    """Every construct of one category in one language."""
    profiles = load_api_profiles(str(path) if path else None)
    return {
        pattern: profile
        for (lang, cat, pattern), profile in profiles.items()
        if lang == language and cat == category
    }


def resolve_algorithm_string(value: str, path: Path | None = None) -> dict[str, Any] | None:
    """Resolve an algorithm name taken from a factory or cipher argument.

    Handles the forms these arguments actually take:

    * Java cipher specifications — ``AES/GCM/NoPadding``
    * Java signature algorithms — ``SHA256withRSA``
    * Node cipher names — ``aes-256-cbc``
    * Bare names — ``ML-KEM-768``

    Returns a dict carrying ``algorithm``, ``family``, ``role``, and where
    determinable ``mode`` and ``key_size``. Returns ``None`` when the string
    matches nothing known — a string the scanner cannot resolve produces no
    finding rather than a guess.
    """
    if not value:
        return None

    table = load_algorithm_strings(str(path) if path else None)
    modes = load_cipher_modes(str(path) if path else None)
    text = value.strip()

    # Java cipher specification: ALGORITHM/MODE/PADDING
    if "/" in text:
        segments = [segment.strip() for segment in text.split("/")]
        base = table.get(_normalise_token(segments[0]))
        if base is None:
            return None
        resolved = dict(base)
        for segment in segments[1:]:
            mode = modes.get(_normalise_token(segment))
            if mode:
                resolved["mode"] = mode.get("mode", segment)
                if mode.get("legacy"):
                    resolved["legacy"] = True
                break
        return resolved

    # Node cipher name: aes-256-cbc / aes-128-gcm
    node_match = re.fullmatch(r"([a-zA-Z0-9]+)-(\d{2,4})-([a-zA-Z]+)", text)
    if node_match:
        base = table.get(_normalise_token(node_match.group(1)))
        if base is None:
            return None
        resolved = dict(base)
        resolved["key_size"] = int(node_match.group(2))
        mode = modes.get(_normalise_token(node_match.group(3)))
        if mode:
            resolved["mode"] = mode.get("mode", node_match.group(3))
            if mode.get("legacy"):
                resolved["legacy"] = True
        return resolved

    # Bare name, exact match only.
    direct = table.get(_normalise_token(text))
    return dict(direct) if direct else None


def known_construct_count(path: Path | None = None) -> int:
    """How many source constructs the knowledge base covers."""
    return len(load_api_profiles(str(path) if path else None))


def construct_coverage(path: Path | None = None) -> dict[str, int]:
    """Construct counts per language, for the coverage statement."""
    counts: dict[str, int] = {}
    for language, _, _ in load_api_profiles(str(path) if path else None):
        counts[language] = counts.get(language, 0) + 1
    return dict(sorted(counts.items()))
