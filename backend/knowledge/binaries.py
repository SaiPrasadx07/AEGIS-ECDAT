"""
Aegis PQC — binary cryptographic knowledge.

Loads ``crypto_binary.yaml`` and resolves the three structures a compiled
artefact exposes: linked libraries, imported symbols, and embedded version
banners.

WHY SYMBOL PATTERNS EXIST
-------------------------
OpenSSL names its cipher constructors consistently — ``EVP_aes_256_gcm``,
``EVP_aes_128_cbc``, ``EVP_des_ede3_cbc``. Enumerating every combination would
be hundreds of entries that drift out of date. A small number of regular
expressions covers the family and, more usefully, extracts the key size and
mode from the name itself.

That extraction is real evidence rather than inference: the symbol
``EVP_aes_256_gcm`` names AES with a 256-bit key in GCM mode, and the binary
references it by that exact name.

WHAT IS NOT MATCHED
-------------------
Bare algorithm words appearing loose in the string table. A compiled binary
contains large quantities of incidental text — paths, error messages, format
strings — and matching "RSA" anywhere in it would produce noise rather than
findings. Only structured constructs are recognised.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from backend.knowledge import parse_simple_yaml

#: Location of the binary knowledge base.
BINARY_KNOWLEDGE_PATH = Path(__file__).resolve().parent / "crypto_binary.yaml"


@dataclass(frozen=True, slots=True)
class BinaryLibraryProfile:
    """A cryptographic library recognised in a dependency table."""

    key: str
    name: str
    provides: tuple[str, ...] = ()
    role: str = ""
    note: str = ""

    def capability_note(self) -> str:
        """The sentence keeping a linked library from reading as usage.

        A linked library is a capability the binary can reach. Which functions
        it actually calls is what the symbol table answers, and that is a
        separate finding.
        """
        if not self.provides:
            return f"{self.name} is linked into this binary."
        return (
            f"{self.name} is linked into this binary and provides "
            f"{', '.join(self.provides)}. Linkage is a capability; the imported "
            "symbols show which primitives are referenced."
        )


@dataclass(frozen=True, slots=True)
class SymbolMatch:
    """A resolved cryptographic symbol."""

    symbol: str
    algorithm: str
    family: str
    role: str
    mode: str = ""
    key_size: int | None = None
    legacy: bool = False
    note: str = ""
    matched_by: str = "exact"


@dataclass(frozen=True, slots=True)
class VersionMatch:
    """A library and version recovered from an embedded banner."""

    library: str
    version: str
    banner: str


@lru_cache(maxsize=2)
def _load_raw(path_str: str) -> dict[str, Any]:
    """Read and parse the binary knowledge base, cached per path."""
    try:
        return parse_simple_yaml(Path(path_str).read_text(encoding="utf-8"))
    except OSError:
        return {}


@lru_cache(maxsize=2)
def load_libraries(path_str: str | None = None) -> dict[str, BinaryLibraryProfile]:
    """Cryptographic libraries, keyed by lowercase soname stem."""
    raw = _load_raw(path_str or str(BINARY_KNOWLEDGE_PATH))
    section = raw.get("libraries")
    if not isinstance(section, dict):
        return {}

    profiles: dict[str, BinaryLibraryProfile] = {}
    for key, values in section.items():
        if not isinstance(values, dict):
            continue
        provides = values.get("provides") or []
        if isinstance(provides, str):
            provides = [provides]
        profiles[key.lower()] = BinaryLibraryProfile(
            key=key,
            name=str(values.get("name", key)),
            provides=tuple(str(item) for item in provides),
            role=str(values.get("role", "")),
            note=str(values.get("note", "")),
        )
    return profiles


@lru_cache(maxsize=2)
def load_exact_symbols(path_str: str | None = None) -> dict[str, dict[str, Any]]:
    """Symbols with a fixed meaning, keyed exactly as they appear."""
    raw = _load_raw(path_str or str(BINARY_KNOWLEDGE_PATH))
    section = raw.get("symbol_exact")
    return section if isinstance(section, dict) else {}


@lru_cache(maxsize=2)
def load_symbol_patterns(path_str: str | None = None) -> list[dict[str, Any]]:
    """Compiled symbol-family patterns, in declaration order.

    A pattern that fails to compile is skipped rather than raising: a malformed
    knowledge base must reduce what the scanner recognises, never abort a scan.
    """
    raw = _load_raw(path_str or str(BINARY_KNOWLEDGE_PATH))
    section = raw.get("symbol_patterns")
    if not isinstance(section, dict):
        return []

    compiled: list[dict[str, Any]] = []
    for key, values in section.items():
        if not isinstance(values, dict) or "pattern" not in values:
            continue
        try:
            expression = re.compile(str(values["pattern"]))
        except re.error:
            continue
        compiled.append({**values, "_key": key, "_regex": expression})
    return compiled


@lru_cache(maxsize=2)
def load_version_patterns(path_str: str | None = None) -> list[dict[str, Any]]:
    """Compiled version-banner patterns."""
    raw = _load_raw(path_str or str(BINARY_KNOWLEDGE_PATH))
    section = raw.get("version_strings")
    if not isinstance(section, dict):
        return []

    compiled: list[dict[str, Any]] = []
    for key, values in section.items():
        if not isinstance(values, dict) or "pattern" not in values:
            continue
        try:
            expression = re.compile(str(values["pattern"]))
        except re.error:
            continue
        compiled.append({**values, "_key": key, "_regex": expression})
    return compiled


def match_library(soname: str, path: Path | None = None) -> BinaryLibraryProfile | None:
    """Resolve a dependency entry to a known cryptographic library.

    Handles the shapes dependency tables actually contain: ``libcrypto.so.3``,
    ``libcrypto.so``, ``libcrypto-3-x64.dll``, ``libcrypto.3.dylib``. Matching
    is on the stem, so version suffixes do not defeat it.

    A library absent from the knowledge base returns ``None`` and produces no
    finding. Most linked libraries are not cryptographic.
    """
    if not soname:
        return None

    libraries = load_libraries(str(path) if path else None)
    name = Path(soname).name.lower()

    # Strip extensions and version decorations: libcrypto.so.3 -> libcrypto
    stem = re.sub(r"\.(so|dll|dylib)(\.\d+)*$", "", name)
    stem = re.sub(r"[-.]\d+([-.]\w+)*$", "", stem)

    direct = libraries.get(stem)
    if direct is not None:
        return direct

    # A soname may carry a prefix or suffix around the known stem.
    for key, profile in libraries.items():
        if stem.startswith(key) or key in stem:
            return profile
    return None


def match_symbol(symbol: str, path: Path | None = None) -> SymbolMatch | None:
    """Resolve an imported symbol to a cryptographic primitive.

    Exact entries are tried first, then family patterns. A pattern can extract
    the key size and mode from the symbol name — ``EVP_aes_256_gcm`` yields AES
    with a 256-bit key in GCM mode — which is read from the name rather than
    inferred.

    Returns ``None`` for anything unrecognised. A binary imports hundreds of
    symbols and almost none are cryptographic.
    """
    if not symbol:
        return None

    exact = load_exact_symbols(str(path) if path else None)
    entry = exact.get(symbol)
    if isinstance(entry, dict):
        return SymbolMatch(
            symbol=symbol,
            algorithm=str(entry.get("algorithm", "")),
            family=str(entry.get("family", "")),
            role=str(entry.get("role", "")),
            legacy=bool(entry.get("legacy", False)),
            note=str(entry.get("note", "")),
            matched_by="exact",
        )

    for rule in load_symbol_patterns(str(path) if path else None):
        match = rule["_regex"].match(symbol)
        if not match:
            continue

        key_size: int | None = None
        if rule.get("key_size_group"):
            try:
                raw_size = match.group(int(rule["key_size_group"]))
                key_size = int(raw_size) if raw_size else None
            except (IndexError, ValueError, TypeError):
                key_size = None

        mode = ""
        if rule.get("mode_group"):
            try:
                captured = match.group(int(rule["mode_group"]))
                mode = captured.upper() if captured else ""
            except (IndexError, ValueError, TypeError):
                mode = ""

        algorithm = str(rule.get("algorithm", ""))
        if rule.get("variant_group"):
            try:
                suffix = match.group(int(rule["variant_group"]))
                if suffix:
                    algorithm = f"SHA-{suffix}"
            except (IndexError, ValueError, TypeError):
                pass

        legacy = bool(rule.get("legacy", False))
        # ECB is unsuitable for confidentiality regardless of the cipher.
        if mode == "ECB":
            legacy = True

        return SymbolMatch(
            symbol=symbol,
            algorithm=algorithm,
            family=str(rule.get("family", "")),
            role=str(rule.get("role", "")),
            mode=mode,
            key_size=key_size,
            legacy=legacy,
            note=str(rule.get("note", "")),
            matched_by=str(rule["_key"]),
        )

    return None


def match_version_banner(text: str, path: Path | None = None) -> VersionMatch | None:
    """Recover a library name and version from an embedded banner.

    Version banners are the only reliable way to learn which release of a
    cryptographic library a binary was built against — nothing in the symbol
    or dependency tables carries it.
    """
    if not text:
        return None

    for rule in load_version_patterns(str(path) if path else None):
        match = rule["_regex"].search(text)
        if not match:
            continue
        version = ""
        if rule.get("version_group"):
            try:
                version = match.group(int(rule["version_group"])) or ""
            except (IndexError, ValueError, TypeError):
                version = ""
        return VersionMatch(
            library=str(rule.get("library", rule["_key"])),
            version=version,
            banner=match.group(0)[:120],
        )
    return None


def known_symbol_count(path: Path | None = None) -> int:
    """Exact symbols plus symbol families the knowledge base covers."""
    return len(load_exact_symbols(str(path) if path else None)) + len(
        load_symbol_patterns(str(path) if path else None)
    )


def known_library_count(path: Path | None = None) -> int:
    """Cryptographic libraries the knowledge base recognises."""
    return len(load_libraries(str(path) if path else None))
