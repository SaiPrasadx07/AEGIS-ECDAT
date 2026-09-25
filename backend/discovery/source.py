"""
Aegis PQC — source-code cryptographic discovery adapter.

Identifies cryptographic usage in application source across Python,
JavaScript/TypeScript, Java, and Go.

THE CLAIM THIS ADAPTER MAKES
----------------------------
Phase 2 could say *"this application depends on a library that provides RSA."*
This adapter can say *"this application calls RSA key generation, at
payments/keys.py line 42, with an explicit 2048-bit key size."*

That is a materially stronger statement, and it is the point of the phase.

Crucially, the two claims stay distinguishable. Every finding carries a
:class:`~backend.model.SourceEvidenceLevel`:

* ``IMPORT`` — the module is referenced. It may be unused, re-exported, or
  imported only for a type annotation.
* ``CALL_SITE`` — the primitive is invoked.
* ``CONFIGURATION`` — a specific algorithm, mode, or parameter is named.

An import is never reported as usage. Collapsing that distinction is the
central dishonesty available to a source scanner, and the confidence model
below exists to prevent it.

NOTHING IS EXECUTED
-------------------
Python is parsed with the standard library's :mod:`ast` module, which builds a
syntax tree without evaluating it. No module is imported, no code is run, no
package manager is invoked, no build is triggered. The other three languages
are analysed with deterministic patterns over comment-stripped text.

NOTHING IS INVENTED
-------------------
A key size is recorded only when a literal integer appears in the source.
``rsa.generate_private_key(key_size=2048)`` yields RSA with key size 2048.
``rsa.generate_private_key(**config)`` yields RSA with key size unknown — never
RSA-2048. The same rule governs modes: read from the source or absent.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from backend import discovery
from backend.discovery import ScanLimits, read_text_safely, safe_walk
from backend.discovery.attribution import ComponentResolver
from backend.knowledge import apis
from backend.knowledge.apis import ApiProfile
from backend.model import (
    ArtefactType,
    Confidence,
    CoverageStatement,
    CryptoFinding,
    DetectionMethod,
    ScanResult,
    ScanStatus,
    SourceEvidenceLevel,
    SourceLanguage,
    SourceType,
    utc_now,
)

#: Source suffixes mapped to the language whose rules apply.
SOURCE_SUFFIXES: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".java": "java",
    ".go": "go",
}

#: Suffix set handed to :func:`safe_walk`.
SOURCE_EXTENSIONS: frozenset[str] = frozenset(SOURCE_SUFFIXES)

#: Reported language per suffix, distinguishing TypeScript from JavaScript even
#: though both use the same detection rules.
_REPORTED_LANGUAGE: dict[str, SourceLanguage] = {
    ".py": SourceLanguage.PYTHON,
    ".js": SourceLanguage.JAVASCRIPT,
    ".mjs": SourceLanguage.JAVASCRIPT,
    ".cjs": SourceLanguage.JAVASCRIPT,
    ".jsx": SourceLanguage.JAVASCRIPT,
    ".ts": SourceLanguage.TYPESCRIPT,
    ".tsx": SourceLanguage.TYPESCRIPT,
    ".java": SourceLanguage.JAVA,
    ".go": SourceLanguage.GO,
}

#: Longest evidence snippet retained. Bounded so no source line can carry an
#: unbounded quantity of surrounding content into a finding.
MAX_EVIDENCE_CHARS = 180


# ==========================================================================
# Detected construct
# ==========================================================================


@dataclass(slots=True)
class SourceDetection:
    """One cryptographic construct located in source.

    An intermediate shape. It never leaves this module and never reaches the
    database — every detection becomes a canonical
    :class:`~backend.model.CryptoFinding` before it goes anywhere.
    """

    algorithm: str
    family: str
    role: str
    evidence_level: SourceEvidenceLevel
    line: int
    snippet: str
    api: str
    mode: str = ""
    key_size: int | None = None
    legacy: bool = False
    note: str = ""


def _clean_snippet(text: str) -> str:
    """Collapse whitespace and bound the length of an evidence snippet.

    Evidence is a single source line, trimmed. Bounding it means no file can
    push an unbounded quantity of content into a finding, and collapsing
    whitespace keeps indented code readable in a table.
    """
    collapsed = re.sub(r"\s+", " ", text).strip()
    if len(collapsed) > MAX_EVIDENCE_CHARS:
        return collapsed[: MAX_EVIDENCE_CHARS - 3] + "..."
    return collapsed


def _line_of(lines: list[str], number: int) -> str:
    """Return one source line by 1-based number, or an empty string."""
    if 1 <= number <= len(lines):
        return lines[number - 1]
    return ""


# ==========================================================================
# Python — AST
# ==========================================================================


def _dotted_name(node: ast.AST) -> str:
    """Reconstruct a dotted name from an attribute or name node.

    ``rsa.generate_private_key`` arrives as nested ``Attribute`` nodes; this
    flattens them back to the form the knowledge base is keyed on.
    """
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    else:
        return ""
    return ".".join(reversed(parts))


def _literal_int(node: ast.AST) -> int | None:
    """Extract a literal integer, or ``None``.

    Only a literal counts. A variable, a call, or an unpacked mapping yields
    ``None``, and the finding then records an unknown key size rather than
    inventing one.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None


def _match_call_profile(name: str) -> ApiProfile | None:
    """Resolve a dotted call name against the Python call knowledge.

    Falls back to matching on the trailing segments, because code imports
    modules under many aliases — ``from cryptography... import rsa`` then
    ``rsa.generate_private_key``, versus a fully qualified call. Matching the
    suffix keeps detection working without guessing at alias resolution.
    """
    calls = apis.constructs_for("python", apis.CONSTRUCT_CALLS)
    if name in calls:
        return calls[name]

    segments = name.split(".")
    for length in (3, 2, 1):
        if len(segments) >= length:
            candidate = ".".join(segments[-length:])
            if candidate in calls:
                return calls[candidate]
    return None


def detect_python(text: str) -> tuple[list[SourceDetection], str]:
    """Analyse Python source with the standard library AST.

    The tree is built, walked, and discarded. :func:`ast.parse` performs no
    evaluation — it is a parser, not an interpreter — so no application code
    executes at any point.

    Returns:
        ``(detections, error)``. A syntax error yields an empty list and a
        message, never an exception: one unparseable file must not end a scan.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError) as exc:
        return [], f"unparseable Python ({type(exc).__name__})"

    lines = text.splitlines()
    detections: list[SourceDetection] = []

    modules = apis.constructs_for("python", apis.CONSTRUCT_MODULES)
    constants = apis.constructs_for("python", apis.CONSTRUCT_CONSTANTS)

    for node in ast.walk(tree):
        # ---- imports ----
        if isinstance(node, ast.Import):
            for alias in node.names:
                profile = _longest_module_match(alias.name, modules)
                if profile:
                    detections.append(
                        _detection_from_profile(
                            profile,
                            SourceEvidenceLevel.IMPORT,
                            node.lineno,
                            _line_of(lines, node.lineno),
                            f"import {alias.name}",
                        )
                    )

        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            # `from x.y import z` may name the crypto module in either half.
            candidates = [base] + [f"{base}.{a.name}" for a in node.names if base]
            matched: ApiProfile | None = None
            matched_path = ""
            for candidate in candidates:
                profile = _longest_module_match(candidate, modules)
                if profile and len(profile.pattern) > len(matched_path):
                    matched, matched_path = profile, profile.pattern
            if matched:
                detections.append(
                    _detection_from_profile(
                        matched,
                        SourceEvidenceLevel.IMPORT,
                        node.lineno,
                        _line_of(lines, node.lineno),
                        f"from {base} import ...",
                    )
                )

        # ---- call sites ----
        elif isinstance(node, ast.Call):
            name = _dotted_name(node.func)
            if not name:
                continue
            profile = _match_call_profile(name)
            if profile is None:
                continue

            key_size: int | None = None
            if profile.key_size_arg:
                for keyword in node.keywords:
                    if keyword.arg == profile.key_size_arg:
                        key_size = _literal_int(keyword.value)
                        break

            detection = _detection_from_profile(
                profile,
                SourceEvidenceLevel.CALL_SITE,
                node.lineno,
                _line_of(lines, node.lineno),
                name,
            )
            detection.key_size = key_size
            detections.append(detection)

        # ---- configuration constants ----
        elif isinstance(node, ast.Attribute):
            name = _dotted_name(node)
            if not name:
                continue
            for pattern, profile in constants.items():
                if name == pattern or name.endswith("." + pattern):
                    detections.append(
                        _detection_from_profile(
                            profile,
                            SourceEvidenceLevel.CONFIGURATION,
                            node.lineno,
                            _line_of(lines, node.lineno),
                            pattern,
                        )
                    )
                    break

    return detections, ""


def _longest_module_match(
    name: str, modules: dict[str, ApiProfile]
) -> ApiProfile | None:
    """Match an import path against the most specific known module.

    ``cryptography.hazmat.primitives.asymmetric.rsa`` must match its own entry
    rather than a shorter prefix, so the longest match wins.
    """
    best: ApiProfile | None = None
    for pattern, profile in modules.items():
        if name == pattern or name.startswith(pattern + "."):
            if best is None or len(pattern) > len(best.pattern):
                best = profile
    return best


def _detection_from_profile(
    profile: ApiProfile,
    level: SourceEvidenceLevel,
    line: int,
    raw_line: str,
    api: str,
) -> SourceDetection:
    """Build a detection from a knowledge-base profile."""
    return SourceDetection(
        algorithm=profile.algorithm,
        family=profile.family,
        role=profile.role,
        evidence_level=level,
        line=line,
        snippet=_clean_snippet(raw_line),
        api=api,
        mode=profile.mode,
        legacy=profile.legacy,
        note=profile.note,
    )


# ==========================================================================
# Comment stripping for brace languages
# ==========================================================================


def strip_comments(text: str, language: str) -> list[str]:
    """Blank out comment content while preserving line numbering.

    Returns a list of lines with comments replaced by spaces, so every
    reported line number still refers to the real file.

    This is the primary false-positive control for the pattern-based
    languages. A comment reading ``// TODO: replace RSA with ML-KEM`` must not
    produce a finding, and blanking comments before matching removes that
    entire class of error.

    String literals are deliberately preserved: Java's
    ``Cipher.getInstance("AES/GCM/NoPadding")`` carries its algorithm inside a
    string, so stripping literals would destroy the detection this scanner
    exists to make.
    """
    if language == "python":
        # Python is handled by the AST, which ignores comments inherently.
        return text.splitlines()

    lines = text.splitlines()
    cleaned: list[str] = []
    in_block = False

    for line in lines:
        output: list[str] = []
        index = 0
        in_string: str | None = None

        while index < len(line):
            pair = line[index : index + 2]

            if in_block:
                if pair == "*/":
                    in_block = False
                    output.append("  ")
                    index += 2
                else:
                    output.append(" ")
                    index += 1
                continue

            char = line[index]

            if in_string:
                output.append(char)
                if char == "\\":
                    # Keep an escape pair intact.
                    if index + 1 < len(line):
                        output.append(line[index + 1])
                        index += 2
                        continue
                elif char == in_string:
                    in_string = None
                index += 1
                continue

            if char in "\"'`":
                in_string = char
                output.append(char)
                index += 1
                continue

            if pair == "//":
                output.append(" " * (len(line) - index))
                break

            if pair == "/*":
                in_block = True
                output.append("  ")
                index += 2
                continue

            output.append(char)
            index += 1

        cleaned.append("".join(output))

    return cleaned


# ==========================================================================
# Pattern-based languages
# ==========================================================================

#: Import forms across the brace languages.
_IMPORT_PATTERNS = {
    "javascript": [
        re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)"""),
        re.compile(r"""\bfrom\s+['"]([^'"]+)['"]"""),
        re.compile(r"""\bimport\s+['"]([^'"]+)['"]"""),
    ],
    "java": [re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)\s*;")],
    "go": [
        re.compile(r"""^\s*(?:[\w.]+\s+)?"([^"]+)"\s*$"""),
        re.compile(r"""^\s*import\s+(?:[\w.]+\s+)?"([^"]+)"""),
    ],
}


def _detect_imports(
    lines: list[str], language: str, modules: dict[str, ApiProfile]
) -> list[SourceDetection]:
    """Locate crypto module imports in a brace language."""
    detections: list[SourceDetection] = []
    patterns = _IMPORT_PATTERNS.get(language, [])

    in_go_import_block = False

    for number, line in enumerate(lines, start=1):
        if language == "go":
            stripped = line.strip()
            if stripped.startswith("import ("):
                in_go_import_block = True
                continue
            if in_go_import_block and stripped == ")":
                in_go_import_block = False
                continue
            if not in_go_import_block and not stripped.startswith("import "):
                continue

        for pattern in patterns:
            match = pattern.search(line)
            if not match:
                continue
            imported = match.group(1)
            profile = _longest_module_match(imported, modules)
            if profile:
                detections.append(
                    _detection_from_profile(
                        profile,
                        SourceEvidenceLevel.IMPORT,
                        number,
                        line,
                        imported,
                    )
                )
            break

    return detections


def _call_text(lines: list[str], start_index: int, open_paren: int) -> str:
    """Return the text of a call expression, following it across lines.

    Multi-line calls are the norm in JavaScript and Java::

        crypto.generateKeyPairSync("rsa", {
          modulusLength: 2048,
        });

    Reading only the first line would miss the key size entirely. This walks
    forward tracking parenthesis depth and stops at the matching close, so the
    text returned belongs to *this* call and cannot pick up an argument from an
    unrelated one further down the file.

    The scan is bounded to a few lines. An argument list longer than that is
    unusual, and an unbounded walk on malformed source could run to end of file.

    Args:
        lines: File lines.
        start_index: Zero-based index of the line holding the call.
        open_paren: Column of the call's opening parenthesis.

    Returns:
        The call text, from the opening parenthesis to its match.
    """
    max_lines = 6
    depth = 0
    collected: list[str] = []

    for offset in range(max_lines):
        index = start_index + offset
        if index >= len(lines):
            break
        line = lines[index]
        begin = open_paren if offset == 0 else 0

        for position in range(begin, len(line)):
            char = line[position]
            collected.append(char)
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return "".join(collected)
        collected.append(" ")

    return "".join(collected)


def _detect_calls(
    lines: list[str], language: str, calls: dict[str, ApiProfile]
) -> list[SourceDetection]:
    """Locate known call expressions.

    Each pattern requires the dotted name followed by an opening parenthesis,
    so an identifier merely mentioned in prose or used as a variable name never
    matches.

    Some calls name their algorithm in a string argument rather than in the
    method name — ``crypto.createHash("sha256")``,
    ``crypto.createCipheriv("aes-256-cbc", ...)``. These are detected the same
    way Java factories are: read the first string argument and resolve it. A
    call whose argument is a variable yields a finding with no algorithm, which
    is the honest outcome — the primitive genuinely cannot be determined
    without executing the program.
    """
    detections: list[SourceDetection] = []

    compiled = [
        (re.compile(r"\b" + re.escape(pattern) + r"\s*\("), pattern, profile)
        for pattern, profile in calls.items()
    ]
    first_string = re.compile(r"""["']([^"']+)["']""")

    for number, line in enumerate(lines, start=1):
        for expression, pattern, profile in compiled:
            match = expression.search(line)
            if not match:
                continue

            # The full call text, following the argument list across lines.
            call_text = _call_text(lines, number - 1, line.index("(", match.start()))

            detection = _detection_from_profile(
                profile, SourceEvidenceLevel.CALL_SITE, number, line, pattern
            )

            # When the method name does not fix the algorithm, the first string
            # argument usually does.
            if profile.resolves_from_argument:
                argument = first_string.search(call_text)
                if argument:
                    resolved = apis.resolve_algorithm_string(argument.group(1))
                    if resolved:
                        detection.algorithm = str(resolved.get("algorithm", ""))
                        detection.family = str(resolved.get("family", detection.family))
                        detection.role = str(resolved.get("role", detection.role))
                        detection.mode = str(resolved.get("mode", detection.mode))
                        if resolved.get("key_size") is not None:
                            detection.key_size = int(resolved["key_size"])
                        if resolved.get("legacy"):
                            detection.legacy = True
                        if resolved.get("note"):
                            detection.note = str(resolved["note"])
                        detection.api = f'{pattern}("{argument.group(1)}")'

            # An explicit key-size argument overrides any size inferred from a
            # cipher name, because it is the more specific statement.
            if profile.key_size_arg:
                explicit = _extract_key_size(call_text, profile.key_size_arg)
                if explicit is not None:
                    detection.key_size = explicit

            detections.append(detection)

    return detections


def _extract_key_size(line: str, argument: str) -> int | None:
    """Read an explicit key size from a call line.

    Handles a named argument (``modulusLength: 2048``, ``bits: 2048``) and Go's
    positional convention (``rsa.GenerateKey(rand.Reader, 2048)``).

    Returns ``None`` whenever the value is not a literal integer, so a key size
    is never inferred.
    """
    if argument.startswith("positional_"):
        try:
            position = int(argument.split("_", 1)[1])
        except ValueError:
            return None
        inner = re.search(r"\(([^()]*)\)", line)
        if not inner:
            return None
        parts = [part.strip() for part in inner.group(1).split(",")]
        if len(parts) >= position:
            candidate = parts[position - 1]
            return int(candidate) if re.fullmatch(r"\d+", candidate) else None
        return None

    match = re.search(re.escape(argument) + r"\s*[:=]\s*(\d+)", line)
    return int(match.group(1)) if match else None


def _detect_factories(
    lines: list[str], language: str, factories: dict[str, ApiProfile]
) -> list[SourceDetection]:
    """Locate factory methods whose string argument names the algorithm.

    This is how the Java Cryptography Architecture works throughout —
    ``Cipher.getInstance("AES/GCM/NoPadding")`` — so the argument must be read
    to learn anything at all. A factory whose argument is a variable yields no
    finding, because the algorithm genuinely cannot be determined statically.
    """
    detections: list[SourceDetection] = []

    compiled = [
        (
            re.compile(r"\b" + re.escape(pattern) + r"""\s*\(\s*["']([^"']+)["']"""),
            pattern,
            profile,
        )
        for pattern, profile in factories.items()
    ]

    for number, line in enumerate(lines, start=1):
        for expression, pattern, profile in compiled:
            match = expression.search(line)
            if not match:
                continue

            resolved = apis.resolve_algorithm_string(match.group(1))
            if resolved is None:
                # The argument names something the knowledge base does not
                # recognise. Reporting a finding here would assert an algorithm
                # we cannot identify.
                continue

            detections.append(
                SourceDetection(
                    algorithm=str(resolved.get("algorithm", "")),
                    family=str(resolved.get("family", profile.family)),
                    role=str(resolved.get("role", profile.role)),
                    evidence_level=SourceEvidenceLevel.CONFIGURATION,
                    line=number,
                    snippet=_clean_snippet(line),
                    api=f'{pattern}("{match.group(1)}")',
                    mode=str(resolved.get("mode", "")),
                    key_size=resolved.get("key_size"),
                    legacy=bool(resolved.get("legacy", False)),
                    # The resolved algorithm's note is more specific than the
                    # factory's: it can explain, for instance, that SHA1withRSA
                    # is unsuitable because of the digest, which is a different
                    # concern from RSA's quantum vulnerability.
                    note=str(resolved.get("note", profile.note)),
                )
            )

    return detections


def detect_patterns(text: str, language: str) -> tuple[list[SourceDetection], str]:
    """Analyse a brace-language file with deterministic patterns.

    Comments are blanked first, so prose mentioning an algorithm cannot
    produce a finding. String literals are preserved, because Java and Node
    both carry algorithm names inside them.
    """
    lines = strip_comments(text, language)

    modules = apis.constructs_for(language, apis.CONSTRUCT_MODULES)
    calls = apis.constructs_for(language, apis.CONSTRUCT_CALLS)
    factories = apis.constructs_for(language, apis.CONSTRUCT_FACTORIES)

    detections: list[SourceDetection] = []
    detections.extend(_detect_imports(lines, language, modules))
    detections.extend(_detect_calls(lines, language, calls))
    detections.extend(_detect_factories(lines, language, factories))

    return detections, ""


# ==========================================================================
# Confidence
# ==========================================================================


def assess_confidence(
    detection: SourceDetection, language: str
) -> tuple[Confidence, DetectionMethod]:
    """Grade a detection and record how it was found.

    Two axes combine:

    *How certain is the parse?* Python is analysed with a real syntax tree, so
    a matched construct is structurally unambiguous. The other languages use
    patterns over comment-stripped text, which is reliable but can still be
    fooled by an algorithm name inside an unrelated string literal.

    *How strong is the claim?* A call site demonstrates invocation. An import
    demonstrates only that a module is referenced — it may be unused, or
    present purely for a type annotation.

    An import therefore never reaches HIGH regardless of parse quality, because
    the weakness is in the claim rather than the parsing.
    """
    is_ast = language == "python"
    method = DetectionMethod.AST_PARSE if is_ast else DetectionMethod.PATTERN_MATCH

    if detection.evidence_level is SourceEvidenceLevel.IMPORT:
        return Confidence.LOW, method

    if detection.evidence_level is SourceEvidenceLevel.CALL_SITE:
        return (Confidence.HIGH if is_ast else Confidence.MEDIUM), method

    # CONFIGURATION: a named mode or an algorithm read from a factory argument.
    return (Confidence.HIGH if is_ast else Confidence.MEDIUM), method


# ==========================================================================
# Finding construction
# ==========================================================================


def _build_variant(algorithm: str, key_size: int | None) -> str:
    """Compose a variant only when the source supplied a key size.

    ``rsa.generate_private_key(key_size=2048)`` becomes ``RSA-2048``.
    ``rsa.generate_private_key(**config)`` stays ``RSA`` — inventing a size
    would fabricate the single most consequential detail in the finding.
    """
    if not algorithm or key_size is None:
        return algorithm
    if algorithm.startswith(("ML-KEM", "ML-DSA", "SLH-DSA")):
        return algorithm
    return f"{algorithm}-{key_size}"


def to_finding(
    detection: SourceDetection,
    scan_id: str,
    path: str,
    component: str,
    language: SourceLanguage,
    detection_language: str,
) -> CryptoFinding:
    """Build a canonical finding from a source detection."""
    confidence, method = assess_confidence(detection, detection_language)

    evidence = f"{Path(path).name}:{detection.line} → {detection.snippet}"
    if len(evidence) > MAX_EVIDENCE_CHARS + 40:
        evidence = evidence[: MAX_EVIDENCE_CHARS + 37] + "..."

    detail: dict[str, Any] = {
        "language": language.value,
        "api": detection.api,
        "evidence_level": detection.evidence_level.value,
        "evidence_meaning": _EVIDENCE_MEANING[detection.evidence_level],
        "role": detection.role,
    }
    if detection.key_size is None and detection.algorithm:
        detail["key_size_status"] = "not specified in source"
    if detection.legacy:
        detail["legacy_primitive"] = True
    if detection.note:
        detail["note"] = detection.note

    # Identity must separate two real detections that share a line. A statement
    # like `DES.new(key, DES.MODE_ECB)` produces both a call site and a
    # configuration finding: the invocation and the mode are different facts,
    # and both belong in the inventory. Hashing only algorithm plus line would
    # collapse them into one, silently losing the ECB finding.
    identity = "|".join(
        [detection.evidence_level.value, detection.mode, evidence]
    )

    return CryptoFinding(
        finding_id=CryptoFinding.compute_id(
            scan_id, path, detection.algorithm or detection.api, detection.line, identity
        ),
        scan_id=scan_id,
        artefact_type=ArtefactType.ALGORITHM if detection.algorithm else ArtefactType.LIBRARY,
        algorithm=detection.algorithm,
        algorithm_family=detection.family,
        variant=_build_variant(detection.algorithm, detection.key_size),
        key_size=detection.key_size,
        mode=detection.mode,
        source_type=SourceType.SOURCE_CODE,
        location=path,
        line=detection.line,
        component=component,
        detection_method=method,
        evidence=evidence,
        confidence=confidence,
        raw_detail=detail,
    )


#: Plain-language meaning of each evidence level, carried into every finding so
#: the distinction survives into the UI and the exported report.
_EVIDENCE_MEANING: dict[SourceEvidenceLevel, str] = {
    SourceEvidenceLevel.IMPORT: (
        "The module is imported. This shows the cryptographic API is available "
        "to this file, not that it is called."
    ),
    SourceEvidenceLevel.CALL_SITE: (
        "The primitive is invoked at this line. This is the strongest evidence "
        "available without executing the application."
    ),
    SourceEvidenceLevel.CONFIGURATION: (
        "A specific algorithm, mode, or parameter is named at this line."
    ),
}


# ==========================================================================
# Adapter
# ==========================================================================


class SourceAdapter:
    """Discovery adapter for cryptographic usage in application source."""

    name = "source"

    def coverage(self) -> CoverageStatement:
        """Declared scope, rendered in the dashboard beside the results."""
        counts = apis.construct_coverage()
        summary = ", ".join(f"{lang} {count}" for lang, count in counts.items())

        return CoverageStatement(
            adapter=self.name,
            supported=[
                "Python via the standard library AST (imports, calls, constants)",
                "JavaScript and TypeScript via deterministic patterns",
                "Java via JCA/JCE factory and call patterns",
                "Go via crypto package imports and call patterns",
                f"{apis.known_construct_count()} known constructs ({summary})",
                "Explicit key sizes read from literal arguments",
                "Cipher modes read from specification strings, including ECB",
                "Import, call-site, and configuration evidence reported separately",
            ],
            not_supported=[
                "Application code is never executed, imported, or built",
                "Variable and alias resolution — an algorithm assembled at "
                "runtime cannot be determined statically",
                "Key sizes supplied by variables or configuration files",
                "Reflection, dynamic dispatch, and generated code",
                "Languages beyond Python, JavaScript/TypeScript, Java, and Go",
                "Whether a detected call sits on a reachable code path",
            ],
            confidence_notes=(
                "Python is parsed with a real syntax tree, so a matched call is "
                "HIGH confidence. The other languages use patterns over "
                "comment-stripped source and are MEDIUM. An import is LOW "
                "regardless of language, because it shows a module is "
                "referenced rather than used — that limit is in the claim, not "
                "in the parsing."
            ),
        )

    def supports(self, target: Path) -> bool:
        """True for a directory, or a file with a recognised source suffix."""
        target = Path(target)
        if target.is_dir():
            return True
        return target.suffix.lower() in SOURCE_EXTENSIONS

    def scan(
        self,
        target: Path,
        scan_id: str,
        limits: ScanLimits | None = None,
        resolver: ComponentResolver | None = None,
    ) -> ScanResult:
        """Scan ``target`` for cryptographic usage in source.

        Args:
            target: Repository root or a single source file.
            scan_id: Scan this run belongs to.
            limits: Traversal and size bounds. Defaults applied if omitted.
            resolver: Component attribution.

        Returns:
            Findings, coverage, and any errors. No application code is executed
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

        attribution_root = target if target.is_dir() else target.parent

        for path, stats in safe_walk(target, limits, suffixes=SOURCE_EXTENSIONS):
            walk_stats = stats
            files_examined = stats.files_examined

            suffix = path.suffix.lower()
            detection_language = SOURCE_SUFFIXES.get(suffix)
            if detection_language is None:
                continue

            text = read_text_safely(path, limits)
            if text is None:
                errors.append(f"{path.name}: unreadable")
                continue

            try:
                if detection_language == "python":
                    detections, error = detect_python(text)
                else:
                    detections, error = detect_patterns(text, detection_language)
            except Exception as exc:
                # Defensive: the detectors are bounded, but this runs against
                # untrusted repositories and one hostile file must not end a scan.
                errors.append(f"{path.name}: analysis failed ({exc})")
                continue

            if error:
                errors.append(f"{path.name}: {error}")
                continue

            component = resolver.attribute(attribution_root, path).component
            language = _REPORTED_LANGUAGE.get(suffix, SourceLanguage.PYTHON)
            location = str(path)

            for detection in _deduplicate(detections):
                findings.append(
                    to_finding(
                        detection,
                        scan_id,
                        location,
                        component,
                        language,
                        detection_language,
                    )
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


def _deduplicate(detections: Iterable[SourceDetection]) -> list[SourceDetection]:
    """Collapse detections that describe the same construct at the same line.

    A single line can match several knowledge-base patterns — a call whose name
    is also a prefix of another entry, or an attribute inside a call. Reporting
    each match separately would inflate the inventory without adding
    information.

    Distinct lines are never merged: two calls to the same primitive in
    different places are two real usages, and a migration programme needs both.
    """
    seen: set[tuple[str, str, int, str]] = set()
    unique: list[SourceDetection] = []

    for detection in sorted(
        detections, key=lambda d: (d.line, d.algorithm, d.evidence_level.value)
    ):
        identity = (
            detection.algorithm,
            detection.mode,
            detection.line,
            detection.evidence_level.value,
        )
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(detection)

    return unique


#: Module-level instance, registered for lookup by name.
SOURCE_ADAPTER = discovery.register(SourceAdapter())
