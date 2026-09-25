"""
Aegis PQC — ECDAT Phase 3 tests: source-code cryptographic discovery.

The phase's thesis is that Aegis can move from *"this library provides
cryptography"* to *"this application calls this primitive here"* without
executing anything. These tests are where that claim is checked.

Run Phase 3 only:  pytest tests/ecdat/test_phase3.py -q
Run all ECDAT:     pytest tests/ecdat -q
Run everything:    pytest tests -q
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend import demo_enterprise as de
from backend import demo_manifests as dm
from backend import demo_source as ds
from backend import discovery, inventory
from backend.discovery import ScanLimits, certificates, dependencies, source
from backend.discovery.attribution import ComponentResolver, extract_declared_paths
from backend.discovery.source import (
    detect_patterns,
    detect_python,
    strip_comments,
)
from backend.knowledge import apis
from backend.model import (
    ArtefactType,
    Confidence,
    DetectionMethod,
    ScanStatus,
    SourceEvidenceLevel,
    SourceLanguage,
    SourceType,
)


@pytest.fixture(scope="module")
def estate(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A full estate: certificates, manifests, and source."""
    root = tmp_path_factory.mktemp("phase3_estate")
    de.generate(root, force=True)
    dm.write_application_manifests(root)
    ds.write_application_source(root)
    return root


@pytest.fixture(scope="module")
def resolver(estate: Path) -> ComponentResolver:
    """Component resolver built from the estate's declared policy."""
    raw = inventory._parse_policy_file(estate / "aegis_policy.yaml")
    return ComponentResolver(extract_declared_paths(raw))


@pytest.fixture(scope="module")
def scan(estate: Path, resolver: ComponentResolver):
    """One real source scan of the estate."""
    return source.SOURCE_ADAPTER.scan(estate, "scan_p3", resolver=resolver)


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    """Isolated database with the ECDAT schema."""
    path = tmp_path / "phase3.db"
    inventory.init_ecdat_schema(path)
    return path


def levels(findings) -> dict[str, int]:
    """Count findings by evidence level."""
    counts: dict[str, int] = {}
    for finding in findings:
        key = finding.raw_detail["evidence_level"]
        counts[key] = counts.get(key, 0) + 1
    return counts


# ==========================================================================
# Python — AST detection
# ==========================================================================


def test_python_detects_imports_as_imports() -> None:
    """Claim: an import is reported as an import, never as usage."""
    detections, error = detect_python(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
    )
    assert error == ""
    assert len(detections) == 1
    assert detections[0].algorithm == "RSA"
    assert detections[0].evidence_level is SourceEvidenceLevel.IMPORT


def test_python_detects_call_sites() -> None:
    """Claim: an invocation is reported as a call site."""
    detections, _ = detect_python(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    calls = [d for d in detections if d.evidence_level is SourceEvidenceLevel.CALL_SITE]
    assert len(calls) == 1
    assert calls[0].algorithm == "RSA"
    assert calls[0].key_size == 2048
    assert calls[0].line == 2


def test_python_extracts_only_literal_key_sizes() -> None:
    """Claim: a key size is read, never inferred.

    This is the phase's most consequential rule. ``key_size=2048`` yields 2048.
    ``key_size=configured`` yields nothing — reporting RSA-2048 there would
    fabricate the single most important detail in the finding.
    """
    literal, _ = detect_python("rsa.generate_private_key(key_size=2048)\n")
    assert literal[0].key_size == 2048

    for expression in (
        "rsa.generate_private_key(key_size=configured)",
        "rsa.generate_private_key(**options)",
        "rsa.generate_private_key(key_size=SIZES['rsa'])",
        "rsa.generate_private_key()",
    ):
        detections, _ = detect_python(expression + "\n")
        calls = [
            d for d in detections if d.evidence_level is SourceEvidenceLevel.CALL_SITE
        ]
        assert calls, expression
        assert calls[0].key_size is None, expression
        assert calls[0].algorithm == "RSA"


def test_python_detects_configuration_constants() -> None:
    """Claim: a named mode is detected as configuration."""
    detections, _ = detect_python(
        "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_ECB)\n"
    )
    configuration = [
        d for d in detections if d.evidence_level is SourceEvidenceLevel.CONFIGURATION
    ]
    assert configuration
    assert configuration[0].mode == "ECB"
    assert configuration[0].legacy is True


def test_python_detects_hash_algorithms() -> None:
    """Claim: hash calls resolve to their specific algorithm."""
    detections, _ = detect_python(
        "import hashlib\n"
        "a = hashlib.md5(x)\n"
        "b = hashlib.sha256(x)\n"
        "c = hashlib.sha1(x)\n"
    )
    found = {
        d.algorithm
        for d in detections
        if d.evidence_level is SourceEvidenceLevel.CALL_SITE
    }
    assert {"MD5", "SHA-256", "SHA-1"} <= found


def test_python_detects_post_quantum_usage() -> None:
    """Claim: ML-KEM usage is detected, and only where genuinely present."""
    detections, _ = detect_python(
        "from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey\n"
        "key = MLKEM768PrivateKey.generate()\n"
    )
    calls = [d for d in detections if d.evidence_level is SourceEvidenceLevel.CALL_SITE]
    assert calls[0].algorithm == "ML-KEM-768"


def test_python_syntax_error_is_reported_not_raised() -> None:
    """Claim: unparseable Python yields an error string, not an exception."""
    detections, error = detect_python("def broken(:\n    pass\n")
    assert detections == []
    assert "unparseable" in error


def test_python_handles_unusual_but_valid_syntax() -> None:
    """Claim: modern syntax parses without special handling."""
    text = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "match mode:\n"
        "    case 'rsa':\n"
        "        key = rsa.generate_private_key(key_size=4096)\n"
    )
    detections, error = detect_python(text)
    assert error == ""
    assert any(d.key_size == 4096 for d in detections)


# ==========================================================================
# JavaScript / TypeScript
# ==========================================================================


def test_javascript_detects_require_and_import() -> None:
    """Claim: both module syntaxes are recognised."""
    for text in ('const tls = require("tls");\n', 'import tls from "tls";\n'):
        detections, _ = detect_patterns(text, "javascript")
        assert any(d.algorithm == "TLS" for d in detections), text


def test_javascript_resolves_algorithm_from_string_argument() -> None:
    """Claim: calls naming their algorithm in a string are resolved.

    ``crypto.createHash("sha256")`` says nothing until the argument is read.
    """
    detections, _ = detect_patterns(
        'const h = crypto.createHash("sha256");\n', "javascript"
    )
    calls = [d for d in detections if d.evidence_level is SourceEvidenceLevel.CALL_SITE]
    assert calls[0].algorithm == "SHA-256"


def test_javascript_resolves_cipher_name_with_key_size_and_mode() -> None:
    """Claim: a Node cipher name yields algorithm, key size, and mode."""
    detections, _ = detect_patterns(
        'const c = crypto.createCipheriv("aes-256-cbc", key, iv);\n', "javascript"
    )
    call = [d for d in detections if d.evidence_level is SourceEvidenceLevel.CALL_SITE][0]
    assert call.algorithm == "AES"
    assert call.key_size == 256
    assert call.mode == "CBC"


def test_javascript_reads_key_size_across_lines() -> None:
    """Claim: a multi-line call still yields its key size.

    Multi-line argument objects are the norm in JavaScript; reading only the
    first line would silently lose the key size.
    """
    text = (
        'const pair = crypto.generateKeyPairSync("rsa", {\n'
        "  modulusLength: 2048,\n"
        "});\n"
    )
    detections, _ = detect_patterns(text, "javascript")
    call = [d for d in detections if d.evidence_level is SourceEvidenceLevel.CALL_SITE][0]
    assert call.algorithm == "RSA"
    assert call.key_size == 2048


def test_typescript_uses_the_same_rules(estate: Path, resolver: ComponentResolver, tmp_path: Path) -> None:
    """Claim: TypeScript is analysed and reported as TypeScript."""
    root = tmp_path / "ts"
    (root / "src").mkdir(parents=True)
    (root / "src" / "crypto.ts").write_text(
        'import crypto from "crypto";\n'
        'export const hash = (d: Buffer): string =>\n'
        '  crypto.createHash("sha512").update(d).digest("hex");\n'
    )
    result = source.SOURCE_ADAPTER.scan(root, "scan_ts")
    languages = {f.raw_detail["language"] for f in result.findings}
    assert SourceLanguage.TYPESCRIPT.value in languages
    assert any(f.algorithm == "SHA-512" for f in result.findings)


# ==========================================================================
# Java
# ==========================================================================


def test_java_detects_jca_factories() -> None:
    """Claim: the JCA factory constructions are detected.

    Java names its algorithm in the factory argument throughout, so reading
    that string is the only way to learn anything.
    """
    text = """
    public class Svc {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        MessageDigest d = MessageDigest.getInstance("SHA-256");
        Signature s = Signature.getInstance("SHA256withRSA");
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        KeyAgreement k = KeyAgreement.getInstance("ECDH");
    }
    """
    detections, _ = detect_patterns(text, "java")
    found = {d.algorithm for d in detections}
    assert {"AES", "SHA-256", "RSA", "ECDSA", "ECDH"} <= found


def test_java_extracts_mode_from_cipher_specification() -> None:
    """Claim: the mode segment of a cipher spec is read, and ECB flagged."""
    detections, _ = detect_patterns(
        'Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");\n', "java"
    )
    detection = [d for d in detections if d.algorithm == "DES"][0]
    assert detection.mode == "ECB"
    assert detection.legacy is True


def test_java_factory_with_variable_argument_yields_nothing() -> None:
    """Claim: an algorithm assembled at runtime is not guessed.

    ``Cipher.getInstance(algorithmName)`` cannot be resolved statically, and
    inventing one would be exactly the fabrication this scanner avoids.
    """
    detections, _ = detect_patterns(
        "Cipher c = Cipher.getInstance(algorithmName);\n", "java"
    )
    assert [d for d in detections if d.algorithm] == []


def test_java_detects_imports_separately() -> None:
    """Claim: a Java import is import-level evidence."""
    detections, _ = detect_patterns("import javax.crypto.Cipher;\n", "java")
    assert detections
    assert detections[0].evidence_level is SourceEvidenceLevel.IMPORT


# ==========================================================================
# Go
# ==========================================================================


def test_go_detects_import_block() -> None:
    """Claim: a parenthesised import block is parsed."""
    text = 'package main\n\nimport (\n\t"crypto/rsa"\n\t"crypto/sha256"\n\t"fmt"\n)\n'
    detections, _ = detect_patterns(text, "go")
    found = {d.algorithm for d in detections}
    assert {"RSA", "SHA-256"} <= found
    assert all(d.evidence_level is SourceEvidenceLevel.IMPORT for d in detections)


def test_go_detects_positional_key_size() -> None:
    """Claim: Go's positional key-size convention is read."""
    detections, _ = detect_patterns(
        "key, err := rsa.GenerateKey(rand.Reader, 4096)\n", "go"
    )
    call = [d for d in detections if d.evidence_level is SourceEvidenceLevel.CALL_SITE][0]
    assert call.algorithm == "RSA"
    assert call.key_size == 4096


def test_go_does_not_invent_positional_key_size() -> None:
    """Claim: a variable key size yields RSA with no size."""
    detections, _ = detect_patterns(
        "key, err := rsa.GenerateKey(rand.Reader, bits)\n", "go"
    )
    call = [d for d in detections if d.evidence_level is SourceEvidenceLevel.CALL_SITE][0]
    assert call.algorithm == "RSA"
    assert call.key_size is None


def test_go_detects_legacy_primitives() -> None:
    """Claim: MD5 and DES usage in Go is detected and flagged."""
    detections, _ = detect_patterns(
        'import (\n\t"crypto/md5"\n)\n\nfunc h() { return md5.Sum(data) }\n', "go"
    )
    assert any(d.algorithm == "MD5" and d.legacy for d in detections)


# ==========================================================================
# False-positive discipline
# ==========================================================================


def test_comments_never_produce_findings() -> None:
    """Claim: prose mentioning an algorithm is not a finding.

    This is the single most important false-positive control. Comments are
    blanked before matching, so a TODO about RSA cannot become evidence of RSA.
    """
    for language, text in (
        ("javascript", "// TODO: migrate from RSA to ML-KEM\n/* uses AES and MD5 */\n"),
        ("java", "// Cipher.getInstance(\"AES/ECB/NoPadding\") was removed\n"),
        ("go", "// crypto/rsa is no longer imported here\n"),
    ):
        detections, _ = detect_patterns(text, language)
        assert detections == [], f"{language} matched inside a comment"


def test_block_comments_are_stripped_across_lines() -> None:
    """Claim: a multi-line comment cannot produce findings."""
    text = (
        "/*\n"
        ' Cipher.getInstance("DES/ECB/PKCS5Padding");\n'
        " MessageDigest.getInstance(\"MD5\");\n"
        "*/\n"
        'Cipher real = Cipher.getInstance("AES/GCM/NoPadding");\n'
    )
    detections, _ = detect_patterns(text, "java")
    assert {d.algorithm for d in detections} == {"AES"}


def test_string_literals_are_preserved_for_factories() -> None:
    """Claim: comment stripping does not destroy factory arguments.

    Java carries its algorithm inside a string, so blanking string literals
    would remove the detection this scanner exists to make.
    """
    cleaned = strip_comments(
        'Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); // safe\n', "java"
    )
    assert "AES/GCM/NoPadding" in cleaned[0]
    assert "safe" not in cleaned[0]


def test_variable_names_alone_are_not_findings() -> None:
    """Claim: an identifier mentioning an algorithm is not usage."""
    for language, text in (
        ("javascript", "const rsaTicketFormat = 'v2';\nlet aesRegion = 'eu-west-1';\n"),
        ("go", "var md5Prefix = \"cache\"\nrsaEnabled := false\n"),
        ("java", "String rsaMode = config.get(\"mode\");\n"),
    ):
        detections, _ = detect_patterns(text, language)
        assert detections == [], f"{language} matched a variable name"


def test_python_docstrings_and_comments_are_not_findings() -> None:
    """Claim: Python prose is ignored because the AST ignores it."""
    text = (
        '"""This module documents RSA, AES, MD5 and SHA-256 usage elsewhere."""\n'
        "# hashlib.md5 was removed in 2024\n"
        "RSA_LABEL = 'rsa'\n"
    )
    detections, error = detect_python(text)
    assert error == ""
    assert detections == []


def test_markdown_is_never_scanned(estate: Path) -> None:
    """Claim: README prose is out of scope entirely.

    ``.md`` is not a source suffix, so documentation never enters the walk.
    """
    result = source.SOURCE_ADAPTER.scan(estate, "scan_md")
    assert all(not f.location.endswith(".md") for f in result.findings)


def test_clean_application_produces_zero_findings(scan) -> None:
    """Claim: an application with no cryptography yields nothing.

    ``content-portal`` is seeded with comments, identifiers, and a README
    naming RSA, AES, and MD5. Any finding here would be a false positive, and
    "we found nothing, and that is correct" is a harder claim to earn than a
    long list.
    """
    assert {f.component for f in scan.findings} & ds.SOURCE_CLEAN_APPLICATIONS == set()


# ==========================================================================
# Evidence and confidence model
# ==========================================================================


def test_all_three_evidence_levels_are_produced(scan) -> None:
    """Claim: the scanner distinguishes import, call site, and configuration."""
    counts = levels(scan.findings)
    assert counts.get("import", 0) > 0
    assert counts.get("call_site", 0) > 0
    assert counts.get("configuration", 0) > 0


def test_imports_are_never_high_confidence(scan) -> None:
    """Claim: an import cannot reach HIGH, whatever the parser.

    The weakness is in the claim rather than the parsing: an imported module
    may be unused, re-exported, or present only for a type annotation.
    """
    for finding in scan.findings:
        if finding.raw_detail["evidence_level"] == "import":
            assert finding.confidence is Confidence.LOW


def test_python_call_sites_are_high_confidence(scan) -> None:
    """Claim: an AST-matched call is the strongest static evidence."""
    python_calls = [
        f
        for f in scan.findings
        if f.raw_detail["language"] == "python"
        and f.raw_detail["evidence_level"] == "call_site"
    ]
    assert python_calls
    for finding in python_calls:
        assert finding.confidence is Confidence.HIGH
        assert finding.detection_method is DetectionMethod.AST_PARSE


def test_pattern_languages_cap_at_medium(scan) -> None:
    """Claim: pattern matching does not claim AST-level certainty."""
    pattern_calls = [
        f
        for f in scan.findings
        if f.raw_detail["language"] in ("javascript", "typescript", "java", "go")
        and f.raw_detail["evidence_level"] != "import"
    ]
    assert pattern_calls
    for finding in pattern_calls:
        assert finding.confidence is Confidence.MEDIUM
        assert finding.detection_method is DetectionMethod.PATTERN_MATCH


def test_every_finding_explains_its_evidence_level(scan) -> None:
    """Claim: the import-versus-usage distinction survives into the finding.

    The meaning travels with the data so it reaches the UI and the exported
    report, rather than living only in a docstring.
    """
    for finding in scan.findings:
        meaning = finding.raw_detail.get("evidence_meaning", "")
        assert meaning
        if finding.raw_detail["evidence_level"] == "import":
            assert "not that it is called" in meaning


def test_unknown_key_size_is_stated_not_omitted(scan) -> None:
    """Claim: an unknown key size is reported as unknown."""
    unknown = [
        f
        for f in scan.findings
        if f.algorithm and f.key_size is None and f.raw_detail.get("key_size_status")
    ]
    assert unknown
    assert unknown[0].raw_detail["key_size_status"] == "not specified in source"


def test_variant_never_asserts_an_unread_key_size(scan) -> None:
    """Claim: ``RSA-2048`` appears only where the source said 2048."""
    for finding in scan.findings:
        if finding.variant and "-" in finding.variant and finding.algorithm == "RSA":
            assert finding.key_size is not None
            assert finding.variant.endswith(str(finding.key_size))


# ==========================================================================
# Estate results
# ==========================================================================


def test_estate_scan_covers_all_four_languages(scan) -> None:
    """Claim: one scan analyses Python, JavaScript, Java, and Go."""
    assert scan.status is ScanStatus.COMPLETED
    assert scan.errors == []
    languages = {f.raw_detail["language"] for f in scan.findings}
    assert {"python", "javascript", "java", "go"} <= languages


def test_payments_api_shows_explicit_rsa_2048(scan) -> None:
    """Claim: the headline case is detected with its literal key size."""
    payments = [f for f in scan.findings if f.component == "payments-api"]
    rsa_calls = [
        f
        for f in payments
        if f.algorithm == "RSA" and f.raw_detail["evidence_level"] == "call_site"
    ]
    assert any(f.key_size == 2048 and f.variant == "RSA-2048" for f in rsa_calls)
    # The configuration-driven call in the same file must stay unsized.
    assert any(f.key_size is None and f.variant == "RSA" for f in rsa_calls)


def test_legacy_auth_shows_multiple_legacy_primitives(scan) -> None:
    """Claim: legacy primitives are surfaced as their own concern.

    MD5, DES, and ECB are problems independent of quantum computing. A tool
    that reported only quantum exposure would miss them entirely.
    """
    legacy_auth = [f for f in scan.findings if f.component == "legacy-auth"]
    algorithms = {f.algorithm for f in legacy_auth}
    assert {"MD5", "DES", "RSA"} <= algorithms
    assert any(f.mode == "ECB" for f in legacy_auth)
    assert any(f.raw_detail.get("legacy_primitive") for f in legacy_auth)


def test_pqc_pilot_shows_post_quantum_and_hybrid(scan) -> None:
    """Claim: post-quantum usage is detected, and the hybrid legs are both seen.

    A hybrid is two key establishments feeding one KDF. Detecting only the
    post-quantum leg would misrepresent the construction.
    """
    pilot = [f for f in scan.findings if f.component == "pqc-pilot"]
    calls = {
        f.algorithm for f in pilot if f.raw_detail["evidence_level"] == "call_site"
    }
    assert "ML-KEM-768" in calls
    assert "X25519" in calls
    assert "HKDF" in calls


def test_components_are_attributed_from_declared_paths(scan) -> None:
    """Claim: source findings land on the declared application."""
    components = {f.component for f in scan.findings}
    assert ds.SOURCE_CRYPTO_APPLICATIONS <= components


def test_findings_carry_file_and_line(scan) -> None:
    """Claim: every finding points at a specific location."""
    for finding in scan.findings:
        assert finding.location
        assert finding.line is not None and finding.line > 0
        assert f":{finding.line}" in finding.evidence


# ==========================================================================
# Determinism and duplicates
# ==========================================================================


def test_repeat_scans_are_identical(estate: Path, resolver: ComponentResolver) -> None:
    """Claim: unchanged source scans identically every time."""
    first = source.SOURCE_ADAPTER.scan(estate, "scan_det", resolver=resolver)
    second = source.SOURCE_ADAPTER.scan(estate, "scan_det", resolver=resolver)
    assert [f.finding_id for f in first.findings] == [
        f.finding_id for f in second.findings
    ]


def test_finding_ids_are_unique_within_a_scan(scan) -> None:
    """Claim: no two findings collide on an id."""
    ids = [f.finding_id for f in scan.findings]
    assert len(ids) == len(set(ids))


def test_repeated_imports_do_not_multiply(tmp_path: Path) -> None:
    """Claim: the same construct at one line is reported once."""
    root = tmp_path / "dup"
    root.mkdir()
    (root / "a.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
    )
    result = source.SOURCE_ADAPTER.scan(root, "scan_dup")
    # Two separate lines are two real statements; one line is one finding.
    assert len(result.findings) == 2
    assert len({f.line for f in result.findings}) == 2


def test_same_primitive_at_different_lines_is_kept(tmp_path: Path) -> None:
    """Claim: two call sites are two findings.

    Collapsing them would hide a usage a migration programme must change.
    """
    root = tmp_path / "multi"
    root.mkdir()
    (root / "a.py").write_text(
        "import hashlib\n"
        "a = hashlib.md5(x)\n"
        "b = hashlib.md5(y)\n"
    )
    result = source.SOURCE_ADAPTER.scan(root, "scan_multi")
    md5 = [f for f in result.findings if f.algorithm == "MD5"]
    assert len(md5) == 2
    assert {f.line for f in md5} == {2, 3}


# ==========================================================================
# Safety
# ==========================================================================


def test_adapter_never_executes_source() -> None:
    """Claim: no execution path exists in the source adapter.

    A static check. ``ast.parse`` builds a tree without evaluating it; nothing
    here imports, compiles, or runs the analysed file.

    ``re.compile`` is excluded before matching — compiling a regular expression
    is not executing source, and leaving it in would make this test fire on its
    own tooling rather than on a real risk.
    """
    text = Path(source.__file__).read_text(encoding="utf-8").replace("re.compile(", "")
    for forbidden in (
        "subprocess", "os.system", "popen", "eval(", "exec(",
        "importlib", "__import__", "compile(", "runpy",
    ):
        assert forbidden not in text, f"source adapter references {forbidden!r}"


def test_ast_parse_does_not_evaluate(tmp_path: Path) -> None:
    """Claim: parsing hostile source has no side effect.

    The file below would create a marker if executed. Parsing must leave the
    filesystem untouched.
    """
    marker = tmp_path / "SHOULD_NOT_EXIST"
    root = tmp_path / "hostile"
    root.mkdir()
    (root / "evil.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed')\n"
        "import hashlib\n"
        "hashlib.md5(b'x')\n"
    )

    result = source.SOURCE_ADAPTER.scan(root, "scan_hostile")
    assert not marker.exists(), "analysed source was executed"
    assert any(f.algorithm == "MD5" for f in result.findings)


def test_traversal_safety_is_inherited(tmp_path: Path) -> None:
    """Claim: build and VCS directories are never descended into."""
    root = tmp_path / "estate"
    (root / "app").mkdir(parents=True)
    (root / "app" / "main.py").write_text("import hashlib\nhashlib.sha256(b'')\n")
    for noisy in ("node_modules", ".git", "__pycache__"):
        (root / noisy).mkdir(parents=True)
        (root / noisy / "x.py").write_text("import hashlib\nhashlib.md5(b'')\n")

    result = source.SOURCE_ADAPTER.scan(root, "scan_prune")
    assert {Path(f.location).parent.name for f in result.findings} == {"app"}


def test_symlinks_are_refused(tmp_path: Path) -> None:
    """Claim: symlinks are not followed."""
    root = tmp_path / "estate"
    (root / "app").mkdir(parents=True)
    (root / "app" / "real.py").write_text("import hashlib\nhashlib.sha256(b'')\n")

    outside = tmp_path / "outside.py"
    outside.write_text("import hashlib\nhashlib.md5(b'')\n")
    try:
        (root / "app" / "link.py").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")

    result = source.SOURCE_ADAPTER.scan(root, "scan_link")
    assert all(Path(f.location).name != "link.py" for f in result.findings)


def test_oversized_source_is_skipped(tmp_path: Path) -> None:
    """Claim: the size ceiling applies to source files."""
    root = tmp_path / "big"
    root.mkdir()
    (root / "huge.py").write_text("import hashlib\n" + "# pad\n" * 20000)
    result = source.SOURCE_ADAPTER.scan(
        root, "scan_big", limits=ScanLimits(max_file_bytes=500)
    )
    assert result.findings == []


def test_evidence_is_bounded(scan) -> None:
    """Claim: no finding carries an unbounded quantity of source."""
    for finding in scan.findings:
        assert len(finding.evidence) <= 240


def test_long_line_does_not_leak_unbounded_content(tmp_path: Path) -> None:
    """Claim: a pathological line is truncated rather than captured whole.

    Without truncation a minified bundle or a long literal could push a large
    quantity of file content into a finding, and from there into a report.
    """
    root = tmp_path / "long"
    root.mkdir()
    padding = "x" * 5000
    (root / "a.py").write_text(f"import hashlib\nresult = hashlib.md5(b'{padding}')\n")

    result = source.SOURCE_ADAPTER.scan(root, "scan_long")
    assert result.findings
    for finding in result.findings:
        assert len(finding.evidence) <= 240
        assert padding not in finding.evidence


def test_malformed_source_does_not_end_the_scan(tmp_path: Path) -> None:
    """Claim: one broken file does not prevent the rest being analysed."""
    root = tmp_path / "mixed"
    root.mkdir()
    (root / "broken.py").write_text("def (:\n  ???\n")
    (root / "binary.py").write_bytes(b"\x00\x01\x02\xff\xfe")
    (root / "good.py").write_text("import hashlib\nhashlib.sha256(b'')\n")

    result = source.SOURCE_ADAPTER.scan(root, "scan_mixed")
    assert any(f.algorithm == "SHA-256" for f in result.findings)
    assert result.status is ScanStatus.PARTIAL
    assert result.errors


def test_empty_repository_scans_cleanly(tmp_path: Path) -> None:
    """Claim: a repository with no source returns an empty result."""
    root = tmp_path / "empty"
    root.mkdir()
    result = source.SOURCE_ADAPTER.scan(root, "scan_empty")
    assert result.status is ScanStatus.COMPLETED
    assert result.findings == []


def test_unsupported_language_is_ignored(tmp_path: Path) -> None:
    """Claim: a language we do not analyse produces nothing.

    Guessing at Ruby or Rust would be a claim the scanner cannot back.
    """
    root = tmp_path / "other"
    root.mkdir()
    (root / "main.rb").write_text("require 'openssl'\nOpenSSL::Digest::MD5.new\n")
    (root / "main.rs").write_text('use ring::digest;\nfn f() { digest::SHA256; }\n')

    result = source.SOURCE_ADAPTER.scan(root, "scan_other")
    assert result.findings == []


def test_missing_target_fails_cleanly(tmp_path: Path) -> None:
    """Claim: a bad path is a reported failure, not an exception."""
    result = source.SOURCE_ADAPTER.scan(tmp_path / "nope", "scan_missing")
    assert result.status is ScanStatus.FAILED
    assert result.errors


def test_coverage_declares_real_limits() -> None:
    """Claim: the adapter states what it cannot do."""
    coverage = source.SOURCE_ADAPTER.coverage()
    joined = " ".join(coverage.not_supported).lower()
    assert "never executed" in joined
    assert "alias resolution" in joined or "variable and alias" in joined
    assert "reachable code path" in joined
    assert coverage.confidence_notes


def test_demo_source_contains_no_secrets(estate: Path) -> None:
    """Claim: the demonstration source carries no credentials.

    It is published in a public repository and screenshotted in a presentation.
    """
    for relative in ds.APPLICATION_SOURCE:
        text = (estate / relative).read_text(encoding="utf-8").lower()
        for marker in ("password =", "secret =", "api_key", "-----begin", "token ="):
            assert marker not in text, f"{relative} contains {marker!r}"


# ==========================================================================
# Integration — three surfaces, one model
# ==========================================================================


def test_all_three_adapters_are_registered() -> None:
    """Claim: the registry holds three conforming adapters."""
    assert {"certificates", "dependencies", "source"} <= set(
        discovery.available_adapters()
    )
    for name in ("certificates", "dependencies", "source"):
        adapter = discovery.get_adapter(name)
        assert isinstance(adapter, discovery.DiscoveryAdapter)
        assert adapter.coverage().not_supported


def test_three_surfaces_share_one_model_and_one_inventory(
    estate: Path, resolver: ComponentResolver, db: Path
) -> None:
    """Claim: certificates, dependencies, and source persist identically.

    This is the phase's structural test. Three discovery surfaces with
    completely different semantics — keys, manifests, syntax trees — reach the
    same tables through the same code path, with no surface-specific schema.
    """
    scans = [
        certificates.CERTIFICATE_ADAPTER.scan(estate, "scan_all"),
        dependencies.DEPENDENCY_ADAPTER.scan(estate, "scan_all", resolver=resolver),
        source.SOURCE_ADAPTER.scan(estate, "scan_all", resolver=resolver),
    ]
    expected = sum(len(s.findings) for s in scans)
    for result in scans:
        inventory.record_scan(result, db)

    reloaded = inventory.get_findings("scan_all", db)
    assert len(reloaded) == expected
    assert {f.source_type for f in reloaded} == {
        SourceType.CERTIFICATE_FILE,
        SourceType.DEPENDENCY,
        SourceType.SOURCE_CODE,
    }


def test_mixed_summary_aggregates_three_surfaces(
    estate: Path, resolver: ComponentResolver, db: Path
) -> None:
    """Claim: the inventory summary needed no change for a third surface."""
    for result in (
        certificates.CERTIFICATE_ADAPTER.scan(estate, "scan_sum3"),
        dependencies.DEPENDENCY_ADAPTER.scan(estate, "scan_sum3", resolver=resolver),
        source.SOURCE_ADAPTER.scan(estate, "scan_sum3", resolver=resolver),
    ):
        inventory.record_scan(result, db)

    summary = inventory.inventory_summary("scan_sum3", db)
    assert set(summary["by_source_type"]) == {
        "certificate_file",
        "dependency",
        "source_code",
    }
    assert sum(summary["by_source_type"].values()) == summary["total_findings"]
    assert summary["by_artefact_type"]["algorithm"] > 0


def test_source_findings_survive_persistence(
    estate: Path, resolver: ComponentResolver, db: Path
) -> None:
    """Claim: line numbers, modes, and evidence levels round-trip intact."""
    result = source.SOURCE_ADAPTER.scan(estate, "scan_persist3", resolver=resolver)
    inventory.record_scan(result, db)

    reloaded = {f.finding_id: f for f in inventory.get_findings("scan_persist3", db)}
    assert len(reloaded) == len(result.findings)

    for original in result.findings:
        stored = reloaded[original.finding_id]
        assert stored.line == original.line
        assert stored.mode == original.mode
        assert stored.key_size == original.key_size
        assert stored.confidence is original.confidence
        assert stored.raw_detail["evidence_level"] == (
            original.raw_detail["evidence_level"]
        )


def test_discovery_still_emits_no_assessment(scan) -> None:
    """Claim: the three-layer separation holds for the third adapter."""
    assets = inventory.build_assets(scan.findings)
    assert assets
    assert all(asset.assessment is None for asset in assets)

    serialised = json.dumps([f.to_dict() for f in scan.findings])
    for forbidden in ('"risk_level"', '"migration_priority"', '"mosca"'):
        assert forbidden not in serialised


def test_source_proves_usage_where_dependencies_only_proved_capability(
    estate: Path, resolver: ComponentResolver
) -> None:
    """Claim: the phase's thesis holds — capability becomes located usage.

    Phase 2 established that payments-api *depends on* a library providing RSA.
    Phase 3 establishes that payments-api *calls* RSA key generation, at a
    specific file and line, with a specific key size. Both claims are real;
    only the second is actionable at a call site.
    """
    dependency_scan = dependencies.DEPENDENCY_ADAPTER.scan(
        estate, "scan_thesis", resolver=resolver
    )
    source_scan = source.SOURCE_ADAPTER.scan(
        estate, "scan_thesis", resolver=resolver
    )

    # Dependency evidence: a library, with no algorithm asserted.
    libraries = [
        f
        for f in dependency_scan.findings
        if f.component == "payments-api" and f.artefact_type is ArtefactType.LIBRARY
    ]
    assert libraries
    assert all(f.algorithm == "" for f in libraries)
    assert any(
        "RSA" in f.raw_detail.get("provides_algorithms", []) for f in libraries
    )

    # Source evidence: a named algorithm, at a line, with a key size.
    usage = [
        f
        for f in source_scan.findings
        if f.component == "payments-api"
        and f.algorithm == "RSA"
        and f.raw_detail["evidence_level"] == "call_site"
        and f.key_size == 2048
    ]
    assert usage
    assert usage[0].line is not None
    assert usage[0].location.endswith(".py")
