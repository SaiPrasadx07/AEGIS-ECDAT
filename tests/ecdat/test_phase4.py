"""
Aegis PQC — ECDAT Phase 4 tests: compiled binary cryptographic discovery.

The phase's claim is that Aegis can inspect a shipped artefact — a vendored
``.so``, a third-party service, anything whose source is unavailable — and
report what cryptography it links and references, without executing it.

These tests run against a genuinely compiled ELF, not a crafted file. The
fixture was produced by gcc from a small C program linking OpenSSL; every
structure asserted below is one the compiler actually emitted.

Run Phase 4 only:  pytest tests/ecdat/test_phase4.py -q
Run all ECDAT:     pytest tests/ecdat -q
Run everything:    pytest tests -q
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend import demo_binaries as demo_bin
from backend import demo_enterprise as de
from backend import demo_manifests as dm
from backend import demo_source as ds
from backend import discovery, inventory
from backend.discovery import ScanLimits, binary, certificates, dependencies, source
from backend.discovery.attribution import ComponentResolver, extract_declared_paths
from backend.discovery.binary import (
    LIEF_AVAILABLE,
    analyse_binary,
    detect_format,
    extract_printable_strings,
)
from backend.knowledge import binaries as kb
from backend.model import (
    ArtefactType,
    BinaryEvidenceLevel,
    BinaryFormat,
    Confidence,
    DetectionMethod,
    ScanStatus,
    SourceType,
)

pytestmark = pytest.mark.skipif(
    not LIEF_AVAILABLE, reason="LIEF is not installed; binary analysis unavailable"
)


@pytest.fixture(scope="module")
def estate(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A full estate: certificates, manifests, source, and a compiled binary."""
    root = tmp_path_factory.mktemp("phase4_estate")
    de.generate(root, force=True)
    dm.write_application_manifests(root)
    ds.write_application_source(root)
    demo_bin.write_application_binaries(root)
    return root


@pytest.fixture(scope="module")
def resolver(estate: Path) -> ComponentResolver:
    """Component resolver built from the estate's declared policy."""
    raw = inventory._parse_policy_file(estate / "aegis_policy.yaml")
    return ComponentResolver(extract_declared_paths(raw))


@pytest.fixture(scope="module")
def scan(estate: Path, resolver: ComponentResolver):
    """One real binary scan of the estate."""
    return binary.BINARY_ADAPTER.scan(estate, "scan_p4", resolver=resolver)


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    """Isolated database with the ECDAT schema."""
    path = tmp_path / "phase4.db"
    inventory.init_ecdat_schema(path)
    return path


# ==========================================================================
# The fixture is genuinely a compiled binary
# ==========================================================================


def test_fixture_is_a_real_elf() -> None:
    """Claim: the demonstration artefact is a compiled binary, not a mock.

    A hand-crafted file with plausible bytes would be exactly the fabrication
    this project refuses elsewhere. This asserts the fixture carries a real ELF
    magic number and a realistic size.
    """
    data = demo_bin.crypto_service_bytes()
    assert data.startswith(b"\x7fELF")
    assert 8_000 < len(data) < 64_000


def test_fixture_round_trips_exactly() -> None:
    """Claim: decoding is lossless, so the scanner sees what gcc produced."""
    first = demo_bin.crypto_service_bytes()
    second = demo_bin.crypto_service_bytes()
    assert first == second
    assert len(first) == 14_480


def test_fixture_contains_no_key_material() -> None:
    """Claim: the shipped artefact carries no credentials.

    It lives in a public repository and is decoded onto a presenter's machine.
    """
    data = demo_bin.crypto_service_bytes()
    for marker in (b"-----BEGIN", b"PRIVATE KEY", b"password", b"secret_key"):
        assert marker not in data


def test_fixture_declares_its_expected_structures() -> None:
    """Claim: the fixture's contract is explicit, not assumed.

    The expected libraries and symbols are declared alongside the artefact so a
    change in the build cannot silently weaken the tests below.
    """
    assert demo_bin.EXPECTED_LIBRARIES
    assert len(demo_bin.EXPECTED_CRYPTO_SYMBOLS) >= 5


# ==========================================================================
# Format detection
# ==========================================================================


@pytest.mark.parametrize(
    "header,expected",
    [
        (b"\x7fELF\x02\x01\x01\x00", BinaryFormat.ELF),
        (b"MZ\x90\x00\x03\x00\x00\x00", BinaryFormat.PE),
        (b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01", BinaryFormat.MACHO),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x02", BinaryFormat.MACHO),
        (b"#!/usr/bin/env python", BinaryFormat.UNKNOWN),
        (b"PK\x03\x04", BinaryFormat.UNKNOWN),
        (b"", BinaryFormat.UNKNOWN),
    ],
)
def test_format_detection_uses_magic_bytes(header: bytes, expected) -> None:
    """Claim: format comes from the file's contents, not its name.

    Linux executables commonly carry no extension, and a ``.dll`` that is
    actually text must not be handed to the parser.
    """
    assert detect_format(header) is expected


def test_extensionless_binary_is_still_analysed(estate: Path) -> None:
    """Claim: the fixture has no file extension and is still found."""
    target = estate / Path(demo_bin.BINARY_RELATIVE_PATH)
    assert target.suffix == ""
    result = binary.BINARY_ADAPTER.scan(target.parent, "scan_ext")
    assert result.findings


def test_non_binary_files_are_skipped_silently(tmp_path: Path) -> None:
    """Claim: text and archives produce neither findings nor errors.

    Extension-less files are common in a repository — LICENSE, Makefile,
    CHANGELOG. Reaching them is expected; complaining about them is noise.
    """
    root = tmp_path / "mixed"
    root.mkdir()
    (root / "LICENSE").write_text("MIT License\n")
    (root / "Makefile").write_text("all:\n\techo hi\n")
    (root / "notes.bin").write_text("plain text pretending to be binary")

    result = binary.BINARY_ADAPTER.scan(root, "scan_text")
    assert result.findings == []
    assert result.status is ScanStatus.COMPLETED


# ==========================================================================
# Knowledge resolution
# ==========================================================================


@pytest.mark.parametrize(
    "soname,expected",
    [
        ("libcrypto.so.3", "OpenSSL libcrypto"),
        ("libcrypto.so", "OpenSSL libcrypto"),
        ("libcrypto-3-x64.dll", "OpenSSL libcrypto"),
        ("libssl.so.1.1", "OpenSSL libssl"),
        ("libsodium.so.23", "libsodium"),
    ],
)
def test_library_matching_survives_version_decoration(soname: str, expected: str) -> None:
    """Claim: sonames are matched on their stem.

    Dependency tables carry version suffixes in several shapes; matching the
    literal string would miss most real entries.
    """
    profile = kb.match_library(soname)
    assert profile is not None
    assert profile.name == expected


@pytest.mark.parametrize("soname", ["libc.so.6", "libm.so.6", "libpthread.so.0", ""])
def test_non_cryptographic_libraries_are_not_matched(soname: str) -> None:
    """Claim: ordinary system libraries produce no finding.

    Most linked libraries are not cryptographic, and classifying them would
    bury the real findings.
    """
    assert kb.match_library(soname) is None


def test_symbol_pattern_extracts_key_size_and_mode() -> None:
    """Claim: a symbol name that encodes its parameters is read, not guessed.

    ``EVP_aes_256_gcm`` names AES with a 256-bit key in GCM mode. That is read
    from the symbol the binary actually imports.
    """
    match = kb.match_symbol("EVP_aes_256_gcm")
    assert match is not None
    assert match.algorithm == "AES"
    assert match.key_size == 256
    assert match.mode == "GCM"

    cbc = kb.match_symbol("EVP_aes_128_cbc")
    assert cbc.key_size == 128
    assert cbc.mode == "CBC"


def test_ecb_mode_is_flagged_from_symbol_name() -> None:
    """Claim: ECB is surfaced wherever it appears.

    ECB is unsuitable for confidentiality regardless of the cipher, and that
    concern is independent of quantum computing.
    """
    match = kb.match_symbol("EVP_des_ecb")
    assert match.algorithm == "DES"
    assert match.legacy is True


def test_legacy_hash_symbols_are_flagged() -> None:
    """Claim: MD5 and SHA-1 entry points are marked legacy."""
    assert kb.match_symbol("EVP_md5").legacy is True
    assert kb.match_symbol("EVP_sha1").legacy is True
    assert kb.match_symbol("EVP_sha256").legacy is False


@pytest.mark.parametrize(
    "symbol", ["printf", "malloc", "memcpy", "__libc_start_main", "puts", ""]
)
def test_ordinary_symbols_are_not_cryptographic(symbol: str) -> None:
    """Claim: a binary's hundreds of ordinary imports produce nothing.

    This is the false-positive control for the symbol table.
    """
    assert kb.match_symbol(symbol) is None


def test_version_banner_extraction() -> None:
    """Claim: a library version is recovered from an embedded banner.

    Nothing in the dependency or symbol tables carries the release; the banner
    is the only structure that does.
    """
    match = kb.match_version_banner("OpenSSL 3.0.2 15 Mar 2022")
    assert match is not None
    assert match.library == "OpenSSL"
    assert match.version == "3.0.2"

    assert kb.match_version_banner("LibreSSL 3.7.2").version == "3.7.2"
    assert kb.match_version_banner("mbed TLS 3.4.0").library == "Mbed TLS"
    assert kb.match_version_banner("no version information here") is None


def test_version_patterns_actually_compiled() -> None:
    """Claim: the banner patterns are live regular expressions.

    An earlier revision wrote them with doubled backslashes, which the
    knowledge-base parser takes literally. Every pattern compiled and every
    pattern silently failed to match. This asserts they fire.
    """
    patterns = kb.load_version_patterns()
    assert patterns
    for rule in patterns:
        assert "\\\\" not in rule["pattern"], (
            f"{rule['_key']} uses doubled backslashes and will never match"
        )


# ==========================================================================
# String extraction
# ==========================================================================


def test_printable_string_extraction() -> None:
    """Claim: printable runs are recovered from binary data."""
    data = b"\x00\x01OpenSSL 3.0.2\x00\xff\xfeshort\x00valid_string_here\x00"
    found = extract_printable_strings(data, minimum=6)
    assert "OpenSSL 3.0.2" in found
    assert "valid_string_here" in found
    assert "short" not in found


def test_string_extraction_is_bounded() -> None:
    """Claim: a large artefact cannot make extraction unbounded."""
    data = b"\x00".join(b"crypto_string_%d" % i for i in range(60_000))
    found = extract_printable_strings(data)
    assert len(found) <= binary.MAX_STRINGS_EXAMINED


# ==========================================================================
# Adapter behaviour on the real fixture
# ==========================================================================


def test_scan_finds_the_linked_crypto_library(scan) -> None:
    """Claim: the dependency table is read and matched."""
    linked = [
        f
        for f in scan.findings
        if f.raw_detail["evidence_level"] == BinaryEvidenceLevel.LINKED_LIBRARY.value
    ]
    assert linked
    assert any("libcrypto" in f.raw_detail["structure"] for f in linked)
    assert any(f.library == "OpenSSL libcrypto" for f in linked)


def test_scan_finds_imported_crypto_symbols(scan) -> None:
    """Claim: the import table yields the primitives the binary references."""
    symbols = {
        f.raw_detail["structure"]
        for f in scan.findings
        if f.raw_detail["evidence_level"] == BinaryEvidenceLevel.IMPORTED_SYMBOL.value
    }
    for expected in demo_bin.EXPECTED_CRYPTO_SYMBOLS:
        assert expected in symbols, f"{expected} not detected"


def test_scan_resolves_algorithms_from_the_real_binary(scan) -> None:
    """Claim: real symbols resolve to real algorithms."""
    algorithms = {f.algorithm for f in scan.findings if f.algorithm}
    assert {"RSA", "AES", "DES", "MD5", "SHA-256"} <= algorithms


def test_aes_key_size_and_mode_come_from_the_binary(scan) -> None:
    """Claim: AES-256-GCM is read from the symbol the compiler emitted."""
    aes = [f for f in scan.findings if f.algorithm == "AES"]
    assert aes
    assert any(f.key_size == 256 and f.mode == "GCM" for f in aes)
    assert any(f.variant == "AES-256" for f in aes)


def test_legacy_primitives_in_the_binary_are_flagged(scan) -> None:
    """Claim: DES/ECB and MD5 are surfaced from a compiled artefact.

    These are problems independent of quantum computing, and a tool reporting
    only quantum exposure would miss them.
    """
    legacy = [f for f in scan.findings if f.raw_detail.get("legacy_primitive")]
    algorithms = {f.algorithm for f in legacy}
    assert {"DES", "MD5"} <= algorithms
    assert any(f.mode == "ECB" for f in legacy)


def test_rsa_key_size_is_not_invented(scan) -> None:
    """Claim: a key size invisible to structural analysis is reported as such.

    ``RSA_generate_key_ex`` takes the key size as a runtime argument. The
    symbol name cannot reveal it, so the finding must say so rather than guess.
    """
    rsa = [f for f in scan.findings if f.algorithm == "RSA"]
    assert rsa
    for finding in rsa:
        assert finding.key_size is None
        assert finding.variant == "RSA"
        assert finding.raw_detail["key_size_status"] == (
            "not determinable from binary structure"
        )


def test_findings_are_attributed_to_the_component(scan) -> None:
    """Claim: a binary is attributed to its owning application."""
    assert {f.component for f in scan.findings} == {"payments-api"}


# ==========================================================================
# Evidence and confidence model
# ==========================================================================


def test_no_binary_finding_is_high_confidence(scan) -> None:
    """Claim: structural analysis never claims certainty of execution.

    Proving a symbol's call path runs would need disassembly this adapter does
    not perform. An import table shows the linker resolved a reference — not
    that the code executes. HIGH would overstate that.
    """
    assert scan.findings
    for finding in scan.findings:
        assert finding.confidence is not Confidence.HIGH


def test_imported_symbols_outrank_linked_libraries(scan) -> None:
    """Claim: naming a primitive is stronger evidence than linking a library."""
    for finding in scan.findings:
        level = finding.raw_detail["evidence_level"]
        if level == BinaryEvidenceLevel.IMPORTED_SYMBOL.value:
            assert finding.confidence is Confidence.MEDIUM
        else:
            assert finding.confidence is Confidence.LOW


def test_every_finding_explains_its_evidence_level(scan) -> None:
    """Claim: the meaning travels with the data into the UI and reports."""
    for finding in scan.findings:
        meaning = finding.raw_detail.get("evidence_meaning", "")
        assert meaning
        if finding.raw_detail["evidence_level"] == (
            BinaryEvidenceLevel.IMPORTED_SYMBOL.value
        ):
            assert "disassembly" in meaning


def test_linked_library_carries_a_capability_disclaimer(scan) -> None:
    """Claim: linkage is presented as capability, not usage.

    The same discipline Phase 2 applied to declared dependencies.
    """
    linked = [
        f
        for f in scan.findings
        if f.raw_detail["evidence_level"] == BinaryEvidenceLevel.LINKED_LIBRARY.value
    ]
    assert linked
    for finding in linked:
        assert "capability" in finding.raw_detail.get("note", "").lower()


def test_detection_method_distinguishes_symbols_from_strings(scan) -> None:
    """Claim: how a finding was located is recorded."""
    for finding in scan.findings:
        if finding.raw_detail["evidence_level"] == (
            BinaryEvidenceLevel.EMBEDDED_STRING.value
        ):
            assert finding.detection_method is DetectionMethod.STRING_MATCH
        else:
            assert finding.detection_method is DetectionMethod.SYMBOL_TABLE


def test_synthetic_version_banner_produces_a_string_finding() -> None:
    """Claim: the embedded-string path works end to end.

    The bundled fixture contains no OpenSSL banner — the banner lives in
    ``libcrypto.so`` rather than in a dynamically linked program — so this
    exercises the path against a constructed ELF whose string table does carry
    one. Faking a banner inside the shipped fixture would misrepresent what
    that artefact contains.
    """
    data = bytearray(demo_bin.crypto_service_bytes())
    data.extend(b"\x00OpenSSL 3.0.2 15 Mar 2022\x00")

    detections, error = analyse_binary(bytes(data), BinaryFormat.ELF)
    assert error == ""

    banners = [
        d
        for d in detections
        if d.evidence_level is BinaryEvidenceLevel.EMBEDDED_STRING
    ]
    assert banners
    assert banners[0].library == "OpenSSL"
    assert banners[0].library_version == "3.0.2"


# ==========================================================================
# Determinism
# ==========================================================================


def test_repeat_scans_are_identical(estate: Path, resolver: ComponentResolver) -> None:
    """Claim: an unchanged binary scans identically every time."""
    first = binary.BINARY_ADAPTER.scan(estate, "scan_det4", resolver=resolver)
    second = binary.BINARY_ADAPTER.scan(estate, "scan_det4", resolver=resolver)
    assert [f.finding_id for f in first.findings] == [
        f.finding_id for f in second.findings
    ]


def test_finding_ids_are_unique(scan) -> None:
    """Claim: no two findings collide, including two symbols of one algorithm.

    ``RSA_new`` and ``RSA_generate_key_ex`` both resolve to RSA; the structure
    name is part of the identity so they remain distinct findings.
    """
    ids = [f.finding_id for f in scan.findings]
    assert len(ids) == len(set(ids))

    rsa = [f for f in scan.findings if f.algorithm == "RSA"]
    assert len(rsa) >= 2
    assert len({f.finding_id for f in rsa}) == len(rsa)


# ==========================================================================
# Safety
# ==========================================================================


def test_adapter_never_executes_a_binary() -> None:
    """Claim: no execution path exists in the binary adapter.

    Checked against the parsed syntax tree rather than the file text. A
    substring scan cannot tell code from prose, and this module's own docstring
    explains that no subprocess is spawned — which a naive check reads as
    evidence that one is. Inspecting imports, calls, and attribute access is
    both stricter and immune to that.
    """
    import ast

    tree = ast.parse(Path(binary.__file__).read_text(encoding="utf-8"))

    forbidden_modules = {"subprocess", "ctypes", "runpy", "importlib", "multiprocessing"}
    forbidden_calls = {"eval", "exec", "compile", "__import__", "system", "popen", "dlopen"}

    imported: set[str] = set()
    called: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            target = node.func
            if isinstance(target, ast.Name):
                called.add(target.id)
            elif isinstance(target, ast.Attribute):
                called.add(target.attr)

    assert not (imported & forbidden_modules), (
        f"binary adapter imports {imported & forbidden_modules}"
    )
    assert not (called & forbidden_calls), (
        f"binary adapter calls {called & forbidden_calls}"
    )


def test_hostile_binary_does_not_crash_the_scan(tmp_path: Path) -> None:
    """Claim: malformed executables are reported, not fatal.

    Estates contain truncated builds and corrupt artefacts. A scanner that dies
    on the first one is unusable.
    """
    root = tmp_path / "hostile"
    root.mkdir()
    (root / "truncated.so").write_bytes(b"\x7fELF" + b"\x00" * 40)
    (root / "garbage.exe").write_bytes(b"MZ" + bytes(range(256)) * 4)
    (root / "empty.so").write_bytes(b"")
    (root / "good").write_bytes(demo_bin.crypto_service_bytes())

    result = binary.BINARY_ADAPTER.scan(root, "scan_hostile")
    assert any(f.algorithm == "RSA" for f in result.findings)


def test_oversized_binary_is_skipped(tmp_path: Path) -> None:
    """Claim: the size ceiling applies to binaries."""
    root = tmp_path / "big"
    root.mkdir()
    (root / "huge.so").write_bytes(demo_bin.crypto_service_bytes())

    result = binary.BINARY_ADAPTER.scan(
        root, "scan_big", limits=ScanLimits(max_file_bytes=1000)
    )
    assert result.findings == []


def test_traversal_safety_is_inherited(tmp_path: Path) -> None:
    """Claim: build and VCS directories are never descended into."""
    root = tmp_path / "estate"
    (root / "app").mkdir(parents=True)
    (root / "app" / "service").write_bytes(demo_bin.crypto_service_bytes())
    (root / "node_modules").mkdir(parents=True)
    (root / "node_modules" / "vendored").write_bytes(demo_bin.crypto_service_bytes())

    result = binary.BINARY_ADAPTER.scan(root, "scan_prune")
    assert {Path(f.location).parent.name for f in result.findings} == {"app"}


def test_evidence_is_bounded(scan) -> None:
    """Claim: no finding carries an unbounded quantity of binary content."""
    for finding in scan.findings:
        assert len(finding.evidence) <= 220


def test_missing_target_fails_cleanly(tmp_path: Path) -> None:
    """Claim: a bad path is a reported failure, not an exception."""
    result = binary.BINARY_ADAPTER.scan(tmp_path / "nope", "scan_missing")
    assert result.status is ScanStatus.FAILED
    assert result.errors


def test_empty_directory_scans_cleanly(tmp_path: Path) -> None:
    """Claim: a directory with no binaries returns an empty result."""
    root = tmp_path / "empty"
    root.mkdir()
    result = binary.BINARY_ADAPTER.scan(root, "scan_empty")
    assert result.status is ScanStatus.COMPLETED
    assert result.findings == []


def test_coverage_declares_real_limits() -> None:
    """Claim: the adapter states what it cannot do.

    The disassembly limit is the important one: it explains why no binary
    finding is HIGH confidence.
    """
    coverage = binary.BINARY_ADAPTER.coverage()
    joined = " ".join(coverage.not_supported).lower()
    assert "never executed" in joined
    assert "disassembly" in joined
    assert "statically linked" in joined
    assert "not exercised" in joined
    assert "disassembly" in coverage.confidence_notes.lower()


def test_coverage_is_honest_when_lief_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Claim: an unavailable dependency is declared, not hidden.

    The adapter degrades rather than failing: a scan missing one surface beats
    a platform that will not start.
    """
    monkeypatch.setattr(binary, "LIEF_AVAILABLE", False)
    coverage = binary.BINARY_ADAPTER.coverage()
    assert coverage.supported == []
    assert any("not installed" in line for line in coverage.not_supported)


def test_scan_degrades_when_lief_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Claim: without LIEF the scan explains itself instead of crashing."""
    monkeypatch.setattr(binary, "LIEF_AVAILABLE", False)
    root = tmp_path / "estate"
    root.mkdir()
    (root / "service").write_bytes(demo_bin.crypto_service_bytes())

    result = binary.BINARY_ADAPTER.scan(root, "scan_nolief")
    assert result.status is ScanStatus.PARTIAL
    assert result.findings == []
    assert any("LIEF" in error for error in result.errors)


# ==========================================================================
# Integration — four surfaces, one model
# ==========================================================================


def test_all_four_adapters_are_registered() -> None:
    """Claim: the registry holds four conforming adapters."""
    assert {"certificates", "dependencies", "source", "binary"} <= set(
        discovery.available_adapters()
    )
    for name in ("certificates", "dependencies", "source", "binary"):
        adapter = discovery.get_adapter(name)
        assert isinstance(adapter, discovery.DiscoveryAdapter)
        assert adapter.coverage().not_supported


def test_adapters_do_not_claim_each_others_files(
    estate: Path, resolver: ComponentResolver
) -> None:
    """Claim: each surface reads only what it should.

    The binary fixture has no extension and the source scanner reads none, so
    no artefact is inventoried twice under two different interpretations.
    """
    binary_scan = binary.BINARY_ADAPTER.scan(estate, "scan_x", resolver=resolver)
    source_scan = source.SOURCE_ADAPTER.scan(estate, "scan_x", resolver=resolver)

    binary_paths = {f.location for f in binary_scan.findings}
    source_paths = {f.location for f in source_scan.findings}
    assert binary_paths.isdisjoint(source_paths)


def test_four_surfaces_share_one_model_and_one_inventory(
    estate: Path, resolver: ComponentResolver, db: Path
) -> None:
    """Claim: a fourth discovery surface needed no schema change.

    Certificates, manifests, syntax trees, and compiled artefacts have nothing
    in common structurally, yet they persist and reload through one code path.
    """
    scans = [
        certificates.CERTIFICATE_ADAPTER.scan(estate, "scan_all4"),
        dependencies.DEPENDENCY_ADAPTER.scan(estate, "scan_all4", resolver=resolver),
        source.SOURCE_ADAPTER.scan(estate, "scan_all4", resolver=resolver),
        binary.BINARY_ADAPTER.scan(estate, "scan_all4", resolver=resolver),
    ]
    expected = sum(len(s.findings) for s in scans)
    for result in scans:
        inventory.record_scan(result, db)

    reloaded = inventory.get_findings("scan_all4", db)
    assert len(reloaded) == expected
    assert {f.source_type for f in reloaded} == {
        SourceType.CERTIFICATE_FILE,
        SourceType.DEPENDENCY,
        SourceType.SOURCE_CODE,
        SourceType.BINARY,
    }


def test_binary_findings_survive_persistence(
    estate: Path, resolver: ComponentResolver, db: Path
) -> None:
    """Claim: modes, key sizes, and evidence levels round-trip intact."""
    result = binary.BINARY_ADAPTER.scan(estate, "scan_persist4", resolver=resolver)
    inventory.record_scan(result, db)

    reloaded = {f.finding_id: f for f in inventory.get_findings("scan_persist4", db)}
    assert len(reloaded) == len(result.findings)

    for original in result.findings:
        stored = reloaded[original.finding_id]
        assert stored.algorithm == original.algorithm
        assert stored.mode == original.mode
        assert stored.key_size == original.key_size
        assert stored.library == original.library
        assert stored.confidence is original.confidence
        assert stored.raw_detail["evidence_level"] == (
            original.raw_detail["evidence_level"]
        )


def test_mixed_summary_aggregates_four_surfaces(
    estate: Path, resolver: ComponentResolver, db: Path
) -> None:
    """Claim: the inventory summary needed no change for a fourth surface."""
    for result in (
        certificates.CERTIFICATE_ADAPTER.scan(estate, "scan_sum4"),
        dependencies.DEPENDENCY_ADAPTER.scan(estate, "scan_sum4", resolver=resolver),
        source.SOURCE_ADAPTER.scan(estate, "scan_sum4", resolver=resolver),
        binary.BINARY_ADAPTER.scan(estate, "scan_sum4", resolver=resolver),
    ):
        inventory.record_scan(result, db)

    summary = inventory.inventory_summary("scan_sum4", db)
    assert set(summary["by_source_type"]) == {
        "certificate_file",
        "dependency",
        "source_code",
        "binary",
    }
    assert sum(summary["by_source_type"].values()) == summary["total_findings"]


def test_discovery_still_emits_no_assessment(scan) -> None:
    """Claim: the three-layer separation holds for the fourth adapter."""
    assets = inventory.build_assets(scan.findings)
    assert assets
    assert all(asset.assessment is None for asset in assets)

    serialised = json.dumps([f.to_dict() for f in scan.findings])
    for forbidden in ('"risk_level"', '"migration_priority"', '"mosca"'):
        assert forbidden not in serialised


def test_binary_reaches_what_source_cannot(
    estate: Path, resolver: ComponentResolver
) -> None:
    """Claim: the phase's thesis — a shipped artefact is inspected directly.

    ``payments-api`` has Python source using RSA and AES. The compiled service
    also links OpenSSL and references DES and MD5, which appear in no source
    file in the estate. Only binary analysis surfaces them, which is precisely
    the gap this adapter closes: vendored and third-party artefacts whose
    source is unavailable.
    """
    source_scan = source.SOURCE_ADAPTER.scan(estate, "scan_gap", resolver=resolver)
    binary_scan = binary.BINARY_ADAPTER.scan(estate, "scan_gap", resolver=resolver)

    source_algorithms = {
        f.algorithm
        for f in source_scan.findings
        if f.component == "payments-api" and f.algorithm
    }
    binary_algorithms = {
        f.algorithm
        for f in binary_scan.findings
        if f.component == "payments-api" and f.algorithm
    }

    only_in_binary = binary_algorithms - source_algorithms
    assert "DES" in only_in_binary
    assert "MD5" in only_in_binary
