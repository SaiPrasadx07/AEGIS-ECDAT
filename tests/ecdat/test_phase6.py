"""
Aegis PQC — ECDAT Phase 6 tests: CBOM generation.

The CBOM is a downstream projection of the canonical inventory into CycloneDX
1.6. These tests hold it to three standards beyond "the JSON parses": it must
validate against the CycloneDX schema, it must be deterministic, and it must
preserve the evidence semantics the earlier phases established — never
upgrading a library capability into a usage claim, never inventing a key size.

Run Phase 6 only:  pytest tests/ecdat/test_phase6.py -q
Run all ECDAT:     pytest tests/ecdat -q
Run everything:    pytest tests -q
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from backend import (
    cbom,
    demo_binaries,
    demo_containers,
    demo_enterprise,
    demo_manifests,
    demo_source,
    inventory,
)
from backend.discovery import binary, certificates, container, dependencies, source
from backend.discovery.attribution import ComponentResolver, extract_declared_paths
from backend.model import (
    ArtefactType,
    CertificateFacts,
    Confidence,
    CryptoFinding,
    DetectionMethod,
    SourceType,
)


# --------------------------------------------------------------------------
# Builders for focused findings
# --------------------------------------------------------------------------


def _finding(**overrides) -> CryptoFinding:
    """A canonical finding with sensible defaults, for focused mapping tests."""
    base = dict(
        finding_id="fnd_test",
        scan_id="s",
        artefact_type=ArtefactType.ALGORITHM,
        algorithm="RSA",
        algorithm_family="RSA",
        variant="RSA-2048",
        key_size=2048,
        oid="1.2.840.113549.1.1.1",
        source_type=SourceType.SOURCE_CODE,
        component="payments-api",
        line=12,
        detection_method=DetectionMethod.AST_PARSE,
        evidence="keys.py:12 -> rsa.generate_private_key",
        confidence=Confidence.HIGH,
        raw_detail={"role": "key_establishment", "evidence_level": "call_site"},
    )
    base.update(overrides)
    return CryptoFinding(**base)


def _components(document: str) -> list[dict]:
    """Parse a CBOM and return its component list."""
    return json.loads(document).get("components", [])


def _prop(component: dict, name: str) -> str | None:
    """Read one aegis property value from a component, or None."""
    for prop in component.get("properties", []):
        if prop["name"] == name:
            return prop["value"]
    return None


# --------------------------------------------------------------------------
# Fixtures — a full inventory from the demo estate
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def estate(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The full demo estate: certificates, manifests, source, binary."""
    root = tmp_path_factory.mktemp("phase6_estate")
    demo_enterprise.generate(root, force=True)
    demo_manifests.write_application_manifests(root)
    demo_source.write_application_source(root)
    demo_binaries.write_application_binaries(root)
    return root


@pytest.fixture(scope="module")
def all_findings(estate: Path) -> list[CryptoFinding]:
    """Findings from all four on-disk surfaces over the demo estate."""
    raw = inventory._parse_policy_file(estate / "aegis_policy.yaml")
    resolver = ComponentResolver(extract_declared_paths(raw))

    findings: list[CryptoFinding] = []
    findings.extend(certificates.CERTIFICATE_ADAPTER.scan(estate, "s").findings)
    findings.extend(
        dependencies.DEPENDENCY_ADAPTER.scan(estate, "s", resolver=resolver).findings
    )
    findings.extend(
        source.SOURCE_ADAPTER.scan(estate, "s", resolver=resolver).findings
    )
    if binary.LIEF_AVAILABLE:
        findings.extend(
            binary.BINARY_ADAPTER.scan(estate, "s", resolver=resolver).findings
        )
    return findings


@pytest.fixture(scope="module")
def estate_cbom(all_findings: list[CryptoFinding]) -> str:
    """One CBOM built from the full demo estate."""
    return cbom.generate_cbom(all_findings)


# ==========================================================================
# CycloneDX version and validation
# ==========================================================================


def test_cbom_declares_cyclonedx_1_6(estate_cbom: str) -> None:
    """Claim: the document declares the intended spec version and format."""
    document = json.loads(estate_cbom)
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    assert document["$schema"].endswith("bom-1.6.schema.json")


def test_cbom_validates_against_the_schema(estate_cbom: str) -> None:
    """Claim: the document passes CycloneDX schema validation.

    Not "the JSON parses" — the JsonStrictValidator checks the document against
    the published CycloneDX 1.6 schema. An empty error list is the pass.
    """
    errors = cbom.validate_cbom(estate_cbom)
    assert errors == [], f"schema validation failed: {errors}"


def test_validator_rejects_a_broken_document() -> None:
    """Claim: the validation is real — it fails an invalid document.

    A test that only ever sees valid input proves nothing about the validator.
    """
    errors = cbom.validate_cbom('{"bomFormat": "CycloneDX"}')
    assert errors, "validator accepted a structurally invalid document"


def test_empty_inventory_produces_a_valid_empty_cbom() -> None:
    """Claim: no findings yields a valid CBOM with no components."""
    document = cbom.generate_cbom([])
    assert cbom.validate_cbom(document) == []
    assert _components(document) == []


# ==========================================================================
# Semantic safeguards — the rules that matter most
# ==========================================================================


def test_library_capability_is_not_algorithm_usage() -> None:
    """Claim: a dependency capability never becomes a usage assertion.

    A LIBRARY finding with no algorithm — the shape Phase 2 produces for a
    declared dependency — must be a plain `library` component, never a
    cryptographic-asset asserting the application performs the algorithm.
    """
    finding = _finding(
        finding_id="fnd_lib",
        artefact_type=ArtefactType.LIBRARY,
        algorithm="",
        variant="",
        key_size=None,
        oid="",
        library="pyca/cryptography",
        library_version="42.0.5",
        source_type=SourceType.DEPENDENCY,
        detection_method=DetectionMethod.MANIFEST_PARSE,
        raw_detail={"provides_algorithms": ["RSA", "AES"]},
    )
    component = _components(cbom.generate_cbom([finding]))[0]

    assert component["type"] == "library"
    assert "cryptoProperties" not in component
    assert _prop(component, "aegis:capability_only") == "true"


def test_confirmed_usage_is_an_algorithm_asset() -> None:
    """Claim: a finding with a concrete algorithm is a cryptographic-asset."""
    component = _components(cbom.generate_cbom([_finding()]))[0]
    assert component["type"] == "cryptographic-asset"
    assert component["cryptoProperties"]["assetType"] == "algorithm"
    assert _prop(component, "aegis:capability_only") == "false"


def test_unknown_key_size_stays_unknown() -> None:
    """Claim: a key size the scanner did not establish is absent from the CBOM.

    ``rsa.generate_private_key(key_size=configured)`` yields RSA with no size.
    The CBOM must not fill that gap with a parameter set.
    """
    finding = _finding(variant="RSA", key_size=None)
    component = _components(cbom.generate_cbom([finding]))[0]

    algo = component["cryptoProperties"]["algorithmProperties"]
    assert "parameterSetIdentifier" not in algo or algo.get("parameterSetIdentifier") is None
    assert _prop(component, "aegis:key_size") is None


def test_known_key_size_is_preserved() -> None:
    """Claim: a key size the scanner established survives into the CBOM."""
    component = _components(cbom.generate_cbom([_finding(key_size=2048)]))[0]
    assert component["cryptoProperties"]["algorithmProperties"][
        "parameterSetIdentifier"
    ] == "2048"
    assert _prop(component, "aegis:key_size") == "2048"


def test_weak_evidence_is_not_upgraded() -> None:
    """Claim: a LOW-confidence finding stays LOW in the CBOM.

    Generation never promotes a linked-library or import finding into a strong
    claim.
    """
    finding = _finding(
        finding_id="fnd_weak",
        confidence=Confidence.LOW,
        raw_detail={"role": "key_establishment", "evidence_level": "import"},
    )
    component = _components(cbom.generate_cbom([finding]))[0]
    assert _prop(component, "aegis:confidence") == "low"
    assert _prop(component, "aegis:evidence_level") == "import"


def test_no_quantum_risk_conclusion_appears_in_the_cbom(estate_cbom: str) -> None:
    """Claim: the CBOM carries observed facts only.

    No risk level, Mosca verdict, or migration priority — those are later
    phases and must not leak into a facts-only document.
    """
    for forbidden in (
        "risk_level",
        "mosca",
        "migration_priority",
        "CRITICAL",
        "quantum_vulnerable",
        "recommendation",
    ):
        assert forbidden.lower() not in estate_cbom.lower()


# ==========================================================================
# Evidence and confidence preservation
# ==========================================================================


@pytest.mark.parametrize(
    "confidence", [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]
)
def test_all_confidence_levels_survive(confidence: Confidence) -> None:
    """Claim: every confidence level is carried through verbatim."""
    component = _components(cbom.generate_cbom([_finding(confidence=confidence)]))[0]
    assert _prop(component, "aegis:confidence") == confidence.value


def test_detection_method_survives() -> None:
    """Claim: how a finding was detected is preserved."""
    component = _components(
        cbom.generate_cbom([_finding(detection_method=DetectionMethod.SYMBOL_TABLE)])
    )[0]
    assert _prop(component, "aegis:detection_method") == "symbol_table"


def test_evidence_string_survives() -> None:
    """Claim: the evidence snippet is preserved."""
    component = _components(cbom.generate_cbom([_finding()]))[0]
    assert "keys.py:12" in _prop(component, "aegis:evidence")


# ==========================================================================
# Certificate mapping
# ==========================================================================


def test_certificate_maps_to_certificate_asset() -> None:
    """Claim: a certificate finding becomes a certificate crypto-asset."""
    finding = _finding(
        finding_id="fnd_cert",
        artefact_type=ArtefactType.CERTIFICATE,
        algorithm="RSA",
        certificate=CertificateFacts(
            subject="CN=payments.northwind.example",
            issuer="CN=payments.northwind.example",
            signature_algorithm="sha256WithRSAEncryption",
            is_self_signed=True,
        ),
        source_type=SourceType.CERTIFICATE_FILE,
        detection_method=DetectionMethod.LIBRARY_PARSE,
    )
    component = _components(cbom.generate_cbom([finding]))[0]

    assert component["type"] == "cryptographic-asset"
    assert component["cryptoProperties"]["assetType"] == "certificate"
    cert_props = component["cryptoProperties"]["certificateProperties"]
    assert "payments.northwind" in cert_props["subjectName"]


# ==========================================================================
# Source, binary, container mapping
# ==========================================================================


def test_source_mode_and_language_survive() -> None:
    """Claim: source-specific provenance is preserved."""
    finding = _finding(
        finding_id="fnd_src",
        algorithm="AES",
        variant="AES",
        key_size=None,
        mode="ECB",
        raw_detail={
            "role": "symmetric",
            "evidence_level": "configuration",
            "language": "python",
        },
    )
    component = _components(cbom.generate_cbom([finding]))[0]
    assert _prop(component, "aegis:mode") == "ECB"
    assert _prop(component, "aegis:language") == "python"


def test_binary_format_survives() -> None:
    """Claim: binary-specific provenance is preserved."""
    finding = _finding(
        finding_id="fnd_bin",
        algorithm="AES",
        variant="AES-256",
        key_size=256,
        mode="GCM",
        source_type=SourceType.BINARY,
        detection_method=DetectionMethod.SYMBOL_TABLE,
        confidence=Confidence.MEDIUM,
        raw_detail={
            "role": "symmetric",
            "evidence_level": "imported_symbol",
            "binary_format": "elf",
        },
    )
    component = _components(cbom.generate_cbom([finding]))[0]
    assert _prop(component, "aegis:binary_format") == "elf"
    assert _prop(component, "aegis:evidence_level") == "imported_symbol"


def test_container_provenance_survives_with_real_digest() -> None:
    """Claim: container provenance, including the real layer digest, is kept.

    The Phase 5 digest honesty must survive into the CBOM: the layer digest is
    a real SHA-256, and the config-ref digest flag is preserved as recorded.
    """
    finding = _finding(
        finding_id="fnd_cont",
        source_type=SourceType.BINARY,
        location="/app/bin/crypto_service",
        raw_detail={
            "role": "key_establishment",
            "evidence_level": "imported_symbol",
            "container": {
                "image_reference": "payments-api:2026.09",
                "image_config_ref": "config.json",
                "image_config_is_digest": False,
                "layer_digest": "sha256:" + "a" * 64,
                "layer_index": 1,
                "image_path": "/app/bin/crypto_service",
                "discovery_surface": "binary",
            },
        },
    )
    component = _components(cbom.generate_cbom([finding]))[0]

    assert _prop(component, "aegis:container_image_reference") == "payments-api:2026.09"
    assert _prop(component, "aegis:container_layer_digest") == "sha256:" + "a" * 64
    assert _prop(component, "aegis:container_image_config_is_digest") == "false"
    assert _prop(component, "aegis:container_image_path") == "/app/bin/crypto_service"
    assert _prop(component, "aegis:container_layer_index") == "1"


def test_container_digest_honesty_flag_true_case() -> None:
    """Claim: an OCI genuine digest is flagged as such."""
    finding = _finding(
        finding_id="fnd_oci",
        raw_detail={
            "role": "key_establishment",
            "container": {
                "image_config_ref": "sha256:" + "b" * 64,
                "image_config_is_digest": True,
                "layer_digest": "sha256:" + "c" * 64,
                "discovery_surface": "binary",
                "image_path": "/x",
            },
        },
    )
    component = _components(cbom.generate_cbom([finding]))[0]
    assert _prop(component, "aegis:container_image_config_is_digest") == "true"


# ==========================================================================
# Traceability and attribution
# ==========================================================================


def test_component_traces_back_to_the_finding_id() -> None:
    """Claim: a CBOM component carries its canonical finding id.

    The bom-ref reuses the finding id, so nothing needs a second identity
    system, and a downstream phase can join the CBOM back to the inventory.
    """
    component = _components(cbom.generate_cbom([_finding(finding_id="fnd_trace")]))[0]
    assert component["bom-ref"] == "crypto:fnd_trace"
    assert _prop(component, "aegis:finding_id") == "fnd_trace"


def test_component_attribution_survives() -> None:
    """Claim: the owning application is preserved."""
    component = _components(
        cbom.generate_cbom([_finding(component="legacy-auth")])
    )[0]
    assert component["group"] == "legacy-auth"
    assert _prop(component, "aegis:component") == "legacy-auth"


def test_source_type_survives() -> None:
    """Claim: which surface found the artefact is preserved."""
    component = _components(
        cbom.generate_cbom([_finding(source_type=SourceType.CONTAINER)])
    )[0]
    assert _prop(component, "aegis:source_type") == "container"


# ==========================================================================
# Determinism
# ==========================================================================


def test_generation_is_deterministic(all_findings: list[CryptoFinding]) -> None:
    """Claim: the same inventory yields byte-identical output."""
    first = cbom.generate_cbom(all_findings)
    second = cbom.generate_cbom(all_findings)
    assert first == second


def test_ordering_does_not_affect_output(all_findings: list[CryptoFinding]) -> None:
    """Claim: input order does not change the document.

    Findings are sorted by id internally, so a shuffled inventory produces the
    identical CBOM — required for stable diffing across scans.
    """
    forward = cbom.generate_cbom(all_findings)
    backward = cbom.generate_cbom(list(reversed(all_findings)))
    assert forward == backward


def test_serial_number_is_stable_but_content_sensitive() -> None:
    """Claim: the serial derives from the findings, deterministically.

    Same findings, same serial; different findings, different serial. This is
    what lets the document be deterministic without a random UUID.
    """
    a = _finding(finding_id="fnd_1")
    b = _finding(finding_id="fnd_2")

    serial_a = json.loads(cbom.generate_cbom([a]))["serialNumber"]
    serial_a_again = json.loads(cbom.generate_cbom([a]))["serialNumber"]
    serial_ab = json.loads(cbom.generate_cbom([a, b]))["serialNumber"]

    assert serial_a == serial_a_again
    assert serial_a != serial_ab


def test_no_wall_clock_timestamp_in_output(estate_cbom: str) -> None:
    """Claim: no changing timestamp is embedded.

    The metadata timestamp is cleared precisely so output is reproducible.
    """
    document = json.loads(estate_cbom)
    assert "timestamp" not in document.get("metadata", {})


# ==========================================================================
# Multiple surfaces in one CBOM
# ==========================================================================


def test_all_surfaces_coexist_in_one_cbom(all_findings: list[CryptoFinding]) -> None:
    """Claim: certificate, dependency, source, and binary assets share one CBOM."""
    document = cbom.generate_cbom(all_findings)
    source_types = {
        _prop(c, "aegis:source_type") for c in _components(document)
    }
    expected = {"certificate_file", "dependency", "source_code"}
    if binary.LIEF_AVAILABLE:
        expected.add("binary")
    assert expected <= source_types


def test_every_component_validates_and_traces(all_findings: list[CryptoFinding]) -> None:
    """Claim: the full estate CBOM is valid and every component is traceable."""
    document = cbom.generate_cbom(all_findings)
    assert cbom.validate_cbom(document) == []
    for component in _components(document):
        assert _prop(component, "aegis:finding_id")
        assert component["bom-ref"].startswith("crypto:")


def test_clean_component_contributes_nothing(all_findings: list[CryptoFinding]) -> None:
    """Claim: content-portal produces no crypto assets.

    The clean application has no findings in the inventory, so it contributes
    nothing to the CBOM — proof the CBOM reflects the real inventory, not a
    hard-coded showcase.
    """
    document = cbom.generate_cbom(all_findings)
    groups = {c.get("group") for c in _components(document)}
    assert "content-portal" not in groups


# ==========================================================================
# Robustness
# ==========================================================================


def test_incomplete_finding_does_not_crash_generation() -> None:
    """Claim: a sparse finding serialises without error.

    A finding missing optional fields must produce a valid component, not an
    exception.
    """
    finding = CryptoFinding(
        finding_id="fnd_sparse",
        scan_id="s",
        artefact_type=ArtefactType.UNKNOWN,
        source_type=SourceType.SOURCE_CODE,
        detection_method=DetectionMethod.PATTERN_MATCH,
        confidence=Confidence.LOW,
    )
    document = cbom.generate_cbom([finding])
    assert cbom.validate_cbom(document) == []


def test_write_cbom_round_trips(tmp_path: Path) -> None:
    """Claim: writing to disk yields the same validated document."""
    path = tmp_path / "estate.cdx.json"
    written = cbom.write_cbom([_finding()], path)
    assert path.read_text(encoding="utf-8") == written
    assert cbom.validate_cbom(path.read_text(encoding="utf-8")) == []


def test_no_secret_material_in_output() -> None:
    """Claim: nothing beyond the canonical finding reaches the CBOM.

    The generator reads only finding fields. A finding never carries key
    material, so the CBOM cannot either. This guards against a future field
    leaking one.
    """
    finding = _finding(evidence="keys.py:12 -> rsa.generate_private_key(key_size=2048)")
    document = cbom.generate_cbom([finding])
    for marker in ("-----BEGIN", "PRIVATE KEY", "password", "secret"):
        assert marker.lower() not in document.lower()


# ==========================================================================
# Safety — pure reporting layer
# ==========================================================================


def test_cbom_module_performs_no_execution_or_io() -> None:
    """Claim: the generator is a pure transformation.

    Checked against the parsed syntax tree: no subprocess, no package manager,
    no network, no independent file scanning. The only filesystem call is the
    explicit write in write_cbom.
    """
    tree = ast.parse(Path(cbom.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                called.add(func.id)
            elif isinstance(func, ast.Attribute):
                called.add(func.attr)

    assert not (imported & {"subprocess", "socket", "urllib", "requests", "docker"})
    assert not (called & {"system", "popen", "run", "eval", "exec", "urlopen"})


def test_cbom_does_not_rescan_the_estate(estate: Path) -> None:
    """Claim: generation consumes findings, never the filesystem.

    Generating a CBOM from an empty finding list produces an empty CBOM even
    though the estate on disk is full of cryptographic material — proof the
    generator does not scan anything itself.
    """
    document = cbom.generate_cbom([])
    assert _components(document) == []


def test_generation_does_not_mutate_findings() -> None:
    """Claim: the source findings are unchanged by generation."""
    finding = _finding()
    before = finding.to_dict()
    cbom.generate_cbom([finding])
    assert finding.to_dict() == before


# ==========================================================================
# Integration with the container surface
# ==========================================================================


@pytest.mark.skipif(
    not binary.LIEF_AVAILABLE, reason="container fixtures need the binary surface"
)
def test_container_findings_flow_into_the_cbom(tmp_path: Path) -> None:
    """Claim: findings discovered through a container reach the CBOM intact.

    End to end: build a real image, scan it, generate a CBOM, and confirm the
    container provenance — including the real layer digest — is present and the
    document validates.
    """
    images = tmp_path / "images"
    demo_containers.write_demo_images(tmp_path)
    resolver = ComponentResolver({"payments-api": "app"})

    result = container.CONTAINER_ADAPTER.scan(
        images / "payments-api.tar", "s", resolver=resolver
    )
    document = cbom.generate_cbom(result.findings)

    assert cbom.validate_cbom(document) == []
    layer_digests = {
        _prop(c, "aegis:container_layer_digest") for c in _components(document)
    }
    layer_digests.discard(None)
    assert layer_digests
    assert all(d.startswith("sha256:") for d in layer_digests)
