"""
Aegis PQC — ECDAT Phase 8 tests: recommendation engine.

The engine answers "given this finding and its established risk context, what
remediation direction is technically appropriate, and why?" — role-aware,
evidence-aware, and never inventing facts. These tests hold it to that across
every algorithm category, and confirm it neither recomputes Phase 7 risk nor
performs Phase 9 prioritisation.

Run Phase 8 only:  pytest tests/ecdat/test_phase8.py -q
Run all ECDAT:     pytest tests/ecdat -q
Run everything:    pytest tests -q
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from backend import (
    demo_binaries,
    demo_enterprise,
    demo_manifests,
    demo_source,
    inventory,
    quantum_risk as qr,
    recommendations as rec,
)
from backend.discovery import binary, certificates, dependencies, source
from backend.discovery.attribution import ComponentResolver, extract_declared_paths
from backend.model import (
    ApplicationContext,
    ArtefactType,
    BusinessCriticality,
    CertificateFacts,
    Confidence,
    ContextSource,
    CryptoFinding,
    DetectionMethod,
    RemediationClass,
    SourceType,
)


# --------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------


def _finding(algorithm: str, **overrides) -> CryptoFinding:
    """A canonical finding with role/evidence routed into raw_detail."""
    role = overrides.pop("role", "key_establishment")
    evidence_level = overrides.pop("evidence_level", "call_site")
    raw_detail = overrides.pop("raw_detail", {"role": role, "evidence_level": evidence_level})
    base = dict(
        finding_id=f"fnd_{algorithm.lower().replace('-', '')[:8]}_{role[:4] if role else 'none'}",
        scan_id="s",
        artefact_type=ArtefactType.ALGORITHM,
        algorithm=algorithm,
        key_size=None,
        source_type=SourceType.SOURCE_CODE,
        component="payments-api",
        location="keys.py",
        line=12,
        detection_method=DetectionMethod.AST_PARSE,
        evidence=f"keys.py:12 -> {algorithm}",
        confidence=Confidence.HIGH,
        raw_detail=raw_detail,
    )
    base.update(overrides)
    return CryptoFinding(**base)


def _context() -> ApplicationContext:
    return ApplicationContext(
        component="payments-api",
        data_lifetime_years=25,
        business_criticality=BusinessCriticality.CRITICAL,
        context_source=ContextSource.POLICY_FILE,
    )


def _policy() -> qr.RiskPolicy:
    return qr.RiskPolicy(
        crqc_horizon_years=10,
        default_migration_years=3,
        source=ContextSource.POLICY_FILE.value,
    )


_UNSET = object()


def _recommend(finding: CryptoFinding, context=_UNSET, policy=None):
    """Run the full risk → recommendation path for one finding.

    ``context`` defaults to a declared context, but an explicit ``None`` is
    honoured (so missing-context cases can be exercised).
    """
    if context is _UNSET:
        context = _context()
    risk = qr.assess_finding(finding, context, policy or _policy())
    return rec.recommend(finding, risk)


# ==========================================================================
# Role-aware public-key recommendations
# ==========================================================================


def test_rsa_key_establishment_maps_to_hybrid() -> None:
    """Claim: RSA key establishment is directed toward a hybrid with ML-KEM."""
    result = _recommend(_finding("RSA", role="key_establishment", key_size=2048))
    assert result.remediation_class is RemediationClass.HYBRID
    assert "ML-KEM" in result.target
    assert "FIPS 203" in result.target_standard


def test_rsa_signature_maps_to_ml_dsa_not_ml_kem() -> None:
    """Claim: an RSA signature maps toward ML-DSA, never ML-KEM.

    The central role-awareness test: mapping a signature to a KEM would be
    cryptographically wrong.
    """
    result = _recommend(_finding("RSA", role="signature", key_size=2048))
    assert result.remediation_class is RemediationClass.PQC_NATIVE
    assert result.target == "ML-DSA"
    assert "ML-KEM" not in result.target
    assert "FIPS 204" in result.target_standard


def test_rsa_unknown_role_gives_no_concrete_target() -> None:
    """Claim: an unknown role yields a conditional recommendation, not a guess."""
    result = _recommend(_finding("RSA", role="", key_size=2048))
    assert result.remediation_class is RemediationClass.INSUFFICIENT_EVIDENCE
    assert result.target == ""
    assert any(
        "key establishment" in item.lower() or "signature" in item.lower()
        for item in result.additional_evidence_required
    )


def test_ecdh_maps_to_hybrid() -> None:
    """Claim: ECDH key agreement is directed toward a hybrid."""
    result = _recommend(_finding("ECDH", role="key_establishment"))
    assert result.remediation_class is RemediationClass.HYBRID
    assert "ML-KEM" in result.target


def test_x25519_maps_to_hybrid() -> None:
    """Claim: X25519 key agreement is directed toward an ML-KEM-based hybrid.

    The target names an ML-KEM-based hybrid direction rather than one hard-coded
    universal construction — the specific construction is an implementation
    decision.
    """
    result = _recommend(_finding("X25519", role="key_establishment"))
    assert result.remediation_class is RemediationClass.HYBRID
    assert "ML-KEM" in result.target
    # The rationale, not the target, is where the existing X25519 mechanism is
    # named as part of the hybrid direction.
    assert "X25519" in " ".join(result.rationale)


def test_ecdsa_signature_maps_to_ml_dsa() -> None:
    """Claim: an ECDSA signature maps toward ML-DSA."""
    result = _recommend(_finding("ECDSA", role="signature"))
    assert result.remediation_class is RemediationClass.PQC_NATIVE
    assert result.target == "ML-DSA"


def test_ed25519_signature_maps_to_ml_dsa() -> None:
    """Claim: an Ed25519 signature maps toward ML-DSA."""
    result = _recommend(_finding("Ed25519", role="signature"))
    assert result.remediation_class is RemediationClass.PQC_NATIVE
    assert result.target == "ML-DSA"


# ==========================================================================
# Already-PQC
# ==========================================================================


@pytest.mark.parametrize("algorithm", ["ML-KEM", "ML-KEM-768", "ML-DSA", "SLH-DSA"])
def test_pqc_native_needs_no_migration(algorithm: str) -> None:
    """Claim: an already-PQC primitive is recognised, not told to migrate."""
    role = "signature" if "DSA" in algorithm else "key_establishment"
    result = _recommend(_finding(algorithm, role=role))
    assert result.remediation_class is RemediationClass.NONE_REQUIRED
    assert result.target == ""
    joined = " ".join(result.rationale).lower()
    assert "no classical-to-pqc" in joined
    # Never overclaims.
    assert "unbreakable" not in joined


# ==========================================================================
# Hybrid discipline
# ==========================================================================


def test_hybrid_is_not_inferred_from_co_presence() -> None:
    """Claim: X25519 and ML-KEM in one component are not merged into a hybrid.

    Each is recommended on its own: X25519 gets a hybrid *target* (it is
    classical key agreement), ML-KEM gets none-required (already PQC). Neither
    result claims a hybrid is already deployed.
    """
    x = _recommend(_finding("X25519", role="key_establishment", component="pqc-pilot"))
    mlkem = _recommend(_finding("ML-KEM-768", role="key_establishment", component="pqc-pilot"))

    assert x.remediation_class is RemediationClass.HYBRID
    assert mlkem.remediation_class is RemediationClass.NONE_REQUIRED
    # The X25519 recommendation is a direction, not a claim of an existing hybrid.
    assert "toward" in x.title.lower()
    # They are distinct recommendations with distinct ids.
    assert x.recommendation_id != mlkem.recommendation_id


# ==========================================================================
# Symmetric / hash
# ==========================================================================


def test_aes_128_is_classical_strengthening() -> None:
    """Claim: AES-128 is directed toward AES-256 as strengthening, not PQC."""
    result = _recommend(_finding("AES", role="symmetric", key_size=128))
    assert result.remediation_class is RemediationClass.CLASSICAL_STRENGTHENING
    assert result.target == "AES-256"
    assert "not a post-quantum" in " ".join(result.rationale).lower()


def test_aes_256_needs_no_pqc_replacement() -> None:
    """Claim: AES-256 is not told to migrate to a PQC algorithm."""
    result = _recommend(_finding("AES", role="symmetric", key_size=256))
    assert result.remediation_class is RemediationClass.NONE_REQUIRED
    assert "ML-KEM" not in result.target


def test_des_is_a_classical_issue() -> None:
    """Claim: DES is a classical security issue, not a PQC migration."""
    result = _recommend(_finding("DES", role="symmetric"))
    assert result.remediation_class is RemediationClass.NON_QUANTUM_ISSUE
    assert "classical" in " ".join(result.rationale).lower()


def test_triple_des_is_a_classical_issue() -> None:
    """Claim: Triple DES is a classical security issue."""
    result = _recommend(_finding("Triple DES", role="symmetric"))
    assert result.remediation_class is RemediationClass.NON_QUANTUM_ISSUE


def test_md5_is_a_classical_issue_with_hash_target() -> None:
    """Claim: MD5 is a classical/deprecation issue, not a PQC migration.

    The target is modernization guidance that names SHA-256 as an example while
    stating the replacement depends on context — not a universal drop-in, and
    never a post-quantum algorithm.
    """
    result = _recommend(_finding("MD5", role="hash"))
    assert result.remediation_class is RemediationClass.NON_QUANTUM_ISSUE
    assert "SHA-256" in result.target
    assert "ML-KEM" not in result.target and "ML-DSA" not in result.target
    assert "not a universal drop-in" in " ".join(result.rationale).lower()


def test_sha1_is_a_classical_issue() -> None:
    """Claim: SHA-1 is a classical/deprecation issue."""
    result = _recommend(_finding("SHA-1", role="hash"))
    assert result.remediation_class is RemediationClass.NON_QUANTUM_ISSUE


@pytest.mark.parametrize("algorithm", ["SHA-256", "SHA-512"])
def test_strong_hashes_need_no_pqc_replacement(algorithm: str) -> None:
    """Claim: SHA-256/512 are not told to migrate to a PQC algorithm."""
    result = _recommend(_finding(algorithm, role="hash"))
    assert result.remediation_class is RemediationClass.NONE_REQUIRED
    assert "ML-" not in result.target


@pytest.mark.parametrize("algorithm", ["HKDF", "HMAC"])
def test_kdf_and_mac_need_no_pqc_replacement(algorithm: str) -> None:
    """Claim: HKDF/HMAC are not directed to ML-KEM/ML-DSA."""
    result = _recommend(_finding(algorithm, role="kdf"))
    assert result.remediation_class is RemediationClass.NONE_REQUIRED
    assert result.target == ""


# ==========================================================================
# Protocols
# ==========================================================================


@pytest.mark.parametrize("protocol", ["TLS 1.2", "SSH"])
def test_protocol_findings_are_conditional(protocol: str) -> None:
    """Claim: a bare protocol finding yields a protocol-dependent recommendation."""
    result = _recommend(_finding(protocol, role="protocol"))
    assert result.remediation_class is RemediationClass.INSUFFICIENT_EVIDENCE
    assert result.target == ""
    assert any("negotiat" in item.lower() for item in result.additional_evidence_required)


def test_tls_13_is_not_called_quantum_vulnerable() -> None:
    """Claim: TLS 1.3 itself is not labelled quantum-vulnerable.

    The negotiated group is the relevant question, and the recommendation says
    so rather than condemning the protocol.
    """
    result = _recommend(_finding("TLS 1.3", role="protocol"))
    joined = " ".join(result.rationale).lower()
    assert "negotiat" in joined


# ==========================================================================
# Capability and unknown
# ==========================================================================


def test_library_capability_is_usage_not_established() -> None:
    """Claim: a capability-only library gets no migration recommendation."""
    finding = CryptoFinding(
        finding_id="fnd_lib",
        scan_id="s",
        artefact_type=ArtefactType.LIBRARY,
        algorithm="",
        library="pyca/cryptography",
        source_type=SourceType.DEPENDENCY,
        component="payments-api",
        detection_method=DetectionMethod.MANIFEST_PARSE,
        evidence="requirements.txt:3",
        confidence=Confidence.HIGH,
        raw_detail={"provides_algorithms": ["RSA"]},
    )
    result = _recommend(finding)
    assert result.remediation_class is RemediationClass.USAGE_NOT_ESTABLISHED
    assert result.target == ""
    assert any("call site" in item.lower() for item in result.additional_evidence_required)


def test_unknown_algorithm_is_insufficient_evidence() -> None:
    """Claim: an unknown algorithm yields insufficient-evidence, not a guess."""
    result = _recommend(_finding("Serpent", role="symmetric"))
    assert result.remediation_class is RemediationClass.INSUFFICIENT_EVIDENCE
    assert result.target == ""


def test_missing_role_and_algorithm_is_handled() -> None:
    """Claim: a finding with neither algorithm nor role does not crash."""
    finding = CryptoFinding(
        finding_id="fnd_empty",
        scan_id="s",
        artefact_type=ArtefactType.UNKNOWN,
        source_type=SourceType.SOURCE_CODE,
        detection_method=DetectionMethod.PATTERN_MATCH,
        confidence=Confidence.LOW,
    )
    result = _recommend(finding)
    assert result.remediation_class is RemediationClass.INSUFFICIENT_EVIDENCE


# ==========================================================================
# Certificate handling
# ==========================================================================


def test_certificate_recommendation_notes_the_usage_caveat() -> None:
    """Claim: a certificate recommendation distinguishes metadata from usage.

    The certificate establishes its own algorithm, not that the application
    uses that key for live key establishment — and the limitation says so.
    """
    finding = _finding(
        "RSA",
        finding_id="fnd_cert",
        role="signature",
        artefact_type=ArtefactType.CERTIFICATE,
        key_size=2048,
        certificate=CertificateFacts(subject="CN=payments", issuer="CN=payments"),
        source_type=SourceType.CERTIFICATE_FILE,
        detection_method=DetectionMethod.LIBRARY_PARSE,
        raw_detail={"role": "signature", "evidence_level": ""},
    )
    result = _recommend(finding)
    assert any("certificate" in item.lower() for item in result.limitations)


# ==========================================================================
# Evidence / confidence preservation
# ==========================================================================


@pytest.mark.parametrize("confidence", [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH])
def test_confidence_is_preserved(confidence: Confidence) -> None:
    """Claim: the finding's confidence is carried through unchanged."""
    result = _recommend(_finding("RSA", role="key_establishment", key_size=2048, confidence=confidence))
    assert result.confidence is confidence


def test_low_confidence_recommendation_notes_verification() -> None:
    """Claim: a low-confidence recommendation is not dressed up as authoritative."""
    result = _recommend(
        _finding(
            "RSA",
            role="key_establishment",
            key_size=2048,
            confidence=Confidence.LOW,
            raw_detail={"role": "key_establishment", "evidence_level": "import"},
        )
    )
    assert result.confidence is Confidence.LOW
    assert result.evidence_level == "import"
    assert any("low confidence" in item.lower() for item in result.limitations)


def test_evidence_level_is_preserved() -> None:
    """Claim: the evidence level survives into the recommendation."""
    result = _recommend(_finding("RSA", role="key_establishment", key_size=2048))
    assert result.evidence_level == "call_site"


# ==========================================================================
# Mosca consumption — never recomputed
# ==========================================================================


def test_mosca_status_is_consumed_not_recomputed() -> None:
    """Claim: the recommendation reflects Phase 7's Mosca status verbatim.

    A within-window asset's recommendation notes the timing relevance; the
    engine does not re-run X + Y > Z.
    """
    result = _recommend(_finding("RSA", role="key_establishment", key_size=2048))
    assert result.mosca_status == "within_quantum_window"
    assert any("within the assumed quantum-threat window" in r for r in result.rationale)


def test_missing_mosca_is_reflected_not_filled() -> None:
    """Claim: an insufficient-information Mosca status is reflected honestly."""
    # No context => no lifetime => insufficient information upstream.
    result = _recommend(_finding("RSA", role="key_establishment", key_size=2048), context=None)
    assert result.mosca_status == "insufficient_information"
    assert any("timing is unresolved" in r.lower() for r in result.rationale)


def test_engine_does_not_import_mosca_math() -> None:
    """Claim: no Mosca recomputation exists in the recommendation engine.

    A static check: the engine must not call the Phase 7 Mosca routine.
    """
    source_text = Path(rec.__file__).read_text(encoding="utf-8")
    assert "run_mosca" not in source_text
    assert "x_data_lifetime" not in source_text


# ==========================================================================
# Cost / latency honesty
# ==========================================================================


def test_no_invented_benchmark_numbers() -> None:
    """Claim: performance is stated as not measured, never fabricated."""
    result = _recommend(_finding("RSA", role="key_establishment", key_size=2048))
    assert "not measured" in result.performance_note.lower()
    # No fabricated percentage.
    assert "%" not in result.performance_note


# ==========================================================================
# Traceability
# ==========================================================================


def test_recommendation_traces_to_finding_id() -> None:
    """Claim: every recommendation names its originating finding."""
    finding = _finding("RSA", role="key_establishment", key_size=2048, finding_id="fnd_trace")
    result = _recommend(finding)
    assert result.finding_id == "fnd_trace"
    assert result.recommendation_id.startswith("rec_")


def test_component_and_provenance_survive() -> None:
    """Claim: component attribution and provenance are carried through."""
    result = _recommend(_finding("RSA", role="key_establishment", key_size=2048, component="legacy-auth"))
    assert result.component == "legacy-auth"
    assert "finding:" in result.provenance


# ==========================================================================
# No Phase 9 leakage
# ==========================================================================


def test_no_priority_or_ranking_fields() -> None:
    """Claim: no prioritisation appears in a Phase 8 recommendation."""
    result = _recommend(_finding("RSA", role="key_establishment", key_size=2048))
    payload = result.to_dict()
    for forbidden in ("priority", "rank", "sequence", "order", "first", "queue"):
        assert not any(forbidden in key.lower() for key in payload)


def test_summary_does_not_rank() -> None:
    """Claim: the summary counts but never ranks or names a worst asset."""
    findings = [
        _finding("RSA", role="key_establishment", key_size=2048),
        _finding("AES", role="symmetric", key_size=128),
    ]
    risks = [qr.assess_finding(f, _context(), _policy()) for f in findings]
    recommendations = rec.recommend_batch(findings, risks)
    summary = rec.summarize(recommendations)
    assert "ranking" not in summary
    assert "worst" not in summary
    assert "priority" not in summary
    assert summary["total"] == 2


# ==========================================================================
# Determinism
# ==========================================================================


def test_recommendation_is_deterministic() -> None:
    """Claim: identical inputs yield identical recommendations."""
    finding = _finding("RSA", role="key_establishment", key_size=2048)
    risk = qr.assess_finding(finding, _context(), _policy())
    first = rec.recommend(finding, risk).to_dict()
    second = rec.recommend(finding, risk).to_dict()
    assert first == second


def test_ids_are_deterministic() -> None:
    """Claim: the recommendation id is a pure function of the finding id."""
    finding = _finding("RSA", role="key_establishment", key_size=2048, finding_id="fnd_stable")
    risk = qr.assess_finding(finding, _context(), _policy())
    id_a = rec.recommend(finding, risk).recommendation_id
    id_b = rec.recommend(finding, risk).recommendation_id
    assert id_a == id_b


def test_batch_ordering_is_independent_of_input_order() -> None:
    """Claim: batch output is sorted by finding id, whatever the input order."""
    findings = [
        _finding("RSA", role="signature", key_size=2048, finding_id="fnd_c"),
        _finding("AES", role="symmetric", key_size=256, finding_id="fnd_a"),
        _finding("ML-KEM-768", role="key_establishment", finding_id="fnd_b"),
    ]
    risks = [qr.assess_finding(f, _context(), _policy()) for f in findings]

    forward = [r.finding_id for r in rec.recommend_batch(findings, risks)]
    backward = [
        r.finding_id
        for r in rec.recommend_batch(list(reversed(findings)), list(reversed(risks)))
    ]
    assert forward == backward == ["fnd_a", "fnd_b", "fnd_c"]


def test_no_timestamp_or_random_in_output() -> None:
    """Claim: recommendations contain no timestamp or random value."""
    import json

    result = _recommend(_finding("RSA", role="key_establishment", key_size=2048))
    text = json.dumps(result.to_dict())
    assert "timestamp" not in text
    assert "assessed_at" not in text


# ==========================================================================
# Safety
# ==========================================================================


def test_engine_performs_no_execution_or_io() -> None:
    """Claim: the engine is pure computation.

    AST-checked: no subprocess, network, or package manager; no file scanning
    beyond the knowledge base loaded at import.
    """
    tree = ast.parse(Path(rec.__file__).read_text(encoding="utf-8"))
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


def test_no_secret_material_in_output() -> None:
    """Claim: no key material reaches a recommendation."""
    result = _recommend(
        _finding(
            "RSA",
            role="key_establishment",
            key_size=2048,
            evidence="-----BEGIN PRIVATE KEY----- MIIEvAIBA...",
        )
    )
    import json

    text = json.dumps(result.to_dict())
    assert "PRIVATE KEY" not in text
    assert "MIIEvAIBA" not in text


def test_engine_does_not_mutate_inputs() -> None:
    """Claim: recommending leaves the finding and risk result unchanged."""
    finding = _finding("RSA", role="key_establishment", key_size=2048)
    risk = qr.assess_finding(finding, _context(), _policy())
    before_f = finding.to_dict()
    before_r = risk.to_dict()
    rec.recommend(finding, risk)
    assert finding.to_dict() == before_f
    assert risk.to_dict() == before_r


# ==========================================================================
# Robustness / batch
# ==========================================================================


def test_empty_inventory_yields_no_recommendations() -> None:
    """Claim: nothing in, nothing out."""
    assert rec.recommend_batch([], []) == []


def test_risk_without_matching_finding_is_skipped() -> None:
    """Claim: a risk result with no finding is skipped, never fabricated."""
    finding = _finding("RSA", role="key_establishment", key_size=2048, finding_id="fnd_x")
    risk = qr.assess_finding(finding, _context(), _policy())
    # Pass the risk but not the finding.
    assert rec.recommend_batch([], [risk]) == []


# ==========================================================================
# Integration — full demo estate
# ==========================================================================


@pytest.fixture(scope="module")
def estate(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The full demo estate with a quantum_risk policy block."""
    root = tmp_path_factory.mktemp("phase8_estate")
    demo_enterprise.generate(root, force=True)
    demo_manifests.write_application_manifests(root)
    demo_source.write_application_source(root)
    demo_binaries.write_application_binaries(root)
    policy_path = root / "aegis_policy.yaml"
    policy_path.write_text(
        policy_path.read_text(encoding="utf-8")
        + "\nquantum_risk:\n  crqc_horizon_years: 10\n  default_migration_years: 3\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture(scope="module")
def estate_recommendations(estate: Path):
    """Recommendations over the full estate."""
    raw = inventory._parse_policy_file(estate / "aegis_policy.yaml")
    resolver = ComponentResolver(extract_declared_paths(raw))
    policy = qr.load_risk_policy(estate)

    findings = []
    findings += certificates.CERTIFICATE_ADAPTER.scan(estate, "s").findings
    findings += dependencies.DEPENDENCY_ADAPTER.scan(estate, "s", resolver=resolver).findings
    findings += source.SOURCE_ADAPTER.scan(estate, "s", resolver=resolver).findings
    if binary.LIEF_AVAILABLE:
        findings += binary.BINARY_ADAPTER.scan(estate, "s", resolver=resolver).findings

    contexts = {
        c: inventory.resolve_context(c, inventory.load_policy(estate))
        for c in {f.component for f in findings if f.component}
    }
    risks = qr.assess_inventory(findings, contexts, policy)
    return findings, rec.recommend_batch(findings, risks)


def test_estate_recommendations_are_explainable(estate_recommendations) -> None:
    """Claim: every estate recommendation has a rationale and traces back."""
    _, recommendations = estate_recommendations
    assert recommendations
    for result in recommendations:
        assert result.finding_id
        assert result.rationale
        assert result.remediation_class in set(RemediationClass)


def test_estate_covers_multiple_remediation_classes(estate_recommendations) -> None:
    """Claim: the estate exercises hybrid, PQC-native, classical, and capability."""
    _, recommendations = estate_recommendations
    classes = {r.remediation_class for r in recommendations}
    assert RemediationClass.HYBRID in classes
    assert RemediationClass.PQC_NATIVE in classes
    assert RemediationClass.NON_QUANTUM_ISSUE in classes
    assert RemediationClass.USAGE_NOT_ESTABLISHED in classes


def test_pqc_pilot_recognises_pqc_and_recommends_hybrid_for_classical(
    estate_recommendations,
) -> None:
    """Claim: pqc-pilot's ML-KEM is none-required; its X25519 is hybrid-directed.

    The hybrid discipline end to end — both legs present, classified distinctly.
    """
    _, recommendations = estate_recommendations
    pilot = [r for r in recommendations if r.component == "pqc-pilot"]
    classes = {r.current_algorithm: r.remediation_class for r in pilot if r.current_algorithm}

    assert any(
        "ML-KEM" in algo and cls is RemediationClass.NONE_REQUIRED
        for algo, cls in classes.items()
    )
    assert any(
        algo == "X25519" and cls is RemediationClass.HYBRID
        for algo, cls in classes.items()
    )


def test_legacy_auth_gets_classical_guidance_not_only_pqc(estate_recommendations) -> None:
    """Claim: legacy-auth's MD5/DES get classical guidance, not PQC migration."""
    _, recommendations = estate_recommendations
    legacy = [r for r in recommendations if r.component == "legacy-auth"]
    non_quantum = [r for r in legacy if r.remediation_class is RemediationClass.NON_QUANTUM_ISSUE]
    algorithms = {r.current_algorithm for r in non_quantum}
    assert {"MD5", "DES"} & algorithms


def test_content_portal_has_no_recommendations(estate_recommendations) -> None:
    """Claim: the clean application yields no recommendations."""
    _, recommendations = estate_recommendations
    assert not any(r.component == "content-portal" for r in recommendations)


def test_estate_summary_counts_match(estate_recommendations) -> None:
    """Claim: the summary aggregates without ranking."""
    _, recommendations = estate_recommendations
    summary = rec.summarize(recommendations)
    assert summary["total"] == len(recommendations)
    assert sum(summary["by_remediation_class"].values()) == len(recommendations)


# ==========================================================================
# Knowledge-base coverage — every mapping loadable and reachable
# ==========================================================================


@pytest.mark.parametrize(
    "algorithm,role,expected_class",
    [
        # Public-key: key establishment -> hybrid
        ("RSA", "key_establishment", RemediationClass.HYBRID),
        ("Diffie-Hellman", "key_establishment", RemediationClass.HYBRID),
        ("ECDH", "key_establishment", RemediationClass.HYBRID),
        ("X25519", "key_establishment", RemediationClass.HYBRID),
        ("X448", "key_establishment", RemediationClass.HYBRID),
        # Public-key: signature -> pqc-native
        ("RSA", "signature", RemediationClass.PQC_NATIVE),
        ("DSA", "signature", RemediationClass.PQC_NATIVE),
        ("ECDSA", "signature", RemediationClass.PQC_NATIVE),
        ("Ed25519", "signature", RemediationClass.PQC_NATIVE),
        ("Ed448", "signature", RemediationClass.PQC_NATIVE),
        # Symmetric
        ("DES", "symmetric", RemediationClass.NON_QUANTUM_ISSUE),
        ("Triple DES", "symmetric", RemediationClass.NON_QUANTUM_ISSUE),
        ("ChaCha20", "symmetric", RemediationClass.NONE_REQUIRED),
        ("ChaCha20-Poly1305", "symmetric", RemediationClass.NONE_REQUIRED),
        # Hash
        ("MD5", "hash", RemediationClass.NON_QUANTUM_ISSUE),
        ("SHA-1", "hash", RemediationClass.NON_QUANTUM_ISSUE),
        ("SHA-2", "hash", RemediationClass.NONE_REQUIRED),
        ("SHA-256", "hash", RemediationClass.NONE_REQUIRED),
        ("SHA-384", "hash", RemediationClass.NONE_REQUIRED),
        ("SHA-512", "hash", RemediationClass.NONE_REQUIRED),
        # KDF / MAC
        ("HKDF", "kdf", RemediationClass.NONE_REQUIRED),
        ("HMAC", "hash", RemediationClass.NONE_REQUIRED),
        # Post-quantum
        ("ML-KEM", "key_establishment", RemediationClass.NONE_REQUIRED),
        ("ML-KEM-768", "key_establishment", RemediationClass.NONE_REQUIRED),
        ("ML-DSA", "signature", RemediationClass.NONE_REQUIRED),
        ("SLH-DSA", "signature", RemediationClass.NONE_REQUIRED),
        # Protocols
        ("TLS", "protocol", RemediationClass.INSUFFICIENT_EVIDENCE),
        ("TLS 1.2", "protocol", RemediationClass.INSUFFICIENT_EVIDENCE),
        ("TLS 1.3", "protocol", RemediationClass.INSUFFICIENT_EVIDENCE),
        ("SSH", "protocol", RemediationClass.INSUFFICIENT_EVIDENCE),
    ],
)
def test_every_kb_mapping_is_reachable(
    algorithm: str, role: str, expected_class: RemediationClass
) -> None:
    """Claim: every supported KB mapping loads and produces its class.

    One case per knowledge-base entry, so an entry that fails to load or is
    unreachable through the engine fails the build rather than silently going
    dead. AES entries are covered separately because they key on the variant.
    """
    result = _recommend(_finding(algorithm, role=role))
    assert result.remediation_class is expected_class


@pytest.mark.parametrize(
    "key_size,expected_class",
    [
        (128, RemediationClass.CLASSICAL_STRENGTHENING),
        (256, RemediationClass.NONE_REQUIRED),
    ],
)
def test_aes_variant_mappings_are_reachable(
    key_size: int, expected_class: RemediationClass
) -> None:
    """Claim: the AES-128 and AES-256 KB entries are both reachable."""
    result = _recommend(_finding("AES", role="symmetric", key_size=key_size))
    assert result.remediation_class is expected_class


def test_hybrid_targets_avoid_universal_construction_claims() -> None:
    """Claim: hybrid targets no longer hard-code one universal construction.

    The correction pass replaced "Hybrid X25519 + ML-KEM-768" as the universal
    target with an ML-KEM-based direction, leaving the specific construction and
    parameter set as an implementation decision.
    """
    for algo in ("RSA", "Diffie-Hellman", "ECDH", "X25519", "X448"):
        result = _recommend(_finding(algo, role="key_establishment"))
        assert result.remediation_class is RemediationClass.HYBRID
        assert "ML-KEM" in result.target
        # No hard-coded universal construction in the target itself.
        assert "X25519 + ML-KEM-768" not in result.target


def test_no_unsupported_tls_deployment_claim() -> None:
    """Claim: no recommendation claims a hybrid is deployed in TLS 1.3.

    A bare protocol finding does not establish the negotiated group, so that
    deployment claim was removed.
    """
    for algo in ("RSA", "ECDH", "X25519"):
        result = _recommend(_finding(algo, role="key_establishment"))
        joined = (result.target + " " + " ".join(result.rationale)).lower()
        assert "deployed in tls" not in joined


def test_x448_does_not_hardcode_ml_kem_1024() -> None:
    """Claim: X448 no longer maps to a hard-coded ML-KEM-1024.

    Parameter selection is an implementation/interoperability decision, stated
    as such rather than fixed.
    """
    result = _recommend(_finding("X448", role="key_establishment"))
    assert "ML-KEM-1024" not in result.target
    assert "parameter" in " ".join(result.rationale).lower()


def test_hash_replacement_is_context_dependent() -> None:
    """Claim: hash guidance states the replacement depends on context.

    SHA-256 is offered as an example, not a universal drop-in for every use.
    """
    for algo in ("MD5", "SHA-1"):
        result = _recommend(_finding(algo, role="hash"))
        assert "not a universal drop-in" in " ".join(result.rationale).lower()


def test_estate_recommendations_are_deterministic(estate: Path) -> None:
    """Claim: regenerating over the estate gives byte-identical output.

    Actually regenerates the full risk → recommendation path a second time and
    compares the serialised results, rather than comparing a value to itself.
    """
    raw = inventory._parse_policy_file(estate / "aegis_policy.yaml")
    resolver = ComponentResolver(extract_declared_paths(raw))
    policy = qr.load_risk_policy(estate)

    findings = []
    findings += certificates.CERTIFICATE_ADAPTER.scan(estate, "s").findings
    findings += dependencies.DEPENDENCY_ADAPTER.scan(estate, "s", resolver=resolver).findings
    findings += source.SOURCE_ADAPTER.scan(estate, "s", resolver=resolver).findings
    if binary.LIEF_AVAILABLE:
        findings += binary.BINARY_ADAPTER.scan(estate, "s", resolver=resolver).findings

    contexts = {
        c: inventory.resolve_context(c, inventory.load_policy(estate))
        for c in {f.component for f in findings if f.component}
    }

    risks_first = qr.assess_inventory(findings, contexts, policy)
    first = rec.recommend_batch(findings, risks_first)

    risks_again = qr.assess_inventory(findings, contexts, policy)
    second = rec.recommend_batch(findings, risks_again)

    assert [r.to_dict() for r in first] == [r.to_dict() for r in second]
    assert [r.finding_id for r in first] == sorted(r.finding_id for r in first)
