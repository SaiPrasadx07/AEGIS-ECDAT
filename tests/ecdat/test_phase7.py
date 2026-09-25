"""
Aegis PQC — ECDAT Phase 7 tests: quantum risk and Mosca analysis.

The engine's job is an auditable answer to: what cryptographic asset do we
have, what quantum issue applies, what assumptions are in play, what is
missing, and why this classification. These tests hold it to that — every
branch of the decision path, the honesty of missing-data handling, and the
preservation of evidence semantics from the earlier phases.

Run Phase 7 only:  pytest tests/ecdat/test_phase7.py -q
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
    MoscaStatus,
    QuantumCategory,
    RiskLevel,
    Sensitivity,
    SourceType,
)


# --------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------


def _finding(algorithm: str, **overrides) -> CryptoFinding:
    """A canonical algorithm finding with sensible defaults.

    ``role`` and ``evidence_level`` are conveniences that route into
    ``raw_detail``, matching how the real scanners populate a finding.
    """
    role = overrides.pop("role", "key_establishment")
    evidence_level = overrides.pop("evidence_level", "call_site")
    raw_detail = overrides.pop(
        "raw_detail", {"role": role, "evidence_level": evidence_level}
    )
    base = dict(
        finding_id=f"fnd_{algorithm.lower().replace('-', '')[:10]}",
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


def _full_policy() -> qr.RiskPolicy:
    """A policy declaring all three Mosca inputs."""
    return qr.RiskPolicy(
        crqc_horizon_years=10,
        default_migration_years=3,
        source=ContextSource.POLICY_FILE.value,
    )


def _long_lived_context() -> ApplicationContext:
    """Declared context with a long data lifetime and critical business."""
    return ApplicationContext(
        component="payments-api",
        data_lifetime_years=25,
        data_sensitivity=Sensitivity.CRITICAL,
        business_criticality=BusinessCriticality.CRITICAL,
        context_source=ContextSource.POLICY_FILE,
    )


def assess(finding, context=None, policy=None):
    """Assess one finding with optional context and policy."""
    return qr.assess_finding(finding, context, policy or _full_policy())


# ==========================================================================
# Quantum classification — the decision path
# ==========================================================================


def test_rsa_is_quantum_vulnerable() -> None:
    """Claim: RSA is classified as quantum-vulnerable public-key crypto."""
    result = assess(_finding("RSA", key_size=2048), _long_lived_context())
    assert result.quantum_category is QuantumCategory.QUANTUM_VULNERABLE
    assert "factorisation" in " ".join(result.rationale).lower()


def test_ecdsa_is_quantum_vulnerable() -> None:
    """Claim: ECDSA is classified as quantum-vulnerable (a signature)."""
    result = assess(_finding("ECDSA", role="signature"), _long_lived_context())
    assert result.quantum_category is QuantumCategory.QUANTUM_VULNERABLE


def test_ecdh_and_x25519_are_quantum_vulnerable() -> None:
    """Claim: classical EC key agreement is quantum-vulnerable.

    X25519 alone is elliptic-curve key agreement, defeated by Shor. It must not
    be waved through as safe.
    """
    for algo in ("ECDH", "X25519"):
        result = assess(_finding(algo), _long_lived_context())
        assert result.quantum_category is QuantumCategory.QUANTUM_VULNERABLE, algo


def test_aes_is_not_treated_like_rsa() -> None:
    """Claim: AES is symmetric, not equivalent to RSA/ECC exposure.

    The central symmetric-vs-public-key distinction.
    """
    aes = assess(_finding("AES", key_size=256, role="symmetric"), _long_lived_context())
    rsa = assess(_finding("RSA", key_size=2048), _long_lived_context())

    assert aes.quantum_category is QuantumCategory.SYMMETRIC_REDUCED
    assert rsa.quantum_category is QuantumCategory.QUANTUM_VULNERABLE
    assert aes.risk_level is not rsa.risk_level
    assert aes.mosca_status is MoscaStatus.NOT_TIME_SENSITIVE


def test_aes_128_and_256_carry_different_margin_notes() -> None:
    """Claim: key size changes the effective-margin explanation, when known."""
    aes256 = assess(_finding("AES", key_size=256, role="symmetric"))
    aes128 = assess(_finding("AES", key_size=128, role="symmetric"))

    assert "wide margin" in " ".join(aes256.rationale).lower()
    assert "64-bit" in " ".join(aes128.rationale).lower()


def test_hashes_and_kdfs_receive_appropriate_treatment() -> None:
    """Claim: hashes and KDFs are not public-key quantum-vulnerable."""
    sha = assess(_finding("SHA-256", role="hash"))
    hkdf = assess(_finding("HKDF", role="kdf"))
    hmac = assess(_finding("HMAC", role="hash"))

    assert sha.quantum_category is QuantumCategory.SYMMETRIC_REDUCED
    assert hkdf.quantum_category is QuantumCategory.NOT_APPLICABLE
    assert hmac.quantum_category is QuantumCategory.NOT_APPLICABLE
    for result in (sha, hkdf, hmac):
        assert result.mosca_status is MoscaStatus.NOT_TIME_SENSITIVE


def test_ml_kem_is_post_quantum() -> None:
    """Claim: ML-KEM and ML-KEM-768 are recognised as post-quantum."""
    for algo in ("ML-KEM", "ML-KEM-768"):
        result = assess(_finding(algo))
        assert result.quantum_category is QuantumCategory.POST_QUANTUM, algo
        assert result.risk_level is RiskLevel.PQC_READY
        # Never "unbreakable" — designed to resist.
        assert "resist" in " ".join(result.rationale).lower()


def test_post_quantum_is_not_called_unbreakable() -> None:
    """Claim: a PQC result never overclaims certainty."""
    result = assess(_finding("ML-KEM-768"))
    joined = " ".join(result.rationale).lower()
    assert "unbreakable" not in joined
    assert "proof" not in joined or "not a proof" in joined


def test_hybrid_components_remain_distinguishable() -> None:
    """Claim: the classical and PQC legs of a hybrid are classified separately.

    The scanner records X25519 and ML-KEM-768 as separate findings. The risk
    engine must classify each on its own merits — X25519 vulnerable, ML-KEM
    post-quantum — not merge them into one verdict.
    """
    classical = assess(_finding("X25519"))
    pq = assess(_finding("ML-KEM-768"))

    assert classical.quantum_category is QuantumCategory.QUANTUM_VULNERABLE
    assert pq.quantum_category is QuantumCategory.POST_QUANTUM
    # They are different findings with different conclusions.
    assert classical.risk_level is not pq.risk_level


def test_unknown_algorithm_stays_unknown() -> None:
    """Claim: an unrecognised algorithm is never guessed."""
    result = assess(_finding("Serpent"))
    assert result.quantum_category is QuantumCategory.UNKNOWN
    assert result.risk_level is RiskLevel.UNKNOWN
    assert "not in the quantum-risk knowledge base" in " ".join(result.rationale)


def test_library_capability_is_not_usage() -> None:
    """Claim: a capability-only library gets no algorithm-level quantum verdict.

    The Phase 2/6 rule carried into risk: a LIBRARY finding with no algorithm
    describes what is available, not what is used.
    """
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
        raw_detail={"provides_algorithms": ["RSA", "AES"]},
    )
    result = assess(finding)
    assert result.quantum_category is QuantumCategory.CAPABILITY_ONLY
    assert result.risk_level is RiskLevel.UNKNOWN
    assert "capability, not confirmed use" in " ".join(result.rationale)


def test_protocol_finding_is_dependent_not_definite() -> None:
    """Claim: a bare protocol finding cannot be given a definite class.

    TLS exposure depends on the negotiated suite, which a protocol finding
    alone does not fix.
    """
    finding = _finding("TLS 1.2", role="protocol")
    result = assess(finding)
    assert result.quantum_category is QuantumCategory.PROTOCOL_DEPENDENT
    assert result.mosca_status is MoscaStatus.INSUFFICIENT_INFORMATION


def test_certificate_finding_is_handled() -> None:
    """Claim: a certificate's algorithm is assessed, as a certificate asset.

    The role is a certificate's signature/public-key algorithm, which is
    assessed — while the artefact type is retained so a reader knows what was
    assessed.
    """
    finding = _finding(
        "RSA",
        finding_id="fnd_cert",
        artefact_type=ArtefactType.CERTIFICATE,
        key_size=2048,
        certificate=CertificateFacts(subject="CN=payments", issuer="CN=payments"),
        source_type=SourceType.CERTIFICATE_FILE,
        detection_method=DetectionMethod.LIBRARY_PARSE,
        raw_detail={"role": "signature", "evidence_level": ""},
    )
    result = assess(finding, _long_lived_context())
    assert result.quantum_category is QuantumCategory.QUANTUM_VULNERABLE
    assert result.artefact_type == "certificate"


# ==========================================================================
# Key size
# ==========================================================================


def test_known_key_size_survives() -> None:
    """Claim: an established key size is carried into the result."""
    result = assess(_finding("RSA", key_size=2048), _long_lived_context())
    assert result.key_size == 2048
    assert "RSA-2048" in " ".join(result.rationale)


def test_unknown_key_size_stays_unknown() -> None:
    """Claim: an absent key size is never invented from the algorithm name."""
    result = assess(_finding("RSA", key_size=None), _long_lived_context())
    assert result.key_size is None
    assert "RSA-2048" not in " ".join(result.rationale)
    assert "RSA " in " ".join(result.rationale) or "RSA " in result.rationale[0]


# ==========================================================================
# Mosca analysis
# ==========================================================================


def test_within_window_is_critical() -> None:
    """Claim: long-lived data crossing the CRQC horizon is the top rating."""
    result = assess(_finding("RSA", key_size=2048), _long_lived_context())
    assert result.mosca_status is MoscaStatus.WITHIN_QUANTUM_WINDOW
    assert result.risk_level is RiskLevel.CRITICAL
    assert result.mosca.verdict.value == "exposed"


def test_outside_window_is_conditional_not_safe() -> None:
    """Claim: staying within the horizon is MEDIUM and explicitly conditional.

    The asset is not called safe — the algorithm is still quantum-vulnerable,
    and the outcome depends on the assumptions.
    """
    short = ApplicationContext(
        component="payments-api",
        data_lifetime_years=2,
        context_source=ContextSource.POLICY_FILE,
    )
    policy = qr.RiskPolicy(
        crqc_horizon_years=15,
        default_migration_years=2,
        source=ContextSource.POLICY_FILE.value,
    )
    result = assess(_finding("RSA", key_size=2048), short, policy)
    assert result.mosca_status is MoscaStatus.OUTSIDE_QUANTUM_WINDOW
    assert result.risk_level is RiskLevel.MEDIUM
    assert "conditional" in " ".join(result.rationale).lower()
    assert "quantum-vulnerable" in " ".join(result.rationale).lower()


def test_mosca_formula_is_x_plus_y_versus_z() -> None:
    """Claim: the implemented relationship is data_lifetime + migration > CRQC."""
    result = assess(_finding("RSA", key_size=2048), _long_lived_context())
    mosca = result.mosca
    assert mosca.x_data_lifetime_years == 25
    assert mosca.y_migration_years == 3
    assert mosca.z_horizon_years == 10
    assert mosca.margin_years == 18  # 25 + 3 - 10
    assert "28 > Z(10)" in mosca.statement


# ==========================================================================
# Missing data — the honesty requirement
# ==========================================================================


def test_missing_lifetime_is_insufficient_information() -> None:
    """Claim: without data lifetime, the Mosca outcome is insufficient.

    The algorithm is still known-vulnerable (HIGH), but the timing question is
    unresolved and says so — no lifetime is invented.
    """
    policy = qr.RiskPolicy(
        crqc_horizon_years=10,
        default_migration_years=3,
        source=ContextSource.POLICY_FILE.value,
    )
    # No context => no declared lifetime, and no default lifetime in policy.
    result = assess(_finding("RSA", key_size=2048), None, policy)
    assert result.mosca_status is MoscaStatus.INSUFFICIENT_INFORMATION
    assert result.risk_level is RiskLevel.HIGH
    assert "data_lifetime_years" in " ".join(result.rationale)


def test_missing_migration_is_insufficient_information() -> None:
    """Claim: without migration time, the Mosca outcome is insufficient."""
    policy = qr.RiskPolicy(
        crqc_horizon_years=10, source=ContextSource.POLICY_FILE.value
    )  # no default_migration_years
    result = assess(_finding("RSA", key_size=2048), _long_lived_context(), policy)
    assert result.mosca_status is MoscaStatus.INSUFFICIENT_INFORMATION
    assert "migration_time_years" in " ".join(result.rationale)


def test_missing_crqc_is_insufficient_information() -> None:
    """Claim: without a CRQC assumption, the Mosca outcome is insufficient."""
    policy = qr.RiskPolicy(
        default_migration_years=3, source=ContextSource.POLICY_FILE.value
    )  # no crqc_horizon_years
    result = assess(_finding("RSA", key_size=2048), _long_lived_context(), policy)
    assert result.mosca_status is MoscaStatus.INSUFFICIENT_INFORMATION


def test_no_policy_yields_insufficient_not_a_guess() -> None:
    """Claim: with no assumptions at all, nothing is fabricated."""
    result = assess(_finding("RSA", key_size=2048), None, qr.RiskPolicy())
    assert result.mosca_status is MoscaStatus.INSUFFICIENT_INFORMATION
    assert result.mosca is None
    missing = {a.name for a in result.assumptions if not a.is_present}
    assert missing == {"data_lifetime_years", "migration_time_years", "crqc_horizon_years"}


# ==========================================================================
# Provenance and assumptions
# ==========================================================================


def test_crqc_assumption_carries_provenance() -> None:
    """Claim: the CRQC horizon is reported with its source, as an assumption."""
    result = assess(_finding("RSA", key_size=2048), _long_lived_context())
    crqc = [a for a in result.assumptions if a.name == "crqc_horizon_years"][0]
    assert crqc.value == 10
    assert crqc.unit == "years"
    assert crqc.provenance == ContextSource.POLICY_FILE.value


def test_policy_values_preserve_provenance() -> None:
    """Claim: a policy-supplied lifetime keeps its policy_file provenance."""
    result = assess(_finding("RSA", key_size=2048), _long_lived_context())
    lifetime = [a for a in result.assumptions if a.name == "data_lifetime_years"][0]
    assert lifetime.provenance == ContextSource.POLICY_FILE.value
    assert lifetime.is_default is False


def test_documented_default_is_marked_as_default() -> None:
    """Claim: a value from a documented default is flagged, not passed as fact.

    An operator using the policy's default_migration_years must see that it was
    a default, not an observation.
    """
    result = assess(_finding("RSA", key_size=2048), _long_lived_context())
    migration = [a for a in result.assumptions if a.name == "migration_time_years"][0]
    assert migration.is_default is True
    assert migration.provenance == ContextSource.POLICY_FILE.value


def test_missing_assumption_is_marked_missing() -> None:
    """Claim: an absent input is explicitly missing, not silently zero."""
    result = assess(_finding("RSA", key_size=2048), None, qr.RiskPolicy())
    for assumption in result.assumptions:
        if not assumption.is_present:
            assert assumption.provenance == "missing"
            assert assumption.value is None


# ==========================================================================
# Evidence / confidence preservation
# ==========================================================================


def test_confidence_survives_unchanged() -> None:
    """Claim: the finding's confidence is carried through verbatim."""
    for confidence in (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH):
        result = assess(_finding("RSA", key_size=2048, confidence=confidence), _long_lived_context())
        assert result.confidence is confidence


def test_low_evidence_is_never_upgraded() -> None:
    """Claim: a LOW/import finding stays LOW; the classification is separate.

    An import-level RSA finding is still quantum-vulnerable by algorithm, but
    its evidence stays weak — the risk engine does not launder weak evidence
    into strong.
    """
    finding = _finding(
        "RSA",
        key_size=2048,
        confidence=Confidence.LOW,
        raw_detail={"role": "key_establishment", "evidence_level": "import"},
    )
    result = assess(finding, _long_lived_context())
    assert result.confidence is Confidence.LOW
    assert result.evidence_level == "import"


def test_evidence_level_and_detection_method_survive() -> None:
    """Claim: evidence level, detection method, and source type are carried."""
    result = assess(_finding("RSA", key_size=2048), _long_lived_context())
    assert result.evidence_level == "call_site"
    assert result.detection_method == "ast_parse"
    assert result.source_type == "source_code"


# ==========================================================================
# Traceability
# ==========================================================================


def test_result_traces_to_the_finding_id() -> None:
    """Claim: every result names the finding that caused it."""
    finding = _finding("RSA", key_size=2048, finding_id="fnd_trace_me")
    result = assess(finding, _long_lived_context())
    assert result.finding_id == "fnd_trace_me"


def test_component_attribution_survives() -> None:
    """Claim: the owning application is preserved on the result."""
    finding = _finding("RSA", key_size=2048, component="legacy-auth")
    result = assess(finding, None, _full_policy())
    assert result.component == "legacy-auth"


def test_rationale_uses_only_available_information() -> None:
    """Claim: the rationale never states a fact absent from the inputs.

    With no key size and no location, neither may appear in the rationale.
    """
    finding = _finding(
        "RSA", key_size=None, location="", line=None, component="mobile-gateway"
    )
    result = assess(finding, None, _full_policy())
    joined = " ".join(result.rationale)
    assert "2048" not in joined
    assert "keys.py" not in joined
    assert "mobile-gateway" in joined


# ==========================================================================
# No forbidden content
# ==========================================================================


def test_no_recommendation_or_priority_fields() -> None:
    """Claim: Phase 8/9 concerns do not appear in a Phase 7 result."""
    result = assess(_finding("RSA", key_size=2048), _long_lived_context())
    payload = result.to_dict()
    assert "recommendation" not in payload
    assert "migration_priority" not in payload
    assert "recommended_target" not in payload


def test_no_wall_clock_or_random_value_in_output() -> None:
    """Claim: the result contains no timestamp or random identifier."""
    import json

    result = assess(_finding("RSA", key_size=2048), _long_lived_context())
    text = json.dumps(result.to_dict())
    assert "timestamp" not in text
    assert "assessed_at" not in text


def test_no_secret_material_in_rationale() -> None:
    """Claim: no key material or secret reaches the rationale.

    The rationale is built from path, line, algorithm, and knowledge-base
    notes — never from raw evidence that could carry sensitive content.
    """
    finding = _finding(
        "RSA",
        key_size=2048,
        evidence="-----BEGIN PRIVATE KEY----- MIIEvAIBADANBg...",
    )
    result = assess(finding, _long_lived_context())
    joined = " ".join(result.rationale)
    assert "PRIVATE KEY" not in joined
    assert "MIIEvAIBADANBg" not in joined


# ==========================================================================
# Determinism
# ==========================================================================


def test_assessment_is_deterministic() -> None:
    """Claim: identical inputs yield identical results."""
    finding = _finding("RSA", key_size=2048)
    context = _long_lived_context()
    policy = _full_policy()
    first = qr.assess_finding(finding, context, policy).to_dict()
    second = qr.assess_finding(finding, context, policy).to_dict()
    assert first == second


def test_batch_ordering_is_independent_of_input_order() -> None:
    """Claim: results are sorted by finding id, whatever the input order."""
    findings = [
        _finding("RSA", finding_id="fnd_c", key_size=2048),
        _finding("AES", finding_id="fnd_a", key_size=256, role="symmetric"),
        _finding("ML-KEM-768", finding_id="fnd_b"),
    ]
    forward = [r.finding_id for r in qr.assess_inventory(findings)]
    backward = [r.finding_id for r in qr.assess_inventory(list(reversed(findings)))]
    assert forward == backward == ["fnd_a", "fnd_b", "fnd_c"]


# ==========================================================================
# Robustness
# ==========================================================================


def test_sparse_finding_does_not_crash() -> None:
    """Claim: a finding missing optional fields is assessed without error."""
    finding = CryptoFinding(
        finding_id="fnd_sparse",
        scan_id="s",
        artefact_type=ArtefactType.UNKNOWN,
        source_type=SourceType.SOURCE_CODE,
        detection_method=DetectionMethod.PATTERN_MATCH,
        confidence=Confidence.LOW,
    )
    result = assess(finding)
    assert result.quantum_category is QuantumCategory.UNKNOWN


def test_clean_inventory_produces_no_risk_findings() -> None:
    """Claim: an empty inventory yields no results."""
    assert qr.assess_inventory([]) == []


def test_multiple_applications_are_assessed_independently() -> None:
    """Claim: each application is assessed on its own context."""
    findings = [
        _finding("RSA", finding_id="fnd_pay", key_size=2048, component="payments-api"),
        _finding("ML-KEM-768", finding_id="fnd_pilot", component="pqc-pilot"),
    ]
    contexts = {
        "payments-api": _long_lived_context(),
        "pqc-pilot": ApplicationContext(
            component="pqc-pilot",
            data_lifetime_years=5,
            context_source=ContextSource.POLICY_FILE,
        ),
    }
    results = {r.component: r for r in qr.assess_inventory(findings, contexts, _full_policy())}
    assert results["payments-api"].quantum_category is QuantumCategory.QUANTUM_VULNERABLE
    assert results["pqc-pilot"].quantum_category is QuantumCategory.POST_QUANTUM


# ==========================================================================
# Safety
# ==========================================================================


def test_engine_performs_no_execution_or_io() -> None:
    """Claim: the engine is pure analysis.

    AST-checked: no subprocess, network, or package manager; no file scanning
    beyond the knowledge base loaded at import.
    """
    tree = ast.parse(Path(qr.__file__).read_text(encoding="utf-8"))
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


def test_engine_does_not_mutate_findings() -> None:
    """Claim: assessment leaves the source finding unchanged."""
    finding = _finding("RSA", key_size=2048)
    before = finding.to_dict()
    assess(finding, _long_lived_context())
    assert finding.to_dict() == before


# ==========================================================================
# Integration — full demo estate
# ==========================================================================


@pytest.fixture(scope="module")
def estate(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The full demo estate with a quantum_risk policy block."""
    root = tmp_path_factory.mktemp("phase7_estate")
    demo_enterprise.generate(root, force=True)
    demo_manifests.write_application_manifests(root)
    demo_source.write_application_source(root)
    demo_binaries.write_application_binaries(root)

    # Append a quantum_risk block to the policy the manifests wrote.
    policy_path = root / "aegis_policy.yaml"
    policy_path.write_text(
        policy_path.read_text(encoding="utf-8")
        + "\nquantum_risk:\n"
        "  crqc_horizon_years: 10\n"
        "  default_migration_years: 3\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture(scope="module")
def estate_results(estate: Path):
    """Risk results over the full estate inventory."""
    raw = inventory._parse_policy_file(estate / "aegis_policy.yaml")
    resolver = ComponentResolver(extract_declared_paths(raw))
    policy = qr.load_risk_policy(estate)

    findings = []
    findings += certificates.CERTIFICATE_ADAPTER.scan(estate, "s").findings
    findings += dependencies.DEPENDENCY_ADAPTER.scan(estate, "s", resolver=resolver).findings
    findings += source.SOURCE_ADAPTER.scan(estate, "s", resolver=resolver).findings
    if binary.LIEF_AVAILABLE:
        findings += binary.BINARY_ADAPTER.scan(estate, "s", resolver=resolver).findings

    contexts = {}
    for component in {f.component for f in findings if f.component}:
        contexts[component] = inventory.resolve_context(
            component, inventory.load_policy(estate)
        )

    return qr.assess_inventory(findings, contexts, policy)


def test_estate_policy_loads_with_provenance(estate: Path) -> None:
    """Claim: the CRQC assumption is loaded from the policy file."""
    policy = qr.load_risk_policy(estate)
    assert policy.crqc_horizon_years == 10
    assert policy.default_migration_years == 3
    assert policy.source == ContextSource.POLICY_FILE.value


def test_estate_produces_explainable_results(estate_results) -> None:
    """Claim: every result over the estate has a rationale and traces back."""
    assert estate_results
    for result in estate_results:
        assert result.finding_id
        assert result.rationale
        assert result.quantum_category in set(QuantumCategory)


def test_estate_covers_multiple_categories(estate_results) -> None:
    """Claim: the estate exercises vulnerable, symmetric, PQC, and capability."""
    categories = {r.quantum_category for r in estate_results}
    assert QuantumCategory.QUANTUM_VULNERABLE in categories
    assert QuantumCategory.SYMMETRIC_REDUCED in categories
    assert QuantumCategory.POST_QUANTUM in categories
    assert QuantumCategory.CAPABILITY_ONLY in categories


def test_pqc_pilot_has_both_vulnerable_and_pqc(estate_results) -> None:
    """Claim: the hybrid pilot shows its classical and PQC legs distinctly.

    pqc-pilot uses X25519 (vulnerable) and ML-KEM-768 (post-quantum). Both must
    appear, classified differently — the hybrid distinction preserved.
    """
    pilot = [r for r in estate_results if r.component == "pqc-pilot"]
    categories = {r.quantum_category for r in pilot}
    assert QuantumCategory.QUANTUM_VULNERABLE in categories
    assert QuantumCategory.POST_QUANTUM in categories


def test_content_portal_has_no_results(estate_results) -> None:
    """Claim: the clean application contributes no risk results.

    It had no findings, so it has no risk — proof the engine reflects the real
    inventory.
    """
    assert not any(r.component == "content-portal" for r in estate_results)


def test_summary_counts_match(estate_results) -> None:
    """Claim: the summary aggregates without ranking applications."""
    summary = qr.risk_summary(estate_results)
    assert summary["total"] == len(estate_results)
    assert sum(summary["by_quantum_category"].values()) == len(estate_results)
    assert sum(summary["by_risk_level"].values()) == len(estate_results)
    # No "worst application" or ranking key.
    assert "ranking" not in summary
    assert "worst" not in summary
