"""
Aegis PQC — ECDAT Phase 9 tests: migration prioritisation and roadmap.

Phase 9 applies organisational context to the technical conclusions of Phases 7
and 8. These tests hold it to being explainable and honest: priority is not risk
restated, a top-bucket item requires declared business criticality, evidence
gaps are surfaced rather than inflated, and no risk or Mosca math is recomputed.

Run Phase 9 only:  pytest tests/ecdat/test_phase9.py -q
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
    migration_priority as mp,
    quantum_risk as qr,
    recommendations as rec,
)
from backend.discovery import binary, certificates, dependencies, source
from backend.discovery.attribution import ComponentResolver, extract_declared_paths
from backend.model import (
    ApplicationContext,
    ArtefactType,
    BusinessCriticality,
    Confidence,
    ContextSource,
    CryptoFinding,
    DetectionMethod,
    MigrationPriority,
    RemediationClass,
    RoadmapBucket,
    SourceType,
)


# --------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------


def _finding(algorithm: str, **overrides) -> CryptoFinding:
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
        component="app",
        location="keys.py",
        line=12,
        detection_method=DetectionMethod.AST_PARSE,
        evidence=f"keys.py:12 -> {algorithm}",
        confidence=Confidence.HIGH,
        raw_detail=raw_detail,
    )
    base.update(overrides)
    return CryptoFinding(**base)


def _context(criticality: BusinessCriticality | None, lifetime: int = 25) -> ApplicationContext | None:
    """A declared context with the given criticality, or None (undeclared)."""
    if criticality is None:
        return None
    return ApplicationContext(
        component="app",
        data_lifetime_years=lifetime,
        business_criticality=criticality,
        context_source=ContextSource.POLICY_FILE,
    )


_POLICY = qr.RiskPolicy(
    crqc_horizon_years=10,
    default_migration_years=3,
    source=ContextSource.POLICY_FILE.value,
)


def _prioritise(finding: CryptoFinding, context: ApplicationContext | None):
    """Full risk → recommendation → priority path for one finding."""
    risk = qr.assess_finding(finding, context, _POLICY)
    recommendation = rec.recommend(finding, risk)
    return mp.prioritize(recommendation, context)


# ==========================================================================
# The decision tree — priority is context applied to risk
# ==========================================================================


def test_critical_vulnerable_within_window_is_immediate() -> None:
    """Claim: quantum-vulnerable + within window + business-critical = IMMEDIATE."""
    result = _prioritise(
        _finding("RSA", role="key_establishment", key_size=2048),
        _context(BusinessCriticality.CRITICAL),
    )
    assert result.priority is MigrationPriority.IMMEDIATE
    assert result.mosca_status == "within_quantum_window"


def test_high_criticality_within_window_is_high_not_immediate() -> None:
    """Claim: within-window on a non-critical system is HIGH, not IMMEDIATE.

    The top bucket is reserved for business-critical systems — priority is not
    risk alone.
    """
    result = _prioritise(
        _finding("RSA", role="key_establishment", key_size=2048),
        _context(BusinessCriticality.HIGH),
    )
    assert result.priority is MigrationPriority.HIGH


def test_within_window_unknown_criticality_is_not_immediate() -> None:
    """Claim: unknown business criticality never reaches IMMEDIATE.

    Missing criticality is stated, not guessed, and cannot produce the top
    bucket.
    """
    # Declared context with a long lifetime but... criticality is declared here,
    # so to get "unknown" we supply context with criticality but test the
    # separate no-context path in a dedicated test. Here we assert the
    # medium-criticality case is not immediate.
    result = _prioritise(
        _finding("RSA", role="key_establishment", key_size=2048),
        _context(BusinessCriticality.MEDIUM),
    )
    assert result.priority is not MigrationPriority.IMMEDIATE


def test_outside_window_is_planned() -> None:
    """Claim: quantum-vulnerable but outside the window is PLANNED, not urgent."""
    result = _prioritise(
        _finding("RSA", role="key_establishment", key_size=2048),
        _context(BusinessCriticality.CRITICAL, lifetime=2),  # short-lived
    )
    assert result.priority is MigrationPriority.PLANNED
    assert result.mosca_status == "outside_quantum_window"


def test_rsa_signature_migration_is_prioritised_not_ignored() -> None:
    """Claim: a PQC-native signature migration is real work, not NO_ACTION.

    PQC_NATIVE means "migrate to a PQC algorithm" (e.g. RSA signature -> ML-DSA),
    which must be prioritised — not confused with an already-PQC finding.
    """
    result = _prioritise(
        _finding("RSA", role="signature", key_size=2048),
        _context(BusinessCriticality.CRITICAL),
    )
    assert result.priority is MigrationPriority.IMMEDIATE
    assert result.remediation_class == RemediationClass.PQC_NATIVE.value


def test_insufficient_mosca_is_evidence_required() -> None:
    """Claim: a vulnerable algorithm with unresolved timing needs evidence.

    Not inflated to top priority merely because timing is missing.
    """
    # No context => Phase 7 has no lifetime => Mosca insufficient_information.
    result = _prioritise(
        _finding("RSA", role="key_establishment", key_size=2048), None
    )
    assert result.priority is MigrationPriority.EVIDENCE_REQUIRED
    assert result.mosca_status == "insufficient_information"


def test_non_time_sensitive_symmetric_is_not_migration() -> None:
    """Claim: AES-256 (none-required) creates no migration task."""
    result = _prioritise(
        _finding("AES", role="symmetric", key_size=256),
        _context(BusinessCriticality.CRITICAL),
    )
    assert result.priority is MigrationPriority.NO_ACTION


# ==========================================================================
# Business criticality handling
# ==========================================================================


def test_missing_criticality_is_unknown_not_guessed() -> None:
    """Claim: absent context yields unknown criticality, stated as such."""
    result = _prioritise(_finding("MD5", role="hash"), None)
    assert result.business_criticality == mp.CRITICALITY_UNKNOWN
    assert any("not declared" in a.lower() for a in result.assumptions)


def test_criticality_is_not_inferred_from_component_name() -> None:
    """Claim: a 'payments' component is not assumed critical.

    Criticality comes only from declared context, never the name.
    """
    finding = _finding("MD5", role="hash", component="payments-api")
    result = _prioritise(finding, None)  # no declared context
    assert result.business_criticality == mp.CRITICALITY_UNKNOWN


def test_declared_criticality_is_used() -> None:
    """Claim: a declared criticality is reflected in the result."""
    result = _prioritise(
        _finding("RSA", role="key_establishment", key_size=2048),
        _context(BusinessCriticality.CRITICAL),
    )
    assert result.business_criticality == "critical"


# ==========================================================================
# Classical issues — real work, kept distinct from PQC migration
# ==========================================================================


def test_classical_issue_on_critical_system_is_high() -> None:
    """Claim: MD5 on a critical system is HIGH classical remediation."""
    result = _prioritise(
        _finding("MD5", role="hash"), _context(BusinessCriticality.CRITICAL)
    )
    assert result.priority is MigrationPriority.HIGH
    assert result.reason_class == mp.REASON_CLASSICAL


def test_classical_issue_on_low_system_is_planned() -> None:
    """Claim: MD5 on a low-criticality system is PLANNED classical work."""
    result = _prioritise(
        _finding("DES", role="symmetric"), _context(BusinessCriticality.LOW)
    )
    assert result.priority is MigrationPriority.PLANNED
    assert result.reason_class == mp.REASON_CLASSICAL


def test_classical_issue_reason_is_not_pqc_migration() -> None:
    """Claim: a classical issue is never labelled a PQC migration."""
    result = _prioritise(
        _finding("SHA-1", role="hash"), _context(BusinessCriticality.HIGH)
    )
    assert result.reason_class == mp.REASON_CLASSICAL
    assert "not a post-quantum migration" in " ".join(result.rationale).lower()


# ==========================================================================
# Strengthening, PQC-native, hybrid, capability, unknown
# ==========================================================================


def test_aes_128_strengthening_is_planned_on_critical() -> None:
    """Claim: AES-128 strengthening on a critical system is PLANNED."""
    result = _prioritise(
        _finding("AES", role="symmetric", key_size=128),
        _context(BusinessCriticality.CRITICAL),
    )
    assert result.priority is MigrationPriority.PLANNED
    assert result.reason_class == mp.REASON_STRENGTHENING


def test_aes_128_strengthening_is_monitor_on_unknown() -> None:
    """Claim: AES-128 strengthening with unknown criticality is MONITOR."""
    result = _prioritise(_finding("AES", role="symmetric", key_size=128), None)
    assert result.priority is MigrationPriority.MONITOR


def test_pqc_native_already_pqc_is_no_action() -> None:
    """Claim: an already-PQC ML-KEM finding creates no migration task."""
    result = _prioritise(
        _finding("ML-KEM-768", role="key_establishment"),
        _context(BusinessCriticality.CRITICAL),
    )
    assert result.priority is MigrationPriority.NO_ACTION
    assert result.reason_class == mp.REASON_NO_MIGRATION


def test_hybrid_recommendation_is_prioritised_as_migration() -> None:
    """Claim: a hybrid recommendation is a migration direction, prioritised."""
    result = _prioritise(
        _finding("ECDH", role="key_establishment"),
        _context(BusinessCriticality.CRITICAL),
    )
    assert result.priority is MigrationPriority.IMMEDIATE
    assert result.reason_class == mp.REASON_PQC_MIGRATION
    # A recommendation toward hybrid is not a claim that a hybrid is deployed.
    assert "deployed" not in " ".join(result.rationale).lower()


def test_capability_only_is_evidence_required_not_migration() -> None:
    """Claim: a library capability is an evidence task, not an application migration."""
    finding = CryptoFinding(
        finding_id="fnd_lib",
        scan_id="s",
        artefact_type=ArtefactType.LIBRARY,
        algorithm="",
        library="pyca/cryptography",
        source_type=SourceType.DEPENDENCY,
        component="app",
        detection_method=DetectionMethod.MANIFEST_PARSE,
        evidence="requirements.txt:3",
        confidence=Confidence.HIGH,
        raw_detail={"provides_algorithms": ["RSA"]},
    )
    result = _prioritise(finding, _context(BusinessCriticality.CRITICAL))
    assert result.priority is MigrationPriority.EVIDENCE_REQUIRED
    assert result.reason_class == mp.REASON_USAGE_UNVERIFIED


def test_unknown_algorithm_is_evidence_required() -> None:
    """Claim: an unknown algorithm needs evidence, not a guessed priority."""
    result = _prioritise(
        _finding("Serpent", role="symmetric"), _context(BusinessCriticality.CRITICAL)
    )
    assert result.priority is MigrationPriority.EVIDENCE_REQUIRED
    assert result.reason_class == mp.REASON_EVIDENCE_GAP


def test_evidence_required_names_what_is_missing() -> None:
    """Claim: an evidence-gap result states exactly what is missing.

    It must not imply the asset is the highest-risk item.
    """
    result = _prioritise(_finding("Serpent", role="symmetric"), _context(BusinessCriticality.CRITICAL))
    assert result.assumptions
    joined = " ".join(result.rationale).lower()
    assert "not a claim that the asset is the highest-risk" in joined


# ==========================================================================
# Traceability and preservation
# ==========================================================================


def test_result_traces_through_recommendation_to_finding() -> None:
    """Claim: the priority traces to recommendation and finding ids."""
    finding = _finding("RSA", role="key_establishment", key_size=2048, finding_id="fnd_trace")
    result = _prioritise(finding, _context(BusinessCriticality.CRITICAL))
    assert result.finding_id == "fnd_trace"
    assert result.recommendation_id.startswith("rec_")
    assert "finding:fnd_trace" in result.provenance
    assert "recommendation:" in result.provenance


@pytest.mark.parametrize("confidence", [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH])
def test_confidence_is_preserved(confidence: Confidence) -> None:
    """Claim: the finding's confidence survives to the priority result."""
    result = _prioritise(
        _finding("RSA", role="key_establishment", key_size=2048, confidence=confidence),
        _context(BusinessCriticality.CRITICAL),
    )
    assert result.confidence is confidence


def test_evidence_level_is_preserved() -> None:
    """Claim: the evidence level survives to the priority result."""
    result = _prioritise(
        _finding("RSA", role="key_establishment", key_size=2048),
        _context(BusinessCriticality.CRITICAL),
    )
    assert result.evidence_level == "call_site"


def test_phase7_conclusions_are_carried_not_recomputed() -> None:
    """Claim: risk level and Mosca status are carried from Phase 7 verbatim."""
    finding = _finding("RSA", role="key_establishment", key_size=2048)
    context = _context(BusinessCriticality.CRITICAL)
    risk = qr.assess_finding(finding, context, _POLICY)
    recommendation = rec.recommend(finding, risk)
    result = mp.prioritize(recommendation, context)
    assert result.risk_level == risk.risk_level.value
    assert result.mosca_status == risk.mosca_status.value


def test_engine_does_not_recompute_mosca() -> None:
    """Claim: no Mosca math exists in the prioritisation engine."""
    source_text = Path(mp.__file__).read_text(encoding="utf-8")
    assert "run_mosca" not in source_text
    assert "x_data_lifetime" not in source_text
    assert "crqc_horizon_years" not in source_text


# ==========================================================================
# Determinism
# ==========================================================================


def test_prioritisation_is_deterministic() -> None:
    """Claim: identical inputs yield identical priority results."""
    finding = _finding("RSA", role="key_establishment", key_size=2048)
    context = _context(BusinessCriticality.CRITICAL)
    risk = qr.assess_finding(finding, context, _POLICY)
    recommendation = rec.recommend(finding, risk)
    first = mp.prioritize(recommendation, context).to_dict()
    second = mp.prioritize(recommendation, context).to_dict()
    assert first == second


def test_batch_ordering_is_independent_of_input_order() -> None:
    """Claim: batch output is sorted by (priority, finding id), order-independent."""
    findings = [
        _finding("ML-KEM-768", role="key_establishment", finding_id="fnd_z"),  # no_action
        _finding("RSA", role="key_establishment", key_size=2048, finding_id="fnd_a"),  # immediate
        _finding("MD5", role="hash", finding_id="fnd_m"),  # high
    ]
    contexts = {"app": _context(BusinessCriticality.CRITICAL)}
    risks = qr.assess_inventory(findings, contexts, _POLICY)
    recs = rec.recommend_batch(findings, risks)

    forward = [r.finding_id for r in mp.prioritize_batch(recs, contexts)]
    backward = [r.finding_id for r in mp.prioritize_batch(list(reversed(recs)), contexts)]
    assert forward == backward
    # IMMEDIATE (fnd_a) before HIGH (fnd_m) before NO_ACTION (fnd_z).
    assert forward == ["fnd_a", "fnd_m", "fnd_z"]


def test_no_timestamp_or_random_in_output() -> None:
    """Claim: no timestamp or random value appears in output."""
    import json

    result = _prioritise(
        _finding("RSA", role="key_establishment", key_size=2048),
        _context(BusinessCriticality.CRITICAL),
    )
    text = json.dumps(result.to_dict())
    assert "timestamp" not in text
    assert "assessed_at" not in text


def test_same_finding_gives_one_consistent_record() -> None:
    """Claim: a finding cannot produce contradictory priority records."""
    finding = _finding("RSA", role="key_establishment", key_size=2048)
    context = _context(BusinessCriticality.CRITICAL)
    risk = qr.assess_finding(finding, context, _POLICY)
    recommendation = rec.recommend(finding, risk)
    results = [mp.prioritize(recommendation, context).priority for _ in range(5)]
    assert len(set(results)) == 1


# ==========================================================================
# Roadmap
# ==========================================================================


def test_roadmap_groups_by_priority() -> None:
    """Claim: roadmap buckets are a deterministic consequence of priority."""
    findings = [
        _finding("RSA", role="key_establishment", key_size=2048, finding_id="fnd_imm"),
        _finding("MD5", role="hash", finding_id="fnd_cls"),
        _finding("AES", role="symmetric", key_size=128, finding_id="fnd_str"),
        _finding("ML-KEM-768", role="key_establishment", finding_id="fnd_pqc"),
    ]
    contexts = {"app": _context(BusinessCriticality.CRITICAL)}
    risks = qr.assess_inventory(findings, contexts, _POLICY)
    recs = rec.recommend_batch(findings, risks)
    prios = mp.prioritize_batch(recs, contexts)
    roadmap = mp.build_roadmap(prios, recs)

    assert RoadmapBucket.IMMEDIATE_ATTENTION.value in roadmap
    assert "fnd_imm" in [i["finding_id"] for i in roadmap[RoadmapBucket.IMMEDIATE_ATTENTION.value]]


def test_no_action_items_are_excluded_from_roadmap() -> None:
    """Claim: NO_ACTION findings are not roadmap work."""
    findings = [_finding("ML-KEM-768", role="key_establishment", finding_id="fnd_pqc")]
    contexts = {"app": _context(BusinessCriticality.CRITICAL)}
    risks = qr.assess_inventory(findings, contexts, _POLICY)
    recs = rec.recommend_batch(findings, risks)
    prios = mp.prioritize_batch(recs, contexts)
    roadmap = mp.build_roadmap(prios, recs)
    all_items = [i["finding_id"] for items in roadmap.values() for i in items]
    assert "fnd_pqc" not in all_items


def test_roadmap_items_within_bucket_are_ordered() -> None:
    """Claim: items within a bucket are deterministically ordered."""
    findings = [
        _finding("RSA", role="key_establishment", key_size=2048, finding_id="fnd_c"),
        _finding("ECDH", role="key_establishment", finding_id="fnd_a"),
    ]
    contexts = {"app": _context(BusinessCriticality.CRITICAL)}
    risks = qr.assess_inventory(findings, contexts, _POLICY)
    recs = rec.recommend_batch(findings, risks)
    prios = mp.prioritize_batch(recs, contexts)
    roadmap = mp.build_roadmap(prios, recs)
    imm = [i["finding_id"] for i in roadmap[RoadmapBucket.IMMEDIATE_ATTENTION.value]]
    assert imm == sorted(imm)


def test_roadmap_has_no_calendar_dates() -> None:
    """Claim: the roadmap invents no dates or deadlines."""
    import json

    findings = [_finding("RSA", role="key_establishment", key_size=2048)]
    contexts = {"app": _context(BusinessCriticality.CRITICAL)}
    risks = qr.assess_inventory(findings, contexts, _POLICY)
    recs = rec.recommend_batch(findings, risks)
    prios = mp.prioritize_batch(recs, contexts)
    text = json.dumps(mp.build_roadmap(prios, recs))
    for token in ("2025", "2026", "2027", "deadline", "due", "q1", "q2"):
        assert token not in text.lower()


# ==========================================================================
# Summary
# ==========================================================================


def test_summary_counts_without_ranking() -> None:
    """Claim: the summary counts by priority but never ranks or names worst."""
    findings = [
        _finding("RSA", role="key_establishment", key_size=2048),
        _finding("MD5", role="hash"),
    ]
    contexts = {"app": _context(BusinessCriticality.CRITICAL)}
    risks = qr.assess_inventory(findings, contexts, _POLICY)
    recs = rec.recommend_batch(findings, risks)
    summary = mp.summarize(mp.prioritize_batch(recs, contexts))
    assert summary["total"] == 2
    assert "worst" not in summary
    assert "ranking" not in summary
    assert set(summary["by_priority"]) <= {p.value for p in MigrationPriority}


# ==========================================================================
# Safety
# ==========================================================================


def test_engine_performs_no_execution_or_io() -> None:
    """Claim: the engine is pure computation."""
    tree = ast.parse(Path(mp.__file__).read_text(encoding="utf-8"))
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
    """Claim: no key material reaches a priority result."""
    import json

    finding = _finding(
        "RSA",
        role="key_establishment",
        key_size=2048,
        evidence="-----BEGIN PRIVATE KEY----- MIIEvAIBA...",
    )
    result = _prioritise(finding, _context(BusinessCriticality.CRITICAL))
    text = json.dumps(result.to_dict())
    assert "PRIVATE KEY" not in text
    assert "MIIEvAIBA" not in text


def test_no_streamlit_or_gui_dependency() -> None:
    """Claim: no Phase 10 GUI dependency leaked into Phase 9."""
    source_text = Path(mp.__file__).read_text(encoding="utf-8")
    assert "streamlit" not in source_text.lower()
    assert "plotly" not in source_text.lower()


def test_empty_inventory_yields_nothing() -> None:
    """Claim: nothing in, nothing out."""
    assert mp.prioritize_batch([], {}) == []
    assert mp.build_roadmap([]) == {}


# ==========================================================================
# Integration — full demo estate
# ==========================================================================


@pytest.fixture(scope="module")
def estate(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("phase9_estate")
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
def estate_priorities(estate: Path):
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
    recs = rec.recommend_batch(findings, risks)
    prios = mp.prioritize_batch(recs, contexts)
    return findings, recs, prios, contexts


def test_estate_priorities_are_explainable(estate_priorities) -> None:
    """Claim: every estate priority has a rationale and traces back."""
    _, _, prios, _ = estate_priorities
    assert prios
    for result in prios:
        assert result.finding_id
        assert result.recommendation_id
        assert result.rationale
        assert result.priority_factors
        assert result.priority in set(MigrationPriority)


def test_content_portal_has_no_priorities(estate_priorities) -> None:
    """Claim: the clean application produces no prioritised work."""
    _, _, prios, _ = estate_priorities
    assert not any(r.component == "content-portal" for r in prios)


def test_pqc_pilot_mlkem_creates_no_migration_task(estate_priorities) -> None:
    """Claim: pqc-pilot's ML-KEM is NO_ACTION, not fake PQC migration work."""
    _, _, prios, _ = estate_priorities
    pilot_pqc = [
        r
        for r in prios
        if r.component == "pqc-pilot" and r.quantum_category == "post_quantum"
    ]
    assert pilot_pqc
    assert all(r.priority is MigrationPriority.NO_ACTION for r in pilot_pqc)


def test_capability_findings_stay_evidence_required(estate_priorities) -> None:
    """Claim: capability-only findings are evidence tasks, not migrations."""
    _, _, prios, _ = estate_priorities
    capability = [r for r in prios if r.reason_class == mp.REASON_USAGE_UNVERIFIED]
    assert capability
    assert all(r.priority is MigrationPriority.EVIDENCE_REQUIRED for r in capability)


def test_legacy_auth_has_classical_remediation(estate_priorities) -> None:
    """Claim: legacy-auth's classical weaknesses appear as classical remediation."""
    _, _, prios, _ = estate_priorities
    legacy_classical = [
        r
        for r in prios
        if r.component == "legacy-auth" and r.reason_class == mp.REASON_CLASSICAL
    ]
    assert legacy_classical


def test_estate_roadmap_is_grouped(estate_priorities) -> None:
    """Claim: the estate yields an explainable, grouped roadmap."""
    _, recs, prios, _ = estate_priorities
    roadmap = mp.build_roadmap(prios, recs)
    assert roadmap
    # Every bucket key is a defined roadmap bucket.
    assert set(roadmap) <= {b.value for b in RoadmapBucket}
    # No NO_ACTION item leaked in.
    no_action_ids = {r.finding_id for r in prios if r.priority is MigrationPriority.NO_ACTION}
    roadmap_ids = {i["finding_id"] for items in roadmap.values() for i in items}
    assert no_action_ids.isdisjoint(roadmap_ids)


def test_estate_summary_counts_match(estate_priorities) -> None:
    """Claim: the summary aggregates without ranking."""
    _, _, prios, _ = estate_priorities
    summary = mp.summarize(prios)
    assert summary["total"] == len(prios)
    assert sum(summary["by_priority"].values()) == len(prios)


def test_estate_prioritisation_is_deterministic(estate: Path) -> None:
    """Claim: regenerating over the estate gives identical output."""
    raw = inventory._parse_policy_file(estate / "aegis_policy.yaml")
    resolver = ComponentResolver(extract_declared_paths(raw))
    policy = qr.load_risk_policy(estate)

    def run():
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
        recs = rec.recommend_batch(findings, risks)
        return mp.prioritize_batch(recs, contexts)

    first = [r.to_dict() for r in run()]
    second = [r.to_dict() for r in run()]
    assert first == second
