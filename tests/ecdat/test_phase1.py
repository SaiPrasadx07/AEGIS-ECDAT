"""
Aegis PQC — ECDAT Phase 1 tests: data model, discovery, inventory.

Kept separate from the inherited suite in ``tests/`` so that ECDAT coverage can
be reported honestly. Roughly 140 of the 259 inherited tests cover the Security
Lab (HNDL and Q-Day), which is frozen and not part of the ECDAT product — a
single combined number would overstate what is tested here.

Run ECDAT only:   pytest tests/ecdat -q
Run everything:   pytest tests -q
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend import demo_enterprise as de
from backend import discovery, inventory, model, scanner
from backend.discovery import ScanLimits, certificates, is_within, safe_walk
from backend.model import (
    ApplicationContext,
    ArtefactType,
    BusinessCriticality,
    Confidence,
    ContextSource,
    CryptoAsset,
    CryptoFinding,
    DetectionMethod,
    MoscaResult,
    MoscaVerdict,
    QuantumStatus,
    RiskLevel,
    ScanStatus,
    Sensitivity,
    SourceType,
)


@pytest.fixture(scope="module")
def estate(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A generated demo estate, shared across the module."""
    root = tmp_path_factory.mktemp("ecdat_estate")
    de.generate(root, force=True)
    return root


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    """An isolated database with the ECDAT schema applied."""
    path = tmp_path / "ecdat.db"
    inventory.init_ecdat_schema(path)
    return path


@pytest.fixture(scope="module")
def scan_result(estate: Path):
    """One real scan of the demo estate."""
    return certificates.CERTIFICATE_ADAPTER.scan(estate, "scan_fixture")


# ==========================================================================
# Layer separation — the reason the model exists
# ==========================================================================


def test_asset_keeps_the_three_layers_separate() -> None:
    """Claim: a serialised asset never flattens facts, context, and conclusions.

    Flattening would reintroduce the exact ambiguity this model removes: the
    inability to answer "which of this did you observe, and which did you
    assume?"
    """
    finding = CryptoFinding(finding_id="fnd_x", scan_id="s", algorithm="RSA")
    asset = CryptoAsset(finding=finding, context=ApplicationContext.default_for("app"))

    payload = asset.to_dict()
    assert set(payload) == {"finding_id", "component", "observed", "context", "assessment"}
    assert "data_lifetime_years" not in payload["observed"]
    assert "algorithm" not in payload["context"]


def test_discovery_never_emits_an_assessment(scan_result) -> None:
    """Claim: discovery reports facts and stops.

    Risk belongs to the assessment engine. If a scanner could set a risk level,
    two components could disagree about the same asset.
    """
    assets = inventory.build_assets(scan_result.findings)
    assert assets
    assert all(asset.assessment is None for asset in assets)


def test_observed_layer_carries_no_business_context(scan_result) -> None:
    """Claim: a finding contains nothing an organisation had to declare."""
    for finding in scan_result.findings:
        payload = finding.to_dict()
        for forbidden in ("data_lifetime_years", "business_criticality", "data_sensitivity", "risk"):
            assert forbidden not in payload


# ==========================================================================
# Vocabulary — deliberate naming decisions
# ==========================================================================


def test_no_risk_level_is_called_safe() -> None:
    """Claim: the product never labels cryptography "SAFE".

    Post-quantum algorithms are designed to resist currently known attacks.
    "Safe" asserts a guarantee nobody can make, so the vocabulary offers
    PQC READY and LOW BASELINE instead.
    """
    values = {level.value for level in RiskLevel}
    assert "SAFE" not in values
    assert RiskLevel.PQC_READY.value == "PQC READY"
    assert RiskLevel.LOW_BASELINE.value == "LOW BASELINE"


def test_remediation_classes_distinguish_quantum_from_classical() -> None:
    """Claim: not every recommendation is a post-quantum migration.

    AES-128 to AES-256 answers Grover, not Shor. MD5 is a break with no quantum
    dimension at all. Collapsing these into one bucket would misstate the threat
    model.
    """
    classes = {c.value for c in model.RemediationClass}
    assert {"pqc_native", "hybrid", "classical_strengthening", "non_quantum_issue"} <= classes


def test_unknown_outranks_settled_low_levels() -> None:
    """Claim: an unidentifiable asset is prioritised above a benign one.

    An asset nobody can classify is exactly the one a migration programme must
    not lose track of.
    """
    assert model.RISK_RANK[RiskLevel.UNKNOWN] < model.RISK_RANK[RiskLevel.LOW_BASELINE]
    assert model.RISK_RANK[RiskLevel.UNKNOWN] < model.RISK_RANK[RiskLevel.PQC_READY]
    assert model.RISK_RANK[RiskLevel.CRITICAL] == 0


def test_legacy_vocabulary_round_trips() -> None:
    """Claim: the frozen Security Lab and ECDAT can still exchange ratings."""
    for level in RiskLevel:
        legacy = model.LEGACY_RISK[level]
        assert model.FROM_LEGACY_RISK[legacy] is level


# ==========================================================================
# Determinism
# ==========================================================================


def test_finding_ids_are_deterministic() -> None:
    """Claim: identical input yields an identical id.

    Required for scan-to-scan diffing; a random id would make every re-scan look
    like a complete replacement of the estate.
    """
    args = ("scan_1", "/srv/app/key.pem", "RSA", None, "1.2.840.113549.1.1.1")
    assert CryptoFinding.compute_id(*args) == CryptoFinding.compute_id(*args)


def test_finding_ids_separate_distinct_artefacts() -> None:
    """Claim: different location, algorithm, or evidence yields a different id."""
    base = ("scan_1", "/a.pem", "RSA", None, "oid")
    variations = [
        ("scan_1", "/b.pem", "RSA", None, "oid"),
        ("scan_1", "/a.pem", "ECDSA", None, "oid"),
        ("scan_1", "/a.pem", "RSA", 42, "oid"),
        ("scan_1", "/a.pem", "RSA", None, "different"),
    ]
    ids = {CryptoFinding.compute_id(*base)} | {
        CryptoFinding.compute_id(*v) for v in variations
    }
    assert len(ids) == len(variations) + 1


def test_repeat_scans_produce_identical_findings(estate: Path) -> None:
    """Claim: scanning an unchanged estate twice gives the same result."""
    first = certificates.CERTIFICATE_ADAPTER.scan(estate, "scan_repeat")
    second = certificates.CERTIFICATE_ADAPTER.scan(estate, "scan_repeat")
    assert [f.finding_id for f in first.findings] == [f.finding_id for f in second.findings]


# ==========================================================================
# Certificate adapter
# ==========================================================================


def test_adapter_finds_every_estate_asset(scan_result) -> None:
    """Claim: the refactor detects exactly what the proven scanner detected."""
    assert scan_result.status is ScanStatus.COMPLETED
    assert len(scan_result.findings) == len(de.ENTERPRISE_ASSETS)


def test_adapter_preserves_oid_identification(scan_result) -> None:
    """Claim: the OID audit trail survives the mapping.

    The OID is what lets a reviewer independently confirm a classification with
    ``openssl asn1parse``. Losing it in the refactor would remove the scanner's
    strongest evidence.
    """
    mlkem = [f for f in scan_result.findings if f.algorithm == "ML-KEM-768" and f.oid]
    assert mlkem
    assert mlkem[0].oid == "2.16.840.1.101.3.4.4.2"

    rsa = [f for f in scan_result.findings if f.algorithm == "RSA"]
    assert rsa
    assert all(f.oid == "1.2.840.113549.1.1.1" for f in rsa)


def test_adapter_preserves_declared_versus_parsed(scan_result) -> None:
    """Claim: a manifest claim is still distinguished from parsed key material.

    This distinction is load-bearing: an organisation's migration status is
    frequently wrong on paper.
    """
    declared = [f for f in scan_result.findings if f.detection_method is DetectionMethod.DECLARED]
    assert len(declared) == 1
    assert declared[0].confidence is Confidence.MEDIUM

    parsed = [f for f in scan_result.findings if f.detection_method is DetectionMethod.LIBRARY_PARSE]
    assert parsed


def test_adapter_records_key_sizes_and_variants(scan_result) -> None:
    """Claim: key sizes become integers; curves stay named."""
    by_variant = {f.variant: f for f in scan_result.findings if f.variant}

    assert "RSA-2048" in by_variant
    assert by_variant["RSA-2048"].key_size == 2048
    assert "RSA-3072" in by_variant
    assert by_variant["RSA-3072"].key_size == 3072

    # A curve name is the designation, not a bit length — it must not be coerced.
    curve = [f for f in scan_result.findings if "ECDSA" in f.algorithm]
    assert curve
    assert curve[0].variant == "SECP256R1"
    assert curve[0].key_size is None


def test_adapter_reports_unparseable_files_rather_than_dropping_them(scan_result) -> None:
    """Claim: a corrupt artefact is surfaced, not silently skipped.

    The estate ships a deliberately truncated file. An asset nobody can read is
    precisely the one a migration programme must not lose.
    """
    unknown = [f for f in scan_result.findings if f.artefact_type is ArtefactType.UNKNOWN]
    assert len(unknown) == 1
    assert unknown[0].confidence is Confidence.LOW


def test_adapter_attributes_findings_to_components(scan_result) -> None:
    """Claim: findings are attributed to owning applications."""
    components = {f.component for f in scan_result.findings}
    assert {"api-gateway", "payments", "legacy-auth", "archive"} <= components


def test_adapter_declares_what_it_cannot_do() -> None:
    """Claim: coverage honesty is structural, not documentation.

    ``coverage()`` is part of the adapter protocol, so a scanner that cannot
    state its limits cannot ship.
    """
    coverage = certificates.CERTIFICATE_ADAPTER.coverage()
    assert coverage.supported and coverage.not_supported
    joined = " ".join(coverage.not_supported).lower()
    assert "chain validation" in joined
    assert "pkcs#12" in joined
    assert coverage.confidence_notes


def test_every_registered_adapter_satisfies_the_protocol() -> None:
    """Claim: the registry only contains conforming adapters."""
    assert "certificates" in discovery.available_adapters()
    for name in discovery.available_adapters():
        adapter = discovery.get_adapter(name)
        assert isinstance(adapter, discovery.DiscoveryAdapter)
        assert adapter.coverage().not_supported, f"{name} declares no limits"


def test_missing_target_fails_cleanly(tmp_path: Path) -> None:
    """Claim: a bad path is a reported failure, not an exception."""
    result = certificates.CERTIFICATE_ADAPTER.scan(tmp_path / "nope", "scan_missing")
    assert result.status is ScanStatus.FAILED
    assert result.errors
    assert result.findings == []


def test_empty_directory_scans_cleanly(tmp_path: Path) -> None:
    """Claim: scanning nothing returns an empty result, not an error."""
    result = certificates.CERTIFICATE_ADAPTER.scan(tmp_path, "scan_empty")
    assert result.status is ScanStatus.COMPLETED
    assert result.findings == []


# ==========================================================================
# Scanner safety — Aegis is itself a security product
# ==========================================================================


def test_containment_check_rejects_traversal(tmp_path: Path) -> None:
    """Claim: paths escaping the scan root are refused."""
    root = tmp_path / "root"
    root.mkdir()
    assert is_within(root, root / "inside.pem")
    assert not is_within(root, tmp_path / "outside.pem")
    assert not is_within(root, root / ".." / "escape.pem")


def test_walk_refuses_symlinks(tmp_path: Path) -> None:
    """Claim: symlinks are never followed.

    A symlink to ``/`` would turn a bounded scan into a filesystem crawl.
    """
    root = tmp_path / "estate"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "real.pem").write_text("x")

    outside = tmp_path / "secret.pem"
    outside.write_text("sensitive")
    try:
        (root / "sub" / "link.pem").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")

    seen = [p.name for p, _ in safe_walk(root, ScanLimits(), suffixes=frozenset({".pem"}))]
    assert "real.pem" in seen
    assert "link.pem" not in seen


def test_walk_skips_oversized_files(tmp_path: Path) -> None:
    """Claim: a file above the size ceiling is skipped and counted."""
    root = tmp_path / "estate"
    root.mkdir()
    (root / "small.pem").write_text("x")
    (root / "huge.pem").write_text("y" * 5000)

    limits = ScanLimits(max_file_bytes=1000)
    stats = None
    names = []
    for path, walk_stats in safe_walk(root, limits, suffixes=frozenset({".pem"})):
        names.append(path.name)
        stats = walk_stats

    assert names == ["small.pem"]
    assert stats is not None and stats.skipped_too_large == 1
    assert "size limit" in " ".join(stats.notes())


def test_walk_respects_the_file_ceiling(tmp_path: Path) -> None:
    """Claim: the file-count limit stops a scan and records why."""
    root = tmp_path / "estate"
    root.mkdir()
    for index in range(10):
        (root / f"f{index}.pem").write_text("x")

    limits = ScanLimits(max_files=4)
    collected = list(safe_walk(root, limits, suffixes=frozenset({".pem"})))
    assert len(collected) == 4
    assert "file limit" in collected[-1][1].limit_reached


def test_walk_prunes_noise_directories(tmp_path: Path) -> None:
    """Claim: build and VCS directories are never descended into."""
    root = tmp_path / "estate"
    for noisy in (".git", "node_modules", "__pycache__"):
        (root / noisy).mkdir(parents=True)
        (root / noisy / "junk.pem").write_text("x")
    (root / "real.pem").write_text("x")

    names = [p.name for p, _ in safe_walk(root, ScanLimits(), suffixes=frozenset({".pem"}))]
    assert names == ["real.pem"]


def test_reading_a_hostile_file_returns_none(tmp_path: Path) -> None:
    """Claim: unreadable input yields ``None`` rather than raising."""
    from backend.discovery import read_bytes_safely

    assert read_bytes_safely(tmp_path / "absent.pem", ScanLimits()) is None

    big = tmp_path / "big.pem"
    big.write_text("z" * 4000)
    assert read_bytes_safely(big, ScanLimits(max_file_bytes=100)) is None


# ==========================================================================
# Context provenance — the product's weakest joint, made explicit
# ==========================================================================


def test_undeclared_context_falls_back_and_says_so(db: Path) -> None:
    """Claim: an undeclared component gets defaults, marked as undeclared."""
    context = inventory.resolve_context("unknown-app", db_path=db)
    assert context.context_source is ContextSource.DEFAULT
    assert context.is_declared is False
    assert context.data_lifetime_years == model.DEFAULT_DATA_LIFETIME_YEARS


def test_policy_file_supplies_declared_context(tmp_path: Path, db: Path) -> None:
    """Claim: an estate can declare context, and provenance records it."""
    root = tmp_path / "estate"
    root.mkdir()
    (root / inventory.POLICY_FILENAME).write_text(
        "payments:\n"
        "  data_sensitivity: critical\n"
        "  data_lifetime_years: 25\n"
        "  business_criticality: critical\n"
        "  notes: Card settlement records\n"
    )

    policy = inventory.load_policy(root)
    assert "payments" in policy

    context = inventory.resolve_context("payments", policy, db_path=db)
    assert context.context_source is ContextSource.POLICY_FILE
    assert context.is_declared is True
    assert context.data_lifetime_years == 25
    assert context.data_sensitivity is Sensitivity.CRITICAL
    assert context.business_criticality is BusinessCriticality.CRITICAL


def test_user_input_overrides_the_policy_file(tmp_path: Path, db: Path) -> None:
    """Claim: an operator's correction outranks a checked-in policy file."""
    root = tmp_path / "estate"
    root.mkdir()
    (root / inventory.POLICY_FILENAME).write_text(
        "payments:\n  data_lifetime_years: 25\n"
    )
    policy = inventory.load_policy(root)

    inventory.save_context(
        ApplicationContext(
            component="payments",
            data_lifetime_years=40,
            context_source=ContextSource.USER_INPUT,
        ),
        db_path=db,
    )

    context = inventory.resolve_context("payments", policy, db_path=db)
    assert context.context_source is ContextSource.USER_INPUT
    assert context.data_lifetime_years == 40


def test_sensitivity_and_criticality_are_independent_axes(tmp_path: Path, db: Path) -> None:
    """Claim: the two dimensions are separable.

    A public status page can be mission-critical while holding no sensitive
    data. Conflating them, as the original prototype did, loses a real
    distinction.
    """
    root = tmp_path / "estate"
    root.mkdir()
    (root / inventory.POLICY_FILENAME).write_text(
        "status-page:\n"
        "  data_sensitivity: low\n"
        "  business_criticality: critical\n"
    )
    context = inventory.load_policy(root)["status-page"]
    assert context.data_sensitivity is Sensitivity.LOW
    assert context.business_criticality is BusinessCriticality.CRITICAL


def test_malformed_policy_file_degrades_to_defaults(tmp_path: Path, db: Path) -> None:
    """Claim: a broken policy file never aborts a scan.

    It falls back to documented defaults with provenance marked accordingly.
    """
    root = tmp_path / "estate"
    root.mkdir()
    (root / inventory.POLICY_FILENAME).write_text(":::not valid:::\n\x00garbage")

    policy = inventory.load_policy(root)
    context = inventory.resolve_context("anything", policy, db_path=db)
    assert context.context_source is ContextSource.DEFAULT


def test_policy_accepts_json(tmp_path: Path) -> None:
    """Claim: a JSON policy file is equally acceptable."""
    root = tmp_path / "estate"
    root.mkdir()
    (root / "aegis_policy.json").write_text(
        json.dumps({"archive": {"data_lifetime_years": 50, "data_sensitivity": "critical"}})
    )
    policy = inventory.load_policy(root)
    assert policy["archive"].data_lifetime_years == 50
    assert policy["archive"].context_source is ContextSource.POLICY_FILE


def test_absurd_lifetime_values_are_clamped(tmp_path: Path) -> None:
    """Claim: nonsense input cannot poison the Mosca calculation downstream."""
    root = tmp_path / "estate"
    root.mkdir()
    (root / inventory.POLICY_FILENAME).write_text(
        "a:\n  data_lifetime_years: -5\n"
        "b:\n  data_lifetime_years: 99999\n"
        "c:\n  data_lifetime_years: not-a-number\n"
    )
    policy = inventory.load_policy(root)
    assert policy["a"].data_lifetime_years == 0
    assert policy["b"].data_lifetime_years == 200
    assert policy["c"].data_lifetime_years == model.DEFAULT_DATA_LIFETIME_YEARS


# ==========================================================================
# Persistence
# ==========================================================================


def test_scan_and_findings_round_trip(db: Path, scan_result) -> None:
    """Claim: a persisted scan reloads identically."""
    inventory.record_scan(scan_result, db)
    reloaded = inventory.get_findings(scan_result.scan_id, db)

    assert len(reloaded) == len(scan_result.findings)
    original = {f.finding_id: f for f in scan_result.findings}
    for finding in reloaded:
        source = original[finding.finding_id]
        assert finding.algorithm == source.algorithm
        assert finding.oid == source.oid
        assert finding.key_size == source.key_size
        assert finding.confidence is source.confidence
        assert finding.detection_method is source.detection_method
        assert finding.component == source.component


def test_certificate_facts_survive_persistence(db: Path, scan_result) -> None:
    """Claim: X.509 detail is not lost in the database round trip."""
    inventory.record_scan(scan_result, db)
    certs_with_facts = [f for f in inventory.get_findings(scan_result.scan_id, db) if f.certificate]
    assert certs_with_facts
    assert any(f.certificate.subject for f in certs_with_facts)


def test_recording_a_scan_twice_is_idempotent(db: Path, scan_result) -> None:
    """Claim: re-recording does not duplicate findings."""
    inventory.record_scan(scan_result, db)
    inventory.record_scan(scan_result, db)
    assert len(inventory.get_findings(scan_result.scan_id, db)) == len(scan_result.findings)


def test_scan_history_accumulates(db: Path, estate: Path) -> None:
    """Claim: scans accumulate, which is what makes drift detection possible."""
    for index in range(3):
        result = certificates.CERTIFICATE_ADAPTER.scan(estate, f"scan_hist_{index}")
        inventory.record_scan(result, db)

    scans = inventory.list_scans(db)
    assert len(scans) == 3
    assert all(s["finding_count"] == len(de.ENTERPRISE_ASSETS) for s in scans)


def test_findings_load_in_deterministic_order(db: Path, scan_result) -> None:
    """Claim: repeated reads return an identical sequence."""
    inventory.record_scan(scan_result, db)
    first = [f.finding_id for f in inventory.get_findings(scan_result.scan_id, db)]
    second = [f.finding_id for f in inventory.get_findings(scan_result.scan_id, db)]
    assert first == second == sorted(first)


def test_inventory_summary_counts_match_findings(db: Path, scan_result) -> None:
    """Claim: the summary cannot disagree with the underlying inventory."""
    inventory.record_scan(scan_result, db)
    summary = inventory.inventory_summary(scan_result.scan_id, db)

    assert summary["total_findings"] == len(scan_result.findings)
    assert sum(summary["by_algorithm"].values()) == len(scan_result.findings)
    assert sum(summary["by_confidence"].values()) == len(scan_result.findings)
    assert summary["components"] == len({f.component for f in scan_result.findings})


def test_summary_reports_discovery_only(db: Path, scan_result) -> None:
    """Claim: the inventory does not report risk.

    Risk is the assessment engine's output. If the inventory also produced it,
    two components could disagree about the same asset.
    """
    inventory.record_scan(scan_result, db)
    summary = inventory.inventory_summary(scan_result.scan_id, db)
    assert not any("risk" in key for key in summary)


# ==========================================================================
# No regression against the frozen Security Lab
# ==========================================================================


def test_ecdat_schema_leaves_inherited_tables_intact(db: Path) -> None:
    """Claim: the new tables are additive.

    The Security Lab depends on the inherited four exactly as they are.
    """
    from backend import database as db_module

    conn = db_module.get_connection(db)
    try:
        names = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
    finally:
        conn.close()

    assert {"users", "key_store", "network_sniff_log", "quantum_attack_log"} <= names
    assert {"ecdat_scans", "ecdat_findings", "ecdat_context"} <= names


def test_legacy_scanner_api_is_untouched() -> None:
    """Claim: every public name the inherited suite depends on still exists.

    ``scanner.py`` was deliberately not edited; it became an internal parsing
    library for the certificate adapter. This test fails loudly if a future
    change breaks that contract.
    """
    for name in (
        "Finding", "scan", "scan_file", "scan_directory", "build_assessment",
        "migration_order", "readiness_score", "extract_spki_oid",
        "RISK_CRITICAL", "RISK_HIGH", "RISK_MEDIUM", "RISK_LOW", "RISK_SAFE",
        "RISK_UNKNOWN", "RISK_RANK", "STATUS_VULNERABLE", "STATUS_POST_QUANTUM",
        "STATUS_HYBRID", "STATUS_UNKNOWN", "EVIDENCE_VERIFIED", "EVIDENCE_DECLARED",
    ):
        assert hasattr(scanner, name), f"scanner.{name} disappeared"


def test_no_private_key_material_reaches_the_new_model(estate: Path) -> None:
    """Claim: the inherited no-leak guarantee holds across the refactor.

    Every new layer is a new exit point for key material, so the guarantee is
    re-tested here rather than assumed to carry over.
    """
    result = certificates.CERTIFICATE_ADAPTER.scan(estate, "scan_leak")
    serialised = json.dumps([f.to_dict() for f in result.findings], default=str)

    for path in estate.rglob("*.pem"):
        text = path.read_text(errors="ignore")
        if "PRIVATE KEY" not in text:
            continue
        body = "".join(line for line in text.splitlines() if not line.startswith("-----"))
        for start in range(0, max(1, len(body) - 40), 40):
            assert body[start : start + 40] not in serialised

    assert "-----BEGIN" not in serialised
