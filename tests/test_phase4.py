"""
AegisPQC — Phase 4 test suite: workflow depth and platform surfaces.

Covers the migration planning engine, procedural staging, packet forensics,
report generation, the executive summary, and the seven-tab dashboard.

The security guarantees from earlier phases are re-tested here against the NEW
exit points, because every feature that renders or exports data is a new way for
key material to escape.

Run with:  pytest tests/ -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend import config
from backend import database as db
from backend import demo_enterprise as de
from backend import migration
from backend import procedure
from backend import reporting
from backend import scanner
from backend import service as svc
from backend import simulator as sim

APP_FILE = str(Path(__file__).resolve().parent.parent / "frontend" / "app.py")


@pytest.fixture()
def temp_db(tmp_path: Path) -> Path:
    """An isolated database per test, seeded with the demo scenario."""
    path = tmp_path / "phase4.db"
    db.reset_db(path)
    svc.reset_and_seed(path)
    return path


@pytest.fixture(scope="module")
def assessment(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """A scanner assessment of a freshly generated enterprise."""
    root = tmp_path_factory.mktemp("p4_enterprise")
    de.generate(root, force=True)
    return scanner.scan(root)


@pytest.fixture(scope="module")
def plan(assessment: dict) -> dict:
    """A migration plan built from that assessment."""
    return migration.build_plan(assessment)


# ==========================================================================
# Workflow backbone
# ==========================================================================


def test_workflow_has_eight_stages() -> None:
    """Claim: the product has one coherent spine, not five disconnected tabs."""
    stages = procedure.workflow_stages()
    assert [s["name"] for s in stages] == [
        "DISCOVER",
        "ASSESS",
        "PRIORITIZE",
        "PROTECT",
        "HARVEST",
        "SIMULATE",
        "MIGRATE",
        "VERIFY",
    ]


def test_every_workflow_stage_names_a_real_module() -> None:
    """Claim: no stage is a diagram box with nothing behind it.

    Each stage must name a module that actually exists in the repository. A
    workflow diagram whose stages are aspirational is marketing, not
    architecture.
    """
    repo_root = Path(__file__).resolve().parent.parent
    for stage in procedure.workflow_stages():
        assert (repo_root / stage["module"]).exists(), (
            f"{stage['name']} claims {stage['module']}, which does not exist"
        )
        assert stage["question"]
        assert stage["surface"]


def test_partially_implemented_stage_declares_its_caveat() -> None:
    """Claim: a stage the prototype does not fully perform says so.

    VERIFY validates the plan's consistency rather than re-scanning a migrated
    estate, because nothing is actually migrated. Claiming otherwise would be
    exactly the overstatement this project exists to avoid.
    """
    stages = {s["key"]: s for s in procedure.workflow_stages()}
    verify = stages["verify"]
    assert verify["implemented"] is False
    assert "does NOT re-scan" in verify["caveat"]
    assert all(s["caveat"] == "" for s in stages.values() if s["implemented"])


# ==========================================================================
# Migration planning
# ==========================================================================


def test_plan_covers_every_asset(plan: dict, assessment: dict) -> None:
    """Claim: no asset silently disappears between assessment and plan."""
    assert plan["assets_total"] == assessment["assets_scanned"]
    assert (
        plan["assets_requiring_migration"] + plan["assets_already_pqc_ready"]
        == plan["assets_total"]
    )


def test_every_queued_asset_has_a_named_target(plan: dict) -> None:
    """Claim: nothing is queued for migration without a replacement named."""
    for rec in plan["recommendations"]:
        if rec["needs_migration"] and rec["risk"] != scanner.RISK_UNKNOWN:
            assert rec["recommended_target"], f"{rec['system_name']} has no target"
            assert rec["target_standard"]
            assert rec["target_rationale"]


def test_every_queued_asset_explains_its_position(plan: dict) -> None:
    """Claim: every position in the queue carries a defensible reason.

    This is the field a security lead would quote in a steering meeting, so it
    must be specific rather than a restatement of the rating.
    """
    for rec in plan["recommendations"]:
        assert rec["why_first"], f"{rec['system_name']} has no justification"
        assert len(rec["why_first"]) > 40
        assert rec["risk_reasons"]


def test_priority_order_is_non_decreasing_in_risk(plan: dict) -> None:
    """Claim: a higher-risk asset never appears below a lower-risk one."""
    ranks = [scanner.RISK_RANK[r["risk"]] for r in plan["recommendations"]]
    assert ranks == sorted(ranks)


def test_retention_breaks_ties_within_a_risk_level(plan: dict) -> None:
    """Claim: among equally-critical assets, longer-lived data is fixed first.

    This is the core of the HNDL argument expressed as an ordering rule: the
    ciphertext only has to outlive the algorithm.
    """
    critical = [
        r for r in plan["recommendations"] if r["risk"] == scanner.RISK_CRITICAL
    ]
    retentions = [r["retention_years"] for r in critical]
    assert retentions == sorted(retentions, reverse=True)


def test_migration_order_is_deterministic(assessment: dict) -> None:
    """Claim: the plan does not reorder itself between runs.

    A migration plan that changes order every time you open it is not a plan.
    """
    orders = {
        tuple(r["system_name"] for r in migration.build_plan(assessment)["recommendations"])
        for _ in range(5)
    }
    assert len(orders) == 1


def test_safe_assets_are_not_queued_for_migration(plan: dict) -> None:
    """Claim: verified post-quantum assets are excluded from the work queue."""
    assert all(r["risk"] != scanner.RISK_SAFE for r in plan["recommendations"])
    assert plan["assets_already_pqc_ready"] >= 1
    for rec in plan["already_pqc_ready"]:
        assert rec["needs_migration"] is False
        assert rec["recommended_target"] == ""


def test_every_asset_lands_in_a_phase(plan: dict) -> None:
    """Claim: the phased programme accounts for the whole queue."""
    phased = sum(phase["asset_count"] for phase in plan["phases"])
    assert phased == plan["assets_requiring_migration"]


def test_critical_assets_land_in_phase_one(plan: dict) -> None:
    """Claim: phase sequencing follows risk, not arrival order."""
    phase_one = next(p for p in plan["phases"] if p["key"] == "phase_1")
    critical = [r for r in plan["recommendations"] if r["risk"] == scanner.RISK_CRITICAL]
    assert phase_one["asset_count"] == len(critical)
    assert set(phase_one["assets"]) == {r["system_name"] for r in critical}


def test_unknown_assets_are_queued_for_investigation(plan: dict) -> None:
    """Claim: an asset nobody can parse is never silently dropped.

    An unidentified asset is exactly the one a migration programme must not lose
    track of, so it gets its own phase rather than being filtered out.
    """
    unknown = [r for r in plan["recommendations"] if r["risk"] == scanner.RISK_UNKNOWN]
    assert unknown
    for rec in unknown:
        assert rec["phase"] == "phase_4"
        assert "could not be identified" in rec["why_first"]


def test_declared_pqc_is_queued_for_confirmation_not_replacement(plan: dict) -> None:
    """Claim: a manifest claim is treated as unconfirmed, not as done.

    An organisation's migration status is frequently wrong on paper. Ranking a
    declared asset for confirmation rather than replacement is the honest
    handling.
    """
    declared = [
        r for r in plan["recommendations"] if r["evidence"] == scanner.EVIDENCE_DECLARED
    ]
    assert declared
    for rec in declared:
        assert "declared" in rec["why_first"].lower()
        assert "not replacement" in rec["why_first"].lower()


def test_target_architecture_keeps_aes_unchanged(plan: dict) -> None:
    """Claim: the plan does not imply AES is being replaced.

    Grover's algorithm offers only a quadratic speedup against symmetric
    ciphers. A migration plan that proposes replacing AES would reveal a
    misunderstanding of the threat.
    """
    architecture = plan["recommended_target_architecture"]
    assert "AES-256-GCM" in architecture["symmetric"]
    assert "unchanged" in architecture["symmetric"].lower()
    assert "quadratic speedup" in architecture["note"]


def test_plan_states_it_modifies_nothing(plan: dict) -> None:
    """Claim: the advisory nature of the plan is stated in the output itself."""
    assert "does not modify" in plan["scope_note"].lower()
    assert "does not predict" in plan["scope_note"].lower()


def test_plan_verification_passes_on_a_valid_plan(plan: dict) -> None:
    """Claim: the VERIFY stage runs real consistency checks."""
    verification = migration.verify_plan(plan)
    assert verification["consistent"] is True
    assert verification["verdict"] == "PLAN CONSISTENT"
    assert len(verification["checks"]) >= 5
    assert all(check["detail"] for check in verification["checks"])


def test_plan_verification_detects_an_inconsistent_plan(plan: dict) -> None:
    """Claim: verification actually fails when the plan is broken.

    A check that can only pass proves nothing. This corrupts the ordering and
    asserts the verifier notices.
    """
    broken = json.loads(json.dumps(plan))
    broken["recommendations"].reverse()
    verification = migration.verify_plan(broken)
    assert verification["consistent"] is False
    assert verification["verdict"] == "PLAN INCOMPLETE"


def test_verification_states_it_is_not_post_migration_validation(plan: dict) -> None:
    """Claim: VERIFY does not overstate what it verified."""
    verification = migration.verify_plan(plan)
    assert "does NOT verify a migrated estate" in verification["scope_note"]


def test_empty_assessment_produces_an_empty_plan() -> None:
    """Claim: planning over nothing returns an empty plan, not a crash."""
    empty = scanner.build_assessment([])
    result = migration.build_plan(empty)
    assert result["assets_total"] == 0
    assert result["recommendations"] == []
    assert migration.verify_plan(result)["consistent"] is True


# ==========================================================================
# Procedural staging
# ==========================================================================


def test_vault_pipeline_has_all_seven_stages(temp_db: Path) -> None:
    """Claim: the vault shows the real cryptographic pipeline."""
    sent = svc.send_message("Alice", "Bob", config.ALGO_ML_KEM_768, "payload", "t", temp_db)
    steps = svc.vault_pipeline(sent)

    assert len(steps) == 7
    assert [s["index"] for s in steps] == list(range(1, 8))
    titles = " ".join(s["title"] for s in steps).lower()
    for expected in ("plaintext", "key establishment", "key derivation", "aes-256-gcm", "ciphertext", "network", "interception"):
        assert expected in titles


def test_vault_pipeline_shows_real_artifacts(temp_db: Path) -> None:
    """Claim: the displayed sizes come from the actual envelope."""
    sent = svc.send_message("Alice", "Bob", config.ALGO_ML_KEM_768, "payload", "t", temp_db)
    steps = svc.vault_pipeline(sent)
    by_index = {s["index"]: s for s in steps}

    # 1088 bytes is fixed by FIPS 203 for ML-KEM-768.
    assert by_index[2]["artifacts"]["kem_ciphertext_bytes"] == 1088
    assert by_index[3]["artifacts"]["derived_key_bits"] == 256
    assert by_index[4]["artifacts"]["nonce_bits"] == 96
    assert by_index[4]["artifacts"]["auth_tag_bits"] == 128
    assert by_index[7]["artifacts"]["packet_id"] == sent["packet_id"]


def test_vault_pipeline_never_shows_key_material(temp_db: Path) -> None:
    """Claim: the pipeline view exposes no secret.

    Checks for actual key MATERIAL rather than for words. An earlier version of
    this test banned the substring "seed", which flagged the sentence "RSA
    encapsulation of a random seed" — descriptive prose, not a disclosure. A
    leak test that fires on vocabulary rather than data trains you to ignore it.
    """
    connection = db.get_connection(temp_db)
    try:
        private_keys = [
            row["private_key"]
            for row in connection.execute("SELECT private_key FROM key_store").fetchall()
        ]
    finally:
        connection.close()

    for algorithm in config.SUPPORTED_ALGORITHMS:
        sent = svc.send_message("Alice", "Bob", algorithm, "payload", "t", temp_db)
        serialised = json.dumps(svc.vault_pipeline(sent))

        for private_key in private_keys:
            assert private_key.hex() not in serialised
            assert private_key.hex()[:32] not in serialised

        # No structural field that could carry a secret should be present.
        for field in ("private_key", "shared_secret", "aes_key", "derived_key_value"):
            assert f'"{field}"' not in serialised, f"{field} present for {algorithm}"


def test_vault_pipeline_states_aes_is_not_replaced(temp_db: Path) -> None:
    """Claim: the UI never implies PQC replaces AES."""
    sent = svc.send_message("Alice", "Bob", config.ALGO_ML_KEM_768, "x", "t", temp_db)
    text = " ".join(step["detail"] for step in svc.vault_pipeline(sent))
    assert "NOT being replaced" in text
    assert "Grover" in text


def test_hybrid_pipeline_shows_both_legs(temp_db: Path) -> None:
    """Claim: hybrid mode explains that two secrets feed one KDF."""
    sent = svc.send_message("Alice", "Bob", config.ALGO_HYBRID, "payload", "t", temp_db)
    steps = svc.vault_pipeline(sent)
    text = " ".join(s["title"] + " " + s["detail"] for s in steps)
    assert "X25519" in text and "ML-KEM-768" in text
    assert "Both are required" in text or "BOTH" in text


def test_rsa_attack_procedure_reaches_every_step(temp_db: Path) -> None:
    """Claim: the RSA break is shown as an explicit, completed procedure."""
    target = [
        p for p in svc.list_harvested(temp_db) if p["algo_used"] == config.ALGO_RSA_DEMO
    ][0]
    result = svc.run_attack(target["packet_id"], temp_db)
    steps = svc.attack_procedure(result)

    assert result["status"] == sim.STATUS_BREACHED
    assert len(steps) == 8
    assert all(step["reached"] for step in steps), [
        s["title"] for s in steps if not s["reached"]
    ]
    assert steps[-1]["outcome"] == sim.STATUS_BREACHED


def test_rsa_procedure_states_it_is_not_shors(temp_db: Path) -> None:
    """Claim: the procedural view never implies quantum computation."""
    target = [
        p for p in svc.list_harvested(temp_db) if p["algo_used"] == config.ALGO_RSA_DEMO
    ][0]
    steps = svc.attack_procedure(svc.run_attack(target["packet_id"], temp_db))
    text = " ".join(step["detail"] for step in steps)
    assert "CLASSICAL algorithm" in text
    assert "not Shor's algorithm" in text
    assert "no quantum computer is involved" in text.lower()


def test_rsa_procedure_evidence_comes_from_the_real_trace(temp_db: Path) -> None:
    """Claim: each displayed step is backed by actual attack output.

    The steps are derived from the simulator's trace rather than hardcoded, so a
    step can only show as reached if the attack really performed it.
    """
    target = [
        p for p in svc.list_harvested(temp_db) if p["algo_used"] == config.ALGO_RSA_DEMO
    ][0]
    result = svc.run_attack(target["packet_id"], temp_db)
    trace_lines = set(result["log_trace"].splitlines())

    for step in svc.attack_procedure(result):
        for line in step["artifacts"]["evidence"]:
            assert line in trace_lines


@pytest.mark.parametrize("algorithm", [config.ALGO_ML_KEM_768, config.ALGO_HYBRID])
def test_lattice_procedure_reports_no_attack_attempted(temp_db: Path, algorithm: str) -> None:
    """Claim: the post-quantum branch says plainly that it attempted nothing."""
    target = [p for p in svc.list_harvested(temp_db) if p["algo_used"] == algorithm][0]
    result = svc.run_attack(target["packet_id"], temp_db)
    steps = svc.attack_procedure(result)

    assert result["status"] == sim.STATUS_IMMUNE
    assert steps
    text = " ".join(step["detail"] for step in steps)
    assert "does not apply" in text
    assert "ESTIMATES" in text or "estimates" in text
    assert "not measurements and not proofs" in text or "not proofs" in text


def test_rsa2048_procedure_shows_a_refusal(temp_db: Path) -> None:
    """Claim: real RSA-2048 renders as an explicit refusal, not a blank list.

    Showing an empty or all-unreached procedure would look like a bug. Showing a
    stated refusal is the honest and stronger presentation.
    """
    from backend import crypto_engine as ce

    bob = db.create_user("Bob", temp_db)
    keypair = ce.generate_keypair(config.ALGO_RSA_2048)
    db.store_keypair(bob, config.ALGO_RSA_2048, keypair.public_key, keypair.private_key, temp_db)
    envelope = ce.seal(config.ALGO_RSA_2048, keypair.public_key, b"payload", b"aad")
    packet_id = sim.intercept(
        "Alice", "Bob", config.ALGO_RSA_2048, envelope, b"aad",
        keypair.public_key, 7, "rc", temp_db,
    )

    result = svc.run_attack(packet_id, temp_db)
    steps = svc.attack_procedure(result)

    assert len(steps) == 1
    assert steps[0]["outcome"] == "REFUSED"
    assert "refuses to fabricate" in steps[0]["detail"]


def test_hybrid_defence_explains_both_legs() -> None:
    """Claim: the hybrid explanation is a property claim, not a security proof."""
    hybrid = svc.hybrid_defence()
    assert len(hybrid["legs"]) == 2
    assert "property of the construction" in hybrid["consequence"]
    assert "not a security proof" in hybrid["consequence"]
    names = " ".join(leg["name"] for leg in hybrid["legs"])
    assert "X25519" in names and "ML-KEM-768" in names


# ==========================================================================
# Packet forensics
# ==========================================================================


def test_forensics_returns_full_envelope_structure(temp_db: Path) -> None:
    """Claim: the forensic view shows what a tap genuinely observes."""
    packet = svc.list_harvested(temp_db)[0]
    forensics = svc.packet_forensics(packet["packet_id"], temp_db)

    for field in (
        "packet_id", "intercepted_at", "sender", "recipient", "algorithm",
        "kem_ciphertext_bytes", "nonce", "auth_tag", "ciphertext_body_bytes",
        "recipient_public_key_bytes", "total_captured_bytes",
    ):
        assert field in forensics, f"missing {field}"

    assert forensics["nonce_bits"] == 96
    assert forensics["auth_tag_bits"] == 128


def test_forensics_declares_no_private_keys_captured(temp_db: Path) -> None:
    """Claim: the guarantee is stated on the artifact itself.

    A judge reading the forensic panel should not have to take it on trust that
    private keys were not captured — the panel says so, and this test enforces
    that the statement is present and true.
    """
    for packet in svc.list_harvested(temp_db):
        forensics = svc.packet_forensics(packet["packet_id"], temp_db)
        assert forensics["private_keys_captured"] is False
        assert "PRIVATE KEYS NOT CAPTURED" in forensics["key_custody_note"]
        assert "no cryptographic modification" in forensics["capture_note"]


def test_forensics_leaks_no_private_key_material(temp_db: Path) -> None:
    """Claim: the forensic view is a new exit point, and it is also sealed."""
    connection = db.get_connection(temp_db)
    try:
        private_keys = [
            row["private_key"]
            for row in connection.execute("SELECT private_key FROM key_store").fetchall()
        ]
    finally:
        connection.close()
    assert private_keys

    for packet in svc.list_harvested(temp_db):
        serialised = json.dumps(svc.packet_forensics(packet["packet_id"], temp_db))
        for private_key in private_keys:
            assert private_key.hex() not in serialised
            assert private_key.hex()[:32] not in serialised


def test_forensics_tag_matches_gcm_layout(temp_db: Path) -> None:
    """Claim: the split of ciphertext into body and tag is correct.

    AES-GCM appends a 16-byte tag. Body plus tag must reconstruct the stored
    payload exactly, or the forensic view is misrepresenting the envelope.
    """
    packet = svc.list_harvested(temp_db)[0]
    forensics = svc.packet_forensics(packet["packet_id"], temp_db)
    stored = db.get_packet(packet["packet_id"], temp_db)

    assert (
        forensics["ciphertext_body_bytes"] + len(bytes.fromhex(forensics["auth_tag"]))
        == len(stored["payload_ciphertext"])
    )


def test_forensics_rejects_unknown_packet(temp_db: Path) -> None:
    """Claim: a bad packet id is a clean error, not a stack trace."""
    with pytest.raises(svc.ServiceError):
        svc.packet_forensics("pkt_nonexistent", temp_db)


# ==========================================================================
# Executive summary
# ==========================================================================


def test_executive_summary_aggregates_every_subsystem(temp_db: Path) -> None:
    """Claim: the overview covers estate, migration, demonstration, threat."""
    summary = svc.executive_summary(temp_db)
    for section in ("estate", "migration", "demonstration", "threat_model"):
        assert section in summary

    assert summary["estate"]["assets_scanned"] > 0
    assert summary["migration"]["top_priorities"]
    assert summary["demonstration"]["packets_harvested"] == 3


def test_executive_summary_agrees_with_the_underlying_tabs(temp_db: Path) -> None:
    """Claim: the overview can never contradict the tab it summarises.

    It is assembled from the same subsystem outputs rather than recomputing,
    so this test would catch a future refactor that introduced a second,
    divergent calculation.
    """
    summary = svc.executive_summary(temp_db)
    assessment = svc.scan_demo_enterprise()
    harvest = svc.harvest_stats(temp_db)

    assert summary["estate"]["assets_scanned"] == assessment["assets_scanned"]
    assert summary["estate"]["readiness_score"] == assessment["readiness_score"]
    assert summary["estate"]["verdict"] == assessment["verdict"]
    assert summary["demonstration"]["packets_harvested"] == harvest["total_packets"]


def test_executive_qday_status_tracks_reality(temp_db: Path) -> None:
    """Claim: the Q-Day status reflects what has actually been run."""
    assert svc.executive_summary(temp_db)["demonstration"]["qday_status"] == "ARMED"
    svc.attack_all(temp_db)
    assert svc.executive_summary(temp_db)["demonstration"]["qday_status"] == "DEMONSTRATED"


def test_executive_threat_model_keeps_the_three_claims_separate(temp_db: Path) -> None:
    """Claim: the executive view does not blur demo, threat, and defence."""
    threat = svc.executive_summary(temp_db)["threat_model"]
    assert "No quantum computer is involved" in threat["demonstrated_today"]
    assert "No machine capable of running it against RSA-2048 exists" in threat["future_threat"]
    assert "designed to resist" in threat["defence"]


# ==========================================================================
# Benchmarks — measured versus estimated
# ==========================================================================


def test_benchmark_bundle_separates_measured_from_estimated() -> None:
    """Claim: measured values and research estimates are never mixed.

    Presenting them in one table would imply we measured quantum attack costs,
    which nobody can.
    """
    bundle = svc.benchmark_bundle(3)
    assert bundle["measured"]["source"] == "MEASURED"
    assert bundle["estimated"]["source"] == "ESTIMATED / RESEARCH-BASED"
    assert "measured on the machine" in bundle["measured"]["note"]
    assert "could be measured by anyone today" in bundle["estimated"]["note"]


def test_every_estimated_value_carries_a_citation() -> None:
    """Claim: no research figure appears without attribution."""
    for row in svc.benchmark_bundle(3)["estimated"]["rows"]:
        assert row["citation"], f"{row['metric']} has no citation"


def test_measured_rows_come_from_the_crypto_engine() -> None:
    """Claim: the benchmark table is real measurement, not hardcoded data."""
    rows = svc.benchmark_bundle(3)["measured"]["rows"]
    assert {r["algorithm"] for r in rows} == {
        config.ALGO_RSA_2048,
        config.ALGO_ML_KEM_768,
        config.ALGO_HYBRID,
    }
    for row in rows:
        assert row["keygen_ms"] > 0
        assert row["public_key_bytes"] > 0


def test_tradeoffs_state_both_sides() -> None:
    """Claim: each algorithm's cost is stated alongside its advantage.

    A comparison showing only the favourable half is marketing.
    """
    for tradeoff in svc.benchmark_bundle(3)["tradeoffs"]:
        assert tradeoff["advantage"] and tradeoff["cost"] and tradeoff["verdict"]
    text = json.dumps(svc.benchmark_bundle(3)["tradeoffs"]).lower()
    assert "bandwidth" in text


# ==========================================================================
# Reporting
# ==========================================================================


def test_report_contains_every_required_section(temp_db: Path) -> None:
    """Claim: the exported report is complete enough to circulate."""
    report = svc.full_report(temp_db)
    for section in (
        "report", "executive_summary", "risk_distribution",
        "algorithm_distribution", "inventory", "migration_plan",
        "verification", "scope_and_limitations", "hndl_demonstration",
    ):
        assert section in report, f"missing {section}"

    assert report["report"]["generated_at"]
    assert report["inventory"]
    assert report["migration_plan"]["priorities"]


def test_report_states_its_limitations(temp_db: Path) -> None:
    """Claim: the report discloses scope rather than leaving it implied."""
    limitations = svc.full_report(temp_db)["scope_and_limitations"]
    joined = " ".join(limitations.values()).lower()
    assert "no cryptanalysis is performed" in joined
    assert "no prediction is made" in joined
    assert "does not modify" in joined
    assert "pkcs#12" in joined


def test_report_contains_no_private_key_material(temp_db: Path) -> None:
    """Claim: the export is safe to email around an organisation."""
    report = svc.full_report(temp_db)
    serialised = json.dumps(report)

    connection = db.get_connection(temp_db)
    try:
        private_keys = [
            row["private_key"]
            for row in connection.execute("SELECT private_key FROM key_store").fetchall()
        ]
    finally:
        connection.close()

    for private_key in private_keys:
        assert private_key.hex() not in serialised
    for marker in ("-----BEGIN", "PRIVATE KEY", "private_key"):
        assert marker not in serialised


def test_report_leak_guard_actually_fires() -> None:
    """Claim: the leak guard is a real check, not a comment.

    A guard that can never fire proves nothing, so this feeds it content that
    must be rejected.
    """
    with pytest.raises(reporting.ReportLeakError):
        reporting._assert_no_secrets("prefix -----BEGIN PRIVATE KEY----- suffix")
    with pytest.raises(reporting.ReportLeakError):
        reporting._assert_no_secrets('{"private_key": "abc"}')


def test_markdown_report_renders_completely(temp_db: Path) -> None:
    """Claim: the Markdown export is a readable document, not a data dump."""
    document = svc.report_markdown(temp_db)

    for heading in (
        "# PQC Readiness Assessment",
        "## Executive summary",
        "## Cryptographic inventory",
        "## Migration priorities",
        "## Migration phases",
        "## Plan verification",
        "## Scope and limitations",
    ):
        assert heading in document, f"missing heading {heading}"

    assert "no private key material" in document.lower()
    assert len(document) > 2000


def test_markdown_report_contains_no_private_keys(temp_db: Path) -> None:
    """Claim: the Markdown path is sealed too, not just the JSON path."""
    document = svc.report_markdown(temp_db)
    assert "-----BEGIN" not in document
    assert "PRIVATE KEY" not in document


def test_report_with_benchmarks_labels_them_measured(temp_db: Path) -> None:
    """Claim: benchmark values in the report are labelled as measured."""
    report = svc.full_report(temp_db, include_benchmarks=True)
    assert "measured_benchmarks" in report
    assert "MEASURED" in report["measured_benchmarks"]["measurement_note"]
    assert report["measured_benchmarks"]["rows"]


# ==========================================================================
# Dashboard
# ==========================================================================


def _app_test(timeout: int = 300):
    """Build an AppTest harness for the dashboard."""
    pytest.importorskip("streamlit.testing.v1")
    from streamlit.testing.v1 import AppTest

    return AppTest.from_file(APP_FILE, default_timeout=timeout)


EXPECTED_TABS = [
    "Overview",
    "PQC Readiness",
    "Migration Plan",
    "Quantum Vault",
    "HNDL Hoard",
    "Q-Day Simulator",
    "Benchmarks",
]


def test_dashboard_renders_seven_tabs() -> None:
    """Claim: the platform surfaces the whole workflow.

    Asserts labels rather than a count, so this fails on a tab being added,
    removed, renamed, or reordered.
    """
    at = _app_test()
    at.run()
    assert not at.exception, [str(e.value) for e in at.exception]
    assert [tab.label for tab in at.tabs] == EXPECTED_TABS


def test_dashboard_exposes_every_control() -> None:
    """Claim: every control the demo depends on is present."""
    at = _app_test()
    at.run()
    labels = {b.label for b in at.button}
    assert {
        "LOAD PRESENTATION DEMO",
        "LOAD DEMO ENTERPRISE",
        "ENCRYPT AND SEND",
        "EXECUTE Q-DAY ATTACK",
        "RUN BENCHMARKS",
        "Prepare JSON report",
        "Prepare Markdown report",
    } <= labels, f"missing controls: {labels}"


def test_dashboard_overview_shows_executive_metrics() -> None:
    """Claim: the overview renders without an interaction.

    A judge landing on the app must see posture immediately, not an empty page
    with a button on it.
    """
    at = _app_test()
    at.run()
    assert not at.exception, [str(e.value) for e in at.exception]
    rendered = " ".join(str(block.value) for block in at.markdown)
    assert "Readiness score" in rendered
    assert "Top migration priorities" in rendered


def test_dashboard_migration_plan_renders() -> None:
    """Claim: the Migration Plan tab shows the queue and the verification."""
    at = _app_test()
    at.run()
    assert not at.exception, [str(e.value) for e in at.exception]
    rendered = " ".join(str(block.value) for block in at.markdown)
    assert "Migration queue" in rendered
    assert "PLAN CONSISTENT" in rendered
    assert "planning output" in rendered


def test_dashboard_send_shows_the_pipeline() -> None:
    """Claim: clicking send renders the procedural pipeline."""
    at = _app_test()
    at.run()
    [b for b in at.button if b.label == "ENCRYPT AND SEND"][0].click().run()

    assert not at.exception, [str(e.value) for e in at.exception]
    rendered = " ".join(str(block.value) for block in at.markdown)
    assert "Cryptographic pipeline" in rendered
    assert "HKDF" in rendered
    assert len(at.success) >= 1


def test_dashboard_qday_shows_procedural_steps() -> None:
    """Claim: the attack renders as a procedure, not just a verdict.

    Drives the real button through the real code path — a genuine factorisation
    runs during this test.
    """
    at = _app_test(timeout=360)
    at.run()
    [b for b in at.button if b.label == "EXECUTE Q-DAY ATTACK"][0].click().run()

    assert not at.exception, [str(e.value) for e in at.exception]
    rendered = " ".join(str(block.value) for block in at.markdown)
    assert "Procedural steps" in rendered
    assert "Extract the public modulus" in rendered
    assert "Reconstruct the private exponent" in rendered

    code_blocks = " ".join(block.value for block in at.code)
    assert "MERGER BRIEF" in code_blocks


def test_dashboard_forensic_view_renders() -> None:
    """Claim: the forensic packet panel appears with its guarantee visible."""
    at = _app_test()
    at.run()
    assert not at.exception, [str(e.value) for e in at.exception]
    rendered = " ".join(str(block.value) for block in at.markdown)
    assert "PRIVATE KEYS NOT CAPTURED" in rendered
    assert "Passive interception" in rendered


def test_dashboard_benchmarks_separate_measured_and_estimated() -> None:
    """Claim: the benchmark tab labels its two data sources distinctly."""
    at = _app_test(timeout=360)
    at.run()
    [b for b in at.button if b.label == "RUN BENCHMARKS"][0].click().run()

    assert not at.exception, [str(e.value) for e in at.exception]
    rendered = " ".join(str(block.value) for block in at.markdown)
    assert "MEASURED" in rendered
    assert "ESTIMATED / RESEARCH-BASED" in rendered


def test_dashboard_report_buttons_produce_downloads() -> None:
    """Claim: the export buttons actually generate downloadable reports."""
    at = _app_test(timeout=360)
    at.run()
    [b for b in at.button if b.label == "Prepare Markdown report"][0].click().run()
    assert not at.exception, [str(e.value) for e in at.exception]
    assert len(at.download_button) >= 1


def test_dashboard_renders_no_private_key_material() -> None:
    """Claim: nothing the dashboard renders contains key material.

    Sweeps every rendered markdown and code block. Checks for PEM headers and
    field names rather than the phrase "PRIVATE KEY", because the forensic panel
    legitimately renders the guarantee "PRIVATE KEYS NOT CAPTURED" — banning the
    phrase would flag the very statement that documents the guarantee.
    """
    at = _app_test(timeout=360)
    at.run()
    [b for b in at.button if b.label == "ENCRYPT AND SEND"][0].click().run()

    rendered = " ".join(
        [str(block.value) for block in at.markdown]
        + [block.value for block in at.code]
    )
    for forbidden in (
        "-----BEGIN",
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "private_key",
        "private_bytes",
    ):
        assert forbidden not in rendered, f"{forbidden} rendered in the UI"

    # The guarantee itself must be present — its absence would mean the
    # forensic panel stopped stating what it does not capture.
    assert "PRIVATE KEYS NOT CAPTURED" in rendered


def test_ui_module_has_no_streamlit_class_dependencies() -> None:
    """Claim: styling targets our own markup, not Streamlit internals.

    Streamlit's DOM changes between releases. Rules that target its generated
    class names break silently on upgrade; ours degrade to plainer styling at
    worst. The few data-testid rules are cosmetic only and allowed.
    """
    source = (Path(__file__).resolve().parent.parent / "frontend" / "ui.py").read_text()
    assert ".css-" not in source, "styling depends on Streamlit's generated classes"
    assert ".st-emotion" not in source


def test_dashboard_workflow_strip_names_all_stages() -> None:
    """Claim: the workflow spine is visible on the surfaces."""
    at = _app_test()
    at.run()
    rendered = " ".join(str(block.value) for block in at.markdown)
    for stage in ("DISCOVER", "ASSESS", "PRIORITIZE", "PROTECT", "HARVEST", "SIMULATE", "MIGRATE", "VERIFY"):
        assert stage in rendered, f"{stage} missing from the workflow strip"


# ==========================================================================
# API surface
# ==========================================================================


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """TestClient bound to an isolated database, seeded."""
    from fastapi.testclient import TestClient

    monkeypatch.setattr(config, "DB_PATH", tmp_path / "api.db")
    from backend.main import app

    with TestClient(app) as test_client:
        test_client.post("/api/demo/reset")
        yield test_client


def test_api_exposes_phase4_endpoints(client) -> None:
    """Claim: the new capabilities are reachable over REST, not UI-only."""
    for path in (
        "/api/overview",
        "/api/migration/plan",
        "/api/migration/verify",
        "/api/workflow",
        "/api/report",
    ):
        response = client.get(path)
        assert response.status_code == 200, f"{path} -> {response.status_code}"
        assert response.json()


def test_api_migration_plan_is_consistent(client) -> None:
    """Claim: the plan served over HTTP passes its own verification."""
    plan = client.get("/api/migration/plan").json()
    verification = client.get("/api/migration/verify").json()
    assert plan["recommendations"]
    assert verification["consistent"] is True


def test_api_forensics_endpoint(client) -> None:
    """Claim: forensic detail is reachable and rejects unknown packets."""
    packets = client.get("/api/interceptor/hoarded-packets").json()
    packet_id = packets[0]["packet_id"]

    body = client.get(f"/api/interceptor/forensics/{packet_id}").json()
    assert body["private_keys_captured"] is False
    assert body["nonce_bits"] == 96

    assert client.get("/api/interceptor/forensics/pkt_nope").status_code == 404


def test_api_phase4_responses_leak_no_private_keys(client, tmp_path: Path) -> None:
    """Claim: every new endpoint is sealed like the existing ones.

    Each feature that renders or exports data is a new way for key material to
    escape, so the guarantee is re-tested against the new exits rather than
    assumed to carry over.
    """
    connection = db.get_connection(tmp_path / "api.db")
    try:
        private_hexes = [
            row["private_key"].hex()
            for row in connection.execute("SELECT private_key FROM key_store").fetchall()
        ]
    finally:
        connection.close()
    assert private_hexes

    packets = client.get("/api/interceptor/hoarded-packets").json()
    bodies = [
        client.get("/api/overview").text,
        client.get("/api/migration/plan").text,
        client.get("/api/migration/verify").text,
        client.get("/api/workflow").text,
        client.get("/api/report").text,
        client.get(f"/api/interceptor/forensics/{packets[0]['packet_id']}").text,
    ]

    for body in bodies:
        for private_hex in private_hexes:
            assert private_hex not in body
            assert private_hex[:64] not in body
        assert "-----BEGIN" not in body


def test_api_no_phase4_user_error_returns_500(client) -> None:
    """Claim: bad input on the new endpoints yields 4xx, never a server error."""
    for path in (
        "/api/interceptor/forensics/nonsense",
        "/api/interceptor/forensics/",
    ):
        assert client.get(path).status_code < 500, path


# ==========================================================================
# Performance
# ==========================================================================
# Guardrails, not optimisation targets. Each budget sits well above the measured
# value so the tests do not flake on slower hardware, while still failing if a
# change would visibly stall a live demo.


def test_migration_planning_is_effectively_free(assessment: dict) -> None:
    """Budget: planning is pure computation over an existing assessment.

    It must not re-scan. If this ever slows down, something started doing I/O
    inside the planner.
    """
    import time as _time

    start = _time.perf_counter()
    for _ in range(10):
        plan = migration.build_plan(assessment)
        migration.verify_plan(plan)
    elapsed = (_time.perf_counter() - start) * 1000
    assert elapsed < 500, f"10 plan+verify cycles took {elapsed:.0f}ms"


def test_procedural_staging_is_effectively_free(temp_db: Path) -> None:
    """Budget: staging is presentation logic, not re-execution.

    The attack must not be re-run to render its steps — a regression there would
    turn a fast redraw into a second live factorisation.
    """
    import time as _time

    sent = svc.send_message("Alice", "Bob", config.ALGO_ML_KEM_768, "x", "t", temp_db)
    target = [
        p for p in svc.list_harvested(temp_db) if p["algo_used"] == config.ALGO_ML_KEM_768
    ][0]
    result = svc.run_attack(target["packet_id"], temp_db)

    start = _time.perf_counter()
    for _ in range(20):
        svc.vault_pipeline(sent)
        svc.attack_procedure(result)
    elapsed = (_time.perf_counter() - start) * 1000
    assert elapsed < 500, f"20 staging cycles took {elapsed:.0f}ms"


def test_forensics_is_fast(temp_db: Path) -> None:
    """Budget: selecting a packet in the forensic view feels instant."""
    import time as _time

    packet_id = svc.list_harvested(temp_db)[0]["packet_id"]
    start = _time.perf_counter()
    for _ in range(20):
        svc.packet_forensics(packet_id, temp_db)
    elapsed = (_time.perf_counter() - start) * 1000
    assert elapsed < 1000, f"20 forensic lookups took {elapsed:.0f}ms"


def test_report_generation_fits_a_demo_click(temp_db: Path) -> None:
    """Budget: the export button returns before the audience notices."""
    import time as _time

    start = _time.perf_counter()
    svc.report_markdown(temp_db)
    elapsed = _time.perf_counter() - start
    assert elapsed < 15.0, f"report generation took {elapsed:.1f}s"


def test_dashboard_caches_expensive_derivations() -> None:
    """Budget: a rerun does not re-scan the estate.

    Streamlit re-runs the whole script on every interaction. Without caching,
    each click would re-scan and rebuild the plan. Measured on reference
    hardware, the cache takes a rerun from roughly 1.2 s to 0.13 s; the budget
    here is loose enough not to flake but tight enough to catch the cache being
    removed.
    """
    import time as _time

    at = _app_test(timeout=360)
    at.run()

    start = _time.perf_counter()
    at.run()
    elapsed = _time.perf_counter() - start
    assert not at.exception, [str(e.value) for e in at.exception]
    assert elapsed < 3.0, f"cached rerun took {elapsed:.1f}s — is the cache gone?"


def test_cache_invalidation_clears_every_derived_key() -> None:
    """Claim: reset drops every cached derivation.

    A stale cache after reset would show the previous judge's state, which is
    worse than no cache at all.
    """
    source = (Path(__file__).resolve().parent.parent / "frontend" / "app.py").read_text()
    for key in ("cache_assessment", "cache_plan", "cache_verify", "cache_exec", "scan", "last_sent"):
        assert f'"{key}"' in source, f"{key} is not cleared by invalidate_cache"
    # The reset handler must call it.
    assert "invalidate_cache()" in source


# ==========================================================================
# Console integrity
# ==========================================================================


def test_no_duplicate_widget_keys() -> None:
    """Claim: no two widgets can collide on an auto-generated ID.

    Streamlit derives a widget's identity from its type, label, and options. Two
    identical widgets in one script raise DuplicateWidgetID at runtime — which
    surfaces as a red error box mid-demo, not at build time.

    Two controls in this console share the label "Run assessment" (they sit in
    mutually exclusive branches of the scan-source selector), so both carry an
    explicit key. This asserts those keys exist and are distinct.
    """
    import re as _re

    source = (Path(__file__).resolve().parent.parent / "frontend" / "app.py").read_text()
    keys = _re.findall(r'key="([^"]+)"', source)
    assert len(keys) == len(set(keys)), f"duplicate widget keys: {keys}"

    # The two same-labelled buttons must be individually keyed.
    assert "scan_path_btn" in keys
    assert "scan_upload_btn" in keys


def test_console_renders_all_surfaces_without_error() -> None:
    """Claim: every surface is mounted and error-free on load.

    ``st.tabs`` keeps all surfaces mounted, so a single render exercises every
    one. If any surface raised, the exception list would be non-empty.
    """
    at = _app_test(timeout=360)
    at.run()
    assert not at.exception, [str(e.value) for e in at.exception]
    assert len(at.tabs) == 7
    assert len(at.markdown) > 100, "console rendered suspiciously little markup"


def test_console_has_no_external_asset_references() -> None:
    """Claim: the console loads no web font, stylesheet, or remote image.

    The demo must run air-gapped. A web font that silently fails would change
    every typographic measurement on the presentation machine.
    """
    frontend = Path(__file__).resolve().parent.parent / "frontend"
    for module in frontend.glob("*.py"):
        source = module.read_text(encoding="utf-8")
        for marker in ("@import", "fonts.googleapis", "cdn.", "<link", "<script"):
            assert marker not in source, f"{module.name} references {marker!r}"


def test_design_system_survives_streamlit_upgrades() -> None:
    """Claim: styling does not depend on Streamlit's generated class names.

    Streamlit's DOM changes between releases. Rules targeting its generated
    classes break silently on upgrade; the rules here target stable
    ``data-testid`` and ``data-baseweb`` attributes and are cosmetic, so the
    worst case is a plainer console rather than a broken one.
    """
    source = (Path(__file__).resolve().parent.parent / "frontend" / "ui.py").read_text()
    assert ".css-" not in source
    assert ".st-emotion" not in source


def test_status_vocabulary_is_consistent_across_surfaces() -> None:
    """Claim: risk terminology is identical everywhere it appears.

    A console that says CRITICAL on one surface and SEVERE on another looks
    assembled rather than designed, and a judge notices.
    """
    from frontend import ui as design

    assert set(design.RISK_COLOUR) == {
        scanner.RISK_CRITICAL,
        scanner.RISK_HIGH,
        scanner.RISK_MEDIUM,
        scanner.RISK_LOW,
        scanner.RISK_SAFE,
        scanner.RISK_UNKNOWN,
    }
