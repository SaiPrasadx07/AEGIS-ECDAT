"""
Aegis PQC — ECDAT Phase 10 tests: GUI service adapter and view helpers.

The GUI is presentation only; these tests exercise the pieces that carry logic
— the pipeline adapter and the pure formatting helpers — directly, without
rendering Streamlit, plus a light AppTest smoke check that the surfaces wire up.
The most important test here is that the frozen Security Lab is byte-for-byte
unchanged.

Run Phase 10 only:  pytest tests/ecdat/test_phase10.py -q
Run all ECDAT:      pytest tests/ecdat -q
Run everything:     pytest tests -q
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest

from backend import ecdat_service as svc
from backend.discovery import binary
from backend.model import MigrationPriority
from frontend import ecdat_view as view

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture(scope="module")
def estate(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The demo estate built through the service adapter's own helper."""
    root = tmp_path_factory.mktemp("phase10_estate")
    return svc.build_demo_estate(root)


@pytest.fixture(scope="module")
def pipeline(estate: Path) -> svc.PipelineResult:
    """One full pipeline run over the demo estate."""
    return svc.run_pipeline(estate)


# ==========================================================================
# Service adapter — orchestration only
# ==========================================================================


def test_pipeline_runs_end_to_end(pipeline: svc.PipelineResult) -> None:
    """Claim: the adapter produces every stage's output, aligned."""
    assert pipeline.findings
    assert len(pipeline.risks) == len(pipeline.findings)
    assert len(pipeline.recommendations) == len(pipeline.findings)
    assert len(pipeline.priorities) == len(pipeline.findings)
    assert pipeline.roadmap


def test_pipeline_is_deterministic(estate: Path) -> None:
    """Claim: two runs over the same estate produce identical results."""
    first = svc.run_pipeline(estate)
    second = svc.run_pipeline(estate)
    assert [f.finding_id for f in first.findings] == [f.finding_id for f in second.findings]
    assert [r.to_dict() for r in first.risks] == [r.to_dict() for r in second.risks]
    assert [p.to_dict() for p in first.priorities] == [p.to_dict() for p in second.priorities]


def test_missing_target_yields_error_not_exception(tmp_path: Path) -> None:
    """Claim: a bad target returns an error-carrying result, not a crash."""
    result = svc.run_pipeline(tmp_path / "nope")
    assert result.is_empty
    assert result.errors


def test_overview_metrics_match_backend(pipeline: svc.PipelineResult) -> None:
    """Claim: overview metrics are consistent with the underlying results."""
    m = svc.overview_metrics(pipeline)
    assert m["total_findings"] == len(pipeline.findings)
    assert m["quantum_vulnerable"] == sum(
        1 for r in pipeline.risks if r.quantum_category.value == "quantum_vulnerable"
    )
    assert m["immediate"] == sum(
        1 for p in pipeline.priorities if p.priority is MigrationPriority.IMMEDIATE
    )


def test_cbom_stats_come_from_generated_cbom(pipeline: svc.PipelineResult) -> None:
    """Claim: CBOM stats are read from the actual generated document."""
    stats = svc.cbom_stats(pipeline)
    document = json.loads(svc.cbom_document(pipeline))
    assert stats["components"] == len(document["components"])


def test_migration_items_exclude_no_action(pipeline: svc.PipelineResult) -> None:
    """Claim: NO_ACTION findings are not presented as migration work."""
    items = svc.migration_items(pipeline)
    assert all(i.priority is not MigrationPriority.NO_ACTION for i in items)


def test_content_portal_absent_from_results(pipeline: svc.PipelineResult) -> None:
    """Claim: the clean application contributes nothing."""
    assert not any(f.component == "content-portal" for f in pipeline.findings)


def test_assumptions_view_shows_provenance(pipeline: svc.PipelineResult) -> None:
    """Claim: assumptions carry provenance, and a missing one says so."""
    rows = svc.assumptions_view(pipeline)
    crqc = next(r for r in rows if r["name"] == "CRQC horizon")
    assert crqc["value"] == "10 years"
    assert crqc["provenance"] == "policy_file"
    lifetime = next(r for r in rows if r["name"] == "Default data lifetime")
    assert lifetime["provenance"] == "missing"


def test_context_view_preserves_declared_flag(pipeline: svc.PipelineResult) -> None:
    """Claim: per-component context carries its declared/default provenance."""
    rows = svc.context_view(pipeline)
    assert rows
    assert all("provenance" in r and "is_declared" in r for r in rows)


# ==========================================================================
# View helpers — pure formatting, no invention
# ==========================================================================


def test_inventory_row_keeps_unknowns_visible(pipeline: svc.PipelineResult) -> None:
    """Claim: an unknown field renders as the unknown sentinel, not a guess."""
    # An RSA source finding with no key size should show — for key_size.
    unknown_size = [
        f for f in pipeline.findings
        if f.algorithm == "RSA" and f.key_size is None and f.source_type.value == "source_code"
    ]
    if unknown_size:
        row = view.inventory_row(unknown_size[0])
        assert row["key_size"] == view.UNKNOWN_DISPLAY


def test_inventory_row_marks_capability_distinctly(pipeline: svc.PipelineResult) -> None:
    """Claim: a library capability is never shown as a confirmed algorithm."""
    capability = [
        f for f in pipeline.findings
        if f.artefact_type.value == "library" and not f.algorithm
    ]
    assert capability
    row = view.inventory_row(capability[0])
    assert row["algorithm"] == "capability only"


def test_inventory_filters_only_offer_real_values(pipeline: svc.PipelineResult) -> None:
    """Claim: filter options are exactly the distinct values in the data."""
    options = view.inventory_filter_options(pipeline.findings)
    real_sources = {f.source_type.value for f in pipeline.findings}
    assert set(options["source_type"]) == real_sources


def test_inventory_filter_narrows(pipeline: svc.PipelineResult) -> None:
    """Claim: applying a filter reduces the result set correctly."""
    filtered = view.apply_inventory_filters(
        pipeline.findings, {"component": "payments-api"}
    )
    assert filtered
    assert all(f.component == "payments-api" for f in filtered)


def test_mosca_view_reports_insufficient_without_substituting() -> None:
    """Claim: a missing Mosca result is shown as insufficient, no fake numbers."""
    from backend.model import QuantumRiskResult, QuantumCategory, MoscaStatus, RiskLevel

    risk = QuantumRiskResult(
        finding_id="f",
        component="c",
        algorithm="RSA",
        quantum_category=QuantumCategory.QUANTUM_VULNERABLE,
        risk_level=RiskLevel.HIGH,
        mosca_status=MoscaStatus.INSUFFICIENT_INFORMATION,
        mosca=None,
    )
    v = view.mosca_view(risk)
    assert v["available"] is False
    assert v["x"] is None and v["y"] is None and v["z"] is None
    assert "insufficient" in v["statement"].lower()


def test_risk_row_does_not_recompute(pipeline: svc.PipelineResult) -> None:
    """Claim: a risk row reflects the backend result verbatim."""
    risk = pipeline.risks[0]
    row = view.risk_row(risk)
    assert row["risk_level"] == risk.risk_level.value
    assert row["mosca_status"] == risk.mosca_status.value


def test_ordered_roadmap_uses_fixed_bucket_order(pipeline: svc.PipelineResult) -> None:
    """Claim: roadmap buckets appear in the fixed priority order."""
    ordered = view.ordered_roadmap(pipeline.roadmap)
    labels = [b["bucket"] for b in ordered]
    # The order must be a subsequence of the canonical order.
    canonical = list(view.ROADMAP_BUCKET_ORDER)
    positions = [canonical.index(b) for b in labels]
    assert positions == sorted(positions)


def test_priority_distribution_is_ordered_by_urgency(pipeline: svc.PipelineResult) -> None:
    """Claim: the priority chart data is ordered most-urgent first."""
    dist = view.priority_distribution(pipeline.priorities)
    keys = list(dist)
    if "Immediate" in keys and "Monitor" in keys:
        assert keys.index("Immediate") < keys.index("Monitor")


def test_view_helpers_never_leak_secret_material(pipeline: svc.PipelineResult) -> None:
    """Claim: no rendered row carries key material."""
    blob = json.dumps(
        [view.inventory_row(f) for f in pipeline.findings]
        + [view.risk_row(r) for r in pipeline.risks]
        + [view.recommendation_row(r) for r in pipeline.recommendations]
        + [view.priority_row(p) for p in pipeline.priorities]
    )
    for marker in ("-----BEGIN", "PRIVATE KEY", "password", "secret_key"):
        assert marker.lower() not in blob.lower()


# ==========================================================================
# The frozen Security Lab must be untouched
# ==========================================================================


def test_security_lab_files_are_unchanged() -> None:
    """Claim: the frozen Security Lab files are byte-for-byte unchanged.

    ``frontend/app.py`` is the HNDL/Q-Day dashboard and must not be modified by
    Phase 10. This pins its hash; any edit fails the build.
    """
    app_hash = hashlib.sha256((REPO_ROOT / "frontend" / "app.py").read_bytes()).hexdigest()
    assert app_hash.startswith("aa8a53cc3f4c83826d2a990b"), (
        "frontend/app.py (frozen Security Lab) was modified"
    )


def test_ui_module_is_unchanged() -> None:
    """Claim: the shared ui.py design system is unchanged.

    ECDAT reuses ui.py but must not alter it — the Security Lab depends on it.
    """
    ui_hash = hashlib.sha256((REPO_ROOT / "frontend" / "ui.py").read_bytes()).hexdigest()
    assert ui_hash.startswith("0a10743cf0307123b6a98908"), (
        "frontend/ui.py was modified"
    )


def test_ecdat_app_is_a_separate_entry_point() -> None:
    """Claim: ECDAT is its own app, not tabs bolted into the frozen one."""
    assert (REPO_ROOT / "frontend" / "ecdat_app.py").exists()
    # The frozen app must not import the ECDAT app or service.
    frozen = (REPO_ROOT / "frontend" / "app.py").read_text(encoding="utf-8")
    assert "ecdat_app" not in frozen
    assert "ecdat_service" not in frozen


# ==========================================================================
# App wiring (AppTest smoke)
# ==========================================================================


@pytest.fixture(scope="module")
def app_after_load():
    """The ECDAT app rendered with the demo estate loaded."""
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file(str(REPO_ROOT / "frontend" / "ecdat_app.py"), default_timeout=400)
    app.run()
    button = [b for b in app.button if b.label == "LOAD DEMO ESTATE"]
    if button:
        button[0].click().run()
    return app


def test_app_renders_without_exception(app_after_load) -> None:
    """Claim: the app renders and loads the demo with no exceptions."""
    assert not app_after_load.exception, [str(e.value) for e in app_after_load.exception]


def test_app_has_all_ecdat_surfaces(app_after_load) -> None:
    """Claim: the nine ECDAT surfaces plus the Security Lab link are present."""
    labels = [t.label for t in app_after_load.tabs]
    for expected in (
        "Overview", "Discovery", "Inventory", "CBOM", "Quantum Risk",
        "Recommendations", "Migration", "Reports", "Settings", "Security Lab",
    ):
        assert expected in labels


def test_app_exposes_downloads_after_load(app_after_load) -> None:
    """Claim: report/CBOM downloads are wired once a scan is loaded."""
    assert len(app_after_load.download_button) >= 5


def test_app_renders_data_tables(app_after_load) -> None:
    """Claim: inventory/risk/recommendation tables render with data."""
    assert len(app_after_load.dataframe) >= 3


def test_empty_state_renders_without_scan() -> None:
    """Claim: before any scan, the app renders a prompt, not a crash."""
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file(str(REPO_ROOT / "frontend" / "ecdat_app.py"), default_timeout=200)
    app.run()
    assert not app.exception
    assert len(app.tabs) == 10


# ==========================================================================
# Safety
# ==========================================================================


def test_gui_layer_performs_no_execution() -> None:
    """Claim: neither the service adapter nor the app introduces execution.

    AST-checked: no subprocess, socket, or package manager in the GUI-facing
    modules. Discovery safety comes from the Phase 1–5 adapters unchanged.
    """
    for module_path in (
        REPO_ROOT / "backend" / "ecdat_service.py",
        REPO_ROOT / "frontend" / "ecdat_view.py",
        REPO_ROOT / "frontend" / "ecdat_app.py",
    ):
        tree = ast.parse(module_path.read_text(encoding="utf-8"))
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
        assert not (imported & {"subprocess", "socket", "urllib", "requests", "docker"}), module_path.name
        assert not (called & {"system", "popen", "run", "eval", "exec", "urlopen"}), module_path.name


def test_view_module_imports_without_streamlit() -> None:
    """Claim: the view helpers are importable without Streamlit.

    This is what lets them be unit-tested directly, and proves no Streamlit
    call leaked into the pure-formatting layer.
    """
    source = (REPO_ROOT / "frontend" / "ecdat_view.py").read_text(encoding="utf-8")
    assert "import streamlit" not in source
    assert "st." not in source
