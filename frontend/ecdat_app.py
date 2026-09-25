"""
Aegis PQC — ECDAT interactive dashboard.

The presentation layer for the Enterprise Cryptographic Discovery & Analysis
Tool. It renders the results of the established backend pipeline — discovery,
inventory, CBOM, quantum risk, recommendations, migration prioritisation, and
roadmap — and computes nothing itself.

Run it:

    streamlit run frontend/ecdat_app.py

This is a **separate entry point** from ``frontend/app.py``. That file is the
frozen Security Lab (the HNDL and Q-Day demonstrations) and is not touched by
this dashboard; a judge reaches the Security Lab by launching it, and this app
links to it from its own Security Lab surface. Keeping them as two apps is what
lets ECDAT be purely additive.

ARCHITECTURE
------------
    ecdat_app.py  (this file — Streamlit rendering only)
          ↓
    frontend/ecdat_view.py  (pure formatting helpers, tested directly)
          ↓
    backend/ecdat_service.py  (thin pipeline orchestration)
          ↓
    the ECDAT backend  (the single source of truth)

Nothing here scans, assesses, recommends, or prioritises. Every figure comes
from the backend through the service adapter. The design vocabulary is the
existing :mod:`frontend.ui` module, so ECDAT and the Security Lab share one
look without sharing code.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

# Make the repo root importable when Streamlit runs this file directly, matching
# the frozen Security Lab app's own path setup.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from backend import cbom
from backend import ecdat_service as svc
from frontend import ecdat_style as sx
from frontend import ecdat_view as view
from frontend import ui

st.set_page_config(
    page_title="Aegis PQC — ECDAT",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

ui.inject_css()
sx.inject()

# One-time cinematic boot overlay per session.
if not st.session_state.get("_booted"):
    sx.boot_overlay()
    st.session_state["_booted"] = True


# ==========================================================================
# Pipeline state (cached, computed once per load / reset)
# ==========================================================================


def _load_demo() -> svc.PipelineResult:
    """Materialise the demo estate and run the full pipeline over it."""
    root = Path(tempfile.mkdtemp(prefix="aegis_ecdat_demo_"))
    svc.build_demo_estate(root)
    return svc.run_pipeline(root)


def get_pipeline() -> svc.PipelineResult | None:
    """The current pipeline result from session state, or None."""
    return st.session_state.get("ecdat_pipeline")


# ==========================================================================
# Sidebar rail
# ==========================================================================

with st.sidebar:
    sx.brand_rail()

    if st.button("LOAD DEMO ESTATE", type="primary", width="stretch"):
        with st.spinner("Discovering, assessing, and prioritising..."):
            st.session_state["ecdat_pipeline"] = _load_demo()
        st.success("Demo estate scanned end to end.")

    pipeline = get_pipeline()

    ui.rail_label("Pipeline")
    ui.rail_workflow(
        [
            {"name": "DISCOVER", "surface": "5 surfaces", "implemented": True},
            {"name": "INVENTORY", "surface": "unified", "implemented": True},
            {"name": "CBOM", "surface": "CycloneDX 1.6", "implemented": True},
            {"name": "QUANTUM RISK", "surface": "Mosca", "implemented": True},
            {"name": "RECOMMEND", "surface": "role-aware", "implemented": True},
            {"name": "PRIORITISE", "surface": "roadmap", "implemented": True},
        ]
    )

    if pipeline and not pipeline.is_empty:
        metrics = svc.overview_metrics(pipeline)
        ui.rail_label("Current scan")
        ui.rail_rows(
            [
                ("Findings", str(metrics["total_findings"]), ui.TEXT),
                ("Components", str(metrics["components"]), ui.TEXT),
                ("Quantum-vulnerable", str(metrics["quantum_vulnerable"]), ui.CRITICAL),
                ("PQC-ready", str(metrics["post_quantum"]), ui.GREEN),
                ("Immediate", str(metrics["immediate"]), ui.CRITICAL if metrics["immediate"] else ui.MUTED),
            ]
        )
    else:
        st.caption("Load the demo estate to begin.")


# ==========================================================================
# Header
# ==========================================================================

pipeline = get_pipeline()

if pipeline and not pipeline.is_empty:
    m = svc.overview_metrics(pipeline)
    sx.app_header(
        [
            {"label": "Findings", "value": str(m["total_findings"]), "colour": sx.CYAN},
            {"label": "Quantum-vulnerable", "value": str(m["quantum_vulnerable"]), "colour": sx.CRITICAL},
            {"label": "Actionable", "value": str(m["actionable"]), "colour": sx.AMBER},
            {"label": "Immediate", "value": str(m["immediate"]), "colour": sx.CRITICAL if m["immediate"] else sx.MUTED},
        ]
    )
else:
    sx.app_header([{"label": "Status", "value": "AWAITING SCAN", "colour": sx.AMBER}])


(
    tab_overview,
    tab_discovery,
    tab_inventory,
    tab_cbom,
    tab_risk,
    tab_recs,
    tab_migration,
    tab_reports,
    tab_settings,
    tab_lab,
) = st.tabs(
    [
        "Overview",
        "Discovery",
        "Inventory",
        "CBOM",
        "Quantum Risk",
        "Recommendations",
        "Migration",
        "Reports",
        "Settings",
        "Security Lab",
    ]
)


def _require_scan() -> svc.PipelineResult | None:
    """Return the pipeline, or render an empty-state prompt and return None."""
    pipeline = get_pipeline()
    if pipeline is None or pipeline.is_empty:
        ui.note(
            "No scan loaded yet. Use <b>LOAD DEMO ESTATE</b> in the sidebar to run "
            "the full pipeline over the demonstration applications.",
            ui.CYAN,
        )
        return None
    return pipeline


# ==========================================================================
# OVERVIEW
# ==========================================================================

with tab_overview:
    sx.hero(
        "Cryptographic posture, discovered and quantified.",
        "Aegis discovers where cryptography lives across an application estate, "
        "assesses quantum exposure with an explicit Mosca time-horizon analysis, "
        "explains technically appropriate remediation, and turns those "
        "conclusions into an evidence-aware migration roadmap. Every figure is "
        "derived from the current scan.",
    )

    pipeline = _require_scan()
    if pipeline:
        m = svc.overview_metrics(pipeline)
        total = max(m["total_findings"], 1)
        sx.posture_command(
            [
                {"label": "Crypto findings", "value": m["total_findings"], "colour": sx.CYAN},
                {"label": "Components", "value": m["components"], "colour": sx.ICE},
                {
                    "label": "Quantum risk", "value": m["quantum_vulnerable"],
                    "colour": sx.CRITICAL, "emphasis": True,
                    "ring": round(m["quantum_vulnerable"] / total * 100),
                },
                {"label": "PQC-ready", "value": m["post_quantum"], "colour": sx.GREEN},
                {
                    "label": "Immediate", "value": m["immediate"], "colour": sx.CRITICAL,
                    "note": "earliest attention", "emphasis": bool(m["immediate"]),
                },
                {"label": "Actionable", "value": m["actionable"], "colour": sx.AMBER},
            ]
        )

        sx.pipeline_ribbon()

        ui.note(
            "<b>Discover</b> finds cryptography across certificates, "
            "dependencies, source, binaries, and containers. <b>Inventory</b> "
            "unifies it with declared context. <b>CBOM</b> exports a standard "
            "CycloneDX 1.6 bill of materials. <b>Quantum Risk</b> classifies each "
            "asset and runs Mosca. <b>Recommend</b> gives role-aware remediation. "
            "<b>Prioritise</b> and <b>Roadmap</b> apply declared organisational "
            "context to sequence the work.",
            ui.CYAN,
        )

        col_a, col_b = st.columns(2)
        with col_a:
            ui.section("Findings by discovery surface", eyebrow="Where cryptography was found")
            dist = view.source_type_distribution(pipeline.findings)
            labels = {
                "certificate_file": "Certificates", "dependency": "Dependencies",
                "source_code": "Source", "binary": "Binary", "container": "Container",
            }
            figure = go.Figure(
                go.Bar(
                    x=[dist[k] for k in dist],
                    y=[labels.get(k, k) for k in dist],
                    orientation="h",
                    marker=dict(color=sx.CYAN, line=dict(width=0)),
                    text=[dist[k] for k in dist],
                    textposition="outside",
                    textfont=dict(family=sx.MONO, size=12),
                )
            )
            st.plotly_chart(ui.chart_layout(figure, 230), width="stretch")
        with col_b:
            ui.section("Quantum category distribution", eyebrow="What the assets are")
            qdist = view.quantum_category_distribution(pipeline.risks)
            colours = [
                view.QUANTUM_CATEGORY_COLOUR.get(
                    next((k for k, v in view.QUANTUM_CATEGORY_LABEL.items() if v == label), ""),
                    sx.GREY,
                )
                for label in qdist
            ]
            figure = go.Figure(
                go.Bar(
                    x=list(qdist.values()),
                    y=list(qdist),
                    orientation="h",
                    marker=dict(color=colours, line=dict(width=0)),
                    text=list(qdist.values()),
                    textposition="outside",
                    textfont=dict(family=sx.MONO, size=12),
                )
            )
            st.plotly_chart(ui.chart_layout(figure, 230), width="stretch")


# ==========================================================================
# DISCOVERY
# ==========================================================================

with tab_discovery:
    sx.hero(
        "Five discovery surfaces.",
        "Each scanner declares its own coverage and the evidence it establishes. "
        "Nothing is executed; every scanner respects its safety limits.",
        tag="DISCOVER",
    )

    pipeline = _require_scan()
    if pipeline:
        m = svc.overview_metrics(pipeline)
        sx.discovery_nodes(
            [
                {"name": "Certificates", "count": m["certificates"], "detail": "PEM · DER · OID", "colour": sx.CYAN},
                {"name": "Dependencies", "count": m["dependencies"], "detail": "manifests · capability", "colour": sx.VIOLET},
                {"name": "Source", "count": m["source_findings"], "detail": "AST · call-site", "colour": sx.GREEN},
                {"name": "Binary", "count": m["binary_findings"], "detail": "ELF · symbols", "colour": sx.AMBER},
                {"name": "Container", "count": m["container_findings"], "detail": "Docker · OCI", "colour": sx.ICE},
            ]
        )

        sx.console_table(
            ["Surface", "What it reads", "Evidence it establishes"],
            [
                [sx.chip("Certificates", sx.CYAN), "PEM, DER, JSON manifests", "Algorithm by OID · VERIFIED vs DECLARED"],
                [sx.chip("Dependencies", sx.VIOLET), "requirements.txt · package.json · pom.xml · go.mod", "Declared library + version — capability, not usage"],
                [sx.chip("Source", sx.GREEN), "Python AST · JS/TS · Java · Go", "Import vs call-site vs configuration usage"],
                [sx.chip("Binary", sx.AMBER), "ELF via LIEF", "Linked library · imported symbol · version string"],
                [sx.chip("Container", sx.ICE), "Docker / OCI archives", "Runs the four surfaces over merged layers"],
            ],
            rail_colours=[sx.CYAN, sx.VIOLET, sx.GREEN, sx.AMBER, sx.ICE],
        )

        if pipeline.errors:
            ui.section("Scan notes", eyebrow="Status")
            for err in pipeline.errors[:20]:
                st.caption(err)
        else:
            ui.note("Scan completed with no errors across all surfaces.", ui.GREEN)


# ==========================================================================
# INVENTORY
# ==========================================================================

with tab_inventory:
    sx.hero(
        "Unified cryptographic inventory.",
        "Every finding in one canonical model. Unknown values stay unknown, and "
        "a library capability is never shown as confirmed usage.",
        tag="INVENTORY",
    )

    pipeline = _require_scan()
    if pipeline:
        options = view.inventory_filter_options(pipeline.findings)
        c1, c2, c3 = st.columns(3)
        with c1:
            f_component = st.selectbox("Component", ["All"] + options["component"])
            f_source = st.selectbox("Source type", ["All"] + options["source_type"])
        with c2:
            f_algorithm = st.selectbox("Algorithm", ["All"] + options["algorithm"])
            f_evidence = st.selectbox("Evidence level", ["All"] + options["evidence_level"])
        with c3:
            f_confidence = st.selectbox("Confidence", ["All"] + options["confidence"])
            query = st.text_input("Search", placeholder="finding id, algorithm, library").strip().lower()

        filtered = view.apply_inventory_filters(
            pipeline.findings,
            {
                "component": f_component,
                "algorithm": f_algorithm,
                "source_type": f_source,
                "evidence_level": f_evidence,
                "confidence": f_confidence,
            },
        )
        if query:
            filtered = [
                f
                for f in filtered
                if query in " ".join(
                    str(x).lower()
                    for x in (f.finding_id, f.algorithm, f.library, f.component)
                )
            ]

        st.caption(f"Showing {len(filtered)} of {len(pipeline.findings)} findings.")

        if filtered:
            conf_colour = {"high": sx.GREEN, "medium": sx.AMBER, "low": sx.GREY}
            rows, rails = [], []
            for f in filtered:
                d = view.inventory_row(f)
                rows.append(
                    [
                        d["component"],
                        sx.chip(d["algorithm"], sx.CYAN if d["algorithm"] != "capability only" else sx.VIOLET),
                        d["role"], d["key_size"], d["source_type"],
                        sx.chip(d["evidence_level"], sx.DIM) if d["evidence_level"] != "—" else "—",
                        sx.chip(d["confidence"].upper(), conf_colour.get(f.confidence.value, sx.GREY)),
                    ]
                )
                rails.append(conf_colour.get(f.confidence.value, sx.GREY))
            sx.console_table(
                ["Component", "Algorithm", "Role", "Key size", "Source", "Evidence", "Confidence"],
                rows, rail_colours=rails,
            )
            with st.expander("Full tabular view (all fields)"):
                st.dataframe(
                    pd.DataFrame([view.inventory_row(f) for f in filtered]),
                    width="stretch", hide_index=True,
                )

            ui.section("Finding detail", eyebrow="Evidence")
            risk_index = svc.risk_by_finding(pipeline)
            chosen = st.selectbox(
                "Inspect a finding",
                [f.finding_id for f in filtered],
                format_func=lambda fid: f"{fid} · "
                + next((f.algorithm or f.library or "—" for f in filtered if f.finding_id == fid), ""),
            )
            finding = next(f for f in filtered if f.finding_id == chosen)
            detail = view.inventory_row(finding)
            ui.panel(
                title=detail["algorithm"],
                meta=finding.finding_id,
                body=finding.evidence[:200],
                accent=view.CONFIDENCE_COLOUR.get(finding.confidence.value, ui.GREY),
                badges=ui.pill(finding.confidence.value.upper(), view.CONFIDENCE_COLOUR.get(finding.confidence.value, ui.GREY)),
                kv=[
                    ("Component", detail["component"]),
                    ("Role", detail["role"]),
                    ("Key size", detail["key_size"]),
                    ("Mode", detail["mode"]),
                    ("Source", detail["source_type"]),
                    ("Detection", detail["detection_method"]),
                    ("Evidence level", detail["evidence_level"]),
                    ("OID", detail["oid"]),
                    ("Library", detail["library"]),
                ],
            )
        else:
            st.info("No findings match the current filters.")


# ==========================================================================
# CBOM
# ==========================================================================

with tab_cbom:
    sx.hero(
        "Cryptography Bill of Materials.",
        "A standards-compliant CycloneDX 1.6 CBOM generated from the canonical "
        "inventory — validated against the published schema, deterministic for a "
        "given inventory.",
        tag="CBOM",
        accent=sx.VIOLET,
    )

    pipeline = _require_scan()
    if pipeline:
        stats = svc.cbom_stats(pipeline)
        ui.cards(
            [
                {"label": "Components", "value": stats["components"], "colour": ui.CYAN},
                {"label": "Crypto assets", "value": stats["crypto_assets"], "colour": ui.CYAN},
                {"label": "Libraries", "value": stats["libraries"], "colour": ui.VIOLET},
                {"label": "Capability-only", "value": stats["capability_only"], "colour": ui.VIOLET, "note": "usage not established"},
            ]
        )

        document = svc.cbom_document(pipeline)
        errors = cbom.validate_cbom(document)
        if errors:
            sx.validity_seal(False, f"Schema validation failed: {errors[0][:60]}")
        else:
            sx.validity_seal(True, "Validated against the CycloneDX 1.6 schema")

        st.download_button(
            "Download CBOM (CycloneDX 1.6 JSON)",
            data=document,
            file_name="aegis_cbom.cdx.json",
            mime="application/json",
        )
        with st.expander("Preview CBOM"):
            st.code(document[:6000], language="json")


# ==========================================================================
# QUANTUM RISK
# ==========================================================================

with tab_risk:
    sx.hero(
        "Quantum risk & Mosca analysis.",
        "Each asset's relationship with a cryptographically relevant quantum "
        "computer, with an explicit Mosca time-horizon analysis. Displayed from "
        "the backend result — never recomputed here.",
        tag="QUANTUM RISK",
        accent=sx.AMBER,
    )

    pipeline = _require_scan()
    if pipeline:
        cat_colour = view.QUANTUM_CATEGORY_COLOUR
        conf_colour = {"high": sx.GREEN, "medium": sx.AMBER, "low": sx.GREY}
        rows, rails = [], []
        for r in pipeline.risks:
            row = view.risk_row(r)
            rows.append(
                [
                    row["component"],
                    row["algorithm"],
                    sx.chip(row["quantum_category"], cat_colour.get(r.quantum_category.value, sx.GREY)),
                    sx.chip(row["risk_level"], view.RISK_LEVEL_COLOUR.get(r.risk_level.value, sx.GREY)),
                    row["mosca_status"].replace("_", " "),
                    sx.chip(row["confidence"].upper(), conf_colour.get(r.confidence.value, sx.GREY)),
                ]
            )
            rails.append(view.RISK_LEVEL_COLOUR.get(r.risk_level.value, sx.GREY))
        sx.console_table(
            ["Component", "Algorithm", "Category", "Risk", "Mosca", "Confidence"],
            rows, rail_colours=rails,
        )
        with st.expander("Full tabular view (all fields)"):
            st.dataframe(
                pd.DataFrame([view.risk_row(r) for r in pipeline.risks]),
                width="stretch", hide_index=True,
            )

        ui.note(
            "<b>Mosca:</b> data lifetime (X) + migration time (Y) &gt; CRQC horizon (Z). "
            "When X + Y crosses the assumed threat window the asset is within it. "
            "A missing input yields <b>INSUFFICIENT_INFORMATION</b> — no value is "
            "substituted. The CRQC horizon is an assumption, shown on the "
            "Settings surface with its provenance.",
            ui.CYAN,
        )

        ui.section("Mosca detail", eyebrow="Time-horizon analysis")
        vulnerable = [r for r in pipeline.risks if r.quantum_category.value == "quantum_vulnerable"]
        if vulnerable:
            chosen = st.selectbox(
                "Inspect a quantum-vulnerable asset",
                [r.finding_id for r in vulnerable],
                format_func=lambda fid: f"{fid} · "
                + next((r.algorithm for r in vulnerable if r.finding_id == fid), ""),
            )
            risk = next(r for r in vulnerable if r.finding_id == chosen)
            mosca = view.mosca_view(risk)
            if mosca["available"]:
                # Labels reflect the backend's actual meaning for each value:
                # mosca["x"] is data confidentiality lifetime, mosca["y"] is
                # migration time. The Mosca math is untouched; only the display
                # labels the bars correctly.
                sx.mosca_horizon(
                    "Data lifetime", mosca["x"],
                    "Migration time", mosca["y"],
                    "CRQC horizon", mosca["z"],
                    within=mosca["status"] == "within_quantum_window",
                    statement=mosca["statement"],
                )
            else:
                sx.mosca_insufficient()

            ui.panel(
                title=f"{risk.algorithm} — {view.QUANTUM_CATEGORY_LABEL.get(risk.quantum_category.value)}",
                meta=risk.finding_id,
                accent=view.RISK_LEVEL_COLOUR.get(risk.risk_level.value, ui.GREY),
                badges=ui.risk_pill(risk.risk_level.value),
            )
            st.markdown("**Rationale**")
            for line in risk.rationale:
                st.markdown(f"- {line}")
            with st.expander("Assumptions & provenance"):
                for a in risk.assumptions:
                    st.markdown(
                        f"- **{a.name}**: {a.value if a.value is not None else 'missing'} "
                        f"({a.unit}) · {a.provenance}"
                        + (" · default" if a.is_default else "")
                    )
        else:
            st.info("No quantum-vulnerable assets in the current scan.")


# ==========================================================================
# RECOMMENDATIONS
# ==========================================================================

with tab_recs:
    sx.hero(
        "Remediation recommendations.",
        "Role-aware remediation directions from the backend. A recommendation "
        "toward a hybrid is a direction, not a claim that a hybrid is deployed.",
        tag="RECOMMENDATIONS",
    )

    pipeline = _require_scan()
    if pipeline:
        rem_colour = {
            "pqc_native": sx.GREEN, "hybrid": sx.CYAN,
            "classical_strengthening": sx.AMBER, "non_quantum_issue": sx.HIGH,
            "none_required": sx.GREY, "usage_not_established": sx.VIOLET,
            "insufficient_evidence": sx.VIOLET,
        }
        rows, rails = [], []
        for r in pipeline.recommendations:
            row = view.recommendation_row(r)
            colour = rem_colour.get(r.remediation_class.value, sx.GREY)
            rows.append(
                [
                    row["component"], row["current_algorithm"], row["role"],
                    sx.chip(row["remediation_class"], colour),
                    row["target"], row["target_standard"],
                ]
            )
            rails.append(colour)
        sx.console_table(
            ["Component", "Current", "Role", "Remediation", "Target", "Standard"],
            rows, rail_colours=rails,
        )
        with st.expander("Full tabular view (all fields)"):
            st.dataframe(
                pd.DataFrame([view.recommendation_row(r) for r in pipeline.recommendations]),
                width="stretch", hide_index=True,
            )

        ui.section("Recommendation detail", eyebrow="Rationale")
        actionable = [
            r for r in pipeline.recommendations
            if r.remediation_class.value not in ("none_required",)
        ]
        if actionable:
            chosen = st.selectbox(
                "Inspect a recommendation",
                [r.finding_id for r in actionable],
                format_func=lambda fid: f"{fid} · "
                + next((view.REMEDIATION_LABEL.get(r.remediation_class.value, "") for r in actionable if r.finding_id == fid), ""),
            )
            r = next(x for x in actionable if x.finding_id == chosen)
            ui.panel(
                title=view.REMEDIATION_LABEL.get(r.remediation_class.value, r.remediation_class.value),
                meta=r.finding_id,
                accent=ui.CYAN,
                badges=ui.pill(r.remediation_class.value.upper(), ui.CYAN),
                kv=[
                    ("Current", r.current_algorithm or "—"),
                    ("Role", r.role or "—"),
                    ("Target", r.target or "—"),
                    ("Standard", r.target_standard or "—"),
                    ("Confidence", r.confidence.value),
                ],
            )
            st.markdown("**Rationale**")
            for line in r.rationale:
                st.markdown(f"- {line}")
            if r.limitations:
                st.markdown("**Limitations**")
                for line in r.limitations:
                    st.markdown(f"- {line}")
            if r.additional_evidence_required:
                st.markdown("**Additional evidence required**")
                for line in r.additional_evidence_required:
                    st.markdown(f"- {line}")
            if r.performance_note:
                st.caption(r.performance_note)


# ==========================================================================
# MIGRATION
# ==========================================================================

with tab_migration:
    sx.hero(
        "Migration priorities & roadmap.",
        "Declared organisational context applied to the technical conclusions. "
        "Risk conclusion is not migration priority. Nothing is ranked within a "
        "bucket, and no dates, cost, or effort are invented.",
        tag="MIGRATION",
    )

    pipeline = _require_scan()
    if pipeline:
        psummary = svc.mp.summarize(pipeline.priorities) if hasattr(svc, "mp") else None
        dist = view.priority_distribution(pipeline.priorities)
        figure = go.Figure(
            go.Bar(
                x=list(dist),
                y=list(dist.values()),
                marker=dict(
                    color=[
                        view.PRIORITY_COLOUR.get(
                            next((k for k, v in view.PRIORITY_LABEL.items() if v == label), ""),
                            ui.GREY,
                        )
                        for label in dist
                    ],
                    line=dict(width=0),
                ),
                text=list(dist.values()),
                textposition="outside",
            )
        )
        st.plotly_chart(ui.chart_layout(figure, 240), width="stretch")

        ui.section("Roadmap", eyebrow="Grouped by priority · deterministic")
        buckets = view.ordered_roadmap(pipeline.roadmap)
        rec_index = svc.recommendation_by_finding(pipeline)
        priority_index = svc.priority_by_finding(pipeline)
        bucket_colour = {
            "immediate_attention": sx.CRITICAL, "near_term_migration": sx.HIGH,
            "planned_migration": sx.AMBER, "evidence_collection": sx.VIOLET,
            "monitoring": sx.CYAN,
        }
        cols = st.columns(min(len(buckets), 3)) if buckets else []
        for index, bucket in enumerate(buckets):
            colour = bucket_colour.get(bucket["bucket"], sx.CYAN)
            with cols[index % len(cols)]:
                items = []
                for item in bucket["items"][:12]:
                    rec = rec_index.get(item["finding_id"])
                    prio = priority_index.get(item["finding_id"])
                    crit = prio.business_criticality if prio else "—"
                    target = item.get("target") or "—"
                    algo = rec.current_algorithm if rec else ""
                    items.append(
                        f"<b>{item['component']}</b> · {algo}<br>"
                        f"<span style='color:{sx.MUTED};font-family:{sx.MONO};font-size:10px'>"
                        f"→ {target} · {crit}</span>"
                    )
                sx.roadmap_lane(bucket["label"], colour, bucket["count"], items)


# ==========================================================================
# REPORTS
# ==========================================================================

with tab_reports:
    sx.hero(
        "Reports & exports.",
        "Every export contains only backend-derived data. No organisation facts "
        "or risk conclusions are invented.",
        tag="REPORTS",
    )

    pipeline = _require_scan()
    if pipeline:
        c1, c2 = st.columns(2)
        with c1:
            st.download_button(
                "CBOM (CycloneDX 1.6 JSON)",
                data=svc.cbom_document(pipeline),
                file_name="aegis_cbom.cdx.json",
                mime="application/json",
                width="stretch",
            )
            st.download_button(
                "Inventory (CSV)",
                data=pd.DataFrame([view.inventory_row(f) for f in pipeline.findings]).to_csv(index=False),
                file_name="aegis_inventory.csv",
                mime="text/csv",
                width="stretch",
            )
            st.download_button(
                "Risk results (CSV)",
                data=pd.DataFrame([view.risk_row(r) for r in pipeline.risks]).to_csv(index=False),
                file_name="aegis_risk.csv",
                mime="text/csv",
                width="stretch",
            )
        with c2:
            st.download_button(
                "Recommendations (CSV)",
                data=pd.DataFrame([view.recommendation_row(r) for r in pipeline.recommendations]).to_csv(index=False),
                file_name="aegis_recommendations.csv",
                mime="text/csv",
                width="stretch",
            )
            st.download_button(
                "Migration priorities (CSV)",
                data=pd.DataFrame([view.priority_row(p) for p in pipeline.priorities]).to_csv(index=False),
                file_name="aegis_migration.csv",
                mime="text/csv",
                width="stretch",
            )
            st.download_button(
                "Full report (JSON)",
                data=json.dumps(
                    {
                        "overview": svc.overview_metrics(pipeline),
                        "risk": [r.to_dict() for r in pipeline.risks],
                        "recommendations": [r.to_dict() for r in pipeline.recommendations],
                        "priorities": [p.to_dict() for p in pipeline.priorities],
                        "roadmap": pipeline.roadmap,
                        "assumptions": svc.assumptions_view(pipeline),
                    },
                    indent=2,
                ),
                file_name="aegis_report.json",
                mime="application/json",
                width="stretch",
            )


# ==========================================================================
# SETTINGS
# ==========================================================================

with tab_settings:
    sx.hero(
        "Assumptions & organisational context.",
        "Every assumption the analysis rests on, shown with its provenance. A "
        "CRQC horizon is an assumption, never an observed fact.",
        tag="SETTINGS",
        accent=sx.MUTED,
    )

    pipeline = _require_scan()
    if pipeline:
        ui.section("Risk assumptions", eyebrow="Provenance")
        ui.table(
            ["Assumption", "Value", "Provenance"],
            [[a["name"], a["value"], a["provenance"]] for a in svc.assumptions_view(pipeline)],
        )

        ui.section("Declared organisation context", eyebrow="Per component")
        context_rows = svc.context_view(pipeline)
        if context_rows:
            ui.table(
                ["Component", "Data lifetime", "Sensitivity", "Business criticality", "Provenance"],
                [
                    [
                        c["component"],
                        f"{c['data_lifetime_years']}y",
                        c["data_sensitivity"],
                        c["business_criticality"],
                        c["provenance"] + ("" if c["is_declared"] else " (default)"),
                    ]
                    for c in context_rows
                ],
            )
        ui.note(
            "Business criticality is used only where an organisation declared it. "
            "An undeclared component is treated as unknown and can never reach the "
            "Immediate bucket on assumption alone.",
            ui.CYAN,
        )


# ==========================================================================
# SECURITY LAB (link to the frozen surface)
# ==========================================================================

with tab_lab:
    sx.hero(
        "Security Lab.",
        "The original HNDL and Q-Day demonstrations — a separate, frozen "
        "capability that motivates the post-quantum problem. It runs as its own "
        "application and is not modified by ECDAT.",
        tag="FROZEN SURFACE",
        accent=sx.VIOLET,
    )
    ui.note(
        "The Security Lab is a distinct Streamlit app. Launch it with:<br>"
        "<b>streamlit run frontend/app.py</b><br><br>"
        "It demonstrates Harvest-Now-Decrypt-Later interception and a live "
        "classical factorisation of a deliberately undersized modulus. ECDAT "
        "and the Security Lab share a visual language but no code — the Lab is "
        "unchanged by this dashboard.",
        ui.VIOLET,
    )
