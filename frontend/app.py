"""
AegisPQC — security operations console.

Seven surfaces, mapped onto the cryptographic migration workflow:

    Overview          Executive posture across every subsystem
    PQC Readiness     DISCOVER + ASSESS — what cryptography is deployed
    Migration Plan    PRIORITIZE + MIGRATE + VERIFY — what to fix, in what order
    Quantum Vault     PROTECT — what a post-quantum protected message looks like
    HNDL Hoard        HARVEST — what a passive adversary collects today
    Q-Day Simulator   SIMULATE — what happens to that archive later
    Benchmarks        The engineering trade-offs, measured

Run it:

    streamlit run frontend/app.py

LAYOUT
------
A persistent sidebar command rail carries the brand, live telemetry, the
workflow, and presentation control. The surfaces sit behind a segmented command
bar at the top of the content area.

The command bar is built on ``st.tabs``. A sidebar-radio navigation would render
only the active surface, which is marginally faster — but ``st.tabs`` keeps every
surface mounted, and the demo's reliability depends on that: a judge can jump
between surfaces mid-question with no re-render, and no interaction can land on
a surface that has not been built yet.

ARCHITECTURE
------------
This console calls :mod:`backend.service` directly, in-process. It does NOT talk
to the FastAPI server over HTTP. A demo needing two processes alive has two ways
to die in front of an audience — a port collision, a slow cold start, a firewall
prompt on an unfamiliar machine. FastAPI remains real and available at `/docs`,
but nothing here depends on it.

CACHING
-------
Streamlit re-runs the whole script on every interaction. Scanning the estate
takes a few hundred milliseconds, so derived results live in ``session_state``
and are invalidated explicitly on reset. No expensive key generation or re-scan
happens on an ordinary click.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Make the repo root importable when Streamlit runs this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from backend import config
from backend import scanner
from backend import service as svc
from backend import simulator as sim
from backend.service import ServiceError
from frontend import ui

# --------------------------------------------------------------------------
# Page setup
# --------------------------------------------------------------------------

st.set_page_config(
    page_title="AegisPQC — Post-Quantum Security Platform",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

ui.inject_css()
svc.ensure_ready()

# Self-heal on an empty database. Without this, a fresh checkout opens to empty
# surfaces and the Q-Day attack control does not exist at all, because there is
# nothing to attack. Seeding on first load means the console is presentable the
# instant it opens, on any machine, with no prior setup.
_autoseeded = False
if not svc.list_harvested():
    svc.reset_presentation_state()
    _autoseeded = True


ALGO_CHOICES = {
    config.ALGO_RSA_DEMO: "RSA · DEMO SCALE",
    config.ALGO_ML_KEM_768: "ML-KEM-768",
    config.ALGO_HYBRID: "HYBRID",
}

ALGO_STATUS = {
    config.ALGO_RSA_DEMO: ("VULNERABLE", ui.CRITICAL),
    config.ALGO_ML_KEM_768: ("POST-QUANTUM READY", ui.SAFE),
    config.ALGO_HYBRID: ("RECOMMENDED", ui.CYAN),
}

SHORT_LABELS = {
    config.ALGO_RSA_DEMO: "RSA-DEMO",
    config.ALGO_RSA_2048: "RSA-2048",
    config.ALGO_ML_KEM_768: "ML-KEM-768",
    config.ALGO_HYBRID: "Hybrid",
}


def is_safe(algorithm: str) -> bool:
    """True if the algorithm resists a cryptographically relevant quantum computer."""
    return algorithm not in config.QUANTUM_VULNERABLE_ALGORITHMS


def mono(text: str) -> str:
    """Wrap machine data in the monospace table style."""
    return f'<span class="mono">{text}</span>'


# --------------------------------------------------------------------------
# Cached derivations
# --------------------------------------------------------------------------


def cached(key: str, producer):
    """Return a cached value, computing it once per reset cycle."""
    if key not in st.session_state:
        st.session_state[key] = producer()
    return st.session_state[key]


def invalidate_cache() -> None:
    """Drop every cached derivation. Called after any state change."""
    for key in (
        "cache_assessment",
        "cache_plan",
        "cache_verify",
        "cache_exec",
        "scan",
        "last_sent",
    ):
        st.session_state.pop(key, None)


def get_assessment() -> dict:
    return cached("cache_assessment", svc.scan_demo_enterprise)


def get_plan() -> dict:
    return cached("cache_plan", lambda: svc.migration_plan(get_assessment()))


def get_verification() -> dict:
    return cached("cache_verify", lambda: svc.verify_migration_plan(get_plan()))


def get_executive() -> dict:
    return cached("cache_exec", svc.executive_summary)


# --------------------------------------------------------------------------
# Command rail
# --------------------------------------------------------------------------

stats = svc.harvest_stats()
workflow = svc.workflow()
state = svc.presentation_state_summary()

with st.sidebar:
    ui.rail_brand()

    if st.button("LOAD PRESENTATION DEMO", type="primary", width="stretch"):
        with st.spinner("Initialising demonstration state..."):
            summary = svc.reset_presentation_state()
        # Carry the confirmation across the rerun. Writing st.success() here and
        # then calling st.rerun() would discard the message before the presenter
        # sees it, which mid-demo reads as "did my click register?"
        st.session_state["reset_summary"] = summary
        invalidate_cache()
        st.rerun()

    reset_summary = st.session_state.pop("reset_summary", None)
    if reset_summary:
        st.success(
            f"Ready. {reset_summary['packet_count']} packets harvested, "
            f"{reset_summary['enterprise_assets']} enterprise assets available."
        )

    ui.rail_label("System status")
    ui.rail_rows(
        [
            ("Engine", "ACTIVE", ui.GREEN),
            ("Defense level", "POST-QUANTUM", ui.GREEN),
            ("Packets held", str(stats["total_packets"]), ui.TEXT),
            ("Vulnerable", str(stats["vulnerable_packets"]), ui.CRITICAL),
            ("PQC protected", str(stats["quantum_safe_packets"]), ui.GREEN),
            ("Breached", str(stats["already_breached"]), ui.AMBER if stats["already_breached"] else ui.MUTED),
        ]
    )

    ui.rail_label("Security workflow")
    ui.rail_workflow(workflow)

    ui.rail_label("Session")
    ui.rail_rows(
        [
            ("Demo modulus", f"{config.RSA_DEMO_PRIME_BITS * 2}-bit", ui.AMBER),
            ("Suite", "FIPS 203", ui.CYAN),
            ("Readiness", "ARMED" if state["ready"] else "STANDBY", ui.GREEN if state["ready"] else ui.AMBER),
        ]
    )

    if not state["ready"]:
        st.warning("Load the presentation demo before presenting.")
    if _autoseeded:
        st.caption("Archive was empty on load — demonstration state seeded.")


# --------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------

executive = get_executive()
estate = executive["estate"]
score = estate["readiness_score"]
score_colour = ui.GREEN if score >= 60 else ui.AMBER if score >= 30 else ui.CRITICAL

ui.header(
    [
        ("Engine", "ACTIVE", ui.GREEN),
        ("Posture", "POST-QUANTUM READY", ui.GREEN),
        ("Archive", f"{stats['total_packets']} PACKETS", ui.CRITICAL),
        ("Readiness", f"{score}/100", score_colour),
    ]
)


tab_overview, tab_scan, tab_migrate, tab_vault, tab_hoard, tab_qday, tab_bench = st.tabs(
    [
        "Overview",
        "PQC Readiness",
        "Migration Plan",
        "Quantum Vault",
        "HNDL Hoard",
        "Q-Day Simulator",
        "Benchmarks",
    ]
)


# ==========================================================================
# OVERVIEW
# ==========================================================================

with tab_overview:
    migration_view = executive["migration"]
    demonstration = executive["demonstration"]
    threat = executive["threat_model"]

    ui.section(
        "Aegis security posture",
        "Current state of the cryptographic estate, the harvest demonstration, "
        "and the migration programme.",
        eyebrow="Executive summary",
    )

    ui.posture(
        score=score,
        verdict=estate["verdict"],
        colour=score_colour,
        note=(
            f"<b>{estate['quantum_vulnerable']} of {estate['assets_scanned']} assets</b> "
            "use key establishment that the published quantum algorithms defeat. "
            f"<b>{migration_view['critical']} are rated critical</b> — quantum-vulnerable "
            "cryptography protecting data with a long confidentiality requirement, "
            "which means traffic captured today would still be sensitive well "
            "beyond the point where the algorithm is expected to be at risk."
        ),
    )

    ui.cards(
        [
            {
                "label": "Critical assets",
                "value": migration_view["critical"],
                "colour": ui.CRITICAL,
                "value_colour": ui.CRITICAL,
                "glow": True,
            },
            {
                "label": "Quantum vulnerable",
                "value": estate["quantum_vulnerable"],
                "colour": ui.HIGH,
                "value_colour": ui.HIGH,
            },
            {
                "label": "PQC ready",
                "value": estate["pqc_ready"],
                "colour": ui.SAFE,
                "value_colour": ui.SAFE,
            },
            {
                "label": "Packets harvested",
                "value": demonstration["packets_harvested"],
                "colour": ui.CYAN,
            },
            {
                "label": "Q-Day status",
                "value": demonstration["qday_status"],
                "colour": ui.CRITICAL if demonstration["qday_status"] == "DEMONSTRATED" else ui.CYAN,
            },
            {
                "label": "Readiness score",
                "value": f"{score}/100",
                "colour": score_colour,
                "value_colour": score_colour,
                "note": estate["verdict"],
            },
        ]
    )

    landscape, priorities = st.columns([2, 3])

    with landscape:
        ui.section("Threat landscape", eyebrow="Risk distribution")
        counts = estate["risk_counts"]
        levels = [
            level
            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN")
            if counts.get(level)
        ]
        figure = go.Figure(
            go.Bar(
                x=[counts[level] for level in levels],
                y=levels,
                orientation="h",
                marker=dict(
                    color=[ui.RISK_COLOUR[level] for level in levels],
                    line=dict(width=0),
                ),
                text=[counts[level] for level in levels],
                textposition="outside",
                textfont=dict(family=ui.MONO, size=12),
            )
        )
        st.plotly_chart(ui.chart_layout(figure, 250), width="stretch")

    with priorities:
        ui.section("Top migration priorities", eyebrow="Prioritize")
        for priority in migration_view["top_priorities"]:
            ui.panel(
                title=f"{priority['position']:02d} &nbsp; {priority['system_name']}",
                meta=f"{priority['current']} · {priority['retention_years']}y retention",
                body=priority["why_first"],
                accent=ui.RISK_COLOUR.get(priority["risk"], ui.UNKNOWN),
                badges=ui.risk_pill(priority["risk"]),
            )

    ui.section("Security workflow", eyebrow="Platform")
    ui.flow(workflow, active=None)

    claim_a, claim_b, claim_c = st.columns(3)
    with claim_a:
        ui.panel("Today's demonstration", body=threat["demonstrated_today"], accent=ui.AMBER)
    with claim_b:
        ui.panel("The future quantum threat", body=threat["future_threat"], accent=ui.HIGH)
    with claim_c:
        ui.panel("The post-quantum defence", body=threat["defence"], accent=ui.SAFE)


# ==========================================================================
# PQC READINESS
# ==========================================================================

with tab_scan:
    ui.flow(workflow, active="discover")

    ui.section(
        "Cryptographic inventory",
        "Parses keys and certificates to identify which algorithms are deployed, "
        "then rates each asset's Harvest-Now-Decrypt-Later exposure.",
        eyebrow="Discover · Assess",
    )

    ui.note(
        "<b>Scope.</b> This is a cryptographic inventory and readiness "
        "assessment. It performs no cryptanalysis against anything it scans, "
        "never reads or derives private key material, and does not predict when "
        "any algorithm will be broken. It reports what is knowable and "
        "actionable: which assets use algorithms that Shor's algorithm defeats, "
        "and how long their data must stay secret.",
        ui.CYAN,
    )

    source = st.radio(
        "Scan source",
        options=["Demo enterprise (built-in)", "Local directory or file", "Upload files"],
        horizontal=True,
    )

    scan_now = False
    scan_kwargs: dict[str, object] = {}

    if source == "Demo enterprise (built-in)":
        st.caption(
            "Northwind Systems, a fictional organisation generated locally on "
            "first use. Every file contains genuine cryptographic material — "
            "real RSA and ECDSA keys, a real ML-KEM-768 encapsulation key, and "
            "one deliberately corrupted file. Fully offline."
        )
        if st.button("LOAD DEMO ENTERPRISE", type="primary", width="stretch"):
            scan_now = True
            scan_kwargs = {"mode": "demo"}

    elif source == "Local directory or file":
        target = st.text_input("Path to scan", placeholder=r"C:\certs  or  /etc/ssl/certs")
        if st.button("Run assessment", type="primary", width="stretch", key="scan_path_btn"):
            if not target.strip():
                st.error("Enter a path to scan.")
            else:
                scan_now = True
                scan_kwargs = {"mode": "path", "target": target.strip()}

    else:
        uploads = st.file_uploader(
            "Certificate or key files",
            type=["pem", "crt", "cer", "der", "key", "pub", "json"],
            accept_multiple_files=True,
        )
        if st.button("Run assessment", type="primary", width="stretch", key="scan_upload_btn"):
            if not uploads:
                st.error("Upload at least one file.")
            else:
                scan_now = True
                scan_kwargs = {
                    "mode": "upload",
                    "files": [(f.name, f.getvalue()) for f in uploads],
                }

    if scan_now:
        try:
            with st.spinner("Assessing cryptographic estate..."):
                if scan_kwargs["mode"] == "demo":
                    st.session_state["scan"] = svc.scan_demo_enterprise()
                elif scan_kwargs["mode"] == "path":
                    st.session_state["scan"] = svc.scan_path(scan_kwargs["target"])
                else:
                    st.session_state["scan"] = svc.scan_uploaded(scan_kwargs["files"])
        except ServiceError as exc:
            st.error(str(exc))

    assessment = st.session_state.get("scan") or get_assessment()

    if assessment["assets_scanned"] == 0:
        st.warning(
            "No cryptographic assets found. The scanner reads .pem, .crt, .cer, "
            ".der, .key, .pub and .json files."
        )
    else:
        counts = assessment["counts"]
        ui.cards(
            [
                {"label": "Assets scanned", "value": assessment["assets_scanned"], "colour": ui.CYAN},
                {
                    "label": "Vulnerable",
                    "value": assessment["quantum_vulnerable"],
                    "colour": ui.CRITICAL,
                    "value_colour": ui.CRITICAL,
                    "glow": True,
                },
                {
                    "label": "PQC ready",
                    "value": assessment["pqc_ready"],
                    "colour": ui.SAFE,
                    "value_colour": ui.SAFE,
                },
                {"label": "Unknown", "value": counts["UNKNOWN"], "colour": ui.UNKNOWN},
                {"label": "Critical", "value": counts["CRITICAL"], "colour": ui.CRITICAL},
                {"label": "High", "value": counts["HIGH"], "colour": ui.HIGH},
            ]
        )

        assess_score = assessment["readiness_score"]
        assess_colour = (
            ui.GREEN if assess_score >= 60 else ui.AMBER if assess_score >= 30 else ui.CRITICAL
        )
        ui.posture(
            score=assess_score,
            verdict=assessment["verdict"],
            colour=assess_colour,
            note=(
                "Each asset earns a share of 100 weighted by its risk rating — "
                "SAFE 100%, LOW 75%, MEDIUM 40%, HIGH 20%, UNKNOWN 10%, "
                "CRITICAL 0%. That is the entire formula. An estate scores 100 "
                "only when every asset is verified post-quantum."
            ),
        )

        with st.expander("Algorithm family distribution"):
            families = assessment["by_family"]
            donut = go.Figure(
                go.Pie(
                    labels=list(families),
                    values=list(families.values()),
                    hole=0.58,
                    marker=dict(
                        colors=[
                            ui.SAFE
                            if ("lattice" in f.lower() or "hash" in f.lower())
                            else ui.CRITICAL
                            for f in families
                        ],
                        line=dict(color=ui.SURFACE, width=2),
                    ),
                )
            )
            donut.update_layout(
                template="plotly_dark",
                height=250,
                margin=dict(l=8, r=8, t=8, b=8),
                paper_bgcolor="rgba(0,0,0,0)",
                showlegend=True,
                font=dict(family=ui.MONO, size=10, color=ui.DIM),
            )
            st.plotly_chart(donut, width="stretch")

        # ---- Filters ----
        ui.section("Asset inventory", eyebrow="Filter · Search")

        filter_col, search_col = st.columns([2, 3])
        with filter_col:
            asset_filter = st.selectbox(
                "Risk / verification filter",
                [
                    "All",
                    "Quantum vulnerable",
                    "PQC ready",
                    "Critical",
                    "High",
                    "Verified",
                    "Declared",
                    "Unidentified",
                ],
            )
        with search_col:
            query = (
                st.text_input("Search", placeholder="asset, business unit, or algorithm")
                .strip()
                .lower()
            )

        def matches(finding: dict) -> bool:
            """Apply the active filter and free-text search to one finding."""
            if asset_filter == "Quantum vulnerable" and finding["quantum_status"] != scanner.STATUS_VULNERABLE:
                return False
            if asset_filter == "PQC ready" and finding["quantum_status"] not in (
                scanner.STATUS_POST_QUANTUM,
                scanner.STATUS_HYBRID,
            ):
                return False
            if asset_filter == "Critical" and finding["risk"] != scanner.RISK_CRITICAL:
                return False
            if asset_filter == "High" and finding["risk"] != scanner.RISK_HIGH:
                return False
            if asset_filter == "Verified" and finding["evidence"] != scanner.EVIDENCE_VERIFIED:
                return False
            if asset_filter == "Declared" and finding["evidence"] != scanner.EVIDENCE_DECLARED:
                return False
            if asset_filter == "Unidentified" and finding["risk"] != scanner.RISK_UNKNOWN:
                return False
            if query:
                haystack = " ".join(
                    str(finding.get(field, ""))
                    for field in (
                        "system_name",
                        "algorithm",
                        "algorithm_family",
                        "business_context",
                        "key_size",
                    )
                ).lower()
                if query not in haystack:
                    return False
            return True

        visible = [f for f in assessment["findings"] if matches(f)]
        st.caption(f"Showing {len(visible)} of {assessment['assets_scanned']} assets.")

        if not visible:
            st.info("No assets match the current filter.")
        else:
            ui.table(
                ["Asset", "Business unit", "Algorithm", "Key size", "Evidence", "Risk", "Retention"],
                [
                    [
                        f'<span class="lead">{f["system_name"]}</span>',
                        f["business_context"][:40] or "—",
                        mono(f["algorithm"] or "unidentified"),
                        mono(f["key_size"] or "—"),
                        ui.evidence_pill(f["evidence"]),
                        ui.risk_pill(f["risk"]),
                        mono(f"{f['retention_years']}y" if f["retention_years"] else "—"),
                    ]
                    for f in visible
                ],
            )

            # A sortable frame alongside the styled console view: this is genuine
            # tabular data an analyst may want to reorder or export.
            with st.expander("Tabular view"):
                st.dataframe(
                    pd.DataFrame(
                        [
                            {
                                "Asset": f["system_name"],
                                "Algorithm": f["algorithm"] or "unidentified",
                                "Key size": f["key_size"] or "—",
                                "PQC status": f["quantum_status"],
                                "HNDL risk": f["risk"],
                                "Evidence": f["evidence"],
                                "Retention": f"{f['retention_years']}y"
                                if f["retention_years"]
                                else "—",
                            }
                            for f in visible
                        ]
                    ),
                    width="stretch",
                    hide_index=True,
                )

            ui.section(
                "Security findings",
                "Why each asset received its rating.",
                eyebrow="Assess",
            )

            for finding in visible:
                risk_colour = ui.RISK_COLOUR.get(finding["risk"], ui.UNKNOWN)
                with st.expander(
                    f"{finding['risk']}  ·  {finding['system_name']}  ·  "
                    f"{finding['algorithm'] or 'unidentified'}"
                ):
                    ui.panel(
                        title=finding["system_name"],
                        meta=Path(finding["path"]).name,
                        body=finding["business_context"],
                        accent=risk_colour,
                        badges=ui.risk_pill(finding["risk"])
                        + ui.evidence_pill(finding["evidence"]),
                        kv=[
                            ("Algorithm", finding["algorithm"] or "unidentified"),
                            ("Key size", finding["key_size"] or "—"),
                            ("OID", finding.get("detail", {}).get("algorithm_oid", "—")),
                            ("File type", finding["file_type"]),
                            ("Verification", finding["evidence"]),
                            ("Retention", f"{finding['retention_years']} years"),
                            ("Sensitivity", finding["data_sensitivity"] or "—"),
                            ("Exposure", finding["quantum_status"]),
                        ],
                    )
                    st.markdown("**Why this rating**")
                    for reason in finding["reasons"]:
                        st.markdown(f"- {reason}")

                    contribution = {
                        scanner.RISK_SAFE: "100%",
                        scanner.RISK_LOW: "75%",
                        scanner.RISK_MEDIUM: "40%",
                        scanner.RISK_HIGH: "20%",
                        scanner.RISK_UNKNOWN: "10%",
                        scanner.RISK_CRITICAL: "0%",
                    }.get(finding["risk"], "—")
                    st.caption(
                        f"Score contribution: {contribution} of this asset's share "
                        "of the readiness score."
                    )
                    if finding["recommended_migration"]:
                        st.caption(f"Recommendation: {finding['recommended_migration']}")


# ==========================================================================
# MIGRATION PLAN
# ==========================================================================

with tab_migrate:
    ui.flow(workflow, active="migrate")

    plan = get_plan()
    verification = get_verification()

    ui.section(
        "PQC migration plan",
        "The assessment turned into an ordered programme of work. Ranked by "
        "risk, then by how long the protected data must remain confidential.",
        eyebrow="Prioritize · Migrate · Verify",
    )

    ui.note(
        "<b>This is a planning output.</b> AegisPQC does not modify, rotate, or "
        "reconfigure any real system, and does not predict when any algorithm "
        "will be broken. Every recommendation is advice derived from the "
        "inventory.",
        ui.CYAN,
    )

    ui.cards(
        [
            {
                "label": "Requiring migration",
                "value": plan["assets_requiring_migration"],
                "colour": ui.HIGH,
                "value_colour": ui.HIGH,
            },
            {
                "label": "Already PQC ready",
                "value": plan["assets_already_pqc_ready"],
                "colour": ui.SAFE,
                "value_colour": ui.SAFE,
            },
            {
                "label": "Critical",
                "value": plan["critical_migrations"],
                "colour": ui.CRITICAL,
                "value_colour": ui.CRITICAL,
                "glow": True,
            },
            {"label": "High", "value": plan["high_migrations"], "colour": ui.HIGH},
            {
                "label": "To investigate",
                "value": plan["unknown_requiring_investigation"],
                "colour": ui.UNKNOWN,
            },
        ]
    )

    ui.section("Recommended target architecture", eyebrow="Target state")
    architecture = plan["recommended_target_architecture"]
    arch_a, arch_b = st.columns([2, 3])
    with arch_a:
        ui.panel(
            "Target cryptography",
            accent=ui.SAFE,
            badges=ui.pill("NIST STANDARDS", ui.SAFE),
            kv=[
                ("Key establishment", architecture["key_establishment"]),
                ("Signatures", architecture["signatures"]),
                ("Symmetric", architecture["symmetric"]),
                ("KDF", architecture["kdf"]),
            ],
        )
    with arch_b:
        ui.note(architecture["note"], ui.SAFE)

    ui.section(
        "Migration queue",
        "Every asset, in the order it should be addressed.",
        eyebrow="Priority",
    )

    for rec in plan["recommendations"]:
        risk_colour = ui.RISK_COLOUR.get(rec["risk"], ui.UNKNOWN)
        current = (
            f"{rec['current_algorithm']}-{rec['current_key_size']}"
            if rec["current_key_size"]
            else rec["current_algorithm"]
        )
        with st.expander(
            f"{rec['position']:02d}  ·  {rec['risk']}  ·  {rec['system_name']}",
            expanded=rec["position"] <= 2,
        ):
            ui.panel(
                title=f"{rec['position']:02d} &nbsp; {rec['system_name']}",
                meta=rec["algorithm_oid"],
                body=rec["business_context"],
                accent=risk_colour,
                badges=ui.risk_pill(rec["risk"]) + ui.evidence_pill(rec["evidence"]),
                kv=[
                    ("Current", current),
                    ("Family", rec["current_family"] or "—"),
                    ("Exposure", rec["quantum_status"]),
                    ("Retention", f"{rec['retention_years']} years"),
                    ("Sensitivity", rec["data_sensitivity"] or "—"),
                    ("Evidence", rec["evidence"]),
                ],
            )

            if rec["needs_migration"]:
                ui.panel(
                    title="Recommended migration",
                    meta=rec["target_standard"],
                    body=rec["target_rationale"],
                    accent=ui.SAFE,
                    badges=ui.pill("TARGET", ui.SAFE),
                    kv=[
                        ("Target", rec["recommended_target"]),
                        ("Phase", rec["phase"].replace("_", " ").title()),
                        ("Effort", rec["effort"]),
                        ("Validation", "Required" if rec["validation_required"] else "—"),
                    ],
                )
                if rec["signature_note"]:
                    st.caption(rec["signature_note"])

            ui.note(f"<b>Why this position.</b> {rec['why_first']}", risk_colour)

            with st.expander("Full risk reasoning"):
                for reason in rec["risk_reasons"]:
                    st.markdown(f"- {reason}")

    ui.section("Phased programme", eyebrow="Sequencing")
    phase_colours = {
        "phase_1": ui.CRITICAL,
        "phase_2": ui.HIGH,
        "phase_3": ui.CYAN,
        "phase_4": ui.UNKNOWN,
    }
    ui.roadmap(
        [
            {**phase, "colour": phase_colours.get(phase["key"], ui.CYAN)}
            for phase in plan["phases"]
            if phase["asset_count"]
        ]
    )

    ui.section("Plan verification", eyebrow="Verify")
    verdict_colour = ui.SAFE if verification["consistent"] else ui.CRITICAL
    st.markdown(ui.pill(verification["verdict"], verdict_colour), unsafe_allow_html=True)

    ui.table(
        ["Check", "Result", "Detail"],
        [
            [
                f'<span class="lead">{check["name"]}</span>',
                ui.pill("PASS" if check["passed"] else "FAIL", ui.SAFE if check["passed"] else ui.CRITICAL),
                check["detail"],
            ]
            for check in verification["checks"]
        ],
    )
    ui.note(verification["scope_note"], ui.AMBER)

    # ---- Export ----
    ui.section("Generate security assessment", eyebrow="Reporting")
    export_json, export_md, export_note = st.columns([1, 1, 3])

    with export_json:
        if st.button("Prepare JSON report", width="stretch"):
            with st.spinner("Building report..."):
                st.session_state["report_json"] = json.dumps(svc.full_report(), indent=2)
    with export_md:
        if st.button("Prepare Markdown report", width="stretch"):
            with st.spinner("Building report..."):
                st.session_state["report_md"] = svc.report_markdown()
    with export_note:
        st.caption(
            "Reports contain the assessment, inventory, risk distribution, "
            "migration priorities, scanner evidence, and limitations. They "
            "contain no private key material — enforced by a check that raises "
            "rather than returning if any is detected."
        )

    if st.session_state.get("report_json"):
        st.download_button(
            "Download JSON report",
            data=st.session_state["report_json"],
            file_name="aegis_pqc_assessment.json",
            mime="application/json",
        )
    if st.session_state.get("report_md"):
        st.download_button(
            "Download Markdown report",
            data=st.session_state["report_md"],
            file_name="aegis_pqc_assessment.md",
            mime="text/markdown",
        )
        with st.expander("Preview Markdown report"):
            st.markdown(st.session_state["report_md"][:4000])


# ==========================================================================
# QUANTUM VAULT
# ==========================================================================

with tab_vault:
    ui.flow(workflow, active="protect")

    ui.section(
        "Secure transmission",
        f"{svc.DEMO_SENDER} &nbsp;&#9656;&nbsp; {svc.DEMO_RECIPIENT} &nbsp;·&nbsp; "
        "The symmetric layer is identical in every mode — HKDF-SHA256 into "
        "AES-256-GCM. Only key establishment changes, which is exactly what the "
        "post-quantum transition is about. AES is not being replaced.",
        eyebrow="Protect",
    )

    algorithm = st.radio(
        "Key establishment",
        options=list(ALGO_CHOICES),
        format_func=lambda a: ALGO_CHOICES[a],
        index=0,
        horizontal=True,
    )

    posture_cols = st.columns(3)
    for column, option in zip(posture_cols, ALGO_CHOICES):
        label, colour = ALGO_STATUS[option]
        selected = option == algorithm
        with column:
            ui.panel(
                title=ALGO_CHOICES[option],
                meta="SELECTED" if selected else "",
                body="",
                accent=colour if selected else ui.BORDER,
                badges=ui.pill(label, colour),
            )

    compose, context = st.columns([3, 2])

    with compose:
        label = st.text_input("Packet label", value="Q3 merger brief")
        message = st.text_area("Payload", value=svc.DEMO_TRAFFIC[0][2], height=150)

        if st.button("ENCRYPT AND SEND", type="primary", width="stretch"):
            try:
                result = svc.send_message(
                    sender=svc.DEMO_SENDER,
                    recipient=svc.DEMO_RECIPIENT,
                    algorithm=algorithm,
                    message=message,
                    label=label,
                )
                st.session_state["last_sent"] = result
                st.success(
                    f"Transmitted as {result['packet_id']} — and harvested by the "
                    "adversary in the same instant."
                )
            except ServiceError as exc:
                st.error(str(exc))

    with context:
        if is_safe(algorithm):
            ui.note(
                "<b>Post-quantum.</b> A recording made today stays unreadable "
                "after Q-Day.",
                ui.SAFE,
            )
        else:
            ui.note(
                "<b>Quantum vulnerable.</b> A recording made today becomes "
                "readable once a sufficiently large quantum computer exists.",
                ui.CRITICAL,
            )

        if algorithm == config.ALGO_HYBRID:
            hybrid = svc.hybrid_defence()
            ui.panel(
                "Hybrid construction",
                meta="X25519MLKEM768",
                body=hybrid["consequence"],
                accent=ui.SAFE,
                kv=[("Derivation", "HKDF(x25519_ss || mlkem_ss)")],
            )
            for leg in hybrid["legs"]:
                ui.panel(
                    leg["name"],
                    meta=leg["problem"],
                    body=f"{leg['quantum_status']}. {leg['verdict']}.",
                    accent=ui.CRITICAL if "Falls" in leg["verdict"] else ui.SAFE,
                )
        elif algorithm == config.ALGO_RSA_DEMO:
            ui.note(
                f"<b>Demo scale.</b> This key uses an "
                f"{config.RSA_DEMO_PRIME_BITS * 2}-bit modulus, deliberately "
                "undersized so the Q-Day console can factor it for real on this "
                "machine. It is labelled demo-scale everywhere it appears.",
                ui.AMBER,
            )

    sent = st.session_state.get("last_sent")
    if sent:
        ui.section(
            "Cryptographic pipeline",
            "Every artifact below came from the envelope just produced. No key "
            "material of any kind is shown.",
            eyebrow="Transmission artifact",
        )

        ui.cards(
            [
                {"label": "Algorithm", "value": SHORT_LABELS.get(sent["algorithm"], sent["algorithm"]), "colour": ui.CYAN},
                {"label": "Plaintext", "value": f"{sent['plaintext_bytes']} B", "colour": ui.CYAN},
                {"label": "KEM ciphertext", "value": f"{sent['kem_ciphertext_bytes']} B", "colour": ui.VIOLET},
                {"label": "Ciphertext", "value": f"{sent['payload_ciphertext_bytes']} B", "colour": ui.VIOLET},
                {"label": "Wire overhead", "value": f"+{sent['total_overhead_bytes']} B", "colour": ui.AMBER},
            ]
        )

        ui.timeline(svc.vault_pipeline(sent))

        ui.terminal(
            f"packet_id          : {sent['packet_id']}\n"
            f"algorithm          : {sent['algorithm']}\n"
            f"kem_ciphertext     : {sent['kem_ciphertext'][:88]}...\n"
            f"nonce (96-bit)     : {sent['nonce']}\n"
            f"auth tag           : appended to ciphertext (128-bit)\n"
            f"payload_ciphertext : {sent['payload_ciphertext'][:88]}...",
            heading="Transmission artifact — exactly what an adversary captures",
        )
        st.caption(
            "No private key, no shared secret, no plaintext. The nonce is public "
            "by design."
        )

        if st.button("Decrypt as Bob (the legitimate recipient)"):
            try:
                received = svc.receive_message(sent["packet_id"])
                st.success(f"Decrypted in {received['decrypt_ms']} ms")
                st.code(received["plaintext"], language="text")
                st.caption(
                    "Bob holds the private key, so this is instant. The adversary "
                    "holds the same ciphertext and cannot do this."
                )
            except ServiceError as exc:
                st.error(str(exc))


# ==========================================================================
# HNDL HOARD
# ==========================================================================

with tab_hoard:
    ui.flow(workflow, active="harvest")

    ui.section(
        "Adversary archive",
        "Everything transmitted, recorded off the wire and stored indefinitely. "
        "Note the algorithm column: post-quantum traffic was harvested too. "
        "Choosing ML-KEM does not make you invisible — it makes the recording "
        "worthless.",
        eyebrow="Harvest",
    )

    packets = svc.list_harvested()

    if not packets:
        st.info("Archive is empty. Load the presentation demo from the rail.")
    else:
        total_ciphertext = sum(
            p["kem_ciphertext_bytes"] + p["payload_ciphertext_bytes"] for p in packets
        )
        ui.cards(
            [
                {
                    "label": "Captured packets",
                    "value": stats["total_packets"],
                    "colour": ui.CRITICAL,
                    "value_colour": ui.CRITICAL,
                    "glow": True,
                },
                {
                    "label": "Vulnerable",
                    "value": stats["vulnerable_packets"],
                    "colour": ui.CRITICAL,
                    "value_colour": ui.CRITICAL,
                },
                {
                    "label": "PQC protected",
                    "value": stats["quantum_safe_packets"],
                    "colour": ui.SAFE,
                    "value_colour": ui.SAFE,
                },
                {"label": "Total ciphertext", "value": f"{total_ciphertext:,} B", "colour": ui.VIOLET},
                {"label": "Plaintext at risk", "value": f"{stats['total_bytes_at_risk']:,} B", "colour": ui.AMBER},
            ]
        )

        ui.note(
            "<b>The harvest is already complete.</b> The adversary does not need "
            "a quantum computer today. They need storage today and patience. "
            "Every packet here sits in an archive waiting for the capability to "
            "catch up — which is why retention period, not algorithm alone, "
            "drives the risk rating on the Readiness surface.",
            ui.AMBER,
        )

        ui.table(
            ["Status", "Packet", "Route", "Algorithm", "Label", "Size", "Intercepted"],
            [
                [
                    ui.pill(
                        "PQC PROTECTED" if is_safe(p["algo_used"]) else "RSA VULNERABLE",
                        ui.SAFE if is_safe(p["algo_used"]) else ui.CRITICAL,
                    ),
                    mono(p["packet_id"]),
                    f'{p["sender"]} &#9656; {p["recipient"]}',
                    mono(SHORT_LABELS.get(p["algo_used"], p["algo_used"])),
                    p["label"],
                    mono(f'{p["kem_ciphertext_bytes"] + p["payload_ciphertext_bytes"]} B'),
                    mono(p["intercepted_at"].replace("T", " ").replace("+00:00", "")),
                ]
                for p in packets
            ],
        )

        ui.section(
            "Forensic packet inspection",
            "Select a captured packet to inspect what the tap actually holds.",
            eyebrow="Forensics",
        )

        options = {
            f'{p["packet_id"]} · {SHORT_LABELS.get(p["algo_used"], p["algo_used"])} · {p["label"]}': p
            for p in sorted(packets, key=lambda x: x["seq"])
        }
        chosen = st.selectbox("Captured packet", list(options), key="forensic_select")
        forensics = svc.packet_forensics(options[chosen]["packet_id"])

        accent = ui.CRITICAL if forensics["quantum_vulnerable"] else ui.SAFE
        ui.panel(
            title=forensics["packet_id"],
            meta=forensics["intercepted_at"],
            body=forensics["capture_note"],
            accent=accent,
            badges=ui.pill("HARVESTED", ui.AMBER)
            + ui.pill(
                "RSA VULNERABLE" if forensics["quantum_vulnerable"] else "PQC PROTECTED",
                accent,
            ),
            kv=[
                ("Sender", forensics["sender"]),
                ("Recipient", forensics["recipient"]),
                ("Algorithm", forensics["algorithm"]),
                ("Capture method", forensics["capture_method"]),
                ("KEM ciphertext", f"{forensics['kem_ciphertext_bytes']} B"),
                ("Nonce", f"{forensics['nonce']} ({forensics['nonce_bits']}-bit)"),
                ("Auth tag", f"{forensics['auth_tag'][:32]} ({forensics['auth_tag_bits']}-bit)"),
                ("Ciphertext body", f"{forensics['ciphertext_body_bytes']} B"),
                ("Recipient public key", f"{forensics['recipient_public_key_bytes']} B"),
                ("Bound metadata", forensics["aad"] or "—"),
                ("Total captured", f"{forensics['total_captured_bytes']} B"),
            ],
        )

        ui.note(f"<b>{forensics['key_custody_note']}</b>", ui.SAFE)

        ui.terminal(
            f"kem_ciphertext[:48] : {forensics['kem_ciphertext_preview']}\n"
            f"nonce               : {forensics['nonce']}\n"
            f"auth_tag            : {forensics['auth_tag']}\n"
            f"ciphertext[:48]     : {forensics['ciphertext_preview']}",
            heading="Raw captured bytes",
        )


# ==========================================================================
# Q-DAY SIMULATOR
# ==========================================================================

with tab_qday:
    ui.flow(workflow, active="simulate")

    ui.section(
        "Q-Day simulation",
        "Illustrative threat model. The RSA demonstration is a classical "
        "demonstration of the mechanism against a deliberately undersized "
        "modulus.",
        eyebrow="Simulate · Threat console",
    )

    honesty_a, honesty_b, honesty_c = st.columns(3)
    with honesty_a:
        ui.panel(
            "TODAY'S DEMONSTRATION",
            body=(
                f"A deliberately undersized {config.RSA_DEMO_PRIME_BITS * 2}-bit "
                "RSA modulus is <b>genuinely factored</b> on this machine using "
                "classical factorisation (Brent's variant of Pollard's rho). "
                "Real work, performed live, using only data visible on the wire. "
                "It is <b>not</b> Shor's algorithm and <b>not</b> a quantum "
                "computer."
            ),
            accent=ui.AMBER,
            badges=ui.pill("CLASSICAL", ui.AMBER),
        )
    with honesty_b:
        ui.panel(
            "THE FUTURE QUANTUM THREAT",
            body=(
                "Shor's algorithm is the relevant quantum threat to RSA and "
                "elliptic curves at cryptographically relevant sizes. It moves "
                "factoring from exponential to polynomial cost. No machine "
                "capable of running it against RSA-2048 exists today. "
                "<b>We have not broken RSA-2048 and do not claim to.</b>"
            ),
            accent=ui.HIGH,
            badges=ui.pill("PROJECTED", ui.HIGH),
        )
    with honesty_c:
        ui.panel(
            "THE POST-QUANTUM DEFENCE",
            body=(
                "ML-KEM (NIST FIPS 203) is built on lattice problems, which "
                "Shor's algorithm does not solve. It is <b>designed to resist</b> "
                "the best known classical and quantum attacks. That is "
                "deliberately a weaker statement than absolute security: lattice "
                "cryptanalysis is an active research field."
            ),
            accent=ui.SAFE,
            badges=ui.pill("FIPS 203", ui.SAFE),
        )

    ui.note(
        "<b>The link between the three panels is the only thing that changes: "
        "time.</b> The mathematics of the break you are about to watch is "
        "identical at 88 bits and at 2048 bits. What differs is the machine "
        "required. The adversary already holds the ciphertext, so the only open "
        "question is how long they have to wait.",
        ui.CYAN,
    )

    packets = svc.list_harvested()
    if not packets:
        st.info("Archive is empty. Load the presentation demo from the rail.")
    else:
        options = {
            f'{p["packet_id"]} · {SHORT_LABELS.get(p["algo_used"], p["algo_used"])} · {p["label"]}': p
            for p in sorted(packets, key=lambda x: x["seq"])
        }
        choice = st.selectbox("Target packet", list(options), key="qday_select")
        target = options[choice]

        col_a, col_b = st.columns([2, 1])
        run_one = col_a.button("EXECUTE Q-DAY ATTACK", type="primary", width="stretch")
        run_all = col_b.button("Attack the entire archive", width="stretch")

        if run_one or run_all:
            targets = sorted(packets, key=lambda x: x["seq"]) if run_all else [target]

            for packet in targets:
                algorithm_label = SHORT_LABELS.get(packet["algo_used"], packet["algo_used"])
                ui.section(
                    f"{packet['packet_id']} — {algorithm_label}",
                    eyebrow="Attack procedure",
                )

                console = st.empty()
                lines: list[str] = []

                def emit(line: str, _console=console, _lines=lines) -> None:
                    """Stream each trace line into the console as it is produced."""
                    _lines.append(line)
                    _console.code("\n".join(_lines[-22:]), language="text")

                started = time.perf_counter()
                with st.spinner("Executing attack procedure..."):
                    result = svc.run_attack(packet["packet_id"], progress=emit)
                elapsed = time.perf_counter() - started
                console.empty()

                st.markdown("**Procedural steps**")
                ui.timeline(svc.attack_procedure(result))

                if result["status"] == sim.STATUS_BREACHED:
                    ui.cards(
                        [
                            {"label": "Verdict", "value": "BREACHED", "colour": ui.CRITICAL, "value_colour": ui.CRITICAL, "glow": True},
                            {"label": "Elapsed", "value": f"{result['execution_time_ms']:.0f} ms", "colour": ui.CRITICAL},
                            {"label": "Method", "value": "CLASSICAL", "colour": ui.AMBER, "note": "Pollard's rho — not Shor's"},
                        ]
                    )
                    st.error(
                        f"**BREACHED in {result['execution_time_ms']:.0f} ms.** The "
                        "private key was reconstructed from public data alone and "
                        "the payload recovered in full."
                    )
                    st.markdown("**Recovered plaintext**")
                    st.code(result["recovered_plaintext"], language="text")
                elif result["status"] == sim.STATUS_IMMUNE:
                    is_refusal = packet["algo_used"] == config.ALGO_RSA_2048
                    ui.cards(
                        [
                            {
                                "label": "Verdict",
                                "value": "DEMONSTRATION REFUSED" if is_refusal else "SHARED SECRET NOT RECOVERED",
                                "colour": ui.SAFE,
                                "value_colour": ui.SAFE,
                            },
                            {
                                "label": "Plaintext",
                                "value": "PROTECTED",
                                "colour": ui.SAFE,
                                "value_colour": ui.SAFE,
                            },
                        ]
                    )
                    if is_refusal:
                        st.success(
                            "**RSA-2048 IS NOT FACTORED.** No publicly known method "
                            "factors it on any machine that currently exists. This "
                            "tool refuses to fabricate a break and reports the "
                            "refusal rather than a fake success."
                        )
                    else:
                        st.success(
                            f"**{result['status']}.** The attack was attempted and "
                            "abandoned as computationally infeasible against the "
                            "best publicly known methods. The recording remains "
                            "unreadable. This is a claim about known attacks, not "
                            "a proof that none exists."
                        )
                    if packet["algo_used"] == config.ALGO_HYBRID:
                        hybrid = svc.hybrid_defence()
                        ui.note(f"<b>Hybrid.</b> {hybrid['consequence']}", ui.SAFE)
                else:
                    st.warning(f"{result['status']} after {elapsed:.1f}s")

                # Rendered with st.code rather than the styled terminal
                # component on purpose: it keeps the copy-to-clipboard
                # affordance, which matters if a judge wants the trace, and it
                # preserves the rendered-output contract the test suite checks.
                # The CSS styles code blocks to match the terminal aesthetic.
                with st.expander("Full attack trace", expanded=False):
                    st.code(result["log_trace"], language="text")

            ui.section("What changes at full scale", eyebrow="Extrapolation")
            extra = svc.extrapolation()
            ui.cards(
                [
                    {
                        "label": "Broken live",
                        "value": f"{extra['demo_modulus_bits']}-bit",
                        "note": f"{extra['demo_factor_ms']:.0f} ms · measured · classical",
                        "colour": ui.CRITICAL,
                    },
                    {
                        "label": "Shor's logical qubits",
                        "value": f"{extra['shor_logical_qubits']:,}",
                        "note": "for RSA-2048 · estimated",
                        "colour": ui.HIGH,
                    },
                    {
                        "label": "ML-KEM-768 quantum cost",
                        "value": f"2^{extra['mlkem_quantum_gates_log2']}",
                        "note": "gates · estimated",
                        "colour": ui.SAFE,
                    },
                ]
            )
            st.caption(extra["shor_runtime_note"])
            st.caption(extra["conclusion"])


# ==========================================================================
# BENCHMARKS
# ==========================================================================

with tab_bench:
    ui.flow(workflow, active=None)

    ui.section(
        "Engineering analysis",
        "Measured performance and the trade-offs it implies. Measured values and "
        "research estimates are kept strictly separate — mixing them would imply "
        "we measured something no one can measure.",
        eyebrow="Benchmarks",
    )

    control, _ = st.columns([2, 3])
    with control:
        iterations = st.slider("Iterations per operation", 5, 200, 50, step=5)
        if st.button("RUN BENCHMARKS", type="primary", width="stretch"):
            with st.spinner(f"Measuring {iterations} iterations per operation..."):
                st.session_state["bench"] = svc.benchmark_bundle(iterations)

    bundle = st.session_state.get("bench")
    if not bundle:
        st.info("Run the benchmarks to populate the analysis.")
    else:
        measured = bundle["measured"]
        rows = measured["rows"]
        names = [SHORT_LABELS.get(r["algorithm"], r["algorithm"]) for r in rows]
        colours = [ui.CRITICAL if not r["quantum_safe"] else ui.SAFE for r in rows]

        st.markdown(ui.pill("MEASURED", ui.SAFE), unsafe_allow_html=True)
        ui.note(f"<b>{measured['note']}</b>", ui.SAFE)

        relative = measured.get("relative") or {}
        if relative:
            ui.cards(
                [
                    {
                        "label": "ML-KEM keygen",
                        "value": f"{relative['mlkem_keygen_speedup']}×",
                        "note": "faster than RSA-2048",
                        "colour": ui.SAFE,
                        "value_colour": ui.SAFE,
                    },
                    {
                        "label": "ML-KEM decapsulate",
                        "value": f"{relative['mlkem_decrypt_speedup']}×",
                        "note": "faster than RSA-2048",
                        "colour": ui.SAFE,
                        "value_colour": ui.SAFE,
                    },
                    {
                        "label": "ML-KEM wire cost",
                        "value": f"{relative['mlkem_wire_overhead_ratio']}×",
                        "note": "more bytes than RSA-2048",
                        "colour": ui.AMBER,
                        "value_colour": ui.AMBER,
                    },
                    {
                        "label": "Hybrid wire cost",
                        "value": f"{relative.get('hybrid_wire_overhead_ratio', '—')}×",
                        "note": "more bytes than RSA-2048",
                        "colour": ui.AMBER,
                        "value_colour": ui.AMBER,
                    },
                ]
            )

        chart_a, chart_b = st.columns(2)
        with chart_a:
            st.markdown("**Key generation — ms, log scale**")
            figure = go.Figure(
                go.Bar(
                    x=names,
                    y=[r["keygen_ms"] for r in rows],
                    marker=dict(color=colours, line=dict(width=0)),
                    text=[f"{r['keygen_ms']:.3f}" for r in rows],
                    textposition="outside",
                    textfont=dict(family=ui.MONO, size=11),
                )
            )
            figure.update_yaxes(type="log")
            st.plotly_chart(ui.chart_layout(figure, 290), width="stretch")

        with chart_b:
            st.markdown("**Decapsulate + decrypt — ms, log scale**")
            figure = go.Figure(
                go.Bar(
                    x=names,
                    y=[r["decapsulate_decrypt_ms"] for r in rows],
                    marker=dict(color=colours, line=dict(width=0)),
                    text=[f"{r['decapsulate_decrypt_ms']:.3f}" for r in rows],
                    textposition="outside",
                    textfont=dict(family=ui.MONO, size=11),
                )
            )
            figure.update_yaxes(type="log")
            st.plotly_chart(ui.chart_layout(figure, 290), width="stretch")

        st.markdown("**Key and ciphertext sizes — bytes**")
        figure = go.Figure()
        figure.add_bar(
            x=names,
            y=[r["public_key_bytes"] for r in rows],
            name="Public key",
            marker=dict(color=ui.CYAN, line=dict(width=0)),
        )
        figure.add_bar(
            x=names,
            y=[r["kem_ciphertext_bytes"] for r in rows],
            name="KEM ciphertext",
            marker=dict(color=ui.VIOLET, line=dict(width=0)),
        )
        figure.add_bar(
            x=names,
            y=[r["wire_overhead_bytes"] for r in rows],
            name="Wire overhead",
            marker=dict(color=ui.AMBER, line=dict(width=0)),
        )
        figure.update_layout(barmode="group")
        chart = ui.chart_layout(figure, 300)
        chart.update_layout(
            showlegend=True,
            legend=dict(orientation="h", y=1.14, font=dict(family=ui.MONO, size=10)),
        )
        st.plotly_chart(chart, width="stretch")

        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Algorithm": SHORT_LABELS.get(r["algorithm"], r["algorithm"]),
                        "Quantum safe": "yes" if r["quantum_safe"] else "no",
                        "Keygen (ms)": r["keygen_ms"],
                        "Encapsulate + encrypt (ms)": r["encapsulate_encrypt_ms"],
                        "Decapsulate + decrypt (ms)": r["decapsulate_decrypt_ms"],
                        "Public key (B)": r["public_key_bytes"],
                        "KEM ct (B)": r["kem_ciphertext_bytes"],
                        "Wire overhead (B)": r["wire_overhead_bytes"],
                    }
                    for r in rows
                ]
            ),
            width="stretch",
            hide_index=True,
        )

        ui.section("Engineering trade-off", eyebrow="Interpretation")
        for tradeoff in bundle["tradeoffs"]:
            ui.panel(
                title=tradeoff["algorithm"],
                meta=tradeoff["verdict"],
                body=f"<b>Advantage:</b> {tradeoff['advantage']}<br>"
                f"<b>Cost:</b> {tradeoff['cost']}",
                accent=ui.CRITICAL if tradeoff["algorithm"].startswith("RSA") else ui.SAFE,
            )

        ui.section("Quantum resource estimates", eyebrow="Research-based")
        estimated = bundle["estimated"]
        st.markdown(ui.pill("ESTIMATED / RESEARCH-BASED", ui.AMBER), unsafe_allow_html=True)
        ui.note(f"<b>{estimated['note']}</b>", ui.AMBER)
        ui.table(
            ["Metric", "Value", "Source"],
            [
                [
                    f'<span class="lead">{row["metric"]}</span>',
                    mono(row["value"]),
                    row["citation"],
                ]
                for row in estimated["rows"]
            ],
        )
