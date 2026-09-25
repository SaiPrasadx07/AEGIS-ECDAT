"""
Aegis PQC — ECDAT view helpers.

Pure functions that turn backend results into display-ready rows and labels.
They contain no Streamlit calls and no business logic, so they are tested
directly and the rendering layer stays a thin shell over them.

DISCIPLINE
----------
These helpers *format*; they never *decide*. They surface exactly what the
backend established, keep unknown values visibly unknown, keep capability
distinct from usage, and never invent a value for display. Colour choices map
existing categories to the shared design tokens — they add no meaning the
backend did not already assign.
"""

from __future__ import annotations

from typing import Any

from backend.model import (
    Confidence,
    MigrationPriority,
    MigrationPriorityResult,
    QuantumCategory,
    QuantumRiskResult,
    RecommendationResult,
    RemediationClass,
    RiskLevel,
)

# Design-token colours (mirrors frontend.ui values, kept here so this module is
# importable without Streamlit for testing).
CYAN = "#00d4ff"
VIOLET = "#8b6cff"
GREEN = "#00e08a"
AMBER = "#ffb020"
RED = "#ff4d5e"
ORANGE = "#ff8534"
GREY = "#6b7889"

#: Colour by quantum category. Vulnerable is red; post-quantum green; the
#: "we cannot say" states are grey, never coloured as if assessed.
QUANTUM_CATEGORY_COLOUR: dict[str, str] = {
    QuantumCategory.QUANTUM_VULNERABLE.value: RED,
    QuantumCategory.POST_QUANTUM.value: GREEN,
    QuantumCategory.SYMMETRIC_REDUCED.value: AMBER,
    QuantumCategory.NOT_APPLICABLE.value: GREY,
    QuantumCategory.CAPABILITY_ONLY.value: GREY,
    QuantumCategory.PROTOCOL_DEPENDENT.value: GREY,
    QuantumCategory.UNKNOWN.value: GREY,
}

#: Human labels for quantum categories.
QUANTUM_CATEGORY_LABEL: dict[str, str] = {
    QuantumCategory.QUANTUM_VULNERABLE.value: "Quantum-vulnerable",
    QuantumCategory.POST_QUANTUM.value: "PQC-ready",
    QuantumCategory.SYMMETRIC_REDUCED.value: "Symmetric (reduced margin)",
    QuantumCategory.NOT_APPLICABLE.value: "Not applicable",
    QuantumCategory.CAPABILITY_ONLY.value: "Capability only",
    QuantumCategory.PROTOCOL_DEPENDENT.value: "Protocol-dependent",
    QuantumCategory.UNKNOWN.value: "Unknown",
}

RISK_LEVEL_COLOUR: dict[str, str] = {
    RiskLevel.CRITICAL.value: RED,
    RiskLevel.HIGH.value: ORANGE,
    RiskLevel.MEDIUM.value: AMBER,
    RiskLevel.LOW_BASELINE.value: CYAN,
    RiskLevel.PQC_READY.value: GREEN,
    RiskLevel.UNKNOWN.value: GREY,
}

PRIORITY_COLOUR: dict[str, str] = {
    MigrationPriority.IMMEDIATE.value: RED,
    MigrationPriority.HIGH.value: ORANGE,
    MigrationPriority.PLANNED.value: AMBER,
    MigrationPriority.EVIDENCE_REQUIRED.value: VIOLET,
    MigrationPriority.MONITOR.value: CYAN,
    MigrationPriority.NO_ACTION.value: GREY,
}

PRIORITY_LABEL: dict[str, str] = {
    MigrationPriority.IMMEDIATE.value: "Immediate",
    MigrationPriority.HIGH.value: "High",
    MigrationPriority.PLANNED.value: "Planned",
    MigrationPriority.EVIDENCE_REQUIRED.value: "Evidence required",
    MigrationPriority.MONITOR.value: "Monitor",
    MigrationPriority.NO_ACTION.value: "No action",
}

REMEDIATION_LABEL: dict[str, str] = {
    RemediationClass.PQC_NATIVE.value: "PQC-native",
    RemediationClass.HYBRID.value: "Hybrid",
    RemediationClass.CLASSICAL_STRENGTHENING.value: "Classical strengthening",
    RemediationClass.NON_QUANTUM_ISSUE.value: "Non-quantum issue",
    RemediationClass.NONE_REQUIRED.value: "None required",
    RemediationClass.USAGE_NOT_ESTABLISHED.value: "Usage not established",
    RemediationClass.INSUFFICIENT_EVIDENCE.value: "Insufficient evidence",
}

CONFIDENCE_COLOUR: dict[str, str] = {
    Confidence.HIGH.value: GREEN,
    Confidence.MEDIUM.value: AMBER,
    Confidence.LOW.value: GREY,
}

#: Roadmap bucket display order and labels.
ROADMAP_BUCKET_ORDER = (
    "immediate_attention",
    "near_term_migration",
    "planned_migration",
    "evidence_collection",
    "monitoring",
)

ROADMAP_BUCKET_LABEL: dict[str, str] = {
    "immediate_attention": "Immediate attention",
    "near_term_migration": "Near-term migration",
    "planned_migration": "Planned migration",
    "evidence_collection": "Evidence collection",
    "monitoring": "Monitoring",
}

#: Sentinel shown wherever a value was genuinely not established.
UNKNOWN_DISPLAY = "—"


def _show(value: Any) -> str:
    """Render a value for display, keeping absence visibly absent."""
    if value is None or value == "":
        return UNKNOWN_DISPLAY
    return str(value)


# ==========================================================================
# Inventory rows
# ==========================================================================


def inventory_row(finding) -> dict[str, str]:
    """One inventory row from a canonical finding.

    Capability-only findings (a library with no algorithm) are marked as such,
    so a reader never mistakes a dependency for confirmed usage. Unknown fields
    stay ``—``.
    """
    is_capability = finding.artefact_type.value == "library" and not finding.algorithm
    return {
        "finding_id": finding.finding_id,
        "component": _show(finding.component),
        "algorithm": "capability only" if is_capability else _show(finding.algorithm),
        "variant": _show(finding.variant),
        "role": _show(finding.raw_detail.get("role")),
        "key_size": _show(finding.key_size),
        "mode": _show(finding.mode),
        "source_type": _show(finding.source_type.value),
        "language": _show(finding.raw_detail.get("language")),
        "evidence_level": _show(finding.raw_detail.get("evidence_level")),
        "confidence": _show(finding.confidence.value),
        "detection_method": _show(finding.detection_method.value),
        "library": _show(finding.library),
        "oid": _show(finding.oid),
    }


def inventory_filter_options(findings) -> dict[str, list[str]]:
    """Distinct filter values present in the data — only real options."""
    def distinct(values):
        return sorted({v for v in values if v})

    return {
        "component": distinct(f.component for f in findings),
        "algorithm": distinct(f.algorithm for f in findings),
        "source_type": distinct(f.source_type.value for f in findings),
        "evidence_level": distinct(f.raw_detail.get("evidence_level") for f in findings),
        "confidence": distinct(f.confidence.value for f in findings),
    }


def apply_inventory_filters(findings, filters: dict[str, str]):
    """Filter findings by the selected (non-empty) filter values.

    A filter value of ``""`` or ``"All"`` means no constraint on that field.
    """
    def keep(finding) -> bool:
        for field_name, wanted in filters.items():
            if not wanted or wanted == "All":
                continue
            if field_name == "component" and finding.component != wanted:
                return False
            if field_name == "algorithm" and finding.algorithm != wanted:
                return False
            if field_name == "source_type" and finding.source_type.value != wanted:
                return False
            if field_name == "evidence_level" and finding.raw_detail.get("evidence_level") != wanted:
                return False
            if field_name == "confidence" and finding.confidence.value != wanted:
                return False
        return True

    return [f for f in findings if keep(f)]


# ==========================================================================
# Risk rows
# ==========================================================================


def risk_row(risk: QuantumRiskResult) -> dict[str, str]:
    """One risk row from a Phase 7 result. No recomputation, display only."""
    return {
        "finding_id": risk.finding_id,
        "component": _show(risk.component),
        "algorithm": _show(risk.algorithm),
        "quantum_category": QUANTUM_CATEGORY_LABEL.get(
            risk.quantum_category.value, risk.quantum_category.value
        ),
        "risk_level": _show(risk.risk_level.value),
        "mosca_status": _show(risk.mosca_status.value),
        "confidence": _show(risk.confidence.value),
        "evidence_level": _show(risk.evidence_level),
    }


def mosca_view(risk: QuantumRiskResult) -> dict[str, Any]:
    """The Mosca relationship for display: inputs, calculation, result.

    Renders ``INSUFFICIENT_INFORMATION`` explicitly when Phase 7 could not
    complete the analysis, rather than substituting values.
    """
    if risk.mosca is None:
        return {
            "available": False,
            "status": risk.mosca_status.value,
            "statement": "Insufficient information — a required input was missing.",
            "x": None,
            "y": None,
            "z": None,
        }
    mosca = risk.mosca
    return {
        "available": True,
        "status": risk.mosca_status.value,
        "statement": mosca.statement,
        "x": mosca.x_data_lifetime_years,
        "y": mosca.y_migration_years,
        "z": mosca.z_horizon_years,
        "margin": mosca.margin_years,
        "verdict": mosca.verdict.value,
    }


# ==========================================================================
# Recommendation rows
# ==========================================================================


def recommendation_row(rec: RecommendationResult) -> dict[str, str]:
    """One recommendation row from a Phase 8 result."""
    return {
        "finding_id": rec.finding_id,
        "component": _show(rec.component),
        "current_algorithm": _show(rec.current_algorithm),
        "role": _show(rec.role),
        "remediation_class": REMEDIATION_LABEL.get(
            rec.remediation_class.value, rec.remediation_class.value
        ),
        "target": _show(rec.target),
        "target_standard": _show(rec.target_standard),
        "confidence": _show(rec.confidence.value),
    }


# ==========================================================================
# Migration / roadmap rows
# ==========================================================================


def priority_row(priority: MigrationPriorityResult) -> dict[str, str]:
    """One migration-priority row from a Phase 9 result."""
    return {
        "finding_id": priority.finding_id,
        "component": _show(priority.component),
        "priority": PRIORITY_LABEL.get(priority.priority.value, priority.priority.value),
        "reason_class": _show(priority.reason_class),
        "business_criticality": _show(priority.business_criticality),
        "risk_level": _show(priority.risk_level),
        "mosca_status": _show(priority.mosca_status),
    }


def ordered_roadmap(roadmap: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Roadmap buckets in display order, with labels and counts.

    Only non-empty buckets appear, in the fixed priority order.
    """
    ordered: list[dict[str, Any]] = []
    for bucket in ROADMAP_BUCKET_ORDER:
        items = roadmap.get(bucket)
        if items:
            ordered.append(
                {
                    "bucket": bucket,
                    "label": ROADMAP_BUCKET_LABEL.get(bucket, bucket),
                    "count": len(items),
                    "items": items,
                }
            )
    return ordered


# ==========================================================================
# Chart data (values only — the renderer draws)
# ==========================================================================


def source_type_distribution(findings) -> dict[str, int]:
    """Findings by source type, for a chart."""
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.source_type.value] = counts.get(finding.source_type.value, 0) + 1
    return dict(sorted(counts.items()))


def quantum_category_distribution(risks) -> dict[str, int]:
    """Risk results by quantum category, for a chart."""
    counts: dict[str, int] = {}
    for risk in risks:
        label = QUANTUM_CATEGORY_LABEL.get(
            risk.quantum_category.value, risk.quantum_category.value
        )
        counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items()))


def priority_distribution(priorities) -> dict[str, int]:
    """Priorities by bucket, for a chart. Ordered by urgency."""
    counts: dict[str, int] = {}
    for priority in priorities:
        counts[priority.priority.value] = counts.get(priority.priority.value, 0) + 1
    ordered = {}
    for key in (
        MigrationPriority.IMMEDIATE.value,
        MigrationPriority.HIGH.value,
        MigrationPriority.PLANNED.value,
        MigrationPriority.EVIDENCE_REQUIRED.value,
        MigrationPriority.MONITOR.value,
        MigrationPriority.NO_ACTION.value,
    ):
        if key in counts:
            ordered[PRIORITY_LABEL[key]] = counts[key]
    return ordered
