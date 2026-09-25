"""
Aegis PQC — migration prioritisation and roadmap.

Answers the organisational question the earlier phases deliberately did not:
*given the context, which migration actions deserve earlier attention, and why?*

WHERE THIS SITS
---------------
Phase 7 said how quantum-relevant a finding is. Phase 8 said what remediation
direction is appropriate. Phase 9 applies organisational context — business
criticality above all — to those conclusions to produce an explainable
priority. It consumes the Phase 8 :class:`~backend.model.RecommendationResult`
(which already carries the Phase 7 risk level and Mosca status) plus the
:class:`~backend.model.ApplicationContext`. It recomputes nothing.

A DECISION TREE, NOT A SCORE
----------------------------
There is no weighted formula. Priority is assigned by an ordered precedence of
rules, each of which is a plain-language statement a reviewer can check. The
first matching rule wins, and it records the factors that placed the item where
it did. No risk conclusion is counted twice.

PRIORITY IS NOT RISK
--------------------
A CRITICAL quantum-risk finding is not automatically the top priority. The
IMMEDIATE bucket requires *both* that the finding is within the assumed
quantum-threat window *and* that the owning system is business-critical. A
within-window finding on a system whose criticality the organisation never
declared is HIGH, not IMMEDIATE — and the rationale says the criticality was
unknown rather than assuming it.

WHAT IT WILL NOT DO
-------------------
It does not invent business criticality from an algorithm or a component name,
does not invent migration effort, cost, latency, or calendar dates, does not
turn "no migration indicated" into a task, and does not recompute Mosca. Where
an input is missing it says so. Nothing executes, opens a socket, or reads a
file.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from backend.model import (
    ApplicationContext,
    BusinessCriticality,
    Confidence,
    MigrationPriority,
    MigrationPriorityResult,
    RecommendationResult,
    RemediationClass,
    RoadmapBucket,
    RoadmapItem,
)

#: Reason-class labels — a short machine tag for the kind of reason, alongside
#: the human rationale.
REASON_NO_MIGRATION = "no_migration_indicated"
REASON_PQC_MIGRATION = "pqc_migration"
REASON_CLASSICAL = "classical_remediation"
REASON_EVIDENCE_GAP = "evidence_gap"
REASON_USAGE_UNVERIFIED = "usage_unverified"
REASON_STRENGTHENING = "classical_strengthening"

#: The value used when the organisation declared no business criticality.
CRITICALITY_UNKNOWN = "unknown"

#: Roadmap bucket for each priority. NO_ACTION maps to nothing — it is not work.
_BUCKET_BY_PRIORITY: dict[MigrationPriority, RoadmapBucket | None] = {
    MigrationPriority.IMMEDIATE: RoadmapBucket.IMMEDIATE_ATTENTION,
    MigrationPriority.HIGH: RoadmapBucket.NEAR_TERM,
    MigrationPriority.PLANNED: RoadmapBucket.PLANNED,
    MigrationPriority.EVIDENCE_REQUIRED: RoadmapBucket.EVIDENCE_COLLECTION,
    MigrationPriority.MONITOR: RoadmapBucket.MONITORING,
    MigrationPriority.NO_ACTION: None,
}


# ==========================================================================
# Context resolution
# ==========================================================================


@dataclass(frozen=True, slots=True)
class _Criticality:
    """A resolved business-criticality value with its provenance."""

    value: str
    declared: bool

    @property
    def is_critical(self) -> bool:
        return self.declared and self.value == BusinessCriticality.CRITICAL.value

    @property
    def is_high_or_above(self) -> bool:
        return self.declared and self.value in (
            BusinessCriticality.CRITICAL.value,
            BusinessCriticality.HIGH.value,
        )


def _resolve_criticality(context: ApplicationContext | None) -> _Criticality:
    """Resolve business criticality, never guessing.

    A criticality is used only when the organisation declared the context. An
    undeclared or absent context yields ``unknown`` — the engine must not infer
    criticality from the algorithm or the component's name.
    """
    if context is not None and context.is_declared:
        return _Criticality(value=context.business_criticality.value, declared=True)
    return _Criticality(value=CRITICALITY_UNKNOWN, declared=False)


# ==========================================================================
# The decision tree
# ==========================================================================


def prioritize(
    recommendation: RecommendationResult,
    context: ApplicationContext | None = None,
) -> MigrationPriorityResult:
    """Assign an explainable migration priority to one recommendation.

    Rules are applied in precedence order; the first match wins and records why.
    The Phase 7 risk level and Mosca status, and the Phase 8 remediation class,
    are read from the recommendation and never recomputed.
    """
    criticality = _resolve_criticality(context)
    remediation = _remediation_class(recommendation)

    base = dict(
        finding_id=recommendation.finding_id,
        recommendation_id=recommendation.recommendation_id,
        component=recommendation.component,
        business_criticality=criticality.value,
        risk_level=recommendation.risk_level,
        mosca_status=recommendation.mosca_status,
        quantum_category=recommendation.quantum_category,
        remediation_class=recommendation.remediation_class.value,
        confidence=recommendation.confidence,
        evidence_level=recommendation.evidence_level,
        provenance=(
            f"finding:{recommendation.finding_id}; "
            f"recommendation:{recommendation.recommendation_id}; "
            f"risk:{recommendation.risk_level}; mosca:{recommendation.mosca_status}"
        ),
    )

    # --- Rule 1: no migration indicated (already-PQC, or a healthy primitive) ---
    if remediation is RemediationClass.NONE_REQUIRED:
        return _result(
            MigrationPriority.NO_ACTION,
            REASON_NO_MIGRATION,
            base,
            rationale=[
                "No post-quantum migration is indicated by this finding, so no "
                "migration work is created.",
            ],
            factors=["remediation class indicates no migration"],
        )

    # --- Rule 2: library capability, usage not established ---
    if remediation is RemediationClass.USAGE_NOT_ESTABLISHED:
        return _result(
            MigrationPriority.EVIDENCE_REQUIRED,
            REASON_USAGE_UNVERIFIED,
            base,
            rationale=[
                "A cryptographic library capability was detected but the "
                "application's actual use of it was not established. This is an "
                "evidence-verification task, not an application migration.",
            ],
            factors=["capability detected", "usage not established"],
            assumptions=["No algorithm usage was confirmed for this library."],
        )

    # --- Rule 3: insufficient evidence (unknown algorithm/role/protocol) ---
    if remediation is RemediationClass.INSUFFICIENT_EVIDENCE:
        missing = recommendation.additional_evidence_required or [
            "The information needed to choose a remediation direction."
        ]
        return _result(
            MigrationPriority.EVIDENCE_REQUIRED,
            REASON_EVIDENCE_GAP,
            base,
            rationale=[
                "A safe migration decision cannot be made yet: the evidence does "
                "not establish a remediation direction. This is not a claim that "
                "the asset is the highest-risk item — only that information is "
                "missing.",
            ],
            factors=["insufficient evidence for a remediation direction"],
            assumptions=[f"Missing: {item}" for item in missing],
        )

    # --- Rule 4: classical security issue (MD5, SHA-1, DES, 3DES) ---
    if remediation is RemediationClass.NON_QUANTUM_ISSUE:
        if criticality.is_high_or_above:
            priority = MigrationPriority.HIGH
            factor = f"classical weakness on a {criticality.value}-criticality system"
        else:
            priority = MigrationPriority.PLANNED
            factor = (
                "classical weakness on a lower- or unknown-criticality system"
                if not criticality.declared
                else f"classical weakness on a {criticality.value}-criticality system"
            )
        return _result(
            priority,
            REASON_CLASSICAL,
            base,
            rationale=[
                "This is a classical security weakness (independent of quantum "
                "computing), which is real remediation work but not a "
                "post-quantum migration.",
                _criticality_sentence(criticality),
            ],
            factors=[factor],
            assumptions=_criticality_assumptions(criticality),
        )

    # --- Rule 5/6: quantum-vulnerable migration (hybrid KEM or PQC signature) ---
    # Both HYBRID and PQC_NATIVE are real migrations away from a quantum-
    # vulnerable algorithm; they share the same timing-driven prioritisation.
    if remediation in (RemediationClass.HYBRID, RemediationClass.PQC_NATIVE):
        return _prioritise_quantum_migration(recommendation, criticality, base)

    # --- Rule 9: classical strengthening (AES-128) ---
    if remediation is RemediationClass.CLASSICAL_STRENGTHENING:
        if criticality.is_high_or_above:
            priority = MigrationPriority.PLANNED
            factor = f"strengthening on a {criticality.value}-criticality system"
        else:
            priority = MigrationPriority.MONITOR
            factor = "strengthening on a lower- or unknown-criticality system"
        return _result(
            priority,
            REASON_STRENGTHENING,
            base,
            rationale=[
                "Classical strengthening may apply (for example a larger "
                "symmetric key for long-lived data); this is not a post-quantum "
                "migration.",
                _criticality_sentence(criticality),
            ],
            factors=[factor],
            assumptions=_criticality_assumptions(criticality),
        )

    # --- Fallback: anything unclassified is monitored, never invented into work ---
    return _result(
        MigrationPriority.MONITOR,
        REASON_NO_MIGRATION,
        base,
        rationale=[
            "No specific migration priority rule applied; the item is flagged for "
            "monitoring rather than assigned invented work.",
        ],
        factors=["no specific rule matched"],
    )


def _prioritise_quantum_migration(
    recommendation: RecommendationResult,
    criticality: _Criticality,
    base: dict[str, Any],
) -> MigrationPriorityResult:
    """Prioritise a quantum-vulnerable migration using the Phase 7 Mosca status.

    Covers both hybrid key-establishment migrations and PQC-native signature
    migrations — both move away from a quantum-vulnerable algorithm. The Mosca
    status is read, not recomputed; timing drives the priority, and business
    criticality decides whether a within-window finding is IMMEDIATE or HIGH.
    """
    mosca = recommendation.mosca_status

    if mosca == "within_quantum_window":
        if criticality.is_critical:
            return _result(
                MigrationPriority.IMMEDIATE,
                REASON_PQC_MIGRATION,
                base,
                rationale=[
                    "Quantum-vulnerable and placed within the assumed "
                    "quantum-threat window by Phase 7, on a business-critical "
                    "system. This combination warrants the earliest attention.",
                ],
                factors=[
                    "quantum-vulnerable",
                    "within the assumed quantum-threat window",
                    "business-critical system",
                ],
            )
        return _result(
            MigrationPriority.HIGH,
            REASON_PQC_MIGRATION,
            base,
            rationale=[
                "Quantum-vulnerable and within the assumed quantum-threat window "
                "by Phase 7. "
                + _criticality_sentence(criticality)
                + " The window placement drives near-term attention; the top "
                "bucket is reserved for business-critical systems.",
            ],
            factors=[
                "quantum-vulnerable",
                "within the assumed quantum-threat window",
                f"criticality: {criticality.value}",
            ],
            assumptions=_criticality_assumptions(criticality),
        )

    if mosca == "insufficient_information":
        return _result(
            MigrationPriority.EVIDENCE_REQUIRED,
            REASON_EVIDENCE_GAP,
            base,
            rationale=[
                "The algorithm is quantum-vulnerable, but Phase 7 could not "
                "complete the Mosca time-horizon analysis (a required input was "
                "missing), so the timing of migration cannot yet be judged.",
            ],
            factors=[
                "quantum-vulnerable",
                "Mosca time-horizon unresolved (insufficient information)",
            ],
            assumptions=[
                "The data lifetime, migration time, or CRQC horizon was not "
                "available to Phase 7."
            ],
        )

    if mosca == "outside_quantum_window":
        return _result(
            MigrationPriority.PLANNED,
            REASON_PQC_MIGRATION,
            base,
            rationale=[
                "Quantum-vulnerable, but Phase 7 placed it outside the assumed "
                "quantum-threat window under the configured assumptions. "
                "Migration remains appropriate but is not time-pressured, "
                "conditional on those assumptions.",
            ],
            factors=[
                "quantum-vulnerable",
                "outside the assumed quantum-threat window under the assumptions",
            ],
        )

    # not_time_sensitive or unexpected: migration direction exists but no timing
    # pressure was established.
    return _result(
        MigrationPriority.PLANNED,
        REASON_PQC_MIGRATION,
        base,
        rationale=[
            "A post-quantum migration direction applies, but no time-horizon "
            "pressure was established for it.",
        ],
        factors=["quantum-vulnerable", "no established timing pressure"],
    )


# ==========================================================================
# Helpers
# ==========================================================================


def _remediation_class(recommendation: RecommendationResult) -> RemediationClass:
    """The Phase 8 remediation class, as an enum."""
    return recommendation.remediation_class


def _criticality_sentence(criticality: _Criticality) -> str:
    """A sentence stating the criticality and whether it was declared."""
    if not criticality.declared:
        return (
            "Business criticality was not declared for this component, so it is "
            "treated as unknown rather than assumed."
        )
    return f"Business criticality is declared {criticality.value}."


def _criticality_assumptions(criticality: _Criticality) -> list[str]:
    """Assumption notes about criticality provenance."""
    if not criticality.declared:
        return ["Business criticality was not declared; treated as unknown."]
    return [f"Business criticality declared as {criticality.value}."]


def _result(
    priority: MigrationPriority,
    reason_class: str,
    base: dict[str, Any],
    rationale: list[str],
    factors: list[str],
    assumptions: list[str] | None = None,
) -> MigrationPriorityResult:
    """Assemble a priority result from the common base and rule-specific parts."""
    return MigrationPriorityResult(
        priority=priority,
        reason_class=reason_class,
        rationale=rationale,
        priority_factors=factors,
        assumptions=assumptions or [],
        **base,
    )


# ==========================================================================
# Batch and roadmap
# ==========================================================================


def prioritize_batch(
    recommendations: Iterable[RecommendationResult],
    contexts: dict[str, ApplicationContext] | None = None,
) -> list[MigrationPriorityResult]:
    """Prioritise a set of recommendations.

    Deterministic and order-independent: results are sorted first by priority
    rank, then by finding id, so the same input always yields the same ordering
    regardless of the order it arrived in.

    Args:
        recommendations: Phase 8 recommendations.
        contexts: Per-component organisation context, if available.

    Returns:
        One priority result per recommendation, ordered by (priority, finding id).
    """
    contexts = contexts or {}
    results: list[MigrationPriorityResult] = []

    for recommendation in recommendations:
        context = contexts.get(recommendation.component)
        results.append(prioritize(recommendation, context))

    return sorted(results, key=lambda r: (r.priority_rank, r.finding_id))


def build_roadmap(
    results: Iterable[MigrationPriorityResult],
    recommendations: Iterable[RecommendationResult] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Group priority results into roadmap buckets.

    The grouping is a deterministic consequence of the priority — no new
    decision is made here. NO_ACTION items are excluded, because they are not
    work. Recommendation titles/targets are joined in for display when the
    recommendations are supplied.

    Args:
        results: Priority results from :func:`prioritize_batch`.
        recommendations: Optional recommendations, to enrich items with title
            and target.

    Returns:
        A mapping of roadmap-bucket value to a list of item dicts, each bucket's
        items ordered by finding id. Empty buckets are omitted.
    """
    rec_by_finding = {}
    if recommendations:
        rec_by_finding = {r.finding_id: r for r in recommendations}

    buckets: dict[str, list[RoadmapItem]] = {}

    for result in results:
        bucket = _BUCKET_BY_PRIORITY.get(result.priority)
        if bucket is None:
            continue  # NO_ACTION is not roadmap work.

        recommendation = rec_by_finding.get(result.finding_id)
        item = RoadmapItem(
            finding_id=result.finding_id,
            recommendation_id=result.recommendation_id,
            component=result.component,
            priority=result.priority,
            title=recommendation.title if recommendation else "",
            target=recommendation.target if recommendation else "",
        )
        buckets.setdefault(bucket.value, []).append(item)

    # Deterministic ordering within each bucket, and stable bucket order.
    ordered: dict[str, list[dict[str, Any]]] = {}
    for bucket in RoadmapBucket:
        items = buckets.get(bucket.value)
        if items:
            ordered[bucket.value] = [
                item.to_dict()
                for item in sorted(items, key=lambda i: i.finding_id)
            ]
    return ordered


def summarize(results: list[MigrationPriorityResult]) -> dict[str, Any]:
    """Aggregate counts over priority results.

    Counts by priority and by reason class only. No "worst asset", no ranking
    beyond the defined priority taxonomy.
    """
    by_priority: dict[str, int] = {}
    by_reason: dict[str, int] = {}

    for result in results:
        by_priority[result.priority.value] = by_priority.get(result.priority.value, 0) + 1
        by_reason[result.reason_class] = by_reason.get(result.reason_class, 0) + 1

    # Migration work excludes NO_ACTION items.
    actionable = sum(
        1 for r in results if r.priority is not MigrationPriority.NO_ACTION
    )

    return {
        "total": len(results),
        "actionable": actionable,
        "by_priority": dict(sorted(by_priority.items())),
        "by_reason_class": dict(sorted(by_reason.items())),
    }
