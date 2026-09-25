"""
Aegis PQC — remediation recommendation engine.

Translates an established finding and its Phase 7 quantum-risk conclusion into a
defensible remediation *direction*: what kind of change is appropriate, a
concrete target only where the mapping holds, and an explicit account of what
the evidence does not establish.

WHAT THIS IS
------------
A pure downstream computation layer, like :mod:`backend.quantum_risk`. It
consumes canonical :class:`~backend.model.CryptoFinding` objects and
:class:`~backend.model.QuantumRiskResult` conclusions; it scans nothing, opens
no socket, runs no subprocess, and reads no file beyond the knowledge base
loaded at import.

WHAT IT DOES NOT DO
-------------------
It does not recompute risk or Mosca — those come from Phase 7 unchanged. It
does not rank, sequence, or prioritise — that is Phase 9. It does not invent
benchmarks; where no measured data exists it says so.

ROLE-AWARENESS IS THE POINT
---------------------------
"Replace RSA with ML-KEM" is wrong for an RSA *signature*. The engine keys its
mapping on the cryptographic role the finding recorded:

* key establishment (RSA transport, ECDH, X25519) → toward ML-KEM / a hybrid
* signature (RSA, ECDSA, EdDSA) → toward ML-DSA or SLH-DSA

When the role is unknown, the engine does not guess a role; it produces a
conditional recommendation and names the evidence that would resolve it.

CAPABILITY IS NOT USAGE
-----------------------
A library capability finding yields ``USAGE_NOT_ESTABLISHED``, never a migration
recommendation for the application. The Phase 2/6/7 discipline is preserved:
detecting that a package *can* do RSA is not evidence the application *does*.

HYBRID IS NOT INFERRED
----------------------
The engine never concludes "this is a hybrid" from the co-presence of X25519 and
ML-KEM in one component. Phase 7 keeps those findings separate; Phase 8 keeps
them separate too. A hybrid *target* may be recommended for a classical key-
establishment finding, but that is a recommendation direction, not a claim that
a hybrid is already deployed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from backend.knowledge import parse_simple_yaml
from backend.model import (
    Confidence,
    CryptoFinding,
    MoscaStatus,
    QuantumCategory,
    QuantumRiskResult,
    RecommendationResult,
    RemediationClass,
)

#: Knowledge base location.
KNOWLEDGE_PATH = Path(__file__).resolve().parent / "knowledge" / "recommendations.yaml"

#: Performance is not measured per finding in the current evidence. Every
#: recommendation states this rather than inventing a number.
_PERFORMANCE_NOT_MEASURED = (
    "Performance impact not measured in current evidence. Post-quantum key "
    "establishment and signatures generally carry larger keys or ciphertexts "
    "than their classical counterparts; treat this as a qualitative "
    "consideration, not a measured result."
)

_CLASS_BY_NAME: dict[str, RemediationClass] = {c.value: c for c in RemediationClass}


# ==========================================================================
# Knowledge base
# ==========================================================================


@dataclass(frozen=True, slots=True)
class Mapping:
    """One remediation mapping from the knowledge base."""

    remediation_class: RemediationClass
    target: str = ""
    standard: str = ""
    note: str = ""


class RecommendationKnowledge:
    """Loaded remediation knowledge, queried by algorithm and role."""

    def __init__(self, path: Path | None = None) -> None:
        raw = self._load(path or KNOWLEDGE_PATH)
        self._public_key: dict[str, dict[str, Mapping]] = {}
        for algo, roles in (raw.get("public_key") or {}).items():
            if isinstance(roles, dict):
                self._public_key[algo] = {
                    role: self._mapping(values)
                    for role, values in roles.items()
                    if isinstance(values, dict)
                }
        self._symmetric = self._flat(raw.get("symmetric"))
        self._hash = self._flat(raw.get("hash"))
        self._kdf_mac = self._flat(raw.get("kdf_mac"))
        self._post_quantum: dict[str, str] = {
            name: str(v.get("note", ""))
            for name, v in (raw.get("post_quantum") or {}).items()
            if isinstance(v, dict)
        }
        self._protocols: dict[str, str] = {
            name: str(v.get("note", ""))
            for name, v in (raw.get("protocols") or {}).items()
            if isinstance(v, dict)
        }

    @staticmethod
    def _load(path: Path) -> dict[str, Any]:
        try:
            return parse_simple_yaml(path.read_text(encoding="utf-8"))
        except OSError:
            return {}

    @staticmethod
    def _mapping(values: dict[str, Any]) -> Mapping:
        cls = _CLASS_BY_NAME.get(
            str(values.get("remediation_class", "")), RemediationClass.INSUFFICIENT_EVIDENCE
        )
        return Mapping(
            remediation_class=cls,
            target=str(values.get("target", "")),
            standard=str(values.get("standard", "")),
            note=str(values.get("note", "")),
        )

    def _flat(self, section: Any) -> dict[str, Mapping]:
        if not isinstance(section, dict):
            return {}
        return {
            name: self._mapping(values)
            for name, values in section.items()
            if isinstance(values, dict)
        }

    def public_key(self, algorithm: str, role: str) -> Mapping | None:
        """Role-specific mapping for a public-key algorithm, or ``None``."""
        entry = self._public_key.get(algorithm)
        if entry is None and "-" in algorithm:
            entry = self._public_key.get(algorithm.rsplit("-", 1)[0])
        if entry is None:
            return None
        return entry.get(role)

    def public_key_roles(self, algorithm: str) -> list[str]:
        """Roles the knowledge base has mappings for, for this algorithm."""
        entry = self._public_key.get(algorithm)
        if entry is None and "-" in algorithm:
            entry = self._public_key.get(algorithm.rsplit("-", 1)[0])
        return sorted(entry) if entry else []

    def symmetric(self, variant: str) -> Mapping | None:
        return self._symmetric.get(variant)

    def hash_(self, algorithm: str) -> Mapping | None:
        return self._hash.get(algorithm)

    def kdf_mac(self, algorithm: str) -> Mapping | None:
        return self._kdf_mac.get(algorithm)

    def post_quantum_note(self, algorithm: str) -> str | None:
        note = self._post_quantum.get(algorithm)
        if note is None and "-" in algorithm:
            note = self._post_quantum.get(algorithm.rsplit("-", 1)[0])
        return note

    def protocol_note(self, algorithm: str) -> str | None:
        return self._protocols.get(algorithm)


#: Module-level knowledge, loaded once.
_KNOWLEDGE = RecommendationKnowledge()


# ==========================================================================
# Recommendation construction
# ==========================================================================


def _recommendation_id(finding_id: str) -> str:
    """Deterministic recommendation id derived from the finding id."""
    digest = hashlib.sha256(f"rec|{finding_id}".encode("utf-8")).hexdigest()[:12]
    return f"rec_{digest}"


def _base(finding: CryptoFinding, risk: QuantumRiskResult) -> dict[str, Any]:
    """Fields common to every recommendation, carried from finding and risk.

    Confidence and evidence level come from the risk result unchanged, so a
    recommendation never looks more authoritative than the evidence beneath it.
    """
    return dict(
        recommendation_id=_recommendation_id(finding.finding_id),
        finding_id=finding.finding_id,
        component=risk.component,
        current_algorithm=finding.algorithm,
        role=risk.role,
        quantum_category=risk.quantum_category.value,
        risk_level=risk.risk_level.value,
        mosca_status=risk.mosca_status.value,
        confidence=risk.confidence,
        evidence_level=risk.evidence_level,
        provenance=f"finding:{finding.finding_id}; risk:{risk.quantum_category.value}",
        source_type=risk.source_type,
        artefact_type=risk.artefact_type,
    )


def _symmetric_lookup_key(finding: CryptoFinding) -> str:
    """The knowledge-base key for a symmetric finding.

    AES with a known key size maps to AES-128/AES-256; without a key size it
    falls back to the bare algorithm. Never invents a size — the Phase 3 rule.
    """
    if finding.algorithm == "AES" and finding.key_size is not None:
        return f"AES-{finding.key_size}"
    return finding.algorithm


def recommend(
    finding: CryptoFinding, risk: QuantumRiskResult
) -> RecommendationResult:
    """Produce a remediation recommendation for one finding.

    The decision path mirrors the quantum category Phase 7 assigned, so the two
    layers never disagree, and each branch states what it does and does not
    establish.
    """
    base = _base(finding, risk)
    category = risk.quantum_category

    if category is QuantumCategory.CAPABILITY_ONLY:
        return _capability(finding, risk, base)
    if category is QuantumCategory.PROTOCOL_DEPENDENT:
        return _protocol(finding, risk, base)
    if category is QuantumCategory.UNKNOWN:
        return _unknown(finding, risk, base)
    if category is QuantumCategory.POST_QUANTUM:
        return _post_quantum(finding, risk, base)
    if category is QuantumCategory.QUANTUM_VULNERABLE:
        return _vulnerable(finding, risk, base)
    if category in (QuantumCategory.SYMMETRIC_REDUCED, QuantumCategory.NOT_APPLICABLE):
        return _symmetric_or_hash(finding, risk, base)

    # Defensive default — every category above is handled.
    return RecommendationResult(
        remediation_class=RemediationClass.INSUFFICIENT_EVIDENCE,
        title="No recommendation could be established",
        rationale=["The finding did not fall into a known remediation category."],
        **base,
    )


def _capability(finding, risk, base) -> RecommendationResult:
    """Library capability: usage not established, so no migration recommended."""
    library = finding.library or "a cryptographic library"
    return RecommendationResult(
        remediation_class=RemediationClass.USAGE_NOT_ESTABLISHED,
        title="Verify usage before recommending remediation",
        rationale=[
            f"{library} was detected as a dependency, but the inventory did not "
            "establish that the application uses any specific algorithm from it.",
            "A capability is not evidence of use, so no application-level "
            "migration is recommended from this finding alone.",
        ],
        limitations=["No algorithm usage was established for this library."],
        additional_evidence_required=[
            "Source or binary evidence of an actual cryptographic call site "
            "confirming which algorithms the application uses from this library.",
        ],
        **base,
    )


def _protocol(finding, risk, base) -> RecommendationResult:
    """Protocol finding: recommendation is conditional on the negotiated suite."""
    note = _KNOWLEDGE.protocol_note(finding.algorithm) or (
        "A protocol's exposure depends on the algorithms it negotiates, which "
        "this finding does not establish."
    )
    return RecommendationResult(
        remediation_class=RemediationClass.INSUFFICIENT_EVIDENCE,
        title="Protocol-dependent — determine the negotiated suite",
        rationale=[
            note,
            "No concrete migration target can be given until the negotiated "
            "key-establishment and signature algorithms are established.",
        ],
        limitations=[
            "The protocol finding alone does not establish the negotiated "
            "cryptographic construction.",
        ],
        additional_evidence_required=[
            "The negotiated cipher suite or key-exchange group, from "
            "configuration or a handshake capture.",
        ],
        **base,
    )


def _unknown(finding, risk, base) -> RecommendationResult:
    """Unknown algorithm: no guess, and a statement of what is missing."""
    label = finding.algorithm or "the artefact"
    return RecommendationResult(
        remediation_class=RemediationClass.INSUFFICIENT_EVIDENCE,
        title="Insufficient evidence for a remediation recommendation",
        rationale=[
            f"{label} was not classified by the quantum-risk knowledge base, so "
            "no defensible remediation direction can be established.",
        ],
        limitations=["The algorithm is unrecognised; its quantum relevance is unknown."],
        additional_evidence_required=[
            "The specific algorithm in use, and its cryptographic role.",
        ],
        **base,
    )


def _post_quantum(finding, risk, base) -> RecommendationResult:
    """Already-PQC: recognise the primitive; no classical-to-PQC migration."""
    note = _KNOWLEDGE.post_quantum_note(finding.algorithm) or (
        f"{finding.algorithm} is a post-quantum primitive."
    )
    return RecommendationResult(
        remediation_class=RemediationClass.NONE_REQUIRED,
        title="PQC-native — no classical-to-PQC migration indicated",
        rationale=[
            note,
            "The detected primitive is already post-quantum, so no "
            "classical-to-PQC replacement is indicated by this finding. This is "
            "not a claim of unconditional security.",
        ],
        **base,
    )


def _vulnerable(finding, risk, base) -> RecommendationResult:
    """Quantum-vulnerable public-key: role-aware target, Mosca carried through."""
    role = risk.role

    # Unknown role: do not invent one. Offer a conditional recommendation
    # naming the candidate directions and the evidence that would resolve it.
    if not role:
        roles = _KNOWLEDGE.public_key_roles(finding.algorithm)
        rationale = [
            f"{finding.algorithm} is quantum-vulnerable public-key "
            "cryptography, but its cryptographic role was not established.",
            "The appropriate target depends on the role: key establishment "
            "maps toward ML-KEM or a hybrid, a signature toward ML-DSA. The "
            "role must be established before a concrete target is given.",
        ]
        return RecommendationResult(
            remediation_class=RemediationClass.INSUFFICIENT_EVIDENCE,
            title="Quantum-vulnerable — establish the role to choose a target",
            rationale=_carry_mosca(rationale, risk),
            limitations=["The cryptographic role was not established."],
            additional_evidence_required=[
                "Whether the algorithm is used for key establishment or "
                f"signatures (known mappings exist for: {', '.join(roles) or 'n/a'}).",
            ],
            **base,
        )

    mapping = _KNOWLEDGE.public_key(finding.algorithm, role)
    if mapping is None:
        # Known-vulnerable, known-role, but no defensible mapping (e.g. a role
        # the KB does not cover for this algorithm). Do not invent a target.
        return RecommendationResult(
            remediation_class=RemediationClass.INSUFFICIENT_EVIDENCE,
            title="Quantum-vulnerable — no defensible target for this role",
            rationale=_carry_mosca(
                [
                    f"{finding.algorithm} in the role '{role.replace('_', ' ')}' is "
                    "quantum-vulnerable, but the knowledge base has no defensible "
                    "remediation target for that specific combination.",
                ],
                risk,
            ),
            limitations=[
                f"No mapping is encoded for {finding.algorithm} used as "
                f"'{role.replace('_', ' ')}'.",
            ],
            **base,
        )

    rationale = [
        f"{finding.algorithm} used for {role.replace('_', ' ')} is "
        "quantum-vulnerable public-key cryptography.",
        mapping.note,
    ]
    return RecommendationResult(
        remediation_class=mapping.remediation_class,
        title=_title_for(mapping, finding, role),
        target=mapping.target,
        target_standard=mapping.standard,
        rationale=_carry_mosca(rationale, risk),
        performance_note=_PERFORMANCE_NOT_MEASURED,
        limitations=_vulnerable_limitations(finding, risk),
        **base,
    )


def _symmetric_or_hash(finding, risk, base) -> RecommendationResult:
    """Symmetric ciphers, hashes, KDFs, MACs — classical guidance, not PQC."""
    algorithm = finding.algorithm

    mapping = (
        _KNOWLEDGE.symmetric(_symmetric_lookup_key(finding))
        or _KNOWLEDGE.hash_(algorithm)
        or _KNOWLEDGE.kdf_mac(algorithm)
    )

    if mapping is None:
        # A symmetric/hash algorithm the KB has no specific guidance for. AES
        # with no key size lands here: real, but the strengthening question
        # cannot be answered without the size.
        limitations = []
        additional = []
        if algorithm == "AES" and finding.key_size is None:
            limitations = ["The AES key size was not established."]
            additional = ["The AES key size, to judge whether strengthening applies."]
        return RecommendationResult(
            remediation_class=RemediationClass.NONE_REQUIRED,
            title="No post-quantum migration indicated",
            rationale=[
                f"{algorithm} is symmetric or hash-based cryptography; no "
                "post-quantum public-key migration is indicated by its presence.",
            ],
            limitations=limitations,
            additional_evidence_required=additional,
            **base,
        )

    title = {
        RemediationClass.CLASSICAL_STRENGTHENING: "Classical strengthening may apply",
        RemediationClass.NON_QUANTUM_ISSUE: "Classical security issue",
        RemediationClass.NONE_REQUIRED: "No post-quantum migration indicated",
    }.get(mapping.remediation_class, "Remediation guidance")

    rationale = [mapping.note]
    if mapping.remediation_class is RemediationClass.CLASSICAL_STRENGTHENING:
        rationale.append(
            "This is classical strengthening, not a post-quantum replacement."
        )

    return RecommendationResult(
        remediation_class=mapping.remediation_class,
        title=title,
        target=mapping.target,
        target_standard=mapping.standard,
        rationale=rationale,
        **base,
    )


# ==========================================================================
# Helpers
# ==========================================================================


def _carry_mosca(rationale: list[str], risk: QuantumRiskResult) -> list[str]:
    """Append the Phase 7 Mosca conclusion without recomputing it.

    The recommendation reflects timing context established upstream; it never
    re-runs X + Y > Z.
    """
    if risk.mosca_status is MoscaStatus.WITHIN_QUANTUM_WINDOW and risk.mosca:
        rationale.append(
            "Phase 7 placed this asset within the assumed quantum-threat window "
            f"({risk.mosca.statement}), so migration is time-relevant."
        )
    elif risk.mosca_status is MoscaStatus.OUTSIDE_QUANTUM_WINDOW:
        rationale.append(
            "Phase 7 placed this asset outside the assumed quantum-threat window "
            "under the configured assumptions; migration remains appropriate but "
            "is less time-pressured, conditional on those assumptions."
        )
    elif risk.mosca_status is MoscaStatus.INSUFFICIENT_INFORMATION:
        rationale.append(
            "Phase 7 could not complete the Mosca time-horizon analysis "
            "(insufficient information), so timing is unresolved; the algorithm "
            "remains quantum-vulnerable regardless."
        )
    return rationale


def _vulnerable_limitations(finding: CryptoFinding, risk: QuantumRiskResult) -> list[str]:
    """State what a vulnerable-asset recommendation does not establish."""
    limitations: list[str] = []
    if finding.artefact_type == "certificate":
        limitations.append(
            "This is a certificate finding; it establishes the certificate's "
            "algorithm, not that the application uses this key for live key "
            "establishment."
        )
    if risk.confidence is Confidence.LOW:
        limitations.append(
            "The underlying evidence is low confidence; verify actual usage "
            "before acting."
        )
    if risk.mosca_status is MoscaStatus.INSUFFICIENT_INFORMATION:
        limitations.append(
            "The migration timing could not be assessed from the available "
            "assumptions."
        )
    return limitations


def _title_for(mapping: Mapping, finding: CryptoFinding, role: str) -> str:
    """A short heading reflecting the remediation class."""
    if mapping.remediation_class is RemediationClass.HYBRID:
        return "Migrate toward a hybrid post-quantum construction"
    if mapping.remediation_class is RemediationClass.PQC_NATIVE:
        return "Migrate toward a post-quantum algorithm"
    return "Remediation guidance"


# ==========================================================================
# Batch API
# ==========================================================================


def recommend_batch(
    findings: Iterable[CryptoFinding],
    risks: Iterable[QuantumRiskResult],
) -> list[RecommendationResult]:
    """Produce recommendations for a set of findings and their risk results.

    Findings and risk results are joined by ``finding_id``. A finding without a
    matching risk result is skipped — Phase 8 never assesses risk itself. Output
    is sorted by finding id, so it is deterministic and order-independent.

    Args:
        findings: Canonical findings.
        risks: Phase 7 risk results for those findings.

    Returns:
        One recommendation per finding that has a risk result, ordered by
        finding id.
    """
    finding_by_id = {f.finding_id: f for f in findings}
    results: list[RecommendationResult] = []

    for risk in risks:
        finding = finding_by_id.get(risk.finding_id)
        if finding is None:
            continue
        results.append(recommend(finding, risk))

    return sorted(results, key=lambda r: r.finding_id)


def summarize(recommendations: list[RecommendationResult]) -> dict[str, Any]:
    """Aggregate counts over recommendations.

    Counts only. No ranking, no "worst asset", no priority — those are Phase 9.
    """
    by_class: dict[str, int] = {}
    for rec in recommendations:
        by_class[rec.remediation_class.value] = (
            by_class.get(rec.remediation_class.value, 0) + 1
        )

    concrete_targets = sum(1 for r in recommendations if r.target)

    return {
        "total": len(recommendations),
        "by_remediation_class": dict(sorted(by_class.items())),
        "with_concrete_target": concrete_targets,
    }
