"""
Aegis PQC — quantum risk and Mosca analysis.

Given a cryptographic asset the discovery engine already found, this module
answers, auditably: what quantum issue applies to it, what assumptions are in
play, what information is missing, and why this particular classification was
reached.

WHAT THIS IS
------------
A computed-conclusions layer (layer 3 of the three-layer model). It consumes
canonical :class:`~backend.model.CryptoFinding` objects and organisation
context; it never scans anything. Every result is reproducible from its inputs
and traces back to the finding that caused it.

DECISION PATH, NOT A SCORE
--------------------------
There is no weighted risk number. A number like ``risk = 0.3·algo + 0.2·key +
…`` would invent precision and hide its reasoning. Instead each asset walks an
explicit path:

1. Is this a library capability rather than confirmed usage? → not assessed.
2. What does the knowledge base say the algorithm's quantum category is?
3. For quantum-vulnerable public-key crypto, run the Mosca time-horizon
   analysis against the configured assumptions.
4. Emit a categorical classification with a rationale built from the actual
   fields, and carry the finding's own evidence markers through unchanged.

MOSCA METHODOLOGY
-----------------
Mosca's inequality as a *planning* framework, not a calendar prediction:

    data_lifetime (X) + migration_time (Y) > crqc_horizon (Z)

When X + Y exceeds Z, data that must stay protected — plus the time to migrate
it — reaches into the window where a CRQC is assumed to exist. That is
``WITHIN_QUANTUM_WINDOW``. When a required input is missing, the outcome is
``INSUFFICIENT_INFORMATION``, never a guess. When the algorithm is not
quantum-vulnerable public-key cryptography, the time-horizon question does not
apply the same way and the status is ``NOT_TIME_SENSITIVE``.

THE CRQC HORIZON IS AN ASSUMPTION
---------------------------------
Z is never a hard-coded fact. It is configuration, carried with provenance and
surfaced in every result, so a reader always sees "CRQC assumption: N years,
source: …" rather than an implied prediction of when a quantum computer will
break RSA. No such prediction is made anywhere in this module.

WHAT IT DOES NOT DO
-------------------
No recommendations, no algorithm replacement, no migration roadmap or priority
ordering. Those are later phases. Nothing here executes, opens a socket, or
reads a file beyond the knowledge base loaded at import.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from backend.knowledge import parse_simple_yaml
from backend.model import (
    ApplicationContext,
    ArtefactType,
    Confidence,
    ContextSource,
    CryptoFinding,
    MoscaResult,
    MoscaStatus,
    MoscaVerdict,
    QuantumCategory,
    QuantumRiskResult,
    RiskAssumption,
    RiskLevel,
)

#: Knowledge base location.
KNOWLEDGE_PATH = Path(__file__).resolve().parent / "knowledge" / "quantum_risk.yaml"

#: Provenance tag for a value read directly from a finding.
SCANNER_OBSERVED = "scanner_observed"

# Category strings as written in the knowledge base.
_KB_VULNERABLE = "quantum_vulnerable"
_KB_SYMMETRIC = "symmetric_reduced"
_KB_POST_QUANTUM = "post_quantum"
_KB_NOT_APPLICABLE = "not_applicable"

_KB_TO_CATEGORY: dict[str, QuantumCategory] = {
    _KB_VULNERABLE: QuantumCategory.QUANTUM_VULNERABLE,
    _KB_SYMMETRIC: QuantumCategory.SYMMETRIC_REDUCED,
    _KB_POST_QUANTUM: QuantumCategory.POST_QUANTUM,
    _KB_NOT_APPLICABLE: QuantumCategory.NOT_APPLICABLE,
}


# ==========================================================================
# Knowledge base
# ==========================================================================


@dataclass(frozen=True, slots=True)
class AlgorithmClass:
    """A knowledge-base classification for one algorithm."""

    category: QuantumCategory
    note: str
    grover: bool | None = None


class QuantumKnowledge:
    """Loaded quantum-risk knowledge, queried by algorithm name."""

    def __init__(self, path: Path | None = None) -> None:
        raw = self._load(path or KNOWLEDGE_PATH)
        self._algorithms: dict[str, AlgorithmClass] = {}
        for name, values in (raw.get("algorithms") or {}).items():
            if not isinstance(values, dict):
                continue
            category = _KB_TO_CATEGORY.get(str(values.get("category", "")))
            if category is None:
                continue
            self._algorithms[name] = AlgorithmClass(
                category=category,
                note=str(values.get("note", "")),
                grover=values.get("grover"),
            )
        self._protocols: dict[str, str] = {
            name: str(v.get("note", ""))
            for name, v in (raw.get("protocols") or {}).items()
            if isinstance(v, dict)
        }
        self._symmetric_margins: dict[str, str] = {
            str(k): str(v) for k, v in (raw.get("symmetric_key_margins") or {}).items()
        }

    @staticmethod
    def _load(path: Path) -> dict[str, Any]:
        try:
            return parse_simple_yaml(path.read_text(encoding="utf-8"))
        except OSError:
            return {}

    def classify(self, algorithm: str) -> AlgorithmClass | None:
        """Return the classification for an algorithm, or ``None`` if unknown.

        Tries the exact name, then the base name before a parameter suffix
        (``ML-KEM-768`` → ``ML-KEM``, ``SHA-256`` stays exact because it is
        itself an entry). Never guesses: an unrecognised algorithm returns
        ``None`` and the caller records UNKNOWN.
        """
        if not algorithm:
            return None
        if algorithm in self._algorithms:
            return self._algorithms[algorithm]
        # Try the family base, e.g. ML-KEM-768 -> ML-KEM.
        if "-" in algorithm:
            base = algorithm.rsplit("-", 1)[0]
            if base in self._algorithms:
                return self._algorithms[base]
        return None

    def protocol_note(self, name: str) -> str | None:
        """Return the note for a protocol, or ``None``."""
        return self._protocols.get(name)

    def symmetric_margin_note(self, key_size: int | None) -> str | None:
        """Return the effective-margin note for a symmetric key size, if known."""
        if key_size is None:
            return None
        return self._symmetric_margins.get(str(key_size))


#: Module-level knowledge, loaded once.
_KNOWLEDGE = QuantumKnowledge()


# ==========================================================================
# CRQC / policy assumptions
# ==========================================================================


@dataclass(frozen=True, slots=True)
class RiskPolicy:
    """The assumptions the Mosca analysis runs against.

    None of these are facts. Each carries provenance so a result can show where
    it came from. A value left as ``None`` is genuinely absent — the engine then
    reports insufficient information rather than substituting a number.

    Attributes:
        crqc_horizon_years: Assumed years until a CRQC exists (Z). An
            assumption, never observed.
        default_migration_years: Fallback migration time when a component does
            not supply one. ``None`` means no default — absence stays absence.
        default_data_lifetime_years: Fallback data lifetime. ``None`` means no
            default.
        source: Where the policy came from.
    """

    crqc_horizon_years: float | None = None
    default_migration_years: float | None = None
    default_data_lifetime_years: float | None = None
    source: str = ContextSource.DEFAULT.value

    @classmethod
    def from_policy_dict(cls, quantum_risk: dict[str, Any] | None, source: str) -> RiskPolicy:
        """Build a policy from a parsed ``quantum_risk:`` block.

        Only values actually present are taken; missing keys stay ``None`` so
        the engine never invents a default that the operator did not declare.
        """
        block = quantum_risk or {}

        def _num(key: str) -> float | None:
            value = block.get(key)
            if value is None or value == "":
                return None
            try:
                return float(value)
            except (TypeError, ValueError):
                return None

        return cls(
            crqc_horizon_years=_num("crqc_horizon_years"),
            default_migration_years=_num("default_migration_years"),
            default_data_lifetime_years=_num("default_data_lifetime_years"),
            source=source,
        )


def load_risk_policy(estate_root: Path) -> RiskPolicy:
    """Load the ``quantum_risk:`` block from an estate's policy file.

    Reuses the existing flat policy parser rather than adding a second
    mechanism. Returns an all-``None`` policy (no assumptions) when the estate
    declares none — which then produces insufficient-information results, the
    honest outcome when nothing is configured.
    """
    from backend import inventory

    for candidate in (estate_root / inventory.POLICY_FILENAME, estate_root / "aegis_policy.json"):
        if candidate.exists():
            raw = inventory._parse_policy_file(candidate)
            block = raw.get("quantum_risk") if isinstance(raw, dict) else None
            if isinstance(block, dict):
                return RiskPolicy.from_policy_dict(block, ContextSource.POLICY_FILE.value)
    return RiskPolicy()


# ==========================================================================
# Mosca time-horizon analysis
# ==========================================================================


def _resolve_lifetime(
    context: ApplicationContext | None, policy: RiskPolicy
) -> RiskAssumption:
    """Resolve data lifetime (X) with provenance.

    Declared context wins; a documented default is used only if the policy
    provides one; otherwise the value is genuinely missing.
    """
    if context is not None and context.is_declared:
        return RiskAssumption(
            name="data_lifetime_years",
            value=float(context.data_lifetime_years),
            provenance=context.context_source.value,
            is_default=False,
        )
    if policy.default_data_lifetime_years is not None:
        return RiskAssumption(
            name="data_lifetime_years",
            value=policy.default_data_lifetime_years,
            provenance=policy.source,
            is_default=True,
        )
    return RiskAssumption(name="data_lifetime_years", value=None, provenance="missing")


def _resolve_migration(policy: RiskPolicy) -> RiskAssumption:
    """Resolve migration time (Y) with provenance.

    Migration time is an organisational planning assumption, never discovered.
    Present only if the policy declares a default; otherwise missing.
    """
    if policy.default_migration_years is not None:
        return RiskAssumption(
            name="migration_time_years",
            value=policy.default_migration_years,
            provenance=policy.source,
            is_default=True,
        )
    return RiskAssumption(name="migration_time_years", value=None, provenance="missing")


def _resolve_crqc(policy: RiskPolicy) -> RiskAssumption:
    """Resolve the CRQC horizon (Z) with provenance.

    An assumption in every case. Present only if configured; the engine never
    supplies a hard-coded year.
    """
    if policy.crqc_horizon_years is not None:
        return RiskAssumption(
            name="crqc_horizon_years",
            value=policy.crqc_horizon_years,
            provenance=policy.source,
            is_default=policy.source == ContextSource.DEFAULT.value,
        )
    return RiskAssumption(name="crqc_horizon_years", value=None, provenance="missing")


def run_mosca(
    lifetime: RiskAssumption, migration: RiskAssumption, crqc: RiskAssumption
) -> tuple[MoscaStatus, MoscaResult | None]:
    """Perform the Mosca time-horizon analysis.

    Returns ``INSUFFICIENT_INFORMATION`` with no calculation when any of the
    three inputs is missing — the analysis is only as good as its assumptions,
    and a missing assumption must not be filled with a guess.
    """
    if not (lifetime.is_present and migration.is_present and crqc.is_present):
        return MoscaStatus.INSUFFICIENT_INFORMATION, None

    x = float(lifetime.value)
    y = float(migration.value)
    z = float(crqc.value)
    combined = x + y
    within = combined > z

    verdict = MoscaVerdict.EXPOSED if within else MoscaVerdict.ACCEPTABLE
    result = MoscaResult(
        x_data_lifetime_years=x,
        y_migration_years=y,
        z_horizon_years=z,
        verdict=verdict,
        margin_years=round(combined - z, 4),
    )
    status = (
        MoscaStatus.WITHIN_QUANTUM_WINDOW
        if within
        else MoscaStatus.OUTSIDE_QUANTUM_WINDOW
    )
    return status, result


# ==========================================================================
# Per-finding assessment
# ==========================================================================


def _is_capability_only(finding: CryptoFinding) -> bool:
    """True for a library finding that establishes no algorithm usage.

    The Phase 2/6 rule: a LIBRARY artefact with an empty algorithm is a
    capability, and must never receive an algorithm-level quantum verdict.
    """
    return finding.artefact_type is ArtefactType.LIBRARY and not finding.algorithm


def assess_finding(
    finding: CryptoFinding,
    context: ApplicationContext | None,
    policy: RiskPolicy,
) -> QuantumRiskResult:
    """Assess one finding, returning an explainable quantum-risk result.

    The decision path is linear and every branch records why it was taken. The
    finding's own confidence and evidence level are copied through unchanged, so
    a weak discovery yields a weak-but-labelled result rather than being
    upgraded.
    """
    rationale: list[str] = []
    crqc = _resolve_crqc(policy)

    common = dict(
        finding_id=finding.finding_id,
        component=finding.component or (context.component if context else ""),
        algorithm=finding.algorithm,
        role=str(finding.raw_detail.get("role", "")),
        key_size=finding.key_size,
        confidence=finding.confidence,
        evidence_level=str(finding.raw_detail.get("evidence_level", "")),
        detection_method=finding.detection_method.value,
        source_type=finding.source_type.value,
        artefact_type=finding.artefact_type.value,
    )

    # --- 1. Library capability, not usage ---
    if _is_capability_only(finding):
        library = finding.library or "a cryptographic library"
        rationale.append(
            f"{library} is linked or declared as a dependency but no "
            "algorithm usage was established, so no algorithm-level quantum "
            "assessment is made. This is a capability, not confirmed use."
        )
        return QuantumRiskResult(
            quantum_category=QuantumCategory.CAPABILITY_ONLY,
            risk_level=RiskLevel.UNKNOWN,
            mosca_status=MoscaStatus.NOT_TIME_SENSITIVE,
            assumptions=[crqc],
            rationale=rationale,
            **common,
        )

    # --- 2. Protocol finding ---
    protocol_note = _KNOWLEDGE.protocol_note(finding.algorithm) if finding.algorithm else None
    if protocol_note and finding.raw_detail.get("role") == "protocol":
        rationale.append(protocol_note)
        rationale.append(
            "A protocol finding does not fix the negotiated algorithms, so a "
            "definite quantum classification cannot be assigned to it alone."
        )
        return QuantumRiskResult(
            quantum_category=QuantumCategory.PROTOCOL_DEPENDENT,
            risk_level=RiskLevel.UNKNOWN,
            mosca_status=MoscaStatus.INSUFFICIENT_INFORMATION,
            assumptions=[crqc],
            rationale=rationale,
            **common,
        )

    classification = _KNOWLEDGE.classify(finding.algorithm)

    # --- 3. Unknown algorithm ---
    if classification is None:
        label = finding.algorithm or "the artefact"
        rationale.append(
            f"{label} is not in the quantum-risk knowledge base, so it is left "
            "unclassified rather than assumed resistant or vulnerable."
        )
        return QuantumRiskResult(
            quantum_category=QuantumCategory.UNKNOWN,
            risk_level=RiskLevel.UNKNOWN,
            mosca_status=MoscaStatus.INSUFFICIENT_INFORMATION,
            assumptions=[crqc],
            rationale=rationale,
            **common,
        )

    where = _describe_location(finding)
    role_phrase = f" ({common['role'].replace('_', ' ')})" if common["role"] else ""
    size_phrase = f"-{finding.key_size}" if finding.key_size is not None else ""
    observed = (
        f"{finding.algorithm}{size_phrase}{role_phrase} was observed in "
        f"{common['component'] or 'an unattributed component'}{where}."
    )
    rationale.append(observed)
    rationale.append(classification.note)

    # --- 4. Post-quantum ---
    if classification.category is QuantumCategory.POST_QUANTUM:
        rationale.append(
            "Classified as post-quantum: designed to resist known classical and "
            "quantum attacks. This is not a proof of unbreakability."
        )
        return QuantumRiskResult(
            quantum_category=QuantumCategory.POST_QUANTUM,
            risk_level=RiskLevel.PQC_READY,
            mosca_status=MoscaStatus.NOT_TIME_SENSITIVE,
            assumptions=[crqc],
            rationale=rationale,
            **common,
        )

    # --- 5. Symmetric / hash ---
    if classification.category is QuantumCategory.SYMMETRIC_REDUCED:
        margin = _KNOWLEDGE.symmetric_margin_note(finding.key_size)
        if margin:
            rationale.append(margin)
        elif finding.key_size is None and finding.algorithm == "AES":
            rationale.append(
                "The AES key size was not established, so the effective quantum "
                "margin cannot be stated precisely."
            )
        return QuantumRiskResult(
            quantum_category=QuantumCategory.SYMMETRIC_REDUCED,
            risk_level=RiskLevel.LOW_BASELINE,
            mosca_status=MoscaStatus.NOT_TIME_SENSITIVE,
            assumptions=[crqc],
            rationale=rationale,
            **common,
        )

    # --- 6. Not applicable (KDF/MAC) ---
    if classification.category is QuantumCategory.NOT_APPLICABLE:
        return QuantumRiskResult(
            quantum_category=QuantumCategory.NOT_APPLICABLE,
            risk_level=RiskLevel.LOW_BASELINE,
            mosca_status=MoscaStatus.NOT_TIME_SENSITIVE,
            assumptions=[crqc],
            rationale=rationale,
            **common,
        )

    # --- 7. Quantum-vulnerable public-key: run Mosca ---
    lifetime = _resolve_lifetime(context, policy)
    migration = _resolve_migration(policy)
    mosca_status, mosca = run_mosca(lifetime, migration, crqc)
    assumptions = [lifetime, migration, crqc]

    risk_level, mosca_rationale = _classify_vulnerable(
        finding, context, mosca_status, mosca, lifetime, migration, crqc
    )
    rationale.extend(mosca_rationale)

    return QuantumRiskResult(
        quantum_category=QuantumCategory.QUANTUM_VULNERABLE,
        risk_level=risk_level,
        mosca_status=mosca_status,
        mosca=mosca,
        assumptions=assumptions,
        rationale=rationale,
        **common,
    )


def _classify_vulnerable(
    finding: CryptoFinding,
    context: ApplicationContext | None,
    mosca_status: MoscaStatus,
    mosca: MoscaResult | None,
    lifetime: RiskAssumption,
    migration: RiskAssumption,
    crqc: RiskAssumption,
) -> tuple[RiskLevel, list[str]]:
    """Assign the risk level for a quantum-vulnerable asset from the Mosca outcome.

    The path is explicit:

    * Missing inputs → HIGH with an insufficient-information note. HIGH rather
      than UNKNOWN because the algorithm *is* known to be quantum-vulnerable;
      only the timing is uncertain, and under-stating that would be the unsafe
      direction.
    * Within the quantum window → CRITICAL, escalated by business criticality
      only as a stated modifier.
    * Outside the window → MEDIUM, explicitly conditional on the assumption.
    """
    rationale: list[str] = []

    if mosca_status is MoscaStatus.INSUFFICIENT_INFORMATION:
        missing = [a.name for a in (lifetime, migration, crqc) if not a.is_present]
        rationale.append(
            "The algorithm is quantum-vulnerable, but the Mosca time-horizon "
            f"analysis is incomplete: missing {', '.join(missing)}. Rated HIGH "
            "on the algorithm alone; the timing question is unresolved."
        )
        return RiskLevel.HIGH, rationale

    assert mosca is not None
    rationale.append(f"Mosca analysis: {mosca.statement}.")

    if mosca_status is MoscaStatus.WITHIN_QUANTUM_WINDOW:
        rationale.append(
            "Data lifetime plus migration time extends past the assumed CRQC "
            f"horizon by {mosca.margin_years:g} years, so the protection "
            "requirement reaches into the assumed quantum-threat window. "
            "Harvest-now-decrypt-later exposure applies."
        )
        level = RiskLevel.CRITICAL
        if context is not None and context.is_declared:
            from backend.model import BusinessCriticality

            if context.business_criticality is BusinessCriticality.CRITICAL:
                rationale.append(
                    "Business criticality is declared CRITICAL, consistent with "
                    "the highest rating."
                )
        return level, rationale

    # OUTSIDE_QUANTUM_WINDOW
    rationale.append(
        "Under the configured assumptions, the combined horizon stays within "
        "the CRQC assumption. This is conditional on those assumptions, not a "
        "statement that the asset is safe; the algorithm remains "
        "quantum-vulnerable."
    )
    return RiskLevel.MEDIUM, rationale


def _describe_location(finding: CryptoFinding) -> str:
    """A short, safe location phrase for the rationale.

    Uses only path and line already in the finding — never raw evidence that
    could carry sensitive content.
    """
    if finding.location and finding.line is not None:
        return f" at {Path(finding.location).name}:{finding.line}"
    if finding.location:
        return f" in {Path(finding.location).name}"
    return ""


# ==========================================================================
# Batch assessment
# ==========================================================================


def assess_inventory(
    findings: Iterable[CryptoFinding],
    contexts: dict[str, ApplicationContext] | None = None,
    policy: RiskPolicy | None = None,
) -> list[QuantumRiskResult]:
    """Assess every finding, returning results sorted by finding id.

    Deterministic: the same findings, contexts, and policy always produce the
    same results in the same order, with no timestamp or random value anywhere.

    Args:
        findings: Canonical findings from the inventory.
        contexts: Per-component organisation context, if available.
        policy: Risk assumptions. An empty policy yields
            insufficient-information Mosca results, which is the honest outcome
            when nothing is configured.

    Returns:
        One :class:`QuantumRiskResult` per finding, ordered by finding id.
    """
    contexts = contexts or {}
    policy = policy or RiskPolicy()

    results: list[QuantumRiskResult] = []
    for finding in findings:
        component = finding.component or "unattributed"
        context = contexts.get(component)
        results.append(assess_finding(finding, context, policy))

    return sorted(results, key=lambda r: r.finding_id)


def risk_summary(results: list[QuantumRiskResult]) -> dict[str, Any]:
    """Aggregate counts over a set of risk results.

    Counts only — no ranking, no "worst" application. Ordering by application is
    left to later phases.
    """
    by_category: dict[str, int] = {}
    by_level: dict[str, int] = {}
    by_mosca: dict[str, int] = {}

    for result in results:
        by_category[result.quantum_category.value] = (
            by_category.get(result.quantum_category.value, 0) + 1
        )
        by_level[result.risk_level.value] = by_level.get(result.risk_level.value, 0) + 1
        by_mosca[result.mosca_status.value] = by_mosca.get(result.mosca_status.value, 0) + 1

    return {
        "total": len(results),
        "by_quantum_category": dict(sorted(by_category.items())),
        "by_risk_level": dict(sorted(by_level.items())),
        "by_mosca_status": dict(sorted(by_mosca.items())),
    }
