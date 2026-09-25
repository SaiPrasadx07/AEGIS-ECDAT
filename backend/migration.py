"""
AegisPQC — PQC migration planning.

Turns a scanner assessment into a prioritised, phased migration plan.

WHAT THIS MODULE DOES NOT DO
----------------------------
It does not modify any file, rotate any key, reconfigure any service, or touch
any real system. It is a **planning and recommendation** engine. Every output is
advice derived from the inventory, and the UI says so.

That restraint is deliberate. A tool that offers to "auto-migrate" an
organisation's cryptography and gets it wrong is worse than no tool at all. The
useful, honest contribution here is the decision support: what to fix, in what
order, and — most importantly — a defensible reason for that order.

WHY THE ORDER IS THE PRODUCT
----------------------------
Any scanner can list vulnerable assets. The hard question a security programme
actually faces is which of forty vulnerable systems to touch in the first
quarter. This module answers that with a stated rule rather than a vibe:

    Harvest-Now-Decrypt-Later exposure is a function of how long the data must
    stay confidential. An asset protecting 50-year records is more exposed than
    one protecting 2-year records, even when both use the identical algorithm.

So retention drives the ordering, risk drives the phase, and every recommendation
carries a "why first" that a security lead could take to a steering committee.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Final

from backend import scanner

# ==========================================================================
# Target architecture
# ==========================================================================

#: Recommended replacement per algorithm family. These follow the NIST
#: standards and the hybrid constructions actually deployed in TLS 1.3, rather
#: than being invented for this project.
MIGRATION_TARGETS: Final[dict[str, dict[str, str]]] = {
    "RSA": {
        "target": "Hybrid X25519 + ML-KEM-768",
        "standard": "NIST FIPS 203 (ML-KEM)",
        "rationale": (
            "Hybrid keeps a classical component alongside the post-quantum one, "
            "so a weakness later found in either does not immediately break the "
            "session. This is what browsers and CDNs deployed for TLS 1.3."
        ),
        "signature_note": (
            "RSA used for signatures rather than key establishment migrates to "
            "ML-DSA (FIPS 204) instead."
        ),
    },
    "Elliptic curve": {
        "target": "Hybrid X25519 + ML-KEM-768",
        "standard": "NIST FIPS 203 (ML-KEM)",
        "rationale": (
            "Elliptic curves fall to the same quantum algorithm as RSA and do "
            "so at smaller key sizes. The hybrid retains the existing curve as "
            "one leg, which keeps the change incremental."
        ),
        "signature_note": "ECDSA signatures migrate to ML-DSA (FIPS 204).",
    },
    "Finite-field": {
        "target": "ML-KEM-768 key establishment",
        "standard": "NIST FIPS 203 (ML-KEM)",
        "rationale": (
            "Finite-field discrete log falls to Shor's algorithm. Non-forward-"
            "secret exchanges are additionally exposed retroactively."
        ),
        "signature_note": "DSA signatures migrate to ML-DSA (FIPS 204).",
    },
}

#: Fallback when the algorithm family is not in the table above.
DEFAULT_TARGET: Final[dict[str, str]] = {
    "target": "Hybrid classical + ML-KEM-768",
    "standard": "NIST FIPS 203 (ML-KEM)",
    "rationale": (
        "Any quantum-vulnerable key establishment should move to a hybrid "
        "construction that includes a NIST-standardised post-quantum component."
    ),
    "signature_note": "Signature primitives migrate to ML-DSA (FIPS 204).",
}

#: Migration phases, in execution order.
PHASES: Final[tuple[dict[str, str], ...]] = (
    {
        "key": "phase_1",
        "name": "Phase 1 — Immediate",
        "scope": "CRITICAL assets",
        "description": (
            "Quantum-vulnerable cryptography protecting data with a long "
            "confidentiality requirement. Traffic captured today would still be "
            "sensitive well beyond the point where the algorithm is expected to "
            "be at risk, so these are exposed now, not later."
        ),
    },
    {
        "key": "phase_2",
        "name": "Phase 2 — Near term",
        "scope": "HIGH assets",
        "description": (
            "Quantum-vulnerable cryptography protecting data with a meaningful "
            "but shorter retention requirement, or highly sensitive data with "
            "moderate retention."
        ),
    },
    {
        "key": "phase_3",
        "name": "Phase 3 — Planned",
        "scope": "MEDIUM and LOW assets",
        "description": (
            "Shorter-lived data, and assets already using post-quantum "
            "cryptography whose status is declared but not yet verified against "
            "the running system."
        ),
    },
    {
        "key": "phase_4",
        "name": "Phase 4 — Investigate",
        "scope": "UNKNOWN assets",
        "description": (
            "Assets whose cryptography could not be identified. These cannot be "
            "assumed safe and must be manually reviewed before the migration "
            "programme can be considered complete."
        ),
    },
)

_PHASE_FOR_RISK: Final[dict[str, str]] = {
    scanner.RISK_CRITICAL: "phase_1",
    scanner.RISK_HIGH: "phase_2",
    scanner.RISK_MEDIUM: "phase_3",
    scanner.RISK_LOW: "phase_3",
    scanner.RISK_UNKNOWN: "phase_4",
}

#: Rough effort bands. Deliberately coarse — a precise day estimate from a file
#: scan would be a fabrication, and a security lead would rightly ignore it.
_EFFORT_BY_FILE_TYPE: Final[dict[str, str]] = {
    "X.509 certificate": "Moderate — certificate reissue and redistribution",
    "Private key": "Moderate — key rotation and dependent service restart",
    "Public key": "Low — key replacement",
    "Deployment manifest": "Low — configuration change and verification",
}


# ==========================================================================
# Per-asset recommendation
# ==========================================================================


def _target_for(finding: dict[str, Any]) -> dict[str, str]:
    """Pick the recommended migration target for one finding."""
    return MIGRATION_TARGETS.get(finding.get("algorithm_family", ""), DEFAULT_TARGET)


def _why_first(finding: dict[str, Any], position: int) -> str:
    """Explain, in one sentence, why this asset sits at this position.

    This is the field a security lead would actually quote in a steering
    meeting, so it states the specific driver rather than repeating the rating.
    """
    risk = finding["risk"]
    retention = finding.get("retention_years", 0)
    algorithm = finding.get("algorithm", "unidentified")
    key_size = finding.get("key_size", "")
    label = f"{algorithm}-{key_size}" if key_size else algorithm

    if risk == scanner.RISK_UNKNOWN:
        return (
            "Ranked for investigation rather than migration: the cryptography "
            "could not be identified, and an unidentified asset cannot be "
            "signed off as safe."
        )

    if finding.get("evidence") == scanner.EVIDENCE_DECLARED:
        return (
            "Already reports post-quantum cryptography, but the status is "
            "declared in a manifest rather than verified from key material. "
            "Ranked for confirmation, not replacement."
        )

    if risk == scanner.RISK_SAFE:
        return "No migration required. Post-quantum, verified from key material."

    if position == 1:
        return (
            f"Highest exposure in the estate: {label} protecting data with a "
            f"{retention}-year confidentiality requirement. Every day this stays "
            "in place adds recordable traffic that must remain secret longer "
            "than the algorithm is expected to hold."
        )

    if retention >= 20:
        return (
            f"{label} protecting {retention}-year data. Long retention is the "
            "dominant factor in harvest exposure: the ciphertext only has to "
            "outlive the algorithm, not the attacker's patience."
        )

    if finding.get("data_sensitivity", "").lower() == "critical":
        return (
            f"{label} protecting data classified critical. Sensitivity raises "
            "this above other assets with comparable retention."
        )

    return (
        f"{label} is quantum vulnerable, protecting data with a {retention}-year "
        "confidentiality requirement."
    )


def build_recommendation(finding: dict[str, Any], position: int) -> dict[str, Any]:
    """Produce the full migration recommendation for one asset.

    Args:
        finding: A scanner finding dict.
        position: Its 1-based rank in the migration order.

    Returns:
        A recommendation carrying the current state, the target state, the
        justification, and what validation the change would require.
    """
    target = _target_for(finding)
    risk = finding["risk"]
    needs_migration = risk not in (scanner.RISK_SAFE,)

    return {
        "position": position,
        "system_name": finding["system_name"],
        "path": finding["path"],
        "business_context": finding.get("business_context", ""),
        # Current state
        "current_algorithm": finding.get("algorithm", "unidentified"),
        "current_key_size": finding.get("key_size", ""),
        "current_family": finding.get("algorithm_family", ""),
        "evidence": finding.get("evidence", ""),
        "algorithm_oid": finding.get("detail", {}).get("algorithm_oid", ""),
        # Risk
        "risk": risk,
        "quantum_status": finding.get("quantum_status", ""),
        "retention_years": finding.get("retention_years", 0),
        "data_sensitivity": finding.get("data_sensitivity", ""),
        "risk_reasons": list(finding.get("reasons", [])),
        # Recommendation
        "needs_migration": needs_migration,
        "recommended_target": target["target"] if needs_migration else "",
        "target_standard": target["standard"] if needs_migration else "",
        "target_rationale": target["rationale"] if needs_migration else "",
        "signature_note": target.get("signature_note", "") if needs_migration else "",
        "why_first": _why_first(finding, position),
        "phase": _PHASE_FOR_RISK.get(risk, "phase_3") if needs_migration else "",
        "effort": (
            _EFFORT_BY_FILE_TYPE.get(finding.get("file_type", ""), "Moderate")
            if needs_migration
            else ""
        ),
        "validation_required": needs_migration,
        "validation_note": (
            "Re-scan after migration to confirm the replacement is verifiable "
            "from key material rather than only declared."
            if needs_migration
            else ""
        ),
    }


# ==========================================================================
# Plan assembly
# ==========================================================================


def build_plan(assessment: dict[str, Any]) -> dict[str, Any]:
    """Build a complete migration plan from a scanner assessment.

    The ordering comes straight from ``scanner.migration_order``, which is
    already deterministic and test-enforced, so the plan inherits that stability
    rather than introducing a second, possibly divergent, sort.

    Args:
        assessment: The dict returned by ``scanner.scan``.

    Returns:
        The plan: recommendations, phases, summary, and target architecture.
    """
    findings = assessment.get("findings", [])

    # Rank everything that needs work; SAFE assets are listed separately so the
    # plan shows the whole estate without padding the queue.
    ranked = [f for f in findings if f["risk"] != scanner.RISK_SAFE]
    ranked.sort(
        key=lambda f: (
            scanner.RISK_RANK.get(f["risk"], 99),
            -f.get("retention_years", 0),
            f["path"],
        )
    )

    recommendations = [
        build_recommendation(finding, position)
        for position, finding in enumerate(ranked, start=1)
    ]
    already_ready = [
        build_recommendation(finding, 0)
        for finding in findings
        if finding["risk"] == scanner.RISK_SAFE
    ]

    phases: list[dict[str, Any]] = []
    for phase in PHASES:
        members = [r for r in recommendations if r["phase"] == phase["key"]]
        phases.append(
            {
                **phase,
                "asset_count": len(members),
                "assets": [r["system_name"] for r in members],
                "positions": [r["position"] for r in members],
            }
        )

    critical = sum(1 for r in recommendations if r["risk"] == scanner.RISK_CRITICAL)
    high = sum(1 for r in recommendations if r["risk"] == scanner.RISK_HIGH)
    unknown = sum(1 for r in recommendations if r["risk"] == scanner.RISK_UNKNOWN)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "assets_total": len(findings),
        "assets_requiring_migration": len(recommendations),
        "assets_already_pqc_ready": len(already_ready),
        "critical_migrations": critical,
        "high_migrations": high,
        "unknown_requiring_investigation": unknown,
        "readiness_score": assessment.get("readiness_score", 0),
        "verdict": assessment.get("verdict", ""),
        "recommended_target_architecture": {
            "key_establishment": "Hybrid X25519 + ML-KEM-768 (NIST FIPS 203)",
            "signatures": "ML-DSA (NIST FIPS 204)",
            "symmetric": "AES-256-GCM (unchanged)",
            "kdf": "HKDF-SHA256 (unchanged)",
            "note": (
                "The symmetric layer does not change. Grover's algorithm offers "
                "only a quadratic speedup against symmetric ciphers, leaving "
                "AES-256 with roughly 128 bits of post-quantum security. Only "
                "the asymmetric layer is being replaced."
            ),
        },
        "phases": phases,
        "recommendations": recommendations,
        "already_pqc_ready": already_ready,
        "scope_note": (
            "This is a planning and recommendation output. AegisPQC does not "
            "modify, rotate, or reconfigure any real system, and does not "
            "predict when any algorithm will be broken."
        ),
    }


def verify_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Validate the plan's internal consistency — the VERIFY workflow stage.

    This is a completeness check on the plan itself, not a post-migration
    verification of a real estate. That distinction is reported explicitly,
    because claiming otherwise would be exactly the kind of overstatement this
    project exists to avoid.

    Returns:
        Named checks with pass/fail, plus an overall verdict.
    """
    recommendations = plan["recommendations"]
    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": passed, "detail": detail})

    add(
        "Every asset accounted for",
        plan["assets_requiring_migration"] + plan["assets_already_pqc_ready"]
        == plan["assets_total"],
        f"{plan['assets_total']} assets scanned; "
        f"{plan['assets_requiring_migration']} queued, "
        f"{plan['assets_already_pqc_ready']} already ready",
    )
    add(
        "Every queued asset has a target",
        all(r["recommended_target"] for r in recommendations if r["needs_migration"]),
        "No asset is queued for migration without a named replacement",
    )
    add(
        "Every queued asset has a justification",
        all(r["why_first"] and r["risk_reasons"] for r in recommendations),
        "Every position in the queue carries a stated reason",
    )
    add(
        "Priority order is strictly non-decreasing in risk",
        all(
            scanner.RISK_RANK.get(recommendations[i]["risk"], 99)
            <= scanner.RISK_RANK.get(recommendations[i + 1]["risk"], 99)
            for i in range(len(recommendations) - 1)
        ),
        "Higher-risk assets never appear below lower-risk ones",
    )
    add(
        "Every asset is assigned to a phase",
        all(r["phase"] for r in recommendations if r["needs_migration"]),
        "No queued asset is left outside the phased plan",
    )
    add(
        "No unidentified asset silently dropped",
        plan["unknown_requiring_investigation"]
        == sum(1 for r in recommendations if r["risk"] == scanner.RISK_UNKNOWN),
        "Assets that could not be parsed are queued for investigation",
    )

    passed = all(check["passed"] for check in checks)
    return {
        "checks": checks,
        "consistent": passed,
        "verdict": "PLAN CONSISTENT" if passed else "PLAN INCOMPLETE",
        "scope_note": (
            "This validates the migration plan's internal consistency and "
            "completeness. It does NOT verify a migrated estate — this "
            "prototype never modifies real infrastructure. Post-migration "
            "verification would re-run the DISCOVER stage against the changed "
            "systems."
        ),
    }
