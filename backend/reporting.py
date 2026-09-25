"""
AegisPQC — assessment report generation.

Produces a complete, shareable assessment as structured JSON or rendered
Markdown.

THE SAFETY PROPERTY THAT MATTERS
--------------------------------
A readiness report gets emailed around an organisation, pasted into tickets, and
attached to board packs. If it contained key material it would be a
vulnerability rather than a security artifact.

The report is therefore assembled **only** from data that has already passed the
scanner's and service layer's no-secret guarantees — findings, risk ratings,
migration recommendations, and public metadata. It never reads the key store and
never touches a private key. :func:`build_report` performs a final defensive
sweep before returning, so a future change that accidentally routes secret
material into an input would fail loudly rather than ship it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from backend import config

#: Substrings that must never appear in a generated report. PEM headers are the
#: giveaway for raw key material; the field names catch a dict being passed in
#: whole from somewhere it should not have been.
_FORBIDDEN_MARKERS: tuple[str, ...] = (
    "-----BEGIN PRIVATE KEY",
    "-----BEGIN RSA PRIVATE KEY",
    "-----BEGIN EC PRIVATE KEY",
    "-----BEGIN ENCRYPTED PRIVATE KEY",
    '"private_key"',
    "private_bytes_raw",
)


class ReportLeakError(Exception):
    """Raised when generated report content contains disallowed material.

    This should be unreachable. It exists so that if it ever becomes reachable,
    the failure is loud and immediate rather than a quiet disclosure.
    """


def _assert_no_secrets(payload: str) -> None:
    """Fail loudly if serialised report content carries key material."""
    for marker in _FORBIDDEN_MARKERS:
        if marker in payload:
            raise ReportLeakError(
                f"Report generation produced content containing {marker!r}. "
                "This is a serious defect; the report was not returned."
            )


def build_report(
    assessment: dict[str, Any],
    plan: dict[str, Any],
    verification: dict[str, Any],
    harvest: dict[str, Any] | None = None,
    benchmarks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble the full assessment report.

    Args:
        assessment: Output of ``scanner.scan``.
        plan: Output of ``migration.build_plan``.
        verification: Output of ``migration.verify_plan``.
        harvest: Optional harvest statistics from the demonstration.
        benchmarks: Optional measured benchmark rows.

    Returns:
        The structured report.

    Raises:
        ReportLeakError: If the assembled content contains key material.
    """
    report = {
        "report": {
            "product": "AegisPQC — Post-Quantum Vault & Anti-HNDL Defense Platform",
            "version": config.API_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "report_type": "PQC Readiness Assessment and Migration Plan",
        },
        "executive_summary": {
            "assets_scanned": assessment["assets_scanned"],
            "quantum_vulnerable": assessment["quantum_vulnerable"],
            "pqc_ready": assessment["pqc_ready"],
            "unidentified": assessment["unidentified"],
            "readiness_score": assessment["readiness_score"],
            "verdict": assessment["verdict"],
            "critical_migrations": plan["critical_migrations"],
            "high_migrations": plan["high_migrations"],
        },
        "risk_distribution": assessment["counts"],
        "algorithm_distribution": assessment["by_family"],
        "inventory": [
            {
                "system_name": finding["system_name"],
                "algorithm": finding["algorithm"] or "unidentified",
                "key_size": finding["key_size"],
                "algorithm_oid": finding.get("detail", {}).get("algorithm_oid", ""),
                "file_type": finding["file_type"],
                "evidence": finding["evidence"],
                "quantum_status": finding["quantum_status"],
                "risk": finding["risk"],
                "retention_years": finding["retention_years"],
                "data_sensitivity": finding["data_sensitivity"],
                "business_context": finding["business_context"],
                "reasons": finding["reasons"],
                "recommended_migration": finding["recommended_migration"],
            }
            for finding in assessment["findings"]
        ],
        "migration_plan": {
            "recommended_target_architecture": plan["recommended_target_architecture"],
            "phases": plan["phases"],
            "priorities": [
                {
                    "position": rec["position"],
                    "system_name": rec["system_name"],
                    "risk": rec["risk"],
                    "current": (
                        f"{rec['current_algorithm']}-{rec['current_key_size']}"
                        if rec["current_key_size"]
                        else rec["current_algorithm"]
                    ),
                    "recommended_target": rec["recommended_target"],
                    "retention_years": rec["retention_years"],
                    "why_first": rec["why_first"],
                    "phase": rec["phase"],
                    "effort": rec["effort"],
                    "validation_required": rec["validation_required"],
                }
                for rec in plan["recommendations"]
            ],
        },
        "verification": verification,
        "scope_and_limitations": {
            "what_this_is": (
                "A cryptographic inventory and post-quantum readiness "
                "assessment, produced by parsing keys and certificates."
            ),
            "no_cryptanalysis": (
                "No cryptanalysis is performed against any scanned asset. No "
                "private key material is read, derived, reported, or exported."
            ),
            "no_date_prediction": (
                "No prediction is made about when any algorithm will be broken. "
                "Risk is derived from algorithm family and how long the "
                "protected data must remain confidential."
            ),
            "no_modification": (
                "AegisPQC does not modify, rotate, or reconfigure any real "
                "system. The migration plan is advisory."
            ),
            "supported_formats": (
                "PEM, DER, and JSON deployment manifests. PKCS#12, JKS, and "
                "password-protected keys are not supported."
            ),
            "not_pki_validation": (
                "Certificate chains and revocation status are not validated. "
                "This is an inventory tool, not a PKI validator."
            ),
            "evidence_levels": (
                "VERIFIED findings were parsed from actual cryptographic "
                "material. DECLARED findings were read from a deployment "
                "manifest and represent an operator's claim, not proof."
            ),
        },
    }

    if harvest is not None:
        report["hndl_demonstration"] = {
            "packets_harvested": harvest.get("total_packets", 0),
            "quantum_vulnerable_packets": harvest.get("vulnerable_packets", 0),
            "quantum_safe_packets": harvest.get("quantum_safe_packets", 0),
            "bytes_at_risk": harvest.get("total_bytes_at_risk", 0),
            "note": (
                "A passive network tap captures all traffic regardless of "
                "algorithm. Encryption does not prevent recording; it "
                "determines what the recording is worth later."
            ),
        }

    if benchmarks is not None:
        report["measured_benchmarks"] = {
            "measurement_note": (
                "All values below are MEASURED on the machine that generated "
                "this report, not quoted from literature."
            ),
            "rows": benchmarks,
        }

    serialised = json.dumps(report)
    _assert_no_secrets(serialised)
    return report


def render_markdown(report: dict[str, Any]) -> str:
    """Render the report as Markdown suitable for circulation.

    Returns:
        A complete Markdown document.

    Raises:
        ReportLeakError: If the rendered content contains key material.
    """
    meta = report["report"]
    summary = report["executive_summary"]
    lines: list[str] = []

    add = lines.append

    add(f"# {meta['report_type']}")
    add("")
    add(f"**{meta['product']}**  ")
    add(f"Generated: {meta['generated_at']}  ")
    add(f"Version: {meta['version']}")
    add("")
    add("---")
    add("")

    # Executive summary
    add("## Executive summary")
    add("")
    add("| Metric | Value |")
    add("|---|---|")
    add(f"| Assets scanned | {summary['assets_scanned']} |")
    add(f"| Quantum vulnerable | {summary['quantum_vulnerable']} |")
    add(f"| PQC ready | {summary['pqc_ready']} |")
    add(f"| Unidentified | {summary['unidentified']} |")
    add(f"| Critical migrations | {summary['critical_migrations']} |")
    add(f"| High migrations | {summary['high_migrations']} |")
    add(f"| **Readiness score** | **{summary['readiness_score']} / 100** |")
    add(f"| **Verdict** | **{summary['verdict']}** |")
    add("")

    # Risk distribution
    add("## Risk distribution")
    add("")
    add("| Rating | Assets |")
    add("|---|---|")
    for level, count in report["risk_distribution"].items():
        add(f"| {level} | {count} |")
    add("")

    # Algorithm distribution
    add("## Algorithm families")
    add("")
    add("| Family | Assets |")
    add("|---|---|")
    for family, count in report["algorithm_distribution"].items():
        add(f"| {family} | {count} |")
    add("")

    # Inventory
    add("## Cryptographic inventory")
    add("")
    add("| Asset | Algorithm | Key size | Evidence | PQC status | Risk | Retention |")
    add("|---|---|---|---|---|---|---|")
    for item in report["inventory"]:
        add(
            f"| {item['system_name']} | {item['algorithm']} | "
            f"{item['key_size'] or '—'} | {item['evidence']} | "
            f"{item['quantum_status']} | {item['risk']} | "
            f"{item['retention_years']}y |"
        )
    add("")
    add(
        "**VERIFIED** findings were parsed from actual cryptographic material. "
        "**DECLARED** findings were read from a deployment manifest and "
        "represent an operator's claim, not proof."
    )
    add("")

    # Target architecture
    add("## Recommended target architecture")
    add("")
    architecture = report["migration_plan"]["recommended_target_architecture"]
    for key, value in architecture.items():
        if key == "note":
            continue
        add(f"- **{key.replace('_', ' ').title()}**: {value}")
    add("")
    add(f"> {architecture['note']}")
    add("")

    # Priorities
    add("## Migration priorities")
    add("")
    for priority in report["migration_plan"]["priorities"]:
        add(f"### {priority['position']}. {priority['system_name']} — {priority['risk']}")
        add("")
        add(f"- **Current**: {priority['current']}")
        add(f"- **Recommended**: {priority['recommended_target'] or 'Investigate'}")
        add(f"- **Retention**: {priority['retention_years']} years")
        add(f"- **Effort**: {priority['effort'] or '—'}")
        add(f"- **Why this position**: {priority['why_first']}")
        add("")

    # Phases
    add("## Migration phases")
    add("")
    for phase in report["migration_plan"]["phases"]:
        add(f"**{phase['name']}** ({phase['scope']}) — {phase['asset_count']} assets")
        add("")
        add(f"{phase['description']}")
        add("")
        if phase["assets"]:
            for asset in phase["assets"]:
                add(f"- {asset}")
            add("")

    # Verification
    add("## Plan verification")
    add("")
    verification = report["verification"]
    add(f"**{verification['verdict']}**")
    add("")
    for check in verification["checks"]:
        mark = "PASS" if check["passed"] else "FAIL"
        add(f"- [{mark}] {check['name']} — {check['detail']}")
    add("")
    add(f"> {verification['scope_note']}")
    add("")

    # HNDL demonstration
    if "hndl_demonstration" in report:
        demonstration = report["hndl_demonstration"]
        add("## HNDL demonstration")
        add("")
        add(f"- Packets harvested: {demonstration['packets_harvested']}")
        add(f"- Quantum vulnerable: {demonstration['quantum_vulnerable_packets']}")
        add(f"- Quantum safe: {demonstration['quantum_safe_packets']}")
        add(f"- Plaintext bytes at risk: {demonstration['bytes_at_risk']}")
        add("")
        add(f"> {demonstration['note']}")
        add("")

    # Benchmarks
    if "measured_benchmarks" in report:
        add("## Measured benchmarks")
        add("")
        add(f"> {report['measured_benchmarks']['measurement_note']}")
        add("")
        add("| Algorithm | Keygen (ms) | Seal (ms) | Unseal (ms) | Public key (B) | Wire overhead (B) |")
        add("|---|---|---|---|---|---|")
        for row in report["measured_benchmarks"]["rows"]:
            add(
                f"| {row['algorithm']} | {row['keygen_ms']} | "
                f"{row['encapsulate_encrypt_ms']} | {row['decapsulate_decrypt_ms']} | "
                f"{row['public_key_bytes']} | {row['wire_overhead_bytes']} |"
            )
        add("")

    # Limitations
    add("## Scope and limitations")
    add("")
    for value in report["scope_and_limitations"].values():
        add(f"- {value}")
    add("")
    add("---")
    add("")
    add(
        "*This report contains no private key material. AegisPQC performs "
        "cryptographic inventory only; it does not attempt cryptanalysis "
        "against any scanned asset and does not modify any system.*"
    )
    add("")

    document = "\n".join(lines)
    _assert_no_secrets(document)
    return document
