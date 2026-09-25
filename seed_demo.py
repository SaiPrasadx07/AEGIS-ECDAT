#!/usr/bin/env python3
"""
AegisPQC — demo seeding and end-to-end verification.

Run this once before a presentation. It resets the database, creates the cast,
sends traffic under all three algorithms, harvests every packet, and then runs
the Q-Day attack against each one so you can watch the whole story in the
terminal before you ever open the UI.

    python seed_demo.py

If this script prints a green summary, your demo works. If it does not, you
know before you are standing in front of judges.
"""

from __future__ import annotations

import sys
import time

from backend import config
from backend import crypto_engine as ce
from backend import database as db
from backend import simulator as sim

# ANSI colours. Windows Terminal and PowerShell 7 support these natively.
GREEN, RED, YELLOW, CYAN, DIM, BOLD, RESET = (
    "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[2m", "\033[1m", "\033[0m",
)


def banner(text: str) -> None:
    """Print a section header."""
    print()
    print(f"{BOLD}{CYAN}{'=' * 74}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 74}{RESET}")


#: The traffic the demo sends. Each tuple is (algorithm, label, message).
DEMO_TRAFFIC = [
    (
        config.ALGO_RSA_DEMO,
        "Q3 merger brief",
        "MERGER BRIEF (CONFIDENTIAL)\n"
        "Acquisition of Northwind Systems closes 14 September.\n"
        "Offer price 4.2x revenue. Board vote is unanimous.\n"
        "Do not forward. Do not discuss outside the deal room.",
    ),
    (
        config.ALGO_ML_KEM_768,
        "Patient record transfer",
        "PATIENT RECORD TRANSFER\n"
        "Genomic sequencing results, 1,240 patients, cohort B.\n"
        "Retention requirement: 75 years.\n"
        "This data must stay confidential longer than RSA will survive.",
    ),
    (
        config.ALGO_HYBRID,
        "Treaty annex",
        "DIPLOMATIC CABLE — ANNEX C\n"
        "Verification protocol for the 2026 accord.\n"
        "Classification review scheduled for 2071.\n"
        "Transport: hybrid X25519 + ML-KEM-768, per CNSA 2.0 guidance.",
    ),
]


def main() -> int:
    """Seed the database and verify the whole pipeline. Returns a shell exit code."""
    banner("AEGIS PQC — DEMO SEEDING")

    print(f"{DIM}Resetting database at {config.DB_PATH}{RESET}")
    db.reset_db()

    print(f"{DIM}Creating users...{RESET}")
    db.create_user("Alice")
    bob_id = db.create_user("Bob")
    print(f"  {GREEN}OK{RESET} Alice and Bob created")

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------
    banner("STEP 1 — KEY GENERATION")
    for algo, _label, _msg in DEMO_TRAFFIC:
        t0 = time.perf_counter()
        kp = ce.generate_keypair(algo)
        elapsed = (time.perf_counter() - t0) * 1000
        db.store_keypair(bob_id, algo, kp.public_key, kp.private_key)
        print(
            f"  {GREEN}OK{RESET} {algo:24s} "
            f"pub={kp.public_key_bytes:>5}B  priv={kp.private_key_bytes:>5}B  "
            f"{elapsed:7.2f} ms"
        )

    # ------------------------------------------------------------------
    # Send + intercept
    # ------------------------------------------------------------------
    banner("STEP 2 — ALICE SENDS, THE ADVERSARY HARVESTS EVERYTHING")
    packet_ids: list[tuple[str, str]] = []

    for algo, label, message in DEMO_TRAFFIC:
        keypair = db.get_keypair("Bob", algo)
        assert keypair is not None, f"missing key for {algo}"

        plaintext = message.encode("utf-8")
        aad = f"Alice->Bob|{algo}".encode()

        envelope = ce.seal(algo, keypair["public_key"], plaintext, aad)

        # Sanity check: Bob really can read it.
        assert ce.unseal(algo, keypair["private_key"], envelope, aad) == plaintext

        packet_id = sim.intercept(
            sender="Alice",
            recipient="Bob",
            algorithm=algo,
            envelope=envelope,
            aad=aad,
            recipient_public=keypair["public_key"],
            plaintext_bytes=len(plaintext),
            label=label,
        )
        packet_ids.append((packet_id, algo))
        print(
            f"  {YELLOW}TAPPED{RESET} {packet_id}  {algo:24s} "
            f"{len(plaintext):>4}B plaintext -> {len(envelope.payload_ciphertext):>4}B ciphertext "
            f"(+{envelope.total_overhead_bytes}B overhead)"
        )

    summary = db.harvest_summary()
    print()
    print(
        f"  {BOLD}Adversary archive: {summary['total_packets']} packets, "
        f"{summary['total_bytes_at_risk']} bytes of plaintext at risk.{RESET}"
    )
    print(f"  {DIM}Note that ALL traffic was harvested, including the quantum-safe kind.{RESET}")
    print(f"  {DIM}Encryption does not stop you being recorded. It decides what the{RESET}")
    print(f"  {DIM}recording is worth.{RESET}")

    # ------------------------------------------------------------------
    # Q-Day
    # ------------------------------------------------------------------
    banner("STEP 3 — Q-DAY. THE ADVERSARY OPENS THE ARCHIVE.")
    outcomes: list[tuple[str, str, float]] = []
    demo_factor_ms = 0.0

    for packet_id, algo in packet_ids:
        print()
        print(f"{BOLD}--- Attacking {packet_id} ({algo}) ---{RESET}")
        result = sim.execute_q_day_attack(packet_id)

        colour = RED if result["status"] == sim.STATUS_BREACHED else GREEN
        for line in result["log_trace"].splitlines():
            print(f"  {DIM}{line}{RESET}")
        print(f"  {colour}{BOLD}>>> {result['status']}{RESET} in {result['execution_time_ms']} ms")

        outcomes.append((algo, result["status"], result["execution_time_ms"]))
        if algo == config.ALGO_RSA_DEMO and result["status"] == sim.STATUS_BREACHED:
            demo_factor_ms = result["execution_time_ms"]

    # ------------------------------------------------------------------
    # Extrapolation
    # ------------------------------------------------------------------
    banner("STEP 4 — WHAT CHANGES AT FULL SCALE")
    extra = sim.extrapolate_to_full_scale(demo_factor_ms or 1800.0)
    print(f"  Demo modulus broken     : {extra['demo_modulus_bits']} bits in {extra['demo_factor_ms']} ms")
    print(f"  Real-world target       : RSA-{extra['target_modulus_bits']}")
    print(f"  Classical cost (rho)    : ~10^{extra['classical_years_log10']:.0f} years  <- unreachable")
    print(f"  Shor's logical qubits   : {extra['shor_logical_qubits']:,}")
    print(f"  Shor's physical qubits  : {extra['shor_physical_qubits']:,}")
    print(f"  Shor's Toffoli gates    : {extra['shor_toffoli_gates']:.2e}")
    print(f"  ML-KEM-768 classical    : 2^{extra['mlkem_classical_gates_log2']} gates")
    print(f"  ML-KEM-768 quantum      : 2^{extra['mlkem_quantum_gates_log2']} gates  <- barely helps")
    print()
    print(f"  {DIM}{extra['shor_runtime_note']}{RESET}")

    # ------------------------------------------------------------------
    # Verdict
    # ------------------------------------------------------------------
    banner("SUMMARY")
    all_correct = True
    for algo, status, ms in outcomes:
        expected_breach = algo in config.QUANTUM_VULNERABLE_ALGORITHMS
        correct = (status == sim.STATUS_BREACHED) == expected_breach
        all_correct &= correct
        mark = f"{GREEN}OK{RESET}" if correct else f"{RED}UNEXPECTED{RESET}"
        colour = RED if status == sim.STATUS_BREACHED else GREEN
        print(f"  {mark}  {algo:24s} {colour}{status:16s}{RESET} {ms:9.1f} ms")

    # ------------------------------------------------------------------
    # Scanner pre-flight
    # ------------------------------------------------------------------
    banner("STEP 5 - PQC READINESS SCANNER PRE-FLIGHT")
    print(f"{DIM}Generating the demo enterprise (offline, local keys only)...{RESET}")

    from backend import demo_enterprise, scanner, service

    demo_enterprise.ensure_generated()
    report = service.scan_demo_enterprise()

    print(
        f"  {GREEN}OK{RESET} {report['assets_scanned']} assets scanned  |  "
        f"{report['quantum_vulnerable']} quantum vulnerable  |  "
        f"{report['pqc_ready']} PQC ready"
    )
    print(
        f"  {GREEN}OK{RESET} readiness score {report['readiness_score']}/100  "
        f"-> {report['verdict']}"
    )
    for entry in report["migration_order"][:3]:
        print(
            f"      {entry['risk']:<9} {entry['system_name']:<28} "
            f"retention {entry['retention_years']}y"
        )

    scanner_ok = report["assets_scanned"] == len(demo_enterprise.ENTERPRISE_ASSETS)
    if not scanner_ok:
        print(f"  {RED}Scanner did not see every asset. Investigate before presenting.{RESET}")

    print()
    if all_correct and scanner_ok:
        print(f"  {GREEN}{BOLD}Demo data seeded and verified. You are ready to present.{RESET}")
        print(f"  {DIM}Database: {config.DB_PATH}{RESET}")
        print(f"  {DIM}Enterprise: {demo_enterprise.DEMO_ENTERPRISE_DIR}{RESET}")
        return 0

    print(f"  {RED}{BOLD}Unexpected attack outcome. Do not present until this is fixed.{RESET}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
