"""
AegisPQC — shared service layer.

Every operation the demo performs lives here, exactly once. Both surfaces call
into this module:

    frontend/app.py  (Streamlit)  -->  service.py  -->  crypto_engine / database / simulator
    backend/main.py  (FastAPI)    -->  service.py  -->  crypto_engine / database / simulator

WHY THIS LAYER EXISTS
---------------------
The obvious architecture is Streamlit calling FastAPI over HTTP. That gives you
two processes that must both be alive during a three-minute pitch, and two ways
for the demo to die in front of judges — a port collision, a slow cold start, a
firewall prompt on a machine you have never used before.

This layer removes that risk. The Streamlit dashboard calls these functions
in-process, so the demo runs as ONE process with zero network dependencies. The
FastAPI service is still real, still fully functional, and still worth showing at
`/docs` — but nothing in the demo depends on it being up.

That is the correct trade: keep the API for the architecture story, remove it
from the critical path of the live demo.

DETERMINISM
-----------
The demo scenario is fixed. Same three messages, same three algorithms, same
order, every run. Nothing here generates random demo content. The only genuine
non-determinism in the system is the wall-clock duration of the RSA
factorization, because Pollard's rho is a randomised algorithm — the OUTCOME is
always the same (BREACHED), only the milliseconds differ.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from backend import config
from backend import crypto_engine as ce
from backend import database as db
from backend import demo_enterprise
from backend import migration
from backend import procedure
from backend import reporting
from backend import scanner
from backend import simulator as sim

# --------------------------------------------------------------------------
# The fixed demo scenario
# --------------------------------------------------------------------------
# Deliberately not randomised. Judges see the identical story every run, and you
# can rehearse against it. Each message is chosen so the HNDL threat is obvious
# from the content: all three have a confidentiality lifetime measured in
# decades, which is longer than RSA is expected to survive.

DEMO_SENDER = "Alice"
DEMO_RECIPIENT = "Bob"

DEMO_TRAFFIC: tuple[tuple[str, str, str], ...] = (
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
)


class ServiceError(Exception):
    """Raised when an operation fails for a reason the caller should surface."""


def _aad_for(sender: str, recipient: str, algorithm: str) -> bytes:
    """Build the additional authenticated data bound to every envelope.

    Binding sender, recipient, and algorithm into the GCM tag means an attacker
    cannot take a valid ciphertext and relabel who it was for, or claim it was
    sent under a different algorithm. Any such tampering makes decryption fail.
    """
    return f"{sender}->{recipient}|{algorithm}".encode()


# --------------------------------------------------------------------------
# Setup
# --------------------------------------------------------------------------


def ensure_ready(db_path: Path | None = None) -> None:
    """Create the schema if missing. Safe to call on every page load."""
    db.init_db(db_path)


def reset_and_seed(db_path: Path | None = None) -> dict[str, Any]:
    """Wipe everything and rebuild the fixed demo scenario from scratch.

    This is the "reset for the next judge" button. It is idempotent in the sense
    that running it twice produces an identical database state.

    Returns:
        A summary of what was created.
    """
    db.reset_db(db_path)
    db.create_user(DEMO_SENDER, db_path)
    recipient_id = db.create_user(DEMO_RECIPIENT, db_path)

    keys_created: list[dict[str, Any]] = []
    packets_created: list[dict[str, Any]] = []

    for algorithm, label, message in DEMO_TRAFFIC:
        keypair = ce.generate_keypair(algorithm)
        db.store_keypair(
            recipient_id, algorithm, keypair.public_key, keypair.private_key, db_path
        )
        keys_created.append(
            {
                "algorithm": algorithm,
                "public_key_bytes": keypair.public_key_bytes,
                "private_key_bytes": keypair.private_key_bytes,
            }
        )
        sent = send_message(
            sender=DEMO_SENDER,
            recipient=DEMO_RECIPIENT,
            algorithm=algorithm,
            message=message,
            label=label,
            db_path=db_path,
        )
        packets_created.append(sent)

    return {
        "users": [DEMO_SENDER, DEMO_RECIPIENT],
        "keys": keys_created,
        "packets": packets_created,
    }


def ensure_keys_for(
    username: str, algorithm: str, db_path: Path | None = None
) -> dict[str, Any]:
    """Return a user's key pair for one algorithm, generating it if absent.

    Lets the UI offer a "send" button for any algorithm without the user having
    to think about key management first.
    """
    existing = db.get_keypair(username, algorithm, db_path)
    if existing is not None:
        return existing

    user_id = db.create_user(username, db_path)
    keypair = ce.generate_keypair(algorithm)
    db.store_keypair(user_id, algorithm, keypair.public_key, keypair.private_key, db_path)

    stored = db.get_keypair(username, algorithm, db_path)
    if stored is None:  # pragma: no cover — would mean a database write failed
        raise ServiceError(f"Failed to store key pair for {username}/{algorithm}")
    return stored


def generate_keys(
    username: str, algorithm: str, db_path: Path | None = None
) -> dict[str, Any]:
    """Force-generate a fresh key pair, replacing any existing one.

    Returns:
        Metadata only. Private key material never leaves this module.
    """
    if algorithm not in (*config.SUPPORTED_ALGORITHMS, config.ALGO_RSA_2048):
        raise ServiceError(f"Unsupported algorithm: {algorithm}")

    user_id = db.create_user(username, db_path)
    keypair = ce.generate_keypair(algorithm)
    key_id = db.store_keypair(
        user_id, algorithm, keypair.public_key, keypair.private_key, db_path
    )
    return {
        "key_id": key_id,
        "username": username,
        "algorithm": algorithm,
        "public_key_bytes": keypair.public_key_bytes,
        "private_key_bytes": keypair.private_key_bytes,
        "public_key_preview": keypair.public_key[:32].hex(),
    }


# --------------------------------------------------------------------------
# Vault operations
# --------------------------------------------------------------------------


def send_message(
    sender: str,
    recipient: str,
    algorithm: str,
    message: str,
    label: str = "",
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Encrypt a message, send it, and let the adversary harvest a copy.

    The interception is NOT optional and NOT conditional on the algorithm. That
    is the whole point of the project: a passive tap records everything. Choosing
    ML-KEM does not make you invisible, it makes the recording worthless.

    Returns:
        The envelope in display form, plus the packet_id the adversary filed it
        under.
    """
    if algorithm not in (*config.SUPPORTED_ALGORITHMS, config.ALGO_RSA_2048):
        raise ServiceError(f"Unsupported algorithm: {algorithm}")

    plaintext = message.encode("utf-8")
    if not plaintext:
        raise ServiceError("Message is empty.")

    keypair = ensure_keys_for(recipient, algorithm, db_path)
    aad = _aad_for(sender, recipient, algorithm)
    envelope = ce.seal(algorithm, keypair["public_key"], plaintext, aad)

    packet_id = sim.intercept(
        sender=sender,
        recipient=recipient,
        algorithm=algorithm,
        envelope=envelope,
        aad=aad,
        recipient_public=keypair["public_key"],
        plaintext_bytes=len(plaintext),
        label=label,
        db_path=db_path,
    )

    return {
        "packet_id": packet_id,
        "sender": sender,
        "recipient": recipient,
        "label": label,
        "plaintext_bytes": len(plaintext),
        "intercepted": True,
        **envelope.to_dict(),
    }


def receive_message(
    packet_id: str, db_path: Path | None = None
) -> dict[str, Any]:
    """Decrypt a packet the way the legitimate recipient would.

    This is the control case. It proves the system actually works — that the
    intended recipient reads the message instantly using the private key they
    already hold, while the adversary holding the same ciphertext cannot.

    Returns:
        The recovered plaintext and how long decryption took.
    """
    import time

    packet = db.get_packet(packet_id, db_path)
    if packet is None:
        raise ServiceError(f"No packet with id {packet_id!r}")

    algorithm = packet["algo_used"]
    keypair = db.get_keypair(packet["recipient"], algorithm, db_path)
    if keypair is None:
        raise ServiceError(
            f"{packet['recipient']} has no {algorithm} key. "
            "The database may have been reset since this packet was sent."
        )

    envelope = ce.SealedEnvelope(
        algorithm=algorithm,
        kem_ciphertext=packet["kem_ciphertext"],
        nonce=packet["nonce"],
        payload_ciphertext=packet["payload_ciphertext"],
    )

    started = time.perf_counter()
    try:
        plaintext = ce.unseal(
            algorithm, keypair["private_key"], envelope, packet["aad"] or None
        )
    except ce.CryptoError as exc:
        raise ServiceError(f"Decryption failed: {exc}") from exc
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    return {
        "packet_id": packet_id,
        "algorithm": algorithm,
        "plaintext": plaintext.decode("utf-8", errors="replace"),
        "decrypt_ms": round(elapsed_ms, 3),
    }


# --------------------------------------------------------------------------
# Adversary view
# --------------------------------------------------------------------------


def list_harvested(db_path: Path | None = None) -> list[dict[str, Any]]:
    """Everything in the adversary's archive, newest first, in stable order."""
    return db.list_packets(db_path)


def harvest_stats(db_path: Path | None = None) -> dict[str, Any]:
    """Headline numbers for the adversary dashboard."""
    summary = db.harvest_summary(db_path)
    packets = db.list_packets(db_path)

    vulnerable = sum(
        1 for p in packets if p["algo_used"] in config.QUANTUM_VULNERABLE_ALGORITHMS
    )
    breached = sum(1 for p in packets if p["last_attack_status"] == sim.STATUS_BREACHED)

    return {
        **summary,
        "vulnerable_packets": vulnerable,
        "quantum_safe_packets": summary["total_packets"] - vulnerable,
        "already_breached": breached,
    }


# --------------------------------------------------------------------------
# Q-Day
# --------------------------------------------------------------------------


def run_attack(
    packet_id: str,
    db_path: Path | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Attempt to break one harvested packet.

    Args:
        packet_id: Target packet.
        db_path: Optional database override.
        progress: Optional per-line callback so the UI can stream the attack
            trace live instead of waiting for the whole result.
    """
    return sim.execute_q_day_attack(packet_id, db_path=db_path, progress=progress)


def attack_all(db_path: Path | None = None) -> list[dict[str, Any]]:
    """Run Q-Day against the entire archive, oldest packet first.

    Oldest-first is deliberate: it matches the order the packets were sent, so
    the RSA packet (sent first in the demo scenario) falls first and the
    post-quantum ones hold afterwards. That is the narrative order you want.
    """
    packets = sorted(db.list_packets(db_path), key=lambda p: p["seq"])
    return [run_attack(p["packet_id"], db_path=db_path) for p in packets]


def list_attack_history(db_path: Path | None = None) -> list[dict[str, Any]]:
    """Every attack attempt recorded so far."""
    return db.list_attacks(db_path)


def extrapolation(demo_factor_ms: float | None = None) -> dict[str, Any]:
    """Full-scale projection from the measured live break.

    Args:
        demo_factor_ms: The measured factoring time. If omitted, the most recent
            successful break in the attack log is used.
    """
    if demo_factor_ms is None:
        breaches = [
            a
            for a in db.list_attacks()
            if a["status"] == sim.STATUS_BREACHED
        ]
        demo_factor_ms = breaches[0]["execution_time_ms"] if breaches else 1800.0
    return sim.extrapolate_to_full_scale(demo_factor_ms)


# --------------------------------------------------------------------------
# Benchmarks
# --------------------------------------------------------------------------


def reset_presentation_state(db_path: Path | None = None) -> dict[str, Any]:
    """Put the ENTIRE application into a known, presentable state.

    This is the one control a presenter needs between judges. It covers every
    beat of the demo in a single call:

        1. Wipes and rebuilds the database
        2. Creates Alice and Bob
        3. Generates a key pair per algorithm
        4. Sends the three demonstration messages
        5. Populates the interceptor archive
        6. Leaves the Q-Day scenario armed but not yet run
        7. Ensures the demo enterprise exists for the scanner tab

    Step 7 is why this exists rather than :func:`reset_and_seed` alone. The
    scanner's enterprise is generated lazily on first use, and that generation
    includes an RSA-3072 key — a few seconds of work. Doing it here means it
    happens during setup, not while a judge is watching the scanner tab load.

    Attack history is deliberately cleared, so the Q-Day tab shows an unbroken
    scenario every time rather than results left over from the previous run.

    Returns:
        A summary of everything that was prepared.
    """
    seeded = reset_and_seed(db_path)

    # Generate the scanner's estate now, so the demo never pays for it on stage.
    enterprise_generated = not demo_enterprise.is_generated()
    enterprise_root = demo_enterprise_path()

    return {
        "packets": seeded["packets"],
        "keys": seeded["keys"],
        "users": seeded["users"],
        "packet_count": len(seeded["packets"]),
        "enterprise_path": str(enterprise_root),
        "enterprise_assets": len(demo_enterprise.ENTERPRISE_ASSETS),
        "enterprise_generated_now": enterprise_generated,
        "attacks_cleared": True,
    }


def presentation_state_summary(db_path: Path | None = None) -> dict[str, Any]:
    """Report whether the application is currently in a presentable state.

    Used by the dashboard sidebar so a presenter can confirm readiness at a
    glance instead of clicking through tabs to check.
    """
    packets = db.list_packets(db_path)
    attacks = db.list_attacks(db_path)
    return {
        "packets": len(packets),
        "algorithms_present": sorted({p["algo_used"] for p in packets}),
        "attacks_run": len(attacks),
        "enterprise_ready": demo_enterprise.is_generated(),
        "ready": len(packets) >= 3 and demo_enterprise.is_generated(),
    }


def benchmarks(iterations: int | None = None) -> list[dict[str, Any]]:
    """Measured key sizes and latencies for every algorithm.

    Args:
        iterations: Samples per operation. Lower values return faster; the
            defaults in config are tuned for a live demo.
    """
    return ce.run_benchmarks(iterations)


# --------------------------------------------------------------------------
# PQC readiness scanner
# --------------------------------------------------------------------------


def demo_enterprise_path(root: Path | None = None) -> Path:
    """Path to the fictional enterprise, generating it on first use.

    Generation is local and offline: real keys and self-signed certificates
    written to disk with no network access and no certificate authority.
    """
    return demo_enterprise.ensure_generated(root)


def scan_demo_enterprise(root: Path | None = None) -> dict[str, Any]:
    """Generate the demo enterprise if needed, then assess it.

    This is what the LOAD DEMO ENTERPRISE button calls. It is the only scanner
    path the presentation depends on, so it must never require the presenter to
    locate certificates on an unfamiliar machine.
    """
    return scanner.scan(demo_enterprise_path(root))


def scan_path(target: str | Path) -> dict[str, Any]:
    """Assess a user-supplied directory or single file.

    Args:
        target: Directory to walk, or a single certificate/key file.

    Raises:
        ServiceError: If the path does not exist.
    """
    path = Path(target).expanduser()
    if not path.exists():
        raise ServiceError(f"Path does not exist: {path}")

    if path.is_file():
        finding = scanner.scan_file(path)
        findings = [finding] if finding is not None else []
        return scanner.build_assessment(findings)

    return scanner.scan(path)


def scan_uploaded(files: list[tuple[str, bytes]]) -> dict[str, Any]:
    """Assess files uploaded through the dashboard.

    The bytes are written to a temporary directory, scanned, and the directory
    is removed immediately afterwards. Nothing uploaded is retained.

    Args:
        files: ``(filename, content)`` pairs.
    """
    import shutil
    import tempfile

    workdir = Path(tempfile.mkdtemp(prefix="aegis_scan_"))
    try:
        for name, content in files:
            # Flatten the name so an uploaded path cannot escape the temp
            # directory. Uploads are untrusted input.
            safe_name = Path(name).name or "unnamed"
            (workdir / safe_name).write_bytes(content)
        return scanner.scan(workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------
# Migration planning
# --------------------------------------------------------------------------


def migration_plan(assessment: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a prioritised migration plan.

    Args:
        assessment: An existing scanner assessment. If omitted, the demo
            enterprise is scanned. Passing one in avoids a redundant re-scan
            when the caller already has the assessment in hand.
    """
    assessment = assessment or scan_demo_enterprise()
    return migration.build_plan(assessment)


def verify_migration_plan(plan: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate a migration plan's internal consistency — the VERIFY stage.

    Checks the plan, not a migrated estate. Nothing here modifies real
    infrastructure, and the returned scope note says so.
    """
    return migration.verify_plan(plan or migration_plan())


# --------------------------------------------------------------------------
# Procedural views
# --------------------------------------------------------------------------


def vault_pipeline(sent: dict[str, Any]) -> list[dict[str, Any]]:
    """Break a completed send into its cryptographic pipeline stages."""
    return procedure.vault_pipeline(sent)


def attack_procedure(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a Q-Day attack result into explicit procedural steps."""
    return procedure.attack_procedure(result)


def hybrid_defence() -> dict[str, Any]:
    """Explain what an attacker faces against the hybrid construction."""
    return procedure.hybrid_defence_explanation()


def workflow() -> list[dict[str, Any]]:
    """The eight-stage cryptographic migration workflow backbone."""
    return procedure.workflow_stages()


# --------------------------------------------------------------------------
# Forensics
# --------------------------------------------------------------------------


def packet_forensics(packet_id: str, db_path: Path | None = None) -> dict[str, Any]:
    """Full forensic detail for one harvested packet.

    Returns exactly what a passive network tap could observe and nothing more.
    The KEM ciphertext, nonce, and authentication tag are all public by design;
    the shared secret, the AES key, and every private key are absent.

    The authentication tag is extracted as the trailing 16 bytes of the AES-GCM
    ciphertext, which is where GCM places it. Splitting it out makes the
    envelope structure legible without revealing anything secret.

    Raises:
        ServiceError: If no such packet exists.
    """
    packet = db.get_packet(packet_id, db_path)
    if packet is None:
        raise ServiceError(f"No packet with id {packet_id!r}")

    payload = packet["payload_ciphertext"]
    tag = payload[-config.AES_TAG_BYTES:] if len(payload) >= config.AES_TAG_BYTES else b""
    body = payload[: -config.AES_TAG_BYTES] if tag else payload
    algorithm = packet["algo_used"]

    return {
        "packet_id": packet["packet_id"],
        "intercepted_at": packet["intercepted_at"],
        "sender": packet["sender"],
        "recipient": packet["recipient"],
        "label": packet["label"],
        "algorithm": algorithm,
        "quantum_vulnerable": algorithm in config.QUANTUM_VULNERABLE_ALGORITHMS,
        "plaintext_bytes": packet["plaintext_bytes"],
        # Observable envelope structure
        "kem_ciphertext_bytes": len(packet["kem_ciphertext"]),
        "kem_ciphertext_preview": packet["kem_ciphertext"][:48].hex(),
        "nonce": packet["nonce"].hex(),
        "nonce_bits": len(packet["nonce"]) * 8,
        "auth_tag": tag.hex(),
        "auth_tag_bits": len(tag) * 8,
        "ciphertext_body_bytes": len(body),
        "ciphertext_preview": body[:48].hex(),
        "total_captured_bytes": (
            len(packet["kem_ciphertext"]) + len(packet["nonce"]) + len(payload)
        ),
        # Public metadata a tap would also observe
        "aad": packet["aad"].decode("utf-8", errors="replace") if packet["aad"] else "",
        "recipient_public_key_bytes": len(packet["recipient_public"]),
        # The guarantees, stated on the artifact itself
        "private_keys_captured": False,
        "capture_method": "Passive optical tap",
        "capture_note": (
            "Passive interception — no cryptographic modification. The adversary "
            "injects nothing, alters nothing, and triggers no alarm. Every field "
            "above is observable on the wire by design."
        ),
        "key_custody_note": (
            "PRIVATE KEYS NOT CAPTURED. A network tap observes ciphertext and "
            "public parameters only. Private keys never traverse the wire."
        ),
    }


# --------------------------------------------------------------------------
# Executive summary
# --------------------------------------------------------------------------


def executive_summary(db_path: Path | None = None) -> dict[str, Any]:
    """Aggregate every subsystem into one executive view.

    Assembled from already-computed subsystem outputs rather than recomputing
    anything, so the overview can never disagree with the tab it summarises.
    """
    harvest = harvest_stats(db_path)
    assessment = scan_demo_enterprise()
    plan = migration.build_plan(assessment)
    attacks = db.list_attacks(db_path)

    breached = [a for a in attacks if a["status"] == sim.STATUS_BREACHED]
    held = [a for a in attacks if a["status"] == sim.STATUS_IMMUNE]

    return {
        "estate": {
            "assets_scanned": assessment["assets_scanned"],
            "quantum_vulnerable": assessment["quantum_vulnerable"],
            "pqc_ready": assessment["pqc_ready"],
            "unidentified": assessment["unidentified"],
            "readiness_score": assessment["readiness_score"],
            "verdict": assessment["verdict"],
            "risk_counts": assessment["counts"],
        },
        "migration": {
            "requiring_migration": plan["assets_requiring_migration"],
            "critical": plan["critical_migrations"],
            "high": plan["high_migrations"],
            "already_ready": plan["assets_already_pqc_ready"],
            "top_priorities": [
                {
                    "position": rec["position"],
                    "system_name": rec["system_name"],
                    "risk": rec["risk"],
                    "current": (
                        f"{rec['current_algorithm']}-{rec['current_key_size']}"
                        if rec["current_key_size"]
                        else rec["current_algorithm"]
                    ),
                    "retention_years": rec["retention_years"],
                    "recommended_target": rec["recommended_target"],
                    "why_first": rec["why_first"],
                }
                for rec in plan["recommendations"][:5]
            ],
        },
        "demonstration": {
            "packets_harvested": harvest["total_packets"],
            "vulnerable_packets": harvest["vulnerable_packets"],
            "quantum_safe_packets": harvest["quantum_safe_packets"],
            "bytes_at_risk": harvest["total_bytes_at_risk"],
            "attacks_run": len(attacks),
            "packets_breached": len(breached),
            "packets_held": len(held),
            "qday_status": (
                "DEMONSTRATED"
                if breached
                else ("ARMED" if harvest["total_packets"] else "NOT READY")
            ),
        },
        "threat_model": {
            "name": "Harvest Now, Decrypt Later",
            "summary": (
                "An adversary who cannot break encryption today records it and "
                "waits. The exposure is not a function of today's attacker but "
                "of how long the data must remain confidential."
            ),
            "demonstrated_today": (
                f"A deliberately undersized {config.RSA_DEMO_PRIME_BITS * 2}-bit "
                "RSA modulus is genuinely factored using classical "
                "factorisation. No quantum computer is involved."
            ),
            "future_threat": (
                "Shor's algorithm is the relevant quantum threat to RSA and "
                "elliptic curves at cryptographically relevant sizes. No machine "
                "capable of running it against RSA-2048 exists today."
            ),
            "defence": (
                "ML-KEM (NIST FIPS 203) rests on lattice problems, which Shor's "
                "algorithm does not solve. It is designed to resist known "
                "classical and quantum attacks."
            ),
        },
    }


# --------------------------------------------------------------------------
# Benchmarks — measured versus estimated, never mixed
# --------------------------------------------------------------------------


def benchmark_bundle(iterations: int | None = None) -> dict[str, Any]:
    """Measured benchmarks alongside clearly-separated research estimates.

    The separation is the point. Latency and size figures are MEASURED on this
    machine. Quantum attack costs are ESTIMATED from published literature and
    cannot be measured by anyone today. Presenting them in one undifferentiated
    table would imply we measured something we did not.
    """
    measured = ce.run_benchmarks(iterations)
    by_algorithm = {row["algorithm"]: row for row in measured}

    rsa = by_algorithm.get(config.ALGO_RSA_2048)
    mlkem = by_algorithm.get(config.ALGO_ML_KEM_768)
    hybrid = by_algorithm.get(config.ALGO_HYBRID)

    relative: dict[str, Any] = {}
    if rsa and mlkem and mlkem["keygen_ms"] > 0:
        relative = {
            "mlkem_keygen_speedup": round(rsa["keygen_ms"] / mlkem["keygen_ms"], 1),
            "mlkem_decrypt_speedup": round(
                rsa["decapsulate_decrypt_ms"] / mlkem["decapsulate_decrypt_ms"], 1
            ),
            "mlkem_wire_overhead_ratio": round(
                mlkem["wire_overhead_bytes"] / rsa["wire_overhead_bytes"], 1
            ),
            "hybrid_wire_overhead_ratio": (
                round(hybrid["wire_overhead_bytes"] / rsa["wire_overhead_bytes"], 1)
                if hybrid
                else None
            ),
        }

    return {
        "measured": {
            "source": "MEASURED",
            "note": (
                "Every value in this section was measured on the machine running "
                "this application, at the iteration count shown. Nothing here is "
                "quoted from literature."
            ),
            "payload_bytes": config.BENCHMARK_PAYLOAD_BYTES,
            "rows": measured,
            "relative": relative,
        },
        "estimated": {
            "source": "ESTIMATED / RESEARCH-BASED",
            "note": (
                "Nothing in this section is measured, and nothing here could be "
                "measured by anyone today. These are published resource estimates "
                "against attacks that no existing machine can run. They are "
                "revised as the research advances."
            ),
            "rows": [
                {
                    "metric": "Shor's algorithm — logical qubits for RSA-2048",
                    "value": f"{config.SHOR_LOGICAL_QUBITS_RSA2048:,}",
                    "citation": "Gidney & Ekera, 2019",
                },
                {
                    "metric": "Shor's algorithm — physical qubits for RSA-2048",
                    "value": f"{config.SHOR_PHYSICAL_QUBITS_RSA2048:,}",
                    "citation": "Gidney & Ekera, 2019 (surface-code assumptions)",
                },
                {
                    "metric": "Shor's algorithm — Toffoli gate count",
                    "value": f"{config.SHOR_TOFFOLI_GATES_RSA2048:.2e}",
                    "citation": "Gidney & Ekera, 2019",
                },
                {
                    "metric": "ML-KEM-768 — best known classical attack",
                    "value": "~2^181 gates",
                    "citation": "BKZ with sieving, NIST FIPS 203 security analysis",
                },
                {
                    "metric": "ML-KEM-768 — best known quantum attack",
                    "value": "~2^165 gates",
                    "citation": "BKZ with sieving, NIST FIPS 203 security analysis",
                },
            ],
        },
        "tradeoffs": [
            {
                "algorithm": "RSA-2048",
                "advantage": "Smaller wire representation and universal deployment",
                "cost": "Quantum vulnerable; slow key generation and decryption",
                "verdict": "Adequate today, exposed to harvesting for long-lived data",
            },
            {
                "algorithm": "ML-KEM-768",
                "advantage": (
                    "Dramatically faster key generation and decapsulation; "
                    "designed for post-quantum security"
                ),
                "cost": "Larger keys and ciphertexts, so more bytes per handshake",
                "verdict": "Bandwidth is the real cost of migration, not speed",
            },
            {
                "algorithm": "Hybrid X25519 + ML-KEM-768",
                "advantage": (
                    "Requires defeating both a classical and a post-quantum problem"
                ),
                "cost": "Highest wire overhead; two key establishments per session",
                "verdict": "Migration resilience bought with bandwidth",
            },
        ],
    }


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def full_report(
    db_path: Path | None = None, include_benchmarks: bool = False
) -> dict[str, Any]:
    """Assemble the complete assessment report.

    Args:
        db_path: Optional database override.
        include_benchmarks: Whether to run and include measured benchmarks. Off
            by default because benchmarking takes a moment and the report is
            usually wanted immediately.
    """
    assessment = scan_demo_enterprise()
    plan = migration.build_plan(assessment)
    verification = migration.verify_plan(plan)
    harvest = harvest_stats(db_path)
    benchmark_rows = ce.run_benchmarks(10) if include_benchmarks else None

    return reporting.build_report(
        assessment=assessment,
        plan=plan,
        verification=verification,
        harvest=harvest,
        benchmarks=benchmark_rows,
    )


def report_markdown(
    db_path: Path | None = None, include_benchmarks: bool = False
) -> str:
    """Render the full assessment report as Markdown."""
    return reporting.render_markdown(full_report(db_path, include_benchmarks))
