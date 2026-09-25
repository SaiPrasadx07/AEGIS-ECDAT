"""
AegisPQC — cryptographic migration workflow and procedural staging.

This module gives the product its conceptual backbone: the eight-stage
cryptographic migration lifecycle that every screen maps onto.

    DISCOVER -> ASSESS -> PRIORITIZE -> PROTECT -> HARVEST -> SIMULATE -> MIGRATE -> VERIFY

A HARD RULE APPLIES HERE
------------------------
Every stage must correspond to something the prototype genuinely does. This is
not a diagram of an imagined enterprise product with the boxes filled in by
marketing. Each stage below names the module that implements it, and
:func:`workflow_stages` reports ``implemented=False`` for anything that is
partially realised — currently VERIFY, which validates the migration plan's
internal consistency rather than re-scanning a migrated estate, because nothing
is actually migrated by this prototype.

WHY THIS MODULE DOES NOT LIVE IN simulator.py
---------------------------------------------
``simulator.py`` is verified, tested, and carries the project's most
scrutinised code — the real factorisation. This module reads its OUTPUT and
structures it for display. It never changes how the attack runs, so the
procedural view cannot introduce a defect into the cryptography. Parsing the
trace is strictly a presentation concern and belongs outside the engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

from backend import config

# ==========================================================================
# The workflow backbone
# ==========================================================================


@dataclass(frozen=True, slots=True)
class WorkflowStage:
    """One stage of the cryptographic migration lifecycle.

    Attributes:
        key: Stable identifier used by the UI.
        name: Display name.
        question: The question this stage answers for a security team.
        surface: Where in the product this stage is performed.
        module: The backend module that actually implements it.
        implemented: Whether the prototype fully performs this stage. Reported
            honestly; the UI shows partial stages differently.
        caveat: What is NOT done, when ``implemented`` is False.
    """

    key: str
    name: str
    question: str
    surface: str
    module: str
    implemented: bool = True
    caveat: str = ""


WORKFLOW: Final[tuple[WorkflowStage, ...]] = (
    WorkflowStage(
        key="discover",
        name="DISCOVER",
        question="What cryptography is actually deployed across the estate?",
        surface="PQC Readiness",
        module="backend/scanner.py",
    ),
    WorkflowStage(
        key="assess",
        name="ASSESS",
        question="Which assets are quantum vulnerable, and on what evidence?",
        surface="PQC Readiness",
        module="backend/scanner.py",
    ),
    WorkflowStage(
        key="prioritize",
        name="PRIORITIZE",
        question="What has to be fixed first, and why that order?",
        surface="Migration Plan",
        module="backend/migration.py",
    ),
    WorkflowStage(
        key="protect",
        name="PROTECT",
        question="What does a post-quantum protected message actually look like?",
        surface="Quantum Vault",
        module="backend/crypto_engine.py",
    ),
    WorkflowStage(
        key="harvest",
        name="HARVEST",
        question="What can a passive adversary collect from the wire today?",
        surface="HNDL Hoard",
        module="backend/simulator.py",
    ),
    WorkflowStage(
        key="simulate",
        name="SIMULATE",
        question="What happens to that archive when the capability arrives?",
        surface="Q-Day Simulator",
        module="backend/simulator.py",
    ),
    WorkflowStage(
        key="migrate",
        name="MIGRATE",
        question="What is the concrete plan to remove the exposure?",
        surface="Migration Plan",
        module="backend/migration.py",
    ),
    WorkflowStage(
        key="verify",
        name="VERIFY",
        question="Is the plan internally consistent and complete?",
        surface="Migration Plan",
        module="backend/migration.py",
        implemented=False,
        caveat=(
            "This prototype validates the migration plan's completeness and "
            "consistency. It does NOT re-scan a migrated estate, because it "
            "never modifies any real system. Post-migration verification in a "
            "production deployment would re-run DISCOVER against the changed "
            "infrastructure."
        ),
    ),
)


def workflow_stages() -> list[dict[str, Any]]:
    """Return the workflow backbone as plain dicts for the UI and API."""
    return [
        {
            "key": stage.key,
            "name": stage.name,
            "question": stage.question,
            "surface": stage.surface,
            "module": stage.module,
            "implemented": stage.implemented,
            "caveat": stage.caveat,
        }
        for stage in WORKFLOW
    ]


# ==========================================================================
# Vault pipeline staging
# ==========================================================================


@dataclass(slots=True)
class ProcedureStep:
    """One step in a displayed procedure, with its real measured artifacts."""

    index: int
    title: str
    detail: str
    artifacts: dict[str, Any] = field(default_factory=dict)
    reached: bool = True
    outcome: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "title": self.title,
            "detail": self.detail,
            "artifacts": dict(self.artifacts),
            "reached": self.reached,
            "outcome": self.outcome,
        }


def vault_pipeline(sent: dict[str, Any]) -> list[dict[str, Any]]:
    """Break a completed send into its cryptographic pipeline stages.

    Every artifact shown comes from the actual envelope that was produced. No
    secret material appears: the KEM ciphertext and nonce are public by design,
    and the shared secret and AES key are never included.

    Args:
        sent: The dict returned by ``service.send_message``.

    Returns:
        Ordered pipeline steps, ready for display.
    """
    algorithm = sent["algorithm"]
    hybrid = algorithm == config.ALGO_HYBRID

    if hybrid:
        establishment_detail = (
            "Two independent key establishments run in parallel. An ephemeral "
            "X25519 exchange produces one shared secret; an ML-KEM-768 "
            "encapsulation produces another. Both are required."
        )
        establishment_title = "Key establishment — X25519 + ML-KEM-768"
    elif algorithm == config.ALGO_ML_KEM_768:
        establishment_detail = (
            "ML-KEM-768 encapsulation against the recipient's public key. The "
            "shared secret is generated locally and never transmitted; only the "
            "KEM ciphertext travels."
        )
        establishment_title = "Key establishment — ML-KEM-768 encapsulation"
    else:
        establishment_detail = (
            "RSA encapsulation of a random seed under the recipient's public "
            "key. This is the quantum-vulnerable step: recovering the seed "
            "requires only factoring the modulus."
        )
        establishment_title = "Key establishment — RSA encapsulation"

    kdf_detail = (
        "HKDF-SHA256 combines BOTH shared secrets into one 256-bit key. An "
        "attacker who defeats only one leg still cannot derive it."
        if hybrid
        else "HKDF-SHA256 stretches the shared secret into a 256-bit AES key "
        "and binds it to a context label, so the same secret cannot produce "
        "the same key in a different context."
    )

    steps = [
        ProcedureStep(
            index=1,
            title="Plaintext",
            detail="The message before any cryptography is applied.",
            artifacts={"plaintext_bytes": sent["plaintext_bytes"]},
        ),
        ProcedureStep(
            index=2,
            title=establishment_title,
            detail=establishment_detail,
            artifacts={
                "algorithm": algorithm,
                "kem_ciphertext_bytes": sent["kem_ciphertext_bytes"],
            },
        ),
        ProcedureStep(
            index=3,
            title="Key derivation — HKDF-SHA256",
            detail=kdf_detail,
            artifacts={"derived_key_bits": config.AES_KEY_BYTES * 8},
        ),
        ProcedureStep(
            index=4,
            title="Symmetric encryption — AES-256-GCM",
            detail=(
                "Identical in every mode. AES is NOT being replaced by "
                "post-quantum cryptography: Grover's algorithm offers only a "
                "quadratic speedup, leaving AES-256 with roughly 128 bits of "
                "post-quantum security. Only the key establishment changes."
            ),
            artifacts={
                "nonce_bits": config.AES_NONCE_BYTES * 8,
                "auth_tag_bits": config.AES_TAG_BYTES * 8,
                "nonce": sent["nonce"],
            },
        ),
        ProcedureStep(
            index=5,
            title="Ciphertext on the wire",
            detail=(
                "The complete envelope: KEM ciphertext, nonce, and the "
                "authenticated payload. No key material of any kind is present."
            ),
            artifacts={
                "payload_ciphertext_bytes": sent["payload_ciphertext_bytes"],
                "total_overhead_bytes": sent["total_overhead_bytes"],
            },
        ),
        ProcedureStep(
            index=6,
            title="Network transit",
            detail="The envelope crosses an untrusted network segment.",
            artifacts={"route": f"{sent['sender']} -> {sent['recipient']}"},
        ),
        ProcedureStep(
            index=7,
            title="Passive interception",
            detail=(
                "A passive tap copies the envelope into the adversary's "
                "archive. This happens regardless of algorithm. Encryption does "
                "not prevent recording; it determines what the recording is "
                "worth later."
            ),
            artifacts={"packet_id": sent["packet_id"], "harvested": True},
            outcome="HARVESTED",
        ),
    ]

    return [step.to_dict() for step in steps]


# ==========================================================================
# Q-Day attack staging
# ==========================================================================

#: Marker prefixes emitted by ``simulator.execute_q_day_attack``, mapped to the
#: procedural step they belong to. Parsing markers rather than free text means
#: a wording change in the simulator cannot silently break the staged view.
_RSA_STEP_MARKERS: Final[tuple[tuple[str, str, str], ...]] = (
    (
        "[FACTOR] Reading",
        "Extract the public modulus",
        "The attacker reads n and e from the recipient's PUBLIC key, captured "
        "off the wire. Nothing secret is used at any point in this procedure.",
    ),
    (
        "[FACTOR] Running",
        "Begin classical factorisation",
        "Brent's variant of Pollard's rho searches for a non-trivial factor. "
        "This is a CLASSICAL algorithm running on ordinary hardware — not "
        "Shor's algorithm, and no quantum computer is involved.",
    ),
    (
        "[FACTOR] FACTORED",
        "Recover the primes p and q",
        "A non-trivial factor is found and verified by multiplication. The "
        "modulus is now fully factored.",
    ),
    (
        "[KEYGEN] Reconstructing",
        "Reconstruct the private exponent",
        "With p and q known, the Carmichael totient follows, and inverting e "
        "modulo it yields d. The private key has been derived from public data.",
    ),
    (
        "[DECAP ] Decapsulating",
        "Decapsulate the harvested KEM ciphertext",
        "Applying d to the captured KEM ciphertext recovers the seed the sender "
        "encapsulated.",
    ),
    (
        "[DECAP ]   HKDF",
        "Derive the AES key",
        "HKDF-SHA256 over the recovered seed produces the same 256-bit AES key "
        "the sender used.",
    ),
    (
        "[DECRYPT] AES-GCM tag verified",
        "Decrypt the payload",
        "AES-256-GCM decryption succeeds and the authentication tag verifies, "
        "confirming the recovered key is correct.",
    ),
    (
        "[RESULT ] A message encrypted",
        "Plaintext recovered",
        "A message encrypted in the past has been read afterwards, using only "
        "the recording and time.",
    ),
)

_LATTICE_STEP_MARKERS: Final[tuple[tuple[str, str, str], ...]] = (
    (
        "[LATTICE] Target is",
        "Obtain the harvested ciphertext",
        "The attacker holds the complete envelope: KEM ciphertext, nonce, and "
        "payload. Exactly the same starting position as the RSA case.",
    ),
    (
        "[LATTICE]   Underlying problem",
        "No decapsulation key is available",
        "Recovering the shared secret requires solving Module Learning With "
        "Errors. Shor's algorithm solves period-finding in abelian groups; "
        "lattice problems are not of that form, so it does not apply.",
    ),
    (
        "[LATTICE]   classical gate cost",
        "Consult the published attack cost",
        "Best known attack is BKZ lattice reduction with sieving. These are "
        "published ESTIMATES against currently known attacks, not measurements "
        "and not proofs.",
    ),
    (
        "[LATTICE] No attack attempted",
        "Shared secret remains unavailable",
        "No reduction is attempted here. Doing so would be theatre — the "
        "published cost is the entire argument.",
    ),
)


def attack_procedure(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a Q-Day attack result into explicit procedural steps.

    Reads the trace produced by ``simulator.execute_q_day_attack`` and maps its
    markers onto named steps. A step that never appears in the trace is returned
    with ``reached=False``, so a partial or aborted attack renders honestly
    rather than showing a completed procedure.

    Args:
        result: The dict returned by ``service.run_attack``.

    Returns:
        Ordered procedural steps with the trace lines that evidence each one.
    """
    algorithm = result.get("algorithm", "")
    trace_lines = result.get("log_trace", "").splitlines()

    if algorithm in config.QUANTUM_VULNERABLE_ALGORITHMS:
        markers = _RSA_STEP_MARKERS
    else:
        markers = _LATTICE_STEP_MARKERS

    steps: list[ProcedureStep] = []
    for position, (marker, title, detail) in enumerate(markers, start=1):
        evidence = [line for line in trace_lines if line.startswith(marker)]
        steps.append(
            ProcedureStep(
                index=position,
                title=title,
                detail=detail,
                artifacts={"evidence": evidence[:4]},
                reached=bool(evidence),
            )
        )

    # RSA-2048 takes the vulnerable-algorithm path but is deliberately never
    # attacked, so no step is reached. Replace the whole procedure with the
    # refusal, which is the honest thing to display.
    if algorithm == config.ALGO_RSA_2048 and not any(s.reached for s in steps):
        steps = [
            ProcedureStep(
                index=1,
                title="Attack not attempted",
                detail=(
                    "This is a production-grade RSA-2048 key. No publicly known "
                    "method factors it on any machine that currently exists. "
                    "This tool refuses to fabricate a break, and reports the "
                    "refusal rather than a fake success."
                ),
                artifacts={
                    "evidence": [
                        line for line in trace_lines if line.startswith("[FACTOR]")
                    ][:6]
                },
                reached=True,
                outcome="REFUSED",
            )
        ]

    # Stamp the overall verdict onto the final step — but never overwrite an
    # outcome a branch above set deliberately. The refusal above carries its own
    # more specific wording, and clobbering it with the generic status would
    # make a refusal read as an ordinary result.
    if steps and not steps[-1].outcome:
        steps[-1].outcome = result.get("status", "")

    return [step.to_dict() for step in steps]


def hybrid_defence_explanation() -> dict[str, Any]:
    """Explain what an attacker would face against the hybrid construction.

    Stated as a property of the construction rather than as a security
    guarantee: the session key is derived from both secrets, so recovering one
    leg is insufficient by design.
    """
    return {
        "construction": "HKDF-SHA256(x25519_shared_secret || mlkem768_shared_secret)",
        "legs": [
            {
                "name": "X25519 (classical)",
                "problem": "Elliptic-curve discrete logarithm",
                "quantum_status": "Solved in polynomial time by Shor's algorithm",
                "verdict": "Falls to a cryptographically relevant quantum computer",
            },
            {
                "name": "ML-KEM-768 (post-quantum)",
                "problem": "Module Learning With Errors",
                "quantum_status": "Shor's algorithm does not apply to lattice problems",
                "verdict": "Resists currently known classical and quantum attacks",
            },
        ],
        "consequence": (
            "Both shared secrets feed one KDF, so the derived key is only "
            "recoverable if BOTH establishments are defeated. This is a property "
            "of the construction, not a security proof of either component."
        ),
        "deployment_note": (
            "This mirrors X25519MLKEM768, the hybrid browsers and CDNs actually "
            "deployed for TLS 1.3 — chosen precisely so that a weakness "
            "discovered in either component does not immediately break the "
            "session."
        ),
    }
