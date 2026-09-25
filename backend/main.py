"""
AegisPQC — FastAPI service layer.

A thin, fully-typed REST surface over :mod:`backend.service`. Every endpoint is
a few lines: validate input with Pydantic, call the service, return the result.
No business logic lives here, which is why the Streamlit dashboard can bypass
this layer entirely and still behave identically.

Run it:

    uvicorn backend.main:app --reload --port 8000

Then open http://127.0.0.1:8000/docs for the interactive OpenAPI explorer.
That page is worth thirty seconds of your pitch — it demonstrates the system is
a real service with a typed contract, not a single-file script.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend import config
from backend import service as svc
from backend.service import ServiceError


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create the database schema on startup.

    Uses the modern lifespan protocol rather than the deprecated
    ``@app.on_event("startup")`` decorator, which emits a DeprecationWarning on
    current FastAPI and will be removed.
    """
    svc.ensure_ready()
    yield


app = FastAPI(
    title=config.API_TITLE,
    version=config.API_VERSION,
    lifespan=lifespan,
    description=(
        "Defends against Harvest Now, Decrypt Later attacks by replacing "
        "quantum-vulnerable key establishment with NIST FIPS 203 ML-KEM-768 "
        "and a hybrid X25519 + ML-KEM construction."
    ),
)

# Wide-open CORS. Correct for a local demo where the dashboard may be served
# from a different port; would be locked to an allowlist in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================================================
# Models
# ==========================================================================


class KeyGenRequest(BaseModel):
    """Request to generate a fresh key pair."""

    username: str = Field(..., min_length=1, examples=["Bob"])
    algorithm: str = Field(..., examples=[config.ALGO_ML_KEM_768])


class KeyGenResponse(BaseModel):
    """Key metadata. Private key material is never returned over the API."""

    key_id: str
    username: str
    algorithm: str
    public_key_bytes: int
    private_key_bytes: int
    public_key_preview: str


class SendRequest(BaseModel):
    """Request to encrypt and transmit a message."""

    sender: str = Field(default=svc.DEMO_SENDER, min_length=1)
    recipient: str = Field(default=svc.DEMO_RECIPIENT, min_length=1)
    algorithm: str = Field(..., examples=[config.ALGO_ML_KEM_768])
    message: str = Field(..., min_length=1)
    label: str = Field(default="", examples=["Q3 merger brief"])


class SendResponse(BaseModel):
    """The envelope that went on the wire, plus its harvested copy's id."""

    packet_id: str
    sender: str
    recipient: str
    label: str
    algorithm: str
    plaintext_bytes: int
    intercepted: bool
    kem_ciphertext: str
    nonce: str
    payload_ciphertext: str
    kem_ciphertext_bytes: int
    payload_ciphertext_bytes: int
    total_overhead_bytes: int


class ReceiveRequest(BaseModel):
    """Request to decrypt a packet as the legitimate recipient."""

    packet_id: str = Field(..., examples=["pkt_3f9a1c2b"])


class ReceiveResponse(BaseModel):
    """Recovered plaintext and decryption latency."""

    packet_id: str
    algorithm: str
    plaintext: str
    decrypt_ms: float


class AttackRequest(BaseModel):
    """Request to run a Q-Day attack against one harvested packet."""

    packet_id: str = Field(..., examples=["pkt_3f9a1c2b"])


class AttackResponse(BaseModel):
    """Attack outcome, including the full step-by-step trace."""

    packet_id: str
    algorithm: str
    status: str
    execution_time_ms: float
    log_trace: str
    recovered_plaintext: str | None


class BenchmarkRow(BaseModel):
    """One algorithm's measured key sizes and latencies."""

    algorithm: str
    quantum_safe: bool
    public_key_bytes: int
    private_key_bytes: int
    kem_ciphertext_bytes: int
    wire_overhead_bytes: int
    keygen_ms: float
    encapsulate_encrypt_ms: float
    decapsulate_decrypt_ms: float
    keygen_samples: int
    operation_samples: int


# ==========================================================================
# Meta
# ==========================================================================


@app.get("/api/health", tags=["meta"])
def health() -> dict[str, Any]:
    """Liveness probe plus the algorithm catalogue the UI populates from."""
    return {
        "status": "ACTIVE",
        "defense_level": "POST-QUANTUM SAFE",
        "version": config.API_VERSION,
        "algorithms": list(config.SUPPORTED_ALGORITHMS),
        "quantum_vulnerable": sorted(config.QUANTUM_VULNERABLE_ALGORITHMS),
        "demo_modulus_bits": config.RSA_DEMO_PRIME_BITS * 2,
    }


@app.post("/api/demo/reset", tags=["meta"])
def reset_demo() -> dict[str, Any]:
    """Wipe the database and rebuild the fixed demo scenario.

    Idempotent by design: running it twice produces an identical state, so you
    can reset between judges without the story changing.
    """
    return svc.reset_and_seed()


# ==========================================================================
# Keys
# ==========================================================================


@app.post("/api/keys/generate", response_model=KeyGenResponse, tags=["keys"])
def generate_keys(request: KeyGenRequest) -> dict[str, Any]:
    """Generate and store a key pair, replacing any existing one."""
    try:
        return svc.generate_keys(request.username, request.algorithm)
    except ServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/keys", tags=["keys"])
def list_keys() -> list[dict[str, Any]]:
    """List every stored key with its sizes. No private material is returned."""
    from backend import database as db

    return db.list_keys()


# ==========================================================================
# Vault
# ==========================================================================


@app.post("/api/vault/send", response_model=SendResponse, tags=["vault"])
def vault_send(request: SendRequest) -> dict[str, Any]:
    """Encrypt, transmit, and let the interceptor harvest a copy.

    Interception is unconditional. Every algorithm gets recorded, because that is
    what a passive network tap actually does.
    """
    try:
        return svc.send_message(
            sender=request.sender,
            recipient=request.recipient,
            algorithm=request.algorithm,
            message=request.message,
            label=request.label,
        )
    except ServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/vault/receive", response_model=ReceiveResponse, tags=["vault"])
def vault_receive(request: ReceiveRequest) -> dict[str, Any]:
    """Decrypt a packet as the legitimate recipient, using their private key."""
    try:
        return svc.receive_message(request.packet_id)
    except ServiceError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ==========================================================================
# Interceptor
# ==========================================================================


@app.get("/api/interceptor/hoarded-packets", tags=["interceptor"])
def hoarded_packets() -> list[dict[str, Any]]:
    """The adversary's complete archive, newest first."""
    return svc.list_harvested()


@app.get("/api/interceptor/stats", tags=["interceptor"])
def interceptor_stats() -> dict[str, Any]:
    """Headline figures: packets held, bytes at risk, how many have fallen."""
    return svc.harvest_stats()


# ==========================================================================
# Q-Day simulator
# ==========================================================================


@app.post("/api/simulator/q-day-attack", response_model=AttackResponse, tags=["simulator"])
def q_day_attack(request: AttackRequest) -> dict[str, Any]:
    """Run a Q-Day attack against one harvested packet.

    Against demo-scale RSA this performs a genuine factorization and returns the
    recovered plaintext. Against ML-KEM or hybrid it reports the real attack cost
    and returns IMMUNE. Against real RSA-2048 it refuses to fabricate a break.
    """
    result = svc.run_attack(request.packet_id)
    if result["status"] == "ERROR" and "No harvested packet" in result["log_trace"]:
        raise HTTPException(status_code=404, detail=result["log_trace"])
    return result


@app.post("/api/simulator/attack-all", tags=["simulator"])
def attack_all() -> list[dict[str, Any]]:
    """Run Q-Day against the entire archive, oldest packet first."""
    return svc.attack_all()


@app.get("/api/simulator/attack-history", tags=["simulator"])
def attack_history() -> list[dict[str, Any]]:
    """Every attack attempt recorded so far."""
    return svc.list_attack_history()


@app.get("/api/simulator/extrapolation", tags=["simulator"])
def extrapolation() -> dict[str, Any]:
    """Project the measured live break up to full-scale RSA-2048."""
    return svc.extrapolation()


# ==========================================================================
# Benchmarks
# ==========================================================================


@app.get("/api/benchmarks/run", response_model=list[BenchmarkRow], tags=["benchmarks"])
def run_benchmarks(iterations: int = config.BENCHMARK_ITERATIONS) -> list[dict[str, Any]]:
    """Measure key sizes and latencies across all algorithms.

    Args:
        iterations: Samples per operation. Lower it if you need a faster response
            during a live demo.
    """
    if iterations < 1 or iterations > 1000:
        raise HTTPException(status_code=400, detail="iterations must be between 1 and 1000")
    return svc.benchmarks(iterations)


# ==========================================================================
# PQC readiness scanner
# ==========================================================================


class ScanRequest(BaseModel):
    """Request to scan a directory or file on the local filesystem."""

    path: str = Field(..., min_length=1, examples=["C:/certs"])


@app.get("/api/scanner/demo-enterprise", tags=["scanner"])
def scan_demo_enterprise() -> dict[str, Any]:
    """Assess the built-in fictional enterprise.

    Generates the environment on first call — real keys and self-signed
    certificates written locally, with no network access — then scans it.

    This performs cryptographic INVENTORY only. No cryptanalysis is attempted
    against any scanned asset and no private key material is reported.
    """
    return svc.scan_demo_enterprise()


@app.post("/api/scanner/scan", tags=["scanner"])
def scan_path(request: ScanRequest) -> dict[str, Any]:
    """Assess a directory or single file supplied by the caller."""
    try:
        return svc.scan_path(request.path)
    except ServiceError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ==========================================================================
# Migration planning
# ==========================================================================


@app.get("/api/migration/plan", tags=["migration"])
def migration_plan() -> dict[str, Any]:
    """Build a prioritised PQC migration plan from the current assessment.

    Planning output only. AegisPQC does not modify, rotate, or reconfigure any
    real system, and does not predict when any algorithm will be broken.
    """
    return svc.migration_plan()


@app.get("/api/migration/verify", tags=["migration"])
def verify_migration_plan() -> dict[str, Any]:
    """Validate the migration plan's internal consistency.

    Checks the plan, not a migrated estate — nothing here modifies real
    infrastructure.
    """
    return svc.verify_migration_plan()


@app.get("/api/workflow", tags=["migration"])
def workflow() -> list[dict[str, Any]]:
    """The eight-stage cryptographic migration workflow backbone."""
    return svc.workflow()


# ==========================================================================
# Overview and reporting
# ==========================================================================


@app.get("/api/overview", tags=["overview"])
def overview() -> dict[str, Any]:
    """Executive summary across the estate, migration, and demonstration."""
    return svc.executive_summary()


@app.get("/api/interceptor/forensics/{packet_id}", tags=["interceptor"])
def packet_forensics(packet_id: str) -> dict[str, Any]:
    """Forensic detail for one harvested packet.

    Returns only what a passive tap could observe. No private key material.
    """
    try:
        return svc.packet_forensics(packet_id)
    except ServiceError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/report", tags=["overview"])
def report(include_benchmarks: bool = False) -> dict[str, Any]:
    """The full assessment report as structured JSON.

    Contains no private key material; generation raises rather than returning
    if any is detected.
    """
    return svc.full_report(include_benchmarks=include_benchmarks)
