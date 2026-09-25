"""
AegisPQC — automated test suite.

Every test here maps to a claim the project makes on stage. If a judge
challenges a claim, the corresponding test is the answer.

Run with:  pytest tests/ -v
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from backend import config
from backend import crypto_engine as ce
from backend import database as db
from backend import simulator as sim

ALL_ALGOS = (
    config.ALGO_RSA_DEMO,
    config.ALGO_RSA_2048,
    config.ALGO_ML_KEM_768,
    config.ALGO_HYBRID,
)

MESSAGE = b"MERGER BRIEF: acquisition of Northwind closes Q3. Do not forward."


@pytest.fixture()
def temp_db(tmp_path: Path) -> Path:
    """An isolated database per test, so tests never contaminate each other."""
    path = tmp_path / "test_aegis.db"
    db.reset_db(path)
    return path


# ==========================================================================
# Cryptographic correctness
# ==========================================================================


@pytest.mark.parametrize("algo", ALL_ALGOS)
def test_seal_unseal_roundtrip(algo: str) -> None:
    """Claim: every mode encrypts and decrypts correctly."""
    kp = ce.generate_keypair(algo)
    aad = f"Alice->Bob|{algo}".encode()
    env = ce.seal(algo, kp.public_key, MESSAGE, aad)
    assert ce.unseal(algo, kp.private_key, env, aad) == MESSAGE


@pytest.mark.parametrize("algo", ALL_ALGOS)
def test_wrong_private_key_is_rejected(algo: str) -> None:
    """Claim: only the intended recipient can open the envelope."""
    good = ce.generate_keypair(algo)
    bad = ce.generate_keypair(algo)
    env = ce.seal(algo, good.public_key, MESSAGE)
    with pytest.raises(ce.CryptoError):
        ce.unseal(algo, bad.private_key, env)


@pytest.mark.parametrize("algo", ALL_ALGOS)
def test_tampered_aad_is_rejected(algo: str) -> None:
    """Claim: metadata is cryptographically bound to the payload.

    An attacker cannot take a valid ciphertext and relabel who it was for.
    """
    kp = ce.generate_keypair(algo)
    env = ce.seal(algo, kp.public_key, MESSAGE, b"Alice->Bob")
    with pytest.raises(ce.CryptoError):
        ce.unseal(algo, kp.private_key, env, b"Alice->Eve")


@pytest.mark.parametrize("algo", ALL_ALGOS)
def test_tampered_ciphertext_is_rejected(algo: str) -> None:
    """Claim: AES-GCM detects any modification of the payload in transit."""
    kp = ce.generate_keypair(algo)
    env = ce.seal(algo, kp.public_key, MESSAGE)
    corrupted = bytearray(env.payload_ciphertext)
    corrupted[0] ^= 0x01
    broken = ce.SealedEnvelope(
        algorithm=env.algorithm,
        kem_ciphertext=env.kem_ciphertext,
        nonce=env.nonce,
        payload_ciphertext=bytes(corrupted),
    )
    with pytest.raises(ce.CryptoError):
        ce.unseal(algo, kp.private_key, broken)


def test_nonces_are_never_reused() -> None:
    """Claim: every message gets a fresh nonce.

    GCM nonce reuse under the same key is catastrophic — it leaks the XOR of the
    plaintexts and can expose the authentication subkey. This test would catch a
    regression that switched to a counter or a fixed nonce.
    """
    kp = ce.generate_keypair(config.ALGO_ML_KEM_768)
    nonces = {
        ce.seal(config.ALGO_ML_KEM_768, kp.public_key, MESSAGE).nonce
        for _ in range(200)
    }
    assert len(nonces) == 200


def test_mlkem_sizes_match_fips203() -> None:
    """Claim: our ML-KEM-768 matches the sizes fixed by the FIPS 203 standard.

    These numbers are not implementation-dependent. Any conforming ML-KEM-768
    produces a 1184-byte encapsulation key and a 1088-byte ciphertext. If this
    test fails, we are not running real ML-KEM-768.
    """
    kp = ce.generate_keypair(config.ALGO_ML_KEM_768)
    env = ce.seal(config.ALGO_ML_KEM_768, kp.public_key, MESSAGE)
    assert kp.public_key_bytes == 1184
    assert len(env.kem_ciphertext) == 1088


def test_hybrid_requires_both_legs() -> None:
    """Claim: breaking one half of the hybrid is not enough.

    We simulate an attacker who has fully broken X25519 (they hold the private
    X25519 key) but not ML-KEM. Feeding a hybrid private key with the ML-KEM half
    replaced by a different key must fail.
    """
    import struct

    victim = ce.generate_keypair(config.ALGO_HYBRID)
    other = ce.generate_keypair(config.ALGO_HYBRID)
    env = ce.seal(config.ALGO_HYBRID, victim.public_key, MESSAGE)

    (x_len,) = struct.unpack_from(">H", victim.private_key, 0)
    victim_x = victim.private_key[2 : 2 + x_len]
    other_mlkem = other.private_key[2 + x_len :]

    # Correct X25519 half, wrong ML-KEM half.
    frankenstein = struct.pack(">H", x_len) + victim_x + other_mlkem
    with pytest.raises(ce.CryptoError):
        ce.unseal(config.ALGO_HYBRID, frankenstein, env)


def test_hkdf_domain_separation() -> None:
    """Claim: the same secret produces different keys in different contexts."""
    secret = b"\x42" * 32
    assert ce.derive_aes_key(secret, config.HKDF_INFO_KEM) != ce.derive_aes_key(
        secret, config.HKDF_INFO_HYBRID
    )


# ==========================================================================
# Persistence
# ==========================================================================


def test_database_wal_mode_enabled(temp_db: Path) -> None:
    """Claim: readers and writers do not block each other during the demo."""
    conn = db.get_connection(temp_db)
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"
    finally:
        conn.close()


def test_keypair_survives_database_roundtrip(temp_db: Path) -> None:
    """Claim: keys stored as SQLite BLOBs still work after being read back.

    This is the test that would have caught a serialization bug silently
    corrupting keys — the kind that only surfaces on stage.
    """
    bob = db.create_user("Bob", temp_db)
    for algo in ALL_ALGOS:
        kp = ce.generate_keypair(algo)
        db.store_keypair(bob, algo, kp.public_key, kp.private_key, temp_db)
        loaded = db.get_keypair("Bob", algo, temp_db)
        assert loaded is not None
        env = ce.seal(algo, loaded["public_key"], MESSAGE)
        assert ce.unseal(algo, loaded["private_key"], env) == MESSAGE


def test_interceptor_captures_every_algorithm(temp_db: Path) -> None:
    """Claim: the adversary harvests ALL traffic, not just the vulnerable kind.

    This is the point of the whole project. Choosing ML-KEM does not stop you
    being recorded; it stops the recording being useful.
    """
    db.create_user("Alice", temp_db)
    bob = db.create_user("Bob", temp_db)
    for algo in (config.ALGO_RSA_DEMO, config.ALGO_ML_KEM_768, config.ALGO_HYBRID):
        kp = ce.generate_keypair(algo)
        db.store_keypair(bob, algo, kp.public_key, kp.private_key, temp_db)
        aad = f"Alice->Bob|{algo}".encode()
        env = ce.seal(algo, kp.public_key, MESSAGE, aad)
        sim.intercept(
            "Alice", "Bob", algo, env, aad, kp.public_key, len(MESSAGE),
            "test", temp_db,
        )

    summary = db.harvest_summary(temp_db)
    assert summary["total_packets"] == 3
    assert len(summary["by_algorithm"]) == 3


def test_interceptor_never_stores_private_keys(temp_db: Path) -> None:
    """Claim: the harvest log contains only what a real network tap can see.

    Scans every BLOB in network_sniff_log for the recipient's private key bytes.
    If a private key ever leaked into the adversary's table, the entire demo
    would be dishonest — and this test would fail.
    """
    db.create_user("Alice", temp_db)
    bob = db.create_user("Bob", temp_db)
    kp = ce.generate_keypair(config.ALGO_ML_KEM_768)
    db.store_keypair(bob, config.ALGO_ML_KEM_768, kp.public_key, kp.private_key, temp_db)
    env = ce.seal(config.ALGO_ML_KEM_768, kp.public_key, MESSAGE, b"aad")
    pid = sim.intercept(
        "Alice", "Bob", config.ALGO_ML_KEM_768, env, b"aad",
        kp.public_key, len(MESSAGE), "test", temp_db,
    )

    packet = db.get_packet(pid, temp_db)
    assert packet is not None
    for column, value in packet.items():
        if isinstance(value, bytes):
            assert kp.private_key not in value, f"private key leaked into {column}"


# ==========================================================================
# The Q-Day attack — the claims a judge will actually probe
# ==========================================================================


def test_qday_genuinely_breaks_demo_rsa(temp_db: Path) -> None:
    """Claim: the RSA break is REAL, not a database lookup.

    Verifies the recovered plaintext matches exactly. The attack path reads only
    the public modulus from the harvested packet; see the companion test below
    which proves the private key is never consulted.
    """
    db.create_user("Alice", temp_db)
    bob = db.create_user("Bob", temp_db)
    kp = ce.generate_keypair(config.ALGO_RSA_DEMO)
    db.store_keypair(bob, config.ALGO_RSA_DEMO, kp.public_key, kp.private_key, temp_db)
    aad = b"Alice->Bob|RSA-DEMO"
    env = ce.seal(config.ALGO_RSA_DEMO, kp.public_key, MESSAGE, aad)
    pid = sim.intercept(
        "Alice", "Bob", config.ALGO_RSA_DEMO, env, aad,
        kp.public_key, len(MESSAGE), "merger brief", temp_db,
    )

    result = sim.execute_q_day_attack(pid, db_path=temp_db)
    assert result["status"] == sim.STATUS_BREACHED
    assert result["recovered_plaintext"] == MESSAGE.decode()


def test_qday_attack_only_uses_public_data(temp_db: Path) -> None:
    """Claim: the attacker never touches the key_store table.

    We delete every stored key BEFORE running the attack. If the attack still
    succeeds, it demonstrably worked from the harvested packet alone. This is the
    test to run live if a judge accuses you of faking the break.
    """
    db.create_user("Alice", temp_db)
    bob = db.create_user("Bob", temp_db)
    kp = ce.generate_keypair(config.ALGO_RSA_DEMO)
    db.store_keypair(bob, config.ALGO_RSA_DEMO, kp.public_key, kp.private_key, temp_db)
    env = ce.seal(config.ALGO_RSA_DEMO, kp.public_key, MESSAGE, b"aad")
    pid = sim.intercept(
        "Alice", "Bob", config.ALGO_RSA_DEMO, env, b"aad",
        kp.public_key, len(MESSAGE), "test", temp_db,
    )

    # Scorched earth: no private key material remains anywhere in the database.
    conn = db.get_connection(temp_db)
    try:
        conn.execute("DELETE FROM key_store")
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM key_store").fetchone()[0] == 0
    finally:
        conn.close()

    result = sim.execute_q_day_attack(pid, db_path=temp_db)
    assert result["status"] == sim.STATUS_BREACHED
    assert result["recovered_plaintext"] == MESSAGE.decode()


@pytest.mark.parametrize("algo", [config.ALGO_ML_KEM_768, config.ALGO_HYBRID])
def test_qday_cannot_break_lattice_modes(temp_db: Path, algo: str) -> None:
    """Claim: ML-KEM and hybrid survive the attack, and leak no plaintext."""
    db.create_user("Alice", temp_db)
    bob = db.create_user("Bob", temp_db)
    kp = ce.generate_keypair(algo)
    db.store_keypair(bob, algo, kp.public_key, kp.private_key, temp_db)
    env = ce.seal(algo, kp.public_key, MESSAGE, b"aad")
    pid = sim.intercept(
        "Alice", "Bob", algo, env, b"aad", kp.public_key, len(MESSAGE), "test", temp_db,
    )

    result = sim.execute_q_day_attack(pid, db_path=temp_db)
    assert result["status"] == sim.STATUS_IMMUNE
    assert result["recovered_plaintext"] is None
    assert MESSAGE.decode() not in result["log_trace"]


def test_qday_refuses_to_fake_rsa2048(temp_db: Path) -> None:
    """Claim: we never pretend to break a key we cannot break.

    Real RSA-2048 must come back IMMUNE, not BREACHED. A project that reports
    BREACHED here is lying, and this test is what stops us shipping that.
    """
    db.create_user("Alice", temp_db)
    bob = db.create_user("Bob", temp_db)
    kp = ce.generate_keypair(config.ALGO_RSA_2048)
    db.store_keypair(bob, config.ALGO_RSA_2048, kp.public_key, kp.private_key, temp_db)
    env = ce.seal(config.ALGO_RSA_2048, kp.public_key, MESSAGE, b"aad")
    pid = sim.intercept(
        "Alice", "Bob", config.ALGO_RSA_2048, env, b"aad",
        kp.public_key, len(MESSAGE), "test", temp_db,
    )

    result = sim.execute_q_day_attack(pid, db_path=temp_db)
    assert result["status"] == sim.STATUS_IMMUNE
    assert result["recovered_plaintext"] is None


def test_brent_rho_finds_true_factors() -> None:
    """Claim: the factoring routine is correct, not just fast."""
    import time as _time

    for _ in range(5):
        n, _e, _d, p, q = ce._generate_demo_rsa(config.RSA_DEMO_PRIME_BITS)
        factor = sim.brent_rho(n, _time.monotonic() + 60)
        assert factor is not None
        assert factor in (p, q)
        assert n % factor == 0


def test_demo_factoring_stays_within_pitch_budget() -> None:
    """Claim: the live break finishes fast enough for a 3-minute pitch.

    Guards against someone raising RSA_DEMO_PRIME_BITS and silently turning a
    2-second demo into a 40-second one.
    """
    import time as _time

    n, _e, _d, _p, _q = ce._generate_demo_rsa(config.RSA_DEMO_PRIME_BITS)
    start = _time.perf_counter()
    assert sim.brent_rho(n, _time.monotonic() + 30) is not None
    assert _time.perf_counter() - start < 15.0


# ==========================================================================
# Benchmarks
# ==========================================================================


def test_benchmarks_return_all_algorithms() -> None:
    """Claim: the benchmark tab has real measured data behind it."""
    results = ce.run_benchmarks(iterations=5)
    assert {r["algorithm"] for r in results} == {
        config.ALGO_RSA_2048,
        config.ALGO_ML_KEM_768,
        config.ALGO_HYBRID,
    }
    for r in results:
        assert r["keygen_ms"] > 0
        assert r["public_key_bytes"] > 0


def test_mlkem_keygen_beats_rsa2048() -> None:
    """Claim: ML-KEM key generation is orders of magnitude faster than RSA-2048.

    This is the most counter-intuitive result in the project. People assume
    post-quantum means slow. For key generation it is dramatically the opposite.
    """
    results = {r["algorithm"]: r for r in ce.run_benchmarks(iterations=5)}
    assert (
        results[config.ALGO_ML_KEM_768]["keygen_ms"]
        < results[config.ALGO_RSA_2048]["keygen_ms"]
    )


def test_mlkem_costs_more_on_the_wire() -> None:
    """Claim: the honest trade-off is bandwidth, not speed.

    ML-KEM wins on latency and loses on bytes. A demo that only shows the
    favourable half is marketing, not engineering.
    """
    results = {r["algorithm"]: r for r in ce.run_benchmarks(iterations=5)}
    assert (
        results[config.ALGO_ML_KEM_768]["wire_overhead_bytes"]
        > results[config.ALGO_RSA_2048]["wire_overhead_bytes"]
    )


def test_extrapolation_is_astronomically_large() -> None:
    """Claim: the extrapolation panel produces a defensible number."""
    out = sim.extrapolate_to_full_scale(demo_factor_ms=1800.0)
    assert out["target_modulus_bits"] == 2048
    assert out["classical_years_log10"] > 100
    assert out["shor_logical_qubits"] == config.SHOR_LOGICAL_QUBITS_RSA2048
