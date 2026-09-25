"""
AegisPQC — Phase 2 test suite: service layer, REST API, and dashboard.

Phase 1 (`test_suite.py`) proves the cryptography is correct. This file proves
the two surfaces built on top of it work, and — critically — that the demo is
deterministic enough to rehearse against.

Run with:  pytest tests/ -v
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend import config
from backend import crypto_engine as ce
from backend import database as db
from backend import service as svc
from backend import simulator as sim

APP_FILE = str(Path(__file__).resolve().parent.parent / "frontend" / "app.py")


@pytest.fixture()
def temp_db(tmp_path: Path) -> Path:
    """An isolated database per test."""
    path = tmp_path / "phase2.db"
    db.reset_db(path)
    return path


# ==========================================================================
# Determinism — the requirement that drove the one Phase 1 change
# ==========================================================================


def test_harvest_ordering_is_deterministic(tmp_path: Path) -> None:
    """Claim: the harvest table shows the same order on every demo run.

    This test exists because of a real bug. ``intercepted_at`` has second
    resolution, so packets seeded in the same second all tie, and the original
    tiebreak was ``packet_id`` — random hex. Measured over 12 seeding runs that
    produced SIX different display orders, meaning the adversary table would
    visibly reshuffle between demos.

    Ordering by SQLite's monotonic ``rowid`` fixes it. This test would catch any
    regression that reintroduced a random tiebreak.
    """
    orderings = set()
    for run in range(8):
        path = tmp_path / f"det{run}.db"
        svc.reset_and_seed(path)
        orderings.add(tuple(p["algo_used"] for p in svc.list_harvested(path)))
    assert len(orderings) == 1, f"harvest order was unstable: {orderings}"


def test_seed_scenario_is_fixed(temp_db: Path) -> None:
    """Claim: the demo scenario never varies. Same messages, same order."""
    first = svc.reset_and_seed(temp_db)
    second = svc.reset_and_seed(temp_db)

    assert [p["algorithm"] for p in first["packets"]] == [
        p["algorithm"] for p in second["packets"]
    ]
    assert [p["label"] for p in first["packets"]] == [
        p["label"] for p in second["packets"]
    ]
    assert [p["plaintext_bytes"] for p in first["packets"]] == [
        p["plaintext_bytes"] for p in second["packets"]
    ]


def test_attack_outcomes_are_deterministic(temp_db: Path) -> None:
    """Claim: the attack VERDICT is identical every run.

    Only the wall-clock duration varies, because Pollard's rho is randomised.
    The outcome — which packets fall and which hold — never does.
    """
    for _ in range(3):
        svc.reset_and_seed(temp_db)
        outcomes = {r["algorithm"]: r["status"] for r in svc.attack_all(temp_db)}
        assert outcomes[config.ALGO_RSA_DEMO] == sim.STATUS_BREACHED
        assert outcomes[config.ALGO_ML_KEM_768] == sim.STATUS_IMMUNE
        assert outcomes[config.ALGO_HYBRID] == sim.STATUS_IMMUNE


def test_attack_all_runs_oldest_first(temp_db: Path) -> None:
    """Claim: the narrative order holds — RSA falls first, then the safe modes."""
    svc.reset_and_seed(temp_db)
    results = svc.attack_all(temp_db)
    assert [r["algorithm"] for r in results] == [
        algo for algo, _label, _msg in svc.DEMO_TRAFFIC
    ]


# ==========================================================================
# Service layer
# ==========================================================================


def test_seed_creates_expected_state(temp_db: Path) -> None:
    """Claim: one reset call produces a fully populated, presentable demo."""
    result = svc.reset_and_seed(temp_db)
    assert len(result["packets"]) == 3
    assert len(result["keys"]) == 3

    stats = svc.harvest_stats(temp_db)
    assert stats["total_packets"] == 3
    assert stats["vulnerable_packets"] == 1
    assert stats["quantum_safe_packets"] == 2
    assert stats["already_breached"] == 0


def test_send_always_intercepts(temp_db: Path) -> None:
    """Claim: post-quantum traffic is harvested too.

    This is the thesis of the entire project. Encryption does not stop you being
    recorded; it decides what the recording is worth.
    """
    for algorithm in config.SUPPORTED_ALGORITHMS:
        result = svc.send_message(
            "Alice", "Bob", algorithm, "test payload", "t", temp_db
        )
        assert result["intercepted"] is True
        assert db.get_packet(result["packet_id"], temp_db) is not None


def test_receive_recovers_exact_plaintext(temp_db: Path) -> None:
    """Claim: the legitimate recipient reads the message; the system works."""
    message = "Board vote is unanimous.\nDo not forward."
    for algorithm in config.SUPPORTED_ALGORITHMS:
        sent = svc.send_message("Alice", "Bob", algorithm, message, "t", temp_db)
        received = svc.receive_message(sent["packet_id"], temp_db)
        assert received["plaintext"] == message
        assert received["decrypt_ms"] >= 0


def test_send_rejects_unknown_algorithm(temp_db: Path) -> None:
    """Claim: bad input fails loudly rather than silently degrading."""
    with pytest.raises(svc.ServiceError):
        svc.send_message("Alice", "Bob", "ROT13", "hello", "t", temp_db)


def test_send_rejects_empty_message(temp_db: Path) -> None:
    """Claim: an empty send is an error, not a zero-byte packet."""
    with pytest.raises(svc.ServiceError):
        svc.send_message("Alice", "Bob", config.ALGO_ML_KEM_768, "", "t", temp_db)


def test_ensure_keys_is_idempotent(temp_db: Path) -> None:
    """Claim: repeated sends reuse one key pair instead of churning new ones."""
    first = svc.ensure_keys_for("Bob", config.ALGO_ML_KEM_768, temp_db)
    second = svc.ensure_keys_for("Bob", config.ALGO_ML_KEM_768, temp_db)
    assert first["key_id"] == second["key_id"]
    assert first["public_key"] == second["public_key"]


def test_service_never_returns_private_keys(temp_db: Path) -> None:
    """Claim: no service response carries private key material.

    Scans every string value returned by the send and keygen paths for the hex
    of the stored private key.
    """
    meta = svc.generate_keys("Bob", config.ALGO_ML_KEM_768, temp_db)
    stored = db.get_keypair("Bob", config.ALGO_ML_KEM_768, temp_db)
    assert stored is not None
    private_hex = stored["private_key"].hex()

    sent = svc.send_message(
        "Alice", "Bob", config.ALGO_ML_KEM_768, "secret", "t", temp_db
    )
    for payload in (meta, sent):
        for value in payload.values():
            if isinstance(value, str):
                assert private_hex not in value


def test_unattacked_packet_shows_no_status(temp_db: Path) -> None:
    """Claim: the harvest table distinguishes attacked from unattacked packets."""
    svc.reset_and_seed(temp_db)
    assert all(p["last_attack_status"] is None for p in svc.list_harvested(temp_db))

    target = sorted(svc.list_harvested(temp_db), key=lambda p: p["seq"])[0]
    svc.run_attack(target["packet_id"], temp_db)

    updated = {p["packet_id"]: p for p in svc.list_harvested(temp_db)}
    assert updated[target["packet_id"]]["last_attack_status"] == sim.STATUS_BREACHED


def test_progress_callback_streams_lines(temp_db: Path) -> None:
    """Claim: the UI can stream the attack trace live rather than blocking."""
    svc.reset_and_seed(temp_db)
    target = sorted(svc.list_harvested(temp_db), key=lambda p: p["seq"])[0]

    streamed: list[str] = []
    result = svc.run_attack(target["packet_id"], temp_db, progress=streamed.append)

    assert len(streamed) > 10
    assert "\n".join(streamed) == result["log_trace"]


# ==========================================================================
# FastAPI layer
# ==========================================================================


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A TestClient bound to an isolated database.

    The API uses the module-level default database path, so we redirect
    ``config.DB_PATH`` for the duration of the test.
    """
    from fastapi.testclient import TestClient

    monkeypatch.setattr(config, "DB_PATH", tmp_path / "api.db")
    from backend.main import app

    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client) -> None:
    """Claim: the service reports liveness and its algorithm catalogue."""
    body = client.get("/api/health").json()
    assert body["status"] == "ACTIVE"
    assert set(body["algorithms"]) == set(config.SUPPORTED_ALGORITHMS)
    assert body["demo_modulus_bits"] == config.RSA_DEMO_PRIME_BITS * 2


def test_reset_endpoint_seeds_three_packets(client) -> None:
    """Claim: one API call produces a presentable demo."""
    body = client.post("/api/demo/reset").json()
    assert len(body["packets"]) == 3
    assert len(client.get("/api/interceptor/hoarded-packets").json()) == 3


def test_full_api_flow(client) -> None:
    """Claim: send, harvest, receive, and attack all work over HTTP.

    This is the end-to-end contract test for the REST surface.
    """
    client.post("/api/demo/reset")

    sent = client.post(
        "/api/vault/send",
        json={
            "sender": "Alice",
            "recipient": "Bob",
            "algorithm": config.ALGO_ML_KEM_768,
            "message": "quantum safe payload",
            "label": "api test",
        },
    ).json()
    assert sent["intercepted"] is True
    assert sent["kem_ciphertext_bytes"] == 1088

    received = client.post(
        "/api/vault/receive", json={"packet_id": sent["packet_id"]}
    ).json()
    assert received["plaintext"] == "quantum safe payload"

    attacked = client.post(
        "/api/simulator/q-day-attack", json={"packet_id": sent["packet_id"]}
    ).json()
    assert attacked["status"] == sim.STATUS_IMMUNE
    assert attacked["recovered_plaintext"] is None


def test_api_breaks_demo_rsa_and_returns_plaintext(client) -> None:
    """Claim: the real break works over HTTP, not just in-process."""
    client.post("/api/demo/reset")
    packets = client.get("/api/interceptor/hoarded-packets").json()
    rsa = [p for p in packets if p["algo_used"] == config.ALGO_RSA_DEMO][0]

    body = client.post(
        "/api/simulator/q-day-attack", json={"packet_id": rsa["packet_id"]}
    ).json()
    assert body["status"] == sim.STATUS_BREACHED
    assert "MERGER BRIEF" in body["recovered_plaintext"]


def test_api_rejects_bad_input(client) -> None:
    """Claim: invalid requests get 4xx, not 500."""
    assert (
        client.post(
            "/api/vault/send",
            json={"algorithm": "ROT13", "message": "hi"},
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/vault/receive", json={"packet_id": "pkt_doesnotexist"}
        ).status_code
        == 404
    )
    assert client.get("/api/benchmarks/run?iterations=0").status_code == 400
    assert client.post("/api/vault/send", json={"message": "hi"}).status_code == 422


def test_api_benchmarks(client) -> None:
    """Claim: the benchmark endpoint returns measured data for every algorithm."""
    rows = client.get("/api/benchmarks/run?iterations=3").json()
    assert {r["algorithm"] for r in rows} == {
        config.ALGO_RSA_2048,
        config.ALGO_ML_KEM_768,
        config.ALGO_HYBRID,
    }


def test_openapi_schema_generates(client) -> None:
    """Claim: /docs works. A typed contract is part of the architecture story."""
    schema = client.get("/openapi.json").json()
    assert "/api/vault/send" in schema["paths"]
    assert "/api/simulator/q-day-attack" in schema["paths"]


# ==========================================================================
# Streamlit dashboard
# ==========================================================================


def _app_test(timeout: int = 180):
    """Build an AppTest harness for the dashboard, skipping if unavailable."""
    pytest.importorskip("streamlit.testing.v1")
    from streamlit.testing.v1 import AppTest

    return AppTest.from_file(APP_FILE, default_timeout=timeout)


def test_dashboard_renders_without_exceptions() -> None:
    """Claim: the dashboard loads clean.

    AppTest executes the actual script body, so this catches real runtime
    errors — not just import errors.

    Asserts tab LABELS rather than a bare count. The original version checked
    ``len(at.tabs) == 4``, which broke when Phase 3 added the scanner tab and
    told us nothing about whether the right tabs existed. Checking labels is
    strictly stronger: it fails if a tab is added, removed, renamed, or
    reordered.
    """
    at = _app_test()
    at.run()
    assert not at.exception, [str(e.value) for e in at.exception]

    assert [tab.label for tab in at.tabs] == [
        "Overview",
        "PQC Readiness",
        "Migration Plan",
        "Quantum Vault",
        "HNDL Hoard",
        "Q-Day Simulator",
        "Benchmarks",
    ]


def test_dashboard_exposes_demo_controls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Claim: every button the pitch depends on is present, even on a fresh install.

    This test caught a real demo bug. Against an EMPTY database the Q-Day tab
    rendered "Archive is empty" and the attack button did not exist at all —
    so opening the dashboard on a fresh checkout produced dead tabs. The app now
    seeds itself on first load if the archive is empty.

    The monkeypatch points the app at a brand-new database file, which is what
    makes this a clean-state test rather than one that happens to pass because a
    previous test left data behind.
    """
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "fresh.db")
    at = _app_test()
    at.run()
    assert not at.exception, [str(e.value) for e in at.exception]

    labels = {b.label for b in at.button}
    assert {
        "LOAD PRESENTATION DEMO",
        "ENCRYPT AND SEND",
        "EXECUTE Q-DAY ATTACK",
        "RUN BENCHMARKS",
    } <= labels, f"missing controls on a fresh database: {labels}"


def test_dashboard_send_button_works() -> None:
    """Claim: clicking send encrypts, harvests, and renders the envelope."""
    at = _app_test()
    at.run()
    [b for b in at.button if b.label == "ENCRYPT AND SEND"][0].click().run()
    assert not at.exception, [str(e.value) for e in at.exception]
    assert len(at.success) >= 1


def test_dashboard_qday_button_breaks_rsa() -> None:
    """Claim: the Q-Day button performs the real break and shows the plaintext.

    The slowest test in the suite — it runs an actual factorization through the
    UI layer. It is worth the seconds: this is the exact code path a judge
    watches, and a passing unit test on the simulator would not catch a UI-layer
    regression here.
    """
    at = _app_test(timeout=240)
    at.run()
    [b for b in at.button if b.label == "EXECUTE Q-DAY ATTACK"][0].click().run()

    assert not at.exception, [str(e.value) for e in at.exception]
    rendered = "\n".join(c.value for c in at.code)
    assert "BREACHED" in rendered
    assert "MERGER BRIEF" in rendered


def test_dashboard_benchmarks_button_works() -> None:
    """Claim: the benchmark tab populates its charts and table."""
    at = _app_test()
    at.run()
    [b for b in at.button if b.label == "RUN BENCHMARKS"][0].click().run()
    assert not at.exception, [str(e.value) for e in at.exception]
    assert len(at.dataframe) >= 1
