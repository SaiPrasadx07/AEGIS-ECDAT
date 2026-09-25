"""
AegisPQC — SQLite persistence layer.

Four tables model the whole scenario:

    users              Who is sending and receiving.
    key_store          Each user's key pair, per algorithm.
    network_sniff_log  THE ADVERSARY'S HARVEST. Every envelope that ever
                       crossed the wire, stored forever.
    quantum_attack_log Results of Q-Day attacks against harvested packets.

The important table is ``network_sniff_log``. It exists to make one point
visceral: the adversary does not need to break anything today. They only need
to *store* things. Everything else in this project is downstream of that.

WAL MODE
--------
The database runs in Write-Ahead Logging mode so that the FastAPI backend can
write while the Streamlit dashboard reads, without either blocking the other.
In the default rollback-journal mode a single write would lock out every reader
and the demo dashboard would freeze at the worst possible moment.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from backend import config

# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id     TEXT PRIMARY KEY,
    username    TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS key_store (
    key_id      TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    algo        TEXT NOT NULL,
    public_key  BLOB NOT NULL,
    private_key BLOB NOT NULL,
    created_at  TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE,
    UNIQUE (user_id, algo)
);

CREATE TABLE IF NOT EXISTS network_sniff_log (
    packet_id          TEXT PRIMARY KEY,
    sender             TEXT NOT NULL,
    recipient          TEXT NOT NULL,
    algo_used          TEXT NOT NULL,
    label              TEXT NOT NULL DEFAULT '',
    kem_ciphertext     BLOB NOT NULL,
    nonce              BLOB NOT NULL,
    payload_ciphertext BLOB NOT NULL,
    aad                BLOB NOT NULL DEFAULT '',
    recipient_public   BLOB NOT NULL,
    plaintext_bytes    INTEGER NOT NULL DEFAULT 0,
    intercepted_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quantum_attack_log (
    attack_id         TEXT PRIMARY KEY,
    packet_id         TEXT NOT NULL,
    algo_target       TEXT NOT NULL,
    status            TEXT NOT NULL,
    execution_time_ms REAL NOT NULL,
    recovered_plaintext TEXT,
    log_trace         TEXT NOT NULL,
    attacked_at       TEXT NOT NULL,
    FOREIGN KEY (packet_id) REFERENCES network_sniff_log (packet_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sniff_algo    ON network_sniff_log (algo_used);
CREATE INDEX IF NOT EXISTS idx_attack_packet ON quantum_attack_log (packet_id);
"""


# --------------------------------------------------------------------------
# Connection management
# --------------------------------------------------------------------------


def _utc_now() -> str:
    """ISO-8601 UTC timestamp. Stored as TEXT because SQLite has no date type."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    """Short prefixed identifier, e.g. ``pkt_3f9a1c2b``.

    Readable IDs matter more than you would think during a live demo — a judge
    can follow ``pkt_3f9a1c2b`` from the harvest table to the attack log with
    their eyes. A bare UUID4 is unreadable on a projector.
    """
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def get_connection(db_path: Path | None = None) -> sqlite3.Connection:
    """Open a SQLite connection configured for concurrent read/write.

    Args:
        db_path: Override the database location. Defaults to ``config.DB_PATH``.

    Returns:
        A connection with WAL enabled, foreign keys enforced, and ``Row`` as the
        row factory so results behave like dictionaries.
    """
    path = db_path or config.DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10.0)
    conn.row_factory = sqlite3.Row

    # WAL lets readers and one writer proceed simultaneously.
    conn.execute("PRAGMA journal_mode=WAL")
    # NORMAL is the recommended companion to WAL: durable across app crashes,
    # only at risk on an OS-level crash. Correct trade-off for a demo app.
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: Path | None = None) -> None:
    """Create the schema if it does not already exist. Safe to call repeatedly."""
    conn = get_connection(db_path)
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def reset_db(db_path: Path | None = None) -> None:
    """Delete the database entirely and rebuild an empty schema.

    Called by the demo seeding script. Removes the ``-wal`` and ``-shm``
    sidecar files too — leaving them behind is a classic source of "why is my
    reset database still full of yesterday's packets" confusion.
    """
    path = db_path or config.DB_PATH
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(path) + suffix)
        if candidate.exists():
            candidate.unlink()
    init_db(db_path)


# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------


def create_user(username: str, db_path: Path | None = None) -> str:
    """Create a user, or return the existing user_id if the name is taken.

    Args:
        username: Display name, unique across the system.

    Returns:
        The user_id.
    """
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT user_id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row:
            return row["user_id"]

        user_id = new_id("usr")
        conn.execute(
            "INSERT INTO users (user_id, username, created_at) VALUES (?, ?, ?)",
            (user_id, username, _utc_now()),
        )
        conn.commit()
        return user_id
    finally:
        conn.close()


def list_users(db_path: Path | None = None) -> list[dict[str, Any]]:
    """Return every user, oldest first."""
    conn = get_connection(db_path)
    try:
        rows = conn.execute("SELECT * FROM users ORDER BY created_at").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Key store
# --------------------------------------------------------------------------


def store_keypair(
    user_id: str,
    algorithm: str,
    public_key: bytes,
    private_key: bytes,
    db_path: Path | None = None,
) -> str:
    """Persist a key pair, replacing any existing pair for that user+algorithm.

    Returns:
        The key_id.
    """
    conn = get_connection(db_path)
    try:
        key_id = new_id("key")
        conn.execute(
            """
            INSERT INTO key_store (key_id, user_id, algo, public_key, private_key, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (user_id, algo) DO UPDATE SET
                key_id      = excluded.key_id,
                public_key  = excluded.public_key,
                private_key = excluded.private_key,
                created_at  = excluded.created_at
            """,
            (key_id, user_id, algorithm, public_key, private_key, _utc_now()),
        )
        conn.commit()
        return key_id
    finally:
        conn.close()


def get_keypair(
    username: str, algorithm: str, db_path: Path | None = None
) -> dict[str, Any] | None:
    """Fetch a user's key pair for one algorithm, looked up by username.

    Returns:
        A dict with ``public_key`` / ``private_key`` as bytes, or ``None``.
    """
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            """
            SELECT k.* FROM key_store k
            JOIN users u ON u.user_id = k.user_id
            WHERE u.username = ? AND k.algo = ?
            """,
            (username, algorithm),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_keys(db_path: Path | None = None) -> list[dict[str, Any]]:
    """Return every stored key with its owner's username and byte sizes.

    Private key material is deliberately excluded — this feeds a UI table.
    """
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            """
            SELECT k.key_id, u.username, k.algo, k.created_at,
                   LENGTH(k.public_key)  AS public_key_bytes,
                   LENGTH(k.private_key) AS private_key_bytes
            FROM key_store k
            JOIN users u ON u.user_id = k.user_id
            ORDER BY u.username, k.algo
            """
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Network sniff log — the adversary's harvest
# --------------------------------------------------------------------------


def record_intercept(
    sender: str,
    recipient: str,
    algorithm: str,
    kem_ciphertext: bytes,
    nonce: bytes,
    payload_ciphertext: bytes,
    aad: bytes,
    recipient_public: bytes,
    plaintext_bytes: int,
    label: str = "",
    db_path: Path | None = None,
) -> str:
    """Store one intercepted envelope in the adversary's archive.

    Note carefully what this function stores and what it does not. It stores the
    ciphertext, the nonce, the KEM ciphertext, and the recipient's PUBLIC key —
    all of which a real network tap can genuinely observe. It never stores a
    private key or a plaintext.

    ``plaintext_bytes`` is recorded only so the UI can show how much data is at
    risk. The adversary would learn this anyway from the ciphertext length; GCM
    is a stream mode and does not hide message size.

    Returns:
        The packet_id.
    """
    conn = get_connection(db_path)
    try:
        packet_id = new_id("pkt")
        conn.execute(
            """
            INSERT INTO network_sniff_log (
                packet_id, sender, recipient, algo_used, label,
                kem_ciphertext, nonce, payload_ciphertext, aad,
                recipient_public, plaintext_bytes, intercepted_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                packet_id, sender, recipient, algorithm, label,
                kem_ciphertext, nonce, payload_ciphertext, aad,
                recipient_public, plaintext_bytes, _utc_now(),
            ),
        )
        conn.commit()
        return packet_id
    finally:
        conn.close()


def get_packet(packet_id: str, db_path: Path | None = None) -> dict[str, Any] | None:
    """Fetch one harvested packet in full, including its BLOBs."""
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM network_sniff_log WHERE packet_id = ?", (packet_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_packets(db_path: Path | None = None) -> list[dict[str, Any]]:
    """Return the harvest table for UI display, newest first.

    Includes each packet's latest attack status via a correlated subquery, so the
    adversary view can show at a glance which packets have already fallen.

    ORDERING IS DELIBERATE. ``intercepted_at`` has second resolution, so packets
    sent in the same second all tie. The original tiebreak was ``packet_id``,
    which is random hex — measured over 12 seeding runs it produced 6 different
    display orders, meaning the harvest table would visibly reshuffle between
    demo runs. Ordering by ``rowid`` (SQLite's monotonic insertion counter)
    makes the display order identical every time.
    """
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            """
            SELECT
                p.rowid AS seq,
                p.packet_id, p.sender, p.recipient, p.algo_used, p.label,
                p.plaintext_bytes, p.intercepted_at,
                LENGTH(p.kem_ciphertext)     AS kem_ciphertext_bytes,
                LENGTH(p.payload_ciphertext) AS payload_ciphertext_bytes,
                (SELECT a.status FROM quantum_attack_log a
                 WHERE a.packet_id = p.packet_id
                 ORDER BY a.attacked_at DESC, a.rowid DESC LIMIT 1) AS last_attack_status
            FROM network_sniff_log p
            ORDER BY p.rowid DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def harvest_summary(db_path: Path | None = None) -> dict[str, Any]:
    """Aggregate stats for the adversary dashboard header.

    Returns:
        Total packets, total bytes at risk, and a per-algorithm breakdown.
    """
    conn = get_connection(db_path)
    try:
        totals = conn.execute(
            """
            SELECT COUNT(*) AS packets,
                   COALESCE(SUM(plaintext_bytes), 0) AS bytes_at_risk
            FROM network_sniff_log
            """
        ).fetchone()
        by_algo = conn.execute(
            """
            SELECT algo_used, COUNT(*) AS packets
            FROM network_sniff_log
            GROUP BY algo_used
            ORDER BY packets DESC
            """
        ).fetchall()
        return {
            "total_packets": totals["packets"],
            "total_bytes_at_risk": totals["bytes_at_risk"],
            "by_algorithm": [dict(r) for r in by_algo],
        }
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Quantum attack log
# --------------------------------------------------------------------------


def record_attack(
    packet_id: str,
    algo_target: str,
    status: str,
    execution_time_ms: float,
    log_trace: str,
    recovered_plaintext: str | None = None,
    db_path: Path | None = None,
) -> str:
    """Persist the outcome of a Q-Day attack attempt.

    Returns:
        The attack_id.
    """
    conn = get_connection(db_path)
    try:
        attack_id = new_id("atk")
        conn.execute(
            """
            INSERT INTO quantum_attack_log (
                attack_id, packet_id, algo_target, status,
                execution_time_ms, recovered_plaintext, log_trace, attacked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attack_id, packet_id, algo_target, status,
                execution_time_ms, recovered_plaintext, log_trace, _utc_now(),
            ),
        )
        conn.commit()
        return attack_id
    finally:
        conn.close()


def list_attacks(db_path: Path | None = None) -> list[dict[str, Any]]:
    """Return every attack attempt, newest first."""
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM quantum_attack_log ORDER BY attacked_at DESC, attack_id DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
