"""
AegisPQC — cryptographic core.

This module implements four key-establishment modes behind one uniform interface.
Every mode produces the same output shape (a `SealedEnvelope`), which is what
lets the vault, the database, the interceptor, and the UI stay algorithm-agnostic.

    generate_keypair(algo)              -> KeyPair
    seal(algo, public_key, plaintext)   -> SealedEnvelope
    unseal(algo, private_key, envelope) -> plaintext

THE SHARED DESIGN
-----------------
All four modes follow the identical three-step pattern:

    1. ESTABLISH a shared secret using asymmetric cryptography (this is the part
       quantum computers threaten).
    2. DERIVE a 256-bit AES key from that shared secret using HKDF-SHA256.
    3. ENCRYPT the payload with AES-256-GCM (this part is quantum-resistant
       already; Grover's algorithm only halves the effective key length, so
       AES-256 retains ~128 bits of post-quantum security).

Holding steps 2 and 3 constant across all modes is deliberate. It means the only
variable in the entire comparison is *how the key was established* — which is
exactly the thing the post-quantum transition is about. Nobody is replacing AES.

WHY A KEM AND NOT "ENCRYPT WITH THE PUBLIC KEY"
-----------------------------------------------
ML-KEM is a Key Encapsulation Mechanism, not a general-purpose encryption scheme.
You cannot hand it a message. You call `encapsulate()` and it hands you back a
random shared secret plus a ciphertext that lets the holder of the private key
recover that same secret. The message is then encrypted symmetrically.

RSA is usually taught the other way around ("encrypt the message with the public
key"), but in practice RSA is also used in KEM form. This module deliberately
uses RSA in KEM form too, so that all four modes are structurally identical and
the comparison is apples-to-apples.
"""

from __future__ import annotations

import math
import os
import random
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from backend import config


# ==========================================================================
# Data structures
# ==========================================================================


@dataclass(frozen=True, slots=True)
class KeyPair:
    """A serialized asymmetric key pair, ready to be written to SQLite as BLOBs.

    Attributes:
        algorithm: One of the ``ALGO_*`` constants from :mod:`backend.config`.
        public_key: Serialized public/encapsulation key.
        private_key: Serialized private/decapsulation key.
        public_key_bytes: Length of ``public_key``, cached for benchmark charts.
        private_key_bytes: Length of ``private_key``, cached for benchmark charts.
    """

    algorithm: str
    public_key: bytes
    private_key: bytes
    public_key_bytes: int = field(init=False)
    private_key_bytes: int = field(init=False)

    def __post_init__(self) -> None:
        # frozen=True blocks normal assignment, so we go through object.__setattr__.
        object.__setattr__(self, "public_key_bytes", len(self.public_key))
        object.__setattr__(self, "private_key_bytes", len(self.private_key))


@dataclass(frozen=True, slots=True)
class SealedEnvelope:
    """The wire format. This is exactly what an adversary captures off the fibre.

    Note what is and is not in here. There is no private key, no shared secret,
    and no plaintext. An adversary who captures this envelope holds:

      - ``kem_ciphertext``: the encapsulated key material
      - ``nonce``: the AES-GCM nonce (public by design, not a secret)
      - ``payload_ciphertext``: the encrypted message plus its 16-byte GCM tag

    To read the message they must recover the shared secret from
    ``kem_ciphertext``, which requires breaking the asymmetric algorithm. That
    is the single point the entire post-quantum argument turns on.
    """

    algorithm: str
    kem_ciphertext: bytes
    nonce: bytes
    payload_ciphertext: bytes

    @property
    def total_overhead_bytes(self) -> int:
        """Bytes on the wire beyond the plaintext itself.

        This is the real cost of post-quantum cryptography. ML-KEM's security
        is fine; its ciphertext is 1088 bytes where X25519 moves 32. For a
        1 MB file that is irrelevant. For a TLS handshake at scale it is the
        entire engineering conversation.
        """
        return (
            len(self.kem_ciphertext)
            + len(self.nonce)
            + config.AES_TAG_BYTES
        )

    def to_dict(self) -> dict[str, Any]:
        """Hex-encoded view, for JSON APIs and UI display."""
        return {
            "algorithm": self.algorithm,
            "kem_ciphertext": self.kem_ciphertext.hex(),
            "nonce": self.nonce.hex(),
            "payload_ciphertext": self.payload_ciphertext.hex(),
            "kem_ciphertext_bytes": len(self.kem_ciphertext),
            "payload_ciphertext_bytes": len(self.payload_ciphertext),
            "total_overhead_bytes": self.total_overhead_bytes,
        }


class CryptoError(Exception):
    """Raised when a cryptographic operation fails or an algorithm is unknown."""


# ==========================================================================
# Shared symmetric layer
# ==========================================================================


def derive_aes_key(shared_secret: bytes, info: bytes) -> bytes:
    """Stretch a KEM shared secret into a 256-bit AES key using HKDF-SHA256.

    A raw KEM shared secret should never be used directly as a cipher key. It may
    have subtle statistical structure, and using it directly gives you no way to
    domain-separate — the same secret in two different contexts would produce the
    same key. HKDF fixes both problems: it extracts uniform randomness and binds
    the output to a context label.

    Args:
        shared_secret: Raw secret from encapsulation or ECDH. For hybrid mode this
            is the concatenation of both component secrets.
        info: Domain-separation label. Two different labels over the same secret
            produce two unrelated keys.

    Returns:
        A 32-byte key suitable for AES-256-GCM.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=config.AES_KEY_BYTES,
        salt=None,
        info=info,
    ).derive(shared_secret)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM under a fresh random nonce.

    Args:
        key: 32-byte key from :func:`derive_aes_key`.
        plaintext: Message bytes.
        aad: Optional additional authenticated data. Not encrypted, but any
            tampering with it makes decryption fail. Use it to bind the ciphertext
            to its metadata (sender, recipient, algorithm) so an attacker cannot
            replay a valid ciphertext under a different header.

    Returns:
        ``(nonce, ciphertext)`` where ciphertext includes the 16-byte GCM tag.
    """
    nonce = os.urandom(config.AES_NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    """Decrypt and authenticate an AES-256-GCM ciphertext.

    Raises:
        CryptoError: If the tag does not verify — meaning either the key is wrong
            or the ciphertext/AAD was tampered with. GCM does not distinguish
            between those cases, and that is intentional.
    """
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:  # InvalidTag and friends
        raise CryptoError(f"AES-GCM authentication failed: {exc}") from exc


# ==========================================================================
# Demo-scale RSA — deliberately breakable, and labelled as such
# ==========================================================================
#
# READ THIS BEFORE JUDGING THE CODE BELOW.
#
# This is textbook RSA with an undersized modulus and no padding. It is
# catastrophically insecure. That is the entire point: the Q-Day simulator
# factors it live, on stage, for real. No lookup table, no faked progress bar,
# no "we already had the private key in the database."
#
# Nothing on Earth can factor RSA-2048 today, so a demo that claims to is
# lying. Instead we shrink the modulus until it is genuinely breakable on a
# laptop, break it honestly, and then show the extrapolation to 2048 bits.
# The argument survives the shrink: the mathematics is identical, only the
# clock changes. That is precisely the Harvest-Now-Decrypt-Later thesis.


def _is_probable_prime(n: int, rounds: int = 24) -> bool:
    """Miller-Rabin primality test.

    Args:
        n: Candidate.
        rounds: Number of random bases. Each round cuts the false-positive
            probability by at least 4x, so 24 rounds gives an error rate below
            4^-24, which is far beyond adequate for a demo key.
    """
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small

    # Write n - 1 as d * 2^r with d odd.
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    """Generate a random probable prime of exactly ``bits`` bits.

    The two forced bits guarantee the value is odd and has the requested bit
    length, so that ``p * q`` lands in a predictable size range.
    """
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def _generate_demo_rsa(prime_bits: int) -> tuple[int, int, int, int, int]:
    """Generate a demo-scale RSA key by hand.

    The ``cryptography`` library refuses to generate keys below 512 bits — quite
    correctly. We need a genuinely factorable modulus, so we build it from raw
    integer arithmetic instead.

    Returns:
        ``(n, e, d, p, q)`` — modulus, public exponent, private exponent, primes.
    """
    e = config.RSA_PUBLIC_EXPONENT
    while True:
        p = _generate_prime(prime_bits)
        q = _generate_prime(prime_bits)
        if p == q:
            continue
        n = p * q
        # Carmichael's totient — the modern choice over Euler's phi. It yields a
        # smaller private exponent and is what FIPS 186-4 actually specifies.
        lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        if math.gcd(e, lam) != 1:
            continue
        d = pow(e, -1, lam)
        return n, e, d, p, q


def _pack_demo_public(n: int, e: int) -> bytes:
    """Serialize a demo RSA public key as ``len(n) | n | len(e) | e``."""
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")
    return struct.pack(">H", len(n_bytes)) + n_bytes + struct.pack(">H", len(e_bytes)) + e_bytes


def _unpack_demo_public(blob: bytes) -> tuple[int, int]:
    """Inverse of :func:`_pack_demo_public`."""
    offset = 0
    (n_len,) = struct.unpack_from(">H", blob, offset)
    offset += 2
    n = int.from_bytes(blob[offset : offset + n_len], "big")
    offset += n_len
    (e_len,) = struct.unpack_from(">H", blob, offset)
    offset += 2
    e = int.from_bytes(blob[offset : offset + e_len], "big")
    return n, e


def _pack_demo_private(n: int, d: int) -> bytes:
    """Serialize a demo RSA private key as ``len(n) | n | len(d) | d``."""
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    d_bytes = d.to_bytes((d.bit_length() + 7) // 8, "big")
    return struct.pack(">H", len(n_bytes)) + n_bytes + struct.pack(">H", len(d_bytes)) + d_bytes


def _unpack_demo_private(blob: bytes) -> tuple[int, int]:
    """Inverse of :func:`_pack_demo_private`."""
    return _unpack_demo_public(blob)  # identical layout


#: Seed size for demo-RSA encapsulation. Must satisfy 2^(8*SEED) < n, and with a
#: 96-bit modulus that means 8 bytes is comfortably safe. HKDF expands it to 32.
_DEMO_SEED_BYTES = 8


# ==========================================================================
# Key generation
# ==========================================================================


def generate_keypair(algorithm: str) -> KeyPair:
    """Generate a key pair for the requested algorithm.

    Args:
        algorithm: One of the ``ALGO_*`` constants in :mod:`backend.config`.

    Returns:
        A :class:`KeyPair` with both halves serialized to bytes.

    Raises:
        CryptoError: If the algorithm identifier is not recognised.
    """
    if algorithm == config.ALGO_ML_KEM_768:
        sk = MLKEM768PrivateKey.generate()
        return KeyPair(
            algorithm=algorithm,
            public_key=sk.public_key().public_bytes_raw(),
            private_key=sk.private_bytes_raw(),
        )

    if algorithm == config.ALGO_HYBRID:
        # A hybrid identity is two independent key pairs travelling together.
        # We concatenate with a length prefix so they can be split on load.
        x_sk = x25519.X25519PrivateKey.generate()
        m_sk = MLKEM768PrivateKey.generate()

        x_pub = x_sk.public_key().public_bytes_raw()   # 32 bytes
        m_pub = m_sk.public_key().public_bytes_raw()   # 1184 bytes
        x_priv = x_sk.private_bytes_raw()              # 32 bytes
        m_priv = m_sk.private_bytes_raw()              # 64 bytes (seed form)

        return KeyPair(
            algorithm=algorithm,
            public_key=struct.pack(">H", len(x_pub)) + x_pub + m_pub,
            private_key=struct.pack(">H", len(x_priv)) + x_priv + m_priv,
        )

    if algorithm == config.ALGO_RSA_DEMO:
        n, e, d, _p, _q = _generate_demo_rsa(config.RSA_DEMO_PRIME_BITS)
        return KeyPair(
            algorithm=algorithm,
            public_key=_pack_demo_public(n, e),
            private_key=_pack_demo_private(n, d),
        )

    if algorithm == config.ALGO_RSA_2048:
        sk = rsa.generate_private_key(
            public_exponent=config.RSA_PUBLIC_EXPONENT,
            key_size=config.RSA_2048_KEY_BITS,
        )
        return KeyPair(
            algorithm=algorithm,
            public_key=sk.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            private_key=sk.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )

    raise CryptoError(f"Unknown algorithm: {algorithm!r}")


# ==========================================================================
# Seal (encrypt)
# ==========================================================================


def seal(algorithm: str, public_key: bytes, plaintext: bytes, aad: bytes | None = None) -> SealedEnvelope:
    """Encapsulate a fresh key and encrypt the payload under it.

    Args:
        algorithm: One of the ``ALGO_*`` constants.
        public_key: Recipient's serialized public key, as produced by
            :func:`generate_keypair`.
        plaintext: Message to protect.
        aad: Optional additional authenticated data bound to the ciphertext.

    Returns:
        A :class:`SealedEnvelope` — exactly the bytes that go on the wire.

    Raises:
        CryptoError: If the algorithm is unknown.
    """
    if algorithm == config.ALGO_ML_KEM_768:
        pk = MLKEM768PublicKey.from_public_bytes(public_key)
        # encapsulate() returns (shared_secret, ciphertext). The secret never
        # travels; only the ciphertext does.
        shared_secret, kem_ct = pk.encapsulate()
        key = derive_aes_key(shared_secret, config.HKDF_INFO_KEM)

    elif algorithm == config.ALGO_HYBRID:
        (x_len,) = struct.unpack_from(">H", public_key, 0)
        x_pub_raw = public_key[2 : 2 + x_len]
        m_pub_raw = public_key[2 + x_len :]

        # Leg 1: ephemeral X25519 ECDH. Broken by a quantum computer.
        eph_sk = x25519.X25519PrivateKey.generate()
        peer_x_pub = x25519.X25519PublicKey.from_public_bytes(x_pub_raw)
        ecdh_secret = eph_sk.exchange(peer_x_pub)
        eph_pub_raw = eph_sk.public_key().public_bytes_raw()

        # Leg 2: ML-KEM-768 encapsulation. Not broken by a quantum computer.
        m_pk = MLKEM768PublicKey.from_public_bytes(m_pub_raw)
        mlkem_secret, mlkem_ct = m_pk.encapsulate()

        # Both secrets feed one HKDF. An attacker needs BOTH to derive the key.
        # This is the same construction browsers deployed as X25519MLKEM768.
        key = derive_aes_key(ecdh_secret + mlkem_secret, config.HKDF_INFO_HYBRID)

        # The wire carries the ephemeral public key plus the ML-KEM ciphertext.
        kem_ct = struct.pack(">H", len(eph_pub_raw)) + eph_pub_raw + mlkem_ct

    elif algorithm == config.ALGO_RSA_DEMO:
        n, e = _unpack_demo_public(public_key)
        seed = secrets.token_bytes(_DEMO_SEED_BYTES)
        m = int.from_bytes(seed, "big")
        c = pow(m, e, n)
        kem_ct = c.to_bytes((n.bit_length() + 7) // 8, "big")
        key = derive_aes_key(seed, config.HKDF_INFO_KEM)

    elif algorithm == config.ALGO_RSA_2048:
        pk = serialization.load_der_public_key(public_key)
        seed = secrets.token_bytes(config.AES_KEY_BYTES)
        kem_ct = pk.encrypt(
            seed,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        key = derive_aes_key(seed, config.HKDF_INFO_KEM)

    else:
        raise CryptoError(f"Unknown algorithm: {algorithm!r}")

    nonce, payload_ct = aes_gcm_encrypt(key, plaintext, aad)
    return SealedEnvelope(
        algorithm=algorithm,
        kem_ciphertext=kem_ct,
        nonce=nonce,
        payload_ciphertext=payload_ct,
    )


# ==========================================================================
# Unseal (decrypt)
# ==========================================================================


def unseal(
    algorithm: str,
    private_key: bytes,
    envelope: SealedEnvelope,
    aad: bytes | None = None,
) -> bytes:
    """Recover the shared secret and decrypt the payload.

    Args:
        algorithm: One of the ``ALGO_*`` constants.
        private_key: Recipient's serialized private key.
        envelope: The sealed envelope to open.
        aad: Must match the AAD supplied to :func:`seal`, or authentication fails.

    Returns:
        The original plaintext.

    Raises:
        CryptoError: On unknown algorithm or failed authentication.
    """
    if algorithm == config.ALGO_ML_KEM_768:
        sk = MLKEM768PrivateKey.from_seed_bytes(private_key)
        shared_secret = sk.decapsulate(envelope.kem_ciphertext)
        key = derive_aes_key(shared_secret, config.HKDF_INFO_KEM)

    elif algorithm == config.ALGO_HYBRID:
        (x_len,) = struct.unpack_from(">H", private_key, 0)
        x_priv_raw = private_key[2 : 2 + x_len]
        m_priv_raw = private_key[2 + x_len :]

        (eph_len,) = struct.unpack_from(">H", envelope.kem_ciphertext, 0)
        eph_pub_raw = envelope.kem_ciphertext[2 : 2 + eph_len]
        mlkem_ct = envelope.kem_ciphertext[2 + eph_len :]

        x_sk = x25519.X25519PrivateKey.from_private_bytes(x_priv_raw)
        ecdh_secret = x_sk.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pub_raw))

        m_sk = MLKEM768PrivateKey.from_seed_bytes(m_priv_raw)
        mlkem_secret = m_sk.decapsulate(mlkem_ct)

        key = derive_aes_key(ecdh_secret + mlkem_secret, config.HKDF_INFO_HYBRID)

    elif algorithm == config.ALGO_RSA_DEMO:
        n, d = _unpack_demo_private(private_key)
        c = int.from_bytes(envelope.kem_ciphertext, "big")
        m = pow(c, d, n)
        try:
            seed = m.to_bytes(_DEMO_SEED_BYTES, "big")
        except OverflowError as exc:
            # A wrong private exponent produces a garbage m far larger than the
            # seed width. Surface it as a CryptoError so callers only ever have
            # to catch one exception type.
            raise CryptoError("RSA-DEMO decapsulation produced an invalid seed") from exc
        key = derive_aes_key(seed, config.HKDF_INFO_KEM)

    elif algorithm == config.ALGO_RSA_2048:
        sk = serialization.load_der_private_key(private_key, password=None)
        try:
            seed = sk.decrypt(
                envelope.kem_ciphertext,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except ValueError as exc:
            # OAEP padding check failed — wrong key or corrupted ciphertext.
            raise CryptoError(f"RSA-OAEP decryption failed: {exc}") from exc
        key = derive_aes_key(seed, config.HKDF_INFO_KEM)

    else:
        raise CryptoError(f"Unknown algorithm: {algorithm!r}")

    return aes_gcm_decrypt(key, envelope.nonce, envelope.payload_ciphertext, aad)


# ==========================================================================
# Benchmarking
# ==========================================================================


def _time_ms(fn, iterations: int) -> float:
    """Run ``fn`` ``iterations`` times and return the mean wall time in ms."""
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    return (time.perf_counter() - start) * 1000.0 / iterations


def run_benchmarks(iterations: int | None = None) -> list[dict[str, Any]]:
    """Measure key size and latency for every algorithm.

    RSA-2048 key generation is intentionally measured over far fewer iterations
    than the rest — it takes hundreds of milliseconds per key, and running 100 of
    them would stall the demo for a minute. The per-key figure is still honest;
    only the sample size differs. This is the single most striking number in the
    whole benchmark: ML-KEM generates keys roughly three orders of magnitude
    faster than RSA-2048.

    Args:
        iterations: Samples per operation. Defaults to
            ``config.BENCHMARK_ITERATIONS``.

    Returns:
        One dict per algorithm, ready to hand straight to Plotly.
    """
    iterations = iterations or config.BENCHMARK_ITERATIONS
    payload = os.urandom(config.BENCHMARK_PAYLOAD_BYTES)
    results: list[dict[str, Any]] = []

    algorithms = (
        config.ALGO_RSA_2048,
        config.ALGO_ML_KEM_768,
        config.ALGO_HYBRID,
    )

    for algo in algorithms:
        # RSA-2048 keygen is slow and high-variance; sample it lightly.
        keygen_iters = 3 if algo == config.ALGO_RSA_2048 else iterations
        keygen_ms = _time_ms(lambda a=algo: generate_keypair(a), keygen_iters)

        kp = generate_keypair(algo)
        seal_ms = _time_ms(
            lambda a=algo, k=kp: seal(a, k.public_key, payload), iterations
        )

        env = seal(algo, kp.public_key, payload)
        unseal_ms = _time_ms(
            lambda a=algo, k=kp, e=env: unseal(a, k.private_key, e), iterations
        )

        results.append(
            {
                "algorithm": algo,
                "quantum_safe": algo not in config.QUANTUM_VULNERABLE_ALGORITHMS,
                "public_key_bytes": kp.public_key_bytes,
                "private_key_bytes": kp.private_key_bytes,
                "kem_ciphertext_bytes": len(env.kem_ciphertext),
                "wire_overhead_bytes": env.total_overhead_bytes,
                "keygen_ms": round(keygen_ms, 4),
                "encapsulate_encrypt_ms": round(seal_ms, 4),
                "decapsulate_decrypt_ms": round(unseal_ms, 4),
                "keygen_samples": keygen_iters,
                "operation_samples": iterations,
            }
        )

    return results
