"""
Aegis PQC — demonstration application source.

Synthetic source files giving the source scanner genuine material to analyse.

DESIGN INTENT
-------------
Five applications, chosen so the scan demonstrates discrimination rather than
volume:

    payments-api    Explicit RSA-2048 with a literal key size, plus AES-GCM.
                    The headline case: strong call-site evidence.
    legacy-auth     MD5, DES, ECB mode, and SHA1withRSA. Several legacy
                    primitives that are problems independent of quantum risk.
    mobile-gateway  ECDSA and TLS in Java and JavaScript.
    pqc-pilot       ML-KEM usage, and a hybrid construction represented
                    honestly — two key establishments feeding one KDF.
    content-portal  No cryptography at all, but deliberately seeded with
                    comments and identifiers mentioning RSA, AES, and MD5.

That last one matters most. It is the false-positive control: prose and
variable names that mention algorithms must produce zero findings. An estate
where everything looks cryptographic is an estate nobody can act on.

NO SECRETS
----------
Every key, token, and credential here is absent rather than fake. Where a
secret would normally appear the source reads from an environment variable, so
nothing in this module resembles a credential a scanner could leak into a
report.
"""

from __future__ import annotations

from pathlib import Path

# ==========================================================================
# payments-api — explicit RSA-2048, AES-GCM
# ==========================================================================

PAYMENTS_KEYS_PY = '''\
"""Settlement key management for the payments service."""

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def generate_settlement_key():
    """Issue the RSA key protecting nightly settlement batches."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def generate_archive_key(configured_size):
    """Key size comes from configuration, so it is not visible in source."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=configured_size,
    )


def derive_batch_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"settlement-batch",
    ).derive(shared_secret)


def seal_batch(key, payload):
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, payload, None)
'''

PAYMENTS_TOKENS_PY = '''\
"""Token signing for the settlement API."""

import hashlib


def fingerprint(document):
    """Content addressing for settlement documents."""
    return hashlib.sha256(document).hexdigest()
'''


# ==========================================================================
# legacy-auth — legacy primitives
# ==========================================================================

LEGACY_AUTH_JAVA = '''\
package com.northwind.auth;

import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class TokenService {

    public byte[] legacyDigest(byte[] input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return digest.digest(input);
    }

    public Cipher legacyCipher() throws Exception {
        return Cipher.getInstance("DES/ECB/PKCS5Padding");
    }

    public Cipher sessionCipher() throws Exception {
        return Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    public KeyPairGenerator signingKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        return generator;
    }

    public Signature legacySignature() throws Exception {
        return Signature.getInstance("SHA1withRSA");
    }
}
'''

LEGACY_AUTH_PY = '''\
"""Password and session helpers for the legacy auth service."""

import hashlib
from Crypto.Cipher import DES


def legacy_password_hash(password, salt):
    """Retained for accounts created before the 2019 migration."""
    return hashlib.md5(salt + password).hexdigest()


def legacy_session_cipher(key):
    return DES.new(key, DES.MODE_ECB)
'''


# ==========================================================================
# mobile-gateway — ECDSA and TLS
# ==========================================================================

MOBILE_GATEWAY_JS = '''\
const crypto = require("crypto");
const tls = require("tls");
const jwt = require("jsonwebtoken");

function deviceFingerprint(payload) {
  return crypto.createHash("sha256").update(payload).digest("hex");
}

function sessionCipher(key, iv) {
  return crypto.createCipheriv("aes-256-cbc", key, iv);
}

function issueKeyPair() {
  return crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
}

module.exports = { deviceFingerprint, sessionCipher, issueKeyPair };
'''

MOBILE_GATEWAY_JAVA = '''\
package com.northwind.mobile;

import java.security.KeyPairGenerator;
import java.security.Signature;
import javax.net.ssl.SSLContext;

public class MobileTransport {

    public KeyPairGenerator deviceKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        return generator;
    }

    public Signature attestation() throws Exception {
        return Signature.getInstance("SHA256withECDSA");
    }

    public SSLContext transport() throws Exception {
        return SSLContext.getInstance("TLSv1.2");
    }
}
'''


# ==========================================================================
# pqc-pilot — post-quantum and hybrid
# ==========================================================================

PQC_PILOT_PY = '''\
"""Post-quantum key establishment pilot."""

from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def post_quantum_keypair():
    """ML-KEM-768 encapsulation key, FIPS 203."""
    return MLKEM768PrivateKey.generate()


def hybrid_keypair():
    """Hybrid establishment: one classical leg, one post-quantum leg.

    Both shared secrets feed a single KDF, so an attacker must defeat both.
    """
    classical = x25519.X25519PrivateKey.generate()
    post_quantum = MLKEM768PrivateKey.generate()
    return classical, post_quantum


def combine(classical_secret, pq_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"hybrid-x25519-mlkem768",
    ).derive(classical_secret + pq_secret)


def seal(key, message):
    return AESGCM(key).encrypt(b"\\x00" * 12, message, None)
'''

PQC_PILOT_GO = '''\
package transport

import (
\t"crypto/rand"
\t"crypto/rsa"
\t"crypto/sha256"
\t"crypto/tls"
)

// LegacyKey remains for the compatibility bridge during migration.
func LegacyKey() (*rsa.PrivateKey, error) {
\treturn rsa.GenerateKey(rand.Reader, 3072)
}

func Digest(payload []byte) [32]byte {
\treturn sha256.Sum256(payload)
}

func TransportConfig() *tls.Config {
\treturn &tls.Config{MinVersion: tls.VersionTLS13}
}
'''


# ==========================================================================
# content-portal — no cryptography, deliberate false-positive bait
# ==========================================================================

CONTENT_PORTAL_JS = '''\
// Content rendering for the public documentation portal.
//
// NOTE: an earlier prototype used RSA to sign preview links, and AES to
// encrypt draft content. Both were removed in the 2024 rewrite — see
// ADR-0042. Do not reintroduce MD5 for cache keys.

const md5CacheKey = "legacy-cache-prefix";
const aesRegion = "eu-west-1";
const rsaTicketFormat = "v2";

function buildCacheKey(slug) {
  return `${md5CacheKey}:${slug}`;
}

function renderArticle(article) {
  return {
    title: article.title,
    region: aesRegion,
    ticket: rsaTicketFormat,
  };
}

module.exports = { buildCacheKey, renderArticle };
'''

CONTENT_PORTAL_PY = '''\
"""Public content portal — no cryptographic operations.

This module mentions RSA, AES, SHA-256 and MD5 in documentation only. The
scanner must not produce findings from prose or identifier names.
"""

# Historical note: the RSA-signed preview links were retired in 2024.
AES_REGION_LABEL = "eu-west-1"
RSA_TICKET_VERSION = "v2"
MD5_LEGACY_PREFIX = "cache"


def describe_encryption_policy():
    """Returns the documented policy text. Performs no cryptography."""
    return (
        "Content at rest is encrypted by the storage layer. "
        "This service performs no cryptographic operations."
    )
'''

CONTENT_PORTAL_README = """\
# Content Portal

Public documentation site.

## Security

TLS termination happens at the edge. This service does not implement RSA,
AES, ECDSA, or any other cryptographic primitive directly. Historical
versions used MD5 cache keys; these were removed.
"""


#: Source files written into the estate: relative path to contents.
APPLICATION_SOURCE: dict[str, str] = {
    "payments-api/src/keys.py": PAYMENTS_KEYS_PY,
    "payments-api/src/tokens.py": PAYMENTS_TOKENS_PY,
    "legacy-auth/src/TokenService.java": LEGACY_AUTH_JAVA,
    "legacy-auth/src/session.py": LEGACY_AUTH_PY,
    "mobile-gateway/src/transport.js": MOBILE_GATEWAY_JS,
    "mobile-gateway/src/MobileTransport.java": MOBILE_GATEWAY_JAVA,
    "pqc-pilot/src/hybrid.py": PQC_PILOT_PY,
    "pqc-pilot/src/transport.go": PQC_PILOT_GO,
    "content-portal/src/render.js": CONTENT_PORTAL_JS,
    "content-portal/src/content.py": CONTENT_PORTAL_PY,
    "content-portal/README.md": CONTENT_PORTAL_README,
}

#: Applications expected to yield source findings.
SOURCE_CRYPTO_APPLICATIONS: frozenset[str] = frozenset(
    {"payments-api", "legacy-auth", "mobile-gateway", "pqc-pilot"}
)

#: Applications whose source must yield nothing. The false-positive control.
SOURCE_CLEAN_APPLICATIONS: frozenset[str] = frozenset({"content-portal"})


def write_application_source(root: Path) -> list[Path]:
    """Write the demonstration source files into ``root``.

    Args:
        root: Estate root directory.

    Returns:
        Paths written, sorted.
    """
    written: list[Path] = []
    for relative, contents in APPLICATION_SOURCE.items():
        path = root / Path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        written.append(path)
    return sorted(written)
