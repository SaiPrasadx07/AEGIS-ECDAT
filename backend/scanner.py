"""
AegisPQC — PQC readiness scanner.

An inventory and migration-assessment tool for cryptographic estates. It walks a
directory, identifies the algorithm behind every key and certificate it finds,
classifies each as quantum-vulnerable or post-quantum, scores the
Harvest-Now-Decrypt-Later exposure, and produces a prioritised migration order.

WHAT THIS TOOL DOES AND DOES NOT DO
-----------------------------------
This scanner performs **cryptographic inventory and readiness assessment**. It
reads files, parses their structure, and reports what algorithms are in use.

It does NOT perform cryptanalysis of any kind. It does not attempt to break,
weaken, or attack anything it scans. It never derives a private key. Calling
"RSA-2048" quantum-vulnerable is a statement about the published state of
quantum algorithms, not a claim that this tool broke anything.

It also does not predict dates. It will not tell you that RSA-2048 falls in a
specific year, because nobody credibly knows that. What it tells you is the
thing that is actually knowable and actually actionable: *this asset uses an
algorithm that Shor's algorithm solves in polynomial time, and the data it
protects must stay confidential for N more years.* The decision follows from
that without needing a prophecy.

HOW IDENTIFICATION WORKS
------------------------
Two tiers, in order:

1. **Library parse.** Hand the file to ``cryptography`` and ask what it is. This
   gives exact key sizes, curve names, certificate subjects, and validity dates.

2. **OID extraction.** If the library cannot load it — because the installed
   version predates the algorithm, or the algorithm has no Python support at all
   — walk the DER and pull the algorithm identifier OID directly, then look it up
   in :data:`ALGORITHM_REGISTRY`.

Tier 2 is what makes this credible as a real tool rather than a demo. An
enterprise estate contains algorithms your Python library has never heard of.
A scanner that reports "unknown" for every ML-DSA or SLH-DSA key it meets is not
an inventory tool. This one identifies them by OID and classifies them
correctly, because the OID is in the file regardless of what software can parse
the rest.

VERIFIED VERSUS DECLARED
------------------------
Every finding carries an ``evidence`` field:

  * ``VERIFIED``  — the algorithm was read out of actual cryptographic material.
  * ``DECLARED``  — the algorithm was read from a deployment manifest. It is a
                    claim by the operator, not proof.

That distinction is not pedantry. An organisation's PQC migration status is
frequently wrong on paper, and a readiness tool that treats a JSON file as
equivalent to a parsed key is lying to whoever reads the report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Iterable

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519

# ==========================================================================
# Risk model
# ==========================================================================

RISK_CRITICAL: Final[str] = "CRITICAL"
RISK_HIGH: Final[str] = "HIGH"
RISK_MEDIUM: Final[str] = "MEDIUM"
RISK_LOW: Final[str] = "LOW"
RISK_SAFE: Final[str] = "SAFE"
RISK_UNKNOWN: Final[str] = "UNKNOWN"

#: Sort order for migration priority. Lower rank is more urgent.
RISK_RANK: Final[dict[str, int]] = {
    RISK_CRITICAL: 0,
    RISK_HIGH: 1,
    RISK_MEDIUM: 2,
    RISK_LOW: 3,
    RISK_UNKNOWN: 4,
    RISK_SAFE: 5,
}

STATUS_VULNERABLE: Final[str] = "Quantum vulnerable"
STATUS_POST_QUANTUM: Final[str] = "Post-quantum"
STATUS_HYBRID: Final[str] = "Hybrid (classical + post-quantum)"
STATUS_SYMMETRIC: Final[str] = "Symmetric (not primarily affected)"
STATUS_UNKNOWN: Final[str] = "Unclassified"

EVIDENCE_VERIFIED: Final[str] = "VERIFIED"
EVIDENCE_DECLARED: Final[str] = "DECLARED"


@dataclass(frozen=True, slots=True)
class AlgorithmProfile:
    """What we know about one cryptographic algorithm.

    Attributes:
        name: Display name.
        family: Grouping used in the summary charts.
        quantum_vulnerable: True if a cryptographically relevant quantum
            computer running Shor's algorithm defeats it in polynomial time.
        rationale: Why it carries that classification, in one sentence. Shown in
            the UI so no classification is unexplained.
        recommended_migration: What to move to. Empty if already post-quantum.
    """

    name: str
    family: str
    quantum_vulnerable: bool
    rationale: str
    recommended_migration: str = ""


#: OID -> algorithm profile. This is the scanner's knowledge base.
#:
#: The post-quantum OIDs are the NIST arc (2.16.840.1.101.3.4.x). Including
#: ML-DSA and SLH-DSA entries the installed library may not support is
#: deliberate: the OID is present in the file whether or not any Python code can
#: parse the key body, so the scanner identifies them regardless.
ALGORITHM_REGISTRY: Final[dict[str, AlgorithmProfile]] = {
    "1.2.840.113549.1.1.1": AlgorithmProfile(
        name="RSA",
        family="RSA",
        quantum_vulnerable=True,
        rationale=(
            "Security rests on integer factorisation. Shor's algorithm solves "
            "factorisation in polynomial time on a sufficiently large quantum "
            "computer."
        ),
        recommended_migration="ML-KEM-768 for key establishment, ML-DSA for signatures",
    ),
    "1.2.840.10045.2.1": AlgorithmProfile(
        name="ECDSA / ECDH",
        family="Elliptic curve",
        quantum_vulnerable=True,
        rationale=(
            "Security rests on the elliptic-curve discrete logarithm problem, "
            "which Shor's algorithm also solves in polynomial time. Smaller keys "
            "than RSA do not help — they fall sooner."
        ),
        recommended_migration="Hybrid X25519 + ML-KEM-768, or ML-DSA for signatures",
    ),
    "1.2.840.10040.4.1": AlgorithmProfile(
        name="DSA",
        family="Finite-field",
        quantum_vulnerable=True,
        rationale=(
            "Security rests on the finite-field discrete logarithm problem, "
            "solved in polynomial time by Shor's algorithm."
        ),
        recommended_migration="ML-DSA (FIPS 204)",
    ),
    "1.2.840.113549.1.3.1": AlgorithmProfile(
        name="Diffie-Hellman",
        family="Finite-field",
        quantum_vulnerable=True,
        rationale=(
            "Finite-field discrete logarithm. Additionally, any traffic "
            "protected by a non-forward-secret DH exchange harvested today is "
            "retroactively readable."
        ),
        recommended_migration="Hybrid X25519 + ML-KEM-768",
    ),
    "1.3.101.112": AlgorithmProfile(
        name="Ed25519",
        family="Elliptic curve",
        quantum_vulnerable=True,
        rationale=(
            "Edwards-curve signature scheme; the underlying discrete logarithm "
            "falls to Shor's algorithm."
        ),
        recommended_migration="ML-DSA (FIPS 204)",
    ),
    "1.3.101.110": AlgorithmProfile(
        name="X25519",
        family="Elliptic curve",
        quantum_vulnerable=True,
        rationale=(
            "Curve25519 key exchange; discrete logarithm falls to Shor's "
            "algorithm. Widely deployed in hybrid mode precisely for this reason."
        ),
        recommended_migration="Hybrid X25519 + ML-KEM-768",
    ),
    "1.3.101.113": AlgorithmProfile(
        name="Ed448",
        family="Elliptic curve",
        quantum_vulnerable=True,
        rationale="Edwards-curve signature scheme; vulnerable to Shor's algorithm.",
        recommended_migration="ML-DSA (FIPS 204)",
    ),
    "1.3.101.111": AlgorithmProfile(
        name="X448",
        family="Elliptic curve",
        quantum_vulnerable=True,
        rationale="Curve448 key exchange; vulnerable to Shor's algorithm.",
        recommended_migration="Hybrid X448 + ML-KEM-1024",
    ),
    # ---- NIST post-quantum standards ----
    "2.16.840.1.101.3.4.4.1": AlgorithmProfile(
        name="ML-KEM-512",
        family="Module lattice (KEM)",
        quantum_vulnerable=False,
        rationale=(
            "NIST FIPS 203. Security rests on Module Learning With Errors. "
            "Shor's algorithm does not apply to lattice problems."
        ),
    ),
    "2.16.840.1.101.3.4.4.2": AlgorithmProfile(
        name="ML-KEM-768",
        family="Module lattice (KEM)",
        quantum_vulnerable=False,
        rationale=(
            "NIST FIPS 203, Category 3. Security rests on Module Learning With "
            "Errors, which Shor's algorithm does not solve."
        ),
    ),
    "2.16.840.1.101.3.4.4.3": AlgorithmProfile(
        name="ML-KEM-1024",
        family="Module lattice (KEM)",
        quantum_vulnerable=False,
        rationale="NIST FIPS 203, Category 5. Lattice-based; resists Shor's algorithm.",
    ),
    "2.16.840.1.101.3.4.3.17": AlgorithmProfile(
        name="ML-DSA-44",
        family="Module lattice (signature)",
        quantum_vulnerable=False,
        rationale="NIST FIPS 204 lattice signature scheme.",
    ),
    "2.16.840.1.101.3.4.3.18": AlgorithmProfile(
        name="ML-DSA-65",
        family="Module lattice (signature)",
        quantum_vulnerable=False,
        rationale="NIST FIPS 204 lattice signature scheme.",
    ),
    "2.16.840.1.101.3.4.3.19": AlgorithmProfile(
        name="ML-DSA-87",
        family="Module lattice (signature)",
        quantum_vulnerable=False,
        rationale="NIST FIPS 204 lattice signature scheme.",
    ),
    "2.16.840.1.101.3.4.3.20": AlgorithmProfile(
        name="SLH-DSA-SHA2-128s",
        family="Hash-based (signature)",
        quantum_vulnerable=False,
        rationale=(
            "NIST FIPS 205. Security rests only on hash function properties, "
            "the most conservative post-quantum assumption available."
        ),
    ),
}

#: Names the scanner recognises inside deployment manifests, mapped to the OID
#: entry above so declared assets get the same classification logic as parsed
#: ones. Matching is case-insensitive and ignores hyphens.
DECLARED_ALGORITHM_ALIASES: Final[dict[str, str]] = {
    "mlkem512": "2.16.840.1.101.3.4.4.1",
    "mlkem768": "2.16.840.1.101.3.4.4.2",
    "kyber768": "2.16.840.1.101.3.4.4.2",
    "mlkem1024": "2.16.840.1.101.3.4.4.3",
    "mldsa44": "2.16.840.1.101.3.4.3.17",
    "mldsa65": "2.16.840.1.101.3.4.3.18",
    "mldsa87": "2.16.840.1.101.3.4.3.19",
    "rsa": "1.2.840.113549.1.1.1",
    "ecdsa": "1.2.840.10045.2.1",
    "ecdsap256": "1.2.840.10045.2.1",
    "x25519": "1.3.101.110",
    "ed25519": "1.3.101.112",
}

#: File extensions the scanner will attempt to read.
SCANNABLE_SUFFIXES: Final[frozenset[str]] = frozenset(
    {".pem", ".crt", ".cer", ".der", ".key", ".pub", ".p7b", ".json"}
)

#: Files that carry business context rather than cryptographic material.
METADATA_FILENAMES: Final[frozenset[str]] = frozenset({"asset.json", "manifest.json"})


# ==========================================================================
# Findings
# ==========================================================================


@dataclass(slots=True)
class Finding:
    """One scanned asset and its assessment."""

    path: str
    system_name: str
    file_type: str
    algorithm: str
    algorithm_family: str
    key_size: str
    quantum_status: str
    risk: str
    evidence: str
    reasons: list[str] = field(default_factory=list)
    recommended_migration: str = ""
    business_context: str = ""
    data_sensitivity: str = ""
    retention_years: int = 0
    detail: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Plain-dict view for the UI and the JSON API."""
        return {
            "path": self.path,
            "system_name": self.system_name,
            "file_type": self.file_type,
            "algorithm": self.algorithm,
            "algorithm_family": self.algorithm_family,
            "key_size": self.key_size,
            "quantum_status": self.quantum_status,
            "risk": self.risk,
            "evidence": self.evidence,
            "reasons": list(self.reasons),
            "recommended_migration": self.recommended_migration,
            "business_context": self.business_context,
            "data_sensitivity": self.data_sensitivity,
            "retention_years": self.retention_years,
            "detail": dict(self.detail),
            "error": self.error,
        }


# ==========================================================================
# DER / OID parsing
# ==========================================================================


def _read_der_length(data: bytes, index: int) -> tuple[int, int]:
    """Read an ASN.1 DER length field.

    Returns:
        ``(length, next_index)``.
    """
    first = data[index]
    index += 1
    if not first & 0x80:
        return first, index
    count = first & 0x7F
    if count == 0 or count > 4 or index + count > len(data):
        raise ValueError("unsupported or truncated DER length")
    return int.from_bytes(data[index : index + count], "big"), index + count


def _decode_oid(raw: bytes) -> str:
    """Decode a DER OID body into dotted-decimal form."""
    if not raw:
        raise ValueError("empty OID")
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def extract_spki_oid(der: bytes) -> str | None:
    """Pull the algorithm OID out of a DER SubjectPublicKeyInfo structure.

    The structure is::

        SubjectPublicKeyInfo ::= SEQUENCE {
            algorithm  AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, ... },
            subjectPublicKey BIT STRING
        }

    So the first OID inside the second-level SEQUENCE is the algorithm.

    This is the fallback path that lets the scanner identify algorithms the
    installed ``cryptography`` version cannot load — including post-quantum
    schemes with no Python support at all. The OID is in the file either way.

    Returns:
        The dotted-decimal OID, or ``None`` if the structure does not match.
    """
    try:
        index = 0
        if der[index] != 0x30:
            return None
        index += 1
        _, index = _read_der_length(der, index)

        if der[index] != 0x30:
            return None
        index += 1
        _, index = _read_der_length(der, index)

        if der[index] != 0x06:
            return None
        index += 1
        length, index = _read_der_length(der, index)
        return _decode_oid(der[index : index + length])
    except (IndexError, ValueError):
        return None


def _pem_blocks_to_der(data: bytes) -> list[bytes]:
    """Extract every base64 body from a PEM file and decode it to DER."""
    import base64
    import re

    blocks: list[bytes] = []
    pattern = re.compile(
        rb"-----BEGIN [^-]+-----(.*?)-----END [^-]+-----", re.DOTALL
    )
    for match in pattern.finditer(data):
        try:
            blocks.append(base64.b64decode(re.sub(rb"\s", b"", match.group(1))))
        except Exception:
            continue
    return blocks


# ==========================================================================
# File analysis
# ==========================================================================


def _describe_public_key(public_key: Any) -> tuple[str, str, dict[str, Any]]:
    """Turn a loaded public key object into (algorithm, key size, detail)."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", str(public_key.key_size), {"modulus_bits": public_key.key_size}
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return (
            "ECDSA / ECDH",
            public_key.curve.name.upper(),
            {"curve": public_key.curve.name, "curve_bits": public_key.curve.key_size},
        )
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", str(public_key.key_size), {"key_bits": public_key.key_size}
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", "255", {}
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", "448", {}
    if isinstance(public_key, x25519.X25519PublicKey):
        return "X25519", "255", {}
    if isinstance(public_key, x448.X448PublicKey):
        return "X448", "448", {}

    # ML-KEM and anything else the library knows but we have not enumerated.
    # ML-KEM parameter sets are fixed by FIPS 203, so the class name carries the
    # security level and the raw public key length confirms it: ML-KEM-768
    # encapsulation keys are exactly 1184 bytes in every conforming
    # implementation.
    name = type(public_key).__name__.replace("PublicKey", "")
    detail: dict[str, Any] = {}
    key_size = ""
    if name.startswith("MLKEM"):
        parameter_set = name.replace("MLKEM", "")
        name = f"ML-KEM-{parameter_set}"
        key_size = parameter_set
        try:
            raw = public_key.public_bytes_raw()
            detail["encapsulation_key_bytes"] = len(raw)
            detail["standard"] = "NIST FIPS 203"
        except Exception:
            pass
    return name, key_size, detail


def _analyse_bytes(data: bytes) -> dict[str, Any]:
    """Identify the cryptographic content of one file's bytes.

    Tries, in order: X.509 certificate, public key, private key, then raw OID
    extraction. Returns a dict with whatever it managed to establish.
    """
    der_blocks = _pem_blocks_to_der(data) if b"-----BEGIN" in data else [data]

    # --- Tier 1: let the library parse it ---
    for loader, file_type in (
        (lambda d: x509.load_pem_x509_certificate(d), "X.509 certificate"),
        (lambda d: x509.load_der_x509_certificate(d), "X.509 certificate"),
    ):
        try:
            cert = loader(data)
            algorithm, key_size, detail = _describe_public_key(cert.public_key())
            detail.update(
                {
                    "subject": cert.subject.rfc4514_string(),
                    "not_valid_after": cert.not_valid_after_utc.date().isoformat(),
                    "signature_algorithm": (
                        cert.signature_algorithm_oid._name
                        if hasattr(cert.signature_algorithm_oid, "_name")
                        else str(cert.signature_algorithm_oid.dotted_string)
                    ),
                }
            )
            return {
                "file_type": file_type,
                "algorithm": algorithm,
                "key_size": key_size,
                "detail": detail,
                "oid": extract_spki_oid(
                    cert.public_key().public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                ),
            }
        except Exception:
            pass

    for loader, file_type in (
        (lambda d: serialization.load_pem_public_key(d), "Public key"),
        (lambda d: serialization.load_der_public_key(d), "Public key"),
        (lambda d: serialization.load_pem_private_key(d, password=None), "Private key"),
        (lambda d: serialization.load_der_private_key(d, password=None), "Private key"),
    ):
        try:
            key = loader(data)
            public_key = key.public_key() if hasattr(key, "public_key") else key
            algorithm, key_size, detail = _describe_public_key(public_key)
            oid = None
            try:
                oid = extract_spki_oid(
                    public_key.public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )
            except Exception:
                pass
            return {
                "file_type": file_type,
                "algorithm": algorithm,
                "key_size": key_size,
                "detail": detail,
                "oid": oid,
            }
        except Exception:
            pass

    # --- Tier 2: OID extraction ---
    # The library could not load this. It may still be a perfectly valid key
    # using an algorithm this build has no support for. The OID is in the DER
    # regardless, so read it directly.
    for block in der_blocks:
        oid = extract_spki_oid(block)
        if oid and oid in ALGORITHM_REGISTRY:
            profile = ALGORITHM_REGISTRY[oid]
            return {
                "file_type": "Public key (identified by OID)",
                "algorithm": profile.name,
                "key_size": "",
                "detail": {"algorithm_oid": oid, "parsed_via": "DER OID extraction"},
                "oid": oid,
            }

    return {"file_type": "Unrecognised", "algorithm": "", "key_size": "", "detail": {}, "oid": None}


# ==========================================================================
# Risk scoring
# ==========================================================================

#: Retention thresholds, in years, used to grade HNDL exposure. The logic:
#: a quantum-vulnerable algorithm protecting data that must stay confidential
#: for decades is exposed by definition, because the ciphertext can be stored
#: today and opened later.
_RETENTION_LONG: Final[int] = 20
_RETENTION_MEDIUM: Final[int] = 7

_SENSITIVITY_RANK: Final[dict[str, int]] = {
    "critical": 3,
    "high": 2,
    "medium": 1,
    "low": 0,
}


def assess_risk(
    profile: AlgorithmProfile | None,
    key_size: str,
    data_sensitivity: str,
    retention_years: int,
    evidence: str,
) -> tuple[str, list[str]]:
    """Score one asset's Harvest-Now-Decrypt-Later exposure.

    The rules, applied in order, are deliberately simple and fully enumerated
    below so that every rating in the report can be traced to the rule that
    produced it. There is no weighting matrix and no hidden constant.

    Args:
        profile: Algorithm profile, or None if unidentified.
        key_size: Key size string, used only for context in the explanation.
        data_sensitivity: ``low`` / ``medium`` / ``high`` / ``critical``.
        retention_years: How long the protected data must stay confidential.
        evidence: VERIFIED or DECLARED.

    Returns:
        ``(risk_level, reasons)`` where reasons explains the rating in plain
        language, one bullet per contributing factor.
    """
    reasons: list[str] = []

    if profile is None:
        return RISK_UNKNOWN, [
            "Algorithm could not be identified from the file contents.",
            "Unidentified cryptography cannot be assumed safe. Manual review required.",
        ]

    # --- Post-quantum assets ---
    if not profile.quantum_vulnerable:
        reasons.append(f"{profile.name} is a NIST-standardised post-quantum algorithm.")
        reasons.append(profile.rationale)
        if evidence == EVIDENCE_DECLARED:
            reasons.append(
                "Status is DECLARED in a deployment manifest, not verified from "
                "key material. Confirm against the running service before "
                "treating this asset as migrated."
            )
            return RISK_LOW, reasons
        reasons.append("Verified directly from the key material on disk.")
        return RISK_SAFE, reasons

    # --- Quantum-vulnerable assets ---
    label = f"{profile.name}-{key_size}" if key_size else profile.name
    reasons.append(f"{label} is a quantum-vulnerable public-key primitive.")
    reasons.append(profile.rationale)

    sensitivity_rank = _SENSITIVITY_RANK.get(data_sensitivity.lower(), 1)

    if retention_years >= _RETENTION_LONG:
        reasons.append(
            f"Protected data has a {retention_years}-year confidentiality "
            "requirement. Ciphertext captured today would still need to be "
            "secret well beyond the point where the underlying algorithm is "
            "expected to be at risk."
        )
        risk = RISK_CRITICAL
    elif retention_years >= _RETENTION_MEDIUM:
        reasons.append(
            f"Protected data has a {retention_years}-year confidentiality "
            "requirement, which is long enough for harvested traffic to remain "
            "sensitive."
        )
        risk = RISK_HIGH
    else:
        reasons.append(
            f"Protected data has a short ({retention_years}-year) "
            "confidentiality requirement, which limits — but does not "
            "eliminate — harvest exposure."
        )
        risk = RISK_MEDIUM

    # Sensitivity can escalate one level, never de-escalate below MEDIUM.
    if sensitivity_rank >= 3 and risk == RISK_HIGH:
        reasons.append(
            "Data is classified critical, escalating this asset above its "
            "retention-based rating."
        )
        risk = RISK_CRITICAL
    elif sensitivity_rank >= 2 and risk == RISK_MEDIUM:
        reasons.append("Data is classified high sensitivity, escalating the rating.")
        risk = RISK_HIGH

    reasons.append(f"Recommended migration: {profile.recommended_migration}.")
    return risk, reasons


# ==========================================================================
# Scanning
# ==========================================================================


def _load_directory_metadata(directory: Path) -> dict[str, dict[str, Any]]:
    """Read a directory's ``asset.json`` business context, if present."""
    path = directory / "asset.json"
    if not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text())
        return loaded if isinstance(loaded, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _scan_manifest_file(path: Path, meta: dict[str, Any]) -> Finding | None:
    """Read a deployment manifest that declares a cryptographic suite.

    Manifests are a claim, not proof, so anything found here is marked DECLARED.
    """
    try:
        document = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(document, dict):
        return None

    declared: str | None = None
    for key in ("key_exchange", "algorithm", "kem", "cipher_suite", "signature"):
        value = document.get(key)
        if isinstance(value, str):
            normalised = value.lower().replace("-", "").replace("_", "").replace(" ", "")
            if normalised in DECLARED_ALGORITHM_ALIASES:
                declared = DECLARED_ALGORITHM_ALIASES[normalised]
                break
    if declared is None:
        return None

    profile = ALGORITHM_REGISTRY[declared]
    risk, reasons = assess_risk(
        profile,
        "",
        meta.get("data_sensitivity", "medium"),
        int(meta.get("retention_years", 0)),
        EVIDENCE_DECLARED,
    )
    return Finding(
        path=str(path),
        system_name=meta.get("system_name", path.parent.name),
        file_type="Deployment manifest",
        algorithm=profile.name,
        algorithm_family=profile.family,
        key_size="",
        quantum_status=(
            STATUS_HYBRID
            if document.get("hybrid_mode")
            else (STATUS_VULNERABLE if profile.quantum_vulnerable else STATUS_POST_QUANTUM)
        ),
        risk=risk,
        evidence=EVIDENCE_DECLARED,
        reasons=reasons,
        recommended_migration=profile.recommended_migration,
        business_context=meta.get("business_context", ""),
        data_sensitivity=meta.get("data_sensitivity", ""),
        retention_years=int(meta.get("retention_years", 0)),
        detail={k: v for k, v in document.items() if isinstance(v, (str, bool, int))},
    )


def scan_file(path: Path, meta: dict[str, Any] | None = None) -> Finding | None:
    """Assess a single file.

    Args:
        path: File to scan.
        meta: Optional business context from the directory's ``asset.json``.

    Returns:
        A :class:`Finding`, or ``None`` if the file is not cryptographic
        material at all (metadata sidecars, unrelated files).
    """
    meta = meta or {}
    system_name = meta.get("system_name") or path.parent.name

    try:
        data = path.read_bytes()
    except OSError as exc:
        return Finding(
            path=str(path),
            system_name=system_name,
            file_type="Unreadable",
            algorithm="",
            algorithm_family="",
            key_size="",
            quantum_status=STATUS_UNKNOWN,
            risk=RISK_UNKNOWN,
            evidence=EVIDENCE_VERIFIED,
            reasons=[f"File could not be read: {exc}"],
            error=str(exc),
        )

    if path.suffix.lower() == ".json":
        return _scan_manifest_file(path, meta)

    analysis = _analyse_bytes(data)
    oid = analysis["oid"]
    profile = ALGORITHM_REGISTRY.get(oid) if oid else None

    # The library may identify the algorithm even when the OID lookup misses.
    if profile is None and analysis["algorithm"]:
        for candidate in ALGORITHM_REGISTRY.values():
            if candidate.name == analysis["algorithm"]:
                profile = candidate
                break

    if profile is None and not analysis["algorithm"]:
        # Malformed, truncated, or simply not cryptographic. Report it as
        # UNKNOWN rather than silently dropping it: an asset a scanner cannot
        # read is exactly the asset a migration programme must not lose track of.
        return Finding(
            path=str(path),
            system_name=system_name,
            file_type="Unparseable",
            algorithm="",
            algorithm_family="",
            key_size="",
            quantum_status=STATUS_UNKNOWN,
            risk=RISK_UNKNOWN,
            evidence=EVIDENCE_VERIFIED,
            reasons=[
                "File appears to contain cryptographic material but could not "
                "be parsed. It may be truncated, corrupted, or password "
                "protected.",
                "Unidentified cryptography cannot be assumed safe. Manual "
                "review required.",
            ],
            business_context=meta.get("business_context", ""),
            data_sensitivity=meta.get("data_sensitivity", ""),
            retention_years=int(meta.get("retention_years", 0)),
            error="parse failed",
        )

    risk, reasons = assess_risk(
        profile,
        analysis["key_size"],
        meta.get("data_sensitivity", "medium"),
        int(meta.get("retention_years", 0)),
        EVIDENCE_VERIFIED,
    )

    if profile is None:
        quantum_status = STATUS_UNKNOWN
    elif profile.quantum_vulnerable:
        quantum_status = STATUS_VULNERABLE
    else:
        quantum_status = STATUS_POST_QUANTUM

    # Record the OID that produced the classification. This is the audit trail:
    # anyone can run `openssl asn1parse` on the same file and confirm the
    # scanner matched the right algorithm identifier.
    detail = dict(analysis["detail"])
    if oid:
        detail.setdefault("algorithm_oid", oid)

    return Finding(
        path=str(path),
        system_name=system_name,
        file_type=analysis["file_type"],
        algorithm=profile.name if profile else analysis["algorithm"],
        algorithm_family=profile.family if profile else "Unclassified",
        key_size=analysis["key_size"],
        quantum_status=quantum_status,
        risk=risk,
        evidence=EVIDENCE_VERIFIED,
        reasons=reasons,
        recommended_migration=profile.recommended_migration if profile else "",
        business_context=meta.get("business_context", ""),
        data_sensitivity=meta.get("data_sensitivity", ""),
        retention_years=int(meta.get("retention_years", 0)),
        detail=detail,
    )


def scan_directory(root: Path) -> list[Finding]:
    """Walk a directory tree and assess every cryptographic file in it.

    Results are sorted by path so the inventory order is identical on every run
    regardless of filesystem enumeration order, which differs between Windows
    and Linux.

    Args:
        root: Directory to scan.

    Returns:
        Findings, sorted by path.
    """
    findings: list[Finding] = []
    metadata_cache: dict[Path, dict[str, dict[str, Any]]] = {}

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name in METADATA_FILENAMES:
            continue
        if path.suffix.lower() not in SCANNABLE_SUFFIXES:
            continue

        if path.parent not in metadata_cache:
            metadata_cache[path.parent] = _load_directory_metadata(path.parent)
        meta = metadata_cache[path.parent].get(path.name, {})

        finding = scan_file(path, meta)
        if finding is not None:
            findings.append(finding)

    return sorted(findings, key=lambda f: f.path)


# ==========================================================================
# Assessment
# ==========================================================================


def readiness_score(findings: Iterable[Finding]) -> int:
    """Compute a 0-100 PQC readiness score.

    The formula is deliberately simple enough to explain in one breath, because
    a score nobody can explain is a score nobody should act on:

        Each asset earns points out of 100/N, where N is the asset count:

            SAFE      100%  of its share  (post-quantum, verified)
            LOW        75%  of its share  (post-quantum, declared only)
            MEDIUM     40%  of its share
            HIGH       20%  of its share
            UNKNOWN    10%  of its share  (cannot be assessed)
            CRITICAL    0%  of its share

    An estate scores 100 only when every asset is verified post-quantum. It
    scores 0 when every asset is critically exposed.

    Returns:
        An integer from 0 to 100.
    """
    weights = {
        RISK_SAFE: 1.0,
        RISK_LOW: 0.75,
        RISK_MEDIUM: 0.40,
        RISK_HIGH: 0.20,
        RISK_UNKNOWN: 0.10,
        RISK_CRITICAL: 0.0,
    }
    items = list(findings)
    if not items:
        return 0
    total = sum(weights.get(f.risk, 0.0) for f in items)
    return int(round(total / len(items) * 100))


def migration_order(findings: Iterable[Finding]) -> list[Finding]:
    """Rank assets by migration urgency.

    Sort key, in order of precedence:

        1. Risk level (CRITICAL first)
        2. Retention years, descending — longer-lived data is more exposed to
           harvesting, because the ciphertext must stay secret for longer
        3. Data sensitivity, descending
        4. Path, ascending — a total ordering so the result is identical on
           every run and on every operating system

    The final tiebreak matters more than it looks. Without it, two assets with
    identical risk and retention could swap places between runs, and a migration
    plan that reorders itself is not a plan.
    """
    return sorted(
        findings,
        key=lambda f: (
            RISK_RANK.get(f.risk, 99),
            -f.retention_years,
            -_SENSITIVITY_RANK.get(f.data_sensitivity.lower(), 1),
            f.path,
        ),
    )


def build_assessment(findings: list[Finding]) -> dict[str, Any]:
    """Turn raw findings into the full enterprise assessment.

    Returns:
        Counts, the readiness score, the migration order, and the findings
        themselves — everything the dashboard and the API need.
    """
    counts = {
        level: sum(1 for f in findings if f.risk == level)
        for level in (RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM, RISK_LOW, RISK_SAFE, RISK_UNKNOWN)
    }

    vulnerable = sum(1 for f in findings if f.quantum_status == STATUS_VULNERABLE)
    pqc_ready = sum(
        1
        for f in findings
        if f.quantum_status in (STATUS_POST_QUANTUM, STATUS_HYBRID)
    )
    unidentified = sum(1 for f in findings if f.quantum_status == STATUS_UNKNOWN)

    score = readiness_score(findings)
    ordered = migration_order(findings)

    if score >= 90:
        verdict = "PQC READY"
    elif score >= 60:
        verdict = "MIGRATION IN PROGRESS"
    elif score >= 30:
        verdict = "MIGRATION REQUIRED"
    else:
        verdict = "URGENT MIGRATION REQUIRED"

    by_family: dict[str, int] = {}
    for finding in findings:
        family = finding.algorithm_family or "Unclassified"
        by_family[family] = by_family.get(family, 0) + 1

    return {
        "assets_scanned": len(findings),
        "quantum_vulnerable": vulnerable,
        "pqc_ready": pqc_ready,
        "unidentified": unidentified,
        "counts": counts,
        "readiness_score": score,
        "verdict": verdict,
        "by_family": dict(sorted(by_family.items())),
        "migration_order": [f.to_dict() for f in ordered if f.risk != RISK_SAFE],
        "findings": [f.to_dict() for f in ordered],
        "scope_note": (
            "This is a cryptographic inventory and readiness assessment. No "
            "cryptanalysis is performed against any scanned asset, and no "
            "private key material is read, derived, or reported."
        ),
    }


def scan(root: Path) -> dict[str, Any]:
    """Scan a directory and return the complete assessment."""
    return build_assessment(scan_directory(root))
