"""
AegisPQC — demo enterprise environment generator.

Builds a fictional organisation's cryptographic estate on local disk, so the
PQC readiness scanner has something real to scan during a presentation without
depending on finding certificates on the venue laptop.

WHAT MAKES THIS DEFENSIBLE
--------------------------
Every file this module writes contains GENUINE cryptographic material, produced
by the same library that secures real systems. The RSA-2048 key in
``api-gateway/`` is a real RSA-2048 key. The ECDSA certificate in ``mobile/`` is
a real, correctly-signed X.509 certificate. The ML-KEM-768 key in
``quantum-safe-service/`` is a real FIPS 203 encapsulation key in standard
SubjectPublicKeyInfo form.

That matters in front of a security-literate judge. The obvious question about
any scanner demo is "is it actually parsing that, or did you hardcode the
answer?" Here the honest answer is: it parses it. You can open the PEM files in
OpenSSL and get the same results.

DETERMINISM
-----------
The generated KEY MATERIAL differs between runs — RSA key generation is random,
and pretending otherwise would be dishonest. What is deterministic is everything
the demo actually shows: the asset inventory, the algorithm classifications, the
risk ratings, the readiness score, and the migration order. Those depend on the
algorithm and key size, not on the specific primes.

The environment is also generated once and cached on disk, so repeat scans
during a presentation return byte-identical results.

OFFLINE
-------
No network access, no external certificate authority, no cloud service. Every
certificate is self-signed locally. The generator works on an air-gapped machine.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.x509.oid import NameOID

from backend import config

#: Where the fictional enterprise is written. Under `data/` so it is git-ignorable
#: and can be wiped without touching source.
DEMO_ENTERPRISE_DIR: Final[Path] = config.DATA_DIR / "demo_enterprise"

#: Bumped whenever the asset list changes, so a stale cached environment from an
#: older version is regenerated instead of silently scanned.
MANIFEST_VERSION: Final[str] = "1.0.0"


@dataclass(frozen=True, slots=True)
class AssetSpec:
    """One system in the fictional enterprise.

    Attributes:
        directory: Folder name under the enterprise root.
        system_name: Human-readable system name shown in the scanner UI.
        filename: File the cryptographic material is written to.
        kind: What to generate — see :func:`_generate_asset`.
        business_context: What the system does. Feeds the risk explanation.
        data_sensitivity: One of ``low``, ``medium``, ``high``, ``critical``.
        retention_years: How long the data this system protects must stay
            confidential. This is the single most important input to HNDL risk:
            data that must stay secret for 30 years and is protected by a
            quantum-vulnerable algorithm today is exposed by definition.
    """

    directory: str
    system_name: str
    filename: str
    kind: str
    business_context: str
    data_sensitivity: str
    retention_years: int


#: The fictional estate. Ordered for narrative, but the scanner sorts by risk,
#: so this ordering never leaks into the assessment.
ENTERPRISE_ASSETS: Final[tuple[AssetSpec, ...]] = (
    AssetSpec(
        directory="api-gateway",
        system_name="API Gateway",
        filename="server_rsa2048.pem",
        kind="rsa_private_2048",
        business_context="Terminates TLS for all external customer API traffic",
        data_sensitivity="critical",
        retention_years=15,
    ),
    AssetSpec(
        directory="api-gateway",
        system_name="API Gateway Certificate",
        filename="certificate.pem",
        kind="rsa_certificate_2048",
        business_context="Public-facing TLS certificate presented to every client",
        data_sensitivity="high",
        retention_years=10,
    ),
    AssetSpec(
        directory="payments",
        system_name="Payment Processing",
        filename="payment_rsa3072.pem",
        kind="rsa_private_3072",
        business_context="Signs and protects card settlement batches",
        data_sensitivity="critical",
        retention_years=25,
    ),
    AssetSpec(
        directory="legacy-auth",
        system_name="Legacy Authentication",
        filename="signing_rsa2048.pem",
        kind="rsa_private_2048",
        business_context="Issues session tokens for internal staff systems",
        data_sensitivity="critical",
        retention_years=30,
    ),
    AssetSpec(
        directory="mobile",
        system_name="Mobile Client",
        filename="ecdsa_certificate.pem",
        kind="ecdsa_certificate_p256",
        business_context="Certificate pinned by the mobile application",
        data_sensitivity="high",
        retention_years=8,
    ),
    AssetSpec(
        directory="quantum-safe-service",
        system_name="Quantum-Safe Service",
        filename="mlkem768_public.pem",
        kind="mlkem768_public",
        business_context="Pilot service already migrated to post-quantum key exchange",
        data_sensitivity="high",
        retention_years=30,
    ),
    AssetSpec(
        directory="quantum-safe-service",
        system_name="Quantum-Safe Service Metadata",
        filename="mlkem_service_metadata.json",
        kind="mlkem_metadata",
        business_context="Deployment manifest declaring the negotiated PQC suite",
        data_sensitivity="medium",
        retention_years=30,
    ),
    AssetSpec(
        directory="archive",
        system_name="Records Archive",
        filename="old_rsa2048.pem",
        kind="rsa_private_2048",
        business_context="Encrypts long-term regulatory record storage",
        data_sensitivity="critical",
        retention_years=50,
    ),
    AssetSpec(
        directory="archive",
        system_name="Corrupted Backup Key",
        filename="truncated_backup.pem",
        kind="malformed",
        business_context="Damaged file recovered from a failed backup volume",
        data_sensitivity="low",
        retention_years=1,
    ),
)


# --------------------------------------------------------------------------
# Generators
# --------------------------------------------------------------------------


def _self_signed_certificate(
    private_key: Any, common_name: str, signing_hash: hashes.HashAlgorithm
) -> x509.Certificate:
    """Build a locally self-signed X.509 certificate.

    Self-signed and locally generated on purpose: the demo must work on an
    air-gapped machine with no certificate authority reachable.

    The validity window is anchored to a fixed date rather than "now" so that
    regenerating the environment does not change the certificate's printed
    validity dates between demo runs.
    """
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Northwind Systems"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    not_before = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + timedelta(days=730))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False
        )
        .sign(private_key, signing_hash)
    )


def _generate_asset(spec: AssetSpec, path: Path) -> None:
    """Write one asset's cryptographic material to disk.

    Args:
        spec: What to generate.
        path: Destination file.
    """
    if spec.kind == "rsa_private_2048":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    elif spec.kind == "rsa_private_3072":
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    elif spec.kind == "rsa_certificate_2048":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = _self_signed_certificate(key, "api.northwind.example", hashes.SHA256())
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    elif spec.kind == "ecdsa_certificate_p256":
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _self_signed_certificate(key, "mobile.northwind.example", hashes.SHA256())
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    elif spec.kind == "mlkem768_public":
        key = MLKEM768PrivateKey.generate()
        # Standard SubjectPublicKeyInfo, exactly as OpenSSL 3.5+ would write it.
        # The scanner identifies it by its algorithm OID (2.16.840.1.101.3.4.4.2),
        # the same way it identifies RSA — no special-casing.
        path.write_bytes(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    elif spec.kind == "mlkem_metadata":
        # Some real estates declare their crypto suite in deployment manifests
        # rather than shipping a key file. The scanner reads these too, and
        # labels them as DECLARED rather than VERIFIED — an important
        # distinction, because a manifest is a claim, not proof.
        path.write_text(
            json.dumps(
                {
                    "service": "quantum-safe-service",
                    "key_exchange": "ML-KEM-768",
                    "signature": "ECDSA-P256",
                    "symmetric": "AES-256-GCM",
                    "standard": "NIST FIPS 203",
                    "hybrid_mode": True,
                    "hybrid_classical_component": "X25519",
                    "migrated_on": "2026-03-11",
                },
                indent=2,
            )
        )

    elif spec.kind == "malformed":
        # A deliberately broken file. Real estates are full of these: truncated
        # backups, half-copied keys, files with the wrong extension. A scanner
        # that crashes on the first bad file is useless in production, so the
        # demo environment ships one to prove ours does not.
        path.write_text(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"
            "vGZlGJpmn65+A4xHXInJYiPuKzrKUnAp<<<TRUNCATED BY BACKUP FAILURE>>>\n"
        )

    else:  # pragma: no cover — guards against a typo in ENTERPRISE_ASSETS
        raise ValueError(f"Unknown asset kind: {spec.kind!r}")


def _asset_metadata(spec: AssetSpec) -> dict[str, Any]:
    """Business context for one asset, written alongside it as ``asset.json``.

    Real scanners get this from a CMDB or asset inventory. Reading it from a
    sidecar file keeps the scanner's risk model driven by declared business
    facts rather than guesses baked into the code — which is what makes the risk
    scoring explainable rather than arbitrary.
    """
    return {
        "system_name": spec.system_name,
        "business_context": spec.business_context,
        "data_sensitivity": spec.data_sensitivity,
        "retention_years": spec.retention_years,
    }


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def is_generated(root: Path | None = None) -> bool:
    """True if a current-version demo environment already exists on disk."""
    root = root or DEMO_ENTERPRISE_DIR
    manifest = root / "manifest.json"
    if not manifest.exists():
        return False
    try:
        return json.loads(manifest.read_text()).get("version") == MANIFEST_VERSION
    except (json.JSONDecodeError, OSError):
        return False


def generate(root: Path | None = None, force: bool = False) -> dict[str, Any]:
    """Create the fictional enterprise on disk.

    Args:
        root: Destination directory. Defaults to :data:`DEMO_ENTERPRISE_DIR`.
        force: Regenerate even if a current environment already exists.

    Returns:
        The manifest describing what was created.
    """
    root = root or DEMO_ENTERPRISE_DIR

    if is_generated(root) and not force:
        return json.loads((root / "manifest.json").read_text())

    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)

    entries: list[dict[str, Any]] = []
    by_directory: dict[str, list[AssetSpec]] = {}

    for spec in ENTERPRISE_ASSETS:
        target_dir = root / spec.directory
        target_dir.mkdir(parents=True, exist_ok=True)
        target_file = target_dir / spec.filename

        _generate_asset(spec, target_file)
        by_directory.setdefault(spec.directory, []).append(spec)

        entries.append(
            {
                "path": str(target_file.relative_to(root)).replace("\\", "/"),
                "directory": spec.directory,
                "system_name": spec.system_name,
                "kind": spec.kind,
                "business_context": spec.business_context,
                "data_sensitivity": spec.data_sensitivity,
                "retention_years": spec.retention_years,
                "bytes": target_file.stat().st_size,
            }
        )

    # One asset.json per directory, keyed by filename.
    for directory, specs in by_directory.items():
        (root / directory / "asset.json").write_text(
            json.dumps(
                {spec.filename: _asset_metadata(spec) for spec in specs},
                indent=2,
            )
        )

    manifest = {
        "version": MANIFEST_VERSION,
        "organisation": "Northwind Systems (fictional)",
        "generated_offline": True,
        "asset_count": len(entries),
        "assets": entries,
        "note": (
            "All cryptographic material is genuine and generated locally. "
            "Certificates are self-signed; no certificate authority, network "
            "connection, or external service is used."
        ),
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def ensure_generated(root: Path | None = None) -> Path:
    """Generate the environment if absent, and return its path."""
    root = root or DEMO_ENTERPRISE_DIR
    if not is_generated(root):
        generate(root)
    return root
