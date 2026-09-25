"""
Aegis PQC — certificate and key discovery adapter.

Discovers cryptographic material in X.509 certificates, public keys, private
keys, and deployment manifests, emitting the canonical
:class:`~backend.model.CryptoFinding`.

WHY THIS WRAPS ``scanner.py`` RATHER THAN REPLACING IT
------------------------------------------------------
The parsing logic in :mod:`backend.scanner` is the most thoroughly exercised
code in the project: a two-tier strategy that first asks ``cryptography`` to
load the artefact, then falls back to walking the DER and extracting the
algorithm OID directly. That fallback is what lets Aegis identify ML-DSA and
SLH-DSA keys the Python library cannot load at all, and it is covered by 38
inherited tests.

Rewriting it to emit the new model would duplicate that logic and put those
tests at risk for no functional gain. Instead, ``scanner.py`` becomes an
internal parsing library, and this adapter maps its output into the canonical
three-layer model.

The result: ECDAT components see only :class:`CryptoAsset`; the inherited
Security Lab surfaces keep their flat ``Finding``; and there is exactly one
implementation of certificate parsing in the codebase.

WHAT THIS ADAPTER DOES NOT DO
-----------------------------
It does not validate certificate chains, check revocation, or open
password-protected keystores. Those limits are declared in :meth:`coverage` and
rendered in the dashboard rather than left for a reviewer to discover.
"""

from __future__ import annotations

from pathlib import Path

from backend import discovery, scanner
from backend.model import (
    ArtefactType,
    CertificateFacts,
    Confidence,
    CoverageStatement,
    CryptoFinding,
    DetectionMethod,
    ScanResult,
    ScanStatus,
    SourceType,
    utc_now,
)
from backend.discovery import ScanLimits, safe_walk

#: Suffixes this adapter will open. Mirrors the proven scanner's own list so the
#: two never drift apart.
CERTIFICATE_SUFFIXES: frozenset[str] = frozenset(scanner.SCANNABLE_SUFFIXES)

#: Maps the legacy scanner's ``file_type`` string onto the canonical artefact
#: type and the detection method that produced it.
_FILE_TYPE_MAP: dict[str, tuple[ArtefactType, DetectionMethod, Confidence]] = {
    "X.509 certificate": (ArtefactType.CERTIFICATE, DetectionMethod.LIBRARY_PARSE, Confidence.HIGH),
    "Public key": (ArtefactType.KEY, DetectionMethod.LIBRARY_PARSE, Confidence.HIGH),
    "Private key": (ArtefactType.KEY, DetectionMethod.LIBRARY_PARSE, Confidence.HIGH),
    "Public key (identified by OID)": (
        ArtefactType.KEY,
        DetectionMethod.OID_EXTRACTION,
        Confidence.HIGH,
    ),
    "Deployment manifest": (ArtefactType.ALGORITHM, DetectionMethod.DECLARED, Confidence.MEDIUM),
    "Unparseable": (ArtefactType.UNKNOWN, DetectionMethod.LIBRARY_PARSE, Confidence.LOW),
    "Unrecognised": (ArtefactType.UNKNOWN, DetectionMethod.LIBRARY_PARSE, Confidence.LOW),
    "Unreadable": (ArtefactType.UNKNOWN, DetectionMethod.LIBRARY_PARSE, Confidence.LOW),
}


def _key_size_to_int(raw: str) -> int | None:
    """Convert the legacy key-size string to an integer where meaningful.

    The legacy field is overloaded: it holds ``"2048"`` for RSA but ``"SECP256R1"``
    for elliptic curves and ``"768"`` for ML-KEM parameter sets. Only genuine
    bit-lengths become integers; curve names stay in ``variant`` instead of
    being coerced into a number they are not.
    """
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _build_variant(algorithm: str, key_size_raw: str) -> str:
    """Compose the most specific designation available, e.g. ``RSA-2048``.

    Three shapes exist because the legacy ``key_size`` field is overloaded:

    * Bit length      → ``RSA-2048``
    * Curve name      → ``SECP256R1`` (the curve *is* the designation; appending
                        it to ``ECDSA / ECDH`` would produce nonsense)
    * Parameter set   → ``ML-KEM-768`` (already fully qualified)
    """
    if not algorithm:
        return ""
    if not key_size_raw:
        return algorithm
    if algorithm.startswith(("ML-KEM", "ML-DSA", "SLH-DSA")):
        return algorithm
    # A non-numeric key size is a named curve, which stands alone as the variant.
    if not key_size_raw.isdigit():
        return key_size_raw
    return f"{algorithm}-{key_size_raw}"


def _certificate_facts(detail: dict) -> CertificateFacts | None:
    """Extract X.509 facts from the legacy detail dict, when present."""
    if not any(k in detail for k in ("subject", "not_valid_after", "signature_algorithm")):
        return None
    subject = str(detail.get("subject", ""))
    issuer = str(detail.get("issuer", subject))
    return CertificateFacts(
        subject=subject,
        issuer=issuer,
        not_after=str(detail.get("not_valid_after", "")),
        signature_algorithm=str(detail.get("signature_algorithm", "")),
        # The demo estate's certificates are self-signed; the legacy parser does
        # not record issuer separately, so this is inferred only when the two
        # match. Chain validation is explicitly out of scope — see coverage().
        is_self_signed=bool(subject and issuer == subject),
    )


def to_finding(
    legacy: scanner.Finding,
    scan_id: str,
    component: str = "",
) -> CryptoFinding:
    """Map one legacy :class:`scanner.Finding` onto the canonical model.

    Only observed facts are carried across. The legacy record also holds
    business context and a computed risk rating; those belong to layers 2 and 3
    and are deliberately dropped here — re-deriving them under the new risk
    model is the assessment engine's job, not discovery's.

    Args:
        legacy: A finding from the proven certificate parser.
        scan_id: Scan this finding belongs to.
        component: Owning application, if the caller can resolve one.

    Returns:
        The canonical observed-facts record.
    """
    artefact_type, method, confidence = _FILE_TYPE_MAP.get(
        legacy.file_type, (ArtefactType.UNKNOWN, DetectionMethod.LIBRARY_PARSE, Confidence.LOW)
    )

    detail = dict(legacy.detail)
    oid = str(detail.get("algorithm_oid", ""))

    # A DER-extracted OID is direct structural evidence; prefer it over the
    # file path, which says nothing about what the artefact actually is.
    evidence = oid or legacy.evidence or Path(legacy.path).name

    # The legacy evidence field carries VERIFIED / DECLARED. DECLARED means the
    # algorithm was read from a manifest — an operator's claim about what is
    # deployed, not proof. That distinction survives into the detection method.
    if legacy.evidence == scanner.EVIDENCE_DECLARED:
        method = DetectionMethod.DECLARED
        confidence = Confidence.MEDIUM

    key_size_raw = legacy.key_size or ""

    return CryptoFinding(
        finding_id=CryptoFinding.compute_id(
            scan_id, legacy.path, legacy.algorithm, None, evidence
        ),
        scan_id=scan_id,
        artefact_type=artefact_type,
        algorithm=legacy.algorithm,
        algorithm_family=legacy.algorithm_family,
        variant=_build_variant(legacy.algorithm, key_size_raw),
        key_size=_key_size_to_int(key_size_raw),
        oid=oid,
        certificate=_certificate_facts(detail),
        source_type=SourceType.CERTIFICATE_FILE,
        location=legacy.path,
        component=component or legacy.system_name,
        detection_method=method,
        evidence=evidence,
        confidence=confidence,
        raw_detail={
            **detail,
            # Preserved so the UI can still show the human label the legacy
            # parser produced, and so the two systems remain traceable.
            "legacy_file_type": legacy.file_type,
            "legacy_system_name": legacy.system_name,
            "legacy_evidence_level": legacy.evidence,
            **({"parse_error": legacy.error} if legacy.error else {}),
        },
    )


class CertificateAdapter:
    """Discovery adapter for certificates, keys, and deployment manifests."""

    name = "certificates"

    def coverage(self) -> CoverageStatement:
        """Declared scope. Rendered in the dashboard beside the results."""
        return CoverageStatement(
            adapter=self.name,
            supported=[
                "X.509 certificates (PEM and DER)",
                "Public and private keys (PEM and DER, unencrypted)",
                "Algorithm identification by ASN.1 OID, including post-quantum "
                "algorithms the Python library cannot load",
                "RSA, DSA, Diffie-Hellman, ECDSA/ECDH, Ed25519/Ed448, "
                "X25519/X448, ML-KEM, ML-DSA, SLH-DSA",
                "Deployment manifests declaring a cryptographic suite",
            ],
            not_supported=[
                "Certificate chain validation",
                "Revocation checking (OCSP, CRL)",
                "PKCS#12 (.p12/.pfx) and Java KeyStore (.jks)",
                "Password-protected private keys",
                "Hardware security module inventory",
            ],
            confidence_notes=(
                "Artefacts parsed structurally or identified by OID are HIGH "
                "confidence. Algorithms read from deployment manifests are "
                "MEDIUM: a manifest records what an operator declared, which is "
                "not proof of what is deployed."
            ),
        )

    def supports(self, target: Path) -> bool:
        """True for a directory, or a file with a recognised suffix."""
        target = Path(target)
        if target.is_dir():
            return True
        return target.suffix.lower() in CERTIFICATE_SUFFIXES

    def scan(self, target: Path, scan_id: str, limits: ScanLimits | None = None) -> ScanResult:
        """Scan ``target`` for cryptographic material.

        Args:
            target: Directory or single file.
            scan_id: Scan this run belongs to.
            limits: Traversal and size bounds. Defaults applied if omitted.

        Returns:
            Findings, coverage, and any errors encountered. A file that cannot
            be parsed is reported as an error rather than silently dropped.
        """
        limits = limits or ScanLimits()
        target = Path(target)
        started = utc_now()

        findings: list[CryptoFinding] = []
        errors: list[str] = []
        files_examined = 0

        if not target.exists():
            return ScanResult(
                scan_id=scan_id,
                adapter=self.name,
                target=str(target),
                status=ScanStatus.FAILED,
                coverage=self.coverage(),
                errors=[f"Target does not exist: {target}"],
                started_at=started,
                completed_at=utc_now(),
            )

        walk_stats = None
        for path, stats in safe_walk(target, limits, suffixes=CERTIFICATE_SUFFIXES):
            walk_stats = stats
            files_examined = stats.files_examined

            if path.name in scanner.METADATA_FILENAMES:
                continue

            try:
                meta = scanner._load_directory_metadata(path.parent)
                legacy = scanner.scan_file(path, meta.get(path.name, {}))
            except Exception as exc:
                # Defensive: the parser is well covered, but this adapter runs
                # against untrusted input and must never abort a whole scan
                # because of one hostile file.
                errors.append(f"{path.name}: {exc}")
                continue

            if legacy is None:
                continue

            component = self._resolve_component(target, path, legacy)
            findings.append(to_finding(legacy, scan_id, component))

        if walk_stats:
            errors.extend(walk_stats.notes())

        return ScanResult(
            scan_id=scan_id,
            adapter=self.name,
            target=str(target),
            status=ScanStatus.PARTIAL if errors else ScanStatus.COMPLETED,
            findings=findings,
            coverage=self.coverage(),
            errors=errors,
            files_examined=files_examined,
            started_at=started,
            completed_at=utc_now(),
        )

    @staticmethod
    def _resolve_component(root: Path, path: Path, legacy: scanner.Finding) -> str:
        """Infer the owning application for a discovered artefact.

        Uses the first path segment below the scan root, which matches how an
        application estate is normally laid out. Falls back to the legacy
        system name, then the parent directory. Nothing here is guessed beyond
        directory structure, and the value is refined by declared context when
        one exists.
        """
        try:
            relative = path.resolve(strict=False).relative_to(root.resolve(strict=False))
            if len(relative.parts) > 1:
                return relative.parts[0]
        except ValueError:
            pass
        return legacy.system_name or path.parent.name


#: Module-level instance, registered for lookup by name.
CERTIFICATE_ADAPTER = discovery.register(CertificateAdapter())
