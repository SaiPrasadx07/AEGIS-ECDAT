"""
Aegis PQC — canonical ECDAT data model.

This module defines the three-layer cryptographic asset model that every ECDAT
component reads and writes. It is the contract between discovery, assessment,
CBOM export, and the dashboard.

WHY THREE LAYERS
----------------
An earlier design flattened everything into one record. That made a specific
question unanswerable: *which parts of this did you discover, and which did you
assume?*

Three kinds of information live in a cryptographic asset, and they have
different epistemic status:

1. :class:`CryptoFinding` — **facts a scanner observed.** "Line 42 of
   payments/keys.py calls ``rsa.generate_private_key(key_size=2048)``."
   Provable, carries evidence, never invented.

2. :class:`ApplicationContext` — **context the organisation supplied.**
   "Payments data must stay confidential for 25 years." A scanner cannot
   discover this. It is declared, and :class:`ContextSource` records who
   declared it.

3. :class:`AssetAssessment` — **conclusions Aegis computed** from 1 and 2.
   "CRITICAL, migrate first, move to hybrid X25519+ML-KEM-768." Reproducible
   from its inputs.

:class:`CryptoAsset` binds the three together for transport and display.

Keeping them separate is not architectural purity — it is what lets the product
answer the hardest question a reviewer can ask, and it is why provenance appears
on every context value in the UI.

VOCABULARY
----------
Two naming decisions are deliberate and should not be "simplified" later:

* There is no risk level called ``SAFE``. Post-quantum cryptography is
  *designed to resist currently known attacks*; calling it safe asserts a
  guarantee nobody can make. The equivalent level is :attr:`RiskLevel.PQC_READY`
  for verified post-quantum material, and :attr:`RiskLevel.LOW_BASELINE` for
  everything else that carries no quantum exposure.

* Remediation is classified by *kind*, not lumped under "PQC". Replacing
  AES-128 with AES-256 is classical strengthening against Grover's algorithm,
  not a post-quantum migration. Flagging MD5 is a pre-existing weakness with no
  quantum dimension at all. See :class:`RemediationClass`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

# ==========================================================================
# Vocabulary
# ==========================================================================


class ContainerFormat(str, Enum):
    """Container image layouts the scanner recognises."""

    OCI_LAYOUT = "oci_layout"
    DOCKER_ARCHIVE = "docker_archive"
    LAYER_TAR = "layer_tar"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ContainerProvenance:
    """Where inside a container image a finding originated.

    Attached to a finding discovered through the container adapter, in addition
    to everything the underlying surface already recorded. The point is that a
    container finding loses nothing: it is a full source/binary/dependency
    finding *plus* the image, layer, and in-image path that locate it.

    Attributes:
        image_reference: Image name and tag, e.g. ``payments-api:2026.09``.
        image_config_ref: Reference to the image config. For an OCI layout this
            is a genuine SHA-256 manifest digest; for a Docker archive it is the
            config member name (often digest-derived, but not verified as such).
            ``image_config_is_digest`` says which.
        image_config_is_digest: True when ``image_config_ref`` is a verified
            content digest.
        layer_digest: SHA-256 of the layer bytes the artefact was found in,
            computed on read. A genuine content digest.
        layer_index: Ordinal of that layer, for human-readable ordering.
        image_path: Path of the artefact inside the image filesystem, e.g.
            ``/app/bin/crypto_service`` — not the temporary extraction path.
        discovery_surface: Which underlying adapter produced the finding.
    """

    image_reference: str = ""
    image_config_ref: str = ""
    image_config_is_digest: bool = False
    layer_digest: str = ""
    layer_index: int | None = None
    image_path: str = ""
    discovery_surface: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "image_reference": self.image_reference,
            "image_config_ref": self.image_config_ref,
            "image_config_is_digest": self.image_config_is_digest,
            "layer_digest": self.layer_digest,
            "layer_index": self.layer_index,
            "image_path": self.image_path,
            "discovery_surface": self.discovery_surface,
        }


class BinaryEvidenceLevel(str, Enum):
    """How strongly a binary finding demonstrates cryptographic use.

    Binary analysis is inference from structure, not from behaviour. Nothing
    here is as strong as an AST-matched call site, and the levels below record
    which kind of structural evidence was found.

    LINKED_LIBRARY
        A cryptographic library appears in the dynamic dependency table
        (``DT_NEEDED`` on ELF, the import directory on PE). The library is
        linked; which of its functions the program reaches is a separate
        question.

    IMPORTED_SYMBOL
        A specific cryptographic function appears in the import table. The
        linker resolved a reference to it, so the code refers to that
        primitive by name. This is the strongest binary evidence available
        without disassembly.

    EMBEDDED_STRING
        A version banner or algorithm name appears in the binary's string
        data. Useful for identifying a library *version*, which nothing else
        reveals, but a string may be inert data rather than evidence of use.
    """

    LINKED_LIBRARY = "linked_library"
    IMPORTED_SYMBOL = "imported_symbol"
    EMBEDDED_STRING = "embedded_string"


class BinaryFormat(str, Enum):
    """Executable formats the binary scanner recognises."""

    ELF = "elf"
    PE = "pe"
    MACHO = "macho"
    UNKNOWN = "unknown"


class SourceEvidenceLevel(str, Enum):
    """How strongly a source finding demonstrates cryptographic *use*.

    Source analysis produces claims of materially different strength, and
    collapsing them would be the central dishonesty available to a source
    scanner. An import proves a module is referenced. A call site proves the
    primitive is invoked. Those are not the same statement.

    IMPORT
        ``from cryptography.hazmat.primitives.asymmetric import rsa``
        The module is referenced. It may be unused, re-exported, or imported
        for a type annotation. This is *capability in reach*, not usage.

    CALL_SITE
        ``rsa.generate_private_key(key_size=2048)``
        The primitive is invoked. This is the strongest source evidence
        available without executing the program.

    CONFIGURATION
        ``AES.MODE_ECB``, ``Cipher.getInstance("AES/ECB/PKCS5Padding")``
        A specific algorithm, mode, or parameter is named. Strong evidence
        that the configuration is intended, though the surrounding call may
        sit on a dead path.
    """

    IMPORT = "import"
    CALL_SITE = "call_site"
    CONFIGURATION = "configuration"


class SourceLanguage(str, Enum):
    """Languages the source scanner analyses."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"


class ArtefactType(str, Enum):
    """What kind of cryptographic artefact a finding describes.

    Mirrors the artefact categories named in PS 26164: algorithms, keys,
    certificates, protocols, libraries, hardware modules, cloud services.
    """

    ALGORITHM = "algorithm"
    KEY = "key"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    LIBRARY = "library"
    HARDWARE_MODULE = "hardware_module"
    CLOUD_SERVICE = "cloud_service"
    UNKNOWN = "unknown"


class SourceType(str, Enum):
    """Which discovery surface a finding came from."""

    SOURCE_CODE = "source_code"
    DEPENDENCY = "dependency"
    BINARY = "binary"
    CONTAINER = "container"
    CERTIFICATE_FILE = "certificate_file"
    CONFIGURATION = "configuration"


class DetectionMethod(str, Enum):
    """How the artefact was identified.

    This is *how we know*, which is separate from *how confident we are*. A
    manifest declaration can be parsed with total certainty while proving
    nothing about what is actually deployed.
    """

    AST_PARSE = "ast_parse"
    PATTERN_MATCH = "pattern_match"
    OID_EXTRACTION = "oid_extraction"
    LIBRARY_PARSE = "library_parse"
    MANIFEST_PARSE = "manifest_parse"
    SYMBOL_TABLE = "symbol_table"
    STRING_MATCH = "string_match"
    DECLARED = "declared"


class Confidence(str, Enum):
    """How much weight the detection deserves.

    HIGH    Parsed structurally; the artefact is unambiguous.
            (DER OID; an AST call node with a literal argument.)
    MEDIUM  Strong, structurally located indicator, but inference is involved.
            (A crypto library import; a symbol in an import table.)
    LOW     Textual indicator only.
            (A version string embedded in a binary.)
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class QuantumStatus(str, Enum):
    """An artefact's exposure to a cryptographically relevant quantum computer."""

    VULNERABLE = "quantum_vulnerable"
    POST_QUANTUM = "post_quantum"
    HYBRID = "hybrid"
    SYMMETRIC_REDUCED = "symmetric_reduced_margin"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Assessed Harvest-Now-Decrypt-Later exposure.

    Note the absence of ``SAFE`` — see the module docstring. ``PQC_READY``
    states what was actually established (post-quantum material, verified),
    and ``LOW_BASELINE`` states the absence of quantum exposure without
    claiming the asset is beyond criticism.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW_BASELINE = "LOW BASELINE"
    PQC_READY = "PQC READY"
    UNKNOWN = "UNKNOWN"


#: Migration ordering. Lower rank is more urgent. UNKNOWN outranks the settled
#: low levels because an asset nobody can identify is precisely the one a
#: migration programme must not lose track of.
RISK_RANK: dict[RiskLevel, int] = {
    RiskLevel.CRITICAL: 0,
    RiskLevel.HIGH: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.UNKNOWN: 3,
    RiskLevel.LOW_BASELINE: 4,
    RiskLevel.PQC_READY: 5,
}


class RemediationClass(str, Enum):
    """What *kind* of change a recommendation represents.

    Collapsing these into one "PQC migration" bucket would misrepresent the
    threat model. Moving AES-128 to AES-256 addresses Grover's quadratic
    speedup, not Shor's algorithm. Replacing MD5 addresses a break that has
    nothing to do with quantum computing at all.
    """

    PQC_NATIVE = "pqc_native"
    HYBRID = "hybrid"
    CLASSICAL_STRENGTHENING = "classical_strengthening"
    NON_QUANTUM_ISSUE = "non_quantum_issue"
    NONE_REQUIRED = "none_required"
    #: A library capability was detected but no algorithm usage was established,
    #: so no application-level remediation can be recommended. Distinct from
    #: NONE_REQUIRED (a healthy asset) — here the question is simply unanswered.
    USAGE_NOT_ESTABLISHED = "usage_not_established"
    #: The available evidence does not support any concrete remediation
    #: direction — an unknown algorithm, an unresolved role, or a
    #: protocol whose negotiated suite is not known.
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class ContextSource(str, Enum):
    """Where a business-context value came from.

    Rendered in the UI beside every context value. The honest answer to "how do
    you know this data lives 25 years?" is "we do not — here is who said so."
    """

    POLICY_FILE = "policy_file"
    USER_INPUT = "user_input"
    DEFAULT = "default"


class Sensitivity(str, Enum):
    """Data sensitivity, declared by the organisation."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class BusinessCriticality(str, Enum):
    """Operational criticality of the owning system.

    Deliberately separate from :class:`Sensitivity`. A public status page can be
    mission-critical while holding no sensitive data; an archived dataset can be
    highly sensitive while being operationally irrelevant. Conflating them, as
    the original prototype did, loses a real distinction.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MoscaVerdict(str, Enum):
    """Outcome of the Mosca inequality."""

    EXPOSED = "exposed"
    ACCEPTABLE = "acceptable"
    UNDETERMINED = "undetermined"


# ==========================================================================
# Layer 1 — observed facts
# ==========================================================================


@dataclass(frozen=True, slots=True)
class CertificateFacts:
    """X.509 details, when the artefact is a certificate."""

    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    signature_algorithm: str = ""
    is_self_signed: bool = False
    serial_number: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "signature_algorithm": self.signature_algorithm,
            "is_self_signed": self.is_self_signed,
            "serial_number": self.serial_number,
        }


@dataclass(frozen=True, slots=True)
class CryptoFinding:
    """Layer 1 — what a scanner actually observed.

    Every field here is either read directly from an artefact or left empty.
    Nothing in this layer is inferred from business context, and nothing is
    computed. If a scanner cannot establish a value, it stays blank rather than
    being guessed.

    Attributes:
        finding_id: Deterministic identifier — see :meth:`compute_id`.
        artefact_type: Which PS 26164 artefact category this is.
        algorithm: Base algorithm name, e.g. ``RSA``, ``AES``, ``ML-KEM``.
        algorithm_family: Grouping used for reporting, e.g. ``Elliptic curve``.
        variant: Full designation where known, e.g. ``RSA-2048``, ``P-256``.
        key_size: Key size in bits, when meaningful and determinable.
        mode: Mode of operation, e.g. ``GCM``, ``CBC``, ``ECB``.
        oid: ASN.1 object identifier, when the artefact carries one.
        library / library_version: Providing library, when identifiable.
        protocol: Protocol and version, e.g. ``TLS 1.2``.
        certificate: Populated only for certificate artefacts.
        source_type: Which discovery surface produced this.
        location: Path, or path-like locator inside an archive.
        line: Line number for source findings.
        component: Owning application, when resolvable.
        detection_method: How the artefact was identified.
        evidence: The literal matched text, symbol, or OID. Never fabricated.
        confidence: Weight the detection deserves.
        raw_detail: Adapter-specific extras, for display and debugging.
    """

    finding_id: str
    scan_id: str

    # --- what ---
    artefact_type: ArtefactType = ArtefactType.UNKNOWN
    algorithm: str = ""
    algorithm_family: str = ""
    variant: str = ""
    key_size: int | None = None
    mode: str = ""
    oid: str = ""
    library: str = ""
    library_version: str = ""
    protocol: str = ""
    certificate: CertificateFacts | None = None

    # --- where ---
    source_type: SourceType = SourceType.CERTIFICATE_FILE
    location: str = ""
    line: int | None = None
    component: str = ""

    # --- how we know ---
    detection_method: DetectionMethod = DetectionMethod.LIBRARY_PARSE
    evidence: str = ""
    confidence: Confidence = Confidence.MEDIUM

    raw_detail: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def compute_id(scan_id: str, location: str, algorithm: str, line: int | None, evidence: str) -> str:
        """Build a deterministic finding id.

        Determinism matters for two reasons: re-scanning an unchanged estate
        must produce identical ids so scan-to-scan diffing works, and tests must
        be reproducible. A random UUID would break both.
        """
        digest = hashlib.sha256(
            "|".join([scan_id, location, algorithm, str(line or ""), evidence[:200]]).encode(
                "utf-8", errors="replace"
            )
        ).hexdigest()[:12]
        return f"fnd_{digest}"

    @property
    def display_name(self) -> str:
        """Human label, preferring the most specific designation available."""
        if self.variant:
            return self.variant
        if self.algorithm and self.key_size:
            return f"{self.algorithm}-{self.key_size}"
        return self.algorithm or "unidentified"

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "scan_id": self.scan_id,
            "artefact_type": self.artefact_type.value,
            "algorithm": self.algorithm,
            "algorithm_family": self.algorithm_family,
            "variant": self.variant,
            "display_name": self.display_name,
            "key_size": self.key_size,
            "mode": self.mode,
            "oid": self.oid,
            "library": self.library,
            "library_version": self.library_version,
            "protocol": self.protocol,
            "certificate": self.certificate.to_dict() if self.certificate else None,
            "source_type": self.source_type.value,
            "location": self.location,
            "line": self.line,
            "component": self.component,
            "detection_method": self.detection_method.value,
            "evidence": self.evidence,
            "confidence": self.confidence.value,
            "raw_detail": dict(self.raw_detail),
        }


# ==========================================================================
# Layer 2 — organisation context
# ==========================================================================

#: Defaults used when neither a policy file nor user input supplies context.
#: Deliberately middle-of-the-road: overstating would inflate risk ratings on
#: no evidence, understating would hide real exposure. Always reported as
#: ``ContextSource.DEFAULT`` so a reviewer can see it was not declared.
DEFAULT_DATA_LIFETIME_YEARS: int = 5
DEFAULT_SENSITIVITY: Sensitivity = Sensitivity.MEDIUM
DEFAULT_CRITICALITY: BusinessCriticality = BusinessCriticality.MEDIUM


@dataclass(frozen=True, slots=True)
class ApplicationContext:
    """Layer 2 — business context the organisation declares.

    None of this is discoverable by scanning. A repository does not state how
    long its data must remain confidential. :attr:`context_source` records, per
    application, where the values came from, and the dashboard shows it.

    Attributes:
        component: Application this context describes.
        data_sensitivity: How sensitive the protected data is.
        data_lifetime_years: How long confidentiality must hold. This is ``X``
            in the Mosca inequality and the strongest driver of risk.
        business_criticality: Operational importance of the system — a separate
            axis from sensitivity.
        context_source: Provenance of these values.
        notes: Free-text justification, shown in the UI when present.
    """

    component: str
    data_sensitivity: Sensitivity = DEFAULT_SENSITIVITY
    data_lifetime_years: int = DEFAULT_DATA_LIFETIME_YEARS
    business_criticality: BusinessCriticality = DEFAULT_CRITICALITY
    context_source: ContextSource = ContextSource.DEFAULT
    notes: str = ""

    @property
    def is_declared(self) -> bool:
        """True if a human supplied these values rather than falling back."""
        return self.context_source is not ContextSource.DEFAULT

    @classmethod
    def default_for(cls, component: str) -> ApplicationContext:
        """Documented fallback context, explicitly marked as undeclared."""
        return cls(component=component, context_source=ContextSource.DEFAULT)

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "data_sensitivity": self.data_sensitivity.value,
            "data_lifetime_years": self.data_lifetime_years,
            "business_criticality": self.business_criticality.value,
            "context_source": self.context_source.value,
            "is_declared": self.is_declared,
            "notes": self.notes,
        }


# ==========================================================================
# Layer 3 — computed conclusions
# ==========================================================================


@dataclass(frozen=True, slots=True)
class MoscaResult:
    """Outcome of Mosca's inequality, with its inputs retained.

    The inputs are kept alongside the verdict so the UI can render
    *inputs → calculation → result* without recomputing, and so a reviewer can
    check the arithmetic.

    ``X + Y > Z`` means the data's required secrecy window, plus the time to
    migrate, extends past the point where the protection may no longer hold.
    """

    x_data_lifetime_years: float
    y_migration_years: float
    z_horizon_years: float
    verdict: MoscaVerdict
    margin_years: float

    @property
    def statement(self) -> str:
        """One-line plain-language rendering of the calculation."""
        total = self.x_data_lifetime_years + self.y_migration_years
        comparison = ">" if total > self.z_horizon_years else "<="
        return (
            f"X({self.x_data_lifetime_years:g}) + Y({self.y_migration_years:g}) "
            f"= {total:g} {comparison} Z({self.z_horizon_years:g})"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "x_data_lifetime_years": self.x_data_lifetime_years,
            "y_migration_years": self.y_migration_years,
            "z_horizon_years": self.z_horizon_years,
            "verdict": self.verdict.value,
            "margin_years": self.margin_years,
            "statement": self.statement,
        }


@dataclass(frozen=True, slots=True)
class Recommendation:
    """A proposed replacement, classified by the kind of change it represents."""

    target: str
    remediation_class: RemediationClass
    standard: str = ""
    rationale: str = ""
    migration_complexity: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "remediation_class": self.remediation_class.value,
            "standard": self.standard,
            "rationale": self.rationale,
            "migration_complexity": self.migration_complexity,
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class AssetAssessment:
    """Layer 3 — what Aegis concluded, and why.

    Every field is reproducible from a :class:`CryptoFinding` plus an
    :class:`ApplicationContext`. :attr:`rationale` carries one readable sentence
    per step actually taken, so a reviewer opening an asset can follow the
    reasoning end to end rather than being handed a score.
    """

    finding_id: str
    quantum_status: QuantumStatus
    quantum_vulnerable: bool
    vulnerability_basis: str = ""
    mosca: MoscaResult | None = None
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    rationale: list[str] = field(default_factory=list)
    recommendation: Recommendation | None = None
    migration_priority: int | None = None
    assessed_at: str = ""

    @property
    def risk_rank(self) -> int:
        """Sort key for migration ordering."""
        return RISK_RANK.get(self.risk_level, 99)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "quantum_status": self.quantum_status.value,
            "quantum_vulnerable": self.quantum_vulnerable,
            "vulnerability_basis": self.vulnerability_basis,
            "mosca": self.mosca.to_dict() if self.mosca else None,
            "risk_level": self.risk_level.value,
            "risk_rank": self.risk_rank,
            "rationale": list(self.rationale),
            "recommendation": self.recommendation.to_dict() if self.recommendation else None,
            "migration_priority": self.migration_priority,
            "assessed_at": self.assessed_at,
        }


# ==========================================================================
# Quantum risk (Phase 7)
# ==========================================================================


class QuantumCategory(str, Enum):
    """An algorithm's relationship with a cryptographically relevant quantum
    computer.

    Distinct from :class:`QuantumStatus` (the discovery-time exposure of an
    artefact) — this is the *classification the risk engine assigns to an
    algorithm* from the knowledge base.

    QUANTUM_VULNERABLE
        Public-key cryptography a CRQC defeats via Shor's algorithm.
    SYMMETRIC_REDUCED
        Symmetric ciphers and hashes. Grover gives at most a quadratic
        speedup; not equivalent to the public-key case.
    POST_QUANTUM
        NIST post-quantum algorithms designed to resist a CRQC.
    NOT_APPLICABLE
        KDFs/MACs whose exposure follows their underlying primitive.
    CAPABILITY_ONLY
        A library that merely *provides* cryptography; no algorithm usage is
        established, so no algorithm-level quantum claim is made.
    PROTOCOL_DEPENDENT
        A protocol whose exposure depends on the negotiated suite.
    UNKNOWN
        An algorithm absent from the knowledge base. Never guessed.
    """

    QUANTUM_VULNERABLE = "quantum_vulnerable"
    SYMMETRIC_REDUCED = "symmetric_reduced"
    POST_QUANTUM = "post_quantum"
    NOT_APPLICABLE = "not_applicable"
    CAPABILITY_ONLY = "capability_only"
    PROTOCOL_DEPENDENT = "protocol_dependent"
    UNKNOWN = "unknown"


class MoscaStatus(str, Enum):
    """Outcome of the Mosca time-horizon analysis.

    Separate from :class:`MoscaVerdict` so that "we could not decide" is a
    first-class outcome rather than being conflated with "acceptable".

    WITHIN_QUANTUM_WINDOW
        Data lifetime + migration time extends past the CRQC horizon. The
        protection requirement reaches into the assumed quantum-threat window.
    OUTSIDE_QUANTUM_WINDOW
        The combined horizon stays within the CRQC assumption. Note this is
        *conditional on the assumption*, not a statement that the asset is safe.
    INSUFFICIENT_INFORMATION
        A required input (data lifetime, migration time, or CRQC horizon) was
        missing, so no time-horizon conclusion can be drawn.
    NOT_TIME_SENSITIVE
        The algorithm is not quantum-vulnerable public-key cryptography, so the
        Mosca time-horizon question does not apply in the same way.
    """

    WITHIN_QUANTUM_WINDOW = "within_quantum_window"
    OUTSIDE_QUANTUM_WINDOW = "outside_quantum_window"
    INSUFFICIENT_INFORMATION = "insufficient_information"
    NOT_TIME_SENSITIVE = "not_time_sensitive"


@dataclass(frozen=True, slots=True)
class RiskAssumption:
    """One input to the risk analysis, with its provenance.

    Every quantity the Mosca analysis depends on — data lifetime, migration
    time, the CRQC horizon — is carried as one of these, so a reviewer can see
    not just the value but where it came from and whether it was observed,
    supplied, or defaulted. A CRQC horizon is an assumption, never a fact, and
    this record is what keeps that visible.

    Attributes:
        name: What the value represents, e.g. ``crqc_horizon_years``.
        value: The value, or ``None`` when the input is missing.
        unit: Unit of the value, e.g. ``years``.
        provenance: Where it came from — see :class:`ContextSource`, plus
            ``scanner_observed`` for values read from a finding.
        is_default: True when a documented default supplied the value.
    """

    name: str
    value: float | None
    unit: str = "years"
    provenance: str = ContextSource.DEFAULT.value
    is_default: bool = False

    @property
    def is_present(self) -> bool:
        """True when a value is available."""
        return self.value is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "unit": self.unit,
            "provenance": self.provenance,
            "is_default": self.is_default,
        }


@dataclass(frozen=True, slots=True)
class QuantumRiskResult:
    """The quantum-risk conclusion for one finding — a computed conclusion.

    This is layer 3 of the three-layer model, kept strictly separate from the
    observed facts and the organisation context that produced it. Every field
    is reproducible from a :class:`CryptoFinding`, an :class:`ApplicationContext`,
    and the configured assumptions; nothing here is observed.

    It deliberately carries the finding's own evidence markers (confidence,
    evidence level, detection method) unchanged, so a weak discovery cannot be
    laundered into a strong risk claim, and so the whole result traces back to
    the finding that caused it.

    Recommendations and migration priority are **not** here — those are Phase 8
    and 9.

    Attributes:
        finding_id: The finding this result assesses. The traceability anchor.
        component: Owning application, carried from the finding.
        algorithm: Algorithm assessed, carried from the finding.
        role: Cryptographic role, when the finding recorded one.
        key_size: Key size, only when the finding established it.
        quantum_category: The knowledge-base classification.
        risk_level: The overall explainable classification.
        mosca_status: Outcome of the time-horizon analysis.
        mosca: The Mosca calculation, when one could be performed.
        assumptions: Every input with its provenance.
        rationale: Human-readable reasons, generated from actual fields.
        confidence: The finding's confidence, carried through unchanged.
        evidence_level: The finding's evidence level, carried through unchanged.
        detection_method: How the finding was detected, carried through.
        source_type: Which surface found it, carried through.
        artefact_type: The finding's artefact type, carried through.
    """

    finding_id: str
    component: str
    algorithm: str
    quantum_category: QuantumCategory
    risk_level: RiskLevel
    mosca_status: MoscaStatus
    role: str = ""
    key_size: int | None = None
    mosca: MoscaResult | None = None
    assumptions: list[RiskAssumption] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW
    evidence_level: str = ""
    detection_method: str = ""
    source_type: str = ""
    artefact_type: str = ""

    @property
    def risk_rank(self) -> int:
        """Sort key for later prioritisation. Lower is more urgent."""
        return RISK_RANK.get(self.risk_level, 99)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "component": self.component,
            "algorithm": self.algorithm,
            "role": self.role,
            "key_size": self.key_size,
            "quantum_category": self.quantum_category.value,
            "risk_level": self.risk_level.value,
            "risk_rank": self.risk_rank,
            "mosca_status": self.mosca_status.value,
            "mosca": self.mosca.to_dict() if self.mosca else None,
            "assumptions": [a.to_dict() for a in self.assumptions],
            "rationale": list(self.rationale),
            "confidence": self.confidence.value,
            "evidence_level": self.evidence_level,
            "detection_method": self.detection_method,
            "source_type": self.source_type,
            "artefact_type": self.artefact_type,
        }


# ==========================================================================
# Recommendations (Phase 8)
# ==========================================================================


@dataclass(frozen=True, slots=True)
class RecommendationResult:
    """A remediation recommendation for one finding — a computed conclusion.

    Layer 3 of the three-layer model, downstream of the quantum-risk result. It
    translates an established finding plus its Phase 7 conclusions into a
    defensible remediation *direction*: what kind of change is appropriate, a
    concrete target only where the mapping is defensible, and an explicit
    statement of what it does not know.

    It never recomputes risk or Mosca — those are read from the
    :class:`QuantumRiskResult` and carried through. It never ranks or
    prioritises — that is Phase 9. It carries the finding's confidence and
    evidence markers unchanged, so a recommendation built on weak evidence
    never looks more authoritative than the evidence supports.

    Attributes:
        recommendation_id: Deterministic id derived from the finding id.
        finding_id: The finding this addresses. The traceability anchor.
        component: Owning application, carried through.
        remediation_class: The kind of change — see :class:`RemediationClass`.
        title: A short human-readable heading.
        current_algorithm: The algorithm as found, carried through.
        role: Cryptographic role, when established.
        target: A concrete target algorithm/family, only where defensible.
            Empty when no concrete target can be justified.
        target_standard: The NIST standard for the target, when one applies.
        rationale: Human-readable reasons, from actual fields only.
        quantum_category: The Phase 7 category, carried through.
        risk_level: The Phase 7 risk level, carried through.
        mosca_status: The Phase 7 Mosca status, carried through (not recomputed).
        confidence: The finding's confidence, unchanged.
        evidence_level: The finding's evidence level, unchanged.
        performance_note: Qualitative consideration, explicitly not a measured
            result.
        limitations: What this recommendation does not establish.
        additional_evidence_required: What would strengthen or unlock a concrete
            recommendation.
        provenance: Where the recommendation's inputs came from.
        source_type / artefact_type: Carried through for traceability.
    """

    recommendation_id: str
    finding_id: str
    component: str
    remediation_class: RemediationClass
    title: str
    current_algorithm: str = ""
    role: str = ""
    target: str = ""
    target_standard: str = ""
    rationale: list[str] = field(default_factory=list)
    quantum_category: str = ""
    risk_level: str = ""
    mosca_status: str = ""
    confidence: Confidence = Confidence.LOW
    evidence_level: str = ""
    performance_note: str = ""
    limitations: list[str] = field(default_factory=list)
    additional_evidence_required: list[str] = field(default_factory=list)
    provenance: str = ""
    source_type: str = ""
    artefact_type: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "recommendation_id": self.recommendation_id,
            "finding_id": self.finding_id,
            "component": self.component,
            "remediation_class": self.remediation_class.value,
            "title": self.title,
            "current_algorithm": self.current_algorithm,
            "role": self.role,
            "target": self.target,
            "target_standard": self.target_standard,
            "rationale": list(self.rationale),
            "quantum_category": self.quantum_category,
            "risk_level": self.risk_level,
            "mosca_status": self.mosca_status,
            "confidence": self.confidence.value,
            "evidence_level": self.evidence_level,
            "performance_note": self.performance_note,
            "limitations": list(self.limitations),
            "additional_evidence_required": list(self.additional_evidence_required),
            "provenance": self.provenance,
            "source_type": self.source_type,
            "artefact_type": self.artefact_type,
        }


# ==========================================================================
# Migration prioritisation (Phase 9)
# ==========================================================================


class MigrationPriority(str, Enum):
    """How much earlier organisational attention a migration action deserves.

    Priority is *organisational context applied to technical risk* — not risk
    restated. A CRITICAL quantum-risk finding is not automatically IMMEDIATE;
    that top bucket also requires the owning system to be business-critical.

    IMMEDIATE
        Quantum-vulnerable, within the assumed quantum-threat window, on a
        business-critical system.
    HIGH
        Within the window on a non-critical or unknown-criticality system, or a
        classical security issue on a critical/high system.
    PLANNED
        Migration is appropriate but not time-pressured under the assumptions —
        outside the window, or classical strengthening, or a lower-criticality
        classical issue.
    EVIDENCE_REQUIRED
        No safe migration decision can be made yet: the timing is unresolved,
        the algorithm or role is unknown, or only a library capability was
        found. The rationale names exactly what is missing.
    MONITOR
        No action indicated now, but worth revisiting as assumptions change.
    NO_ACTION
        No migration is indicated by this finding — already post-quantum, or a
        primitive with no established concern.
    """

    IMMEDIATE = "immediate"
    HIGH = "high"
    PLANNED = "planned"
    EVIDENCE_REQUIRED = "evidence_required"
    MONITOR = "monitor"
    NO_ACTION = "no_action"


#: Ordering for deterministic sorting and roadmap grouping. Lower is earlier.
MIGRATION_PRIORITY_RANK: dict[MigrationPriority, int] = {
    MigrationPriority.IMMEDIATE: 0,
    MigrationPriority.HIGH: 1,
    MigrationPriority.PLANNED: 2,
    MigrationPriority.EVIDENCE_REQUIRED: 3,
    MigrationPriority.MONITOR: 4,
    MigrationPriority.NO_ACTION: 5,
}


class RoadmapBucket(str, Enum):
    """A roadmap grouping. A deterministic consequence of the priority.

    No calendar dates — the buckets express sequence and kind of work, not
    deadlines, because the inventory carries no dates to justify one.
    """

    IMMEDIATE_ATTENTION = "immediate_attention"
    NEAR_TERM = "near_term_migration"
    PLANNED = "planned_migration"
    EVIDENCE_COLLECTION = "evidence_collection"
    MONITORING = "monitoring"


@dataclass(frozen=True, slots=True)
class MigrationPriorityResult:
    """The prioritisation conclusion for one finding — a computed conclusion.

    Consumes the Phase 7 risk result and the Phase 8 recommendation; it never
    recomputes risk or Mosca. Every field needed to answer "why is this item in
    this priority category?" travels with the result, and the whole chain traces
    back through ``recommendation_id`` and ``finding_id``.

    Attributes:
        priority: The assigned :class:`MigrationPriority`.
        finding_id / recommendation_id: Traceability anchors.
        component: Owning application.
        business_criticality: The context value used, or ``"unknown"`` when the
            organisation did not declare one — never guessed.
        risk_level / mosca_status / quantum_category: Carried from Phase 7.
        remediation_class: Carried from Phase 8.
        reason_class: A short machine label for the kind of reason
            (e.g. ``pqc_migration``, ``classical_remediation``, ``evidence_gap``).
        rationale: Plain-language reasons, built from actual fields.
        priority_factors: The specific factors that placed it here, in order.
        assumptions: What the decision depended on, including missing inputs.
        confidence / evidence_level: Carried through unchanged.
        provenance: The upstream chain.
    """

    priority: MigrationPriority
    finding_id: str
    recommendation_id: str
    component: str
    reason_class: str
    business_criticality: str = "unknown"
    risk_level: str = ""
    mosca_status: str = ""
    quantum_category: str = ""
    remediation_class: str = ""
    rationale: list[str] = field(default_factory=list)
    priority_factors: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW
    evidence_level: str = ""
    provenance: str = ""

    @property
    def priority_rank(self) -> int:
        """Sort key. Lower is earlier attention."""
        return MIGRATION_PRIORITY_RANK.get(self.priority, 99)

    def to_dict(self) -> dict[str, Any]:
        return {
            "priority": self.priority.value,
            "priority_rank": self.priority_rank,
            "finding_id": self.finding_id,
            "recommendation_id": self.recommendation_id,
            "component": self.component,
            "business_criticality": self.business_criticality,
            "risk_level": self.risk_level,
            "mosca_status": self.mosca_status,
            "quantum_category": self.quantum_category,
            "remediation_class": self.remediation_class,
            "reason_class": self.reason_class,
            "rationale": list(self.rationale),
            "priority_factors": list(self.priority_factors),
            "assumptions": list(self.assumptions),
            "confidence": self.confidence.value,
            "evidence_level": self.evidence_level,
            "provenance": self.provenance,
        }


@dataclass(frozen=True, slots=True)
class RoadmapItem:
    """One entry in a roadmap bucket, referencing its priority result."""

    finding_id: str
    recommendation_id: str
    component: str
    priority: MigrationPriority
    title: str
    target: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "recommendation_id": self.recommendation_id,
            "component": self.component,
            "priority": self.priority.value,
            "title": self.title,
            "target": self.target,
        }


# ==========================================================================
# Composite
# ==========================================================================


@dataclass(frozen=True, slots=True)
class CryptoAsset:
    """The three layers bound together for transport, storage, and display.

    This is what discovery adapters ultimately produce, what the inventory
    stores, what CBOM export consumes, and what the dashboard renders.
    """

    finding: CryptoFinding
    context: ApplicationContext
    assessment: AssetAssessment | None = None

    @property
    def finding_id(self) -> str:
        return self.finding.finding_id

    @property
    def component(self) -> str:
        return self.finding.component or self.context.component

    @property
    def risk_level(self) -> RiskLevel:
        return self.assessment.risk_level if self.assessment else RiskLevel.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        """Flattened-by-layer view.

        The layers stay visibly separate in the payload. Flattening them here
        would reintroduce exactly the ambiguity this model exists to remove.
        """
        return {
            "finding_id": self.finding_id,
            "component": self.component,
            "observed": self.finding.to_dict(),
            "context": self.context.to_dict(),
            "assessment": self.assessment.to_dict() if self.assessment else None,
        }


# ==========================================================================
# Scan metadata
# ==========================================================================


class ScanStatus(str, Enum):
    """Lifecycle of a scan run."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


@dataclass(slots=True)
class CoverageStatement:
    """What a discovery adapter does and does not cover.

    Part of the adapter interface rather than documentation, so that honesty
    about scope is structural. The dashboard renders this next to results; a
    scanner that cannot state its limits cannot ship.
    """

    adapter: str
    supported: list[str] = field(default_factory=list)
    not_supported: list[str] = field(default_factory=list)
    confidence_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "supported": list(self.supported),
            "not_supported": list(self.not_supported),
            "confidence_notes": self.confidence_notes,
        }


@dataclass(slots=True)
class ScanResult:
    """Everything one adapter produced in one run.

    ``errors`` is a first-class field: a scan that skipped ten unreadable files
    must say so. Silently returning fewer findings would misrepresent coverage.
    """

    scan_id: str
    adapter: str
    target: str
    status: ScanStatus
    findings: list[CryptoFinding] = field(default_factory=list)
    coverage: CoverageStatement | None = None
    errors: list[str] = field(default_factory=list)
    files_examined: int = 0
    started_at: str = ""
    completed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "adapter": self.adapter,
            "target": self.target,
            "status": self.status.value,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "coverage": self.coverage.to_dict() if self.coverage else None,
            "errors": list(self.errors),
            "files_examined": self.files_examined,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


def utc_now() -> str:
    """ISO-8601 UTC timestamp, second resolution."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ==========================================================================
# Legacy interoperability
# ==========================================================================
# The inherited Security Lab surfaces still speak the original flat vocabulary.
# These maps translate between the two without either side importing the other,
# so the frozen code keeps working while ECDAT uses the canonical model.

#: Canonical risk level -> legacy scanner string.
LEGACY_RISK: dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: "CRITICAL",
    RiskLevel.HIGH: "HIGH",
    RiskLevel.MEDIUM: "MEDIUM",
    RiskLevel.LOW_BASELINE: "LOW",
    RiskLevel.PQC_READY: "SAFE",
    RiskLevel.UNKNOWN: "UNKNOWN",
}

#: Legacy scanner string -> canonical risk level.
FROM_LEGACY_RISK: dict[str, RiskLevel] = {
    "CRITICAL": RiskLevel.CRITICAL,
    "HIGH": RiskLevel.HIGH,
    "MEDIUM": RiskLevel.MEDIUM,
    "LOW": RiskLevel.LOW_BASELINE,
    "SAFE": RiskLevel.PQC_READY,
    "UNKNOWN": RiskLevel.UNKNOWN,
}

#: Legacy quantum-status string -> canonical status.
FROM_LEGACY_STATUS: dict[str, QuantumStatus] = {
    "Quantum vulnerable": QuantumStatus.VULNERABLE,
    "Post-quantum": QuantumStatus.POST_QUANTUM,
    "Hybrid (classical + post-quantum)": QuantumStatus.HYBRID,
    "Symmetric (not primarily affected)": QuantumStatus.SYMMETRIC_REDUCED,
    "Unclassified": QuantumStatus.UNKNOWN,
}
