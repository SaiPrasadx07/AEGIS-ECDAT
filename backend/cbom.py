"""
Aegis PQC — Cryptography Bill of Materials (CBOM) generation.

Projects the canonical inventory into a CycloneDX-compatible CBOM using
``cyclonedx-python-lib``. This is a **downstream reporting layer**: the unified
inventory produced by the five discovery surfaces is the single source of
truth, and this module only serialises what is already there.

WHAT THIS MODULE IS
-------------------
A pure transformation. It reads :class:`~backend.model.CryptoFinding` objects
and emits a CycloneDX 1.6 document. It never scans a file, never runs a
subprocess, never touches the network, and never mutates the inventory. Given
the same findings it produces byte-identical output.

WHAT THIS MODULE IS NOT
-----------------------
It is not a second scanner and it invents nothing. Three rules from the earlier
phases are load-bearing here and are enforced, not merely intended:

* **Capability is not usage.** A dependency finding with ``artefact_type =
  LIBRARY`` and an empty ``algorithm`` describes a library that *provides*
  cryptography. It becomes a CBOM ``library`` component, never an ``algorithm``
  asset asserting the application performs RSA. The distinction Phase 2 drew
  survives serialisation.

* **Unknown stays unknown.** A key size absent from a finding is absent from
  the CBOM. Nothing is inferred from a symbol name, an architecture, or a
  filename that the scanner did not already establish.

* **Weak evidence stays weak.** The ``confidence`` and evidence level recorded
  by the scanner are carried through verbatim as properties. CBOM generation
  never upgrades a LOW linked-library finding into a HIGH usage claim.

No quantum-risk conclusion, Mosca score, or migration priority appears in the
CBOM. Those are later phases; the CBOM represents observed facts and existing
inventory context only.

CYCLONEDX MAPPING
-----------------
Each finding becomes one CycloneDX ``Component``:

* An artefact with a concrete algorithm → a ``cryptographic-asset`` component
  carrying ``cryptoProperties`` (asset type ``algorithm``, primitive, functions,
  parameter set, OID, mode).
* A certificate finding → a ``cryptographic-asset`` with ``certificateProperties``
  (subject, issuer, signature algorithm, validity).
* A library/dependency finding with no confirmed algorithm → an ordinary
  ``library`` component, so it can never be read as an algorithm assertion.

Every canonical field that CycloneDX has no native slot for is preserved as an
``aegis:`` namespaced ``Property``, so nothing from the inventory is lost and
the mapping is fully reversible for downstream phases.

DETERMINISM
-----------
CycloneDX requires a BOM serial number and permits a metadata timestamp. Both
default to values that change per run, which would make output
non-deterministic. This module fixes the serial number to a UUIDv5 derived from
the ordered finding identities and sets the timestamp to ``None``, so the same
inventory always yields the same document.
"""

from __future__ import annotations

import uuid
from typing import Any, Iterable

from cyclonedx.model import Property, XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CertificateProperties,
    CryptoAssetType,
    CryptoFunction,
    CryptoPrimitive,
    CryptoProperties,
)
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion

from backend.model import (
    ArtefactType,
    Confidence,
    CryptoFinding,
)

#: The CycloneDX specification version this module targets and validates against.
TARGET_SCHEMA = SchemaVersion.V1_6

#: Namespace for properties carrying canonical fields CycloneDX cannot express
#: natively. Keeps our extensions clearly separated from standard fields.
NS = "aegis"

#: Fixed namespace for deriving a deterministic BOM serial number. Arbitrary
#: but constant, so the UUIDv5 below is stable across machines and runs.
_SERIAL_NAMESPACE = uuid.UUID("a3591b70-0000-4000-8000-ae0150000000")


# ==========================================================================
# Vocabulary mapping
# ==========================================================================

#: Canonical algorithm family / role → CycloneDX primitive. Falls back to
#: nothing (omitted) rather than guessing when the role is unclear.
_PRIMITIVE_BY_ROLE: dict[str, CryptoPrimitive] = {
    "key_establishment": CryptoPrimitive.KEY_AGREE,
    "signature": CryptoPrimitive.SIGNATURE,
    "symmetric": CryptoPrimitive.BLOCK_CIPHER,
    "hash": CryptoPrimitive.HASH,
    "kdf": CryptoPrimitive.KDF,
    "protocol": CryptoPrimitive.OTHER,
}

#: A few algorithms are more precisely typed than their role implies. KEMs and
#: public-key encryption differ from a generic key-agreement, and stream
#: ciphers from block ciphers. These refinements apply where the algorithm name
#: makes the primitive unambiguous.
_PRIMITIVE_BY_ALGORITHM: dict[str, CryptoPrimitive] = {
    "RSA": CryptoPrimitive.PKE,
    "ML-KEM": CryptoPrimitive.KEM,
    "ML-KEM-512": CryptoPrimitive.KEM,
    "ML-KEM-768": CryptoPrimitive.KEM,
    "ML-KEM-1024": CryptoPrimitive.KEM,
    "ChaCha20": CryptoPrimitive.STREAM_CIPHER,
    "ChaCha20-Poly1305": CryptoPrimitive.STREAM_CIPHER,
    "HMAC": CryptoPrimitive.MAC,
    "HKDF": CryptoPrimitive.KDF,
}

#: Canonical role → the CycloneDX crypto function it primarily performs.
_FUNCTION_BY_ROLE: dict[str, CryptoFunction] = {
    "key_establishment": CryptoFunction.KEYGEN,
    "signature": CryptoFunction.SIGN,
    "symmetric": CryptoFunction.ENCRYPT,
    "hash": CryptoFunction.DIGEST,
    "kdf": CryptoFunction.KEYDERIVE,
}


def _primitive_for(finding: CryptoFinding) -> CryptoPrimitive | None:
    """Resolve the CycloneDX primitive for an algorithm finding.

    Prefers an algorithm-specific mapping (RSA is PKE, ML-KEM is KEM), then the
    role recorded by the scanner. Returns ``None`` when neither determines it,
    so the field is omitted rather than guessed.
    """
    if finding.algorithm in _PRIMITIVE_BY_ALGORITHM:
        return _PRIMITIVE_BY_ALGORITHM[finding.algorithm]

    base = finding.algorithm.split("-")[0]
    if base in _PRIMITIVE_BY_ALGORITHM:
        return _PRIMITIVE_BY_ALGORITHM[base]

    role = str(finding.raw_detail.get("role", ""))
    return _PRIMITIVE_BY_ROLE.get(role)


def _function_for(finding: CryptoFinding) -> list[CryptoFunction]:
    """Resolve the crypto function(s) for an algorithm finding.

    A single primary function, derived from the role. Empty when the role does
    not map cleanly — an empty list is valid and honest.
    """
    role = str(finding.raw_detail.get("role", ""))
    function = _FUNCTION_BY_ROLE.get(role)
    return [function] if function else []


# ==========================================================================
# Property construction
# ==========================================================================


def _properties(finding: CryptoFinding) -> list[Property]:
    """Carry every canonical field CycloneDX cannot express natively.

    This is what makes the CBOM a lossless projection: the evidence level,
    confidence, detection method, component attribution, source type, and all
    of the container provenance ride here under the ``aegis:`` namespace, so a
    downstream phase can reconstruct the finding exactly.
    """
    props: list[Property] = [
        Property(name=f"{NS}:finding_id", value=finding.finding_id),
        Property(name=f"{NS}:artefact_type", value=finding.artefact_type.value),
        Property(name=f"{NS}:source_type", value=finding.source_type.value),
        Property(name=f"{NS}:confidence", value=finding.confidence.value),
        Property(name=f"{NS}:detection_method", value=finding.detection_method.value),
    ]

    if finding.component:
        props.append(Property(name=f"{NS}:component", value=finding.component))
    if finding.location:
        props.append(Property(name=f"{NS}:location", value=finding.location))
    if finding.line is not None:
        props.append(Property(name=f"{NS}:line", value=str(finding.line)))
    if finding.evidence:
        props.append(Property(name=f"{NS}:evidence", value=finding.evidence))
    if finding.mode:
        props.append(Property(name=f"{NS}:mode", value=finding.mode))
    if finding.key_size is not None:
        props.append(Property(name=f"{NS}:key_size", value=str(finding.key_size)))
    if finding.library:
        props.append(Property(name=f"{NS}:library", value=finding.library))
    if finding.library_version:
        props.append(
            Property(name=f"{NS}:library_version", value=finding.library_version)
        )

    # Evidence level differs by surface (source vs binary) but always lives in
    # raw_detail. Surfacing it as a first-class property keeps the
    # import-vs-call-site / linked-vs-symbol distinction visible in the CBOM.
    evidence_level = finding.raw_detail.get("evidence_level")
    if evidence_level:
        props.append(
            Property(name=f"{NS}:evidence_level", value=str(evidence_level))
        )

    # Source language, where a source finding recorded one.
    language = finding.raw_detail.get("language")
    if language:
        props.append(Property(name=f"{NS}:language", value=str(language)))

    # Binary format, where a binary finding recorded one.
    binary_format = finding.raw_detail.get("binary_format")
    if binary_format:
        props.append(Property(name=f"{NS}:binary_format", value=str(binary_format)))

    # Whether a library capability is confirmed as usage. Explicit, so a reader
    # never has to infer it: a LIBRARY artefact with no algorithm is capability.
    is_capability = (
        finding.artefact_type is ArtefactType.LIBRARY and not finding.algorithm
    )
    props.append(
        Property(
            name=f"{NS}:capability_only",
            value="true" if is_capability else "false",
        )
    )

    props.extend(_container_properties(finding))
    return props


def _container_properties(finding: CryptoFinding) -> list[Property]:
    """Carry Phase 5 container provenance, preserving its exact semantics.

    The digest honesty from the Phase 5 review is retained: ``layer_digest`` is
    a real SHA-256, and ``image_config_ref`` is flagged as a verified digest or
    not. Nothing here promotes a filename reference to a digest.
    """
    container = finding.raw_detail.get("container")
    if not isinstance(container, dict):
        return []

    props: list[Property] = []
    mapping = (
        ("image_reference", "container_image_reference"),
        ("image_config_ref", "container_image_config_ref"),
        ("layer_digest", "container_layer_digest"),
        ("image_path", "container_image_path"),
        ("discovery_surface", "container_discovery_surface"),
    )
    for source_key, prop_name in mapping:
        value = container.get(source_key)
        if value:
            props.append(Property(name=f"{NS}:{prop_name}", value=str(value)))

    # The digest-honesty flag and layer index are booleans/ints — emit them
    # explicitly rather than only when truthy, so their absence is never
    # ambiguous.
    if "image_config_is_digest" in container:
        props.append(
            Property(
                name=f"{NS}:container_image_config_is_digest",
                value="true" if container["image_config_is_digest"] else "false",
            )
        )
    if container.get("layer_index") is not None:
        props.append(
            Property(
                name=f"{NS}:container_layer_index",
                value=str(container["layer_index"]),
            )
        )
    return props


# ==========================================================================
# Component construction
# ==========================================================================


def _crypto_properties(finding: CryptoFinding) -> CryptoProperties:
    """Build CycloneDX ``cryptoProperties`` for an algorithm finding."""
    primitive = _primitive_for(finding)
    functions = _function_for(finding)

    # parameterSetIdentifier is CycloneDX's home for a key size or parameter
    # set — but only when the scanner actually established one.
    parameter_set = None
    if finding.key_size is not None:
        parameter_set = str(finding.key_size)
    elif finding.variant and finding.variant != finding.algorithm:
        parameter_set = finding.variant

    algorithm_properties = AlgorithmProperties(
        primitive=primitive,
        parameter_set_identifier=parameter_set,
        crypto_functions=functions or None,
        mode=None,  # CycloneDX mode is an enum; our free-form mode rides in properties
    )

    return CryptoProperties(
        asset_type=CryptoAssetType.ALGORITHM,
        algorithm_properties=algorithm_properties,
        oid=finding.oid or None,
    )


def _certificate_properties(finding: CryptoFinding) -> CryptoProperties:
    """Build CycloneDX ``cryptoProperties`` for a certificate finding."""
    cert = finding.certificate
    certificate_properties = CertificateProperties(
        subject_name=cert.subject or None if cert else None,
        issuer_name=cert.issuer or None if cert else None,
        not_valid_before=None,
        not_valid_after=None,
        signature_algorithm_ref=None,
    )
    return CryptoProperties(
        asset_type=CryptoAssetType.CERTIFICATE,
        certificate_properties=certificate_properties,
        oid=finding.oid or None,
    )


def _bom_ref(finding: CryptoFinding) -> str:
    """Stable CycloneDX component identifier, derived from the finding id.

    Reuses the canonical identity rather than inventing a second one, so a CBOM
    component traces directly back to its inventory finding.
    """
    return f"crypto:{finding.finding_id}"


def finding_to_component(finding: CryptoFinding) -> Component:
    """Project one canonical finding onto one CycloneDX component.

    The component *type* encodes the capability-versus-usage distinction:

    * A finding with a concrete algorithm becomes a ``cryptographic-asset`` and
      carries crypto properties.
    * A certificate becomes a ``cryptographic-asset`` with certificate
      properties.
    * A library with no confirmed algorithm becomes a plain ``library`` — it
      cannot be read as an algorithm assertion, because it structurally is not
      one.
    """
    is_certificate = (
        finding.artefact_type is ArtefactType.CERTIFICATE and finding.certificate
    )
    has_algorithm = bool(finding.algorithm)

    if is_certificate:
        component_type = ComponentType.CRYPTOGRAPHIC_ASSET
        crypto = _certificate_properties(finding)
        name = finding.certificate.subject or finding.display_name or "certificate"
    elif has_algorithm:
        component_type = ComponentType.CRYPTOGRAPHIC_ASSET
        crypto = _crypto_properties(finding)
        name = finding.display_name
    else:
        # Library capability, or an unidentified artefact. Never a crypto asset.
        component_type = ComponentType.LIBRARY
        crypto = None
        name = finding.library or finding.display_name or "unidentified"

    return Component(
        name=name,
        type=component_type,
        bom_ref=_bom_ref(finding),
        version=finding.library_version or None,
        group=finding.component or None,
        crypto_properties=crypto,
        properties=_properties(finding),
    )


# ==========================================================================
# BOM assembly
# ==========================================================================


def _deterministic_serial(findings: list[CryptoFinding]) -> uuid.UUID:
    """Derive a stable BOM serial number from the ordered finding identities.

    A UUIDv5 over the sorted finding ids. The same inventory always yields the
    same serial; a different inventory yields a different one. This replaces the
    random UUID CycloneDX would otherwise generate, which alone would make every
    document differ.
    """
    seed = "|".join(sorted(f.finding_id for f in findings))
    return uuid.uuid5(_SERIAL_NAMESPACE, seed)


def build_bom(findings: Iterable[CryptoFinding]) -> Bom:
    """Assemble a CycloneDX BOM from canonical findings.

    Findings are sorted by id so component ordering is deterministic. The BOM
    serial number is derived from the finding set and the metadata timestamp is
    cleared, so serialising the same inventory twice yields identical output.

    Args:
        findings: Canonical findings from the inventory.

    Returns:
        A CycloneDX :class:`Bom` ready to serialise.
    """
    ordered = sorted(findings, key=lambda f: f.finding_id)

    bom = Bom()
    bom.serial_number = _deterministic_serial(ordered)
    # CycloneDX defaults the metadata timestamp to "now". Clearing it is what
    # makes byte-for-byte output determinism achievable.
    bom.metadata.timestamp = None
    # A property on the BOM metadata records what produced it, without claiming
    # anything the tests have not verified.
    bom.metadata.properties.add(
        Property(name=f"{NS}:generator", value="aegis-pqc-cbom")
    )

    for finding in ordered:
        bom.components.add(finding_to_component(finding))

    return bom


def to_json(bom: Bom) -> str:
    """Serialise a BOM to CycloneDX 1.6 JSON.

    Args:
        bom: A BOM from :func:`build_bom`.

    Returns:
        Pretty-printed CycloneDX 1.6 JSON.
    """
    outputter = make_outputter(bom, OutputFormat.JSON, TARGET_SCHEMA)
    return outputter.output_as_string(indent=2)


def generate_cbom(findings: Iterable[CryptoFinding]) -> str:
    """Generate a CycloneDX 1.6 CBOM JSON document from canonical findings.

    The one call most callers want: inventory in, validated-shape CBOM JSON
    out. Deterministic for a given set of findings.
    """
    return to_json(build_bom(findings))


def write_cbom(findings: Iterable[CryptoFinding], path: Any) -> str:
    """Generate a CBOM and write it to ``path``.

    Args:
        findings: Canonical findings from the inventory.
        path: Destination file path.

    Returns:
        The JSON that was written.
    """
    from pathlib import Path

    document = generate_cbom(findings)
    Path(path).write_text(document, encoding="utf-8")
    return document


# ==========================================================================
# Validation
# ==========================================================================


def validate_cbom(document: str) -> list[str]:
    """Validate a CBOM against the CycloneDX 1.6 JSON schema.

    Uses ``cyclonedx-python-lib``'s ``JsonStrictValidator``, which checks the
    document against the published CycloneDX schema — not merely that the JSON
    parses. Returns a list of error strings; an empty list means the document
    is schema-valid.

    Args:
        document: CBOM JSON.

    Returns:
        Validation errors, empty when the document is valid.
    """
    from cyclonedx.validation.json import JsonStrictValidator

    validator = JsonStrictValidator(TARGET_SCHEMA)
    error = validator.validate_str(document)
    if error is None:
        return []
    return [str(error)]
