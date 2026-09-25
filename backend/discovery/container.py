"""
Aegis PQC — container image cryptographic discovery adapter.

Inspects OCI and Docker image archives and reports the cryptography inside
them, by extracting the image filesystem under strict bounds and running the
four existing discovery surfaces over it.

THIS IS A THIN ADAPTER
----------------------
It contains **no cryptographic detection logic of its own**. Every finding is
produced by the certificate, dependency, source, or binary adapter exactly as
it would be for a loose file on disk. The container adapter does two things
those adapters do not: it turns an image archive into a filesystem safely, and
it wraps each resulting finding with :class:`~backend.model.ContainerProvenance`
recording the image, the layer, and the in-image path.

The design goal is that *a crypto_service binary found inside an image produces
the identical finding it would produce on disk* — same algorithm, same
evidence, same confidence — with the container origin added, never substituted.

WHAT IT ACCEPTS
---------------
* Docker ``docker save`` archives (``manifest.json`` + layer tarballs)
* OCI image layouts (``oci-layout`` + ``index.json`` + ``blobs/``)
* A single layer tarball, as a fallback

No Docker daemon, no registry, no runtime, no CLI. Everything operates on a
local archive, offline. Formats that cannot be handled safely are declared
unsupported rather than half-parsed.

SAFETY IS THE HARD PART
-----------------------
A container archive is attacker-controlled and layered, which multiplies every
archive risk. Extraction enforces, and tests exercise: per-file and total size
ceilings, a file-count ceiling, a layer-count ceiling, path-traversal
rejection (``../`` and absolute members), symlink refusal, and containment of
every written path inside the extraction root. Nothing from an image is ever
executed — not an entrypoint, not a script, not a layer's contents.

LAYER SEMANTICS
---------------
Layers are applied in order and a later occurrence of a path replaces an
earlier one, which mirrors how an overlay filesystem resolves a file — the
scanner sees each path as its final version. OCI whiteout markers
(``.wh.<name>``) are honoured so a file deleted in a later layer does not
appear in the inventory. This is deterministic and explainable; what it does
**not** model is a file's history across layers, and the coverage statement
says so.
"""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend import discovery
from backend.discovery import ScanLimits, is_within
from backend.discovery.attribution import ComponentResolver
from backend.model import (
    ContainerFormat,
    ContainerProvenance,
    CoverageStatement,
    CryptoFinding,
    ScanResult,
    ScanStatus,
    utc_now,
)

#: Bounds specific to container extraction, layered on top of ScanLimits.
#: Containers amplify every archive risk, so these are deliberately
#: conservative — a demonstration image is small, and a legitimate enterprise
#: image scanned for inventory does not need gigabytes extracted to find its
#: certificates and binaries.


@dataclass(slots=True)
class ContainerLimits:
    """Bounds applied to container extraction.

    Attributes:
        max_archive_bytes: Reject an image archive larger than this outright.
        max_layers: Stop after this many layers.
        max_extracted_bytes: Abort once cumulative extracted bytes exceed this.
        max_files: Abort after this many extracted files.
        max_member_bytes: Skip any single archive member larger than this.
        max_entries: Hard cap on archive entries *examined*, applied before
            extraction. ``tarfile.getmembers()`` reads the whole member list
            into memory, so an archive with tens of millions of entries could
            exhaust memory before any per-file budget engaged. Iterating with
            this ceiling closes that window.
    """

    max_archive_bytes: int = 256 * 1024 * 1024
    max_layers: int = 64
    max_extracted_bytes: int = 512 * 1024 * 1024
    max_files: int = 50_000
    max_member_bytes: int = 32 * 1024 * 1024
    max_entries: int = 200_000


#: Whiteout prefix used by the OCI layer specification to mark deletions.
_WHITEOUT = ".wh."

#: OCI opaque-whiteout marker: ``.wh..wh..opq`` in a directory hides everything
#: that directory inherited from lower layers.
_OPAQUE_WHITEOUT = ".wh..wh..opq"


@dataclass(slots=True)
class LayerRecord:
    """One extracted layer's identity.

    Attributes:
        digest: SHA-256 of the layer's raw bytes, computed on read. This is a
            genuine content digest, not a value scraped from a filename.
        index: Ordinal of the layer in application order.
        source_ref: The archive member or manifest reference the layer came
            from, kept for traceability. Explicitly *not* a digest.
    """

    digest: str
    index: int
    source_ref: str = ""


@dataclass(slots=True)
class ExtractedImage:
    """The result of flattening an image into a directory.

    Attributes:
        root: Directory holding the merged filesystem.
        format: Which layout the archive used.
        image_reference: Image name and tag, when recoverable.
        config_ref: Identifier for the image config — for a Docker archive this
            is the config member name, which is *not* a cryptographic digest
            and is named accordingly. For an OCI layout it is the manifest
            digest, which is.
        config_is_digest: True when ``config_ref`` is a genuine SHA-256 digest
            (OCI), false when it is a filename identifier (Docker archive).
        layers: Layers applied, in order, each with a real content digest.
        path_layer: Maps each merged path to the layer that last wrote it, so a
            finding can be traced to its originating layer.
        errors: Non-fatal problems encountered during extraction.
    """

    root: Path
    format: ContainerFormat
    image_reference: str = ""
    config_ref: str = ""
    config_is_digest: bool = False
    layers: list[LayerRecord] = field(default_factory=list)
    path_layer: dict[str, LayerRecord] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


# ==========================================================================
# Format detection
# ==========================================================================


def detect_container_format(archive: Path) -> ContainerFormat:
    """Identify a container archive by its member names.

    Reads only the tar index, not the contents, so detection is cheap and
    touches no file data. Member iteration is bounded so a hostile archive
    with a vast number of entries cannot exhaust memory during detection.
    """
    if not tarfile.is_tarfile(archive):
        return ContainerFormat.UNKNOWN

    names: list[str] = []
    try:
        with tarfile.open(archive, "r:*") as tar:
            # Iterate lazily rather than calling getnames(), which would
            # materialise every entry. A few thousand top-level names is far
            # more than any real image layout needs.
            for count, member in enumerate(tar):
                if count >= 10_000:
                    break
                names.append(member.name)
    except (tarfile.TarError, OSError):
        return ContainerFormat.UNKNOWN

    nameset = set(names)
    if "manifest.json" in nameset and any(n.endswith(".tar") for n in names):
        return ContainerFormat.DOCKER_ARCHIVE
    if "oci-layout" in nameset or "index.json" in nameset:
        return ContainerFormat.OCI_LAYOUT
    if any(n in ("layer.tar",) or n.startswith("blobs/") for n in names):
        return ContainerFormat.LAYER_TAR
    # A plain tar with filesystem-looking content is treated as a single layer.
    return ContainerFormat.LAYER_TAR


# ==========================================================================
# Safe extraction
# ==========================================================================


def _safe_members(
    tar: tarfile.TarFile,
    dest_root: Path,
    limits: ContainerLimits,
    budget: dict[str, int],
) -> list[tarfile.TarInfo]:
    """Filter a tar's members to those safe to extract.

    Every guard the container spec demands lives here: absolute paths and
    ``..`` traversal are rejected, symlinks and hard links are refused
    entirely, device and FIFO entries are skipped, oversized members are
    skipped, and the running byte and file budgets abort extraction. A rejected
    member is dropped, never written.

    Members are iterated lazily with an entry ceiling, so an archive padded
    with a huge number of tiny entries cannot exhaust memory before the
    per-file budget engages.
    """
    safe: list[tarfile.TarInfo] = []
    examined = 0

    for member in tar:
        examined += 1
        if examined > limits.max_entries:
            budget["limit"] = f"entry limit ({limits.max_entries}) reached during extraction"
            break

        name = member.name

        # Reject absolute paths and traversal before resolving anything.
        if name.startswith("/") or name.startswith("\\"):
            continue
        if ".." in Path(name).parts:
            continue

        target = dest_root / name
        if not is_within(dest_root, target):
            continue

        # Links are never materialised: a symlink can point outside the root,
        # and a hard link can alias a file we would otherwise bound.
        if member.issym() or member.islnk():
            continue
        if member.ischr() or member.isblk() or member.isfifo() or member.isdev():
            continue

        if member.isfile():
            if member.size > limits.max_member_bytes:
                continue
            if budget["files"] >= limits.max_files:
                budget["limit"] = "file limit reached during extraction"
                break
            if budget["bytes"] + member.size > limits.max_extracted_bytes:
                budget["limit"] = "extracted-size limit reached"
                break
            budget["files"] += 1
            budget["bytes"] += member.size

        safe.append(member)

    return safe


def _extract_layer(
    tar: tarfile.TarFile,
    layer_root: Path,
    limits: ContainerLimits,
    budget: dict[str, int],
) -> None:
    """Extract one layer tar into its own directory under the bounds."""
    members = _safe_members(tar, layer_root, limits, budget)
    for member in members:
        try:
            tar.extract(member, layer_root, filter="data")
        except (tarfile.TarError, OSError, KeyError):
            # A member that fails to extract is skipped; the rest proceed.
            continue


def _apply_layer_onto(
    layer_root: Path,
    merged_root: Path,
    record: LayerRecord,
    path_layer: dict[str, LayerRecord],
) -> None:
    """Merge an extracted layer onto the accumulating filesystem.

    Later layers overwrite earlier ones, matching overlay resolution. Two kinds
    of whiteout are honoured:

    * A regular whiteout ``.wh.name`` removes ``name`` from the merged view.
    * An opaque whiteout ``.wh..wh..opq`` in a directory removes everything the
      merged view inherited in that directory from lower layers, before the
      current layer's own contents for that directory are applied.

    Opaque markers are applied first, so a directory replaced wholesale by a
    later layer does not retain stale lower-layer files.
    """
    # First pass: apply opaque whiteouts, clearing inherited directory contents.
    for path in sorted(layer_root.rglob("*")):
        if path.name != _OPAQUE_WHITEOUT:
            continue
        relative_dir = path.relative_to(layer_root).parent
        merged_dir = merged_root / relative_dir
        if merged_dir.is_dir():
            for existing in sorted(merged_dir.rglob("*"), reverse=True):
                if existing.is_file():
                    existing.unlink()
                    path_layer.pop(
                        existing.relative_to(merged_root).as_posix(), None
                    )

    # Second pass: apply regular whiteouts and file contents.
    for path in sorted(layer_root.rglob("*")):
        if not path.is_file():
            continue
        if path.name == _OPAQUE_WHITEOUT:
            continue
        relative = path.relative_to(layer_root)

        # Regular whiteout: ".wh.name" deletes "name" from the merged filesystem.
        if path.name.startswith(_WHITEOUT):
            deleted = relative.parent / path.name[len(_WHITEOUT) :]
            target = merged_root / deleted
            if target.exists():
                target.unlink()
            path_layer.pop(deleted.as_posix(), None)
            continue

        target = merged_root / relative
        if not is_within(merged_root, target):
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        # Key on the POSIX form so the lookup in _wrap (which normalises with
        # as_posix) matches on every platform. Using str() here yields
        # backslash-separated keys on Windows that never match the forward-slash
        # lookup, silently dropping layer provenance.
        path_layer[relative.as_posix()] = record


def _read_json_member(tar: tarfile.TarFile, name: str) -> Any:
    """Read and parse a JSON member from a tar, or return ``None``."""
    try:
        handle = tar.extractfile(name)
        if handle is None:
            return None
        return json.loads(handle.read().decode("utf-8", errors="replace"))
    except (tarfile.TarError, OSError, json.JSONDecodeError, KeyError):
        return None


def extract_image(
    archive: Path,
    fmt: ContainerFormat,
    workspace: Path,
    limits: ContainerLimits,
) -> ExtractedImage:
    """Flatten a container image archive into a single filesystem directory.

    Args:
        archive: The image tar on disk.
        fmt: Format identified by :func:`detect_container_format`.
        workspace: Writable scratch directory. The merged filesystem is created
            beneath it, and per-layer scratch is cleaned up as it goes.
        limits: Extraction bounds.

    Returns:
        The merged image, with per-path layer provenance and any non-fatal
        extraction errors. A structurally broken image yields whatever was
        recoverable plus an error, never an exception.
    """
    merged_root = workspace / "merged"
    merged_root.mkdir(parents=True, exist_ok=True)
    result = ExtractedImage(root=merged_root, format=fmt)
    budget: dict[str, int] = {"files": 0, "bytes": 0, "limit": ""}

    try:
        with tarfile.open(archive, "r:*") as outer:
            layer_names, meta = _resolve_layer_order(outer, fmt, result)

            for index, layer_name in enumerate(layer_names):
                if index >= limits.max_layers:
                    result.errors.append(
                        f"layer limit ({limits.max_layers}) reached; "
                        f"{len(layer_names) - index} layer(s) not scanned"
                    )
                    break
                if budget.get("limit"):
                    result.errors.append(budget["limit"])
                    break

                layer_scratch = workspace / f"layer_{index}"
                layer_scratch.mkdir(parents=True, exist_ok=True)

                try:
                    member = outer.extractfile(layer_name)
                    if member is None:
                        result.errors.append(f"layer {index}: unreadable")
                        continue
                    # Read the layer bytes once, hash them for a genuine content
                    # digest, then parse from the same buffer. A layer archive
                    # is already bounded by the outer member-size limit, and
                    # this is the only point where the true SHA-256 is knowable.
                    layer_bytes = member.read()
                    digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
                    record = LayerRecord(
                        digest=digest, index=index, source_ref=_short_ref(layer_name)
                    )
                    result.layers.append(record)

                    with tarfile.open(
                        fileobj=io.BytesIO(layer_bytes), mode="r:*"
                    ) as layer_tar:
                        _extract_layer(layer_tar, layer_scratch, limits, budget)
                except (tarfile.TarError, OSError) as exc:
                    result.errors.append(f"layer {index}: {exc}")
                    continue

                _apply_layer_onto(layer_scratch, merged_root, record, result.path_layer)
                shutil.rmtree(layer_scratch, ignore_errors=True)

            if budget.get("limit") and budget["limit"] not in result.errors:
                result.errors.append(budget["limit"])

    except (tarfile.TarError, OSError) as exc:
        result.errors.append(f"malformed container archive: {exc}")

    return result


def _resolve_layer_order(
    tar: tarfile.TarFile, fmt: ContainerFormat, result: ExtractedImage
) -> tuple[list[str], dict]:
    """Determine which members are layers, in application order.

    Docker archives name their layers and order in ``manifest.json``; OCI
    layouts list them in the image manifest referenced by ``index.json``. A
    bare layer tar is its own single layer.
    """
    names = tar.getnames()

    if fmt is ContainerFormat.DOCKER_ARCHIVE:
        manifest = _read_json_member(tar, "manifest.json")
        if isinstance(manifest, list) and manifest:
            entry = manifest[0]
            if isinstance(entry, dict):
                tags = entry.get("RepoTags") or []
                if tags:
                    result.image_reference = str(tags[0])
                layers = [str(layer) for layer in entry.get("Layers", [])]
                config = entry.get("Config", "")
                if config:
                    # The Docker archive references its config by filename. That
                    # filename often *contains* the config's sha256 (Docker
                    # names it "<digest>.json"), but the manifest gives us no
                    # guarantee of that, so it is recorded as an identifier, not
                    # asserted to be a digest.
                    result.config_ref = str(config)
                    result.config_is_digest = False
                if layers:
                    return [name for name in layers if name in names], {}

    if fmt is ContainerFormat.OCI_LAYOUT:
        index = _read_json_member(tar, "index.json")
        layer_digests: list[str] = []
        if isinstance(index, dict):
            for manifest_desc in index.get("manifests", []):
                digest = manifest_desc.get("digest", "")
                if digest:
                    # An OCI descriptor digest is a real content digest.
                    result.config_ref = digest
                    result.config_is_digest = True
                bare = digest.replace("sha256:", "")
                manifest_path = f"blobs/sha256/{bare}"
                manifest = _read_json_member(tar, manifest_path)
                if isinstance(manifest, dict):
                    for layer in manifest.get("layers", []):
                        layer_digest = layer.get("digest", "").replace("sha256:", "")
                        blob = f"blobs/sha256/{layer_digest}"
                        if blob in names:
                            layer_digests.append(blob)
        if layer_digests:
            return layer_digests, {}

    # Fallback: any .tar members, or the archive as a single layer.
    tar_members = [n for n in names if n.endswith(".tar")]
    if tar_members:
        return tar_members, {}
    return [], {}


def _short_ref(name: str) -> str:
    """Reduce a layer member path to a short traceability reference.

    This is a source reference — which archive member the layer came from —
    not a content digest. The real digest is computed from the layer bytes in
    :func:`extract_image`. Named ``_short_ref`` precisely so it is never
    mistaken for one.
    """
    text = name.replace("blobs/sha256/", "")
    stem = Path(text).name.replace(".tar", "")
    return stem[:24] if stem else name[:24]


# ==========================================================================
# Adapter
# ==========================================================================

#: Suffixes recognised as container archives.
CONTAINER_SUFFIXES: frozenset[str] = frozenset({".tar"})


class ContainerAdapter:
    """Orchestration adapter: extract an image, then run the four surfaces."""

    name = "container"

    def __init__(self) -> None:
        # Imported lazily and held, so the registry order in
        # ``backend.discovery`` does not matter and a missing optional adapter
        # (binary, when LIEF is absent) simply contributes nothing.
        self._surfaces: dict[str, Any] = {}

    def _load_surfaces(self) -> dict[str, Any]:
        """Resolve the four discovery adapters from the registry once."""
        if not self._surfaces:
            from backend.discovery import binary, certificates, dependencies, source

            self._surfaces = {
                "certificates": certificates.CERTIFICATE_ADAPTER,
                "dependencies": dependencies.DEPENDENCY_ADAPTER,
                "source": source.SOURCE_ADAPTER,
                "binary": binary.BINARY_ADAPTER,
            }
        return self._surfaces

    def coverage(self) -> CoverageStatement:
        """Declared scope, rendered in the dashboard beside the results."""
        return CoverageStatement(
            adapter=self.name,
            supported=[
                "Docker image archives from `docker save` (manifest.json + layers)",
                "OCI image layouts (oci-layout, index.json, blobs)",
                "A single layer tarball as a fallback",
                "Layers merged in order, with later layers overriding earlier",
                "Regular and opaque OCI whiteouts honoured, so deleted files "
                "and replaced directories do not appear",
                "A genuine SHA-256 digest computed for each layer's contents",
                "All four discovery surfaces run over the merged filesystem",
                "Image, layer digest, and in-image path recorded on every finding",
            ],
            not_supported=[
                "No Docker daemon, registry pull, or container runtime is used",
                "Images must be supplied as local archives",
                "Registry references and image URLs are not resolved",
                "Kubernetes and Helm resources are not scanned",
                "Full per-file layer history is not modelled — only the final "
                "merged filesystem, plus the layer that last wrote each path",
                "Encrypted or signed image layers are not decrypted",
            ],
            confidence_notes=(
                "A container finding carries the confidence of the surface that "
                "produced it — a binary symbol inside an image is MEDIUM exactly "
                "as it would be on disk. The container origin adds provenance, "
                "never certainty."
            ),
        )

    def supports(self, target: Path) -> bool:
        """True for a ``.tar`` archive that looks like a container image."""
        target = Path(target)
        if target.is_dir():
            return False
        return target.suffix.lower() in CONTAINER_SUFFIXES

    def scan(
        self,
        target: Path,
        scan_id: str,
        limits: ScanLimits | None = None,
        resolver: ComponentResolver | None = None,
        container_limits: ContainerLimits | None = None,
    ) -> ScanResult:
        """Scan a container image archive for cryptographic artefacts.

        Args:
            target: Image archive on disk.
            scan_id: Scan this run belongs to.
            limits: Bounds passed through to the underlying surfaces.
            resolver: Component attribution, applied to in-image paths.
            container_limits: Extraction bounds. Defaults applied if omitted.

        Returns:
            The aggregated findings from all four surfaces, each carrying
            container provenance, plus any extraction errors. A broken image
            yields a partial result rather than an exception.
        """
        limits = limits or ScanLimits()
        resolver = resolver or ComponentResolver()
        container_limits = container_limits or ContainerLimits()
        target = Path(target)
        started = utc_now()

        if not target.exists():
            return self._failed(scan_id, target, started, "Target does not exist")

        try:
            if target.stat().st_size > container_limits.max_archive_bytes:
                return self._failed(
                    scan_id, target, started,
                    f"archive exceeds size limit ({container_limits.max_archive_bytes} bytes)",
                )
        except OSError as exc:
            return self._failed(scan_id, target, started, f"unreadable archive: {exc}")

        fmt = detect_container_format(target)
        if fmt is ContainerFormat.UNKNOWN:
            return self._failed(
                scan_id, target, started, "not a recognised container image archive"
            )

        errors: list[str] = []
        findings: list[CryptoFinding] = []

        # Extraction happens in a temporary workspace that is always cleaned up,
        # so nothing from an untrusted image persists after the scan.
        workspace = Path(tempfile.mkdtemp(prefix="aegis_container_"))
        try:
            image = extract_image(target, fmt, workspace, container_limits)
            errors.extend(image.errors)

            reference = image.image_reference or target.stem

            for surface_name, adapter in self._load_surfaces().items():
                try:
                    sub = self._run_surface(adapter, image.root, scan_id, limits, resolver)
                except Exception as exc:
                    errors.append(f"{surface_name}: {exc}")
                    continue

                errors.extend(f"{surface_name}: {e}" for e in sub.errors)
                for finding in sub.findings:
                    findings.append(
                        self._wrap(finding, image, reference, surface_name)
                    )
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

        deduped = self._dedupe(findings)

        return ScanResult(
            scan_id=scan_id,
            adapter=self.name,
            target=str(target),
            status=ScanStatus.PARTIAL if errors else ScanStatus.COMPLETED,
            findings=deduped,
            coverage=self.coverage(),
            errors=errors,
            files_examined=len(image.path_layer),
            started_at=started,
            completed_at=utc_now(),
        )

    @staticmethod
    def _run_surface(
        adapter: Any,
        root: Path,
        scan_id: str,
        limits: ScanLimits,
        resolver: ComponentResolver,
    ) -> ScanResult:
        """Invoke one underlying adapter, tolerating its varying signature.

        The certificate adapter predates the resolver argument; the other three
        accept it. Passing it only where accepted keeps the container adapter a
        pure orchestrator rather than forcing signature changes downstream.
        """
        try:
            return adapter.scan(root, scan_id, limits, resolver=resolver)
        except TypeError:
            return adapter.scan(root, scan_id, limits)

    def _wrap(
        self,
        finding: CryptoFinding,
        image: ExtractedImage,
        reference: str,
        surface: str,
    ) -> CryptoFinding:
        """Attach container provenance to a finding from an underlying surface.

        The finding is preserved intact — algorithm, evidence, confidence,
        component. Only the container origin is added, and the reported location
        is rewritten to the in-image path so a reader sees ``/app/...`` rather
        than a temporary extraction directory.
        """
        merged_path = self._relative_to_root(finding.location, image.root)
        record = image.path_layer.get(merged_path)
        image_path = "/" + merged_path if merged_path else finding.location

        provenance = ContainerProvenance(
            image_reference=reference,
            image_config_ref=image.config_ref,
            image_config_is_digest=image.config_is_digest,
            layer_digest=record.digest if record else "",
            layer_index=record.index if record else None,
            image_path=image_path,
            discovery_surface=surface,
        )

        detail = dict(finding.raw_detail)
        detail["container"] = provenance.to_dict()

        import dataclasses

        # Recompute the id from the stable in-image path. The underlying adapter
        # derived it from the temporary extraction directory, which changes
        # every run — so without this, a container scan would not be
        # deterministic and scan-to-scan diffing would see every finding as new.
        # The image reference plus in-image path is the finding's true, stable
        # identity.
        stable_id = CryptoFinding.compute_id(
            finding.scan_id,
            f"{reference}!{image_path}",
            finding.algorithm or finding.library or finding.evidence,
            finding.line,
            f"{surface}|{finding.evidence.split(chr(8594))[-1].strip()}",
        )

        return dataclasses.replace(
            finding,
            finding_id=stable_id,
            location=image_path,
            raw_detail=detail,
        )

    @staticmethod
    def _relative_to_root(location: str, root: Path) -> str:
        """Express an extraction path relative to the merged root, POSIX-style."""
        try:
            return Path(location).resolve().relative_to(root.resolve()).as_posix()
        except (ValueError, OSError):
            return Path(location).name

    @staticmethod
    def _dedupe(findings: list[CryptoFinding]) -> list[CryptoFinding]:
        """Drop findings that collide on id after provenance is attached.

        Because layers are merged before scanning, a file present in several
        layers is scanned once and cannot double-count. This is a final guard
        for the rare case where two surfaces legitimately describe the same
        artefact identically; distinct findings are always kept.
        """
        seen: set[str] = set()
        unique: list[CryptoFinding] = []
        for finding in findings:
            if finding.finding_id in seen:
                continue
            seen.add(finding.finding_id)
            unique.append(finding)
        return unique

    def _failed(
        self, scan_id: str, target: Path, started: str, message: str
    ) -> ScanResult:
        """Build a failed result carrying an explanatory error."""
        return ScanResult(
            scan_id=scan_id,
            adapter=self.name,
            target=str(target),
            status=ScanStatus.FAILED,
            coverage=self.coverage(),
            errors=[message],
            started_at=started,
            completed_at=utc_now(),
        )


#: Module-level instance, registered for lookup by name.
CONTAINER_ADAPTER = discovery.register(ContainerAdapter())
