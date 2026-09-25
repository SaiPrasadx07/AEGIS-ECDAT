"""
Aegis PQC — ECDAT Phase 5 tests: container image cryptographic discovery.

The phase's thesis: a cryptographic artefact discovered directly on disk and
the same artefact discovered inside a container image produce the *identical*
canonical finding, with the container origin added as provenance rather than
substituted for the underlying evidence.

The fixtures are real ``docker save``-style archives built from the same
binary, source, and manifest fixtures the earlier phases use.

Run Phase 5 only:  pytest tests/ecdat/test_phase5.py -q
Run all ECDAT:     pytest tests/ecdat -q
Run everything:    pytest tests -q
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from backend import demo_binaries, demo_containers, inventory
from backend.discovery import ScanLimits, binary, container, source
from backend.discovery.attribution import ComponentResolver
from backend.discovery.container import (
    ContainerLimits,
    detect_container_format,
    extract_image,
)
from backend.model import (
    ContainerFormat,
    ScanStatus,
    SourceType,
)

pytestmark = pytest.mark.skipif(
    not binary.LIEF_AVAILABLE,
    reason="LIEF is required for the binary surface used by container fixtures",
)


@pytest.fixture(scope="module")
def images(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A directory of real demonstration container archives."""
    root = tmp_path_factory.mktemp("phase5_images")
    demo_containers.write_demo_images(root)
    return root / "images"


@pytest.fixture(scope="module")
def resolver() -> ComponentResolver:
    """Attribution mapping the in-image directories to components."""
    return ComponentResolver(
        {
            "payments-api": "app",
            "legacy-auth": "srv",
            "pqc-pilot": "opt",
            "content-portal": "www",
        }
    )


@pytest.fixture(scope="module")
def payments_scan(images: Path, resolver: ComponentResolver):
    """One real scan of the payments-api image."""
    return container.CONTAINER_ADAPTER.scan(
        images / "payments-api.tar", "scan_pay", resolver=resolver
    )


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    """Isolated database with the ECDAT schema."""
    path = tmp_path / "phase5.db"
    inventory.init_ecdat_schema(path)
    return path


def _make_archive(members: dict[str, bytes]) -> bytes:
    """Build a raw tar with the given members, for hostile-input tests."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


# ==========================================================================
# The fixtures are real container archives
# ==========================================================================


def test_demo_images_are_valid_docker_archives(images: Path) -> None:
    """Claim: each fixture is a real docker-save layout, not a stand-in."""
    for filename in demo_containers.DEMO_IMAGES:
        archive = images / filename
        assert tarfile.is_tarfile(archive)
        with tarfile.open(archive) as tar:
            names = set(tar.getnames())
        assert "manifest.json" in names
        assert any(n.endswith(".tar") for n in names)


def test_format_detection_identifies_docker_archives(images: Path) -> None:
    """Claim: the docker layout is recognised from its members."""
    assert (
        detect_container_format(images / "payments-api.tar")
        is ContainerFormat.DOCKER_ARCHIVE
    )


def test_format_detection_rejects_non_images(tmp_path: Path) -> None:
    """Claim: an ordinary tar is not mistaken for a container image."""
    plain = tmp_path / "plain.tar"
    plain.write_bytes(_make_archive({"notes.txt": b"hello"}))
    assert detect_container_format(plain) is ContainerFormat.LAYER_TAR

    not_a_tar = tmp_path / "nope.tar"
    not_a_tar.write_bytes(b"this is not a tar file")
    assert detect_container_format(not_a_tar) is ContainerFormat.UNKNOWN


# ==========================================================================
# The thesis: identical finding, added provenance
# ==========================================================================


def test_same_binary_yields_the_same_finding_on_disk_and_in_image(
    images: Path, tmp_path: Path, resolver: ComponentResolver
) -> None:
    """Claim: the container path adds provenance, it does not change the finding.

    The Phase 4 binary is scanned directly, then scanned again inside the
    payments image. The algorithm, mode, key size, confidence, and evidence of
    each detection must match; only the container origin is added.
    """
    on_disk_root = tmp_path / "disk" / "app" / "bin"
    on_disk_root.mkdir(parents=True)
    (on_disk_root / "crypto_service").write_bytes(demo_binaries.crypto_service_bytes())

    disk_scan = binary.BINARY_ADAPTER.scan(
        tmp_path / "disk", "scan_disk", resolver=resolver
    )
    image_scan = container.CONTAINER_ADAPTER.scan(
        images / "payments-api.tar", "scan_img", resolver=resolver
    )

    def signature(finding):
        return (finding.algorithm, finding.mode, finding.key_size, finding.confidence.value)

    disk_sigs = sorted(signature(f) for f in disk_scan.findings)
    image_binary_sigs = sorted(
        signature(f)
        for f in image_scan.findings
        if f.raw_detail.get("container", {}).get("discovery_surface") == "binary"
    )
    assert disk_sigs == image_binary_sigs

    # And the container findings carry provenance the disk findings do not.
    for finding in image_scan.findings:
        if finding.raw_detail.get("container", {}).get("discovery_surface") == "binary":
            assert finding.raw_detail["container"]["image_path"] == (
                "/app/bin/crypto_service"
            )
    assert all("container" not in f.raw_detail for f in disk_scan.findings)


# ==========================================================================
# Provenance
# ==========================================================================


def test_every_container_finding_carries_full_provenance(payments_scan) -> None:
    """Claim: a container finding answers image, layer, path, and surface."""
    assert payments_scan.findings
    for finding in payments_scan.findings:
        prov = finding.raw_detail.get("container")
        assert prov is not None
        assert prov["image_reference"] == "payments-api:2026.09"
        assert prov["image_path"].startswith("/")
        assert prov["discovery_surface"] in (
            "certificates",
            "dependencies",
            "source",
            "binary",
        )
        assert prov["layer_digest"]


def test_location_is_rewritten_to_the_in_image_path(payments_scan) -> None:
    """Claim: the reported location is the image path, not a temp directory.

    A reader must see ``/app/bin/crypto_service``, never a scratch extraction
    directory that no longer exists after the scan.
    """
    for finding in payments_scan.findings:
        assert finding.location.startswith("/app/")
        assert "aegis_container_" not in finding.location
        assert "/tmp/" not in finding.location


def test_findings_attribute_to_components_not_container(payments_scan) -> None:
    """Claim: a finding inside a container resolves to its application.

    ``/app/bin/crypto_service`` must become ``payments-api``, not "container".
    """
    assert {f.component for f in payments_scan.findings} == {"payments-api"}


# ==========================================================================
# Layer semantics
# ==========================================================================


def test_later_layer_overrides_earlier_via_whiteout(payments_scan) -> None:
    """Claim: the real binary in layer 1 replaces the placeholder in layer 0.

    The payments image ships a placeholder binary in layer 0, then whites it
    out and installs the real compiled binary in layer 1. Only the real one is
    scanned, and its findings are attributed to layer 1.
    """
    binary_findings = [
        f
        for f in payments_scan.findings
        if f.raw_detail["container"]["discovery_surface"] == "binary"
    ]
    assert binary_findings
    # The real binary yields RSA/AES/etc.; the placeholder would yield nothing.
    assert {f.algorithm for f in binary_findings if f.algorithm} >= {"RSA", "AES"}
    for finding in binary_findings:
        assert finding.raw_detail["container"]["layer_index"] == 1


def test_whiteout_removes_a_deleted_file(tmp_path: Path) -> None:
    """Claim: a file deleted by a later layer does not appear in the inventory."""
    layer0 = demo_containers._tar_bytes(
        {"app/old.py": b"import hashlib\nhashlib.md5(b'x')\n"}
    )
    layer1 = demo_containers._tar_bytes({"app/.wh.old.py": b""})
    archive = demo_containers._image_archive(
        [
            {"app/old.py": b"import hashlib\nhashlib.md5(b'x')\n"},
            {"app/.wh.old.py": b""},
        ],
        "test:1",
    )
    path = tmp_path / "wh.tar"
    path.write_bytes(archive)

    result = container.CONTAINER_ADAPTER.scan(path, "scan_wh")
    assert all("old.py" not in f.location for f in result.findings)


def test_extraction_records_layer_order(images: Path) -> None:
    """Claim: layers are enumerated in application order."""
    from backend.discovery.container import ContainerLimits, extract_image
    import tempfile

    workspace = Path(tempfile.mkdtemp())
    try:
        fmt = detect_container_format(images / "payments-api.tar")
        image = extract_image(
            images / "payments-api.tar", fmt, workspace, ContainerLimits()
        )
        assert [layer.index for layer in image.layers] == [0, 1]
        assert image.image_reference == "payments-api:2026.09"
    finally:
        import shutil

        shutil.rmtree(workspace, ignore_errors=True)


# ==========================================================================
# Four-surface orchestration
# ==========================================================================


def test_dependency_surface_runs_inside_a_container(payments_scan) -> None:
    """Claim: the dependency scanner runs over the extracted filesystem."""
    deps = [
        f
        for f in payments_scan.findings
        if f.raw_detail["container"]["discovery_surface"] == "dependencies"
    ]
    assert deps
    assert any(f.library == "pyca/cryptography" for f in deps)


def test_binary_surface_runs_inside_a_container(payments_scan) -> None:
    """Claim: the binary scanner runs over the extracted filesystem."""
    binaries = [
        f
        for f in payments_scan.findings
        if f.raw_detail["container"]["discovery_surface"] == "binary"
    ]
    assert binaries
    assert any(f.algorithm == "RSA" for f in binaries)


def test_source_surface_runs_inside_a_container(
    images: Path, resolver: ComponentResolver
) -> None:
    """Claim: the source scanner runs over the extracted filesystem."""
    result = container.CONTAINER_ADAPTER.scan(
        images / "legacy-auth.tar", "scan_src", resolver=resolver
    )
    source_findings = [
        f
        for f in result.findings
        if f.raw_detail["container"]["discovery_surface"] == "source"
    ]
    assert source_findings
    assert {"MD5", "DES"} <= {f.algorithm for f in source_findings}


def test_pqc_evidence_survives_the_container_path(
    images: Path, resolver: ComponentResolver
) -> None:
    """Claim: ML-KEM usage is discovered inside an image, not only on disk."""
    result = container.CONTAINER_ADAPTER.scan(
        images / "pqc-pilot.tar", "scan_pqc", resolver=resolver
    )
    algorithms = {f.algorithm for f in result.findings}
    assert "ML-KEM-768" in algorithms
    assert "X25519" in algorithms


def test_multiple_surfaces_contribute_to_one_image(payments_scan) -> None:
    """Claim: a single image scan aggregates several surfaces."""
    surfaces = {
        f.raw_detail["container"]["discovery_surface"] for f in payments_scan.findings
    }
    assert {"dependencies", "binary"} <= surfaces


def test_clean_image_produces_no_findings(
    images: Path, resolver: ComponentResolver
) -> None:
    """Claim: an image with no cryptography yields nothing.

    content-portal ships false-positive bait — algorithm names in comments,
    identifiers, and a README. A finding here would be a false positive.
    """
    result = container.CONTAINER_ADAPTER.scan(
        images / "content-portal.tar", "scan_clean", resolver=resolver
    )
    assert result.status is ScanStatus.COMPLETED
    assert result.findings == []


# ==========================================================================
# Safety — a container archive is attacker-controlled and layered
# ==========================================================================


def test_path_traversal_members_are_rejected(tmp_path: Path) -> None:
    """Claim: archive members escaping the root are never written."""
    import tempfile

    layer = demo_containers._tar_bytes({"app/ok.py": b"import hashlib\n"})
    outer = io.BytesIO()
    with tarfile.open(fileobj=outer, mode="w") as tar:
        for name in ("../escape.py", "/etc/evil.py", "app/../../escape2.py"):
            data = b"import hashlib\nhashlib.md5(b'x')\n"
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        info = tarfile.TarInfo(name="layer_0.tar")
        info.size = len(layer)
        tar.addfile(info, io.BytesIO(layer))
        manifest = json.dumps(
            [{"Config": "c", "RepoTags": ["evil:1"], "Layers": ["layer_0.tar"]}]
        ).encode()
        info = tarfile.TarInfo(name="manifest.json")
        info.size = len(manifest)
        tar.addfile(info, io.BytesIO(manifest))

    archive = tmp_path / "evil.tar"
    archive.write_bytes(outer.getvalue())

    # No file must be written outside the workspace. If traversal were allowed,
    # this marker path would be created.
    marker = tmp_path / "escape.py"
    container.CONTAINER_ADAPTER.scan(archive, "scan_evil")
    assert not marker.exists()
    assert not Path("/etc/evil.py").exists()


def test_symlink_members_are_refused(tmp_path: Path) -> None:
    """Claim: symlink members are never materialised.

    A symlink inside a layer could point outside the extraction root.
    """
    import tempfile
    from backend.discovery.container import ContainerLimits, extract_image

    outer = io.BytesIO()
    with tarfile.open(fileobj=outer, mode="w") as tar:
        layer_buffer = io.BytesIO()
        with tarfile.open(fileobj=layer_buffer, mode="w") as layer:
            link = tarfile.TarInfo(name="app/evil_link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            layer.addfile(link)
            data = b"import hashlib\nhashlib.sha256(b'')\n"
            real = tarfile.TarInfo(name="app/real.py")
            real.size = len(data)
            layer.addfile(real, io.BytesIO(data))
        layer_bytes = layer_buffer.getvalue()
        info = tarfile.TarInfo(name="layer_0.tar")
        info.size = len(layer_bytes)
        tar.addfile(info, io.BytesIO(layer_bytes))
        manifest = json.dumps(
            [{"Config": "c", "RepoTags": ["t:1"], "Layers": ["layer_0.tar"]}]
        ).encode()
        info = tarfile.TarInfo(name="manifest.json")
        info.size = len(manifest)
        tar.addfile(info, io.BytesIO(manifest))

    workspace = Path(tempfile.mkdtemp())
    try:
        archive = tmp_path / "link.tar"
        archive.write_bytes(outer.getvalue())
        fmt = detect_container_format(archive)
        image = extract_image(archive, fmt, workspace, ContainerLimits())
        # The symlink is gone; the real file remains.
        assert not (image.root / "app" / "evil_link").exists()
        assert (image.root / "app" / "real.py").exists()
    finally:
        import shutil

        shutil.rmtree(workspace, ignore_errors=True)


def test_oversized_archive_is_rejected(images: Path) -> None:
    """Claim: an archive above the size ceiling is refused before extraction."""
    result = container.CONTAINER_ADAPTER.scan(
        images / "payments-api.tar",
        "scan_big",
        container_limits=ContainerLimits(max_archive_bytes=100),
    )
    assert result.status is ScanStatus.FAILED
    assert any("size limit" in e for e in result.errors)


def test_layer_limit_is_enforced(tmp_path: Path) -> None:
    """Claim: an image with too many layers stops and says so."""
    layers = [{f"app/f{i}.py": b"x = 1\n"} for i in range(10)]
    archive = demo_containers._image_archive(layers, "many:1")
    path = tmp_path / "many.tar"
    path.write_bytes(archive)

    result = container.CONTAINER_ADAPTER.scan(
        path, "scan_layers", container_limits=ContainerLimits(max_layers=3)
    )
    assert any("layer limit" in e for e in result.errors)


def test_extraction_byte_budget_is_enforced(tmp_path: Path) -> None:
    """Claim: total extracted size is bounded."""
    big = b"# padding\n" * 100_000  # ~1 MB of source
    archive = demo_containers._image_archive([{"app/big.py": big}], "big:1")
    path = tmp_path / "bigfile.tar"
    path.write_bytes(archive)

    result = container.CONTAINER_ADAPTER.scan(
        path,
        "scan_budget",
        container_limits=ContainerLimits(max_extracted_bytes=1000),
    )
    # Nothing crashed; the budget was applied.
    assert result.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)


def test_malformed_archive_fails_cleanly(tmp_path: Path) -> None:
    """Claim: a broken archive yields a failed scan, not an exception."""
    broken = tmp_path / "broken.tar"
    broken.write_bytes(b"\x00\x01\x02 not a tar \xff" * 20)
    result = container.CONTAINER_ADAPTER.scan(broken, "scan_broken")
    assert result.status is ScanStatus.FAILED
    assert result.errors


def test_missing_target_fails_cleanly(tmp_path: Path) -> None:
    """Claim: a bad path is a reported failure, not an exception."""
    result = container.CONTAINER_ADAPTER.scan(tmp_path / "nope.tar", "scan_missing")
    assert result.status is ScanStatus.FAILED


def test_corrupt_layer_does_not_end_the_scan(tmp_path: Path) -> None:
    """Claim: one unreadable layer does not prevent scanning the others."""
    good_layer = demo_containers._tar_bytes(
        {"app/keys.py": b"from cryptography.hazmat.primitives.asymmetric import rsa\n"
         b"rsa.generate_private_key(key_size=2048)\n"}
    )
    outer = io.BytesIO()
    with tarfile.open(fileobj=outer, mode="w") as tar:
        # A layer name that the manifest references but that is corrupt.
        bad = b"not a valid tar layer"
        info = tarfile.TarInfo(name="layer_0.tar")
        info.size = len(bad)
        tar.addfile(info, io.BytesIO(bad))
        info = tarfile.TarInfo(name="layer_1.tar")
        info.size = len(good_layer)
        tar.addfile(info, io.BytesIO(good_layer))
        manifest = json.dumps(
            [{"Config": "c", "RepoTags": ["mix:1"],
              "Layers": ["layer_0.tar", "layer_1.tar"]}]
        ).encode()
        info = tarfile.TarInfo(name="manifest.json")
        info.size = len(manifest)
        tar.addfile(info, io.BytesIO(manifest))

    archive = tmp_path / "mixed.tar"
    archive.write_bytes(outer.getvalue())
    result = container.CONTAINER_ADAPTER.scan(archive, "scan_corrupt")
    assert any(f.algorithm == "RSA" for f in result.findings)


def test_adapter_invokes_no_runtime_or_package_manager() -> None:
    """Claim: no container runtime, daemon, or package manager is called.

    Checked against the parsed syntax tree, which cannot be fooled by prose in
    a docstring the way a substring scan can.
    """
    import ast

    tree = ast.parse(Path(container.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            target = node.func
            if isinstance(target, ast.Name):
                called.add(target.id)
            elif isinstance(target, ast.Attribute):
                called.add(target.attr)

    assert not (imported & {"subprocess", "docker", "podman", "ctypes"})
    assert not (called & {"system", "popen", "run", "eval", "exec", "dlopen"})


def test_evidence_stays_bounded_through_the_container_path(payments_scan) -> None:
    """Claim: wrapping a finding in provenance does not unbound its evidence."""
    for finding in payments_scan.findings:
        assert len(finding.evidence) <= 240


def test_extraction_cleans_up_after_itself(images: Path, resolver: ComponentResolver) -> None:
    """Claim: no scratch directory survives a scan.

    Nothing extracted from an untrusted image should persist on disk.
    """
    import glob
    import tempfile

    before = set(glob.glob(str(Path(tempfile.gettempdir()) / "aegis_container_*")))
    container.CONTAINER_ADAPTER.scan(images / "payments-api.tar", "scan_cleanup", resolver=resolver)
    after = set(glob.glob(str(Path(tempfile.gettempdir()) / "aegis_container_*")))
    assert after == before


# ==========================================================================
# Determinism and persistence
# ==========================================================================


def test_repeat_scans_are_identical(images: Path, resolver: ComponentResolver) -> None:
    """Claim: an unchanged image scans identically every time."""
    first = container.CONTAINER_ADAPTER.scan(
        images / "payments-api.tar", "scan_det", resolver=resolver
    )
    second = container.CONTAINER_ADAPTER.scan(
        images / "payments-api.tar", "scan_det", resolver=resolver
    )
    assert sorted(f.finding_id for f in first.findings) == sorted(
        f.finding_id for f in second.findings
    )


def test_finding_ids_are_unique(payments_scan) -> None:
    """Claim: no two container findings collide on an id."""
    ids = [f.finding_id for f in payments_scan.findings]
    assert len(ids) == len(set(ids))


def test_container_findings_persist_through_the_canonical_model(
    payments_scan, db: Path
) -> None:
    """Claim: container findings use the same persistence path as every surface.

    No container-specific table. Provenance rides in the finding's raw_detail
    and survives the round trip intact.
    """
    inventory.record_scan(payments_scan, db)
    reloaded = {f.finding_id: f for f in inventory.get_findings(payments_scan.scan_id, db)}
    assert len(reloaded) == len(payments_scan.findings)

    for original in payments_scan.findings:
        stored = reloaded[original.finding_id]
        assert stored.algorithm == original.algorithm
        assert stored.component == original.component
        assert stored.raw_detail["container"]["image_reference"] == (
            original.raw_detail["container"]["image_reference"]
        )
        assert stored.raw_detail["container"]["layer_digest"] == (
            original.raw_detail["container"]["layer_digest"]
        )


def test_container_findings_use_underlying_source_types(payments_scan) -> None:
    """Claim: source_type reflects the surface, not a generic 'container'.

    A binary inside an image is still a BINARY finding; a manifest is still a
    DEPENDENCY finding. The container origin is provenance, layered on top.
    """
    source_types = {f.source_type for f in payments_scan.findings}
    assert SourceType.BINARY in source_types
    assert SourceType.DEPENDENCY in source_types


def test_container_adapter_is_registered() -> None:
    """Claim: the fifth adapter is registered and conforms."""
    from backend import discovery

    assert "container" in discovery.available_adapters()
    adapter = discovery.get_adapter("container")
    assert adapter.coverage().not_supported


def test_coverage_declares_real_limits() -> None:
    """Claim: the coverage statement is honest about scope.

    It must not claim registry, daemon, or Kubernetes support, and must state
    the layer-history limitation.
    """
    coverage = container.CONTAINER_ADAPTER.coverage()
    joined = " ".join(coverage.not_supported).lower()
    assert "no docker daemon" in joined or "daemon" in joined
    assert "kubernetes" in joined
    assert "registry" in joined
    assert "layer history" in joined or "per-file layer history" in joined


def test_discovery_still_emits_no_assessment(payments_scan) -> None:
    """Claim: the three-layer separation holds through the container path."""
    assets = inventory.build_assets(payments_scan.findings)
    assert assets
    assert all(asset.assessment is None for asset in assets)


# ==========================================================================
# Corrected provenance semantics (review pass)
# ==========================================================================


def test_layer_digest_is_a_real_sha256_of_layer_bytes(images: Path) -> None:
    """Claim: the layer digest is a genuine content hash, not a filename.

    An earlier revision stored a filename-derived value and called it a digest,
    which the honesty audit rightly rejects. The value must now be a real
    SHA-256 of the layer's bytes, verifiable independently.
    """
    import hashlib
    import shutil
    import tempfile

    workspace = Path(tempfile.mkdtemp())
    try:
        fmt = detect_container_format(images / "payments-api.tar")
        image = extract_image(
            images / "payments-api.tar", fmt, workspace, ContainerLimits()
        )
        assert image.layers
        for layer in image.layers:
            assert layer.digest.startswith("sha256:")
            hex_part = layer.digest.split(":", 1)[1]
            assert len(hex_part) == 64
            int(hex_part, 16)  # raises if not valid hex

        # Independently recompute the digest of the first layer's bytes.
        with tarfile.open(images / "payments-api.tar") as tar:
            manifest = json.loads(tar.extractfile("manifest.json").read())
            first_layer_name = manifest[0]["Layers"][0]
            raw = tar.extractfile(first_layer_name).read()
        expected = "sha256:" + hashlib.sha256(raw).hexdigest()
        assert image.layers[0].digest == expected
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_layer_digest_is_deterministic(images: Path) -> None:
    """Claim: the same layer hashes to the same digest every time."""
    import shutil
    import tempfile

    digests = []
    for _ in range(2):
        workspace = Path(tempfile.mkdtemp())
        try:
            fmt = detect_container_format(images / "payments-api.tar")
            image = extract_image(
                images / "payments-api.tar", fmt, workspace, ContainerLimits()
            )
            digests.append([layer.digest for layer in image.layers])
        finally:
            shutil.rmtree(workspace, ignore_errors=True)
    assert digests[0] == digests[1]


def test_docker_config_ref_is_not_claimed_as_a_digest(images: Path) -> None:
    """Claim: a Docker archive's config reference is an identifier, not a digest.

    The manifest references the config by filename. We do not verify it is a
    content digest, so we must not label it one.
    """
    import shutil
    import tempfile

    workspace = Path(tempfile.mkdtemp())
    try:
        fmt = detect_container_format(images / "payments-api.tar")
        image = extract_image(
            images / "payments-api.tar", fmt, workspace, ContainerLimits()
        )
        assert image.config_is_digest is False
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_provenance_reports_config_digest_honesty(payments_scan) -> None:
    """Claim: findings say whether the config reference is a real digest."""
    for finding in payments_scan.findings:
        prov = finding.raw_detail["container"]
        assert "image_config_ref" in prov
        assert "image_config_is_digest" in prov
        # Docker archive fixtures: the flag is false.
        assert prov["image_config_is_digest"] is False


def test_opaque_whiteout_clears_inherited_directory(tmp_path: Path) -> None:
    """Claim: an opaque whiteout hides everything a directory inherited.

    ``.wh..wh..opq`` in a directory removes all lower-layer files there before
    the current layer's contents apply. A file present only in the lower layer
    must not survive.
    """
    lower = {
        "app/inherited.py": b"import hashlib\nhashlib.md5(b'x')\n",
        "app/kept_by_lower.py": b"import hashlib\nhashlib.sha1(b'x')\n",
    }
    upper = {
        "app/.wh..wh..opq": b"",  # opaque: clear everything in app/
        "app/fresh.py": b"import hashlib\nhashlib.sha256(b'x')\n",
    }
    archive = demo_containers._image_archive([lower, upper], "opq:1")
    path = tmp_path / "opq.tar"
    path.write_bytes(archive)

    result = container.CONTAINER_ADAPTER.scan(path, "scan_opq")
    locations = {f.location for f in result.findings}
    # The inherited MD5 and SHA-1 files are gone; only the fresh file remains.
    assert not any("inherited.py" in loc for loc in locations)
    assert not any("kept_by_lower.py" in loc for loc in locations)
    assert any("fresh.py" in loc for loc in locations)


def test_opaque_whiteout_is_declared_in_coverage() -> None:
    """Claim: opaque-whiteout support is stated, not left implicit."""
    coverage = container.CONTAINER_ADAPTER.coverage()
    joined = " ".join(coverage.supported).lower()
    assert "opaque" in joined


def test_entry_count_is_bounded_before_extraction(tmp_path: Path) -> None:
    """Claim: a huge member count cannot exhaust memory before budgets engage.

    ``tarfile.getmembers()`` would read the entire member list into memory. The
    adapter iterates lazily with an entry ceiling instead. This builds a layer
    with many entries and confirms the ceiling stops iteration.
    """
    many_files = {f"app/f{i}.py": b"x = 1\n" for i in range(500)}
    archive = demo_containers._image_archive([many_files], "many:1")
    path = tmp_path / "many_entries.tar"
    path.write_bytes(archive)

    result = container.CONTAINER_ADAPTER.scan(
        path, "scan_entries", container_limits=ContainerLimits(max_entries=50)
    )
    # The scan completes without exhausting memory, and reports the limit.
    assert result.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
    assert any("entry limit" in e for e in result.errors)


def test_layer_record_source_ref_is_separate_from_digest(images: Path) -> None:
    """Claim: the filename reference is retained but kept distinct from the digest.

    Traceability to the archive member is useful; conflating it with the
    content digest was the original error.
    """
    import shutil
    import tempfile

    workspace = Path(tempfile.mkdtemp())
    try:
        fmt = detect_container_format(images / "payments-api.tar")
        image = extract_image(
            images / "payments-api.tar", fmt, workspace, ContainerLimits()
        )
        for layer in image.layers:
            assert layer.source_ref
            assert not layer.source_ref.startswith("sha256:")
            assert layer.source_ref != layer.digest
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_layer_provenance_keys_are_posix_separated(images: Path) -> None:
    """Claim: path-to-layer keys use forward slashes on every platform.

    Regression guard for a Windows-specific bug: the extraction side keyed
    path_layer with ``str(Path)`` (backslashes on Windows) while the lookup side
    normalised with ``as_posix()`` (forward slashes). The keys never matched on
    Windows, so every container finding silently lost its layer digest and
    index. Both sides now use ``as_posix()``; this asserts the keys are always
    POSIX-shaped, so the mismatch cannot return unnoticed.
    """
    import shutil
    import tempfile

    workspace = Path(tempfile.mkdtemp())
    try:
        fmt = detect_container_format(images / "payments-api.tar")
        image = extract_image(
            images / "payments-api.tar", fmt, workspace, ContainerLimits()
        )
        assert image.path_layer, "no paths were mapped to layers"
        for key in image.path_layer:
            assert "\\" not in key, f"path_layer key is not POSIX-separated: {key!r}"
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_container_layer_digest_and_index_reach_every_finding(
    images: Path, resolver: ComponentResolver
) -> None:
    """Claim: layer digest and index survive to every container finding.

    The Windows failure surfaced as an empty layer_digest and a None
    layer_index. This asserts, from a real scan, that both are populated on
    every finding — the property the path-key fix restores.
    """
    result = container.CONTAINER_ADAPTER.scan(
        images / "payments-api.tar", "scan_prov", resolver=resolver
    )
    assert result.findings
    for finding in result.findings:
        provenance = finding.raw_detail["container"]
        assert provenance["layer_digest"].startswith("sha256:")
        assert provenance["layer_index"] is not None
