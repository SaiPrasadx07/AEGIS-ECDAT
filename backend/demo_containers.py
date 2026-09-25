"""
Aegis PQC — demonstration container images.

Builds real Docker-style image archives so the container adapter has genuine
structure to extract, rather than a hand-crafted stand-in.

WHY THESE ARE REAL ARCHIVES
---------------------------
Each image is a valid ``docker save`` layout: a ``manifest.json`` naming its
layers in order, and one or more layer tarballs holding a real filesystem. The
container adapter parses them with the same code that would handle an archive
from a production registry. Nothing here is mocked.

WHAT GOES INSIDE
----------------
The layers are populated from the *same fixtures the earlier phases already
use* — the compiled OpenSSL-linked binary from Phase 4, the manifests from
Phase 2, the source from Phase 3. That reuse is the point: it lets the tests
prove that an artefact discovered on disk and the same artefact discovered
inside an image produce the identical finding, differing only in provenance.

    payments-api    A dependency manifest and the real crypto binary.
    legacy-auth     A manifest and source with MD5/DES.
    pqc-pilot       Source using ML-KEM and a hybrid construction.
    content-portal  Benign files and false-positive bait — must stay clean.

Layer semantics are exercised too: the payments image ships the binary in one
layer and then, in a later layer, a whiteout marker plus a replacement, so the
merge-and-override and deletion paths are covered by a real fixture rather than
only by unit tests.

NO SECRETS
----------
Every file placed in every layer comes from a fixture already audited for
secrets in earlier phases. Nothing new is introduced here.
"""

from __future__ import annotations

import io
import json
import tarfile
import time
from pathlib import Path

from backend import demo_binaries, demo_manifests, demo_source


def _tar_bytes(files: dict[str, bytes]) -> bytes:
    """Build an in-memory tar of ``path -> contents`` (a container layer)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for path, data in files.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            info.mtime = 0  # fixed, so archives are byte-deterministic
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _image_archive(layers: list[dict[str, bytes]], repo_tag: str) -> bytes:
    """Assemble a Docker-style image archive from ordered layers.

    Produces the ``manifest.json`` + layer-tar structure that ``docker save``
    writes and the container adapter expects.
    """
    outer = io.BytesIO()
    with tarfile.open(fileobj=outer, mode="w") as tar:
        layer_names: list[str] = []
        for index, files in enumerate(layers):
            layer_bytes = _tar_bytes(files)
            layer_name = f"layer_{index}.tar"
            info = tarfile.TarInfo(name=layer_name)
            info.size = len(layer_bytes)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(layer_bytes))
            layer_names.append(layer_name)

        config = json.dumps(
            {"architecture": "amd64", "os": "linux"}, sort_keys=True
        ).encode()
        config_name = "config.json"
        info = tarfile.TarInfo(name=config_name)
        info.size = len(config)
        info.mtime = 0
        tar.addfile(info, io.BytesIO(config))

        manifest = json.dumps(
            [{"Config": config_name, "RepoTags": [repo_tag], "Layers": layer_names}]
        ).encode()
        info = tarfile.TarInfo(name="manifest.json")
        info.size = len(manifest)
        info.mtime = 0
        tar.addfile(info, io.BytesIO(manifest))

    return outer.getvalue()


def build_payments_image() -> bytes:
    """payments-api: real crypto binary, plus a layer exercising overrides.

    Layer 0 installs an early build of the binary and the dependency manifest.
    Layer 1 whites out the early binary and installs the real compiled one, so
    the merge sees only the final version — exercising override and whiteout
    against a genuine artefact.
    """
    binary = demo_binaries.crypto_service_bytes()
    manifest = demo_manifests.PAYMENTS_REQUIREMENTS.encode()

    layer0 = {
        "app/requirements.txt": manifest,
        "app/bin/crypto_service": b"\x7fELF placeholder from an earlier build\n",
    }
    layer1 = {
        "app/bin/.wh.crypto_service": b"",  # whiteout removes the placeholder
        "app/bin/crypto_service": binary,  # the real binary replaces it
    }
    return _image_archive([layer0, layer1], "payments-api:2026.09")


def build_legacy_auth_image() -> bytes:
    """legacy-auth: manifest and source carrying MD5 and DES."""
    layer0 = {
        "srv/pom.xml": demo_manifests.LEGACY_AUTH_POM.encode(),
        "srv/session.py": demo_source.LEGACY_AUTH_PY.encode(),
    }
    return _image_archive([layer0], "legacy-auth:1.4")


def build_pqc_pilot_image() -> bytes:
    """pqc-pilot: source using ML-KEM and a hybrid construction."""
    layer0 = {
        "opt/hybrid.py": demo_source.PQC_PILOT_PY.encode(),
        "opt/go.mod": demo_manifests.PQC_PILOT_GO_MOD.encode(),
    }
    return _image_archive([layer0], "pqc-pilot:0.3")


def build_content_portal_image() -> bytes:
    """content-portal: benign files and false-positive bait. Must stay clean."""
    layer0 = {
        "www/render.js": demo_source.CONTENT_PORTAL_JS.encode(),
        "www/content.py": demo_source.CONTENT_PORTAL_PY.encode(),
        "www/package.json": demo_manifests.CONTENT_PORTAL_PACKAGE_JSON.encode(),
        "www/README.md": demo_source.CONTENT_PORTAL_README.encode(),
    }
    return _image_archive([layer0], "content-portal:2.1")


#: Image builders keyed by the archive filename they are written to.
DEMO_IMAGES: dict[str, callable] = {
    "payments-api.tar": build_payments_image,
    "legacy-auth.tar": build_legacy_auth_image,
    "pqc-pilot.tar": build_pqc_pilot_image,
    "content-portal.tar": build_content_portal_image,
}

#: Images expected to yield at least one finding.
CRYPTO_IMAGES: frozenset[str] = frozenset(
    {"payments-api.tar", "legacy-auth.tar", "pqc-pilot.tar"}
)

#: Images that must yield nothing — the false-positive control.
CLEAN_IMAGES: frozenset[str] = frozenset({"content-portal.tar"})


def write_demo_images(root: Path) -> list[Path]:
    """Write the demonstration container archives into ``root``.

    Args:
        root: Directory to receive the ``.tar`` image archives.

    Returns:
        Paths written, sorted.
    """
    images_dir = root / "images"
    images_dir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    for filename, builder in DEMO_IMAGES.items():
        path = images_dir / filename
        path.write_bytes(builder())
        written.append(path)
    return sorted(written)
