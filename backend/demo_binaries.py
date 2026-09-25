"""
Aegis PQC — demonstration compiled artefact.

Ships one genuinely compiled binary so the binary scanner has real structure to
analyse rather than a fabricated file.

WHY A REAL BINARY
-----------------
A hand-crafted file with plausible-looking bytes would be exactly the kind of
fabrication this project refuses elsewhere. The artefact below was compiled
with gcc from a small C program that links OpenSSL and calls RSA, AES, DES,
MD5, and SHA-256 entry points. It is a real ELF: ``readelf``, ``objdump``, and
``nm`` all read it, and the scanner parses it with no special handling.

Stored zlib-compressed and base64-encoded — 2.8 KB of text for a 14 KB binary —
so it travels inside the repository without a build step on the target machine.

WHAT IT CONTAINS
----------------
    DT_NEEDED       libcrypto.so.3, libc.so.6
    Imported        RSA_new, RSA_generate_key_ex, EVP_aes_256_gcm,
                    EVP_des_ecb, EVP_md5, EVP_sha256, EVP_MD_CTX_new,
                    EVP_DigestInit_ex, OpenSSL_version
    Strings         a build tag identifying the service

It contains no credentials, no keys, and no OpenSSL source — only references to
symbols resolved at load time.

PLATFORM NOTE
-------------
This is an x86-64 Linux ELF. The scanner parses it identically on Windows and
macOS, because parsing a file format does not require the host to be able to
run it. PE and Mach-O are supported by the same library but are not exercised
by this fixture, and the adapter's coverage statement says so.
"""

from __future__ import annotations

import base64
import zlib
from pathlib import Path

#: Compiled ELF, zlib-compressed and base64-encoded.
CRYPTO_SERVICE_ELF_B64 = """\
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
    chRQqPGeoP4xD38WgzXea4Pgf0Od+fNfU30R0A==
"""

#: Where the artefact is written inside the demonstration estate.
BINARY_RELATIVE_PATH = "payments-api/bin/crypto_service"

#: Structures a correct scan finds in it. Used by the tests as an explicit
#: contract rather than an assumption about what gcc happened to emit.
EXPECTED_LIBRARIES = ("libcrypto.so.3",)
EXPECTED_CRYPTO_SYMBOLS = (
    "RSA_new",
    "RSA_generate_key_ex",
    "EVP_aes_256_gcm",
    "EVP_des_ecb",
    "EVP_md5",
    "EVP_sha256",
)


def crypto_service_bytes() -> bytes:
    """Decode the compiled artefact.

    Returns:
        The ELF as raw bytes, byte-identical to what gcc produced.
    """
    return zlib.decompress(base64.b64decode(CRYPTO_SERVICE_ELF_B64))


def write_application_binaries(root: Path) -> list[Path]:
    """Write the demonstration binary into ``root``.

    Args:
        root: Estate root directory.

    Returns:
        Paths written.
    """
    target = root / Path(BINARY_RELATIVE_PATH)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(crypto_service_bytes())
    return [target]
