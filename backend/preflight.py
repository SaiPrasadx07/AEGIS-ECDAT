"""
AegisPQC — pre-flight validation.

One command that answers a single question: **is this prototype safe to present
right now?**

Run it before you walk into the room, not thirty seconds before you speak. Every
check exercises a real code path rather than merely confirming a file exists,
because "the file is there" and "the thing works" are different claims and only
one of them matters on stage.

    python -m backend.preflight            full check, including the test suite
    python -m backend.preflight --fast     skip the test suite (~10s instead of ~60s)

Exit code 0 means go. Anything else means do not present until it is fixed.
"""

from __future__ import annotations

import argparse
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

from backend import config

# ANSI colours. Windows Terminal and PowerShell 5.1+ render these natively.
GREEN, RED, YELLOW, CYAN, DIM, BOLD, RESET = (
    "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[2m", "\033[1m", "\033[0m",
)


class CheckFailed(Exception):
    """Raised by a check to report a specific, actionable failure."""


# ==========================================================================
# Individual checks
# ==========================================================================


def check_python_environment() -> str:
    """Python version and interpreter are usable."""
    if sys.version_info < (3, 10):
        raise CheckFailed(
            f"Python {sys.version_info.major}.{sys.version_info.minor} is too old. "
            "This project needs 3.10 or newer for modern type syntax."
        )
    return f"Python {platform.python_version()} on {platform.system()}"


def check_dependencies() -> str:
    """Every required package imports."""
    required = {
        "cryptography": "cryptography",
        "fastapi": "fastapi",
        "pydantic": "pydantic",
        "streamlit": "streamlit",
        "plotly": "plotly",
        "pandas": "pandas",
    }
    missing: list[str] = []
    versions: list[str] = []

    for label, module_name in required.items():
        try:
            module = __import__(module_name)
            version = getattr(module, "__version__", None) or getattr(
                module, "VERSION", "?"
            )
            versions.append(f"{label} {version}")
        except ImportError:
            missing.append(label)

    if missing:
        raise CheckFailed(
            f"Missing packages: {', '.join(missing)}. "
            "Run: python -m pip install -r requirements.txt"
        )
    return ", ".join(versions)


def check_crypto_engine() -> str:
    """ML-KEM, hybrid, and RSA all round-trip on this machine.

    This is the check that matters most. If ML-KEM is unavailable — an older
    ``cryptography`` build, a wheel that fell back to a different backend — then
    nothing else in the product is meaningful, and it is better to find out now.
    """
    from backend import crypto_engine as ce

    message = b"pre-flight round trip"
    sizes: list[str] = []

    for algorithm in (
        config.ALGO_RSA_DEMO,
        config.ALGO_ML_KEM_768,
        config.ALGO_HYBRID,
        config.ALGO_RSA_2048,
    ):
        keypair = ce.generate_keypair(algorithm)
        envelope = ce.seal(algorithm, keypair.public_key, message, b"preflight")
        recovered = ce.unseal(algorithm, keypair.private_key, envelope, b"preflight")
        if recovered != message:
            raise CheckFailed(f"{algorithm} failed to round-trip")
        if algorithm == config.ALGO_ML_KEM_768:
            # Fixed by FIPS 203. If these differ, it is not ML-KEM-768.
            if keypair.public_key_bytes != 1184 or len(envelope.kem_ciphertext) != 1088:
                raise CheckFailed(
                    f"ML-KEM-768 sizes are wrong "
                    f"(public {keypair.public_key_bytes}B, "
                    f"ciphertext {len(envelope.kem_ciphertext)}B). "
                    "Expected 1184 and 1088 per FIPS 203."
                )
            sizes.append("ML-KEM-768 verified against FIPS 203 sizes")

    return "4 algorithms round-tripped; " + "; ".join(sizes)


def check_database() -> str:
    """SQLite opens, runs in WAL mode, and accepts writes."""
    from backend import database as db

    db.init_db()
    connection = db.get_connection()
    try:
        mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        connection.close()

    if mode.lower() != "wal":
        raise CheckFailed(f"Expected WAL journal mode, got {mode!r}")
    return f"SQLite ready at {config.DB_PATH.name} (WAL mode)"


def check_demo_data() -> str:
    """The demo scenario seeds, and the vault round-trips through it."""
    from backend import service as svc

    result = svc.reset_and_seed()
    packets = svc.list_harvested()
    if len(packets) != len(result["packets"]):
        raise CheckFailed("Seeded packet count does not match the harvest table")

    first = sorted(packets, key=lambda p: p["seq"])[0]
    received = svc.receive_message(first["packet_id"])
    if not received["plaintext"]:
        raise CheckFailed("Legitimate recipient could not decrypt a seeded packet")

    return f"{len(packets)} packets seeded and harvested; recipient decrypt verified"


def check_interceptor() -> str:
    """The harvest captures every algorithm, and stores no private keys."""
    from backend import database as db
    from backend import service as svc

    stats = svc.harvest_stats()
    if stats["total_packets"] == 0:
        raise CheckFailed("Interceptor archive is empty")
    if stats["quantum_safe_packets"] == 0:
        raise CheckFailed(
            "No post-quantum traffic was harvested. The core argument of the "
            "demo is that ALL traffic gets recorded."
        )

    connection = db.get_connection()
    try:
        private_keys = [
            row["private_key"]
            for row in connection.execute("SELECT private_key FROM key_store").fetchall()
        ]
        rows = connection.execute("SELECT * FROM network_sniff_log").fetchall()
    finally:
        connection.close()

    for row in rows:
        for column in row.keys():
            value = row[column]
            if isinstance(value, bytes):
                for private_key in private_keys:
                    if private_key in value:
                        raise CheckFailed(
                            f"PRIVATE KEY LEAK: found key material in "
                            f"network_sniff_log.{column}"
                        )

    return (
        f"{stats['total_packets']} packets held "
        f"({stats['vulnerable_packets']} vulnerable, "
        f"{stats['quantum_safe_packets']} quantum safe); no key leakage"
    )


def check_qday_simulator() -> str:
    """The real break works, and the post-quantum modes hold."""
    from backend import service as svc
    from backend import simulator as sim

    results = svc.attack_all()
    outcomes = {r["algorithm"]: r for r in results}

    demo = outcomes.get(config.ALGO_RSA_DEMO)
    if demo is None or demo["status"] != sim.STATUS_BREACHED:
        raise CheckFailed("The demo-scale RSA break did not succeed")
    if not demo["recovered_plaintext"]:
        raise CheckFailed("The break succeeded but recovered no plaintext")

    for algorithm in (config.ALGO_ML_KEM_768, config.ALGO_HYBRID):
        result = outcomes.get(algorithm)
        if result is None or result["status"] != sim.STATUS_IMMUNE:
            raise CheckFailed(f"{algorithm} did not hold against the attack")
        if result["recovered_plaintext"] is not None:
            raise CheckFailed(f"{algorithm} leaked plaintext — this is a serious bug")

    return (
        f"RSA-DEMO broken in {demo['execution_time_ms']:.0f} ms "
        f"({config.RSA_DEMO_PRIME_BITS * 2}-bit modulus, real factorisation); "
        "ML-KEM and hybrid held"
    )


def check_benchmarks() -> str:
    """Benchmarks run and return measured data for every algorithm."""
    from backend import service as svc

    rows = svc.benchmarks(5)
    if len(rows) != 3:
        raise CheckFailed(f"Expected 3 benchmark rows, got {len(rows)}")
    for row in rows:
        if row["keygen_ms"] <= 0 or row["public_key_bytes"] <= 0:
            raise CheckFailed(f"Benchmark for {row['algorithm']} returned no data")
    return f"{len(rows)} algorithms measured"


def check_demo_enterprise() -> str:
    """The fictional estate generates offline and contains real key material."""
    from backend import demo_enterprise as de

    root = de.ensure_generated()
    missing = [
        entry["path"]
        for entry in de.generate(root)["assets"]
        if not (root / entry["path"]).exists()
    ]
    if missing:
        raise CheckFailed(f"Demo enterprise is missing files: {missing}")

    return f"{len(de.ENTERPRISE_ASSETS)} assets generated at {root.name} (offline)"


def check_scanner() -> str:
    """The scanner parses the estate and produces a complete assessment."""
    from backend import demo_enterprise as de
    from backend import scanner
    from backend import service as svc

    report = svc.scan_demo_enterprise()

    if report["assets_scanned"] != len(de.ENTERPRISE_ASSETS):
        raise CheckFailed(
            f"Scanner saw {report['assets_scanned']} assets, "
            f"expected {len(de.ENTERPRISE_ASSETS)}"
        )
    if report["pqc_ready"] == 0:
        raise CheckFailed("Scanner found no PQC-ready asset; ML-KEM detection is broken")
    if report["quantum_vulnerable"] == 0:
        raise CheckFailed("Scanner found no vulnerable asset; RSA detection is broken")
    if not report["migration_order"]:
        raise CheckFailed("Scanner produced no migration order")
    if report["migration_order"][0]["risk"] != scanner.RISK_CRITICAL:
        raise CheckFailed("Migration order does not lead with a CRITICAL asset")

    verified_pqc = [
        f
        for f in report["findings"]
        if f["algorithm"].startswith("ML-KEM")
        and f["evidence"] == scanner.EVIDENCE_VERIFIED
    ]
    if not verified_pqc:
        raise CheckFailed("No ML-KEM key was verified from real key material")

    return (
        f"{report['assets_scanned']} assets scanned, "
        f"{report['quantum_vulnerable']} vulnerable, {report['pqc_ready']} PQC ready, "
        f"score {report['readiness_score']}/100 ({report['verdict']})"
    )


def check_streamlit_app() -> str:
    """The dashboard file exists, parses, and declares all seven surfaces."""
    import ast

    app_file = config.PROJECT_ROOT / "frontend" / "app.py"
    if not app_file.exists():
        raise CheckFailed(f"Dashboard not found at {app_file}")

    ui_file = config.PROJECT_ROOT / "frontend" / "ui.py"
    if not ui_file.exists():
        raise CheckFailed(f"Design system not found at {ui_file}")

    for path in (app_file, ui_file):
        try:
            ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            raise CheckFailed(
                f"{path.name} has a syntax error at line {exc.lineno}"
            ) from exc

    source = app_file.read_text(encoding="utf-8")
    expected_tabs = [
        "Overview",
        "PQC Readiness",
        "Migration Plan",
        "Quantum Vault",
        "HNDL Hoard",
        "Q-Day Simulator",
        "Benchmarks",
    ]
    missing = [tab for tab in expected_tabs if f'"{tab}"' not in source]
    if missing:
        raise CheckFailed(f"Dashboard is missing surfaces: {missing}")

    return f"{len(expected_tabs)} surfaces present, dashboard and design system parse"


def check_migration_planner() -> str:
    """The migration plan builds and passes its own consistency verification."""
    from backend import service as svc

    plan = svc.migration_plan()
    verification = svc.verify_migration_plan(plan)

    if not plan["recommendations"]:
        raise CheckFailed("Migration planner produced an empty queue")
    if not verification["consistent"]:
        failures = [c["name"] for c in verification["checks"] if not c["passed"]]
        raise CheckFailed(f"Migration plan is inconsistent: {failures}")
    if plan["recommendations"][0]["risk"] != "CRITICAL":
        raise CheckFailed("Migration queue does not lead with a CRITICAL asset")
    if not all(r["why_first"] for r in plan["recommendations"]):
        raise CheckFailed("Some queued assets have no stated justification")

    return (
        f"{plan['assets_requiring_migration']} assets queued across "
        f"{sum(1 for p in plan['phases'] if p['asset_count'])} phases; "
        f"{verification['verdict'].lower()}"
    )


def check_reporting() -> str:
    """Reports generate in both formats and contain no key material."""
    from backend import service as svc

    report = svc.full_report()
    document = svc.report_markdown()

    if not report["inventory"]:
        raise CheckFailed("Report contains no inventory")
    if "## Migration priorities" not in document:
        raise CheckFailed("Markdown report is missing the migration section")

    # The generator raises on detection, so reaching here means it passed —
    # but check the rendered document directly as well.
    for marker in ("-----BEGIN", "private_key"):
        if marker in document:
            raise CheckFailed(f"PRIVATE KEY LEAK: report contains {marker!r}")

    return f"JSON and Markdown reports generated ({len(document):,} chars), no key material"


def check_fastapi() -> str:
    """The API imports and every documented route is registered."""
    from backend.main import app

    routes = {getattr(route, "path", "") for route in app.routes}
    required = {
        "/api/health",
        "/api/demo/reset",
        "/api/keys/generate",
        "/api/vault/send",
        "/api/vault/receive",
        "/api/interceptor/hoarded-packets",
        "/api/simulator/q-day-attack",
        "/api/benchmarks/run",
        "/api/scanner/demo-enterprise",
        "/api/scanner/scan",
    }
    missing = required - routes
    if missing:
        raise CheckFailed(f"API is missing routes: {sorted(missing)}")

    return f"{len(required)} core routes registered; /docs available when running"


def check_test_suite() -> str:
    """The full pytest suite passes.

    Slow (roughly a minute), so ``--fast`` skips it. Worth running at least once
    on the presentation machine.
    """
    start = time.perf_counter()
    process = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-q", "-p", "no:cacheprovider"],
        cwd=str(config.PROJECT_ROOT),
        capture_output=True,
        text=True,
        timeout=900,
    )
    elapsed = time.perf_counter() - start

    if process.returncode != 0:
        tail = "\n".join(process.stdout.strip().splitlines()[-12:])
        raise CheckFailed(f"Test suite failed:\n{tail}")

    summary = ""
    for line in reversed(process.stdout.strip().splitlines()):
        if "passed" in line:
            summary = line.strip()
            break
    return f"{summary or 'all tests passed'} ({elapsed:.0f}s)"


# ==========================================================================
# Runner
# ==========================================================================

#: Ordered so that a failure surfaces the root cause rather than a symptom.
#: Dependencies before crypto, crypto before database, database before demo data.
CHECKS: list[tuple[str, Callable[[], str]]] = [
    ("Python environment", check_python_environment),
    ("Dependencies", check_dependencies),
    ("Crypto Engine", check_crypto_engine),
    ("Database", check_database),
    ("Demo Data", check_demo_data),
    ("HNDL Interceptor", check_interceptor),
    ("Q-Day Simulator", check_qday_simulator),
    ("Benchmarks", check_benchmarks),
    ("Demo Enterprise", check_demo_enterprise),
    ("PQC Scanner", check_scanner),
    ("Migration Planner", check_migration_planner),
    ("Reporting", check_reporting),
    ("Streamlit", check_streamlit_app),
    ("FastAPI", check_fastapi),
]


def run_all(include_tests: bool = True) -> dict[str, Any]:
    """Run every check and return a structured report.

    Args:
        include_tests: Whether to run the full pytest suite. Skipped by the
            release test module, which would otherwise recurse into itself.

    Returns:
        ``{"ready": bool, "checks": [...], "elapsed_seconds": float}``.
    """
    checks = list(CHECKS)
    if include_tests:
        checks.append(("Test Suite", check_test_suite))

    results: list[dict[str, Any]] = []
    started = time.perf_counter()

    for name, function in checks:
        check_started = time.perf_counter()
        try:
            detail = function()
            passed, error = True, ""
        except CheckFailed as exc:
            detail, passed, error = "", False, str(exc)
        except Exception as exc:  # unexpected: still a NO-GO, but label it
            detail, passed, error = "", False, f"unexpected error: {exc!r}"

        results.append(
            {
                "name": name,
                "passed": passed,
                "detail": detail,
                "error": error,
                "elapsed_ms": round((time.perf_counter() - check_started) * 1000, 1),
            }
        )

    return {
        "ready": all(result["passed"] for result in results),
        "checks": results,
        "elapsed_seconds": round(time.perf_counter() - started, 1),
    }


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point. Returns a shell exit code."""
    parser = argparse.ArgumentParser(description="AegisPQC pre-flight validation")
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Skip the full test suite (about 10 seconds instead of 60)",
    )
    args = parser.parse_args(argv)

    print()
    print(f"{BOLD}{CYAN}{'=' * 58}{RESET}")
    print(f"{BOLD}{CYAN}        AEGISPQC PRE-FLIGHT{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 58}{RESET}")
    print()

    report = run_all(include_tests=not args.fast)

    for result in report["checks"]:
        if result["passed"]:
            print(f"  {GREEN}[ OK ]{RESET} {result['name']:<20} {DIM}{result['detail']}{RESET}")
        else:
            print(f"  {RED}[FAIL]{RESET} {result['name']:<20} {RED}{result['error']}{RESET}")

    print()
    print(f"{BOLD}{CYAN}{'=' * 58}{RESET}")

    if report["ready"]:
        print(f"{BOLD}{GREEN}        ALL SYSTEMS GO{RESET}")
        print(f"{BOLD}{CYAN}{'=' * 58}{RESET}")
        print()
        print(f"  {DIM}Checks completed in {report['elapsed_seconds']}s")
        if args.fast:
            print("  Test suite skipped (--fast). Run without --fast at least once.")
        print(f"{RESET}")
        print(f"  {BOLD}READY FOR PRESENTATION{RESET}")
        print()
        print(f"  {DIM}Launch: .\\run_demo.ps1{RESET}")
        print()
        return 0

    failures = [result for result in report["checks"] if not result["passed"]]
    print(f"{BOLD}{RED}        NO-GO — {len(failures)} CHECK(S) FAILED{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 58}{RESET}")
    print()
    for failure in failures:
        print(f"  {RED}{failure['name']}{RESET}: {failure['error']}")
    print()
    print(f"  {YELLOW}Do not present until these are resolved.{RESET}")
    print()
    return 1


if __name__ == "__main__":
    sys.exit(main())
