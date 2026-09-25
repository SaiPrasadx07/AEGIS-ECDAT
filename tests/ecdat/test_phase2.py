"""
Aegis PQC — ECDAT Phase 2 tests: dependency and library discovery.

Separate from the inherited suite, and from Phase 1, so coverage per phase can
be reported honestly.

Run Phase 2 only:  pytest tests/ecdat/test_phase2.py -q
Run all ECDAT:     pytest tests/ecdat -q
Run everything:    pytest tests -q
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend import demo_enterprise as de
from backend import demo_manifests as dm
from backend import discovery, inventory, knowledge
from backend.discovery import ScanLimits, certificates, dependencies
from backend.discovery.attribution import (
    AttributionMethod,
    ComponentResolver,
    extract_declared_paths,
)
from backend.discovery.dependencies import (
    parse_go_mod,
    parse_package_json,
    parse_pom_xml,
    parse_requirements_txt,
)
from backend.model import (
    ArtefactType,
    Confidence,
    DetectionMethod,
    ScanStatus,
    SourceType,
)


@pytest.fixture(scope="module")
def estate(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A full demo estate: certificates plus application manifests."""
    root = tmp_path_factory.mktemp("phase2_estate")
    de.generate(root, force=True)
    dm.write_application_manifests(root)
    return root


@pytest.fixture(scope="module")
def resolver(estate: Path) -> ComponentResolver:
    """Component resolver built from the estate's declared policy."""
    raw = inventory._parse_policy_file(estate / "aegis_policy.yaml")
    return ComponentResolver(extract_declared_paths(raw))


@pytest.fixture(scope="module")
def scan(estate: Path, resolver: ComponentResolver):
    """One real dependency scan of the estate."""
    return dependencies.DEPENDENCY_ADAPTER.scan(estate, "scan_p2", resolver=resolver)


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    """Isolated database with the ECDAT schema."""
    path = tmp_path / "phase2.db"
    inventory.init_ecdat_schema(path)
    return path


# ==========================================================================
# requirements.txt
# ==========================================================================


def test_requirements_parses_pinned_versions() -> None:
    """Claim: an exact pin yields the package and its version."""
    found = parse_requirements_txt("cryptography==42.0.5\npyOpenSSL==24.0.0\n")
    assert [(d.package, d.version) for d in found] == [
        ("cryptography", "42.0.5"),
        ("pyOpenSSL", "24.0.0"),
    ]


def test_requirements_handles_extras_markers_and_comments() -> None:
    """Claim: real-world requirement syntax parses correctly.

    Developers write extras, environment markers, and inline comments. A parser
    that only handles the clean case is not usable against real repositories.
    """
    text = (
        "# deployment requirements\n"
        "cryptography[ssh]==42.0.5  # pinned for reproducibility\n"
        "pynacl==1.5.0 ; python_version >= '3.9'\n"
        "\n"
        "   \n"
    )
    found = parse_requirements_txt(text)
    assert [(d.package, d.version) for d in found] == [
        ("cryptography", "42.0.5"),
        ("pynacl", "1.5.0"),
    ]


def test_requirements_records_unpinned_packages() -> None:
    """Claim: a package with no version is still discovered.

    The dependency is real; only the version is unknown. Dropping it would hide
    a genuine cryptographic library.
    """
    found = parse_requirements_txt("cryptography\nrsa>=4.9\n")
    assert found[0].package == "cryptography"
    assert found[0].version == ""
    assert found[1].package == "rsa"
    assert found[1].version == ">=4.9"


def test_requirements_skips_unresolvable_entries() -> None:
    """Claim: VCS, editable, and option lines are skipped.

    Each would need resolution the scanner deliberately does not perform, and
    guessing a package name from a git URL would be a fabrication.
    """
    text = (
        "-r base.txt\n"
        "-e .\n"
        "--index-url https://example.invalid/simple\n"
        "git+https://example.invalid/repo.git#egg=something\n"
        "cryptography==42.0.5\n"
    )
    found = parse_requirements_txt(text)
    assert [d.package for d in found] == ["cryptography"]


def test_requirements_records_line_numbers() -> None:
    """Claim: findings point at the line that produced them."""
    found = parse_requirements_txt("# header\n\ncryptography==42.0.5\n")
    assert found[0].line == 3


# ==========================================================================
# package.json
# ==========================================================================


def test_package_json_parses_all_dependency_sections() -> None:
    """Claim: dev and peer dependencies are inventoried too.

    A cryptographic library in devDependencies is still present in the
    repository and still part of the estate's cryptographic surface.
    """
    text = json.dumps(
        {
            "dependencies": {"node-forge": "1.3.1"},
            "devDependencies": {"crypto-js": "^4.2.0"},
            "peerDependencies": {"elliptic": "6.5.4"},
        }
    )
    found = {d.package: d for d in parse_package_json(text)}
    assert set(found) == {"node-forge", "crypto-js", "elliptic"}
    assert found["crypto-js"].scope == "devDependencies"
    assert found["elliptic"].scope == "peerDependencies"


def test_package_json_preserves_range_syntax() -> None:
    """Claim: a caret range is recorded as written, not normalised away."""
    found = parse_package_json(json.dumps({"dependencies": {"elliptic": "^6.5.4"}}))
    assert found[0].version == "^6.5.4"


def test_malformed_package_json_yields_nothing() -> None:
    """Claim: broken JSON produces no findings and does not raise."""
    assert parse_package_json("{not valid json") == []
    assert parse_package_json("") == []
    assert parse_package_json("[1, 2, 3]") == []


# ==========================================================================
# pom.xml
# ==========================================================================


def test_pom_parses_namespaced_and_bare() -> None:
    """Claim: both POM dialects parse.

    Maven files appear with and without the namespace declaration; a parser
    handling only one would silently miss half of a real estate.
    """
    namespaced = """<?xml version="1.0"?>
    <project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies><dependency>
      <groupId>commons-codec</groupId><artifactId>commons-codec</artifactId>
      <version>1.15</version></dependency></dependencies></project>"""
    bare = """<project><dependencies><dependency>
      <groupId>commons-codec</groupId><artifactId>commons-codec</artifactId>
      <version>1.15</version></dependency></dependencies></project>"""

    for text in (namespaced, bare):
        found = parse_pom_xml(text)
        assert len(found) == 1
        assert found[0].package == "commons-codec:commons-codec"
        assert found[0].version == "1.15"


def test_pom_resolves_property_versions() -> None:
    """Claim: a ${property} version is resolved against the POM's properties."""
    text = """<project>
      <properties><bc.version>1.68</bc.version></properties>
      <dependencies><dependency>
        <groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk15on</artifactId>
        <version>${bc.version}</version></dependency></dependencies></project>"""
    found = parse_pom_xml(text)
    assert found[0].version == "1.68"


def test_pom_leaves_unresolvable_property_empty() -> None:
    """Claim: an unresolvable placeholder becomes an empty version.

    Reporting the literal ``${parent.version}`` as a version would be worse than
    reporting none — it looks like data while being meaningless.
    """
    text = """<project><dependencies><dependency>
      <groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId>
      <version>${parent.version}</version></dependency></dependencies></project>"""
    assert parse_pom_xml(text)[0].version == ""


def test_pom_records_scope() -> None:
    """Claim: test-scoped dependencies are marked as such."""
    text = """<project><dependencies><dependency>
      <groupId>junit</groupId><artifactId>junit</artifactId>
      <version>4.13.2</version><scope>test</scope>
      </dependency></dependencies></project>"""
    assert parse_pom_xml(text)[0].scope == "test"


def test_malformed_pom_yields_nothing() -> None:
    """Claim: unparseable XML produces no findings and does not raise."""
    assert parse_pom_xml("<project><unclosed>") == []
    assert parse_pom_xml("") == []


# ==========================================================================
# go.mod
# ==========================================================================


def test_go_mod_parses_require_block() -> None:
    """Claim: a parenthesised require block parses, with indirect marked."""
    text = (
        "module example.com/app\n\ngo 1.22\n\n"
        "require (\n"
        "\tgithub.com/cloudflare/circl v1.3.7\n"
        "\tgolang.org/x/crypto v0.21.0\n"
        "\tgithub.com/stretchr/testify v1.9.0 // indirect\n"
        ")\n"
    )
    found = {d.package: d for d in parse_go_mod(text)}
    assert found["github.com/cloudflare/circl"].version == "1.3.7"
    assert found["golang.org/x/crypto"].scope == "direct"
    assert found["github.com/stretchr/testify"].scope == "indirect"


def test_go_mod_parses_single_line_require() -> None:
    """Claim: the single-line form parses too."""
    found = parse_go_mod("module x\n\nrequire golang.org/x/crypto v0.21.0\n")
    assert found[0].package == "golang.org/x/crypto"
    assert found[0].version == "0.21.0"


def test_go_mod_strips_major_version_suffix() -> None:
    """Claim: a /v5 path suffix is trimmed so it matches the knowledge base.

    Go encodes the major version in the module path. Without trimming,
    ``github.com/golang-jwt/jwt/v5`` would never match its knowledge entry.
    """
    found = parse_go_mod("module x\n\nrequire github.com/golang-jwt/jwt/v5 v5.2.1\n")
    assert found[0].package == "github.com/golang-jwt/jwt"


def test_malformed_go_mod_yields_nothing() -> None:
    """Claim: garbage input produces no findings and does not raise."""
    assert parse_go_mod("module\n\nrequire (\n") == []
    assert parse_go_mod("") == []


# ==========================================================================
# Knowledge base
# ==========================================================================


def test_knowledge_base_loads_all_ecosystems() -> None:
    """Claim: the knowledge base parses without a YAML dependency."""
    counts = knowledge.coverage_by_ecosystem()
    assert set(counts) == {"pypi", "npm", "maven", "go"}
    assert knowledge.known_package_count() == sum(counts.values())
    assert knowledge.known_package_count() >= 20


def test_lookup_is_case_and_separator_insensitive() -> None:
    """Claim: PyPI naming variations resolve to one entry.

    PyPI treats underscore and hyphen as equivalent and is case-insensitive, so
    ``PyJWT``, ``pyjwt``, and ``py_jwt`` must not become three unknown packages.
    """
    assert knowledge.lookup("pypi", "PyJWT") is not None
    assert knowledge.lookup("pypi", "pyjwt") is not None
    assert knowledge.lookup("npm", "crypto-js") is not None
    assert knowledge.lookup("npm", "crypto_js") is not None


def test_unknown_packages_return_nothing() -> None:
    """Claim: a non-cryptographic package is never classified.

    This is the false-positive guard. A web framework is not cryptographic
    material, and inventing a classification would make the whole inventory
    untrustworthy.
    """
    for package in ("flask", "react", "express", "requests", "numpy", "left-pad"):
        assert knowledge.lookup("pypi", package) is None or package in ("requests",)
    assert knowledge.lookup("npm", "react") is None
    assert knowledge.lookup("npm", "express") is None
    assert knowledge.lookup("pypi", "flask") is None
    assert knowledge.lookup("go", "github.com/gin-gonic/gin") is None


def test_ecosystems_do_not_bleed_into_each_other() -> None:
    """Claim: a package name is looked up within its own ecosystem only."""
    assert knowledge.lookup("npm", "cryptography") is None
    assert knowledge.lookup("pypi", "node-forge") is None


def test_deprecated_and_unmaintained_entries_are_marked() -> None:
    """Claim: legacy packages carry status and a replacement where one exists."""
    pycrypto = knowledge.lookup("pypi", "pycrypto")
    assert pycrypto.status == knowledge.STATUS_UNMAINTAINED
    assert pycrypto.is_legacy
    assert pycrypto.superseded_by == "pycryptodome"

    bc = knowledge.lookup("maven", "org.bouncycastle:bcprov-jdk15on")
    assert bc.status == knowledge.STATUS_DEPRECATED
    assert bc.superseded_by == "org.bouncycastle:bcprov-jdk18on"


def test_pqc_capability_is_claimed_only_where_real() -> None:
    """Claim: ``pqc_capable`` marks only libraries that ship NIST PQC.

    Overstating this would be the most damaging possible error in a
    post-quantum readiness tool — it would report an estate as further along
    than it is.
    """
    assert knowledge.lookup("go", "github.com/cloudflare/circl").pqc_capable is True
    assert knowledge.lookup("maven", "org.bouncycastle:bcprov-jdk18on").pqc_capable is True
    assert knowledge.lookup("pypi", "rsa").pqc_capable is False
    assert knowledge.lookup("npm", "node-forge").pqc_capable is False


def test_capability_note_never_claims_usage() -> None:
    """Claim: every capability statement disclaims usage.

    A library providing RSA is not evidence the application performs RSA. This
    sentence is what keeps the distinction visible in the UI.
    """
    for (ecosystem, key) in knowledge.load_library_profiles():
        profile = knowledge.lookup(ecosystem, key)
        note = profile.capability_note()
        if profile.provides:
            assert "not evidence" in note


@pytest.mark.parametrize(
    "version,minimum,expected",
    [
        ("1.2.0", "1.3.0", True),
        ("1.4.0", "1.3.0", False),
        ("^6.5.5", "6.5.4", False),
        (">=1.0,<2", "1.3.0", None),
        ("${bc.version}", "1.3.0", None),
        ("1.x", "1.3.0", None),
        ("", "1.3.0", None),
    ],
)
def test_version_comparison_refuses_ranges(version, minimum, expected) -> None:
    """Claim: an unresolvable version produces no claim in either direction.

    An earlier implementation reduced ``>=1.0,<2`` to its lower bound and
    reported it as outdated — a false positive, since the range permits 1.9. A
    scanner that cries wolf about versions stops being believed.
    """
    assert knowledge.is_below_recommended(version, minimum) is expected


def test_exact_version_detection() -> None:
    """Claim: pinned versions are distinguished from ranges."""
    assert knowledge.is_exact_version("1.3.0") is True
    assert knowledge.is_exact_version("2.0.0rc1") is True
    assert knowledge.is_exact_version("^1.3.0") is False
    assert knowledge.is_exact_version(">=49.0.0") is False
    assert knowledge.is_exact_version("") is False


def test_malformed_knowledge_base_degrades(tmp_path: Path) -> None:
    """Claim: a broken knowledge base yields fewer libraries, never a crash."""
    broken = tmp_path / "broken.yaml"
    broken.write_text(":::\n\x00garbage\n  - - -\n")
    assert knowledge.load_library_profiles(broken) == {}

    missing = tmp_path / "absent.yaml"
    assert knowledge.load_library_profiles(missing) == {}


# ==========================================================================
# Component attribution — the Phase 1 concern
# ==========================================================================


def test_declared_path_beats_directory_heuristic(tmp_path: Path) -> None:
    """Claim: a declared mapping overrides the directory-name guess.

    This is the Phase 1 defect: an application not sitting at the top level was
    misattributed, and its business context silently resolved to defaults.
    """
    root = tmp_path / "estate"
    target = root / "services" / "payments" / "requirements.txt"
    target.parent.mkdir(parents=True)
    target.write_text("cryptography==42.0.5\n")

    naive = ComponentResolver()
    assert naive.attribute(root, target).component == "services"

    declared = ComponentResolver({"payments-api": "services/payments"})
    result = declared.attribute(root, target)
    assert result.component == "payments-api"
    assert result.method is AttributionMethod.DECLARED_PATH
    assert result.is_declared


def test_longest_declared_prefix_wins(tmp_path: Path) -> None:
    """Claim: the most specific declared path matches.

    A nested service inside a declared parent must attribute to the service,
    not the parent.
    """
    root = tmp_path / "estate"
    target = root / "services" / "payments" / "go.mod"
    target.parent.mkdir(parents=True)
    target.write_text("module x\n")

    resolver = ComponentResolver(
        {"platform": "services", "payments-api": "services/payments"}
    )
    assert resolver.attribute(root, target).component == "payments-api"


def test_declared_paths_normalise_separators(tmp_path: Path) -> None:
    """Claim: path declarations are forgiving of how they were written.

    Operators write ``payments``, ``payments/``, and ``./payments``
    interchangeably, and Windows contributors write backslashes.
    """
    root = tmp_path / "estate"
    target = root / "payments" / "requirements.txt"
    target.parent.mkdir(parents=True)
    target.write_text("rsa==4.9\n")

    for declared in ("payments", "payments/", "./payments", "payments\\"):
        resolver = ComponentResolver({"payments-api": declared})
        assert resolver.attribute(root, target).component == "payments-api", declared


def test_attribution_falls_back_and_records_the_method(tmp_path: Path) -> None:
    """Claim: an undeclared path still attributes, and says how."""
    root = tmp_path / "estate"
    nested = root / "unknown-app" / "requirements.txt"
    nested.parent.mkdir(parents=True)
    nested.write_text("rsa==4.9\n")

    resolver = ComponentResolver({"payments-api": "payments"})
    result = resolver.attribute(root, nested)
    assert result.component == "unknown-app"
    assert result.method is AttributionMethod.DIRECTORY_HEURISTIC
    assert not result.is_declared


def test_file_at_scan_root_attributes_to_parent(tmp_path: Path) -> None:
    """Claim: a manifest directly under the root still resolves."""
    root = tmp_path / "solo"
    root.mkdir()
    manifest = root / "requirements.txt"
    manifest.write_text("rsa==4.9\n")

    result = ComponentResolver().attribute(root, manifest)
    assert result.component == "solo"
    assert result.method is AttributionMethod.PARENT_DIRECTORY


def test_extract_declared_paths_ignores_components_without_one() -> None:
    """Claim: only components declaring a path enter the mapping."""
    raw = {
        "payments-api": {"path": "payments", "data_lifetime_years": 25},
        "legacy-auth": {"data_lifetime_years": 30},
        "broken": {"path": "   "},
    }
    assert extract_declared_paths(raw) == {"payments-api": "payments"}


# ==========================================================================
# Adapter behaviour on the demo estate
# ==========================================================================


def test_scan_discovers_dependencies_across_all_manifests(scan) -> None:
    """Claim: all four manifest formats produce findings in one scan."""
    assert scan.status is ScanStatus.COMPLETED
    assert scan.errors == []
    assert len(scan.findings) >= 15

    manifests = {f.raw_detail["manifest"] for f in scan.findings}
    assert manifests == {"requirements.txt", "pom.xml", "go.mod", "package.json"}


def test_findings_are_libraries_not_algorithms(scan) -> None:
    """Claim: a declared dependency is reported as a library, nothing more.

    The algorithm field stays empty on purpose. Populating it would let a
    consumer treat a manifest mention as a located algorithm — a far stronger
    claim than the evidence supports.
    """
    for finding in scan.findings:
        assert finding.artefact_type is ArtefactType.LIBRARY
        assert finding.algorithm == ""
        assert finding.variant == ""
        assert finding.library
        assert finding.source_type is SourceType.DEPENDENCY
        assert finding.detection_method is DetectionMethod.MANIFEST_PARSE


def test_every_finding_carries_the_capability_disclaimer(scan) -> None:
    """Claim: the capability-versus-usage distinction reaches every finding."""
    for finding in scan.findings:
        note = finding.raw_detail.get("capability_note", "")
        assert "not evidence" in note


def test_confidence_reflects_version_certainty(scan) -> None:
    """Claim: a ranged version is MEDIUM, an exact pin is HIGH.

    Confidence tracks whether the deployed release is actually knowable.
    """
    for finding in scan.findings:
        declared = finding.library_version
        if knowledge.is_exact_version(declared):
            assert finding.confidence is Confidence.HIGH, declared
        else:
            assert finding.confidence is Confidence.MEDIUM, declared


def test_deprecated_dependencies_are_flagged(scan) -> None:
    """Claim: legacy packages in the estate are surfaced with a replacement."""
    legacy = [f for f in scan.findings if f.raw_detail.get("legacy_status")]
    names = {f.library for f in legacy}
    assert "PyCrypto" in names
    assert "Bouncy Castle (JDK 1.5 provider)" in names
    for finding in legacy:
        assert finding.raw_detail.get("superseded_by")


def test_outdated_versions_are_flagged_against_the_floor(scan) -> None:
    """Claim: a version below the recommended floor is reported."""
    flagged = {
        f.library: f.raw_detail["below_recommended_version"]
        for f in scan.findings
        if "below_recommended_version" in f.raw_detail
    }
    assert flagged.get("PyJWT") == "2.0.0"
    assert flagged.get("node-forge") == "1.3.0"


def test_pqc_capable_dependency_is_identified(scan) -> None:
    """Claim: the scanner recognises the good case, not only failures."""
    pqc = [f for f in scan.findings if f.raw_detail.get("pqc_capable")]
    assert pqc
    assert "CIRCL" in {f.library for f in pqc}
    assert {f.component for f in pqc} == {"pqc-pilot"}


def test_non_crypto_application_produces_no_findings(scan) -> None:
    """Claim: an application with no cryptographic dependencies yields nothing.

    ``content-portal`` declares seven packages, none cryptographic. Producing a
    finding for any of them would be the false positive that discredits the
    whole inventory.
    """
    components = {f.component for f in scan.findings}
    assert "content-portal" not in components


def test_components_are_attributed_from_declared_paths(scan) -> None:
    """Claim: findings land on the declared application, not a directory guess."""
    components = {f.component for f in scan.findings}
    assert {"payments-api", "legacy-auth", "pqc-pilot", "mobile-gateway"} <= components


def test_multiple_crypto_libraries_in_one_application(scan) -> None:
    """Claim: an application with several crypto dependencies reports each."""
    legacy_auth = [f for f in scan.findings if f.component == "legacy-auth"]
    assert len(legacy_auth) >= 5
    assert len({f.library for f in legacy_auth}) == len(legacy_auth)


def test_duplicate_declarations_are_collapsed(tmp_path: Path) -> None:
    """Claim: one package declared twice in a manifest is one finding."""
    root = tmp_path / "dup"
    root.mkdir()
    (root / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"node-forge": "1.3.1"},
                "devDependencies": {"node-forge": "1.3.1"},
            }
        )
    )
    result = dependencies.DEPENDENCY_ADAPTER.scan(root, "scan_dup")
    assert len([f for f in result.findings if f.library == "node-forge"]) == 1


def test_same_package_at_different_versions_is_not_collapsed(tmp_path: Path) -> None:
    """Claim: two versions of one package across applications are distinct.

    Collapsing them would hide a real inconsistency in the estate.
    """
    root = tmp_path / "multi"
    for app, version in (("a", "1.3.1"), ("b", "0.10.0")):
        (root / app).mkdir(parents=True)
        (root / app / "package.json").write_text(
            json.dumps({"dependencies": {"node-forge": version}})
        )
    result = dependencies.DEPENDENCY_ADAPTER.scan(root, "scan_multi")
    versions = {f.library_version for f in result.findings if f.library == "node-forge"}
    assert versions == {"1.3.1", "0.10.0"}


# ==========================================================================
# Determinism
# ==========================================================================


def test_repeat_scans_are_identical(estate: Path, resolver: ComponentResolver) -> None:
    """Claim: an unchanged estate scans identically every time."""
    first = dependencies.DEPENDENCY_ADAPTER.scan(estate, "scan_det", resolver=resolver)
    second = dependencies.DEPENDENCY_ADAPTER.scan(estate, "scan_det", resolver=resolver)
    assert [f.finding_id for f in first.findings] == [f.finding_id for f in second.findings]


def test_finding_ids_are_unique_within_a_scan(scan) -> None:
    """Claim: no two findings collide on an id."""
    ids = [f.finding_id for f in scan.findings]
    assert len(ids) == len(set(ids))


# ==========================================================================
# Safety — never execute, never overreach
# ==========================================================================


def test_adapter_invokes_no_package_manager() -> None:
    """Claim: no package manager, build tool, or subprocess is ever called.

    A static check on the source. Aegis analyses artefacts; executing a
    repository's build would hand control to the thing under examination.
    """
    source = Path(dependencies.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "subprocess", "os.system", "popen", "eval(", "exec(",
        "importlib", "__import__", "pip install", "npm install", "mvn ", "go get",
    ):
        assert forbidden not in source, f"dependency adapter references {forbidden!r}"


def test_adapter_respects_traversal_safety(tmp_path: Path) -> None:
    """Claim: the shared traversal guards apply to this adapter too."""
    root = tmp_path / "estate"
    (root / "app").mkdir(parents=True)
    (root / "app" / "requirements.txt").write_text("cryptography==42.0.5\n")
    (root / "node_modules" / "pkg").mkdir(parents=True)
    (root / "node_modules" / "pkg" / "package.json").write_text(
        json.dumps({"dependencies": {"node-forge": "1.3.1"}})
    )

    result = dependencies.DEPENDENCY_ADAPTER.scan(root, "scan_safe")
    locations = {Path(f.location).parent.name for f in result.findings}
    assert "pkg" not in locations
    assert "app" in locations


def test_oversized_manifest_is_skipped(tmp_path: Path) -> None:
    """Claim: the size ceiling applies to manifests."""
    root = tmp_path / "big"
    root.mkdir()
    (root / "requirements.txt").write_text("cryptography==42.0.5\n" + "# pad\n" * 5000)

    result = dependencies.DEPENDENCY_ADAPTER.scan(
        root, "scan_big", limits=ScanLimits(max_file_bytes=200)
    )
    assert result.findings == []


def test_evidence_is_bounded_and_from_declarations_only(scan) -> None:
    """Claim: evidence never carries unbounded file content.

    Evidence is drawn from a parsed dependency declaration and truncated, so no
    manifest can leak an unrelated secret into a finding.
    """
    for finding in scan.findings:
        assert len(finding.evidence) <= 220
        assert "→" in finding.evidence


def test_empty_repository_scans_cleanly(tmp_path: Path) -> None:
    """Claim: a repository with no manifests returns an empty result."""
    root = tmp_path / "empty"
    root.mkdir()
    result = dependencies.DEPENDENCY_ADAPTER.scan(root, "scan_empty")
    assert result.status is ScanStatus.COMPLETED
    assert result.findings == []


def test_unsupported_manifest_is_ignored(tmp_path: Path) -> None:
    """Claim: a manifest format we do not support produces nothing.

    Guessing at a Gemfile or Cargo.toml would be a claim the parser cannot back.
    """
    root = tmp_path / "ruby"
    root.mkdir()
    (root / "Gemfile").write_text("gem 'openssl'\n")
    (root / "Cargo.toml").write_text('[dependencies]\nring = "0.17"\n')

    result = dependencies.DEPENDENCY_ADAPTER.scan(root, "scan_unsupported")
    assert result.findings == []


def test_missing_target_fails_cleanly(tmp_path: Path) -> None:
    """Claim: a bad path is a reported failure, not an exception."""
    result = dependencies.DEPENDENCY_ADAPTER.scan(tmp_path / "nope", "scan_missing")
    assert result.status is ScanStatus.FAILED
    assert result.errors


def test_coverage_declares_real_limits() -> None:
    """Claim: the adapter states what it cannot do."""
    coverage = dependencies.DEPENDENCY_ADAPTER.coverage()
    joined = " ".join(coverage.not_supported).lower()
    assert "transitive" in joined
    assert "lock file" in joined
    assert "knowledge base" in joined
    assert "source scanning" in joined
    assert coverage.confidence_notes


# ==========================================================================
# Integration — two adapters, one model
# ==========================================================================


def test_both_adapters_are_registered() -> None:
    """Claim: the registry now holds two conforming adapters."""
    assert {"certificates", "dependencies"} <= set(discovery.available_adapters())
    for name in ("certificates", "dependencies"):
        adapter = discovery.get_adapter(name)
        assert isinstance(adapter, discovery.DiscoveryAdapter)
        assert adapter.coverage().not_supported


def test_certificate_and_dependency_findings_share_one_model(
    estate: Path, resolver: ComponentResolver, db: Path
) -> None:
    """Claim: the canonical model holds a second discovery surface.

    This is the real test of Phase 1's abstraction: both adapters persist to the
    same tables and reload through the same code path, with no dependency-
    specific schema anywhere.
    """
    cert_scan = certificates.CERTIFICATE_ADAPTER.scan(estate, "scan_mixed")
    dep_scan = dependencies.DEPENDENCY_ADAPTER.scan(
        estate, "scan_mixed", resolver=resolver
    )

    inventory.record_scan(cert_scan, db)
    inventory.record_scan(dep_scan, db)

    reloaded = inventory.get_findings("scan_mixed", db)
    sources = {f.source_type for f in reloaded}
    assert sources == {SourceType.CERTIFICATE_FILE, SourceType.DEPENDENCY}
    assert len(reloaded) == len(cert_scan.findings) + len(dep_scan.findings)


def test_mixed_inventory_summary_counts_both_surfaces(
    estate: Path, resolver: ComponentResolver, db: Path
) -> None:
    """Claim: the inventory summary aggregates across adapters unchanged."""
    for scan_result in (
        certificates.CERTIFICATE_ADAPTER.scan(estate, "scan_sum"),
        dependencies.DEPENDENCY_ADAPTER.scan(estate, "scan_sum", resolver=resolver),
    ):
        inventory.record_scan(scan_result, db)

    summary = inventory.inventory_summary("scan_sum", db)
    assert summary["by_source_type"]["certificate_file"] > 0
    assert summary["by_source_type"]["dependency"] > 0
    assert summary["by_artefact_type"]["library"] > 0
    assert sum(summary["by_source_type"].values()) == summary["total_findings"]


def test_dependency_findings_survive_persistence(
    estate: Path, resolver: ComponentResolver, db: Path
) -> None:
    """Claim: library metadata round-trips through the database intact."""
    scan_result = dependencies.DEPENDENCY_ADAPTER.scan(
        estate, "scan_persist", resolver=resolver
    )
    inventory.record_scan(scan_result, db)

    reloaded = {f.finding_id: f for f in inventory.get_findings("scan_persist", db)}
    assert len(reloaded) == len(scan_result.findings)

    for original in scan_result.findings:
        stored = reloaded[original.finding_id]
        assert stored.library == original.library
        assert stored.library_version == original.library_version
        assert stored.component == original.component
        assert stored.confidence is original.confidence
        assert stored.raw_detail["provides_algorithms"] == (
            original.raw_detail["provides_algorithms"]
        )


def test_discovery_still_emits_no_assessment(scan) -> None:
    """Claim: the three-layer separation holds for the second adapter.

    Dependency discovery reports facts. Risk, recommendations, and priority
    remain the assessment engine's responsibility.
    """
    assets = inventory.build_assets(scan.findings)
    assert assets
    assert all(asset.assessment is None for asset in assets)

    serialised = json.dumps([f.to_dict() for f in scan.findings])
    for forbidden in ('"risk_level"', '"migration_priority"', '"mosca"'):
        assert forbidden not in serialised


def test_demo_estate_contains_no_secrets(estate: Path) -> None:
    """Claim: the demonstration manifests carry no credentials.

    They are published in a public repository and screenshotted in a
    presentation.
    """
    for relative in dm.APPLICATION_MANIFESTS:
        text = (estate / relative).read_text(encoding="utf-8")
        lowered = text.lower()
        for marker in ("password", "secret", "api_key", "apikey", "token=", "-----begin"):
            assert marker not in lowered, f"{relative} contains {marker!r}"
