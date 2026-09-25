"""
Aegis PQC — cryptographic asset inventory.

The layer between discovery and assessment. It takes raw
:class:`~backend.model.CryptoFinding` records from any adapter, resolves the
organisation context that applies to each, assembles
:class:`~backend.model.CryptoAsset` composites, and persists everything so that
scans accumulate into an inventory rather than evaporating.

CONTEXT RESOLUTION IS THE POINT
-------------------------------
A scanner can establish that ``payments-api`` uses RSA-2048. It cannot
establish that the data must stay confidential for twenty-five years. That is
an organisational fact, and the quality of every downstream risk rating depends
on where it came from.

:func:`resolve_context` uses three tiers, in descending authority:

1. ``USER_INPUT``  — edited in the dashboard, stored in the database
2. ``POLICY_FILE`` — ``aegis_policy.yaml`` shipped alongside the estate
3. ``DEFAULT``     — documented fallback, always marked as undeclared

Every resolved context records which tier supplied it, and the dashboard
renders that marker. The honest answer to "how do you know this data lives
twenty-five years?" is "we do not — the organisation declared it, and here is
where." Inferring it would be the single most damaging overclaim available.

PERSISTENCE
-----------
Findings are written to dedicated ECDAT tables. The four inherited tables used
by the Security Lab are untouched, so the frozen surfaces keep working while
the new inventory accumulates beside them.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from backend import database
from backend.model import (
    ApplicationContext,
    ArtefactType,
    BusinessCriticality,
    CertificateFacts,
    Confidence,
    ContextSource,
    CryptoAsset,
    CryptoFinding,
    DEFAULT_CRITICALITY,
    DEFAULT_DATA_LIFETIME_YEARS,
    DEFAULT_SENSITIVITY,
    DetectionMethod,
    ScanResult,
    ScanStatus,
    Sensitivity,
    SourceType,
    utc_now,
)

#: Filename an estate uses to declare business context for its applications.
POLICY_FILENAME = "aegis_policy.yaml"

# ==========================================================================
# Schema
# ==========================================================================
# Additive only. The inherited users / key_store / network_sniff_log /
# quantum_attack_log tables are not referenced here and must not be altered —
# the Security Lab depends on them exactly as they are.

_ECDAT_SCHEMA = """
CREATE TABLE IF NOT EXISTS ecdat_scans (
    scan_id         TEXT PRIMARY KEY,
    target          TEXT NOT NULL,
    target_type     TEXT NOT NULL DEFAULT '',
    adapters        TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL,
    finding_count   INTEGER NOT NULL DEFAULT 0,
    files_examined  INTEGER NOT NULL DEFAULT 0,
    errors          TEXT NOT NULL DEFAULT '',
    started_at      TEXT NOT NULL,
    completed_at    TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ecdat_findings (
    finding_id       TEXT PRIMARY KEY,
    scan_id          TEXT NOT NULL,
    artefact_type    TEXT NOT NULL,
    algorithm        TEXT NOT NULL DEFAULT '',
    algorithm_family TEXT NOT NULL DEFAULT '',
    variant          TEXT NOT NULL DEFAULT '',
    key_size         INTEGER,
    mode             TEXT NOT NULL DEFAULT '',
    oid              TEXT NOT NULL DEFAULT '',
    library          TEXT NOT NULL DEFAULT '',
    library_version  TEXT NOT NULL DEFAULT '',
    protocol         TEXT NOT NULL DEFAULT '',
    certificate      TEXT NOT NULL DEFAULT '',
    source_type      TEXT NOT NULL,
    location         TEXT NOT NULL DEFAULT '',
    line             INTEGER,
    component        TEXT NOT NULL DEFAULT '',
    detection_method TEXT NOT NULL,
    evidence         TEXT NOT NULL DEFAULT '',
    confidence       TEXT NOT NULL,
    raw_detail       TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES ecdat_scans (scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ecdat_context (
    component            TEXT PRIMARY KEY,
    data_sensitivity     TEXT NOT NULL,
    data_lifetime_years  INTEGER NOT NULL,
    business_criticality TEXT NOT NULL,
    context_source       TEXT NOT NULL,
    notes                TEXT NOT NULL DEFAULT '',
    updated_at           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ecdat_findings_scan ON ecdat_findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_ecdat_findings_component ON ecdat_findings (component);
CREATE INDEX IF NOT EXISTS idx_ecdat_findings_algorithm ON ecdat_findings (algorithm);
"""


def init_ecdat_schema(db_path: Path | None = None) -> None:
    """Create the ECDAT tables if absent. Safe to call repeatedly.

    Reuses :func:`backend.database.get_connection` so WAL mode, foreign-key
    enforcement, and the connection settings stay identical to the inherited
    layer.
    """
    database.init_db(db_path)
    conn = database.get_connection(db_path)
    try:
        conn.executescript(_ECDAT_SCHEMA)
        conn.commit()
    finally:
        conn.close()


# ==========================================================================
# Context resolution
# ==========================================================================


def _parse_policy_file(path: Path) -> dict[str, dict[str, Any]]:
    """Read an ``aegis_policy.yaml`` into a per-component mapping.

    Deliberately parsed with a small hand-rolled reader rather than a YAML
    dependency. The supported subset is a flat two-level mapping, which is all
    the policy format needs, and avoiding the dependency keeps installation
    unchanged. A JSON file of the same name is also accepted.

    Malformed input yields an empty mapping rather than raising: a broken
    policy file must not abort a scan, it must fall back to documented defaults
    with the provenance marked accordingly.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    # A policy file may legitimately be JSON.
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            loaded = json.loads(text)
            return loaded if isinstance(loaded, dict) else {}
        except json.JSONDecodeError:
            return {}

    result: dict[str, dict[str, Any]] = {}
    current: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())
        content = line.strip()

        if indent == 0:
            if content.endswith(":"):
                current = content[:-1].strip().strip("\"'")
                result[current] = {}
            continue

        if current is None or ":" not in content:
            continue

        key, _, value = content.partition(":")
        cleaned = value.strip().strip("\"'")
        if cleaned:
            result[current][key.strip()] = cleaned

    return result


def _coerce_sensitivity(value: Any) -> Sensitivity:
    """Map a declared value onto the enum, falling back to the default."""
    try:
        return Sensitivity(str(value).strip().lower())
    except ValueError:
        return DEFAULT_SENSITIVITY


def _coerce_criticality(value: Any) -> BusinessCriticality:
    """Map a declared value onto the enum, falling back to the default."""
    try:
        return BusinessCriticality(str(value).strip().lower())
    except ValueError:
        return DEFAULT_CRITICALITY


def _coerce_years(value: Any) -> int:
    """Parse a declared lifetime, clamped to a sane range."""
    try:
        years = int(float(str(value).strip()))
    except (ValueError, TypeError):
        return DEFAULT_DATA_LIFETIME_YEARS
    return max(0, min(years, 200))


def load_policy(estate_root: Path) -> dict[str, ApplicationContext]:
    """Load declared context from an estate's policy file.

    Args:
        estate_root: Directory that may contain ``aegis_policy.yaml``.

    Returns:
        Per-component context, each marked ``POLICY_FILE``. Empty if no
        readable policy file exists.
    """
    for candidate in (estate_root / POLICY_FILENAME, estate_root / "aegis_policy.json"):
        if not candidate.exists():
            continue
        raw = _parse_policy_file(candidate)
        contexts: dict[str, ApplicationContext] = {}
        for component, values in raw.items():
            if not isinstance(values, dict):
                continue
            contexts[component] = ApplicationContext(
                component=component,
                data_sensitivity=_coerce_sensitivity(values.get("data_sensitivity")),
                data_lifetime_years=_coerce_years(values.get("data_lifetime_years")),
                business_criticality=_coerce_criticality(values.get("business_criticality")),
                context_source=ContextSource.POLICY_FILE,
                notes=str(values.get("notes", "")),
            )
        return contexts
    return {}


def get_stored_context(component: str, db_path: Path | None = None) -> ApplicationContext | None:
    """Fetch user-supplied context for a component, if any was saved."""
    conn = database.get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM ecdat_context WHERE component = ?", (component,)
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    finally:
        conn.close()

    if row is None:
        return None
    return ApplicationContext(
        component=row["component"],
        data_sensitivity=_coerce_sensitivity(row["data_sensitivity"]),
        data_lifetime_years=_coerce_years(row["data_lifetime_years"]),
        business_criticality=_coerce_criticality(row["business_criticality"]),
        context_source=ContextSource(row["context_source"]),
        notes=row["notes"] or "",
    )


def save_context(context: ApplicationContext, db_path: Path | None = None) -> None:
    """Persist context for a component, overwriting any previous value."""
    init_ecdat_schema(db_path)
    conn = database.get_connection(db_path)
    try:
        conn.execute(
            """
            INSERT INTO ecdat_context (component, data_sensitivity, data_lifetime_years,
                                       business_criticality, context_source, notes, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (component) DO UPDATE SET
                data_sensitivity     = excluded.data_sensitivity,
                data_lifetime_years  = excluded.data_lifetime_years,
                business_criticality = excluded.business_criticality,
                context_source       = excluded.context_source,
                notes                = excluded.notes,
                updated_at           = excluded.updated_at
            """,
            (
                context.component,
                context.data_sensitivity.value,
                context.data_lifetime_years,
                context.business_criticality.value,
                context.context_source.value,
                context.notes,
                utc_now(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def resolve_context(
    component: str,
    policy: dict[str, ApplicationContext] | None = None,
    db_path: Path | None = None,
) -> ApplicationContext:
    """Resolve business context for a component across the three tiers.

    Order of authority: stored user input, then the estate's policy file, then
    the documented default. The returned object always records which tier
    supplied it.

    Args:
        component: Application the context applies to.
        policy: Pre-loaded policy mapping, if the caller has one.
        db_path: Optional database override.

    Returns:
        Resolved context, never ``None`` — an unresolvable component yields the
        default, explicitly marked as undeclared.
    """
    stored = get_stored_context(component, db_path)
    if stored is not None:
        return stored

    if policy and component in policy:
        return policy[component]

    return ApplicationContext.default_for(component)


# ==========================================================================
# Asset assembly
# ==========================================================================


def build_assets(
    findings: Iterable[CryptoFinding],
    policy: dict[str, ApplicationContext] | None = None,
    db_path: Path | None = None,
) -> list[CryptoAsset]:
    """Bind findings to their resolved context.

    Context is resolved once per component rather than once per finding, so an
    estate with hundreds of findings across a dozen applications performs a
    dozen lookups.

    Assessment is left as ``None`` — computing risk is the assessment engine's
    job, and discovery must not pre-empt it.
    """
    resolved: dict[str, ApplicationContext] = {}
    assets: list[CryptoAsset] = []

    for finding in findings:
        component = finding.component or "unattributed"
        if component not in resolved:
            resolved[component] = resolve_context(component, policy, db_path)
        assets.append(CryptoAsset(finding=finding, context=resolved[component]))

    return assets


# ==========================================================================
# Persistence
# ==========================================================================


def record_scan(result: ScanResult, db_path: Path | None = None) -> str:
    """Persist a scan and all of its findings.

    Returns:
        The scan id.
    """
    init_ecdat_schema(db_path)
    conn = database.get_connection(db_path)
    try:
        conn.execute(
            """
            INSERT INTO ecdat_scans (scan_id, target, target_type, adapters, status,
                                     finding_count, files_examined, errors,
                                     started_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (scan_id) DO UPDATE SET
                status         = excluded.status,
                finding_count  = excluded.finding_count,
                files_examined = excluded.files_examined,
                errors         = excluded.errors,
                completed_at   = excluded.completed_at
            """,
            (
                result.scan_id,
                result.target,
                "directory" if Path(result.target).is_dir() else "file",
                result.adapter,
                result.status.value,
                len(result.findings),
                result.files_examined,
                json.dumps(result.errors),
                result.started_at or utc_now(),
                result.completed_at or utc_now(),
            ),
        )

        for finding in result.findings:
            conn.execute(
                """
                INSERT INTO ecdat_findings (
                    finding_id, scan_id, artefact_type, algorithm, algorithm_family,
                    variant, key_size, mode, oid, library, library_version, protocol,
                    certificate, source_type, location, line, component,
                    detection_method, evidence, confidence, raw_detail
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (finding_id) DO NOTHING
                """,
                (
                    finding.finding_id,
                    finding.scan_id,
                    finding.artefact_type.value,
                    finding.algorithm,
                    finding.algorithm_family,
                    finding.variant,
                    finding.key_size,
                    finding.mode,
                    finding.oid,
                    finding.library,
                    finding.library_version,
                    finding.protocol,
                    json.dumps(finding.certificate.to_dict()) if finding.certificate else "",
                    finding.source_type.value,
                    finding.location,
                    finding.line,
                    finding.component,
                    finding.detection_method.value,
                    finding.evidence,
                    finding.confidence.value,
                    json.dumps(finding.raw_detail, default=str),
                ),
            )

        conn.commit()
        return result.scan_id
    finally:
        conn.close()


def _row_to_finding(row: sqlite3.Row) -> CryptoFinding:
    """Rebuild a finding from a database row."""
    certificate = None
    if row["certificate"]:
        try:
            certificate = CertificateFacts(**json.loads(row["certificate"]))
        except (json.JSONDecodeError, TypeError):
            certificate = None

    try:
        raw_detail = json.loads(row["raw_detail"]) if row["raw_detail"] else {}
    except json.JSONDecodeError:
        raw_detail = {}

    return CryptoFinding(
        finding_id=row["finding_id"],
        scan_id=row["scan_id"],
        artefact_type=ArtefactType(row["artefact_type"]),
        algorithm=row["algorithm"],
        algorithm_family=row["algorithm_family"],
        variant=row["variant"],
        key_size=row["key_size"],
        mode=row["mode"],
        oid=row["oid"],
        library=row["library"],
        library_version=row["library_version"],
        protocol=row["protocol"],
        certificate=certificate,
        source_type=SourceType(row["source_type"]),
        location=row["location"],
        line=row["line"],
        component=row["component"],
        detection_method=DetectionMethod(row["detection_method"]),
        evidence=row["evidence"],
        confidence=Confidence(row["confidence"]),
        raw_detail=raw_detail,
    )


def get_findings(scan_id: str, db_path: Path | None = None) -> list[CryptoFinding]:
    """Every finding from one scan, ordered deterministically.

    Ordered by ``finding_id`` so repeated reads return an identical sequence
    regardless of filesystem or insertion order.
    """
    init_ecdat_schema(db_path)
    conn = database.get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM ecdat_findings WHERE scan_id = ? ORDER BY finding_id",
            (scan_id,),
        ).fetchall()
        return [_row_to_finding(row) for row in rows]
    finally:
        conn.close()


def get_assets(
    scan_id: str,
    policy: dict[str, ApplicationContext] | None = None,
    db_path: Path | None = None,
) -> list[CryptoAsset]:
    """Rebuild the full asset view for one scan."""
    return build_assets(get_findings(scan_id, db_path), policy, db_path)


def list_scans(db_path: Path | None = None, limit: int = 50) -> list[dict[str, Any]]:
    """Scan history, newest first.

    The foundation for scan-to-scan comparison: two scan ids and their findings
    are all a diff needs.
    """
    init_ecdat_schema(db_path)
    conn = database.get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM ecdat_scans ORDER BY started_at DESC, rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            record = dict(row)
            try:
                record["errors"] = json.loads(record["errors"]) if record["errors"] else []
            except json.JSONDecodeError:
                record["errors"] = []
            out.append(record)
        return out
    finally:
        conn.close()


def inventory_summary(scan_id: str, db_path: Path | None = None) -> dict[str, Any]:
    """Aggregate counts for one scan's inventory.

    Discovery-level only: what was found, where, and how confidently. Risk is
    absent by design — it belongs to the assessment engine, and reporting it
    here would let two components disagree about the same asset.
    """
    findings = get_findings(scan_id, db_path)

    by_algorithm: dict[str, int] = {}
    by_component: dict[str, int] = {}
    by_artefact: dict[str, int] = {}
    by_confidence: dict[str, int] = {}
    by_source: dict[str, int] = {}

    for finding in findings:
        label = finding.algorithm or "unidentified"
        by_algorithm[label] = by_algorithm.get(label, 0) + 1
        component = finding.component or "unattributed"
        by_component[component] = by_component.get(component, 0) + 1
        by_artefact[finding.artefact_type.value] = by_artefact.get(finding.artefact_type.value, 0) + 1
        by_confidence[finding.confidence.value] = by_confidence.get(finding.confidence.value, 0) + 1
        by_source[finding.source_type.value] = by_source.get(finding.source_type.value, 0) + 1

    return {
        "scan_id": scan_id,
        "total_findings": len(findings),
        "components": len(by_component),
        "by_algorithm": dict(sorted(by_algorithm.items())),
        "by_component": dict(sorted(by_component.items())),
        "by_artefact_type": dict(sorted(by_artefact.items())),
        "by_confidence": dict(sorted(by_confidence.items())),
        "by_source_type": dict(sorted(by_source.items())),
    }
