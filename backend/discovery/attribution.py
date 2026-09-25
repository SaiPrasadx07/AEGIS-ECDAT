"""
Aegis PQC — component attribution.

Answers "which application does this file belong to?" for every discovery
adapter.

WHY THIS EXISTS
---------------
Phase 1 attributed findings by taking the first directory segment below the
scan root. That is correct on a tidy estate and wrong on a monorepo, a nested
service layout, or anything where applications do not sit at the top level.

The failure was quiet, which is what made it worth fixing early: a
misattributed finding resolves its business context to the documented default,
so a twenty-five-year payments asset silently becomes a five-year one and its
risk rating drops. Nothing errors; the number is just wrong.

RESOLUTION ORDER
----------------
1. **Declared mapping** — a ``path:`` under a component in the policy file.
   Longest matching prefix wins, so ``services/payments/`` beats ``services/``.
2. **First path segment** — the Phase 1 heuristic, retained as a fallback.
3. **Parent directory name** — for files directly under the scan root.

Every resolution records which rule produced it, so the dashboard can show
attribution as declared or inferred rather than presenting a guess as a fact.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath


class AttributionMethod(str, Enum):
    """How a component was determined."""

    DECLARED_PATH = "declared_path"
    DIRECTORY_HEURISTIC = "directory_heuristic"
    PARENT_DIRECTORY = "parent_directory"
    UNATTRIBUTED = "unattributed"


#: Used when no rule produces a component.
UNATTRIBUTED = "unattributed"


@dataclass(frozen=True, slots=True)
class Attribution:
    """A resolved component and the rule that produced it."""

    component: str
    method: AttributionMethod

    @property
    def is_declared(self) -> bool:
        """True when an operator mapped this path explicitly."""
        return self.method is AttributionMethod.DECLARED_PATH


def _normalise(prefix: str) -> str:
    """Normalise a declared path prefix to a comparable POSIX form.

    Declared prefixes are written by hand and arrive inconsistently —
    ``payments``, ``payments/``, ``./payments``, ``payments\\`` on Windows.
    Normalising here means the comparison logic below handles one shape.
    """
    cleaned = prefix.strip().replace("\\", "/").strip("/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


class ComponentResolver:
    """Maps file paths to owning components.

    Args:
        declared: Component name to declared path prefix, from the policy file.
    """

    def __init__(self, declared: dict[str, str] | None = None) -> None:
        # Sorted longest-first so the most specific prefix matches first.
        self._prefixes: list[tuple[str, str]] = sorted(
            (
                (_normalise(prefix), component)
                for component, prefix in (declared or {}).items()
                if _normalise(prefix)
            ),
            key=lambda pair: len(pair[0]),
            reverse=True,
        )

    @property
    def has_declarations(self) -> bool:
        """True when at least one component declared a path."""
        return bool(self._prefixes)

    def declared_components(self) -> list[str]:
        """Components with a declared path mapping."""
        return sorted({component for _, component in self._prefixes})

    def attribute(self, root: Path, path: Path) -> Attribution:
        """Resolve the component owning ``path``.

        Args:
            root: Scan root the path was discovered under.
            path: File being attributed.

        Returns:
            The component and the rule that produced it. Never raises — a path
            outside the root falls back to its parent directory name rather
            than failing the scan.
        """
        try:
            relative = PurePosixPath(
                path.resolve(strict=False)
                .relative_to(root.resolve(strict=False))
                .as_posix()
            )
        except (ValueError, OSError):
            return Attribution(path.parent.name or UNATTRIBUTED,
                               AttributionMethod.PARENT_DIRECTORY)

        relative_text = str(relative)

        # 1. Declared path mapping, most specific first.
        for prefix, component in self._prefixes:
            if relative_text == prefix or relative_text.startswith(prefix + "/"):
                return Attribution(component, AttributionMethod.DECLARED_PATH)

        # 2. First path segment — the Phase 1 heuristic.
        parts = relative.parts
        if len(parts) > 1:
            return Attribution(parts[0], AttributionMethod.DIRECTORY_HEURISTIC)

        # 3. A file directly under the root has no owning directory.
        return Attribution(
            path.parent.name or UNATTRIBUTED, AttributionMethod.PARENT_DIRECTORY
        )


def extract_declared_paths(raw_policy: dict[str, dict]) -> dict[str, str]:
    """Pull ``path:`` declarations out of a parsed policy mapping.

    The policy file already carries business context per component; a ``path:``
    key alongside it declares which directory that component owns. Reusing the
    existing structure keeps one file for operators to maintain.

    Args:
        raw_policy: Component name to its declared values.

    Returns:
        Component name to declared path prefix, for components that declared one.
    """
    paths: dict[str, str] = {}
    for component, values in raw_policy.items():
        if not isinstance(values, dict):
            continue
        declared = values.get("path")
        if isinstance(declared, str) and declared.strip():
            paths[component] = declared
    return paths
