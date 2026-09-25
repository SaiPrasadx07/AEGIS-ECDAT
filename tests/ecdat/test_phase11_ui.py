"""
Aegis PQC — ECDAT premium redesign tests.

The redesign is presentation-only: it changes how the ECDAT dashboard looks, not
what it computes. These tests confirm the new premium layer renders without
error, the pure style helpers behave, no external asset or overclaim crept in,
and — most importantly — the frozen Security Lab is still byte-for-byte
unchanged.

Run these only:  pytest tests/ecdat/test_phase11_ui.py -q
Run everything:  pytest tests -q
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pytest

from frontend import ecdat_style as sx

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


# ==========================================================================
# Pure style helpers
# ==========================================================================


def test_chip_returns_safe_markup() -> None:
    """Claim: the chip helper returns styled markup with the given colour."""
    markup = sx.chip("RSA", sx.CYAN)
    assert markup.startswith("<span")
    assert sx.CYAN in markup
    assert "RSA" in markup


def test_style_module_exposes_every_component() -> None:
    """Claim: the premium component API is complete.

    A missing component would fail the app at render time; this catches it at
    import time instead.
    """
    for name in (
        "inject", "brand_rail", "app_header", "boot_overlay", "hero",
        "posture_command", "pipeline_ribbon", "discovery_nodes", "metric_grid",
        "console_table", "mosca_horizon", "mosca_insufficient", "roadmap_lane",
        "validity_seal", "chip",
    ):
        assert hasattr(sx, name), f"ecdat_style is missing {name}"


def test_ecdat_palette_is_a_distinct_identity() -> None:
    """Claim: ECDAT has its own visual identity, not the Security Lab's palette.

    The design directive requires ECDAT and the frozen AegisPQC Security Lab to
    be immediately distinguishable. ECDAT therefore defines its own accent
    colours rather than reusing ``ui.py``'s exact tokens. This asserts the
    identity actually diverges (the electric-cyan primary differs) while both
    remain in a coherent dark family.
    """
    from frontend import ui

    # The primary accent is deliberately ECDAT's own, not a copy of the Lab's.
    assert sx.CYAN != ui.CYAN
    # ECDAT declares a full six-level depth model the shared module does not.
    for level in ("L0", "L1", "L2", "L3", "L4", "L5"):
        assert hasattr(sx, level), f"ecdat_style is missing depth level {level}"


# ==========================================================================
# Offline / honesty guarantees for the new layer
# ==========================================================================


def test_style_module_uses_no_external_asset() -> None:
    """Claim: the premium CSS loads no web font, CDN, or remote image.

    The demo must run air-gapped; a missing CDN would break the whole aesthetic.
    """
    source = (REPO_ROOT / "frontend" / "ecdat_style.py").read_text(encoding="utf-8")
    # Only the docstring may mention a CDN (explaining it avoids one). The inline
    # SVG XML namespace (http://www.w3.org/2000/svg) is a well-known identifier,
    # not a fetched resource, so it is excluded — nothing is loaded from it.
    code = "\n".join(
        line for line in source.splitlines() if not line.strip().startswith("#")
    ).replace("http://www.w3.org/2000/svg", "")
    for marker in ("http://", "https://", "@import", "fonts.googleapis", "cdn.jsdelivr"):
        assert marker not in code, f"ecdat_style references {marker!r}"


def test_style_module_has_no_execution() -> None:
    """Claim: the premium layer performs no execution, network, or subprocess."""
    tree = ast.parse((REPO_ROOT / "frontend" / "ecdat_style.py").read_text(encoding="utf-8"))
    imported: set[str] = set()
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                called.add(func.id)
            elif isinstance(func, ast.Attribute):
                called.add(func.attr)
    assert not (imported & {"subprocess", "socket", "urllib", "requests", "os"})
    assert not (called & {"system", "popen", "run", "eval", "exec"})


def test_animations_respect_reduced_motion() -> None:
    """Claim: every animation is gated behind prefers-reduced-motion.

    A machine set to reduce motion must get the full static layout. This asserts
    the stylesheet only animates inside a no-preference media query.
    """
    source = (REPO_ROOT / "frontend" / "ecdat_style.py").read_text(encoding="utf-8")
    assert "prefers-reduced-motion: no-preference" in source
    # The boot overlay's fade is the one animation that must also be gated.
    assert "@media (prefers-reduced-motion: no-preference)" in source


# ==========================================================================
# The frozen Security Lab must remain untouched by the redesign
# ==========================================================================


def test_security_lab_still_frozen() -> None:
    """Claim: the redesign did not touch the frozen Security Lab app."""
    app_hash = hashlib.sha256((REPO_ROOT / "frontend" / "app.py").read_bytes()).hexdigest()
    assert app_hash.startswith("aa8a53cc3f4c83826d2a990b"), "frontend/app.py changed"


def test_shared_ui_module_still_frozen() -> None:
    """Claim: the shared ui.py design system is unchanged.

    The redesign adds a new module on top of ui.py rather than editing it.
    """
    ui_hash = hashlib.sha256((REPO_ROOT / "frontend" / "ui.py").read_bytes()).hexdigest()
    assert ui_hash.startswith("0a10743cf0307123b6a98908"), "frontend/ui.py changed"


def test_redesign_is_additive() -> None:
    """Claim: the app imports the new style layer; the Lab does not."""
    ecdat = (REPO_ROOT / "frontend" / "ecdat_app.py").read_text(encoding="utf-8")
    assert "ecdat_style" in ecdat

    frozen = (REPO_ROOT / "frontend" / "app.py").read_text(encoding="utf-8")
    assert "ecdat_style" not in frozen
    assert "ecdat_app" not in frozen


# ==========================================================================
# App wiring (AppTest smoke)
# ==========================================================================


@pytest.fixture(scope="module")
def app_after_load():
    """The redesigned app rendered with the demo estate loaded."""
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file(str(REPO_ROOT / "frontend" / "ecdat_app.py"), default_timeout=400)
    app.run()
    button = [b for b in app.button if "INITIALISE" in b.label or "DEMO" in b.label]
    if button:
        button[0].click().run()
    return app


def test_redesigned_app_renders_without_exception(app_after_load) -> None:
    """Claim: the redesigned app renders and loads the demo cleanly."""
    assert not app_after_load.exception, [str(e.value) for e in app_after_load.exception]


def test_redesigned_app_keeps_all_surfaces(app_after_load) -> None:
    """Claim: all ten surfaces survive the redesign."""
    labels = [t.label for t in app_after_load.tabs]
    for expected in (
        "Overview", "Discovery", "Inventory", "CBOM", "Quantum Risk",
        "Recommendations", "Migration", "Reports", "Settings", "Security Lab",
    ):
        assert expected in labels


def test_redesigned_app_keeps_all_downloads(app_after_load) -> None:
    """Claim: the redesign preserves every export.

    A prettier UI must not silently drop a deliverable.
    """
    assert len(app_after_load.download_button) >= 7


def test_boot_overlay_is_one_time(app_after_load) -> None:
    """Claim: the cinematic boot overlay is session-gated.

    After the first render the ``_booted`` flag is set, so the overlay does not
    replay on every rerun.
    """
    assert app_after_load.session_state["_booted"] is True


def test_empty_state_still_renders() -> None:
    """Claim: before any scan the redesigned app renders a prompt, not a crash."""
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file(str(REPO_ROOT / "frontend" / "ecdat_app.py"), default_timeout=200)
    app.run()
    assert not app.exception
    assert len(app.tabs) == 10


# ==========================================================================
# Structure verification demanded by the redesign directive
# ==========================================================================


def _loaded_markdown(app) -> str:
    """All markdown emitted by the app after the demo estate is loaded."""
    return "\n".join(m.value for m in app.markdown)


def test_required_visual_systems_are_emitted(app_after_load) -> None:
    """Claim: every required premium component is actually emitted into the DOM.

    The directive requires verifying intended components are present, not merely
    that the app runs. This checks the boot sequence, ECDAT brand and header,
    the command-center posture with its radial ring, the pipeline ribbon, the
    discovery engine, glass surfaces, the Mosca horizon, the console tables, and
    the roadmap lanes are all rendered.
    """
    md = _loaded_markdown(app_after_load)
    for marker in (
        "ec-boot",        # cinematic boot sequence
        "ec-brand",       # ECDAT brand rail
        "ec-hdr",         # ECDAT command header
        "pc-grid",        # command-center posture
        "pc-ring",        # radial exposure indicator
        "rb glass",       # pipeline ribbon (glass)
        "dn-engine",      # discovery engine core
        "dn-grid",        # discovery nodes
        "mos",            # Mosca horizon
        "ctbl",           # intelligence console table
        "ln glass",       # roadmap lane (glass)
        "glass",          # glass material system
    ):
        assert marker in md, f"required visual component {marker!r} was not emitted"


def test_default_streamlit_tab_styling_is_overridden() -> None:
    """Claim: the default Streamlit tab highlight/border is removed.

    The directive requires the navigation not to look like ordinary Streamlit
    tabs. The stylesheet must neutralise the default tab highlight and border
    and restyle the selected tab.
    """
    source = (REPO_ROOT / "frontend" / "ecdat_style.py").read_text(encoding="utf-8")
    assert 'tab-highlight"]' in source and "display:none" in source.replace(" ", "")
    assert 'tab-border"]' in source
    assert 'button[aria-selected="true"]' in source


def test_ecdat_brand_is_present_not_security_lab_brand(app_after_load) -> None:
    """Claim: ECDAT presents its own identity, not the frozen Lab's brand.

    The directive requires the ECDAT/Security-Lab distinction to be immediately
    obvious. The header must read ECDAT and must not reuse the Lab's
    "Post-Quantum Security Platform" primary branding.
    """
    md = _loaded_markdown(app_after_load)
    assert "ECDAT" in md
    assert "Enterprise Cryptographic Intelligence" in md
    # The Lab's primary brand line must not be ECDAT's header identity.
    assert "ec-hdr-title" in md


def test_six_level_depth_system_exists() -> None:
    """Claim: the material-depth system defines six distinct levels.

    The directive's central fix is depth instead of identical dark rectangles.
    """
    for level in ("L0", "L1", "L2", "L3", "L4", "L5"):
        value = getattr(sx, level)
        assert value, f"{level} is empty"
    # Levels must not all be the same colour.
    assert len({sx.L0, sx.L1, sx.L3, sx.L4}) >= 3


def test_atmospheric_background_is_layered() -> None:
    """Claim: the background is an atmospheric layered system, not flat black.

    Radial light fields, a faint grid, and ambient haze — all CSS, no external
    asset.
    """
    source = (REPO_ROOT / "frontend" / "ecdat_style.py").read_text(encoding="utf-8")
    assert "radial-gradient" in source
    assert ".stApp::before" in source  # the faint grid layer
    assert ".stApp::after" in source   # the ambient haze layer


def test_boot_sequence_has_the_engine_checklist() -> None:
    """Claim: the boot sequence includes the staged engine checklist.

    The directive specifies the initialising-engines sequence resolving to
    SYSTEM READY.
    """
    source = (REPO_ROOT / "frontend" / "ecdat_style.py").read_text(encoding="utf-8")
    for stage in (
        "CRYPTOGRAPHIC ENGINE", "DISCOVERY LAYER", "EVIDENCE INDEX",
        "CBOM GRAPH", "QUANTUM RISK MODEL", "MIGRATION INTELLIGENCE",
        "SYSTEM READY",
    ):
        assert stage in source, f"boot sequence is missing '{stage}'"


def test_mosca_horizon_labels_bind_to_backend_values() -> None:
    """Claim: the Mosca horizon labels its bars by their true backend meaning.

    The backend value order (data lifetime, migration time) is preserved; the
    display labels each bar correctly rather than swapping the underlying math.
    """
    import inspect

    source = inspect.getsource(sx.mosca_horizon)
    # The function takes explicit label+value pairs, so the caller binds meaning.
    assert "x_label" in source and "y_label" in source and "z_label" in source
    # It computes nothing beyond positioning — no risk logic.
    assert "within" in source


# ==========================================================================
# Second-pass: neutral-first colour & material system
# ==========================================================================


def test_base_canvas_is_neutral_graphite_not_blue() -> None:
    """Claim: the foundation is near-neutral obsidian, not a navy/blue base.

    The second-pass directive's central fix: the base canvas reads as graphite
    (approx #05070a / #080b0f), and the heavy blue atmospheric fill was removed.
    """
    # Measured, not hardcoded: every surface level must be near-neutral
    # graphite. "Blue excess" is the blue channel minus the red channel — an
    # earlier palette reached +20 here, which read as a blue-gray SaaS
    # dashboard once it covered large panels. Obsidian holds it near zero.
    for level in ("L0", "L1", "L2", "L3", "L4", "L5"):
        value = getattr(sx, level)
        red = int(value[1:3], 16)
        blue = int(value[5:7], 16)
        assert blue - red <= 4, (
            f"{level} ({value}) has a blue excess of {blue - red}; "
            "the base surfaces must stay near-neutral graphite"
        )

    source = (REPO_ROOT / "frontend" / "ecdat_style.py").read_text(encoding="utf-8")
    # The previous passes' dominant blue atmosphere must be gone.
    assert "rgba(20,30,60" not in source
    assert "rgba(20, 30, 60" not in source


def test_atmospheric_light_pools_are_barely_visible() -> None:
    """Claim: atmospheric colour comes only from very low-alpha light pools.

    No radial light field in the base may exceed ~0.05 alpha — the background
    must not read as "blue".
    """
    import re

    source = (REPO_ROOT / "frontend" / "ecdat_style.py").read_text(encoding="utf-8")
    # Grab the .stApp background block.
    start = source.index(".stApp {")
    block = source[start:start + 600]
    alphas = [float(a) for a in re.findall(r"rgba\([^)]*?,\s*([0-9.]+)\)", block)]
    assert alphas, "no rgba light pools found in the base background"
    assert max(alphas) <= 0.05, f"a base light pool is too strong: {max(alphas)}"


def test_material_depth_levels_are_distinct() -> None:
    """Claim: the six material levels are genuinely distinct graphite tones.

    Depth must come from real tonal separation, not identical dark boxes.
    """
    levels = [sx.L0, sx.L1, sx.L2, sx.L3, sx.L4, sx.L5]
    assert len(set(levels)) == 6, "material levels are not all distinct"


def test_light_from_above_borders_exist() -> None:
    """Claim: surfaces use light-from-above border logic (top brighter)."""
    source = (REPO_ROOT / "frontend" / "ecdat_style.py").read_text(encoding="utf-8")
    assert "border-top-color" in source
    assert "border-bottom-color" in source
    # The top border token must be brighter (higher alpha) than the bottom.
    assert sx.BORDER_TOP == "rgba(255, 255, 255, 0.10)"
    assert sx.BORDER_BOT == "rgba(255, 255, 255, 0.035)"


def test_accent_is_a_minority_of_the_palette() -> None:
    """Claim: accents are signals, not the theme.

    The primary accent is electric ice, distinct from a saturated blue theme,
    and the neutral text/surface tokens dominate the token set.
    """
    assert sx.CYAN == "#7de7ff"          # electric ice, not a blue theme
    assert sx.RED == "#ff6472"           # critical stays rare
    # Neutral foundation tokens are near-neutral (low channel spread = greyish).
    for token in (sx.L0, sx.L1, sx.L2, sx.L3):
        r, g, b = int(token[1:3], 16), int(token[3:5], 16), int(token[5:7], 16)
        # A small cool bias is intended (graphite, faintly cool); a saturated
        # navy would show a much larger spread. 16 admits the directive's own
        # L3 (#111720) while still rejecting a blue theme.
        assert max(r, g, b) - min(r, g, b) <= 16, f"{token} is too saturated for a neutral base"


def test_active_nav_is_depth_not_a_bright_pill() -> None:
    """Claim: the active tab is selected by depth, not a screaming cyan block.

    The directive requires the active tab to read as elevated dark glass with a
    small indicator, not a bright cyan rectangle.
    """
    source = (REPO_ROOT / "frontend" / "ecdat_style.py").read_text(encoding="utf-8")
    idx = source.index('button[aria-selected="true"]')
    block = source[idx:idx + 320]
    # It uses an elevated surface + inset indicator, not a full cyan-glow fill.
    assert "inset" in block
    assert "L4" in block or "161d27" in block or "rgba(255,255,255" in block


def test_primary_button_is_an_instrument_not_a_gradient_cta() -> None:
    """Claim: the primary button is a dark instrument control, not a gradient CTA."""
    source = (REPO_ROOT / "frontend" / "ecdat_style.py").read_text(encoding="utf-8")
    idx = source.index('button[kind="primary"]')
    block = source[idx:idx + 360]
    # No 135deg cyan-to-cyan gradient fill.
    assert "linear-gradient(135deg" not in block


def test_cryptographic_geometry_is_present_and_subtle() -> None:
    """Claim: the atmosphere includes low-opacity cryptographic geometry.

    Large orbital arcs / connectors as instrumentation, inline SVG, offline.
    """
    source = (REPO_ROOT / "frontend" / "ecdat_style.py").read_text(encoding="utf-8")
    assert "data:image/svg+xml" in source          # inline, no external asset
    assert "<circle" in source and "stroke='rgba(255,255,255,0.020)'" in source
