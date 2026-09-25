"""
Aegis PQC — ECDAT design system.

A distinct visual and interaction language for the Enterprise Cryptographic
Discovery & Analysis Tool: a premium, cinematic cryptographic-intelligence
console. It is a genuinely new system, not a restyle of the shared
:mod:`frontend.ui` module — it defines its own depth model, materials,
atmosphere, brand, and components, and never modifies ``ui.py`` (which the
frozen Security Lab depends on).

DESIGN PILLARS
--------------
* **Material depth, not identical rectangles.** Six elevation levels, from the
  atmospheric application background to critical security states, each with its
  own surface, border, and shadow. Nothing is a flat black box.
* **Precision-engineered glass.** Translucent surfaces, thin luminous borders,
  inner highlights, backdrop blur where supported — controlled, never the
  overused glassmorphism blur-everything look.
* **Restrained lighting.** Cyan reads as instrument lighting, violet as quantum
  energy, amber as warning, red as danger. Most of the interface is calm deep
  blue-black; colour and glow are reserved for meaning.
* **Cinematic motion, gated.** A one-time boot sequence, sectional entrances,
  micro-elevation on hover, a flowing pipeline, an animated Mosca horizon. Every
  animation lives behind ``prefers-reduced-motion: no-preference`` so a
  reduced-motion machine gets the full static layout.

CONSTRAINTS HONOURED
--------------------
No external asset, font, or CDN — everything is inline CSS and SVG, so the demo
runs air-gapped. No JavaScript framework. The palette extends the shared tokens
for coherence but the surfaces, depth, and components are ECDAT's own.
"""

from __future__ import annotations

from typing import Any

import streamlit as st

from frontend import ui

# ==========================================================================
# Palette — neutral-first graphite with controlled instrument lighting
# ==========================================================================
#
# The environment is a dark, near-neutral graphite room; colour appears only
# where information matters (~80–90% neutral, ~10–20% accent). Values follow the
# second-pass directive's foundation and semantic accent system.

# Depth levels 0–5 — TRUE OBSIDIAN. These are deliberately near-neutral
# graphite: the blue excess (B minus R) is held at or below 4 at every level,
# where the previous palette climbed to 20 and read as a blue-gray SaaS
# dashboard at panel scale. Colour now lives only in the accents, where it
# carries meaning. A trace of warmth keeps it reading as charcoal, not slate.
L0 = "#050506"   # atmospheric background — obsidian
L1 = "#08090a"   # main canvas
L2 = "#0d0e10"   # workspace
L3 = "#131416"   # glass surface
L4 = "#191a1d"   # elevated surface
L5 = "#212225"   # maximum elevation

# Translucent material fills (Material 2 / 3), used with backdrop blur.
GLASS_2 = "rgba(19, 20, 22, 0.70)"
GLASS_3 = "rgba(25, 26, 29, 0.82)"
CRITICAL_FILL = "rgba(74, 22, 28, 0.30)"   # Material 5, never pure red

# Borders — light-from-above logic; white at low alpha keeps them neutral.
BORDER = "rgba(255, 255, 255, 0.075)"
BORDER_LIT = "rgba(255, 255, 255, 0.12)"
BORDER_TOP = "rgba(255, 255, 255, 0.10)"
BORDER_BOT = "rgba(255, 255, 255, 0.035)"
BORDER_GLASS = "rgba(255, 255, 255, 0.065)"
BORDER_FOCUS = "rgba(120, 220, 255, 0.32)"
BORDER_CRIT = "rgba(255, 92, 105, 0.35)"

# Type — aggressive hierarchy, never all-white. Neutral warm greys: the
# previous ramp was blue-tinted (#a5afba, #687482), which tinted every label
# and table cell in the product and reinforced the blue cast.
TEXT = "#f4f4f3"
TEXT_SOFT = "#b0b0ae"
DIM = "#b0b0ae"
MUTED = "#76766f"
FAINT = "#5a5a55"

# Accent system — several controlled instrument colours, not one cyan theme.
CYAN = "#7de7ff"          # primary signal — electric ice
CYAN_DEEP = "#3aa8c4"
ICE = "#c6d6e3"           # neutral ice — secondary / binary / container telemetry
VIOLET = "#9b8cff"        # analytical / CBOM, used sparingly
VIOLET_DEEP = "#7166d6"
COOL_WHITE = "#f2f5f7"
GREEN = "#48d7a0"         # trust / verified / SYSTEM READY
AMBER = "#f3b85b"         # attention / warning telemetry
ORANGE = "#f3b85b"        # (attention family; kept for call sites)
RED = "#ff6472"           # critical — rare
GREY = "#687482"

# Semantic
CRITICAL = RED
HIGH = "#f39a5b"          # high-attention, between amber and red
WARNING = AMBER
SAFE = GREEN
PRIMARY = CYAN

# Glow tints — weak, used only as accent lighting (never on every surface).
CYAN_GLOW = "rgba(125, 231, 255, 0.10)"
VIOLET_GLOW = "rgba(155, 140, 255, 0.09)"
RED_GLOW = "rgba(255, 100, 114, 0.12)"

# Typography — system stacks only (offline). A modern sans for display and body,
# monospace reserved for technical metadata.
DISPLAY = (
    '"SF Pro Display", -apple-system, BlinkMacSystemFont, '
    '"Segoe UI Variable Display", "Segoe UI", Inter, Roboto, sans-serif'
)
SANS = (
    '-apple-system, BlinkMacSystemFont, "Segoe UI Variable Text", "Segoe UI", '
    "Inter, Roboto, sans-serif"
)
MONO = (
    'ui-monospace, "Cascadia Code", "SF Mono", "JetBrains Mono", Menlo, '
    "Consolas, monospace"
)

# Backwards-compatible aliases used by ecdat_app / ecdat_view.
VOID = L0
SURFACE = L1
RAISED = L3


def inject() -> None:
    """Inject the ECDAT stylesheet and atmospheric background. Call once."""
    st.markdown(_ATMOSPHERE + _STYLE, unsafe_allow_html=True)


# ==========================================================================
# Brand identity
# ==========================================================================


def brand_rail() -> None:
    """The ECDAT product mark for the command rail — its own identity.

    Deliberately distinct from the frozen Security Lab's AegisPQC branding: the
    two products must be immediately distinguishable.
    """
    st.markdown(
        """
        <div class="ec-brand">
          <div class="ec-brand-row">
            <svg class="ec-sigil-mini" viewBox="0 0 40 40" width="34" height="34">
              <path class="s1" d="M20 4 L34 20 L20 36 L6 20 Z"/>
              <path class="s2" d="M20 11 L29 20 L20 29 L11 20 Z"/>
              <circle class="s3" cx="20" cy="20" r="2.6"/>
            </svg>
            <div>
              <div class="ec-brand-name">ECDAT</div>
              <div class="ec-brand-sub">Cryptographic Discovery &amp; Analysis</div>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def app_header(stats: list[dict[str, Any]]) -> None:
    """The ECDAT command header: identity, live state, and posture telemetry."""
    cells = "".join(
        f'<div class="ec-hdr-stat"><div class="ec-hdr-k">{s["label"]}</div>'
        f'<div class="ec-hdr-v" style="color:{s["colour"]}">{s["value"]}</div></div>'
        for s in stats
    )
    st.markdown(
        f"""
        <div class="ec-hdr glass">
          <div class="ec-hdr-brand">
            <div class="ec-hdr-title">ECDAT
              <span class="ec-hdr-live"><i></i>Live</span>
            </div>
            <div class="ec-hdr-sub">Enterprise Cryptographic Intelligence</div>
          </div>
          <div class="ec-hdr-stats">{cells}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ==========================================================================
# Cinematic boot sequence
# ==========================================================================


def boot_overlay() -> None:
    """A one-time cinematic boot sequence.

    Shows the ECDAT identity, an animated cryptographic sigil, a scanning sweep,
    and a staged engine checklist that resolves to SYSTEM READY, then fades into
    the application. ``pointer-events: none`` means it never blocks interaction,
    and the whole overlay is hidden under reduced-motion.
    """
    st.markdown(
        """
        <div class="ec-boot" aria-hidden="true">
          <div class="ec-boot-inner">
            <svg class="ec-boot-sigil" viewBox="0 0 160 160" width="150" height="150">
              <circle class="ring o1" cx="80" cy="80" r="70"/>
              <circle class="ring o2" cx="80" cy="80" r="54"/>
              <circle class="ring o3" cx="80" cy="80" r="38"/>
              <path class="glyph" d="M80 30 L124 80 L80 130 L36 80 Z"/>
              <path class="glyph inner" d="M80 48 L106 80 L80 112 L54 80 Z"/>
              <circle class="pip" cx="80" cy="80" r="5"/>
              <line class="scan" x1="10" y1="80" x2="150" y2="80"/>
            </svg>
            <div class="ec-boot-name">ECDAT</div>
            <div class="ec-boot-full">CRYPTOGRAPHIC DISCOVERY &amp; ANALYSIS</div>
            <div class="ec-boot-status">INITIALIZING SECURE ENVIRONMENT</div>
            <div class="ec-boot-checks">
              <div class="ck c1"><i>✓</i> CRYPTOGRAPHIC ENGINE</div>
              <div class="ck c2"><i>✓</i> DISCOVERY LAYER</div>
              <div class="ck c3"><i>✓</i> EVIDENCE INDEX</div>
              <div class="ck c4"><i>✓</i> CBOM GRAPH</div>
              <div class="ck c5"><i>✓</i> QUANTUM RISK MODEL</div>
              <div class="ck c6"><i>✓</i> MIGRATION INTELLIGENCE</div>
            </div>
            <div class="ec-boot-ready">SYSTEM READY</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ==========================================================================
# Section hero
# ==========================================================================


def hero(title: str, subtitle: str, tag: str = "ECDAT", accent: str = CYAN) -> None:
    """A cinematic surface hero: an eyebrow tag, display title, and sweep rule."""
    st.markdown(
        f"""
        <div class="ec-hero reveal">
          <div class="ec-hero-tag" style="--c:{accent}">{tag}</div>
          <div class="ec-hero-title">{title}</div>
          <div class="ec-hero-sub">{subtitle}</div>
          <div class="ec-hero-rule"><i style="--c:{accent}"></i></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ==========================================================================
# Command-center posture (Overview)
# ==========================================================================


def posture_command(stats: list[dict[str, Any]]) -> None:
    """The Overview's command-center posture block.

    Large display numbers with animated count-in, a radial ring on the primary
    exposure figure, and glass elevation. ``stats`` items: ``label``, ``value``,
    ``colour``, optional ``note``, ``ring`` (0–100 for the radial), ``emphasis``.
    """
    cells: list[str] = []
    for index, s in enumerate(stats):
        colour = s.get("colour", CYAN)
        note = f'<div class="pc-note">{s["note"]}</div>' if s.get("note") else ""
        emphasis = " emphasis" if s.get("emphasis") else ""
        ring = ""
        if s.get("ring") is not None:
            ring = (
                f'<div class="pc-ring" style="--p:{s["ring"]};--c:{colour}">'
                f'<div class="pc-ring-in"></div></div>'
            )
        cells.append(
            f'<div class="pc-cell glass{emphasis} reveal" '
            f'style="--c:{colour};--d:{index * 0.08:.2f}s">'
            f'{ring}'
            f'<div class="pc-value" style="color:{colour}">{s["value"]}</div>'
            f'<div class="pc-label">{s["label"]}</div>{note}</div>'
        )
    st.markdown(
        f'<div class="pc-grid">{"".join(cells)}</div>', unsafe_allow_html=True
    )


# ==========================================================================
# Pipeline signal
# ==========================================================================


def pipeline_ribbon(active: str | None = None) -> None:
    """The DISCOVER→…→MIGRATION pipeline as a flowing signal ribbon."""
    stages = [
        ("discover", "Discover"), ("inventory", "Inventory"), ("cbom", "CBOM"),
        ("risk", "Quantum Risk"), ("recommend", "Recommend"),
        ("prioritise", "Prioritise"), ("roadmap", "Roadmap"),
    ]
    parts: list[str] = []
    for index, (key, label) in enumerate(stages):
        on = " on" if key == active else ""
        if index:
            parts.append('<div class="rb-flow"><i></i></div>')
        parts.append(
            f'<div class="rb-node{on} reveal" style="--d:{index * 0.06:.2f}s">'
            f'<div class="rb-dot"></div><div class="rb-label">{label}</div></div>'
        )
    st.markdown(
        f'<div class="rb glass reveal">{"".join(parts)}</div>',
        unsafe_allow_html=True,
    )


# ==========================================================================
# Discovery engine nodes
# ==========================================================================


def discovery_nodes(nodes: list[dict[str, Any]]) -> None:
    """Five illuminated discovery surfaces around a central engine.

    ``nodes`` items: ``name``, ``count``, ``detail``, ``colour``.
    """
    cards: list[str] = []
    for index, n in enumerate(nodes):
        colour = n.get("colour", CYAN)
        cards.append(
            f'<div class="dn glass reveal" style="--c:{colour};--d:{index * 0.07:.2f}s">'
            f'<div class="dn-count" style="color:{colour}">{n["count"]}</div>'
            f'<div class="dn-name">{n["name"]}</div>'
            f'<div class="dn-detail">{n["detail"]}</div></div>'
        )
    st.markdown(
        f"""
        <div class="dn-engine reveal">
          <div class="dn-core">
            <div class="dn-core-ring"></div>
            <div class="dn-core-label">CRYPTOGRAPHIC<br>DISCOVERY ENGINE</div>
          </div>
        </div>
        <div class="dn-grid">{"".join(cards)}</div>
        """,
        unsafe_allow_html=True,
    )


# ==========================================================================
# Glass metric tiles
# ==========================================================================


def metric_grid(items: list[dict[str, Any]]) -> None:
    """A responsive grid of glass metric tiles with staggered entrance."""
    cells: list[str] = []
    for index, item in enumerate(items):
        colour = item.get("colour", BORDER_LIT)
        note = f'<div class="mt-note">{item["note"]}</div>' if item.get("note") else ""
        glow = " glow" if item.get("glow") else ""
        cells.append(
            f'<div class="mt glass{glow} reveal" '
            f'style="--c:{colour};--d:{index * 0.05:.2f}s">'
            f'<div class="mt-label">{item["label"]}</div>'
            f'<div class="mt-value" style="color:{item.get("value_colour", TEXT)}">'
            f'{item["value"]}</div>{note}</div>'
        )
    st.markdown(f'<div class="mt-grid">{"".join(cells)}</div>', unsafe_allow_html=True)


# ==========================================================================
# Intelligence console table
# ==========================================================================


def console_table(
    columns: list[str],
    rows: list[list[str]],
    rail_colours: list[str] | None = None,
) -> None:
    """A cryptographic-intelligence console: severity rails, glass, hover lift.

    Every field a plain table would show is preserved; ``rail_colours`` gives
    each row a left status rail.
    """
    head = "".join(f"<th>{c}</th>" for c in columns)
    body: list[str] = []
    for index, row in enumerate(rows):
        rail = (rail_colours[index] if rail_colours and index < len(rail_colours) else BORDER_LIT)
        cells = "".join(f"<td>{c}</td>" for c in row)
        body.append(f'<tr style="--rail:{rail}">{cells}</tr>')
    st.markdown(
        f'<div class="ctbl glass reveal"><table><thead><tr>{head}</tr></thead>'
        f'<tbody>{"".join(body)}</tbody></table></div>',
        unsafe_allow_html=True,
    )


# ==========================================================================
# Mosca horizon — the showstopper
# ==========================================================================


def mosca_horizon(
    x_label: str, x_value: float,
    y_label: str, y_value: float,
    z_label: str, z_value: float,
    within: bool,
    statement: str,
) -> None:
    """Render the Mosca inequality as a cinematic quantum-horizon timeline.

    A NOW origin, two stacked protection segments, and a luminous CRQC threshold
    marker. When the combined horizon crosses the threshold the track reads
    critical. Labels and values are supplied by the caller and come straight
    from the backend — nothing is computed here.
    """
    total = x_value + y_value
    scale = max(total, z_value) * 1.28 or 1.0
    x_pct = x_value / scale * 100
    y_pct = y_value / scale * 100
    z_pct = z_value / scale * 100
    colour = CRITICAL if within else GREEN
    verdict = "WITHIN QUANTUM WINDOW" if within else "OUTSIDE WINDOW · under assumptions"

    st.markdown(
        f"""
        <div class="mos glass reveal">
          <div class="mos-scale">
            <span>NOW</span><span>QUANTUM HORIZON</span>
          </div>
          <div class="mos-track">
            <div class="mos-seg x" style="--w:{x_pct:.1f}%;--c:{CYAN}">
              <span>{x_label} · {x_value:g}y</span>
            </div>
            <div class="mos-seg y" style="--w:{y_pct:.1f}%;--left:{x_pct:.1f}%;--c:{VIOLET}">
              <span>{y_label} · {y_value:g}y</span>
            </div>
            <div class="mos-marker" style="--left:{z_pct:.1f}%">
              <div class="mos-marker-line"></div>
              <div class="mos-marker-cap"></div>
              <div class="mos-marker-label">{z_label} · {z_value:g}y</div>
            </div>
          </div>
          <div class="mos-verdict" style="--c:{colour}">
            <span class="mos-eq">{statement}</span>
            <span class="mos-state">{verdict}</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def mosca_insufficient() -> None:
    """The Mosca panel when the backend returned INSUFFICIENT_INFORMATION."""
    st.markdown(
        f"""
        <div class="mos glass reveal insufficient">
          <div class="mos-scale"><span>NOW</span><span>QUANTUM HORIZON</span></div>
          <div class="mos-track empty"><span>INSUFFICIENT INFORMATION</span></div>
          <div class="mos-verdict" style="--c:{AMBER}">
            <span class="mos-state">A required input was missing — no value is substituted.</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ==========================================================================
# Roadmap lanes
# ==========================================================================


def roadmap_lane(label: str, colour: str, count: int, items: list[str]) -> None:
    """One migration roadmap lane (a priority bucket) with staggered reveal."""
    rows = "".join(
        f'<div class="ln-item reveal" style="--d:{i * 0.04:.2f}s">{item}</div>'
        for i, item in enumerate(items)
    )
    st.markdown(
        f"""
        <div class="ln glass reveal" style="--c:{colour}">
          <div class="ln-head">
            <span class="ln-marker"></span>
            <span class="ln-label">{label}</span>
            <span class="ln-count">{count}</span>
          </div>
          <div class="ln-body">{rows}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ==========================================================================
# Chips & seals
# ==========================================================================


def chip(text: str, colour: str) -> str:
    """A status chip, returned as markup for composition inside table cells."""
    return f'<span class="ec-chip" style="--c:{colour}">{text}</span>'


def validity_seal(valid: bool, label: str, sub: str = "") -> None:
    """A prominent validation seal (CBOM schema validity)."""
    colour = GREEN if valid else CRITICAL
    icon = "◉" if valid else "✕"
    sub_html = f'<div class="seal-sub">{sub}</div>' if sub else ""
    st.markdown(
        f"""
        <div class="ec-seal glass reveal" style="--c:{colour}">
          <div class="seal-mark">{icon}</div>
          <div><div class="seal-text">{label}</div>{sub_html}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ==========================================================================
# The stylesheet is assembled from parts defined below and in _STYLE.
# ==========================================================================

# Atmosphere — a designed obsidian environment, not a blue gradient wallpaper.
# Layer A obsidian base + subtle vertical tone. Layer B vignette. Layer C a few
# barely-visible light pools (must NOT read as "blue"). Layer D a faint, sparse,
# gradient-masked grid. Layer F large, low-opacity, partly-clipped cryptographic
# geometry (orbital arcs) as instrumentation. All CSS/SVG, offline, subtle.
_GEO = (
    "url(\"data:image/svg+xml;utf8,"
    "<svg xmlns='http://www.w3.org/2000/svg' width='1600' height='1200'>"
    "<g fill='none' stroke='rgba(255,255,255,0.020)' stroke-width='1'>"
    "<circle cx='1440' cy='150' r='520'/>"
    "<circle cx='1440' cy='150' r='360'/>"
    "<circle cx='140' cy='1080' r='440'/>"
    "<circle cx='140' cy='1080' r='300'/>"
    "<path d='M-40 300 Q 400 120 900 340 T 1700 300'/>"
    "</g>"
    "<g stroke='rgba(255,255,255,0.026)' stroke-width='1'>"
    "<line x1='1440' y1='150' x2='1180' y2='470'/>"
    "<line x1='1440' y1='150' x2='1700' y2='430'/>"
    "<line x1='140' y1='1080' x2='430' y2='830'/>"
    "</g>"
    "<g fill='rgba(255,255,255,0.045)'>"
    "<circle cx='1180' cy='470' r='2.5'/><circle cx='1700' cy='430' r='2'/>"
    "<circle cx='430' cy='830' r='2.5'/><circle cx='900' cy='340' r='2'/>"
    "</g></svg>\")"
)

_ATMOSPHERE = f"""
<style>
  /* Obsidian base. The light pools are near-white at very low alpha — light,
     not colour. A blue/violet wash here is what made the product read as a
     generic blue dashboard; a single faint cool pool remains as a directional
     key light, far too weak to tint the canvas. */
  .stApp {{
    background:
      radial-gradient(ellipse 70% 50% at 18% -6%, rgba(255,255,255,0.040), transparent 60%),
      radial-gradient(ellipse 60% 45% at 88% 4%, rgba(190,225,240,0.016), transparent 58%),
      radial-gradient(ellipse 90% 60% at 50% 108%, rgba(255,255,255,0.012), transparent 60%),
      linear-gradient(180deg, {L1} 0%, {L0} 55%, #040405 100%);
    background-attachment: fixed;
  }}
  /* Layer D — faint, sparse cryptographic grid, gradient-masked. */
  .stApp::before {{
    content: ""; position: fixed; inset: 0; z-index: 0; pointer-events: none;
    background-image:
      linear-gradient(rgba(255,255,255,0.018) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,0.018) 1px, transparent 1px);
    background-size: 60px 60px;
    mask-image: radial-gradient(1200px 820px at 60% 20%, black, transparent 82%);
    -webkit-mask-image: radial-gradient(1200px 820px at 60% 20%, black, transparent 82%);
  }}
  /* Layer B vignette + Layer F cryptographic geometry, fixed, behind content. */
  .stApp::after {{
    content: ""; position: fixed; inset: 0; z-index: 0; pointer-events: none;
    background:
      {_GEO} no-repeat center / cover,
      radial-gradient(140% 120% at 50% 40%, transparent 60%, rgba(0,0,0,0.55) 100%);
    opacity: 0.9;
  }}
  @media (prefers-reduced-motion: no-preference) {{
    .stApp::after {{ animation: ecDrift 40s ease-in-out infinite alternate; }}
  }}
  @keyframes ecDrift {{
    0% {{ transform: translate3d(0,0,0); }}
    100% {{ transform: translate3d(-1.2%, 0.8%, 0); }}
  }}
  .block-container {{ position: relative; z-index: 1; padding-top: 1.2rem !important;
      max-width: 1560px; }}
</style>
"""


# The full component + surface stylesheet. Assembled as one f-string so tokens
# resolve once. Injected after _ATMOSPHERE.
_STYLE = f"""
<style>
  /* ============ Motion primitives (reduced-motion aware) ============ */
  @keyframes ecReveal {{ from {{ opacity:0; transform: translateY(16px); }}
      to {{ opacity:1; transform: translateY(0); }} }}
  @keyframes ecFadeOut {{ 0%,74% {{ opacity:1; visibility:visible; }}
      100% {{ opacity:0; visibility:hidden; }} }}
  @keyframes ecSpin {{ to {{ transform: rotate(360deg); }} }}
  @keyframes ecSpinR {{ to {{ transform: rotate(-360deg); }} }}
  @keyframes ecScan {{ 0% {{ transform: translateY(-58px); opacity:0; }}
      20% {{ opacity:1; }} 80% {{ opacity:1; }}
      100% {{ transform: translateY(58px); opacity:0; }} }}
  @keyframes ecGrow {{ from {{ width:0; }} to {{ width: var(--w); }} }}
  @keyframes ecRule {{ from {{ width:0; }} to {{ width:100%; }} }}
  @keyframes ecPulse {{ 0%,100% {{ opacity:1; box-shadow:0 0 9px var(--c,{CYAN}); }}
      50% {{ opacity:0.5; box-shadow:0 0 2px var(--c,{CYAN}); }} }}
  @keyframes ecFlow {{ 0% {{ transform: translateX(-100%); opacity:0; }}
      50% {{ opacity:1; }} 100% {{ transform: translateX(320%); opacity:0; }} }}
  @keyframes ecCheck {{ from {{ opacity:0.2; transform: translateX(-6px); }}
      to {{ opacity:1; transform: translateX(0); }} }}
  @keyframes ecRingGrow {{ from {{ stroke-dashoffset: 999; }} to {{ stroke-dashoffset: 0; }} }}

  .reveal {{ opacity:1; }}
  @media (prefers-reduced-motion: no-preference) {{
    .reveal {{ animation: ecReveal 0.6s cubic-bezier(0.16,0.8,0.3,1) both;
        animation-delay: var(--d,0s); }}
  }}

  /* ============ Material / depth system ============ */
  /* Material 2 — coated technical glass. Light-from-above borders (brighter
     top, darker bottom), restrained blur, a subtle vertical material gradient,
     and a real drop shadow for depth. Not every surface glows. */
  /* Real glass: a bright specular edge along the top (as if lit from above),
     a soft inner sheen falling off quickly, a genuine cast shadow for
     separation from the canvas, and a fine inner hairline that reads as the
     pane's own thickness. This is what makes a panel look like a material
     rather than a coloured rectangle. */
  .glass {{
    background:
      linear-gradient(180deg, rgba(255,255,255,0.022), rgba(255,255,255,0.003) 42%),
      {GLASS_2};
    border: 1px solid {BORDER_GLASS};
    border-top-color: {BORDER_TOP};
    border-bottom-color: {BORDER_BOT};
    border-radius: 14px;
    box-shadow:
      0 1px 0 rgba(255,255,255,0.055) inset,
      0 0 0 1px rgba(0,0,0,0.30),
      0 16px 40px -12px rgba(0,0,0,0.60),
      0 2px 8px -2px rgba(0,0,0,0.40);
    backdrop-filter: blur(14px) saturate(112%);
    -webkit-backdrop-filter: blur(14px) saturate(112%);
    position: relative;
  }}
  /* Specular highlight — a narrow bright band on the top edge only. */
  .glass::before {{
    content:""; position:absolute; inset:0; border-radius:14px; pointer-events:none;
    background:
      linear-gradient(180deg, rgba(255,255,255,0.05), transparent 16%),
      radial-gradient(120% 60% at 20% -10%, rgba(255,255,255,0.045), transparent 60%);
  }}
  /* Material 3 — elevated glass: brighter surface, stronger shadow. */
  .glass.elev {{
    background:
      linear-gradient(180deg, rgba(255,255,255,0.024), rgba(255,255,255,0.005)),
      {GLASS_3};
    border-color: {BORDER_LIT};
    box-shadow: 0 18px 45px rgba(0,0,0,0.34);
  }}
  /* Material 4 — active / focused: semantic edge + weak, separate accent glow. */
  .glass.active {{
    border-color: {BORDER_FOCUS};
    box-shadow: 0 20px 55px rgba(0,0,0,0.42), 0 0 0 1px {BORDER_FOCUS};
  }}
  /* Material 5 — critical: dark red-tinted, never pure red. */
  .glass.crit {{
    background:
      linear-gradient(180deg, rgba(255,255,255,0.012), transparent),
      {CRITICAL_FILL};
    border-color: {BORDER_CRIT};
  }}
  /* Flat workspace panel — Material 1, barely differentiated, no blur/shadow. */
  .panel-flat {{ background: {L2}; border: 1px solid {BORDER}; border-radius: 12px; }}

  /* ============ Chrome cleanup ============ */
  #MainMenu, footer {{ visibility:hidden; }}
  header[data-testid="stHeader"] {{ background:transparent; height:0; }}
  [data-testid="stToolbar"], [data-testid="stDecoration"] {{ display:none; }}

  /* ============ Boot sequence ============ */
  .ec-boot {{ position:fixed; inset:0; z-index:9999; pointer-events:none;
      display:flex; align-items:center; justify-content:center;
      background: radial-gradient(760px 560px at 50% 42%, {L1}, {L0} 72%);
      visibility:hidden; opacity:0; }}
  @media (prefers-reduced-motion: no-preference) {{
    .ec-boot {{ animation: ecFadeOut 3.4s ease forwards; }}
  }}
  .ec-boot-inner {{ text-align:center; }}
  .ec-boot-sigil {{ overflow:visible; }}
  .ec-boot-sigil .ring {{ fill:none; stroke:{BORDER_LIT}; stroke-width:1; opacity:0.55;
      transform-origin:80px 80px; }}
  .ec-boot-sigil .o1 {{ stroke:{CYAN}; stroke-dasharray:50 300; }}
  .ec-boot-sigil .o2 {{ stroke:{VIOLET}; stroke-dasharray:34 240; }}
  .ec-boot-sigil .o3 {{ stroke:{CYAN}; stroke-dasharray:18 180; opacity:0.4; }}
  .ec-boot-sigil .glyph {{ fill:none; stroke:{CYAN}; stroke-width:1.5;
      filter: drop-shadow(0 0 7px {CYAN}); }}
  .ec-boot-sigil .glyph.inner {{ stroke:{VIOLET}; opacity:0.8; }}
  .ec-boot-sigil .pip {{ fill:{CYAN}; filter: drop-shadow(0 0 9px {CYAN}); }}
  .ec-boot-sigil .scan {{ stroke:{ICE}; stroke-width:1.4; opacity:0; filter:drop-shadow(0 0 6px {CYAN}); }}
  @media (prefers-reduced-motion: no-preference) {{
    .ec-boot-sigil .o1 {{ animation: ecSpin 3.4s linear infinite; }}
    .ec-boot-sigil .o2 {{ animation: ecSpinR 4.6s linear infinite; }}
    .ec-boot-sigil .o3 {{ animation: ecSpin 2.2s linear infinite; }}
    .ec-boot-sigil .glyph {{ animation: ecPulse 1.6s ease-in-out infinite; }}
    .ec-boot-sigil .scan {{ animation: ecScan 1.8s ease-in-out infinite; }}
  }}
  .ec-boot-name {{ font-family:{DISPLAY}; font-size:44px; font-weight:800;
      letter-spacing:0.18em; color:{TEXT}; margin-top:26px; }}
  .ec-boot-full {{ font-family:{MONO}; font-size:9px; letter-spacing:0.34em;
      color:{DIM}; margin-top:10px; }}
  .ec-boot-status {{ font-family:{MONO}; font-size:9px; letter-spacing:0.24em;
      color:{CYAN}; margin-top:26px; }}
  .ec-boot-checks {{ display:inline-flex; flex-direction:column; gap:7px;
      margin-top:16px; text-align:left; }}
  .ec-boot-checks .ck {{ font-family:{MONO}; font-size:10px; letter-spacing:0.14em;
      color:{TEXT_SOFT}; opacity:0.2; }}
  .ec-boot-checks .ck i {{ color:{GREEN}; font-style:normal; margin-right:8px; }}
  @media (prefers-reduced-motion: no-preference) {{
    .ec-boot-checks .c1 {{ animation: ecCheck 0.4s ease 0.5s forwards; }}
    .ec-boot-checks .c2 {{ animation: ecCheck 0.4s ease 0.8s forwards; }}
    .ec-boot-checks .c3 {{ animation: ecCheck 0.4s ease 1.1s forwards; }}
    .ec-boot-checks .c4 {{ animation: ecCheck 0.4s ease 1.4s forwards; }}
    .ec-boot-checks .c5 {{ animation: ecCheck 0.4s ease 1.7s forwards; }}
    .ec-boot-checks .c6 {{ animation: ecCheck 0.4s ease 2.0s forwards; }}
  }}
  .ec-boot-ready {{ font-family:{MONO}; font-size:12px; letter-spacing:0.3em;
      color:{GREEN}; margin-top:22px; opacity:0.15; }}
  @media (prefers-reduced-motion: no-preference) {{
    .ec-boot-ready {{ animation: ecCheck 0.5s ease 2.4s forwards; }}
  }}

  /* ============ Brand rail ============ */
  .ec-brand {{ padding:4px 0 16px; border-bottom:1px solid {BORDER}; margin-bottom:16px; }}
  .ec-brand-row {{ display:flex; align-items:center; gap:12px; }}
  .ec-sigil-mini .s1 {{ fill:none; stroke:{CYAN}; stroke-width:1.4; filter:drop-shadow(0 0 4px {CYAN}); }}
  .ec-sigil-mini .s2 {{ fill:none; stroke:{VIOLET}; stroke-width:1.2; opacity:0.85; }}
  .ec-sigil-mini .s3 {{ fill:{CYAN}; filter:drop-shadow(0 0 5px {CYAN}); }}
  @media (prefers-reduced-motion: no-preference) {{
    .ec-sigil-mini {{ animation: ecSpin 18s linear infinite; }}
    .ec-sigil-mini .s2 {{ transform-origin:20px 20px; animation: ecSpinR 12s linear infinite; }}
  }}
  .ec-brand-name {{ font-family:{DISPLAY}; font-size:22px; font-weight:800;
      letter-spacing:0.14em; color:{TEXT}; line-height:1; }}
  .ec-brand-sub {{ font-family:{MONO}; font-size:8px; letter-spacing:0.16em;
      color:{MUTED}; text-transform:uppercase; margin-top:6px; }}

  /* ============ Header ============ */
  .ec-hdr {{ display:flex; justify-content:space-between; align-items:center;
      flex-wrap:wrap; gap:18px; padding:16px 24px; margin-bottom:6px; }}
  .ec-hdr-title {{ font-family:{DISPLAY}; font-size:20px; font-weight:760; color:{TEXT};
      letter-spacing:0.06em; display:flex; align-items:center; gap:12px; }}
  .ec-hdr-live {{ display:inline-flex; align-items:center; gap:6px; font-family:{MONO};
      font-size:9px; letter-spacing:0.14em; color:{GREEN}; text-transform:uppercase; }}
  .ec-hdr-live i {{ width:6px; height:6px; border-radius:50%; background:{GREEN};
      box-shadow:0 0 9px {GREEN}; --c:{GREEN}; }}
  @media (prefers-reduced-motion: no-preference) {{
    .ec-hdr-live i {{ animation: ecPulse 2.4s ease-in-out infinite; }}
  }}
  .ec-hdr-sub {{ font-family:{MONO}; font-size:9px; letter-spacing:0.2em; color:{MUTED};
      text-transform:uppercase; margin-top:5px; }}
  .ec-hdr-stats {{ display:flex; gap:28px; flex-wrap:wrap; align-items:center; }}
  .ec-hdr-k {{ font-family:{MONO}; font-size:8px; letter-spacing:0.17em; color:{MUTED};
      text-transform:uppercase; text-align:right; }}
  .ec-hdr-v {{ font-family:{MONO}; font-size:17px; font-weight:700; margin-top:4px;
      text-align:right; font-variant-numeric:tabular-nums; }}

  /* ============ Premium segmented navigation ============ */
  .stTabs [data-baseweb="tab-list"] {{ position:sticky; top:0; z-index:50; gap:3px;
      background:{L2}; backdrop-filter:blur(14px); padding:6px;
      border:1px solid {BORDER_GLASS}; border-radius:13px; margin:16px 0 10px;
      box-shadow: 0 14px 40px -30px rgba(0,0,0,0.9); }}
  .stTabs [data-baseweb="tab-list"] button {{ font-family:{MONO} !important;
      font-size:10px !important; letter-spacing:0.1em; text-transform:uppercase;
      color:{MUTED} !important; border-radius:8px; padding:10px 15px !important;
      border:none !important; transition:all 0.18s ease; }}
  .stTabs [data-baseweb="tab-list"] button:hover {{ color:{TEXT} !important;
      background:{L3}; }}
  .stTabs [data-baseweb="tab-list"] button[aria-selected="true"] {{ color:{CYAN} !important;
      background: linear-gradient(180deg, rgba(255,255,255,0.028), rgba(255,255,255,0.006)), {L4};
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.08),
                  inset 0 -2px 0 {CYAN}, 0 8px 20px rgba(0,0,0,0.3); }}
  .stTabs [data-baseweb="tab-highlight"], .stTabs [data-baseweb="tab-border"] {{ display:none !important; }}

  /* ============ Hero ============ */
  .ec-hero {{ margin:10px 0 20px; }}
  .ec-hero-tag {{ display:inline-block; font-family:{MONO}; font-size:9px;
      letter-spacing:0.28em; color:var(--c,{CYAN}); padding:5px 11px;
      border:1px solid color-mix(in srgb, var(--c,{CYAN}) 40%, transparent);
      border-radius:4px; background: color-mix(in srgb, var(--c,{CYAN}) 12%, transparent);
      text-transform:uppercase; }}
  .ec-hero-title {{ font-family:{DISPLAY}; font-size:32px; font-weight:740; color:{TEXT};
      letter-spacing:-0.02em; line-height:1.1; margin-top:15px; max-width:24ch; }}
  .ec-hero-sub {{ font-size:14px; color:{DIM}; margin-top:12px; line-height:1.65;
      max-width:76ch; }}
  .ec-hero-rule {{ height:2px; margin-top:18px; background:{BORDER}; border-radius:2px;
      overflow:hidden; max-width:460px; }}
  .ec-hero-rule i {{ display:block; height:100%;
      background: linear-gradient(90deg, var(--c,{CYAN}), {VIOLET}); }}
  @media (prefers-reduced-motion: no-preference) {{
    .ec-hero-rule i {{ animation: ecRule 1.1s cubic-bezier(0.16,0.8,0.3,1) 0.25s both; }}
  }}

  /* ============ Posture command ============ */
  .pc-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
      gap:12px; margin:8px 0; }}
  .pc-cell {{ padding:24px 22px; overflow:hidden; transition:transform 0.22s ease; }}
  .pc-cell::after {{ content:""; position:absolute; top:0; left:0; right:0; height:2px;
      background:var(--c); opacity:0.35; }}
  .pc-cell:hover {{ transform: translateY(-4px); }}
  .pc-cell.emphasis {{ box-shadow: 0 0 34px -12px var(--c), 0 18px 44px -28px rgba(0,0,0,0.9); }}
  .pc-cell.emphasis::after {{ opacity:1; box-shadow:0 0 16px var(--c); }}
  .pc-value {{ font-family:{DISPLAY}; font-size:46px; font-weight:800; line-height:1;
      letter-spacing:-0.03em; font-variant-numeric:tabular-nums; }}
  .pc-label {{ font-family:{MONO}; font-size:9.5px; letter-spacing:0.15em; color:{MUTED};
      text-transform:uppercase; margin-top:13px; }}
  .pc-note {{ font-size:11px; color:{DIM}; margin-top:6px; }}
  .pc-ring {{ position:absolute; top:18px; right:18px; width:44px; height:44px;
      border-radius:50%;
      background: conic-gradient(var(--c) calc(var(--p)*1%), {L3} 0); }}
  .pc-ring-in {{ position:absolute; inset:5px; border-radius:50%; background:{L1}; }}

  /* ============ Pipeline ribbon ============ */
  .rb {{ display:flex; align-items:center; flex-wrap:wrap; gap:2px; padding:18px 22px;
      margin:6px 0 14px; }}
  .rb-node {{ display:flex; flex-direction:column; align-items:center; gap:9px;
      padding:0 8px; min-width:78px; }}
  .rb-dot {{ width:13px; height:13px; border-radius:50%; background:{L3};
      border:1px solid {BORDER_LIT}; transition:all 0.3s ease; }}
  .rb-node.on .rb-dot {{ background:{CYAN}; border-color:{CYAN}; box-shadow:0 0 16px {CYAN}; }}
  .rb-label {{ font-family:{MONO}; font-size:8px; letter-spacing:0.1em; color:{MUTED};
      text-transform:uppercase; text-align:center; }}
  .rb-node.on .rb-label {{ color:{CYAN}; }}
  .rb-flow {{ flex:1; min-width:16px; height:2px; position:relative; overflow:hidden;
      background:{BORDER}; border-radius:2px; }}
  .rb-flow i {{ position:absolute; inset:0; width:40%;
      background: linear-gradient(90deg, transparent, {CYAN}, transparent); }}
  @media (prefers-reduced-motion: no-preference) {{
    .rb-flow i {{ animation: ecFlow 2.6s ease-in-out infinite; }}
  }}

  /* ============ Discovery engine ============ */
  .dn-engine {{ display:flex; justify-content:center; margin:6px 0 14px; }}
  .dn-core {{ position:relative; width:180px; height:96px; display:flex;
      align-items:center; justify-content:center; }}
  .dn-core-ring {{ position:absolute; width:96px; height:96px; border-radius:50%;
      border:1px solid {CYAN}; opacity:0.4; box-shadow:0 0 30px -6px {CYAN} inset; }}
  @media (prefers-reduced-motion: no-preference) {{
    .dn-core-ring {{ animation: ecSpin 20s linear infinite; }}
  }}
  .dn-core-label {{ position:relative; font-family:{MONO}; font-size:9px;
      letter-spacing:0.16em; color:{CYAN}; text-align:center; line-height:1.5;
      text-transform:uppercase; }}
  .dn-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
      gap:12px; }}
  .dn {{ padding:20px 18px; text-align:center; transition:transform 0.22s ease; }}
  .dn::after {{ content:""; position:absolute; top:0; left:50%; transform:translateX(-50%);
      width:40%; height:2px; background:var(--c); opacity:0.6; }}
  .dn:hover {{ transform: translateY(-4px); }}
  .dn-count {{ font-family:{DISPLAY}; font-size:34px; font-weight:780; line-height:1;
      font-variant-numeric:tabular-nums; }}
  .dn-name {{ font-family:{MONO}; font-size:10px; letter-spacing:0.12em; color:{TEXT_SOFT};
      text-transform:uppercase; margin-top:11px; }}
  .dn-detail {{ font-size:10.5px; color:{MUTED}; margin-top:6px; line-height:1.4; }}

  /* ============ Metric tiles ============ */
  .mt-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
      gap:11px; margin:8px 0; }}
  .mt {{ padding:17px 19px; overflow:hidden; transition:transform 0.2s ease; }}
  .mt::after {{ content:""; position:absolute; top:0; left:0; right:0; height:2px;
      background:var(--c); }}
  .mt:hover {{ transform: translateY(-3px); }}
  .mt.glow {{ box-shadow:0 0 30px -12px var(--c), 0 18px 44px -28px rgba(0,0,0,0.9); }}
  .mt-label {{ font-family:{MONO}; font-size:8.5px; letter-spacing:0.15em; color:{MUTED};
      text-transform:uppercase; }}
  .mt-value {{ font-family:{DISPLAY}; font-size:31px; font-weight:760; margin-top:9px;
      line-height:1; letter-spacing:-0.02em; font-variant-numeric:tabular-nums; }}
  .mt-note {{ font-size:11px; color:{MUTED}; margin-top:7px; }}

  /* ============ Console table ============ */
  .ctbl {{ overflow:hidden; margin:8px 0; }}
  .ctbl table {{ width:100%; border-collapse:collapse; font-size:12.5px; }}
  .ctbl thead th {{ font-family:{MONO}; font-size:8.5px; letter-spacing:0.15em;
      color:{MUTED}; text-transform:uppercase; text-align:left; font-weight:600;
      padding:13px 15px; border-bottom:1px solid {BORDER_LIT};
      background: rgba(4,6,13,0.5); white-space:nowrap; }}
  .ctbl tbody td {{ padding:12px 15px; border-bottom:1px solid {BORDER};
      color:{DIM}; vertical-align:middle; }}
  .ctbl tbody td:first-child {{ box-shadow: inset 3px 0 0 var(--rail); color:{TEXT_SOFT}; }}
  .ctbl tbody tr {{ transition: background 0.16s ease; }}
  .ctbl tbody tr:hover {{ background: rgba(29,39,66,0.5); }}
  .ctbl tbody tr:last-child td {{ border-bottom:none; }}

  /* ============ Mosca horizon ============ */
  .mos {{ padding:28px 30px 24px; margin:10px 0; }}
  .mos-scale {{ display:flex; justify-content:space-between; font-family:{MONO};
      font-size:8.5px; letter-spacing:0.18em; color:{MUTED}; text-transform:uppercase;
      margin-bottom:10px; }}
  .mos-track {{ position:relative; height:46px; background: rgba(4,6,13,0.6);
      border-radius:9px; margin-bottom:48px; border:1px solid {BORDER}; }}
  .mos-track.empty {{ display:flex; align-items:center; justify-content:center;
      font-family:{MONO}; font-size:12px; letter-spacing:0.2em; color:{AMBER};
      margin-bottom:16px; }}
  .mos-seg {{ position:absolute; top:0; height:46px; display:flex; align-items:center;
      padding:0 13px; overflow:hidden; }}
  .mos-seg span {{ font-family:{MONO}; font-size:9.5px; color:{L0}; font-weight:700;
      white-space:nowrap; }}
  .mos-seg.x {{ left:0; background: linear-gradient(180deg, {ICE}, var(--c));
      border-radius:9px 0 0 9px; width:var(--w); }}
  .mos-seg.y {{ left:var(--left); background:var(--c); width:var(--w);
      border-radius:0 9px 9px 0; opacity:0.9; }}
  @media (prefers-reduced-motion: no-preference) {{
    .mos-seg.x {{ animation: ecGrow 0.95s cubic-bezier(0.16,0.8,0.3,1) 0.25s both; }}
    .mos-seg.y {{ animation: ecGrow 0.95s cubic-bezier(0.16,0.8,0.3,1) 0.65s both; }}
  }}
  .mos-marker {{ position:absolute; top:-12px; bottom:-38px; left:var(--left); }}
  .mos-marker-line {{ width:2px; height:96px; background:{AMBER};
      box-shadow:0 0 12px {AMBER}; }}
  .mos-marker-cap {{ position:absolute; top:-4px; left:-3px; width:8px; height:8px;
      border-radius:50%; background:{AMBER}; box-shadow:0 0 10px {AMBER}; }}
  .mos-marker-label {{ font-family:{MONO}; font-size:9px; color:{AMBER}; white-space:nowrap;
      margin-top:6px; transform:translateX(-42%); }}
  .mos-verdict {{ display:flex; flex-direction:column; gap:4px; }}
  .mos-eq {{ font-family:{MONO}; font-size:13px; font-weight:700; color:var(--c); }}
  .mos-state {{ font-family:{MONO}; font-size:10px; letter-spacing:0.14em; color:var(--c);
      text-transform:uppercase; }}

  /* ============ Roadmap lanes ============ */
  .ln {{ border-top:2px solid var(--c); overflow:hidden; height:100%; }}
  .ln-head {{ display:flex; align-items:center; gap:9px; padding:14px 16px;
      border-bottom:1px solid {BORDER}; }}
  .ln-marker {{ width:8px; height:8px; border-radius:50%; background:var(--c);
      box-shadow:0 0 10px var(--c); }}
  .ln-label {{ font-family:{MONO}; font-size:10px; letter-spacing:0.1em; color:var(--c);
      text-transform:uppercase; font-weight:640; flex:1; }}
  .ln-count {{ font-family:{MONO}; font-size:13px; font-weight:700; color:{TEXT};
      background:{L3}; border-radius:20px; padding:2px 11px; }}
  .ln-body {{ padding:9px; display:flex; flex-direction:column; gap:7px;
      max-height:360px; overflow-y:auto; }}
  .ln-item {{ background: rgba(4,6,13,0.5); border:1px solid {BORDER}; border-radius:8px;
      padding:10px 12px; font-size:11.5px; color:{DIM}; line-height:1.45;
      transition:border-color 0.16s ease; }}
  .ln-item:hover {{ border-color:var(--c); }}

  /* ============ Chips & seals ============ */
  .ec-chip {{ display:inline-flex; align-items:center; font-family:{MONO}; font-size:8.5px;
      font-weight:640; letter-spacing:0.08em; text-transform:uppercase; padding:3px 8px;
      border-radius:4px; color:var(--c);
      border:1px solid color-mix(in srgb, var(--c) 38%, transparent);
      background: color-mix(in srgb, var(--c) 12%, transparent); white-space:nowrap; }}
  .ec-seal {{ display:inline-flex; align-items:center; gap:14px; padding:14px 20px; }}
  .seal-mark {{ width:34px; height:34px; border-radius:50%; display:flex; align-items:center;
      justify-content:center; font-size:17px; font-weight:700; color:{L0}; background:var(--c);
      box-shadow:0 0 18px -3px var(--c); }}
  .seal-text {{ font-size:14px; font-weight:660; color:{TEXT}; }}
  .seal-sub {{ font-family:{MONO}; font-size:9px; letter-spacing:0.12em; color:{MUTED};
      text-transform:uppercase; margin-top:3px; }}

  /* ============ Streamlit widget polish ============ */
  .stButton button {{ font-family:{MONO} !important; font-size:10.5px !important;
      letter-spacing:0.1em; text-transform:uppercase; border-radius:9px; font-weight:640;
      transition:all 0.18s ease; }}
  .stButton button[kind="primary"] {{
      background: linear-gradient(180deg, rgba(255,255,255,0.03), transparent), {L4};
      border:1px solid {BORDER_FOCUS}; color:{CYAN} !important;
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.08), 0 12px 30px rgba(0,0,0,0.28); }}
  .stButton button[kind="primary"]:hover {{ border-color:{CYAN};
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.10), 0 0 18px -8px {CYAN};
      transform: translateY(-1px); }}
  .stDownloadButton button {{ font-family:{MONO} !important; font-size:10.5px !important;
      letter-spacing:0.08em; border-radius:9px; background:{L3};
      border:1px solid {BORDER_LIT}; }}
  .stDownloadButton button:hover {{ border-color:{CYAN}; color:{CYAN} !important; }}
  section[data-testid="stSidebar"] {{ background: linear-gradient(180deg, {L0}, {L1});
      border-right:1px solid {BORDER}; backdrop-filter:blur(8px); }}
  div[data-testid="stDataFrame"] {{ border:1px solid {BORDER}; border-radius:10px;
      overflow:hidden; }}
  div[data-testid="stExpander"] {{ background:{L2}; border:1px solid {BORDER_GLASS};
      border-radius:11px; backdrop-filter:blur(10px); }}
  .stSelectbox div[data-baseweb="select"] > div, .stTextInput input {{
      background:{L2} !important; border-color:{BORDER} !important; border-radius:9px !important;
      color:{TEXT} !important; }}
  code, pre {{ font-family:{MONO} !important; font-size:11.5px !important; }}

  /* ============ Responsive ============ */
  @media (max-width: 1600px) {{
    .pc-value {{ font-size:38px; }}
    .ec-hero-title {{ font-size:27px; }}
    .mt-value {{ font-size:26px; }}
  }}
  @media (max-width: 1200px) {{
    .pc-value {{ font-size:32px; }}
    .block-container {{ padding-left:1.6rem !important; padding-right:1.6rem !important; }}
  }}
</style>
"""
