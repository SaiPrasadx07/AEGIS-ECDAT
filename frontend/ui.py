"""
AegisPQC — dashboard design system.

Visual language for the platform: a futuristic enterprise cyber-defense command
center. Every component the dashboard renders is defined here, so the surfaces
compose from one vocabulary and restyling is a change in one file.

DESIGN POSITION
---------------
The reference points are security operations consoles and premium developer
tooling — Datadog, Vercel, Grafana — not gaming interfaces.

  * **Restraint.** Most of the interface is near-black graphite. Colour carries
    meaning (risk level, verification state, measured versus estimated) and is
    never decoration. Glow appears only on states that matter.
  * **Hierarchy.** Eyebrow, title, subtitle, label, value are visually distinct
    so an executive can skim the same screen an engineer drills into.
  * **Monospace for machine data only.** Hex, OIDs, byte counts, traces. Prose
    stays in the UI font.
  * **Density with air.** Enterprise consoles show a lot at once; generous
    spacing is what keeps that readable rather than cluttered.

TWO HARD CONSTRAINTS
--------------------
**No external assets.** No web fonts, no CDN, no remote images. The demo must
run air-gapped, and a test asserts no frontend module references an external
URL. Typography uses system font stacks, which look native and load instantly.

**Streamlit's DOM is not a stable API.** Its generated class names change
between releases, so styling that targets them breaks silently on upgrade.
Everything here styles our OWN markup inside ``st.markdown(unsafe_allow_html)``.
The handful of rules that touch Streamlit target stable ``data-testid`` and
``data-baseweb`` attributes, and are cosmetic only — if a future version ignores
them the dashboard still renders correctly, just plainer.
"""

from __future__ import annotations

from typing import Any, Iterable

import streamlit as st

# ==========================================================================
# Tokens
# ==========================================================================

# Surfaces — near-black graphite, four steps of elevation.
VOID = "#05070b"
BASE = "#080b11"
SURFACE = "#0d1119"
RAISED = "#121722"
BORDER = "#1c2431"
BORDER_LIT = "#2a3547"

# Type
TEXT = "#e9eff7"
DIM = "#8493a6"
FAINT = "#55617240"
MUTED = "#6b7889"

# Primary — electric cyan
CYAN = "#00d4ff"
CYAN_DEEP = "#0891b2"
CYAN_GLOW = "rgba(0, 212, 255, 0.13)"

# Secondary — restrained violet
VIOLET = "#8b6cff"
VIOLET_GLOW = "rgba(139, 108, 255, 0.11)"

# Status
GREEN = "#00e08a"
AMBER = "#ffb020"
RED = "#ff4d5e"
GREY = "#6b7889"

# Semantic aliases used across surfaces
ACCENT = CYAN
SAFE = GREEN
LOW = CYAN
MEDIUM = AMBER
HIGH = "#ff8534"
CRITICAL = RED
UNKNOWN = GREY
TEXT_MUTED = DIM
TEXT_DIM = MUTED
BORDER_STRONG = BORDER_LIT
SURFACE_RAISED = RAISED

RISK_COLOUR: dict[str, str] = {
    "CRITICAL": CRITICAL,
    "HIGH": HIGH,
    "MEDIUM": MEDIUM,
    "LOW": LOW,
    "SAFE": SAFE,
    "UNKNOWN": UNKNOWN,
}

# System font stacks. No web fonts — the demo runs offline.
SANS = (
    '-apple-system, BlinkMacSystemFont, "Segoe UI Variable Display", '
    '"Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'
)
MONO = (
    'ui-monospace, "Cascadia Mono", "Cascadia Code", "SF Mono", '
    'Menlo, Consolas, "Liberation Mono", monospace'
)


def inject_css() -> None:
    """Inject the stylesheet. Call once, at the top of the app."""
    st.markdown(
        f"""
        <style>
          /* ============ Streamlit chrome ============ */
          /* Cosmetic only. If a future release ignores these the app still
             works — it just shows Streamlit's default furniture. */
          #MainMenu {{ visibility: hidden; }}
          footer {{ visibility: hidden; }}
          header[data-testid="stHeader"] {{
              background: transparent; height: 0;
          }}
          [data-testid="stToolbar"] {{ display: none; }}
          [data-testid="stDecoration"] {{ display: none; }}
          [data-testid="stStatusWidget"] {{ display: none; }}

          .stApp {{
              background:
                radial-gradient(1200px 600px at 15% -10%, {CYAN_GLOW}, transparent 60%),
                radial-gradient(900px 500px at 95% 0%, {VIOLET_GLOW}, transparent 55%),
                {BASE};
              font-family: {SANS};
          }}
          .block-container {{
              padding-top: 1.6rem !important;
              padding-bottom: 3rem !important;
              max-width: 1500px;
          }}

          /* ============ Sidebar command rail ============ */
          section[data-testid="stSidebar"] {{
              background: linear-gradient(180deg, {VOID} 0%, {BASE} 100%);
              border-right: 1px solid {BORDER};
          }}
          section[data-testid="stSidebar"] .block-container {{ padding-top: 1rem; }}

          .rail-brand {{
              padding: 4px 0 16px 0; border-bottom: 1px solid {BORDER};
              margin-bottom: 16px;
          }}
          .rail-mark {{
              font-family: {MONO}; font-size: 19px; font-weight: 700;
              letter-spacing: 0.13em; color: {TEXT}; line-height: 1;
          }}
          .rail-mark span {{ color: {CYAN}; }}
          .rail-sub {{
              font-family: {MONO}; font-size: 8.5px; letter-spacing: 0.21em;
              color: {MUTED}; text-transform: uppercase; margin-top: 7px;
          }}

          .rail-label {{
              font-family: {MONO}; font-size: 9px; letter-spacing: 0.19em;
              color: {MUTED}; text-transform: uppercase;
              margin: 20px 0 9px 0;
          }}
          .rail-row {{
              display: flex; justify-content: space-between; align-items: center;
              padding: 6px 0; border-bottom: 1px solid {BORDER};
              font-size: 12px; color: {DIM};
          }}
          .rail-row:last-child {{ border-bottom: none; }}
          .rail-row b {{ font-family: {MONO}; font-size: 12.5px; color: {TEXT}; }}

          .rail-stage {{
              display: flex; align-items: center; gap: 9px; padding: 5px 0;
              font-family: {MONO}; font-size: 10px; letter-spacing: 0.11em;
              color: {MUTED};
          }}
          .rail-stage i {{
              width: 5px; height: 5px; border-radius: 50%;
              background: {CYAN}; box-shadow: 0 0 7px {CYAN};
              flex: 0 0 5px; font-style: normal;
          }}
          .rail-stage.partial i {{ background: {AMBER}; box-shadow: 0 0 7px {AMBER}; }}
          .rail-stage em {{ font-style: normal; color: {DIM}; }}

          /* ============ Top header ============ */
          .hdr {{
              display: flex; justify-content: space-between; align-items: center;
              flex-wrap: wrap; gap: 18px;
              padding: 15px 22px; margin-bottom: 4px;
              background: linear-gradient(90deg, {SURFACE} 0%, rgba(13,17,25,0.4) 100%);
              border: 1px solid {BORDER}; border-radius: 8px;
              position: relative; overflow: hidden;
          }}
          .hdr::before {{
              content: ""; position: absolute; left: 0; top: 0; bottom: 0;
              width: 2px; background: linear-gradient(180deg, {CYAN}, {VIOLET});
          }}
          .hdr-title {{
              font-size: 17px; font-weight: 660; color: {TEXT};
              letter-spacing: -0.01em;
          }}
          .hdr-title span {{ color: {CYAN}; }}
          .hdr-sub {{
              font-family: {MONO}; font-size: 9px; letter-spacing: 0.2em;
              color: {MUTED}; text-transform: uppercase; margin-top: 4px;
          }}
          .hdr-stats {{ display: flex; gap: 22px; flex-wrap: wrap; align-items: center; }}
          .hdr-stat {{ text-align: right; }}
          .hdr-stat-k {{
              font-family: {MONO}; font-size: 8.5px; letter-spacing: 0.17em;
              color: {MUTED}; text-transform: uppercase;
          }}
          .hdr-stat-v {{
              font-family: {MONO}; font-size: 13px; font-weight: 600;
              margin-top: 3px; letter-spacing: 0.04em;
          }}

          .live {{
              display: inline-flex; align-items: center; gap: 7px;
              font-family: {MONO}; font-size: 10px; letter-spacing: 0.15em;
              color: {GREEN}; text-transform: uppercase;
          }}
          .live i {{
              width: 6px; height: 6px; border-radius: 50%; background: {GREEN};
              box-shadow: 0 0 9px {GREEN}; font-style: normal;
              animation: pulse 2.4s ease-in-out infinite;
          }}
          @keyframes pulse {{
              0%, 100% {{ opacity: 1; }}
              50% {{ opacity: 0.35; }}
          }}

          /* ============ Tabs as a segmented command bar ============ */
          .stTabs [data-baseweb="tab-list"] {{
              gap: 2px; background: {SURFACE}; padding: 4px;
              border: 1px solid {BORDER}; border-radius: 8px;
              margin: 14px 0 6px 0;
          }}
          .stTabs [data-baseweb="tab-list"] button {{
              font-family: {MONO} !important; font-size: 10.5px !important;
              letter-spacing: 0.11em; text-transform: uppercase;
              color: {MUTED} !important; border-radius: 5px;
              padding: 9px 15px !important; transition: all 0.15s ease;
          }}
          .stTabs [data-baseweb="tab-list"] button:hover {{
              color: {TEXT} !important; background: {RAISED};
          }}
          .stTabs [data-baseweb="tab-list"] button[aria-selected="true"] {{
              color: {CYAN} !important; background: {CYAN_GLOW};
              box-shadow: inset 0 0 0 1px rgba(0,212,255,0.28);
          }}
          .stTabs [data-baseweb="tab-highlight"] {{ display: none; }}
          .stTabs [data-baseweb="tab-border"] {{ display: none; }}

          /* ============ Sections ============ */
          .sec {{ margin: 30px 0 15px 0; }}
          .sec-eyebrow {{
              font-family: {MONO}; font-size: 9px; letter-spacing: 0.21em;
              color: {CYAN}; text-transform: uppercase; margin-bottom: 7px;
              display: flex; align-items: center; gap: 9px;
          }}
          .sec-eyebrow::after {{
              content: ""; flex: 1; height: 1px;
              background: linear-gradient(90deg, {BORDER_LIT}, transparent);
          }}
          .sec-title {{
              font-size: 21px; font-weight: 650; color: {TEXT};
              letter-spacing: -0.015em; line-height: 1.2;
          }}
          .sec-sub {{
              font-size: 13px; color: {DIM}; margin-top: 7px;
              max-width: 88ch; line-height: 1.6;
          }}

          /* ============ Metric cards ============ */
          .cards {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 8px 0; }}
          .card {{
              flex: 1 1 148px; background: {SURFACE};
              border: 1px solid {BORDER}; border-radius: 7px;
              padding: 14px 16px; position: relative; overflow: hidden;
              transition: border-color 0.18s ease;
          }}
          .card:hover {{ border-color: {BORDER_LIT}; }}
          .card::before {{
              content: ""; position: absolute; top: 0; left: 0; right: 0;
              height: 2px; background: var(--c, {BORDER_LIT});
          }}
          .card.glow {{ box-shadow: 0 0 22px -8px var(--c); }}
          .card-k {{
              font-family: {MONO}; font-size: 9px; letter-spacing: 0.16em;
              color: {MUTED}; text-transform: uppercase;
          }}
          .card-v {{
              font-size: 28px; font-weight: 660; color: var(--vc, {TEXT});
              margin-top: 7px; line-height: 1; letter-spacing: -0.02em;
              font-variant-numeric: tabular-nums;
          }}
          .card-n {{ font-size: 11px; color: {MUTED}; margin-top: 6px; }}

          /* ============ Posture ring ============ */
          .posture {{
              display: flex; align-items: center; gap: 30px; flex-wrap: wrap;
              background: {SURFACE}; border: 1px solid {BORDER};
              border-radius: 10px; padding: 26px 30px;
          }}
          .ring {{
              width: 168px; height: 168px; border-radius: 50%; flex: 0 0 168px;
              background: conic-gradient(var(--c) calc(var(--p) * 1%), {RAISED} 0);
              display: flex; align-items: center; justify-content: center;
              position: relative;
          }}
          .ring::after {{
              content: ""; position: absolute; inset: 11px; border-radius: 50%;
              background: {SURFACE};
          }}
          .ring-in {{ position: relative; z-index: 1; text-align: center; }}
          .ring-v {{
              font-size: 46px; font-weight: 700; color: var(--c); line-height: 1;
              letter-spacing: -0.035em; font-variant-numeric: tabular-nums;
          }}
          .ring-d {{
              font-family: {MONO}; font-size: 11px; color: {MUTED}; margin-top: 3px;
          }}
          .ring-k {{
              font-family: {MONO}; font-size: 8px; letter-spacing: 0.19em;
              color: {MUTED}; text-transform: uppercase; margin-top: 8px;
          }}
          .posture-body {{ flex: 1 1 320px; min-width: 260px; }}
          .posture-verdict {{
              font-size: 24px; font-weight: 680; letter-spacing: -0.02em;
              line-height: 1.15;
          }}
          .posture-note {{
              font-size: 13px; color: {DIM}; margin-top: 10px; line-height: 1.62;
              max-width: 62ch;
          }}

          /* ============ Pills ============ */
          .pill {{
              display: inline-flex; align-items: center; gap: 5px;
              font-family: {MONO}; font-size: 9px; font-weight: 620;
              letter-spacing: 0.13em; text-transform: uppercase;
              padding: 3px 9px; border-radius: 3px; border: 1px solid;
              margin-right: 6px; vertical-align: middle; white-space: nowrap;
          }}
          .pill i {{
              width: 4px; height: 4px; border-radius: 50%;
              background: currentColor; font-style: normal;
          }}

          /* ============ Panels ============ */
          .panel {{
              background: {SURFACE}; border: 1px solid {BORDER};
              border-left: 2px solid var(--c, {BORDER_LIT});
              border-radius: 7px; padding: 16px 18px; margin-bottom: 10px;
              transition: border-color 0.18s ease;
          }}
          .panel:hover {{ border-color: {BORDER_LIT}; border-left-color: var(--c, {BORDER_LIT}); }}
          .panel-head {{
              display: flex; justify-content: space-between; align-items: baseline;
              gap: 14px; flex-wrap: wrap;
          }}
          .panel-t {{ font-size: 14.5px; font-weight: 640; color: {TEXT}; }}
          .panel-m {{ font-family: {MONO}; font-size: 10.5px; color: {MUTED}; }}
          .panel-b {{
              font-size: 12.5px; color: {DIM}; margin-top: 9px; line-height: 1.62;
          }}
          .panel-b b {{ color: {TEXT}; font-weight: 600; }}

          /* ============ Key/value grid ============ */
          .kv {{
              display: flex; flex-wrap: wrap; gap: 10px 28px; margin-top: 13px;
              padding-top: 13px; border-top: 1px solid {BORDER};
          }}
          .kv-i {{ min-width: 116px; }}
          .kv-k {{
              font-family: {MONO}; font-size: 8.5px; letter-spacing: 0.15em;
              color: {MUTED}; text-transform: uppercase;
          }}
          .kv-v {{
              font-family: {MONO}; font-size: 12px; color: {TEXT}; margin-top: 4px;
              word-break: break-all;
          }}

          /* ============ Data table ============ */
          .tbl {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
          .tbl thead th {{
              font-family: {MONO}; font-size: 8.5px; letter-spacing: 0.16em;
              color: {MUTED}; text-transform: uppercase; text-align: left;
              padding: 9px 12px; border-bottom: 1px solid {BORDER_LIT};
              font-weight: 600; white-space: nowrap;
          }}
          .tbl tbody td {{
              padding: 10px 12px; border-bottom: 1px solid {BORDER};
              color: {DIM}; vertical-align: middle;
          }}
          .tbl tbody tr {{ transition: background 0.14s ease; }}
          .tbl tbody tr:hover {{ background: {RAISED}; }}
          .tbl tbody tr:last-child td {{ border-bottom: none; }}
          .tbl .mono {{ font-family: {MONO}; font-size: 11.5px; color: {TEXT}; }}
          .tbl .lead {{ color: {TEXT}; font-weight: 570; }}
          .tbl-wrap {{
              background: {SURFACE}; border: 1px solid {BORDER};
              border-radius: 7px; overflow-x: auto; margin: 8px 0;
          }}

          /* ============ Timeline ============ */
          .tl {{ margin: 6px 0; }}
          .tl-s {{
              display: flex; gap: 15px; padding: 12px 0;
              border-bottom: 1px solid {BORDER}; position: relative;
          }}
          .tl-s:last-child {{ border-bottom: none; }}
          .tl-n {{
              flex: 0 0 30px; height: 30px; border-radius: 6px;
              display: flex; align-items: center; justify-content: center;
              font-family: {MONO}; font-size: 11px; font-weight: 660;
              background: {RAISED}; border: 1px solid {BORDER_LIT}; color: {MUTED};
          }}
          .tl-s.on .tl-n {{
              background: rgba(0,224,138,0.11); border-color: {GREEN};
              color: {GREEN}; box-shadow: 0 0 14px -4px {GREEN};
          }}
          .tl-s.off {{ opacity: 0.42; }}
          .tl-t {{ font-size: 13px; font-weight: 620; color: {TEXT}; }}
          .tl-s.off .tl-t {{ color: {MUTED}; }}
          .tl-d {{
              font-size: 12px; color: {DIM}; margin-top: 4px;
              line-height: 1.58; max-width: 92ch;
          }}

          /* ============ Roadmap ============ */
          .rm {{ position: relative; padding-left: 26px; margin: 10px 0; }}
          .rm::before {{
              content: ""; position: absolute; left: 7px; top: 8px; bottom: 8px;
              width: 1px; background: linear-gradient(180deg, {CYAN}, {VIOLET}, {BORDER});
          }}
          .rm-p {{ position: relative; margin-bottom: 16px; }}
          .rm-p::before {{
              content: ""; position: absolute; left: -23px; top: 14px;
              width: 9px; height: 9px; border-radius: 50%;
              background: var(--c, {CYAN}); box-shadow: 0 0 11px var(--c, {CYAN});
              border: 2px solid {BASE};
          }}

          /* ============ Terminal ============ */
          .term {{
              background: {VOID}; border: 1px solid {BORDER};
              border-radius: 7px; padding: 14px 16px; margin: 8px 0;
              font-family: {MONO}; font-size: 11px; line-height: 1.62;
              color: {DIM}; max-height: 340px; overflow-y: auto;
              white-space: pre-wrap; word-break: break-word;
          }}
          .term-h {{
              font-family: {MONO}; font-size: 8.5px; letter-spacing: 0.17em;
              color: {MUTED}; text-transform: uppercase; margin-bottom: 9px;
              padding-bottom: 8px; border-bottom: 1px solid {BORDER};
          }}

          /* ============ Note ============ */
          .note {{
              border-radius: 7px; padding: 13px 16px; margin: 11px 0;
              font-size: 12.5px; line-height: 1.65; color: {DIM};
              background: {SURFACE};
              border: 1px solid {BORDER}; border-left: 2px solid var(--c, {CYAN});
          }}
          .note b {{ color: {TEXT}; font-weight: 600; }}

          /* ============ Flow strip ============ */
          .flow {{
              display: flex; flex-wrap: wrap; align-items: center; gap: 3px;
              margin: 8px 0 16px 0; font-family: {MONO}; font-size: 9.5px;
              letter-spacing: 0.13em;
          }}
          .flow-s {{
              padding: 6px 12px; border-radius: 5px; border: 1px solid {BORDER};
              color: {MUTED}; background: {SURFACE}; white-space: nowrap;
          }}
          .flow-s.on {{
              border-color: {CYAN}; color: {CYAN}; background: {CYAN_GLOW};
              font-weight: 640; box-shadow: 0 0 16px -6px {CYAN};
          }}
          .flow-a {{ color: {FAINT}; padding: 0 1px; }}

          /* ============ Streamlit widget polish ============ */
          .stButton button {{
              font-family: {MONO} !important; font-size: 11px !important;
              letter-spacing: 0.11em; text-transform: uppercase;
              border-radius: 6px; font-weight: 620;
              transition: all 0.16s ease;
          }}
          .stButton button[kind="primary"] {{
              background: linear-gradient(135deg, {CYAN_DEEP}, {CYAN});
              border: none; color: {VOID} !important;
          }}
          .stButton button[kind="primary"]:hover {{
              box-shadow: 0 0 22px -5px {CYAN}; transform: translateY(-1px);
          }}
          .stButton button[kind="secondary"] {{
              background: {SURFACE}; border: 1px solid {BORDER_LIT};
              color: {DIM} !important;
          }}
          .stButton button[kind="secondary"]:hover {{
              border-color: {CYAN}; color: {CYAN} !important;
          }}
          .stDownloadButton button {{
              font-family: {MONO} !important; font-size: 11px !important;
              letter-spacing: 0.09em; border-radius: 6px;
              background: {SURFACE}; border: 1px solid {BORDER_LIT};
          }}

          div[data-testid="stMetricValue"] {{
              font-size: 25px; font-weight: 650; font-variant-numeric: tabular-nums;
          }}
          div[data-testid="stMetricLabel"] {{
              font-family: {MONO}; font-size: 9px; letter-spacing: 0.15em;
              text-transform: uppercase; color: {MUTED};
          }}

          div[data-testid="stExpander"] {{
              background: {SURFACE}; border: 1px solid {BORDER};
              border-radius: 7px; margin-bottom: 8px;
          }}
          div[data-testid="stExpander"] summary {{ font-size: 13px; font-weight: 570; }}

          .stRadio [role="radiogroup"] {{ gap: 6px; }}
          .stSelectbox div[data-baseweb="select"] > div,
          .stTextInput input, .stTextArea textarea {{
              background: {SURFACE} !important; border-color: {BORDER} !important;
              border-radius: 6px !important; color: {TEXT} !important;
          }}
          .stTextArea textarea {{ font-family: {MONO} !important; font-size: 12px !important; }}

          div[data-testid="stDataFrame"] {{
              border: 1px solid {BORDER}; border-radius: 7px;
          }}

          code, pre {{ font-family: {MONO} !important; font-size: 11.5px !important; }}

          /* Code blocks share the terminal's look, so a trace rendered with
             st.code (which keeps its copy affordance) is visually identical to
             the custom terminal component. */
          div[data-testid="stCode"], .stCode {{
              background: {VOID} !important; border: 1px solid {BORDER};
              border-radius: 7px;
          }}
          div[data-testid="stCode"] pre, .stCode pre {{
              background: transparent !important; color: {DIM} !important;
              line-height: 1.62 !important;
          }}

          hr {{ border-color: {BORDER}; }}

          /* 1366x768 is the likely demo machine — tighten spacing there. */
          @media (max-width: 1400px) {{
              .block-container {{ padding-left: 2.2rem !important; padding-right: 2.2rem !important; }}
              .ring {{ width: 138px; height: 138px; flex: 0 0 138px; }}
              .ring-v {{ font-size: 38px; }}
              .card-v {{ font-size: 24px; }}
              .sec-title {{ font-size: 19px; }}
              .posture {{ padding: 20px 22px; gap: 22px; }}
          }}
        </style>
        """,
        unsafe_allow_html=True,
    )


# ==========================================================================
# Rail
# ==========================================================================


def rail_brand() -> None:
    """The product mark at the top of the sidebar rail."""
    st.markdown(
        f'<div class="rail-brand"><div class="rail-mark">AEGIS<span>PQC</span></div>'
        f'<div class="rail-sub">Post-Quantum Security Platform</div></div>',
        unsafe_allow_html=True,
    )


def rail_label(text: str) -> None:
    """A small uppercase section label inside the rail."""
    st.markdown(f'<div class="rail-label">{text}</div>', unsafe_allow_html=True)


def rail_rows(rows: list[tuple[str, str, str]]) -> None:
    """Telemetry rows: ``(label, value, colour)``."""
    body = "".join(
        f'<div class="rail-row"><span>{label}</span>'
        f'<b style="color:{colour}">{value}</b></div>'
        for label, value, colour in rows
    )
    st.markdown(body, unsafe_allow_html=True)


def rail_workflow(stages: Iterable[dict[str, Any]]) -> None:
    """The migration workflow, with partially-implemented stages marked.

    A stage the prototype does not fully perform shows amber rather than cyan.
    The distinction is deliberate — the workflow must not imply capability the
    product does not have.
    """
    body = "".join(
        f'<div class="rail-stage{"" if stage["implemented"] else " partial"}">'
        f'<i></i><span>{stage["name"]}</span>'
        f'<em style="margin-left:auto;font-size:9px">{stage["surface"]}</em></div>'
        for stage in stages
    )
    st.markdown(body, unsafe_allow_html=True)


# ==========================================================================
# Header
# ==========================================================================


def header(stats: list[tuple[str, str, str]]) -> None:
    """The top command header: brand, live indicator, and key telemetry."""
    cells = "".join(
        f'<div class="hdr-stat"><div class="hdr-stat-k">{label}</div>'
        f'<div class="hdr-stat-v" style="color:{colour}">{value}</div></div>'
        for label, value, colour in stats
    )
    st.markdown(
        f'<div class="hdr"><div><div class="hdr-title">AEGIS<span>PQC</span> '
        f'&nbsp;<span class="live"><i></i>Live</span></div>'
        f'<div class="hdr-sub">Post-Quantum Security Platform</div></div>'
        f'<div class="hdr-stats">{cells}</div></div>',
        unsafe_allow_html=True,
    )


def flow(stages: Iterable[dict[str, Any]], active: str | None = None) -> None:
    """The workflow strip, with the current stage highlighted."""
    parts: list[str] = []
    for index, stage in enumerate(stages):
        if index:
            parts.append('<span class="flow-a">&#9656;</span>')
        on = " on" if stage["key"] == active else ""
        parts.append(f'<span class="flow-s{on}">{stage["name"]}</span>')
    st.markdown(f'<div class="flow">{"".join(parts)}</div>', unsafe_allow_html=True)


# ==========================================================================
# Structure
# ==========================================================================


def section(title: str, subtitle: str = "", eyebrow: str = "") -> None:
    """A section header with optional eyebrow rule and description."""
    eyebrow_html = f'<div class="sec-eyebrow">{eyebrow}</div>' if eyebrow else ""
    subtitle_html = f'<div class="sec-sub">{subtitle}</div>' if subtitle else ""
    st.markdown(
        f'<div class="sec">{eyebrow_html}<div class="sec-title">{title}</div>'
        f"{subtitle_html}</div>",
        unsafe_allow_html=True,
    )


def cards(items: list[dict[str, Any]]) -> None:
    """A row of metric cards.

    Args:
        items: Dicts with ``label``, ``value``, optional ``note``, ``colour``,
            ``value_colour``, and ``glow`` (reserve the glow for states that
            genuinely matter — everything glowing is nothing glowing).
    """
    cells: list[str] = []
    for item in items:
        colour = item.get("colour", BORDER_LIT)
        note = f'<div class="card-n">{item["note"]}</div>' if item.get("note") else ""
        glow = " glow" if item.get("glow") else ""
        cells.append(
            f'<div class="card{glow}" style="--c:{colour};'
            f'--vc:{item.get("value_colour", TEXT)}">'
            f'<div class="card-k">{item["label"]}</div>'
            f'<div class="card-v">{item["value"]}</div>{note}</div>'
        )
    st.markdown(f'<div class="cards">{"".join(cells)}</div>', unsafe_allow_html=True)


#: Backwards-compatible alias — earlier surfaces call this name.
tiles = cards


def posture(score: int, verdict: str, colour: str, note: str) -> None:
    """The hero security-posture display: a scored ring plus the verdict."""
    st.markdown(
        f'<div class="posture">'
        f'<div class="ring" style="--p:{score};--c:{colour}">'
        f'<div class="ring-in"><div class="ring-v">{score}</div>'
        f'<div class="ring-d">/ 100</div>'
        f'<div class="ring-k">Readiness score</div></div></div>'
        f'<div class="posture-body">'
        f'<div class="posture-verdict" style="color:{colour}">{verdict}</div>'
        f'<div class="posture-note">{note}</div></div></div>',
        unsafe_allow_html=True,
    )


def pill(text: str, colour: str, dot: bool = True) -> str:
    """Return status-pill markup. Returns rather than renders, for composition."""
    marker = "<i></i>" if dot else ""
    return (
        f'<span class="pill" style="color:{colour};border-color:{colour}55;'
        f'background:{colour}14">{marker}{text}</span>'
    )


def risk_pill(risk: str) -> str:
    """Status pill coloured by risk level."""
    return pill(risk, RISK_COLOUR.get(risk, UNKNOWN))


def evidence_pill(evidence: str) -> str:
    """Status pill for VERIFIED versus DECLARED.

    Different colours because the distinction is load-bearing: one is proof of
    what is deployed, the other is an operator's claim.
    """
    return pill(evidence, GREEN if evidence == "VERIFIED" else AMBER)


# Aliases kept so existing surface code continues to work.
badge = pill
risk_badge = risk_pill
evidence_badge = evidence_pill


def panel(
    title: str,
    meta: str = "",
    body: str = "",
    accent: str = BORDER_LIT,
    badges: str = "",
    kv: list[tuple[str, str]] | None = None,
) -> None:
    """A content panel with optional pills and a monospace key/value grid."""
    kv_html = ""
    if kv:
        cells = "".join(
            f'<div class="kv-i"><div class="kv-k">{key}</div>'
            f'<div class="kv-v">{value}</div></div>'
            for key, value in kv
        )
        kv_html = f'<div class="kv">{cells}</div>'
    body_html = f'<div class="panel-b">{body}</div>' if body else ""
    st.markdown(
        f'<div class="panel" style="--c:{accent}">'
        f'<div class="panel-head"><div class="panel-t">{badges}{title}</div>'
        f'<div class="panel-m">{meta}</div></div>'
        f"{body_html}{kv_html}</div>",
        unsafe_allow_html=True,
    )


card = panel


def note(text: str, colour: str = CYAN) -> None:
    """A callout box."""
    st.markdown(
        f'<div class="note" style="--c:{colour}">{text}</div>', unsafe_allow_html=True
    )


def table(columns: list[str], rows: list[list[str]]) -> None:
    """A styled data table.

    Cells may contain markup, so pills and monospace spans compose into rows.
    Used where the display should read as a security console; genuine tabular
    data the user may want to sort still uses ``st.dataframe``.
    """
    head = "".join(f"<th>{column}</th>" for column in columns)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows
    )
    st.markdown(
        f'<div class="tbl-wrap"><table class="tbl">'
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>",
        unsafe_allow_html=True,
    )


def timeline(steps: list[dict[str, Any]]) -> None:
    """A numbered procedure.

    Steps not reached are dimmed rather than hidden, so a partial or refused
    procedure reads honestly instead of appearing complete.
    """
    rows: list[str] = []
    for step in steps:
        reached = step.get("reached", True)
        state = "on" if reached else "off"
        outcome = (
            pill(step["outcome"], GREEN if reached else GREY)
            if step.get("outcome")
            else ""
        )
        rows.append(
            f'<div class="tl-s {state}"><div class="tl-n">'
            f'{step["index"]:02d}</div><div style="flex:1">'
            f'<div class="tl-t">{step["title"]} {outcome}</div>'
            f'<div class="tl-d">{step["detail"]}</div></div></div>'
        )
    st.markdown(f'<div class="tl">{"".join(rows)}</div>', unsafe_allow_html=True)


procedure_steps = timeline


def roadmap(phases: list[dict[str, Any]]) -> None:
    """A vertical phase roadmap.

    Args:
        phases: Dicts with ``name``, ``scope``, ``description``, ``assets``,
            ``asset_count``, and ``colour``.
    """
    blocks: list[str] = []
    for phase in phases:
        assets = (
            '<div class="kv"><div class="kv-i" style="min-width:100%">'
            f'<div class="kv-k">Assets</div><div class="kv-v">'
            f'{" · ".join(phase["assets"])}</div></div></div>'
            if phase.get("assets")
            else ""
        )
        blocks.append(
            f'<div class="rm-p" style="--c:{phase["colour"]}">'
            f'<div class="panel" style="--c:{phase["colour"]};margin-bottom:0">'
            f'<div class="panel-head">'
            f'<div class="panel-t">{phase["name"]}</div>'
            f'<div class="panel-m">{phase["asset_count"]} assets · {phase["scope"]}</div>'
            f'</div><div class="panel-b">{phase["description"]}</div>'
            f"{assets}</div></div>"
        )
    st.markdown(f'<div class="rm">{"".join(blocks)}</div>', unsafe_allow_html=True)


def terminal(text: str, heading: str = "Evidence") -> None:
    """A monospace evidence panel for raw traces and captured bytes."""
    escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    st.markdown(
        f'<div class="term"><div class="term-h">{heading}</div>{escaped}</div>',
        unsafe_allow_html=True,
    )


def chart_layout(figure, height: int = 280):
    """Apply the platform chart styling to a Plotly figure.

    Centralised so every chart in the product shares one visual language rather
    than each surface configuring its own.
    """
    figure.update_layout(
        template="plotly_dark",
        height=height,
        margin=dict(l=8, r=24, t=10, b=8),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=MONO, size=11, color=DIM),
        showlegend=False,
    )
    figure.update_xaxes(gridcolor=BORDER, zerolinecolor=BORDER)
    figure.update_yaxes(gridcolor=BORDER, zerolinecolor=BORDER)
    return figure
