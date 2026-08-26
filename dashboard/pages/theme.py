"""
Theme ThreatHunter — esthetique "Replicate" adaptee au Threat Hunting.

Carnet de laboratoire d'analyste SOC : canvas creme chaud, orange vif
reserve aux alertes CRITICAL (accent-tampon), wells sombres pour les
donnees techniques (IP, hashs, IOC, logs Zeek), typographie massive.

UTILISATION (une seule ligne dans ton dashboard) :

    from dashboard.theme import inject_theme
    inject_theme()   # a appeler juste apres st.set_page_config(...)

Puis, pour les composants signature (optionnel) :

    from dashboard.theme import kpi_card, severity_badge, code_well, section_header

Aucune dependance autre que streamlit. Ne touche pas a ta logique de donnees.
"""
from __future__ import annotations
import streamlit as st


# ─────────────────────────────────────────────────────────────
#  JETONS DE DESIGN (issus du systeme Replicate, adaptes cyber)
# ─────────────────────────────────────────────────────────────
TOKENS = {
    # Marque / accent — l'orange est un TAMPON : rare, sur le critique
    "primary":        "#ea2804",
    "primary_deep":   "#c01f00",
    "hero_glow":      "#ff6a3d",
    "hero_pink":      "#f4a8a0",
    # Surfaces creme (jamais de blanc pur au niveau page)
    "canvas":         "#f9f7f3",
    "surface_bone":   "#f3f0e8",
    "surface_card":   "#ffffff",
    "surface_dark":   "#202020",
    "surface_deep":   "#000000",
    # Texte
    "ink":            "#202020",
    "body":           "#3a3a3a",
    "charcoal":       "#575757",
    "mute":           "#646464",
    "ash":            "#8d8d8d",
    "on_dark":        "#fcfcfc",
    "on_dark_mute":   "rgba(252,252,252,0.72)",
    # Lignes
    "hairline":       "rgba(32,32,32,0.12)",
    "hairline_strong":"#202020",
    "divider_dark":   "rgba(255,255,255,0.20)",
    # Semantique cyber (severite) — l'orange reste la marque, ces tons servent le sens
    "sev_critical":   "#ea2804",   # = primary : CRITICAL merite le tampon
    "sev_high":       "#d97706",   # ambre profond
    "sev_medium":     "#b8860b",   # or mat
    "sev_low":        "#2b9a66",   # vert succes
    "sev_info":       "#575757",   # charcoal
}


# ─────────────────────────────────────────────────────────────
#  CSS GLOBAL — injecte le look complet dans Streamlit
# ─────────────────────────────────────────────────────────────
def _css() -> str:
    t = TOKENS
    return f"""
<style>
/* ---- Polices (substituts open-source des familles proprietaires) ----
   rb-freigeist-neue  -> Bricolage Grotesque (display massif)
   basier-square      -> Geist / Inter        (UI + corps)
   jetbrains-mono     -> JetBrains Mono        (IOC, IP, hashs, logs)      */
@import url('https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,400..800&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

:root {{
  --primary: {t['primary']};
  --primary-deep: {t['primary_deep']};
  --canvas: {t['canvas']};
  --bone: {t['surface_bone']};
  --card: {t['surface_card']};
  --dark: {t['surface_dark']};
  --deep: {t['surface_deep']};
  --ink: {t['ink']};
  --body: {t['body']};
  --charcoal: {t['charcoal']};
  --mute: {t['mute']};
  --on-dark: {t['on_dark']};
  --hairline: {t['hairline']};
  --hairline-strong: {t['hairline_strong']};
}}

/* ---- Canvas creme : JAMAIS de blanc pur au niveau page ---- */
.stApp {{
  background: {t['canvas']};
  color: {t['ink']};
}}
.main .block-container {{
  max-width: 1280px;
  padding-top: 2.2rem;
  padding-bottom: 4rem;
}}

/* ---- Typographie : familles strictes, 3 roles ---- */
html, body, [class*="css"], .stMarkdown, p, span, div, label, .stMetricLabel {{
  font-family: 'Inter', system-ui, sans-serif;
  color: {t['ink']};
  letter-spacing: 0;
}}
h1, h2, h3, h4, .display {{
  font-family: 'Bricolage Grotesque', 'Inter', sans-serif !important;
  color: {t['ink']} !important;
  line-height: 1.0 !important;
  letter-spacing: -1px !important;
  font-weight: 700 !important;
}}
h1 {{ font-size: 3.4rem !important; letter-spacing: -1.8px !important; margin-bottom: .2rem !important; }}
h2 {{ font-size: 2.1rem !important; letter-spacing: -1px !important; }}
h3 {{ font-size: 1.4rem !important; letter-spacing: -.5px !important; line-height: 1.2 !important; }}
code, kbd, pre, .mono {{
  font-family: 'JetBrains Mono', monospace !important;
}}

/* ---- Barre laterale : demi-ton creme (bone) + hairline ---- */
section[data-testid="stSidebar"] {{
  background: {t['surface_bone']};
  border-right: 1px solid {t['hairline']};
}}
section[data-testid="stSidebar"] * {{ color: {t['ink']}; }}
section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3 {{ letter-spacing:-.5px !important; }}

/* ---- Metriques Streamlit : gros chiffres editoriaux ---- */
[data-testid="stMetric"] {{
  background: {t['surface_card']};
  border: 1px solid {t['hairline']};
  border-radius: 10px;
  padding: 18px 20px;
}}
[data-testid="stMetricValue"] {{
  font-family: 'Bricolage Grotesque', sans-serif !important;
  font-size: 2.6rem !important;
  font-weight: 700 !important;
  letter-spacing: -1.5px !important;
  line-height: 1.0 !important;
  color: {t['ink']} !important;
}}
[data-testid="stMetricLabel"] {{
  font-family: 'Inter', sans-serif !important;
  font-size: .8rem !important;
  text-transform: uppercase;
  letter-spacing: .06em !important;
  color: {t['charcoal']} !important;
}}
[data-testid="stMetricDelta"] {{ font-size: .85rem !important; }}

/* ---- Boutons : entierement arrondis (pill), orange = action primaire ---- */
.stButton > button {{
  font-family: 'Inter', sans-serif;
  font-weight: 600;
  border-radius: 9999px;
  border: 1px solid {t['hairline_strong']};
  background: {t['surface_card']};
  color: {t['ink']};
  padding: 10px 22px;
  transition: transform .04s ease, background .15s ease;
}}
.stButton > button:hover {{ background: {t['surface_bone']}; }}
.stButton > button:active {{ transform: translateY(1px); }}
.stButton > button[kind="primary"] {{
  background: {t['primary']};
  border-color: {t['primary']};
  color: #fff;
}}
.stButton > button[kind="primary"]:hover {{ background: {t['primary_deep']}; border-color: {t['primary_deep']}; }}

/* ---- Champs (inputs) : pill creme + focus ---- */
.stTextInput input, .stSelectbox div[data-baseweb="select"] > div,
.stDateInput input, .stNumberInput input, .stMultiSelect div[data-baseweb="select"] > div {{
  border-radius: 9999px !important;
  border: 1px solid {t['hairline']} !important;
  background: {t['surface_card']} !important;
  color: {t['ink']} !important;
}}
.stTextInput input:focus {{
  border-color: {t['hairline_strong']} !important;
  box-shadow: 0 0 0 3px rgba(234,40,4,0.15) !important;
}}

/* ---- Onglets : underline orange sur l'actif ---- */
.stTabs [data-baseweb="tab-list"] {{ gap: 4px; border-bottom: 1px solid {t['hairline']}; }}
.stTabs [data-baseweb="tab"] {{
  font-family: 'Inter', sans-serif; font-weight: 600;
  color: {t['mute']}; background: transparent;
}}
.stTabs [aria-selected="true"] {{
  color: {t['ink']} !important;
  border-bottom: 2px solid {t['primary']} !important;
}}

/* ---- Tableaux / dataframes : hairline, pas d'ombre ---- */
[data-testid="stDataFrame"], [data-testid="stTable"] {{
  border: 1px solid {t['hairline']};
  border-radius: 10px;
  overflow: hidden;
}}

/* ---- Expander : carte bone ---- */
.streamlit-expanderHeader, [data-testid="stExpander"] {{
  background: {t['surface_bone']};
  border: 1px solid {t['hairline']};
  border-radius: 10px;
}}

/* ---- Alertes Streamlit : bord gauche colore, fond creme ---- */
.stAlert {{ border-radius: 10px; border: 1px solid {t['hairline']}; }}

/* ---- Barre superieure Streamlit transparente ---- */
header[data-testid="stHeader"] {{ background: transparent; }}
#MainMenu, footer {{ visibility: hidden; }}

/* ---- Scrollbar discrete ---- */
::-webkit-scrollbar {{ width: 10px; height: 10px; }}
::-webkit-scrollbar-thumb {{ background: #bbbbbb; border-radius: 9999px; }}
::-webkit-scrollbar-track {{ background: transparent; }}
</style>
"""


def inject_theme() -> None:
    """Injecte tout le theme Replicate-cyber. A appeler apres set_page_config."""
    st.markdown(_css(), unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
#  COMPOSANTS SIGNATURE (optionnels, tres visuels)
# ─────────────────────────────────────────────────────────────
def app_header(title: str = "ThreatHunter",
               subtitle: str = "Plateforme de Threat Hunting reseau",
               kicker: str = "SOC · Keystone Group") -> None:
    """En-tete editorial : eyebrow + titre massif + sous-titre + filet."""
    t = TOKENS
    st.markdown(f"""
    <div style="margin:.2rem 0 1.6rem 0;">
      <div style="font-family:'Inter';font-size:.8rem;font-weight:600;
                  text-transform:uppercase;letter-spacing:.14em;color:{t['primary']};">
        {kicker}
      </div>
      <div style="font-family:'Bricolage Grotesque';font-weight:800;
                  font-size:4.2rem;line-height:.95;letter-spacing:-2.4px;
                  color:{t['ink']};margin-top:.35rem;">{title}</div>
      <div style="font-family:'Inter';font-size:1.05rem;color:{t['charcoal']};
                  margin-top:.5rem;max-width:60ch;">{subtitle}</div>
      <div style="height:1px;background:{t['hairline']};margin-top:1.3rem;"></div>
    </div>
    """, unsafe_allow_html=True)


def severity_badge(severity: str) -> str:
    """Retourne le HTML d'un badge de severite (pill). CRITICAL = orange tampon."""
    t = TOKENS
    s = (severity or "").upper()
    color = {
        "CRITICAL": t["sev_critical"], "HIGH": t["sev_high"],
        "MEDIUM": t["sev_medium"], "LOW": t["sev_low"], "INFO": t["sev_info"],
    }.get(s, t["charcoal"])
    on = "#fff"
    return (f"<span style=\"font-family:'Inter';font-size:.72rem;font-weight:600;"
            f"text-transform:uppercase;letter-spacing:.04em;background:{color};"
            f"color:{on};border-radius:9999px;padding:3px 11px;\">{s}</span>")


def kpi_card(label: str, value, delta: str | None = None,
             accent: bool = False) -> None:
    """Carte KPI editoriale : grand chiffre Bricolage + label capitales.
    accent=True passe la carte en inversion sombre (pour le chiffre le plus fort)."""
    t = TOKENS
    if accent:
        bg, fg, lab, sub = t["surface_dark"], t["on_dark"], t["on_dark_mute"], t["hero_glow"]
    else:
        bg, fg, lab, sub = t["surface_card"], t["ink"], t["charcoal"], t["primary"]
    delta_html = (f"<div style=\"font-family:'JetBrains Mono';font-size:.8rem;"
                  f"color:{sub};margin-top:.4rem;\">{delta}</div>") if delta else ""
    st.markdown(f"""
    <div style="background:{bg};border:1px solid {t['hairline']};border-radius:10px;
                padding:20px 22px;height:100%;">
      <div style="font-family:'Inter';font-size:.75rem;font-weight:600;
                  text-transform:uppercase;letter-spacing:.08em;color:{lab};">{label}</div>
      <div style="font-family:'Bricolage Grotesque';font-weight:800;font-size:3rem;
                  line-height:1.0;letter-spacing:-1.8px;color:{fg};margin-top:.35rem;">{value}</div>
      {delta_html}
    </div>
    """, unsafe_allow_html=True)


def code_well(content: str, label: str | None = None) -> None:
    """Well sombre facon 'pull-quote imprime' pour IOC, IP, hashs, logs Zeek."""
    t = TOKENS
    lab = (f"<div style=\"font-family:'JetBrains Mono';font-size:.7rem;"
           f"color:{t['on_dark_mute']};text-transform:uppercase;letter-spacing:.1em;"
           f"margin-bottom:.6rem;\">{label}</div>") if label else ""
    st.markdown(f"""
    <div style="background:{t['surface_dark']};border-radius:10px;padding:20px 22px;">
      {lab}
      <pre style="font-family:'JetBrains Mono';font-size:.82rem;color:{t['on_dark']};
                  margin:0;white-space:pre-wrap;word-break:break-word;">{content}</pre>
    </div>
    """, unsafe_allow_html=True)


def section_header(title: str, eyebrow: str | None = None) -> None:
    """Titre de section editorial avec eyebrow optionnel et filet."""
    t = TOKENS
    eb = (f"<div style=\"font-family:'Inter';font-size:.75rem;font-weight:600;"
          f"text-transform:uppercase;letter-spacing:.12em;color:{t['primary']};"
          f"margin-bottom:.25rem;\">{eyebrow}</div>") if eyebrow else ""
    st.markdown(f"""
    <div style="margin:2.2rem 0 1rem 0;">
      {eb}
      <div style="font-family:'Bricolage Grotesque';font-weight:700;font-size:1.9rem;
                  letter-spacing:-1px;line-height:1.0;color:{t['ink']};">{title}</div>
      <div style="height:1px;background:{t['hairline']};margin-top:.9rem;"></div>
    </div>
    """, unsafe_allow_html=True)


# Palette Plotly assortie (a passer a tes graphiques pour la coherence)
PLOTLY_COLORWAY = [
    TOKENS["primary"], TOKENS["surface_dark"], TOKENS["sev_high"],
    TOKENS["sev_low"], TOKENS["charcoal"], TOKENS["hero_pink"],
]

def plotly_layout() -> dict:
    """Layout Plotly assorti au theme (fond transparent, police Inter, filets discrets)."""
    t = TOKENS
    return dict(
        colorway=PLOTLY_COLORWAY,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color=t["ink"], size=13),
        title_font=dict(family="Bricolage Grotesque, sans-serif", size=18),
        xaxis=dict(gridcolor=t["hairline"], zerolinecolor=t["hairline"]),
        yaxis=dict(gridcolor=t["hairline"], zerolinecolor=t["hairline"]),
        margin=dict(l=10, r=10, t=40, b=10),
    )
