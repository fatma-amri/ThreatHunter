"""
Theme ThreatHunter — "SOC evidence board / terminal console" (Keystone Group).

Pas un site vitrine : un poste operateur. Canvas quasi-noir, rouge/noir
Keystone comme couleur STRUCTURELLE (nav, en-tetes, tampon CRITICAL, CTA) —
pas une simple pointe de couleur reservee. Wells noir pur type "log brut"
pour IP/hashs/IOC/Zeek. Coins en "equerres de visee" sur les cartes cles,
tampon encreur pivote pour CRITICAL, curseur clignotant dans l'entete,
diviseurs en degrade rouge->transparent façon signal.

UTILISATION (une seule ligne dans ton dashboard) :

    from dashboard.pages.theme import inject_theme
    inject_theme()   # a appeler juste apres st.set_page_config(...)

Puis, pour les composants signature (optionnel) :

    from dashboard.pages.theme import (
        kpi_card, severity_badge, critical_stamp, mono_chip,
        code_well, section_header, perforated_divider, plotly_layout,
    )

Aucune dependance autre que streamlit. Ne touche pas a ta logique de donnees.
"""
from __future__ import annotations
import html
import streamlit as st


# ─────────────────────────────────────────────────────────────
#  JETONS DE DESIGN — rouge/noir Keystone, poste operateur SOC
# ─────────────────────────────────────────────────────────────
TOKENS = {
    # Marque / accent — le rouge Keystone est STRUCTUREL : nav, entetes,
    # CTA, CRITICAL. Pas un tampon rare, une signature qui revient.
    "primary":        "#ff2b3c",
    "primary_deep":   "#a4111f",
    "primary_glow":   "rgba(255,43,60,0.45)",
    "stamp_tint":     "rgba(255,43,60,0.14)",
    "hero_glow":      "#ff6a5c",
    "hero_pink":      "#7ea6ff",   # bleu froid technique, pour varier les series de graphes
    # Surfaces quasi-noires, jamais de blanc
    "canvas":         "#0a0a0d",
    "surface_bone":   "#1c1c21",   # panneaux releves (sidebar, en-tete de table)
    "surface_card":   "#141417",   # cartes / KPI
    "surface_dark":   "#000000",   # well le plus profond (IOC/log brut)
    "surface_deep":   "#000000",
    # Texte
    "ink":            "#f2f1ec",
    "body":           "#c9c8c2",
    "charcoal":       "#98979f",
    "mute":           "#7d7d86",
    "ash":            "#5c5b63",
    "on_dark":        "#f2f1ec",
    "on_dark_mute":   "rgba(242,241,236,0.72)",
    # Lignes
    "hairline":       "rgba(255,255,255,0.10)",
    "hairline_strong":"rgba(255,255,255,0.26)",
    "divider_dark":   "rgba(255,255,255,0.20)",
    "grid_dot":       "rgba(255,255,255,0.035)",
    # Semantique cyber (severite)
    "sev_critical":   "#ff2b3c",   # = primary
    "sev_high":       "#ffb020",
    "sev_medium":     "#d1a300",
    "sev_low":        "#23d18b",
    "sev_info":       "#7d7d86",
}


# ─────────────────────────────────────────────────────────────
#  CSS GLOBAL — injecte le look complet dans Streamlit
# ─────────────────────────────────────────────────────────────
def _css() -> str:
    t = TOKENS
    return f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,400..800&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

:root {{
  --primary: {t['primary']};
  --primary-deep: {t['primary_deep']};
  --primary-glow: {t['primary_glow']};
  --canvas: {t['canvas']};
  --bone: {t['surface_bone']};
  --card: {t['surface_card']};
  --dark: {t['surface_dark']};
  --ink: {t['ink']};
  --charcoal: {t['charcoal']};
  --mute: {t['mute']};
  --hairline: {t['hairline']};
  --hairline-strong: {t['hairline_strong']};
}}

@keyframes th-blink {{ 0%, 49% {{ opacity: 1; }} 50%, 100% {{ opacity: 0; }} }}
@keyframes th-pulse {{
  0%, 100% {{ box-shadow: 0 0 0 0 rgba(255,43,60,.55); }}
  50%      {{ box-shadow: 0 0 16px 3px rgba(255,43,60,.4); }}
}}

/* ---- Canvas quasi-noir : grille technique fine + vignette rouge tres subtile ----
   Une vraie grille (papier millimetre) plutot qu'une trame de points :
   plus "poste operateur / plan technique" qu'un fond decoratif. ---- */
.stApp {{
  background-color: {t['canvas']};
  background-image:
    repeating-linear-gradient(0deg, rgba(255,255,255,0.018) 0px, rgba(255,255,255,0.018) 1px, transparent 1px, transparent 3px),
    linear-gradient(rgba(255,255,255,0.028) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,0.028) 1px, transparent 1px),
    radial-gradient(ellipse at 15% 0%, rgba(255,43,60,0.055), transparent 55%);
  background-size: auto, 42px 42px, 42px 42px, auto;
  color: {t['ink']};
}}
.main .block-container {{
  max-width: 1320px;
  padding-top: 1.4rem;
  padding-bottom: 3rem;
}}

/* ---- Typographie : dense, enterprise — pas de titres XXL ---- */
html, body, [class*="css"], .stMarkdown, p, span, div, label, .stMetricLabel {{
  font-family: 'Inter', system-ui, sans-serif;
  color: {t['ink']};
  letter-spacing: 0;
}}
h1, h2, h3, h4, .display {{
  font-family: 'Bricolage Grotesque', 'Inter', sans-serif !important;
  color: {t['ink']} !important;
  line-height: 1.15 !important;
  letter-spacing: -.5px !important;
  font-weight: 700 !important;
}}
h1 {{ font-size: 1.9rem !important; letter-spacing: -.7px !important; margin-bottom: .2rem !important; }}
h2 {{ font-size: 1.4rem !important; letter-spacing: -.4px !important; }}
h3 {{ font-size: 1.05rem !important; letter-spacing: -.2px !important; line-height: 1.3 !important; }}
code, kbd, pre, .mono {{
  font-family: 'JetBrains Mono', monospace !important;
}}
a, a:visited {{ color: {t['primary']} !important; }}

/* ---- Barre laterale : panneau releve noir, rouge = navigation active ---- */
section[data-testid="stSidebar"] {{
  background: {t['surface_bone']};
  border-right: 1px solid {t['hairline']};
}}
section[data-testid="stSidebar"] * {{ color: {t['ink']}; }}
section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3 {{ letter-spacing:-.5px !important; }}

/* ---- Bloc logo + marque en tete de sidebar ---- */
.th-brand-row {{
  display: flex; align-items: center; gap: 10px; margin-bottom: .3rem;
}}
.th-logo-chip {{
  display: flex; align-items: center; justify-content: center;
  width: 34px; height: 34px; border-radius: 7px; flex-shrink: 0;
  background: {t['ink']};
  box-shadow: 0 0 0 1px {t['hairline']};
}}
.th-logo-chip img {{ width: 24px; height: 24px; display: block; }}
.th-status-dot {{
  display: inline-block; width: 6px; height: 6px; border-radius: 50%;
  background: {t['sev_low']}; margin-right: 6px; flex-shrink: 0;
}}

/* ---- Navigation laterale : boutons a icones (Material), pas d'emoji ----
   Chaque bouton nav vit dans le conteneur cle .st-key-main_nav : on
   reecrit son apparence (transparent, filet gauche) et on reserve le
   rouge plein a l'entree active (type="primary" pilote depuis Python). */
.st-key-main_nav {{ gap: 1px !important; }}
.st-key-main_nav .stButton > button {{
  font-family: 'Inter', sans-serif !important;
  font-weight: 500;
  font-size: .86rem;
  text-transform: none;
  letter-spacing: 0;
  justify-content: flex-start;
  gap: 10px;
  background: transparent;
  border: none;
  border-left: 3px solid transparent;
  border-radius: 4px !important;
  padding: 7px 10px !important;
  color: {t['charcoal']};
  transition: background .12s ease, border-color .12s ease, color .12s ease;
}}
.st-key-main_nav .stButton > button:hover {{
  background: rgba(255,255,255,0.045);
  color: {t['ink']};
  border-color: transparent;
}}
.st-key-main_nav .stButton > button[kind="primary"] {{
  background: rgba(255,43,60,0.10) !important;
  border-left-color: {t['primary']} !important;
  color: {t['ink']} !important;
  font-weight: 700;
}}
.st-key-main_nav .stButton > button[kind="primary"]:hover {{
  background: rgba(255,43,60,0.15) !important;
}}
.st-key-main_nav .stButton > button span[data-testid="stIconMaterial"] {{
  font-size: 1.05rem;
  color: inherit;
}}

/* ---- Panneau de filtres : dense, groupe, premium ----------------------- */

/* Resserre l'empilement vertical natif de la sidebar */
section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] {{
  gap: .4rem;
}}
section[data-testid="stSidebar"] label {{
  font-size: .78rem !important;
  color: {t['charcoal']} !important;
  margin-bottom: .1rem !important;
}}
section[data-testid="stSidebar"] [data-testid="stCaptionContainer"] {{
  margin-top: -.25rem;
}}
section[data-testid="stSidebar"] .stTextInput input,
section[data-testid="stSidebar"] .stSelectbox div[data-baseweb="select"] > div,
section[data-testid="stSidebar"] .stDateInput input {{
  padding-top: 6px !important;
  padding-bottom: 6px !important;
  font-size: .82rem !important;
}}

/* Eyebrow "FILTER PANEL" au-dessus des sections repliables */
.th-filter-eyebrow {{
  font-family: 'JetBrains Mono', monospace;
  font-size: .7rem; font-weight: 600; text-transform: uppercase;
  letter-spacing: .14em; color: {t['mute']}; margin: .6rem 0 .3rem 0;
}}

/* Sections repliables (st.expander) : cartes sombres compactes */
section[data-testid="stSidebar"] [data-testid="stExpander"] {{
  background: {t['surface_card']};
  border: 1px solid {t['hairline']};
  border-radius: 8px;
  margin-bottom: .45rem;
}}
section[data-testid="stSidebar"] [data-testid="stExpander"] summary {{
  padding: 8px 12px !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: .72rem !important;
  font-weight: 700 !important;
  text-transform: uppercase;
  letter-spacing: .07em;
  color: {t['charcoal']} !important;
  min-height: 0 !important;
}}
section[data-testid="stSidebar"] [data-testid="stExpander"] summary:hover {{
  color: {t['ink']} !important;
}}
section[data-testid="stSidebar"] [data-testid="stExpander"] [data-testid="stExpanderDetails"] {{
  padding: 2px 12px 10px 12px !important;
}}

/* Barre de recherche libre : toujours visible, en tete du panneau */
.st-key-quick_search .stTextInput input {{
  border-radius: 9999px !important;
  font-family: 'JetBrains Mono', monospace !important;
}}

/* Pastilles de severite : 4 checkboxes cote a cote, chacune sa couleur.
   Scope via st.container(key="sev_pills") -> .st-key-sev_pills EST le
   stVerticalBlock lui-meme (confirme par inspection du DOM reel) ; on
   force le passage en ligne malgre le flex-column natif de Streamlit.
   Chaque checkbox a un key= propre -> Streamlit lui donne deja une classe
   st-key-<key> UNIQUE sur son .element-container : on cible ces classes
   directement, plus fiable qu'un nth-of-type (chaque case est enveloppee
   dans son propre .element-container, ce qui casse le comptage de freres). */
.st-key-sev_pills {{
  display: flex !important;
  flex-direction: row !important;
  gap: 5px !important;
  flex-wrap: nowrap !important;
}}
.st-key-sev_pills [data-testid="stElementContainer"] {{
  flex: 1 1 0 !important;
  min-width: 0 !important;
  width: auto !important;
}}
.st-key-sev_pills [data-testid="stCheckbox"] label {{
  display: flex; align-items: center; justify-content: center;
  border-radius: 9999px; border: 1px solid {t['hairline']};
  padding: 5px 0; margin: 0; width: 100%;
  background: {t['canvas']};
  font-family: 'JetBrains Mono', monospace; font-size: .66rem; font-weight: 700;
  letter-spacing: .02em; text-transform: uppercase; color: {t['mute']};
  cursor: pointer; transition: background .12s ease, border-color .12s ease, color .12s ease;
}}
/* icone de coche : c'est le 1er <div> parmi les enfants du label (le tout
   premier enfant est un <span> d'input masque pour l'accessibilite) */
.st-key-sev_pills [data-testid="stCheckbox"] label > div:nth-of-type(1) {{
  display: none;
}}
.st-key-f_sev_critical [data-testid="stCheckbox"] label:has(input:checked) {{
  background: rgba(255,43,60,.16); border-color: {t['sev_critical']}; color: {t['sev_critical']};
}}
.st-key-f_sev_high [data-testid="stCheckbox"] label:has(input:checked) {{
  background: rgba(255,176,32,.16); border-color: {t['sev_high']}; color: {t['sev_high']};
}}
.st-key-f_sev_medium [data-testid="stCheckbox"] label:has(input:checked) {{
  background: rgba(209,163,0,.16); border-color: {t['sev_medium']}; color: {t['sev_medium']};
}}
.st-key-f_sev_low [data-testid="stCheckbox"] label:has(input:checked) {{
  background: rgba(35,209,139,.16); border-color: {t['sev_low']}; color: {t['sev_low']};
}}

/* ---- Metriques Streamlit natives ---- */
[data-testid="stMetric"] {{
  background: {t['surface_card']};
  border: 1px solid {t['hairline']};
  border-radius: 8px;
  padding: 18px 20px;
}}
[data-testid="stMetricValue"] {{
  font-family: 'Bricolage Grotesque', sans-serif !important;
  font-size: 1.8rem !important;
  font-weight: 700 !important;
  letter-spacing: -.8px !important;
  line-height: 1.0 !important;
  color: {t['ink']} !important;
}}
[data-testid="stMetricLabel"] {{
  font-family: 'JetBrains Mono', monospace !important;
  font-size: .74rem !important;
  text-transform: uppercase;
  letter-spacing: .1em !important;
  color: {t['charcoal']} !important;
}}
[data-testid="stMetricDelta"] {{ font-size: .85rem !important; }}

/* ---- Boutons : console technique, pas des pilules commerce ---- */
.stButton > button {{
  font-family: 'JetBrains Mono', monospace;
  font-weight: 600;
  font-size: .85rem;
  text-transform: uppercase;
  letter-spacing: .06em;
  border-radius: 6px;
  border: 1px solid {t['hairline_strong']};
  background: {t['surface_card']};
  color: {t['ink']};
  padding: 10px 20px;
  transition: transform .04s ease, background .15s ease, border-color .15s ease;
}}
.stButton > button:hover {{ background: {t['surface_bone']}; border-color: {t['primary']}; }}
.stButton > button:active {{ transform: translateY(1px); }}
.stButton > button[kind="primary"] {{
  background: {t['primary']};
  border-color: {t['primary']};
  color: #0a0a0d;
  font-weight: 700;
}}
.stButton > button[kind="primary"]:hover {{ background: {t['primary_deep']}; border-color: {t['primary_deep']}; color: {t['ink']}; }}

.stDownloadButton > button {{
  font-family: 'JetBrains Mono', monospace;
  font-weight: 600;
  font-size: .85rem;
  text-transform: uppercase;
  letter-spacing: .06em;
  border-radius: 6px;
  border: 1px solid {t['hairline_strong']};
  background: {t['surface_card']};
  color: {t['ink']};
}}
.stDownloadButton > button:hover {{ border-color: {t['primary']}; }}

/* ---- Champs (inputs) : console de requete, monospace ---- */
.stTextInput input, .stSelectbox div[data-baseweb="select"] > div,
.stDateInput input, .stNumberInput input, .stMultiSelect div[data-baseweb="select"] > div {{
  font-family: 'JetBrains Mono', monospace !important;
  border-radius: 6px !important;
  border: 1px solid {t['hairline']} !important;
  background: {t['surface_card']} !important;
  color: {t['ink']} !important;
}}
.stTextInput input:focus {{
  border-color: {t['primary']} !important;
  box-shadow: 0 0 0 3px rgba(255,43,60,0.18) !important;
}}

/* ---- Onglets ---- */
.stTabs [data-baseweb="tab-list"] {{ gap: 4px; border-bottom: 1px solid {t['hairline']}; }}
.stTabs [data-baseweb="tab"] {{
  font-family: 'JetBrains Mono', monospace; font-weight: 600;
  color: {t['mute']}; background: transparent;
}}
.stTabs [aria-selected="true"] {{
  color: {t['ink']} !important;
  border-bottom: 2px solid {t['primary']} !important;
}}

/* ---- Tableaux / dataframes ---- */
[data-testid="stDataFrame"], [data-testid="stTable"] {{
  border: 1px solid {t['hairline']};
  border-radius: 8px;
  overflow: hidden;
}}
[data-testid="stDataFrame"] * {{ font-family: 'JetBrains Mono', 'Inter', monospace; }}

/* ---- Expander ---- */
.streamlit-expanderHeader, [data-testid="stExpander"] {{
  background: {t['surface_bone']};
  border: 1px solid {t['hairline']};
  border-radius: 8px;
}}

/* ---- Alertes Streamlit ---- */
.stAlert {{ border-radius: 8px; border: 1px solid {t['hairline']}; }}

/* ---- Barre superieure transparente ---- */
header[data-testid="stHeader"] {{ background: transparent; }}
#MainMenu, footer {{ visibility: hidden; }}

/* ---- Scrollbar ---- */
::-webkit-scrollbar {{ width: 10px; height: 10px; }}
::-webkit-scrollbar-thumb {{ background: {t['surface_bone']}; border-radius: 9999px; }}
::-webkit-scrollbar-track {{ background: transparent; }}

/* ---- Curseur clignotant façon terminal (en-tete) ---- */
.th-cursor {{
  display: inline-block; width: .5ch; margin-left: 2px;
  background: {t['primary']}; animation: th-blink 1.1s steps(1) infinite;
}}

/* ---- Equerres de visee : coins type reticule sur les elements cles ---- */
.th-bracket {{ position: relative; }}
.th-bracket::before, .th-bracket::after {{
  content: ""; position: absolute; width: 16px; height: 16px;
  border-color: {t['primary']}; border-style: solid; opacity: .9; pointer-events: none;
}}
.th-bracket::before {{ top: -6px; left: -6px; border-width: 2px 0 0 2px; }}
.th-bracket::after  {{ bottom: -6px; right: -6px; border-width: 0 2px 2px 0; }}

/* ---- Variante equerres inset : pour une cellule a l'interieur d'un
   bandeau contigu (kpi_strip), ou depasser vers l'exterieur chevaucherait
   la cellule voisine ---- */
.th-bracket-inset {{ position: relative; }}
.th-bracket-inset::before, .th-bracket-inset::after {{
  content: ""; position: absolute; width: 14px; height: 14px;
  border-color: {t['primary']}; border-style: solid; opacity: .85; pointer-events: none;
}}
.th-bracket-inset::before {{ top: 10px; left: 10px; border-width: 2px 0 0 2px; }}
.th-bracket-inset::after  {{ bottom: 10px; right: 10px; border-width: 0 2px 2px 0; }}

/* ---- Point d'alerte pulsant ---- */
.th-live-dot {{
  display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  background: {t['primary']}; margin-right: 7px; animation: th-pulse 1.7s ease-in-out infinite;
}}

/* ---- Tampon CRITICAL : cachet encreur pivote ---- */
.th-stamp {{
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-family: 'JetBrains Mono', monospace;
  font-weight: 700;
  font-size: .78rem;
  text-transform: uppercase;
  letter-spacing: .12em;
  color: {t['primary']};
  background: {t['stamp_tint']};
  border: 2px solid {t['primary']};
  border-radius: 4px;
  padding: 5px 14px;
  transform: rotate(-3deg);
}}

/* ---- Badge de severite : tag log-level entre crochets ---- */
.th-sev-tag {{
  font-family: 'JetBrains Mono', monospace;
  font-size: .74rem;
  font-weight: 700;
  letter-spacing: .04em;
  border-radius: 4px;
  padding: 3px 9px;
  display: inline-block;
}}
.th-sev-critical {{ animation: th-pulse 1.7s ease-in-out infinite; }}

/* ---- Puce mono pour IP/hash/MITRE en ligne ---- */
.th-mono-chip {{
  font-family: 'JetBrains Mono', monospace;
  font-size: .78rem;
  background: {t['surface_bone']};
  border: 1px solid {t['hairline']};
  border-radius: 4px;
  padding: 2px 8px;
  color: {t['ink']};
  display: inline-block;
}}
</style>
"""


def inject_theme() -> None:
    """Injecte tout le theme SOC evidence-board. A appeler apres set_page_config."""
    st.markdown(_css(), unsafe_allow_html=True)


def _emit(html_block: str) -> None:
    """Rend un bloc HTML via st.markdown(unsafe_allow_html=True), en retirant
    les lignes vides internes. Sans ca, une ligne blanche au milieu d'un
    template multi-lignes (typiquement un placeholder optionnel du genre
    {label} qui se resout en chaine vide) fait sortir CommonMark du mode
    'bloc HTML brut' — le reste du bloc est alors traite comme du Markdown
    normal et, vu son indentation, rendu tel quel comme texte litteral au
    lieu d'etre interprete comme du HTML."""
    st.markdown("\n".join(line for line in html_block.splitlines() if line.strip()),
                unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
#  COMPOSANTS SIGNATURE
# ─────────────────────────────────────────────────────────────
def app_header(title: str = "ThreatHunter",
               subtitle: str = "Plateforme de Threat Hunting reseau",
               kicker: str = "SOC · Keystone Group",
               logo_data_uri: str | None = None) -> None:
    """En-tete console, compact (pas de titre XXL) : logo optionnel + eyebrow
    prompt + titre + curseur clignotant + filet degrade fin."""
    t = TOKENS
    logo_html = (f'<div class="th-logo-chip" style="width:38px;height:38px;flex-shrink:0;">'
                 f'<img src="{logo_data_uri}" style="width:26px;height:26px;"></div>'
                 ) if logo_data_uri else ""
    _emit(f"""
    <div style="margin:.1rem 0 1.1rem 0;">
      <div style="display:flex;align-items:center;gap:12px;">
        {logo_html}
        <div>
          <div style="font-family:'JetBrains Mono';font-size:.7rem;font-weight:600;
                      text-transform:uppercase;letter-spacing:.14em;color:{t['primary']};">
            &gt; {kicker}
          </div>
          <div style="font-family:'Bricolage Grotesque';font-weight:800;
                      font-size:1.85rem;line-height:1.1;letter-spacing:-.7px;
                      color:{t['ink']};">{title}<span class="th-cursor">&nbsp;</span></div>
        </div>
      </div>
      <div style="font-family:'Inter';font-size:.9rem;color:{t['charcoal']};
                  margin-top:.5rem;max-width:70ch;">{subtitle}</div>
      <div style="height:1px;margin-top:.9rem;
                  background:linear-gradient(90deg,{t['primary']},transparent 55%);"></div>
    </div>
    """)


def severity_badge(severity: str) -> str:
    """HTML d'un tag de severite façon log-level ([ CRITICAL ]). CRITICAL pulse en rouge plein."""
    t = TOKENS
    s = (severity or "").upper()
    color = {
        "CRITICAL": t["sev_critical"], "HIGH": t["sev_high"],
        "MEDIUM": t["sev_medium"], "LOW": t["sev_low"], "INFO": t["sev_info"],
    }.get(s, t["charcoal"])
    if s == "CRITICAL":
        return (f"<span class=\"th-sev-tag th-sev-critical\" style=\"background:{color};"
                f"color:#0a0a0d;border:1px solid {color};\">[ {s} ]</span>")
    return (f"<span class=\"th-sev-tag\" style=\"background:transparent;color:{color};"
            f"border:1px solid {color};\">[ {s} ]</span>")


def critical_stamp(text: str = "CRITICAL") -> str:
    """HTML d'un tampon encreur pivote — reserve a l'alerte la plus grave d'une vue."""
    return f"<span class=\"th-stamp\">&#9679; {html.escape(str(text))}</span>"


def mono_chip(text: str) -> str:
    """Puce JetBrains Mono discrete pour un IOC/IP/hash cite en ligne dans du texte.
    Contenu echappe : donnees issues du trafic reseau, potentiellement forgees."""
    return f"<span class=\"th-mono-chip\">{html.escape(str(text))}</span>"


def kpi_card(label: str, value, delta: str | None = None,
             accent: bool = False) -> None:
    """Carte KPI console. accent=True = LE chiffre le plus critique de la vue :
    lueur rouge, point pulsant, equerres de visee — reserve a UN SEUL par ecran."""
    t = TOKENS
    if accent:
        border = t["hairline_strong"]
        value_style = f"color:{t['primary']};text-shadow:0 0 18px {t['primary_glow']};"
        dot = "<span class=\"th-live-dot\"></span>"
        bracket_class = " th-bracket"
    else:
        border = t["hairline"]
        value_style = f"color:{t['ink']};"
        dot = ""
        bracket_class = ""
    delta_html = (f"<div style=\"font-family:'JetBrains Mono';font-size:.8rem;"
                  f"color:{t['charcoal']};margin-top:.4rem;\">{html.escape(str(delta))}</div>") if delta else ""
    _emit(f"""
    <div class="{bracket_class.strip()}" style="background:{t['surface_card']};border:1px solid {border};
                border-radius:6px;padding:14px 16px;height:100%;">
      <div style="font-family:'JetBrains Mono';font-size:.68rem;font-weight:600;
                  text-transform:uppercase;letter-spacing:.09em;color:{t['charcoal']};">{dot}{html.escape(str(label))}</div>
      <div style="font-family:'Bricolage Grotesque';font-weight:800;font-size:1.9rem;
                  line-height:1.1;letter-spacing:-1px;margin-top:.3rem;{value_style}">{value}</div>
      {delta_html}
    </div>
    """)


def kpi_strip(items: list[dict]) -> None:
    """Bandeau de stats unifie : UNE bordure, cellules egales separees par
    des filets internes — plutot que des cartes flottantes independantes,
    dont les hauteurs/largeurs divergent des que les labels different
    (repli sur 2 lignes, cellule elargie qui casse la grille). A utiliser
    des qu'on affiche plusieurs KPI cote a cote.

    items: liste de {"label": str, "value": ..., "delta": str optionnel,
    "accent": bool optionnel — reserve a UNE SEULE cellule du bandeau}."""
    t = TOKENS
    n = len(items)
    cells = []
    for i, item in enumerate(items):
        accent = item.get("accent", False)
        border_right = f"border-right:1px solid {t['hairline']};" if i < n - 1 else ""
        if accent:
            value_style = f"color:{t['primary']};text-shadow:0 0 18px {t['primary_glow']};"
            dot = "<span class=\"th-live-dot\"></span>"
            bg = f"background:{t['stamp_tint']};"
            bracket = "th-bracket-inset"
        else:
            value_style = f"color:{t['ink']};"
            dot = ""
            bg = ""
            bracket = ""
        delta_html = (f"<div style=\"font-family:'JetBrains Mono';font-size:.72rem;"
                      f"color:{t['charcoal']};margin-top:.3rem;white-space:nowrap;"
                      f"overflow:hidden;text-overflow:ellipsis;\">{html.escape(str(item['delta']))}</div>"
                      ) if item.get("delta") else ""
        cells.append(f"""
        <div class="{bracket}" style="flex:1;min-width:0;{border_right}{bg}padding:13px 16px;position:relative;">
          <div style="font-family:'JetBrains Mono';font-size:.66rem;font-weight:600;
                      text-transform:uppercase;letter-spacing:.07em;color:{t['charcoal']};
                      white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{dot}{html.escape(str(item['label']))}</div>
          <div style="font-family:'Bricolage Grotesque';font-weight:800;font-size:1.6rem;
                      line-height:1.2;letter-spacing:-.8px;margin-top:.25rem;{value_style}">{item['value']}</div>
          {delta_html}
        </div>
        """)
    _emit(
        f'<div style="display:flex;border:1px solid {t["hairline"]};border-radius:6px;'
        f'overflow:hidden;background:{t["surface_card"]};">' + "".join(cells) + "</div>")


def code_well(content: str, label: str | None = None) -> None:
    """Well noir pur façon 'log brut imprime' pour IOC, IP, hashs, logs Zeek —
    bandeau rouge en tete, comme une etiquette de piece a conviction.
    Contenu echappe avant injection HTML (donnees issues du trafic reseau,
    potentiellement forgees par l'attaquant qu'on analyse)."""
    t = TOKENS
    lab = (f"<div style=\"font-family:'JetBrains Mono';font-size:.7rem;"
           f"color:{t['primary']};text-transform:uppercase;letter-spacing:.12em;"
           f"margin-bottom:.6rem;\">{html.escape(str(label))}</div>") if label else ""
    safe_content = html.escape(str(content))
    _emit(f"""
    <div style="background:{t['surface_dark']};border-radius:6px;border-top:2px solid {t['primary']};
                padding:18px 22px;">
      {lab}
      <pre style="font-family:'JetBrains Mono';font-size:.82rem;color:{t['on_dark']};
                  margin:0;white-space:pre-wrap;word-break:break-word;">{safe_content}</pre>
    </div>
    """)


def section_header(title: str, eyebrow: str | None = None, accent: bool = False) -> None:
    """Titre de section : eyebrow façon prompt terminal (chevron rouge) + filet degrade."""
    t = TOKENS
    eb = (f"<div style=\"font-family:'JetBrains Mono';font-size:.75rem;font-weight:600;"
          f"text-transform:uppercase;letter-spacing:.1em;color:{t['charcoal']};"
          f"margin-bottom:.3rem;\"><span style=\"color:{t['primary']};\">&gt;</span> {html.escape(str(eyebrow))}</div>"
          ) if eyebrow else ""
    _emit(f"""
    <div style="margin:1.5rem 0 .8rem 0;">
      {eb}
      <div style="font-family:'Bricolage Grotesque';font-weight:700;font-size:1.3rem;
                  letter-spacing:-.4px;line-height:1.2;color:{t['ink']};">{html.escape(str(title))}</div>
      <div style="height:1px;margin-top:.6rem;
                  background:linear-gradient(90deg,{t['primary']},transparent 45%);"></div>
    </div>
    """)


def perforated_divider() -> None:
    """Filet pointille discret entre deux blocs d'une meme section."""
    t = TOKENS
    st.markdown(
        f"<div style=\"height:0;border-top:1px dashed {t['hairline']};margin:1.6rem 0;\"></div>",
        unsafe_allow_html=True)


def empty_state(message: str, hint: str | None = None) -> None:
    """Panneau 'aucun signal' — a utiliser à la place d'un st.info generique
    partout ou un graphique/tableau n'a rien a montrer (evite aussi les
    graphes Plotly casses sur des jeux de donnees entierement vides)."""
    t = TOKENS
    hint_html = (f"<div style=\"font-family:'Inter';font-size:.82rem;color:{t['ash']};"
                 f"margin-top:.4rem;\">{html.escape(str(hint))}</div>") if hint else ""
    _emit(f"""
    <div style="border:1px dashed {t['hairline_strong']};border-radius:8px;
                padding:26px 22px;text-align:center;background:rgba(255,255,255,0.015);">
      <div style="font-family:'JetBrains Mono';font-size:.78rem;font-weight:600;
                  text-transform:uppercase;letter-spacing:.14em;color:{t['mute']};">
        &#9711; NO SIGNAL — {html.escape(str(message))}
      </div>
      {hint_html}
    </div>
    """)


def status_row(label: str, online: bool = True, detail: str | None = None) -> None:
    """Ligne de statut de service — point fixe (vert=up, rouge=down), pas de pulse
    (le pulse est reserve aux alertes vivantes, pas au statut d'infra)."""
    t = TOKENS
    color = t["sev_low"] if online else t["primary"]
    detail_html = (f"<span style=\"color:{t['charcoal']};font-family:'JetBrains Mono';"
                   f"font-size:.78rem;margin-left:8px;\">{html.escape(str(detail))}</span>") if detail else ""
    _emit(f"""
    <div style="display:flex;align-items:center;padding:6px 0;">
      <span style="display:inline-block;width:8px;height:8px;border-radius:50%;
                   background:{color};margin-right:10px;flex-shrink:0;"></span>
      <span style="font-family:'Inter';font-size:.92rem;color:{t['ink']};">{html.escape(str(label))}</span>
      {detail_html}
    </div>
    """)


def ranked_list(items: list[tuple[str, int]], mono: bool = True, max_bar: int | None = None) -> None:
    """Liste classee compacte (Top MITRE, Top IOCs...) : rang, libelle, barre
    de proportion fine, valeur — plus dense qu'un graphique pour un TOP N."""
    t = TOKENS
    if not items:
        empty_state("aucune donnee")
        return
    peak = max(v for _, v in items) or 1
    rows = []
    font = "'JetBrains Mono', monospace" if mono else "'Inter', sans-serif"
    for i, (label, value) in enumerate(items):
        pct = max(6, round(100 * value / peak))
        rows.append(f"""
        <div style="display:flex;align-items:center;gap:10px;padding:5px 0;">
          <span style="font-family:'JetBrains Mono';font-size:.72rem;color:{t['ash']};width:1.4em;flex-shrink:0;">{i + 1:02d}</span>
          <span style="font-family:{font};font-size:.82rem;color:{t['ink']};flex-shrink:0;
                       max-width:40%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{html.escape(str(label))}</span>
          <span style="flex:1;height:5px;background:{t['surface_bone']};border-radius:3px;overflow:hidden;">
            <span style="display:block;height:100%;width:{pct}%;background:{t['primary']};border-radius:3px;"></span>
          </span>
          <span style="font-family:'JetBrains Mono';font-size:.76rem;color:{t['charcoal']};width:2.4em;text-align:right;flex-shrink:0;">{value}</span>
        </div>
        """)
    _emit("".join(rows))


def threat_level_banner(level: str, detail: str = "") -> None:
    """Bandeau pleine largeur façon panneau DEFCON — lit le niveau de menace
    d'un seul coup d'oeil. level in {"CRITICAL","ELEVATED","NOMINAL"}."""
    t = TOKENS
    cfg = {
        "CRITICAL": (t["primary"], "rgba(255,43,60,0.12)", True),
        "ELEVATED": (t["sev_high"], "rgba(255,176,32,0.10)", False),
        "NOMINAL":  (t["sev_low"], "rgba(35,209,139,0.08)", False),
    }.get(level, (t["mute"], "rgba(255,255,255,0.04)", False))
    color, bg, pulse = cfg
    dot_class = "th-live-dot" if pulse else ""
    dot_style = "" if pulse else f"background:{color};display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:10px;"
    _emit(f"""
    <div style="display:flex;align-items:center;justify-content:space-between;
                border:1px solid {color};background:{bg};border-radius:8px;
                padding:14px 20px;margin:1.2rem 0 .4rem 0;">
      <div style="display:flex;align-items:center;">
        <span class="{dot_class}" style="{dot_style}"></span>
        <span style="font-family:'JetBrains Mono';font-weight:700;font-size:.95rem;
                     letter-spacing:.08em;color:{color};">THREAT LEVEL: {html.escape(level)}</span>
      </div>
      <span style="font-family:'JetBrains Mono';font-size:.8rem;color:{t['charcoal']};">{html.escape(detail)}</span>
    </div>
    """)


# Palette Plotly assortie (fond transparent -> laisse voir le canvas noir)
PLOTLY_COLORWAY = [
    TOKENS["primary"], TOKENS["sev_high"], TOKENS["sev_low"],
    TOKENS["hero_pink"], TOKENS["sev_medium"], TOKENS["mute"],
    TOKENS["primary_deep"], TOKENS["on_dark"],
]

def plotly_layout() -> dict:
    """Layout Plotly assorti au theme sombre (fond transparent, filets clairs discrets,
    infobulles façon well noir cerne de rouge)."""
    t = TOKENS
    return dict(
        colorway=PLOTLY_COLORWAY,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color=t["ink"], size=13),
        title=dict(text="", font=dict(family="Bricolage Grotesque, sans-serif", size=18)),
        xaxis=dict(gridcolor=t["hairline"], zerolinecolor=t["hairline"]),
        yaxis=dict(gridcolor=t["hairline"], zerolinecolor=t["hairline"]),
        margin=dict(l=10, r=10, t=40, b=10),
        hoverlabel=dict(
            bgcolor=t["surface_dark"],
            bordercolor=t["primary"],
            font=dict(family="JetBrains Mono, monospace", color=t["on_dark"], size=12),
        ),
    )
