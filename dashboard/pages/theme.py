"""
Theme ThreatHunter — dark SOC moderne, sobre et lisible.

Direction :
  - Fond slate profond, surfaces legerement relevees, hairlines discretes,
    beaucoup d'air. Pas de "terminal hacker", pas de scanlines, pas de glow.
  - UNE couleur d'accent : rouge Keystone (#e01e2b), utilisee avec parcimonie
    (liens, focus, etat actif de nav, bouton primaire, 1 KPI critique).
  - Echelle semantique de severite : Critical (rouge) / High (orange) /
    Medium (jaune) / Low (vert).
  - Typographie : Inter pour toute l'UI (casse normale) ; JetBrains Mono
    UNIQUEMENT pour IP / hash / IOC / identifiants MITRE (helper mono_chip).
  - Style 100 % centralise : un seul inject_theme() = un seul bloc <style>
    pilote par des variables CSS. Aucun style disperse dans les pages.

UTILISATION :

    from dashboard.pages.theme import inject_theme
    inject_theme()   # juste apres st.set_page_config(...)

API publique conservee (memes noms/signatures, memes cles TOKENS).
"""
from __future__ import annotations
import html
import streamlit as st


# ─────────────────────────────────────────────────────────────
#  JETONS DE DESIGN — source de verite unique (aussi exposee en CSS vars)
# ─────────────────────────────────────────────────────────────
TOKENS = {
    # Accent unique — rouge Keystone, dose avec parcimonie
    "primary":         "#e01e2b",
    "primary_deep":    "#b3141f",
    "primary_soft":    "rgba(224,30,43,0.12)",
    "on_primary":      "#ffffff",
    "danger":          "#e01e2b",
    "danger_deep":     "#b3141f",
    "stamp_tint":      "rgba(224,30,43,0.12)",
    "link":            "#ff6b73",
    "ring_focus":      "rgba(224,30,43,0.40)",
    # compat (anciens alias encore reference ailleurs)
    "danger_glow":     "rgba(224,30,43,0.28)",
    "primary_bright":  "#ff4d59",
    "hero_glow":       "#ff6b73",
    "hero_pink":       "#f4a8a0",

    # Surfaces — slate profond -> releve
    "canvas":          "#0f1216",
    "surface_bone":    "#14181e",
    "surface_card":    "#161a20",
    "surface_raised":  "#1c222b",
    "surface_dark":    "#0b0e12",
    "surface_deep":    "#080a0d",

    # Texte
    "ink":             "#e6e9ef",
    "body":            "#c2c8d2",
    "charcoal":        "#9aa3b0",
    "mute":            "#7b8492",
    "ash":             "#5c6472",
    "stone":           "#3a414c",
    "on_dark":         "#eef1f6",
    "on_dark_mute":    "rgba(238,241,246,0.62)",

    # Lignes
    "hairline":        "rgba(255,255,255,0.08)",
    "hairline_strong": "rgba(255,255,255,0.16)",
    "divider_dark":    "rgba(255,255,255,0.10)",

    # Severite
    "sev_critical":    "#e01e2b",
    "sev_high":        "#f5872b",
    "sev_medium":      "#e8c341",
    "sev_low":         "#3ecf8e",
    "sev_info":        "#7b8492",
    "badge_success":   "#3ecf8e",
}


# ─────────────────────────────────────────────────────────────
#  CSS GLOBAL — un seul bloc, pilote par variables
# ─────────────────────────────────────────────────────────────
def _css() -> str:
    t = TOKENS
    return f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {{
  --th-bg: {t['canvas']};
  --th-surface: {t['surface_card']};
  --th-surface-2: {t['surface_raised']};
  --th-surface-sunken: {t['surface_dark']};
  --th-border: {t['hairline']};
  --th-border-strong: {t['hairline_strong']};
  --th-text: {t['ink']};
  --th-text-soft: {t['body']};
  --th-text-muted: {t['charcoal']};
  --th-text-faint: {t['mute']};
  --th-accent: {t['primary']};
  --th-accent-deep: {t['primary_deep']};
  --th-accent-soft: {t['primary_soft']};
  --sev-critical: {t['sev_critical']};
  --sev-high: {t['sev_high']};
  --sev-medium: {t['sev_medium']};
  --sev-low: {t['sev_low']};
  --th-radius: 10px;
  --th-radius-sm: 7px;
}}

@keyframes th-breathe {{
  0%, 100% {{ opacity: 1; }}
  50%      {{ opacity: .45; }}
}}

/* ---- Base ---- */
.stApp {{
  background: var(--th-bg);
  color: var(--th-text);
}}
.main .block-container {{
  max-width: 1520px;
  padding-top: 1.4rem;
  padding-bottom: 3rem;
}}
.main [data-testid="stVerticalBlock"] {{ gap: .8rem; }}
[data-testid="stElementContainer"] {{ margin-bottom: 0 !important; }}

html, body, [class*="css"], .stMarkdown, p, span, div, label, input, button, .stMetricLabel {{
  font-family: 'Inter', system-ui, -apple-system, sans-serif;
}}
h1, h2, h3, h4, h5 {{
  font-family: 'Inter', system-ui, sans-serif !important;
  color: var(--th-text) !important;
  font-weight: 700 !important;
  letter-spacing: -.01em !important;
  line-height: 1.25 !important;
}}
h1 {{ font-size: 1.55rem !important; }}
h2 {{ font-size: 1.25rem !important; }}
h3 {{ font-size: 1.02rem !important; }}
code, kbd, pre, .mono {{ font-family: 'JetBrains Mono', ui-monospace, monospace !important; }}
a, a:visited {{ color: {t['link']} !important; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}

/* st.subheader -> petit label de section discret */
[data-testid="stHeadingWithActionElements"] h3 {{
  font-size: .8rem !important;
  font-weight: 600 !important;
  letter-spacing: .06em !important;
  text-transform: uppercase;
  color: var(--th-text-muted) !important;
  margin: .6rem 0 .4rem 0 !important;
}}

/* ═══════════════════════════════════════════════════════════
   SIDEBAR — 3 zones : (1) identite + etat  (2) navigation
                       (3) Threat Control (filtres)
   ═══════════════════════════════════════════════════════════ */
section[data-testid="stSidebar"] {{
  background: var(--th-surface-sunken);
  border-right: 1px solid var(--th-border);
  min-width: 300px !important;
  max-width: 300px !important;
}}
section[data-testid="stSidebar"] > div {{ padding-top: .55rem; }}
section[data-testid="stSidebar"] [data-testid="stSidebarContent"] {{
  padding-left: .9rem; padding-right: .9rem;
}}
section[data-testid="stSidebar"] * {{ color: var(--th-text); }}
section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] {{ gap: .4rem; }}
section[data-testid="stSidebar"] label {{
  font-size: .76rem !important; font-weight: 500 !important;
  color: var(--th-text-muted) !important;
}}
section[data-testid="stSidebar"] hr {{ margin: .55rem 0; border-color: var(--th-border); }}
section[data-testid="stSidebar"] [data-testid="stCaptionContainer"] {{ color: var(--th-text-faint); }}

/* --- Separation des 3 zones (conteneurs keyed) --- */
div[class*="st-key-sb_identity"],
div[class*="st-key-sb_nav"] {{
  padding-bottom: .55rem;
  border-bottom: 1px solid var(--th-border);
  margin-bottom: .3rem;
}}

/* Streamlit applique margin-bottom:-1rem aux conteneurs de markdown (pour
   compenser la marge des <p>). Nos blocs HTML custom de la sidebar n'ont
   pas de <p> final -> ce -1rem fait chevaucher les sous-blocs. On le
   neutralise UNIQUEMENT pour nos composants custom (cible via :has). */
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"]:has(> .th-brand),
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"]:has(> .th-state-pill),
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"]:has(> .th-session),
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"]:has(> .th-nav-label),
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"]:has(> .th-filter-eyebrow),
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"]:has(> .th-filter-count) {{
  margin-bottom: 0 !important;
}}

/* --- Petits intitules de zone --- */
.th-nav-label, .th-filter-eyebrow {{
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: .64rem; font-weight: 600; text-transform: uppercase;
  letter-spacing: .16em; color: var(--th-text-faint);
  padding: 2px 4px 4px 4px;
}}
.th-filter-eyebrow {{ display: flex; align-items: center; height: 2.1rem; }}

/* ---------- ZONE 1 : identite + etat + session ----------
   Trois sous-blocs qui doivent RESPIRER : bloc titre, pastille d'etat,
   bloc identite. La cle "sb_identity" est posee DIRECTEMENT sur le
   VerticalBlock (conteneur flex) -> on cible ce flex pour elargir le gap. */
section[data-testid="stSidebar"] [data-testid="stVerticalBlock"].st-key-sb_identity {{
  gap: .7rem !important;
}}

.th-brand {{ display: flex; align-items: center; gap: 11px; padding: 4px 2px 4px 2px; }}
.th-brand-logo {{
  width: 38px; height: 38px; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  background: var(--th-surface-2); border: 1px solid var(--th-border); border-radius: 9px;
}}
.th-brand-logo img {{ width: 26px; height: 26px; display: block; }}
.th-brand-name {{ font-size: 1.04rem; font-weight: 700; letter-spacing: -.01em; color: var(--th-text); line-height: 1.15; }}
.th-brand-sub {{ font-size: .7rem; font-weight: 500; color: var(--th-text-faint); margin-top: 3px; letter-spacing: .02em; }}

/* Pastille d'etat unifiee (systeme / MongoDB). tone = ok | warn | crit */
.th-state-pill {{
  display: flex; align-items: center; gap: 9px;
  font-size: .74rem; font-weight: 600; letter-spacing: .01em;
  padding: 9px 11px; margin: 2px 2px 2px 2px;
  border-radius: var(--th-radius-sm);
  border: 1px solid var(--th-border);
  border-left: 2px solid var(--th-text-faint);
  background: var(--th-surface-2);
  color: var(--th-text-soft);
}}
.th-state-pill .th-state-dot {{
  width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; background: currentColor;
}}
.th-state-ok   {{ color: var(--sev-low);  border-left-color: var(--sev-low);
                  background: rgba(62,207,142,0.08); border-color: rgba(62,207,142,0.22); }}
.th-state-warn {{ color: var(--sev-high); border-left-color: var(--sev-high);
                  background: rgba(245,135,43,0.09); border-color: rgba(245,135,43,0.24); }}
.th-state-crit {{ color: var(--th-accent); border-left-color: var(--th-accent);
                  background: var(--th-accent-soft); border-color: rgba(224,30,43,0.30); }}
.th-state-ok .th-state-dot {{ animation: th-breathe 3s ease-in-out infinite; }}
.th-state-crit .th-state-dot, .th-state-warn .th-state-dot {{ animation: th-breathe 1.8s ease-in-out infinite; }}

/* Identite de session : avatar + (nom / role) centres verticalement */
.th-session {{
  display: flex; align-items: center; gap: 10px;
  padding: 4px 3px 2px 3px;
  margin-top: 2px;
}}
.th-session-avatar {{
  width: 28px; height: 28px; border-radius: 8px; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  background: var(--th-accent-soft); color: var(--th-accent);
  font-size: .8rem; font-weight: 700; line-height: 1;
}}
.th-session-id {{ display: flex; flex-direction: column; justify-content: center; min-width: 0; }}
.th-session-name {{
  font-size: .82rem; font-weight: 600; color: var(--th-text); line-height: 1.2;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}}
.th-session-role {{ font-size: .68rem; color: var(--th-text-faint); line-height: 1.2; margin-top: 1px; }}
/* Bouton Sign out : detache du bloc identite */
.st-key-th_logout_btn {{ margin-top: .15rem; }}
.st-key-th_logout_btn .stButton > button {{
  padding: 7px 10px !important; font-size: .76rem !important;
  min-height: 0 !important; background: transparent;
  border: 1px solid var(--th-border); color: var(--th-text-muted);
}}
.st-key-th_logout_btn .stButton > button:hover {{
  background: var(--th-surface-2); color: var(--th-text); border-color: var(--th-text-faint);
}}

/* ---------- ZONE 2 : navigation ----------
   Items alignes a GAUCHE (comme le reste de la sidebar), icones dans une
   gouttiere de largeur fixe -> colonne verticale nette, labels au meme x.
   Interligne resserre pour une lecture dense d'un coup d'oeil. La cle
   "sb_nav" est posee DIRECTEMENT sur le VerticalBlock (conteneur flex). */
section[data-testid="stSidebar"] [data-testid="stVerticalBlock"].st-key-sb_nav {{
  gap: 3px !important;
}}
section[data-testid="stSidebar"] div[class*="st-key-nav_"] .stButton > button {{
  font-family: 'Inter', sans-serif !important;
  font-weight: 500; font-size: .88rem;
  text-align: left !important;
  justify-content: flex-start !important;
  background: transparent !important;
  border: 1px solid transparent !important;
  border-left: 2px solid transparent !important;
  border-radius: var(--th-radius-sm) !important;
  padding: 6px 10px !important;
  min-height: 0 !important;
  color: var(--th-text-muted) !important;
  transition: background .13s ease, color .13s ease, border-color .13s ease;
}}
/* Streamlit enveloppe le contenu du bouton dans div>span en justify:center :
   on les repasse a flex-start + pleine largeur pour un vrai alignement gauche. */
section[data-testid="stSidebar"] div[class*="st-key-nav_"] .stButton > button > div,
section[data-testid="stSidebar"] div[class*="st-key-nav_"] .stButton > button > div > span {{
  justify-content: flex-start !important;
  width: 100% !important;
}}
section[data-testid="stSidebar"] div[class*="st-key-nav_"] .stButton > button * {{ color: inherit !important; }}
section[data-testid="stSidebar"] div[class*="st-key-nav_"] .stButton > button:hover {{
  background: var(--th-surface-2) !important;
  color: var(--th-text) !important;
}}
section[data-testid="stSidebar"] div[class*="st-key-nav_"] .stButton > button[kind="primary"] {{
  background: var(--th-accent-soft) !important;
  border-left: 2px solid var(--th-accent) !important;
  color: var(--th-text) !important;
  font-weight: 600;
}}
section[data-testid="stSidebar"] div[class*="st-key-nav_"] .stButton > button[kind="primary"] span[data-testid="stIconMaterial"] {{
  color: var(--th-accent) !important; opacity: 1;
}}
/* Gouttiere d'icone : le conteneur direct de l'icone a une largeur FIXE
   -> toutes les icones forment une colonne, les labels demarrent au meme x. */
section[data-testid="stSidebar"] div[class*="st-key-nav_"] .stButton > button > div > span > span:first-child {{
  width: 1.35rem !important; min-width: 1.35rem !important;
  margin-right: 8px !important; flex-shrink: 0 !important;
  display: inline-flex !important; align-items: center; justify-content: center;
}}
section[data-testid="stSidebar"] div[class*="st-key-nav_"] .stButton > button span[data-testid="stIconMaterial"] {{
  font-size: 1.05rem; opacity: .7;
}}

/* ---------- ZONE 3 : Threat Control (accordeons homogenes) ---------- */
.st-key-btn_reset_filters .stButton > button {{
  padding: 5px 9px !important; font-size: .72rem !important; width: 100%;
  white-space: nowrap !important; min-height: 0 !important;
  background: transparent; border: 1px solid var(--th-border); color: var(--th-text-muted);
}}
.st-key-btn_reset_filters .stButton > button:hover {{
  background: var(--th-surface-2); color: var(--th-text);
}}
.st-key-quick_search .stTextInput input {{ font-size: .8rem !important; }}

section[data-testid="stSidebar"] [data-testid="stExpander"] {{
  background: var(--th-surface);
  border: 1px solid var(--th-border);
  border-radius: var(--th-radius-sm);
  margin-bottom: 5px;
  overflow: hidden;
}}
section[data-testid="stSidebar"] [data-testid="stExpander"] details {{ border: none !important; background: transparent !important; }}
section[data-testid="stSidebar"] [data-testid="stExpander"] summary {{
  padding: 9px 11px !important;
  font-size: .74rem !important; font-weight: 600 !important;
  letter-spacing: .05em; text-transform: uppercase;
  color: var(--th-text-muted) !important;
  min-height: 0 !important;
  border-left: 2px solid transparent;
  transition: color .12s ease, background .12s ease;
}}
section[data-testid="stSidebar"] [data-testid="stExpander"] summary:hover {{
  color: var(--th-text) !important; background: rgba(255,255,255,0.02);
}}
section[data-testid="stSidebar"] [data-testid="stExpander"] details[open] summary {{
  color: var(--th-text) !important;
  border-left: 2px solid var(--th-accent);
  background: rgba(255,255,255,0.02);
}}
section[data-testid="stSidebar"] [data-testid="stExpander"] summary svg {{ color: var(--th-text-faint); }}
section[data-testid="stSidebar"] [data-testid="stExpander"] [data-testid="stExpanderDetails"] {{
  padding: 8px 11px 11px 11px !important;
  border-top: 1px solid var(--th-border);
}}

/* Pills (st.pills -> data-testid=stButtonGroup, boutons data-variant=pills) */
section[data-testid="stSidebar"] [data-testid="stButtonGroup"] {{ gap: 5px; flex-wrap: wrap; }}
section[data-testid="stSidebar"] [data-testid="stButtonGroup"] button[data-variant="pills"] {{
  font-size: .72rem !important; font-weight: 600 !important;
  padding: 4px 11px !important; border-radius: 999px !important;
  background: transparent !important;
  border: 1px solid var(--th-border) !important;
  color: var(--th-text-faint) !important;
}}
section[data-testid="stSidebar"] [data-testid="stButtonGroup"] button[data-variant="pills"]:hover {{
  color: var(--th-text) !important; border-color: var(--th-text-faint) !important;
}}
/* Severite : pilule selectionnee = fond neutre + teinte semantique par
   position (ordre fixe CRITICAL / HIGH / MEDIUM / LOW). */
.st-key-f_severity_pills button[data-variant="pills"][data-selected="true"] {{
  background: var(--th-surface-2) !important;
  border-color: var(--th-border-strong) !important;
}}
.st-key-f_severity_pills button[data-variant="pills"]:nth-of-type(1)[data-selected="true"] {{ color: var(--sev-critical) !important; box-shadow: inset 3px 0 0 var(--sev-critical); }}
.st-key-f_severity_pills button[data-variant="pills"]:nth-of-type(2)[data-selected="true"] {{ color: var(--sev-high) !important; box-shadow: inset 3px 0 0 var(--sev-high); }}
.st-key-f_severity_pills button[data-variant="pills"]:nth-of-type(3)[data-selected="true"] {{ color: var(--sev-medium) !important; box-shadow: inset 3px 0 0 var(--sev-medium); }}
.st-key-f_severity_pills button[data-variant="pills"]:nth-of-type(4)[data-selected="true"] {{ color: var(--sev-low) !important; box-shadow: inset 3px 0 0 var(--sev-low); }}

/* Pied de la zone filtres : compteur + actions */
.th-filter-count {{
  font-size: .74rem; color: var(--th-text-muted);
  padding: 8px 4px 6px 4px;
}}
.th-filter-count strong {{ color: var(--th-text); font-weight: 700; }}
.st-key-sb_filters .stDownloadButton > button,
.st-key-sb_filters div[class*="st-key-btn_refresh"] .stButton > button {{
  width: 100%; font-size: .78rem !important; padding: 7px 12px !important;
}}

/* ═══════════ PANNEAUX ═══════════ */
div[class*="st-key-panel_"] {{
  background: var(--th-surface);
  border: 1px solid var(--th-border);
  border-radius: var(--th-radius);
  padding: 16px 18px;
}}
div[class*="st-key-darkpanel_"] {{
  background: var(--th-surface-sunken);
  border: 1px solid var(--th-border);
  border-radius: var(--th-radius);
  padding: 16px 18px;
}}
div[class*="st-key-darkpanel_"] * {{ color: var(--th-on-dark, {t['on_dark']}); }}
div[class*="st-key-darkpanel_"] .th-panel-title .th-panel-sub {{ color: {t['on_dark_mute']}; }}

.th-panel-title {{
  font-size: .92rem; font-weight: 600; color: var(--th-text);
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: .8rem;
}}
.th-panel-title .th-panel-sub {{
  font-size: .74rem; font-weight: 400; color: var(--th-text-faint);
}}

/* ═══════════ METRIQUES NATIVES ═══════════ */
[data-testid="stMetric"] {{
  background: var(--th-surface);
  border: 1px solid var(--th-border);
  border-radius: var(--th-radius);
  padding: 14px 16px;
}}
[data-testid="stMetricValue"] {{
  font-size: 1.7rem !important; font-weight: 700 !important; color: var(--th-text) !important;
}}
[data-testid="stMetricLabel"] {{
  font-size: .78rem !important; color: var(--th-text-muted) !important;
}}

/* ═══════════ BOUTONS ═══════════ */
.stButton > button, .stDownloadButton > button, .stFormSubmitButton > button {{
  font-family: 'Inter', sans-serif;
  font-weight: 600; font-size: .86rem;
  border-radius: var(--th-radius-sm);
  border: 1px solid var(--th-border-strong);
  background: var(--th-surface-2);
  color: var(--th-text);
  padding: 9px 18px;
  transition: background .14s ease, border-color .14s ease, transform .04s ease;
}}
.stButton > button:hover, .stDownloadButton > button:hover, .stFormSubmitButton > button:hover {{
  background: var(--th-surface);
  border-color: var(--th-text-faint);
}}
.stButton > button:active {{ transform: translateY(1px); }}
.stButton > button[kind="primary"], .stFormSubmitButton > button {{
  background: var(--th-accent);
  border-color: var(--th-accent);
  color: {t['on_primary']};
}}
.stButton > button[kind="primary"] *, .stFormSubmitButton > button * {{ color: {t['on_primary']} !important; }}
.stButton > button[kind="primary"]:hover, .stFormSubmitButton > button:hover {{
  background: var(--th-accent-deep); border-color: var(--th-accent-deep);
}}

/* ═══════════ CHAMPS ═══════════ */
.stTextInput input, .stSelectbox div[data-baseweb="select"] > div,
.stDateInput input, .stNumberInput input, .stMultiSelect div[data-baseweb="select"] > div {{
  border-radius: var(--th-radius-sm) !important;
  border: 1px solid var(--th-border) !important;
  background: var(--th-surface-2) !important;
  color: var(--th-text) !important;
}}
.stTextInput input:focus, .stNumberInput input:focus {{
  border-color: var(--th-accent) !important;
  box-shadow: 0 0 0 3px var(--th-ring, {t['ring_focus']}) !important;
}}
.stTextInput input::placeholder {{ color: {t['ash']} !important; }}

/* ═══════════ ONGLETS ═══════════ */
.stTabs [data-baseweb="tab-list"] {{ gap: 4px; border-bottom: 1px solid var(--th-border); }}
.stTabs [data-baseweb="tab"] {{ font-weight: 500; color: var(--th-text-faint); background: transparent; }}
.stTabs [aria-selected="true"] {{
  color: var(--th-text) !important;
  border-bottom: 2px solid var(--th-accent) !important;
}}

/* ═══════════ TABLEAUX ═══════════ */
[data-testid="stDataFrame"], [data-testid="stTable"] {{
  border: 1px solid var(--th-border);
  border-radius: var(--th-radius-sm);
  overflow: hidden;
}}

/* ═══════════ EXPANDER (contenu principal) ═══════════ */
.streamlit-expanderHeader, [data-testid="stExpander"] {{
  background: var(--th-surface);
  border: 1px solid var(--th-border);
  border-radius: var(--th-radius-sm);
}}

/* ═══════════ ALERTES STREAMLIT ═══════════ */
.stAlert {{ border-radius: var(--th-radius-sm); border: 1px solid var(--th-border); }}

/* ═══════════ HEADER / SCROLLBAR ═══════════ */
header[data-testid="stHeader"] {{ background: transparent; }}
#MainMenu, footer {{ visibility: hidden; }}
::-webkit-scrollbar {{ width: 10px; height: 10px; }}
::-webkit-scrollbar-thumb {{ background: {t['stone']}; border-radius: 6px; }}
::-webkit-scrollbar-thumb:hover {{ background: {t['ash']}; }}
::-webkit-scrollbar-track {{ background: transparent; }}

/* ═══════════ COMPOSANTS ═══════════ */
.th-live-dot {{
  display: inline-block; width: 7px; height: 7px; border-radius: 50%;
  background: var(--th-accent); margin-right: 7px;
  animation: th-breathe 2.4s ease-in-out infinite;
}}
.th-sev-tag {{
  font-size: .72rem; font-weight: 600; letter-spacing: .02em;
  border-radius: 999px; padding: 2px 10px; display: inline-block;
}}
.th-stamp {{
  display: inline-flex; align-items: center; gap: 7px;
  font-size: .78rem; font-weight: 700; letter-spacing: .04em;
  color: var(--th-accent);
  background: var(--th-accent-soft);
  border: 1px solid var(--th-accent);
  border-radius: 999px;
  padding: 4px 14px;
}}
.th-mono-chip {{
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: .76rem;
  background: var(--th-surface-2);
  border: 1px solid var(--th-border);
  border-radius: var(--th-radius-sm);
  padding: 1px 8px;
  color: var(--th-text);
  display: inline-block;
}}
.th-icon-badge {{
  display: flex; align-items: center; justify-content: center;
  width: 40px; height: 40px; border-radius: var(--th-radius-sm); flex-shrink: 0;
}}
.th-icon-badge .material-symbols-outlined {{ font-size: 1.2rem; }}

/* ═══════════ ECRAN DE LOGIN ═══════════ */
div[class*="st-key-th_login_box"] {{
  background: var(--th-surface-2);
  border: 1px solid var(--th-border-strong);
  border-radius: 14px;
  padding: 30px 30px 26px 30px;
  margin-top: 8vh;
  box-shadow: 0 30px 70px -24px rgba(0,0,0,0.6);
}}
div[class*="st-key-th_login_box"] .stTextInput input {{ background: var(--th-surface) !important; }}
div[class*="st-key-th_login_box"] .stTextInput input {{ padding: 11px 13px; }}
/* Masque l'indication "Press Enter to submit form" / "Press Enter to apply"
   sous les champs de l'ecran de login. */
div[class*="st-key-th_login_box"] [data-testid="InputInstructions"] {{ display: none !important; }}
.th-login-head {{ display: flex; align-items: center; gap: 13px; margin-bottom: 4px; }}
.th-login-mark {{
  width: 42px; height: 42px; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  background: var(--th-surface-2); border: 1px solid var(--th-border);
  border-radius: 10px;
}}
.th-login-mark img {{ width: 28px; height: 28px; display: block; }}
.th-login-title {{ font-size: 1.2rem; font-weight: 700; color: var(--th-text); line-height: 1.1; }}
.th-login-sub {{ font-size: .76rem; color: var(--th-text-faint); margin-top: 2px; }}
.th-login-hint {{
  font-size: .82rem; color: var(--th-text-muted);
  margin: 14px 0 6px 0;
  padding-top: 14px; border-top: 1px solid var(--th-border);
}}
</style>
"""


def inject_theme() -> None:
    """Injecte tout le theme (un seul bloc CSS). A appeler apres set_page_config."""
    st.markdown(_css(), unsafe_allow_html=True)
    st.markdown(
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?'
        'family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..40,400,0,0" />',
        unsafe_allow_html=True)


def _emit(html_block: str) -> None:
    """Rend un bloc HTML via st.markdown en retirant les lignes vides internes
    (sinon CommonMark sort du mode 'bloc HTML brut')."""
    st.markdown("\n".join(line for line in html_block.splitlines() if line.strip()),
                unsafe_allow_html=True)


def _hexpair(h: str, i: int) -> int:
    return int(h[i:i + 2], 16)


def _rgba(hexcolor: str, alpha: float) -> str:
    h = hexcolor.lstrip("#")
    if len(h) != 6:
        return hexcolor
    return f"rgba({_hexpair(h,0)},{_hexpair(h,2)},{_hexpair(h,4)},{alpha})"


# ─────────────────────────────────────────────────────────────
#  COMPOSANTS
# ─────────────────────────────────────────────────────────────
def panel_title(title: str, subtitle: str | None = None) -> None:
    """Titre de panneau (dans un st.container(key='panel_xxx' / 'darkpanel_xxx'))."""
    sub = f'<span class="th-panel-sub">{html.escape(str(subtitle))}</span>' if subtitle else ""
    _emit(f'<div class="th-panel-title"><span>{html.escape(str(title))}</span>{sub}</div>')


def sidebar_state_pill(label: str, tone: str = "ok") -> None:
    """Pastille d'etat unifiee pour la barre laterale (statut systeme /
    connexion MongoDB). tone ∈ {"ok" (vert), "warn" (orange), "crit" (rouge)}.
    Meme composant pour tous les etats -> lecture coherente."""
    tone = tone if tone in ("ok", "warn", "crit") else "ok"
    _emit(
        f'<div class="th-state-pill th-state-{tone}">'
        f'<span class="th-state-dot"></span><span>{html.escape(str(label))}</span></div>')


def severity_badge(severity: str) -> str:
    """Pilule de severite : fond tinte + texte de la couleur, filet discret."""
    t = TOKENS
    s = (severity or "").upper()
    color = {
        "CRITICAL": t["sev_critical"], "HIGH": t["sev_high"],
        "MEDIUM": t["sev_medium"], "LOW": t["sev_low"], "INFO": t["sev_info"],
    }.get(s, t["charcoal"])
    return (f'<span class="th-sev-tag" style="background:{_rgba(color, 0.14)};'
            f'color:{color};border:1px solid {_rgba(color, 0.42)};">{s or "—"}</span>')


def critical_stamp(text: str = "CRITICAL") -> str:
    """Marqueur discret pour l'alerte la plus grave d'une vue."""
    return f'<span class="th-stamp">&#9679; {html.escape(str(text))}</span>'


def mono_chip(text: str) -> str:
    """Puce monospace — RESERVEE aux IP / hash / IOC / identifiants MITRE."""
    return f'<span class="th-mono-chip">{html.escape(str(text))}</span>'


_ICON_TONES = {
    "primary": ("rgba(255,255,255,0.05)", TOKENS["ink"]),
    "danger":  (TOKENS["stamp_tint"], TOKENS["sev_critical"]),
    "amber":   ("rgba(245,135,43,0.14)", TOKENS["sev_high"]),
    "teal":    ("rgba(62,207,142,0.14)", TOKENS["sev_low"]),
    "violet":  ("rgba(255,255,255,0.05)", TOKENS["charcoal"]),
}


def kpi_icon_card(icon: str, label: str, value, tone: str = "primary",
                  delta: str | None = None) -> None:
    """Carte KPI epuree avec pastille d'icone. tone='danger' = seul KPI qui
    porte l'accent (a reserver a Critical)."""
    t = TOKENS
    bg, fg = _ICON_TONES.get(tone, _ICON_TONES["primary"])
    accent = tone == "danger"
    delta_html = (f'<div style="font-size:.76rem;color:{t["charcoal"]};margin-top:.15rem;">'
                  f'{html.escape(str(delta))}</div>') if delta else ""
    border = _rgba(t["primary"], 0.45) if accent else t["hairline"]
    _emit(f"""
    <div style="background:{t['surface_card']};border:1px solid {border};
                border-radius:10px;padding:15px 16px;height:100%;
                display:flex;align-items:center;gap:13px;">
      <div class="th-icon-badge" style="background:{bg};color:{fg};">
        <span class="material-symbols-outlined">{icon}</span>
      </div>
      <div>
        <div style="font-size:1.7rem;font-weight:700;line-height:1;color:{t['ink']};">{value}</div>
        <div style="font-size:.78rem;color:{t['charcoal']};margin-top:.25rem;">{html.escape(str(label))}</div>
        {delta_html}
      </div>
    </div>
    """)


def kpi_card(label: str, value, delta: str | None = None,
             accent: bool = False) -> None:
    """Carte KPI simple. accent=True = signal critique (accent) — un seul par vue."""
    t = TOKENS
    border = _rgba(t["primary"], 0.45) if accent else t["hairline"]
    value_color = t["primary"] if accent else t["ink"]
    dot = '<span class="th-live-dot"></span>' if accent else ""
    delta_html = (f'<div style="font-size:.78rem;color:{t["charcoal"]};margin-top:.4rem;">'
                  f'{html.escape(str(delta))}</div>') if delta else ""
    _emit(f"""
    <div style="background:{t['surface_card']};border:1px solid {border};
                border-radius:10px;padding:15px 16px;height:100%;">
      <div style="font-size:.78rem;font-weight:500;color:{t['charcoal']};">{dot}{html.escape(str(label))}</div>
      <div style="font-size:1.9rem;font-weight:700;line-height:1.15;margin-top:.3rem;color:{value_color};">{value}</div>
      {delta_html}
    </div>
    """)


def kpi_strip(items: list[dict]) -> None:
    """Bandeau de stats unifie : une bordure, cellules egales separees par des
    filets internes. items: {"label", "value", "delta"?, "accent"?}."""
    t = TOKENS
    n = len(items)
    cells = []
    for i, item in enumerate(items):
        accent = item.get("accent", False)
        border_right = f"border-right:1px solid {t['hairline']};" if i < n - 1 else ""
        value_color = t["primary"] if accent else t["ink"]
        dot = '<span class="th-live-dot"></span>' if accent else ""
        delta_html = (f'<div style="font-size:.72rem;color:{t["charcoal"]};margin-top:.3rem;'
                      f'white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">'
                      f'{html.escape(str(item["delta"]))}</div>') if item.get("delta") else ""
        cells.append(f"""
        <div style="flex:1;min-width:0;{border_right}padding:13px 16px;">
          <div style="font-size:.72rem;font-weight:500;color:{t['charcoal']};
                      white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{dot}{html.escape(str(item['label']))}</div>
          <div style="font-size:1.55rem;font-weight:700;line-height:1.2;margin-top:.2rem;color:{value_color};">{item['value']}</div>
          {delta_html}
        </div>
        """)
    _emit(
        f'<div style="display:flex;border:1px solid {t["hairline"]};border-radius:10px;'
        f'overflow:hidden;background:{t["surface_card"]};">' + "".join(cells) + "</div>")


def code_well(content: str, label: str | None = None) -> None:
    """Bloc technique brut (IOC, IP, hash, logs). Contenu echappe (donnees
    issues du trafic reseau, potentiellement forgees)."""
    t = TOKENS
    lab = (f'<div style="font-size:.7rem;font-weight:600;color:{t["mute"]};'
           f'text-transform:uppercase;letter-spacing:.08em;margin-bottom:.5rem;">'
           f'{html.escape(str(label))}</div>') if label else ""
    safe_content = html.escape(str(content))
    _emit(f"""
    <div style="background:{t['surface_dark']};border:1px solid {t['hairline']};
                border-left:2px solid {t['hairline_strong']};border-radius:8px;padding:14px 16px;">
      {lab}
      <pre style="font-family:'JetBrains Mono',ui-monospace,monospace;font-size:.8rem;
                  color:{t['on_dark']};margin:0;white-space:pre-wrap;word-break:break-word;">{safe_content}</pre>
    </div>
    """)


def report_block(text: str, label: str | None = None) -> None:
    """Bloc de prose façon rapport d'incident : filet d'accent a gauche."""
    t = TOKENS
    lab = (f'<div style="font-size:.7rem;font-weight:600;color:{t["primary"]};'
           f'text-transform:uppercase;letter-spacing:.1em;margin-bottom:.5rem;">'
           f'{html.escape(str(label))}</div>') if label else ""
    safe_text = html.escape(str(text))
    _emit(f"""
    <div style="background:{t['surface_card']};border:1px solid {t['hairline']};
                border-left:3px solid {t['primary']};border-radius:8px;padding:16px 18px;">
      {lab}
      <div style="font-size:.92rem;line-height:1.65;color:{t['body']};">{safe_text}</div>
    </div>
    """)


def section_header(title: str, eyebrow: str | None = None, accent: bool = False) -> None:
    """Titre de page : petit sur-titre discret + titre en Inter, casse normale."""
    t = TOKENS
    color = t["primary"] if accent else t["mute"]
    eb = (f'<div style="font-size:.72rem;font-weight:600;text-transform:uppercase;'
          f'letter-spacing:.12em;color:{color};margin-bottom:.35rem;">'
          f'{html.escape(str(eyebrow))}</div>') if eyebrow else ""
    _emit(f"""
    <div style="margin:.1rem 0 1rem 0;">
      {eb}
      <div style="font-size:1.7rem;font-weight:700;line-height:1.15;letter-spacing:-.01em;
                  color:{t['ink']};">{html.escape(str(title))}</div>
    </div>
    """)


def perforated_divider() -> None:
    """Filet discret entre deux blocs."""
    t = TOKENS
    st.markdown(
        f'<div style="height:0;border-top:1px solid {t["hairline"]};margin:1rem 0;"></div>',
        unsafe_allow_html=True)


_EMPTY_SVG = (
    '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" '
    'xmlns="http://www.w3.org/2000/svg" style="display:block;">'
    '<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.6" '
    'stroke-dasharray="3 3.2" opacity="0.9"/>'
    '<path d="M8.5 12h7" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>'
    '</svg>')


def empty_state(message: str, hint: str | None = None, on_dark: bool = False) -> None:
    """Etat vide elegant : marqueur discret + phrase courte + hint optionnel.
    (icone en SVG inline — aucune dependance de police)."""
    t = TOKENS
    border = t["divider_dark"] if on_dark else t["hairline"]
    fg = t["on_dark_mute"] if on_dark else t["charcoal"]
    hint_fg = t["on_dark_mute"] if on_dark else t["mute"]
    badge_bg = "rgba(255,255,255,0.05)" if on_dark else t["surface_raised"]
    hint_html = (f'<div style="font-size:.8rem;color:{hint_fg};margin-top:.35rem;">'
                 f'{html.escape(str(hint))}</div>') if hint else ""
    _emit(f"""
    <div style="border:1px dashed {border};border-radius:10px;
                padding:28px 22px;text-align:center;">
      <div style="width:38px;height:38px;border-radius:9px;margin:0 auto .7rem auto;
                  display:flex;align-items:center;justify-content:center;
                  background:{badge_bg};color:{fg};">{_EMPTY_SVG}</div>
      <div style="font-size:.9rem;font-weight:500;color:{fg};">{html.escape(str(message))}</div>
      {hint_html}
    </div>
    """)


def status_row(label: str, online: bool = True, detail: str | None = None) -> None:
    """Ligne de statut de service — point + libelle + etat."""
    t = TOKENS
    color = t["badge_success"] if online else t["primary"]
    state = "Online" if online else "Offline"
    detail_html = (f'<span style="color:{t["charcoal"]};font-size:.8rem;margin-left:8px;">'
                   f'{html.escape(str(detail))}</span>') if detail else ""
    _emit(f"""
    <div style="display:flex;align-items:center;padding:9px 13px;background:{t['surface_card']};
                border:1px solid {t['hairline']};border-radius:8px;margin-bottom:6px;">
      <span style="display:inline-block;width:7px;height:7px;border-radius:50%;
                   background:{color};margin-right:11px;flex-shrink:0;"></span>
      <span style="font-size:.88rem;font-weight:500;color:{t['ink']};">{html.escape(str(label))}</span>
      <span style="font-size:.72rem;font-weight:600;color:{color};margin-left:10px;">{state}</span>
      {detail_html}
    </div>
    """)


def ranked_list(items: list[tuple[str, int]], mono: bool = True, max_bar: int | None = None,
                on_dark: bool = False) -> None:
    """Liste classee compacte (Top MITRE, Top IOCs...) : rang, libelle, barre
    fine, valeur."""
    t = TOKENS
    if not items:
        empty_state("Nothing to rank yet", on_dark=on_dark)
        return
    fg = t["on_dark"] if on_dark else t["ink"]
    sub = t["on_dark_mute"] if on_dark else t["charcoal"]
    track = "rgba(255,255,255,0.07)"
    bar = _rgba(t["primary"], 0.85)
    peak = max(v for _, v in items) or 1
    rows = []
    font = "'JetBrains Mono', ui-monospace, monospace" if mono else "'Inter', sans-serif"
    for i, (label, value) in enumerate(items):
        pct = max(5, round(100 * value / peak))
        rows.append(f"""
        <div style="display:flex;align-items:center;gap:10px;padding:5px 0;">
          <span style="font-size:.72rem;color:{sub};width:1.5em;flex-shrink:0;">{i + 1:02d}</span>
          <span style="font-family:{font};font-size:.8rem;color:{fg};flex-shrink:0;
                       max-width:42%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{html.escape(str(label))}</span>
          <span style="flex:1;height:4px;background:{track};border-radius:3px;overflow:hidden;">
            <span style="display:block;height:100%;width:{pct}%;background:{bar};border-radius:3px;"></span>
          </span>
          <span style="font-size:.76rem;color:{sub};width:2.4em;text-align:right;flex-shrink:0;">{value}</span>
        </div>
        """)
    _emit("".join(rows))


def threat_level_banner(level: str, detail: str = "") -> None:
    """Bandeau : niveau de menace d'un coup d'oeil.
    level in {"CRITICAL","ELEVATED","NOMINAL"}."""
    t = TOKENS
    cfg = {
        "CRITICAL": (t["sev_critical"], True),
        "ELEVATED": (t["sev_high"], False),
        "NOMINAL":  (t["badge_success"], False),
    }.get(level, (t["mute"], False))
    color, pulse = cfg
    dot = ('<span class="th-live-dot"></span>' if pulse else
           f'<span style="display:inline-block;width:8px;height:8px;border-radius:50%;'
           f'background:{color};margin-right:10px;"></span>')
    _emit(f"""
    <div style="display:flex;align-items:center;justify-content:space-between;
                border:1px solid {_rgba(color, 0.35)};border-left:3px solid {color};
                background:{_rgba(color, 0.07)};border-radius:8px;
                padding:13px 18px;margin:.4rem 0;">
      <div style="display:flex;align-items:center;">
        {dot}
        <span style="font-weight:700;font-size:.92rem;color:{color};">Threat level: {html.escape(level.title())}</span>
      </div>
      <span style="font-size:.8rem;color:{t['charcoal']};">{html.escape(detail)}</span>
    </div>
    """)


# ─────────────────────────────────────────────────────────────
#  PLOTLY — habillage sombre unifie
# ─────────────────────────────────────────────────────────────
# Series generiques : gris neutres. L'accent et les couleurs de severite
# n'arrivent que via color_discrete_map explicite.
PLOTLY_COLORWAY = [
    "#c2c8d2", TOKENS["sev_high"], TOKENS["sev_low"],
    "#8b93a1", TOKENS["sev_medium"], "#5c6472",
    "#a4abb7", TOKENS["stone"],
]


def plotly_layout() -> dict:
    """Layout Plotly sombre (fond transparent, grille discrete, hover sombre)."""
    t = TOKENS
    return dict(
        colorway=PLOTLY_COLORWAY,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color=t["body"], size=12),
        title=dict(text="", font=dict(family="Inter, sans-serif", size=15)),
        xaxis=dict(gridcolor=t["hairline"], zerolinecolor=t["hairline"], linecolor=t["hairline"]),
        yaxis=dict(gridcolor=t["hairline"], zerolinecolor=t["hairline"], linecolor=t["hairline"]),
        margin=dict(l=10, r=10, t=30, b=10),
        legend=dict(font=dict(color=t["charcoal"], size=10)),
        hoverlabel=dict(
            bgcolor=t["surface_deep"],
            bordercolor=t["hairline_strong"],
            font=dict(family="Inter, sans-serif", color=t["on_dark"], size=11),
        ),
    )


def plotly_layout_dark() -> dict:
    """Variante pour un graphique DANS un darkpanel_ (fond plus sombre)."""
    t = TOKENS
    layout = plotly_layout()
    layout.update(
        font=dict(family="Inter, sans-serif", color=t["on_dark"], size=12),
        xaxis=dict(gridcolor=t["divider_dark"], zerolinecolor=t["divider_dark"]),
        yaxis=dict(gridcolor=t["divider_dark"], zerolinecolor=t["divider_dark"]),
    )
    return layout
