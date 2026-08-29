"""
Dashboard ThreatHunter - Streamlit + Plotly.

8 pages (navigation laterale a icones) avec un module THREAT CONTROL
(filtres globaux) applique a toutes les pages : periode (from/to +
presets), severite, risk score, detecteur, technique MITRE, IP
source/destination, CTI confirmee, incidents correles, recherche libre.

Lancement :
    streamlit run dashboard/main.py --server.port 8501
    # acces depuis le Mac : http://192.168.100.10:8501
"""
import base64
import re as _re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from database.db import Database
from config import settings
import dashboard_data as data

st.set_page_config(page_title="ThreatHunter SOC", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="expanded")
MAX_ALERTS = 2000
from dashboard.pages.theme import (
    inject_theme, section_header, kpi_card, kpi_icon_card, kpi_strip,
    severity_badge, critical_stamp, mono_chip, code_well, report_block,
    perforated_divider, panel_title, plotly_layout, plotly_layout_dark,
    empty_state, status_row, threat_level_banner, ranked_list,
    sidebar_state_pill, TOKENS,
)
from dashboard.pages.auth import require_auth, logout_button
from dashboard.pages.advanced_pages import page_investigation, page_attack_matrix


def _load_logo_data_uri() -> str | None:
    """Charge le logo officiel Keystone Group tel quel (aucune regeneration) —
    encode en data URI pour l'injecter dans le HTML du theme sans dependre
    d'un serveur de fichiers statiques Streamlit."""
    logo_path = Path(__file__).resolve().parent / "keystone-logo-reduced.png"
    if not logo_path.exists():
        return None
    encoded = base64.b64encode(logo_path.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


LOGO_URI = _load_logo_data_uri()

inject_theme()
# NB : la marque (logo Keystone + "THREATHUNTER" + "SOC · KEYSTONE GROUP" +
# "● SYSTEM OPERATIONAL") vit UNIQUEMENT dans la barre laterale permanente
# (sidebar_nav()). Chaque page a deja son propre section_header().


@st.cache_data(ttl=30)
def load_data() -> pd.DataFrame:
    try:
        db = Database()
        return data.to_dataframe(db.get_alerts(limit=MAX_ALERTS))
    except Exception as e:                       # noqa: BLE001
        st.session_state["db_error"] = str(e)
        return data.to_dataframe([])


def sev_badge(sev: str) -> str:
    return severity_badge(sev)


def _pretty_json(obj) -> str:
    import json
    try:
        return json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(obj)


def themed(fig):
    """Applique l'habillage Plotly du theme creme (fond transparent, filets hairline)."""
    fig.update_layout(**plotly_layout())
    return fig


def themed_dark(fig):
    """Variante pour un graphique qui vit DANS un darkpanel_ (fond encre) :
    police et filets clairs plutot que sombres."""
    fig.update_layout(**plotly_layout_dark())
    return fig


def _hex_to_rgb(hexcolor: str) -> str:
    h = hexcolor.lstrip("#")
    return ",".join(str(int(h[i:i + 2], 16)) for i in (0, 2, 4))


def style_severity(df: pd.DataFrame, column: str = "severity"):
    """Colore la colonne severite d'un dataframe selon la palette du theme,
    pour que les tableaux natifs Streamlit portent la meme semantique
    que les badges/KPI plutot que du texte brut indifferencie."""
    if column not in df.columns:
        return df

    def _cell(val):
        color = data.SEV_COLORS.get(val, TOKENS["mute"])
        return f"background-color: rgba({_hex_to_rgb(color)}, 0.16); color: {color}; font-weight: 700;"

    return df.style.map(_cell, subset=[column])


def _top_list(df: pd.DataFrame, col: str, n: int = 6) -> list[tuple[str, int]]:
    tc = data.top_counts(df, col, n)
    if tc.empty:
        return []
    return list(zip(tc[col].astype(str), tc["count"].astype(int)))


def _top_talkers(df: pd.DataFrame, n: int = 8) -> list[tuple[str, int]]:
    """IP les plus actives, source OU destination confondues (distinct de
    'top sources' / 'top destinations' pris separement)."""
    if df.empty:
        return []
    combined = pd.concat([df["src_ip"], df["dst_ip"]]).dropna().astype(str)
    vc = combined[combined != "None"].value_counts().head(n)
    if vc.empty:
        return []
    return list(zip(vc.index, vc.values.astype(int)))


_IP_RE = _re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_HASH_RE = _re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_DOMAIN_RE = _re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-]+)+$")


def classify_indicator(term: str) -> str:
    """Classe la FORME de l'indicateur recherche (pas les donnees des
    resultats) : IP / HASH / DOMAIN / FREE-TEXT. Sert a orienter l'analyste,
    pas a fabriquer des categories de donnees qui n'existent pas dans le
    modele Alert (qui ne porte que des IP, pas de domaine/hash dedies)."""
    t = (term or "").strip()
    if _IP_RE.match(t):
        return "IP"
    if _HASH_RE.match(t):
        return "HASH"
    if _DOMAIN_RE.match(t) and not _IP_RE.match(t):
        return "DOMAIN"
    return "FREE-TEXT"


def _mask_uri(uri: str) -> str:
    """Masque les identifiants (user:pass@) embarques dans une URI de connexion.
    'mongodb://thunter:S3cr3t@host:27017/db' -> 'mongodb://***:***@host:27017/db'.
    Greedy jusqu'au DERNIER '@' : un mot de passe peut lui-meme contenir un
    '@' non encode (ex: le mot de passe par defaut du docker-compose de ce
    projet) — un `[^@]+` naif s'arreterait au premier '@' et laisserait une
    partie du secret en clair apres celui-ci. Ne jamais afficher un secret
    en clair dans l'UI, meme en lecture seule."""
    return _re.sub(r"//.*@", "//***:***@", uri or "")


def threat_flow_map(df: pd.DataFrame):
    """'Live Threat Map' honnete vu nos donnees (pas de geoloc reelle sur des
    IP privees de lab) : diagramme de flux source -> destination, colore par
    volume. Montre qui parle a qui, ce qu'un analyste veut vraiment voir."""
    flows = (df.dropna(subset=["src_ip", "dst_ip"])
               .groupby(["src_ip", "dst_ip"]).size().reset_index(name="count")
               .sort_values("count", ascending=False).head(10))
    if flows.empty:
        return None
    srcs = flows["src_ip"].unique().tolist()
    dsts = flows["dst_ip"].unique().tolist()
    src_idx = {ip: i for i, ip in enumerate(srcs)}
    dst_idx = {ip: i + len(srcs) for i, ip in enumerate(dsts)}
    # Lit dans un darkpanel_ (fond encre) : noeuds/liens en tons clairs,
    # jamais l'orange de marque ici — c'est un diagramme de flux generique,
    # pas un signal de severite.
    fig = go.Figure(go.Sankey(
        arrangement="snap",
        node=dict(
            label=srcs + dsts,
            color=["rgba(252,252,252,0.45)"] * len(srcs) + [TOKENS["on_dark"]] * len(dsts),
            pad=10, thickness=10,
            line=dict(color=TOKENS["divider_dark"], width=0.5),
        ),
        link=dict(
            source=[src_idx[s] for s in flows["src_ip"]],
            target=[dst_idx[d] for d in flows["dst_ip"]],
            value=flows["count"],
            color="rgba(252,252,252,0.16)",
        ),
    ))
    fig.update_layout(height=300, font=dict(size=11))
    return fig


# threat_level() / _executive_summary() vivent desormais dans dashboard_data
# (purs, partages avec l'export PDF). Ces alias gardent les appels existants
# de ce fichier inchanges.
def threat_level(k: dict) -> tuple[str, str]:
    return data.threat_level(k)


def _executive_summary(df: pd.DataFrame, k: dict, level: str) -> str:
    return data.executive_summary(df, k, level)


_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def severity_radar(df: pd.DataFrame):
    """'Threat Distribution by Severity' — radar a 4 axes, part (%) de
    chaque niveau dans la selection courante (donnee reelle, severity_counts)."""
    sc = data.severity_counts(df).set_index("severity")
    total = sc["count"].sum() or 1
    pct = [round(100 * sc.loc[s, "count"] / total) for s in _SEV_ORDER]
    theta = _SEV_ORDER + [_SEV_ORDER[0]]
    r = pct + [pct[0]]
    fig = go.Figure(go.Scatterpolar(
        r=r, theta=theta, fill="toself",
        line=dict(color=TOKENS["primary"], width=2),
        fillcolor="rgba(224,30,43,0.16)",
        hovertemplate="%{theta}: %{r}%<extra></extra>",
    ))
    fig.update_layout(
        polar=dict(
            bgcolor="rgba(0,0,0,0)",
            radialaxis=dict(visible=True, range=[0, 100], showticklabels=True,
                             tickfont=dict(size=8, color=TOKENS["mute"]),
                             gridcolor=TOKENS["hairline"]),
            angularaxis=dict(gridcolor=TOKENS["hairline"],
                              tickfont=dict(color=TOKENS["ink"], size=11)),
        ),
        showlegend=False, height=250, margin=dict(l=30, r=30, t=20, b=20),
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color=TOKENS["ink"]),
    )
    return fig


def detection_reliability_donut(df: pd.DataFrame):
    """'Detection Reliability' — repartition REELLE (pas inventee) de la
    selection : confirme par la CTI / corrobore par plusieurs detecteurs
    (correlated_count>1) / signal d'un seul detecteur, non confirme."""
    if df.empty:
        return None, {}
    cti = int(df["cti_hit"].sum())
    corr_only = int(((df["correlated_count"] > 1) & (~df["cti_hit"])).sum())
    single = int(len(df) - cti - corr_only)
    labels = ["CTI-confirmed", "Correlated", "Single-source"]
    values = [cti, corr_only, single]
    # "Correlated" n'est pas un signal critique — l'encre neutre plutot que
    # le tampon orange, reserve au vrai hit CTI/severite.
    colors = [TOKENS["sev_low"], TOKENS["ink"], TOKENS["sev_medium"]]
    fig = go.Figure(go.Pie(labels=labels, values=values, hole=0.68,
                            marker=dict(colors=colors,
                                        line=dict(color=TOKENS["surface_card"], width=2)),
                            textinfo="none", sort=False))
    fig.update_layout(
        height=210, showlegend=True,
        legend=dict(font=dict(size=10, color=TOKENS["charcoal"]), orientation="h",
                    yanchor="bottom", y=-.25),
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color=TOKENS["ink"]),
    )
    pct_cti = round(100 * cti / len(df)) if len(df) else 0
    return fig, {"cti": cti, "corr_only": corr_only, "single": single, "pct_cti": pct_cti}


def severity_ring(value: int, total: int, color: str):
    """Anneau circulaire (donut a 2 parts) pour une severite donnee — le
    nombre reel au centre, l'anneau colore represente sa part du total."""
    total = total or 1
    pct = value / total
    # La piste (portion vide) doit rester lisible sur une carte blanche —
    # surface_bone est trop proche du blanc pour marquer le contraste ici.
    fig = go.Figure(go.Pie(
        values=[pct, 1 - pct], hole=0.72, sort=False, direction="clockwise",
        marker=dict(colors=[color, "rgba(255,255,255,0.07)"]),
        textinfo="none", hoverinfo="skip",
    ))
    fig.update_layout(
        showlegend=False, height=130, margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        annotations=[dict(text=str(value), x=0.5, y=0.5, showarrow=False,
                          font=dict(size=20, color=TOKENS["ink"], family="Rajdhani, sans-serif"))],
    )
    return fig


def trend_by_severity(df: pd.DataFrame):
    """'Threat Trends Over Time' — une ligne par severite (donnee reelle,
    resample sur la selection), pas une seule courbe generique."""
    t = df.dropna(subset=["timestamp"])
    per = (t.set_index("timestamp").groupby("severity")
             .resample("30min").size().rename("count").reset_index())
    fig = px.line(per, x="timestamp", y="count", color="severity",
                  color_discrete_map=data.SEV_COLORS,
                  category_orders={"severity": _SEV_ORDER})
    fig.update_traces(mode="lines")
    fig.update_layout(height=230, showlegend=True,
                       legend=dict(font=dict(size=9, color=TOKENS["charcoal"]),
                                   orientation="h", yanchor="bottom", y=1.02, x=0))
    return fig


def _gradient_bar_vertical(counts_df, col):
    # Compte generique (pas une severite) : degrade encre, pas le tampon
    # orange — reserve au CTA / a CRITICAL.
    fig = px.bar(counts_df, x=col, y="count",
                 color="count", color_continuous_scale=[TOKENS["surface_bone"], TOKENS["ink"]])
    fig.update_layout(coloraxis_showscale=False, xaxis=dict(categoryorder="total descending"))
    fig.update_traces(marker_line_width=0)
    return fig


# Navigation : (libelle affiche, icone Material Symbols — pas d'emoji).
# Le libelle EST la cle utilisee dans PAGES plus bas.
# Libelles de nav COURTS (comme la reference : "Dashboard / Summary / Alert
# / Activities / Data / Settings", tous un seul mot) — huit items dans une
# barre horizontale n'ont pas la place pour des libelles longs ("Network
# Activity" force un retour a la ligne caractere par caractere). Le titre
# complet de chaque page reste dans son propre section_header().
NAV_ITEMS = [
    ("Overview", "grid_view"),
    ("Alerts", "warning"),
    ("Investigation", "manage_search"),
    ("ATT&CK Matrix", "table_chart"),
    ("IOC Intelligence", "fingerprint"),
    ("Network Activity", "lan"),
    ("Threat Timeline", "timeline"),
    ("Hunting Queries", "travel_explore"),
    ("Reports", "summarize"),
    ("Settings", "settings"),
]


# ═══════════════════════════════════════════════════════════════
#  SIDEBAR NAV — barre laterale permanente (marque + navigation)
# ═══════════════════════════════════════════════════════════════
def sidebar_nav(k_all: dict) -> None:
    """Barre laterale permanente — ZONE 1 (identite + etat + session) et
    ZONE 2 (navigation), separees par un filet.

    ZONE 1 : logo Keystone (asset fourni tel quel) + 'ThreatHunter' +
    'SOC · Keystone Group', une pastille d'etat unifiee (verte = operationnel,
    orange = alertes critiques actives, rouge = base injoignable / mode
    degrade), puis l'identite de session + 'Sign out'.

    ZONE 2 : les 8 pages. L'item actif porte une fine barre d'accent + un
    voile leger (pas d'aplat rouge) ; les items inactifs restent sobres,
    icones alignees en gouttiere."""
    if "current_page" not in st.session_state:
        st.session_state.current_page = NAV_ITEMS[0][0]
    logo_inner = (f'<img src="{LOGO_URI}" alt="Keystone Group">' if LOGO_URI
                  else '<span style="color:#e01e2b;font-size:1.1rem;">&#9670;</span>')
    crit = int(k_all.get("critical", 0) or 0)
    degraded = "db_error" in st.session_state

    with st.sidebar:
        # ── ZONE 1 — identite + etat + session ──────────────────
        with st.container(key="sb_identity"):
            st.markdown(f"""
            <div class="th-brand">
              <div class="th-brand-logo">{logo_inner}</div>
              <div>
                <div class="th-brand-name">ThreatHunter</div>
                <div class="th-brand-sub">SOC · Keystone Group</div>
              </div>
            </div>
            """, unsafe_allow_html=True)

            # Pastille d'etat unifiee (systeme / MongoDB) — un seul composant.
            if degraded:
                sidebar_state_pill("Database offline · degraded mode", "crit")
            elif crit:
                n = crit if crit < 100 else "99+"
                sidebar_state_pill(f"{n} active critical alert" + ("s" if crit != 1 else ""), "warn")
            else:
                sidebar_state_pill("System operational", "ok")

            logout_button()   # identite de session + Sign out (auth.py)

        # ── ZONE 2 — navigation ────────────────────────────────
        with st.container(key="sb_nav"):
            st.markdown('<div class="th-nav-label">Navigation</div>', unsafe_allow_html=True)
            for name, icon in NAV_ITEMS:
                is_active = st.session_state.current_page == name
                if st.button(name, icon=f":material/{icon}:", key=f"nav_{icon}",
                             use_container_width=True,
                             type="primary" if is_active else "secondary"):
                    st.session_state.current_page = name
                    st.rerun()


# ═══════════════════════════════════════════════════════════════
#  THREAT CONTROL — module de filtres globaux (barre laterale)
# ═══════════════════════════════════════════════════════════════
# Cles des widgets de filtre (pas la navigation) -> effacees par RESET FILTERS.
FILTER_KEYS = [
    "f_quick_search", "f_period_preset", "f_period_start", "f_period_end",
    "f_severity_pills",
    "f_risk_score", "f_detector", "f_mitre", "f_src_ip", "f_dst_ip",
    "f_cti_only", "f_corr_only",
]


def sidebar_filters(df_all: pd.DataFrame):
    """ZONE 3 — module THREAT CONTROL, dans la meme barre laterale.

    En-tete 'Threat Control' + Reset, champ de recherche libre, puis 6
    accordeons au style homogene (TIME RANGE, SEVERITY, RISK SCORE,
    DETECTOR & MITRE, NETWORK / IP, CTI & CORRELATION), et un pied de zone :
    compteur 'X / Y alerts selected' + export CSV + Refresh data.

    Tous les widgets, leurs cles (f_*) et la logique de filtrage sont
    INCHANGES : seul l'emballage visuel (conteneur keyed 'sb_filters',
    accordeons) evolue."""
    with st.sidebar:
      with st.container(key="sb_filters"):
        # --- En-tete de zone : label + Reset ---
        top1, top2 = st.columns([1.55, 1])
        with top1:
            st.markdown('<div class="th-filter-eyebrow">Threat Control</div>',
                        unsafe_allow_html=True)
        with top2:
            if st.button("Reset", key="btn_reset_filters", use_container_width=True):
                for k in FILTER_KEYS:
                    st.session_state.pop(k, None)
                st.rerun()

        # --- Recherche libre ---
        with st.container(key="quick_search"):
            text = st.text_input(
                "Quick search", placeholder="Search IP, hash, description…",
                label_visibility="collapsed", key="f_quick_search")

        # --- Accordeon 1 : Time Range (from / to + presets) ---
        with st.expander("TIME RANGE", expanded=True, icon=":material/schedule:"):
            preset = st.selectbox(
                "Time range", ["All time", "Last 24h", "Last 7 days",
                               "Last 30 days", "Custom"], label_visibility="collapsed",
                key="f_period_preset")
            dmin, dmax = data.date_bounds(df_all)
            preset_fr = {"All time": "Tout", "Last 24h": "Dernieres 24h",
                         "Last 7 days": "7 derniers jours", "Last 30 days": "30 derniers jours",
                         "Custom": "Personnalise"}[preset]
            if preset == "Custom":
                c1, c2 = st.columns(2)
                start = c1.date_input("From", value=dmin, min_value=dmin, max_value=dmax, key="f_period_start")
                end = c2.date_input("To", value=dmax, min_value=dmin, max_value=dmax, key="f_period_end")
            else:
                # Bornes calculees a partir du preset (plus de sous-titre
                # "date → date" affiche : le preset se suffit a lui-meme).
                start, end = data.preset_range(df_all, preset_fr)

        # --- Accordeon 2 : Severity (st.pills multi-select) ---
        # La cle "f_severity_pills" sert d'accroche CSS pour la teinte
        # semantique par position (rouge / orange / jaune / vert).
        with st.expander("SEVERITY", expanded=True, icon=":material/priority_high:"):
            sevs = st.pills("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                            selection_mode="multi",
                            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                            label_visibility="collapsed", key="f_severity_pills") or []

        # --- Accordeon 3 : Risk score (slider 0-100) ---
        with st.expander("RISK SCORE", expanded=True, icon=":material/speed:"):
            rmin, rmax = st.slider("Risk score", 0, 100, (0, 100), step=5,
                                   label_visibility="collapsed", key="f_risk_score")

        # --- Accordeon 4 : Detector / MITRE ATT&CK ---
        with st.expander("DETECTOR & MITRE", expanded=False, icon=":material/radar:"):
            detectors = ["All"] + (sorted(df_all["detector"].dropna().unique())
                                   if not df_all.empty else [])
            det = st.selectbox("Detector", detectors, key="f_detector")
            mitres = ["All"] + (sorted(df_all["mitre"].dropna().unique())
                                if not df_all.empty else [])
            mitre = st.selectbox("MITRE technique", mitres, key="f_mitre")

        # --- Accordeon 5 : Network / IP ---
        with st.expander("NETWORK / IP", expanded=False, icon=":material/lan:"):
            src = st.text_input("Source IP contains", key="f_src_ip")
            dst = st.text_input("Destination IP contains", key="f_dst_ip")

        # --- Accordeon 6 : CTI & Correlation ---
        with st.expander("CTI & CORRELATION", expanded=False, icon=":material/link:"):
            c3, c4 = st.columns(2)
            cti_only = c3.toggle("CTI ✓", key="f_cti_only")
            corr_only = c4.toggle("Correlated", key="f_corr_only")

        # --- Application des filtres (dashboard_data, INCHANGE) ---
        det_all = "Tous" if det == "All" else det
        mitre_all = "Toutes" if mitre == "All" else mitre
        df = data.filter_by_period(df_all, start, end)
        df = data.filter_alerts(df, severities=sevs, detector=det_all, mitre=mitre_all,
                                min_risk=rmin, max_risk=rmax, src_ip=src or None,
                                dst_ip=dst or None, cti_only=cti_only,
                                correlated_only=corr_only, text=text or None)

        # --- Pied de zone : compteur + actions ---
        st.markdown(
            f'<div class="th-filter-count"><strong>{len(df)}</strong> / {len(df_all)} '
            f'alerts selected</div>', unsafe_allow_html=True)
        if not df.empty:
            st.download_button(
                "Export selection (CSV)", icon=":material/download:",
                data=df.drop(columns=["sev_rank"], errors="ignore").to_csv(index=False)
                  .encode("utf-8"),
                file_name="threathunter_selection.csv", mime="text/csv",
                use_container_width=True)
        with st.container(key="btn_refresh"):
            if st.button("Refresh data", icon=":material/refresh:", use_container_width=True):
                st.cache_data.clear()
    return df


# ─── Page 1 — Overview ──────────────────────────────────────────
def page_home(df):
    section_header("Threat Intelligence Overview", eyebrow="Real-time SOC posture")
    k = data.compute_kpis(df)
    level, level_detail = threat_level(k)
    threat_level_banner(level, level_detail)

    k1, k2, k3, k4, k5 = st.columns(5)
    with k1: kpi_icon_card("emergency_home", "Total Alerts", k["total"], tone="primary")
    with k2: kpi_icon_card("block", "Critical Alerts", k["critical"], tone="danger")
    with k3: kpi_icon_card("bolt", "High Risk", k["high"], tone="amber")
    with k4: kpi_icon_card("fingerprint", "IOC Matches", k["cti_hits"], tone="teal")
    with k5: kpi_icon_card("hub", "Active Incidents", k["correlated"], tone="violet")

    perforated_divider()

    # Bento-grid a 3 colonnes, comme un poste de controle SOC : distribution
    # (radar+donut) | carte de flux + tops | tendance + repartition + anneaux.
    col_left, col_mid, col_right = st.columns([1, 1.35, 1])

    with col_left:
        with st.container(key="panel_radar"):
            panel_title("Threat Distribution by Severity")
            if k["total"] == 0:
                empty_state("no alerts")
            else:
                st.plotly_chart(themed(severity_radar(df)), use_container_width=True,
                                 key="ov_radar", config={"displayModeBar": False})
        with st.container(key="panel_donut"):
            panel_title("Detection Reliability")
            fig, mix = detection_reliability_donut(df)
            if fig is None:
                empty_state("no alerts")
            else:
                st.plotly_chart(themed(fig), use_container_width=True,
                                 key="ov_donut", config={"displayModeBar": False})
                st.caption(f"{mix['pct_cti']}% of alerts confirmed against threat intelligence")

    with col_mid:
        # Le seul bandeau sombre de la page — le rythme "creme -> encre ->
        # creme" du fichier de reference, applique a la seule donnee qui le
        # merite vraiment ici : la topologie reseau, traitee comme un well
        # technique imprime plutot qu'une carte comme les autres.
        with st.container(key="darkpanel_map"):
            panel_title("Network Threat Map", subtitle="source → destination flow")
            fig3 = threat_flow_map(df) if not df.empty else None
            if fig3 is None:
                empty_state("no active connections for these filters", on_dark=True)
            else:
                st.plotly_chart(themed_dark(fig3), use_container_width=True,
                                 key="ov_threat_map", config={"displayModeBar": False})
        with st.container(key="panel_lists"):
            lc1, lc2 = st.columns(2)
            with lc1:
                panel_title("Top MITRE Techniques")
                ranked_list(_top_list(df, "mitre", 5))
            with lc2:
                panel_title("Top Detectors")
                ranked_list(_top_list(df, "detector", 5))

    with col_right:
        with st.container(key="panel_trend"):
            panel_title("Threat Trends Over Time")
            if df.empty or df["timestamp"].isna().all():
                empty_state("no temporal data")
            else:
                st.plotly_chart(themed(trend_by_severity(df)), use_container_width=True,
                                 key="ov_trend", config={"displayModeBar": False})
        with st.container(key="panel_breakdown"):
            panel_title("Breakdown of Alerts by Detector")
            if df.empty:
                empty_state("no data")
            else:
                st.plotly_chart(themed(_gradient_bar_vertical(data.top_counts(df, "detector", 8), "detector")),
                                 use_container_width=True, key="ov_breakdown",
                                 config={"displayModeBar": False})

    perforated_divider()
    with st.container(key="panel_rings"):
        panel_title("Alerts by Severity")
        sc = data.severity_counts(df).set_index("severity")
        total = int(sc["count"].sum()) or 1
        ring_colors = {"CRITICAL": TOKENS["danger"], "HIGH": TOKENS["sev_high"],
                       "MEDIUM": TOKENS["sev_medium"], "LOW": TOKENS["sev_low"]}
        rc = st.columns(4)
        for col, sev in zip(rc, _SEV_ORDER):
            with col:
                v = int(sc.loc[sev, "count"])
                st.plotly_chart(severity_ring(v, total, ring_colors[sev]),
                                 use_container_width=True, key=f"ring_{sev}",
                                 config={"displayModeBar": False})
                st.markdown(f"<div style='text-align:center;font-size:.8rem;color:{TOKENS['charcoal']};"
                            f"margin-top:-.6rem;'>{sev.title()}</div>", unsafe_allow_html=True)

    perforated_divider()
    st.subheader("Recent Critical Alerts")
    crit = df[df["severity"] == "CRITICAL"].head(10) if not df.empty else df
    if crit.empty:
        empty_state("no critical alerts in current selection",
                     hint="Widen Threat Control filters or run the pipeline: python3 app.py --pcap <capture>")
        return
    st.dataframe(style_severity(crit[["timestamp", "severity", "risk_score", "detector",
                              "src_ip", "dst_ip", "mitre"]]),
                 use_container_width=True, hide_index=True,
                 column_config={"risk_score": st.column_config.ProgressColumn(
                     "Risk", min_value=0, max_value=100, format="%d")})


# ─── Page 2 — Alerts ───────────────────────────────────────────
def page_alerts(df):
    section_header("Alerts", eyebrow="Investigation table")
    if df.empty:
        empty_state("no alerts for current filters")
        return
    f = df.sort_values(["sev_rank", "risk_score"], ascending=False).reset_index(drop=True)
    st.caption(f"{len(f)} alert(s) — click a row to inspect")

    display_cols = ["timestamp", "severity", "risk_score", "confidence", "detector",
                     "src_ip", "dst_ip", "mitre", "correlated_count", "description"]
    event = st.dataframe(
        style_severity(f[display_cols]),
        use_container_width=True, hide_index=True,
        on_select="rerun", selection_mode="single-row", key="alerts_table",
        column_config={
            "risk_score": st.column_config.ProgressColumn(
                "Risk", min_value=0, max_value=100, format="%d"),
            "confidence": st.column_config.ProgressColumn(
                "Conf.", min_value=0.0, max_value=1.0, format="%.2f"),
            "correlated_count": st.column_config.NumberColumn("Corr."),
        },
    )
    selected_rows = list(event.selection.rows) if event and event.selection else []
    row = f.iloc[selected_rows[0] if selected_rows else 0]

    st.subheader("Detail")
    # Le tampon CRITICAL n'apparait que sur CETTE alerte-la : le seul
    # accent tolere sur la vue (les autres severites restent en badge neutre).
    if (row["severity"] or "").upper() == "CRITICAL":
        st.markdown(critical_stamp("CRITICAL"), unsafe_allow_html=True)
    else:
        st.markdown(sev_badge(row["severity"]), unsafe_allow_html=True)
    st.markdown(
        f"**{row['detector']}** · MITRE {mono_chip(row['mitre'])} · "
        f"risk {row['risk_score']} · confidence {row['confidence']}",
        unsafe_allow_html=True)
    st.markdown(
        f"src {mono_chip(row['src_ip'])} &nbsp;→&nbsp; dst {mono_chip(row['dst_ip'])}",
        unsafe_allow_html=True)
    if row["src_ip"] and st.button("Investigate this source →", key="alerts_investigate_src"):
        st.session_state.focus_entity = row["src_ip"]
        st.session_state.current_page = "Investigation"
        st.rerun()
    st.write(row["description"])
    if row["correlated_count"] > 1:
        st.info(f"Correlated incident — {row['correlated_count']} alerts "
                f"({', '.join(row['related_detectors'])})")
    if data._is_cti_hit(row["cti_context"]):
        st.success("CTI enrichment")
        code_well(_pretty_json(row["cti_context"]), label="CTI CONTEXT")
    with st.expander("Evidence"):
        code_well(_pretty_json(row["evidence"]), label="EVIDENCE")


# ─── Page 3 — IOC Intelligence ──────────────────────────────────
def page_ioc(df):
    section_header("IOC Intelligence", eyebrow="Indicator investigation workspace")
    _, mid, _ = st.columns([1, 2, 1])
    with mid:
        term = st.text_input("Indicator", placeholder="IP · domain · hash · CTI tag",
                              label_visibility="collapsed", key="ioc_term")
    if not term:
        empty_state("awaiting an indicator", hint="Search an IP, domain, hash, or CTI tag to begin.")
        return

    kind = classify_indicator(term)
    code_well(term, label=f"QUERY · CLASSIFIED AS {kind}")
    res = data.search_iocs(df, term)
    if res.empty:
        empty_state(f"no matches for “{term}”")
        return

    term_l = term.strip().lower()
    ip_hits = res[res["src_ip"].astype(str).str.lower().str.contains(term_l, na=False) |
                  res["dst_ip"].astype(str).str.lower().str.contains(term_l, na=False)]
    cti_hits = res[res["cti_hit"]]
    corr_hits = res[res["correlated_count"] > 1]

    # Resultats separes par categorie d'enrichissement, pas un seul blob.
    # accent (rouge) reserve au signal reellement alarmant : un hit CTI
    # confirme — pas juste la carte "type d'indicateur", informative.
    c1, c2, c3, c4 = st.columns(4)
    with c1: kpi_card("Indicator Type", kind)
    with c2: kpi_card("IP Matches", len(ip_hits))
    with c3: kpi_card("CTI Hits", len(cti_hits), accent=len(cti_hits) > 0)
    with c4: kpi_card("Correlated", len(corr_hits))

    perforated_divider()
    st.subheader(f"{len(res)} matching alert(s)")
    st.dataframe(style_severity(res[["timestamp", "severity", "detector", "src_ip", "dst_ip",
                      "mitre", "risk_score", "description"]]),
                 use_container_width=True, hide_index=True,
                 column_config={"risk_score": st.column_config.ProgressColumn(
                     "Risk", min_value=0, max_value=100, format="%d")})


# ─── Page 4 — Network Activity ─────────────────────────────────
def _gradient_bar(counts_df, col):
    # Compte generique (pas une severite) : degrade encre, pas le tampon
    # orange — reserve au CTA / a CRITICAL.
    fig = px.bar(counts_df, x="count", y=col, orientation="h",
                 color="count", color_continuous_scale=[TOKENS["surface_bone"], TOKENS["ink"]])
    fig.update_layout(coloraxis_showscale=False, yaxis=dict(categoryorder="total ascending"))
    fig.update_traces(marker_line_width=0)
    return fig


def page_network(df):
    section_header("Network Activity", eyebrow="Top talkers, detectors & anomalies")
    if df.empty:
        empty_state("no alerts for current filters")
        return

    top_src = data.top_counts(df, "src_ip", 10)
    if not top_src.empty:
        offender = top_src.iloc[0]
        oc1, oc2 = st.columns([1, 3])
        with oc1:
            kpi_card("Top Offender", int(offender["count"]),
                     delta=f"{offender['src_ip']} · most active source", accent=True)
        with oc2:
            st.write("")
    perforated_divider()

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Top Source IPs")
        st.plotly_chart(themed(_gradient_bar(top_src, "src_ip")), use_container_width=True,
                         key="net_top_src")
    with c2:
        st.subheader("Top Destination IPs")
        st.plotly_chart(themed(_gradient_bar(data.top_counts(df, "dst_ip", 10), "dst_ip")),
                         use_container_width=True, key="net_top_dst")

    perforated_divider()
    c3, c4 = st.columns(2)
    with c3:
        st.subheader("Top Talkers")
        st.caption("Most active IPs, source or destination combined")
        ranked_list(_top_talkers(df, 8))
    with c4:
        st.subheader("Detector Activity")
        st.plotly_chart(themed(_gradient_bar(data.top_counts(df, "detector", 12), "detector")),
                         use_container_width=True, key="net_detector")

    perforated_divider()
    c5, c6 = st.columns(2)
    with c5:
        st.subheader("MITRE Techniques")
        fig = px.pie(data.top_counts(df, "mitre", 12), names="mitre", values="count", hole=0.45)
        fig.update_traces(marker=dict(line=dict(color=TOKENS["canvas"], width=2)))
        st.plotly_chart(themed(fig), use_container_width=True, key="net_mitre_pie")
    with c6:
        with st.container(key="darkpanel_net_anomalies"):
            panel_title("Network Anomalies", subtitle="source → destination flow")
            fig3 = threat_flow_map(df)
            if fig3 is None:
                empty_state("no active connections for these filters", on_dark=True)
            else:
                st.plotly_chart(themed_dark(fig3), use_container_width=True, key="net_anomalies")


# ─── Page 5 — Threat Timeline ──────────────────────────────────
SEV_SYMBOLS = {"CRITICAL": "diamond", "HIGH": "triangle-up", "MEDIUM": "circle", "LOW": "circle"}


def page_timeline(df):
    section_header("Threat Timeline", eyebrow="Investigation timeline")
    if df.empty or df["timestamp"].isna().all():
        empty_state("no temporal data for current filters")
        return
    t = df.dropna(subset=["timestamp"]).copy()
    st.caption("Marker shape = severity (◆ critical · ▲ high · ● medium/low) · "
               "hover an event for detector, IPs, MITRE technique and correlation.")
    fig = px.scatter(t, x="timestamp", y="severity", color="severity",
                     color_discrete_map=data.SEV_COLORS,
                     symbol="severity", symbol_map=SEV_SYMBOLS,
                     size=t["risk_score"].fillna(10),
                     hover_data=["detector", "src_ip", "dst_ip", "mitre", "correlated_count"],
                     category_orders={"severity": ["LOW","MEDIUM","HIGH","CRITICAL"]})
    fig.update_layout(height=400, showlegend=False)
    fig.update_traces(marker=dict(line=dict(color=TOKENS["canvas"], width=1)))
    st.plotly_chart(themed(fig), use_container_width=True, key="timeline_scatter")
    st.subheader("Event Volume Over Time")
    per = t.set_index("timestamp").resample("1min").size().reset_index(name="count")
    fig2 = px.area(per, x="timestamp", y="count", template=data.PLOTLY_TEMPLATE)
    # Volume d'evenements (toutes severites) : trace rouge Keystone, remplissage
    # rouge tres dilue — lecture "activite / tempo de la menace".
    fig2.update_traces(line_color=TOKENS["primary"],
                        fillcolor="rgba(224,30,43,0.12)")
    fig2.update_layout(height=200)
    st.plotly_chart(themed(fig2), use_container_width=True, key="timeline_volume")


# ─── Page 6 — Hunting Queries ──────────────────────────────────
def page_hunting(df):
    section_header("Hunting Queries", eyebrow="Analyst investigation workspace")
    if df.empty:
        empty_state("no alerts for current filters")
        return

    st.caption("Runs on top of the current Threat Control selection.")
    q1, q2 = st.columns([5, 1])
    with q1:
        query = st.text_input("Query", placeholder="Search description, IOC, MITRE ID…",
                               label_visibility="collapsed", key="hunt_query")
    with q2:
        st.button("Execute", icon=":material/play_arrow:", type="primary",
                   use_container_width=True, key="hunt_execute")

    result_df = data.search_iocs(df, query) if query else df
    code_well(query or "(no query — showing full current selection)", label="ACTIVE QUERY")

    if result_df.empty:
        empty_state("no results", hint="Adjust the query or widen Threat Control filters.")
        return

    kpi_strip([
        {"label": "Result Count", "value": len(result_df)},
        {"label": "Detector Matches", "value": result_df["detector"].nunique()},
        {"label": "IOC Matches", "value": int(result_df["cti_hit"].sum())},
        {"label": "Risk Summary", "value": int(result_df["risk_score"].mean())
                     if result_df["risk_score"].notna().any() else 0},
    ])
    perforated_divider()
    st.subheader("Results")
    show = result_df[["timestamp", "severity", "risk_score", "detector",
               "src_ip", "dst_ip", "mitre", "description"]]
    st.dataframe(style_severity(show), use_container_width=True, hide_index=True,
                 column_config={"risk_score": st.column_config.ProgressColumn(
                     "Risk", min_value=0, max_value=100, format="%d")})
    st.download_button("Export results (CSV)", icon=":material/download:",
                       data=show.to_csv(index=False).encode("utf-8"),
                       file_name="hunting_export.csv", mime="text/csv")


# ─── Page 7 — Reports ───────────────────────────────────────────
def page_reports(df):
    section_header("Reports", eyebrow="Incident summary report")
    k = data.compute_kpis(df)
    level, level_detail = threat_level(k)
    threat_level_banner(level, level_detail)
    report_block(_executive_summary(df, k, level), label="EXECUTIVE SUMMARY")
    perforated_divider()

    kpi_strip([
        {"label": "Total Alerts", "value": k["total"]},
        {"label": "Critical", "value": k["critical"], "accent": True},
        {"label": "High Risk", "value": k["high"]},
        {"label": "IOC Matches", "value": k["cti_hits"]},
        {"label": "Active Incidents", "value": k["correlated"]},
        {"label": "Distinct Sources", "value": k["distinct_sources"]},
    ])
    perforated_divider()

    if df.empty:
        empty_state("no alerts for current filters — nothing to report")
        return

    r1, r2 = st.columns(2)
    with r1:
        st.subheader("Severity Breakdown")
        sc = data.severity_counts(df)
        st.dataframe(style_severity(sc), use_container_width=True, hide_index=True,
                     key="rep_sev_table")
    with r2:
        st.subheader("Top Techniques & Detectors")
        ranked_list(_top_list(df, "mitre", 5))
        st.caption("By detector")
        ranked_list(_top_list(df, "detector", 5))

    perforated_divider()
    st.subheader("Full Result Export")
    st.caption(f"{len(df)} alert(s) in current selection — export for hand-off or archival.")
    exp1, exp2, exp3 = st.columns(3)
    with exp1:
        st.download_button("Export CSV", icon=":material/download:",
                           data=df.drop(columns=["sev_rank"], errors="ignore").to_csv(index=False).encode("utf-8"),
                           file_name="threathunter_report.csv", mime="text/csv", use_container_width=True)
    with exp2:
        summary = {
            "generated_for": f"{len(df)} alerts",
            "threat_level": level,
            "executive_summary": _executive_summary(df, k, level),
            "kpis": k,
            "top_mitre": _top_list(df, "mitre", 10),
            "top_detectors": _top_list(df, "detector", 10),
        }
        st.download_button("Export Summary (JSON)", icon=":material/download:",
                           data=_pretty_json(summary).encode("utf-8"),
                           file_name="threathunter_report_summary.json", mime="application/json",
                           use_container_width=True)
    with exp3:
        # Rapport PDF de la SELECTION COURANTE — memes agregations que la page
        # (dashboard_data). Import paresseux : une lib PDF absente ne doit pas
        # casser le dashboard.
        try:
            from reports.pdf_export import build_pdf
            st.download_button(
                "Export PDF", icon=":material/picture_as_pdf:",
                data=build_pdf(df),
                file_name="threathunter_report.pdf", mime="application/pdf",
                use_container_width=True)
        except Exception as exc:                     # noqa: BLE001
            st.button("Export PDF", disabled=True, use_container_width=True,
                      help=f"PDF export unavailable — {exc}")


# ─── Page 8 — Settings ──────────────────────────────────────────
def page_settings(df):
    section_header("Settings", eyebrow="Technical configuration · read-only")
    st.subheader("Service Status")
    status_row("MongoDB", online="db_error" not in st.session_state,
                detail="unreachable — degraded mode" if "db_error" in st.session_state else "connected")
    status_row("MISP", online=True, detail=f"{len(getattr(settings,'CTI_FEEDS',[]))} feed(s) configured")
    status_row("OpenCTI", online=False, detail="connector implemented, not wired up")

    perforated_divider()
    st.subheader("Database")
    # MONGO_URI peut embarquer des identifiants (mongodb://user:pass@host/) —
    # jamais affiches en clair, meme en lecture seule.
    code_well(f"MONGO_URI = {_mask_uri(getattr(settings, 'MONGO_URI', 'N/A'))}\n"
              f"DB_NAME   = {getattr(settings,'DB_NAME','N/A')}")
    st.subheader("CTI Feeds")
    feeds = getattr(settings, "CTI_FEEDS", [])
    if feeds:
        st.markdown(" ".join(mono_chip(f) for f in feeds), unsafe_allow_html=True)
    else:
        st.caption("No feeds configured.")
    st.subheader("Detection Thresholds")
    code_well(_pretty_json(getattr(settings, "THRESHOLDS", {})))


PAGES = {
    "Overview": page_home,
    "Alerts": page_alerts,
    "Investigation": page_investigation,
    "ATT&CK Matrix": page_attack_matrix,
    "IOC Intelligence": page_ioc,
    "Network Activity": page_network,
    "Threat Timeline": page_timeline,
    "Hunting Queries": page_hunting,
    "Reports": page_reports,
    "Settings": page_settings,
}


def degraded_banner() -> None:
    """Bandeau clair en haut du contenu quand MongoDB est injoignable — le
    dashboard reste utilisable (etats vides propres), il ne plante pas.
    Icone en SVG inline (aucune dependance de police -> toujours net)."""
    icon = (
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" '
        f'style="flex-shrink:0;"><path d="M7 18h9a4 4 0 0 0 .8-7.92A6 6 0 0 0 5.2 8.5" '
        f'stroke="{TOKENS["sev_high"]}" stroke-width="1.7" stroke-linecap="round"/>'
        f'<path d="M4 4l16 16" stroke="{TOKENS["sev_high"]}" stroke-width="1.7" stroke-linecap="round"/></svg>')
    st.markdown(
        f'<div style="display:flex;align-items:center;gap:10px;'
        f'border:1px solid {TOKENS["sev_high"]}55;border-left:3px solid {TOKENS["sev_high"]};'
        f'background:{TOKENS["sev_high"]}12;border-radius:8px;padding:11px 16px;margin-bottom:.8rem;">'
        f'{icon}'
        f'<span style="font-size:.86rem;color:{TOKENS["body"]};">'
        f'<strong style="color:{TOKENS["ink"]};">Degraded mode</strong> — '
        f'the alert database is unreachable. Showing empty states until it comes back online.'
        f'</span></div>',
        unsafe_allow_html=True)


def main():
    # Barriere d'authentification : rien n'est charge ni affiche avant login.
    require_auth(LOGO_URI)

    df_all = load_data()
    sidebar_nav(data.compute_kpis(df_all))   # zones 1 + 2 (identite/etat/session + nav)
    df = sidebar_filters(df_all)             # zone 3 (Threat Control)

    if "db_error" in st.session_state:
        degraded_banner()
    PAGES[st.session_state.current_page](df)


main()
