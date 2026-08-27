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

st.set_page_config(page_title="ThreatHunter SOC", page_icon="🛡️", layout="wide")
MAX_ALERTS = 2000
from dashboard.pages.theme import (
    inject_theme, section_header, kpi_card, kpi_strip, severity_badge,
    critical_stamp, mono_chip, code_well, report_block, perforated_divider,
    plotly_layout, empty_state, status_row, threat_level_banner, ranked_list,
    TOKENS,
)


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
# NB : pas d'app_header() ici — la marque (logo + "ThreatHunter" + "SOC ·
# Keystone Group") vit UNIQUEMENT dans la sidebar (sidebar_filters()). La
# repeter en tete de CHAQUE page dupliquerait le branding et mangerait de
# l'espace vertical ; chaque page a deja son propre section_header().


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
    """Applique l'habillage Plotly du theme (fond transparent, filets, tooltip well sombre)."""
    fig.update_layout(**plotly_layout())
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
    fig = go.Figure(go.Sankey(
        arrangement="snap",
        node=dict(
            label=srcs + dsts,
            color=[TOKENS["mute"]] * len(srcs) + [TOKENS["primary"]] * len(dsts),
            pad=10, thickness=10,
            line=dict(color=TOKENS["hairline"], width=0.5),
        ),
        link=dict(
            source=[src_idx[s] for s in flows["src_ip"]],
            target=[dst_idx[d] for d in flows["dst_ip"]],
            value=flows["count"],
            color="rgba(255,43,60,0.22)",
        ),
    ))
    fig.update_layout(height=300, font=dict(size=11))
    return fig


def threat_level(k: dict) -> tuple[str, str]:
    if k["critical"] > 0:
        return "CRITICAL", f"{k['critical']} active critical alert(s)"
    if k["high"] > 0:
        return "ELEVATED", f"{k['high']} high-risk alert(s)"
    if k["total"] > 0:
        return "NOMINAL", "no critical or high-risk alerts"
    return "NOMINAL", "no data for current filters"


def _executive_summary(df: pd.DataFrame, k: dict, level: str) -> str:
    """Paragraphe narratif genere a partir des KPI reels de la selection —
    aucune donnee inventee, uniquement une mise en phrase de compute_kpis()."""
    if df.empty:
        return "No alerts were recorded for the current selection — nothing to report."
    top_mitre = _top_list(df, "mitre", 1)
    technique = f" The most frequently observed technique was {top_mitre[0][0]} ({top_mitre[0][1]} alert(s))." \
        if top_mitre else ""
    cti_txt = f" {k['cti_hits']} alert(s) were confirmed against threat intelligence." if k["cti_hits"] else ""
    corr_txt = f" {k['correlated']} incident(s) correlate activity across multiple detectors." \
        if k["correlated"] else ""
    return (
        f"During the selected period, {k['total']} alert(s) were recorded across "
        f"{k['distinct_sources']} distinct source(s), including {k['critical']} critical and "
        f"{k['high']} high-risk event(s). Overall threat level is assessed as {level}."
        f"{technique}{cti_txt}{corr_txt}"
    )


def risk_gauge(value: int):
    v = value or 0
    bar_color = TOKENS["primary"] if v >= 70 else TOKENS["sev_high"] if v >= 45 else TOKENS["mute"]
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=v,
        number={"font": {"family": "Bricolage Grotesque, sans-serif", "size": 44, "color": TOKENS["ink"]}},
        gauge={"axis": {"range": [0, 100], "tickcolor": TOKENS["hairline_strong"]},
               "bar": {"color": bar_color},
               "bgcolor": "rgba(0,0,0,0)",
               "bordercolor": TOKENS["hairline"],
               "steps": [{"range": [0, 45], "color": TOKENS["surface_bone"]},
                         {"range": [45, 70], "color": "rgba(255,176,32,0.14)"},
                         {"range": [70, 100], "color": TOKENS["stamp_tint"]}]},
        title={"text": "Risk score max", "font": {"family": "Inter, sans-serif", "size": 14, "color": TOKENS["charcoal"]}}))
    fig.update_layout(height=240, margin=dict(l=20, r=20, t=40, b=10),
                       paper_bgcolor="rgba(0,0,0,0)",
                       font=dict(family="Inter, sans-serif", color=TOKENS["ink"]))
    return fig


# Navigation : (libelle affiche, icone Material Symbols — pas d'emoji).
# Le libelle EST la cle utilisee dans PAGES plus bas.
NAV_ITEMS = [
    ("Overview", "dashboard"),
    ("Alerts", "warning"),
    ("IOC Intelligence", "fingerprint"),
    ("Network Activity", "hub"),
    ("Threat Timeline", "timeline"),
    ("Hunting Queries", "travel_explore"),
    ("Reports", "summarize"),
    ("Settings", "settings"),
]


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
    logo_inner = (f'<img src="{LOGO_URI}" alt="Keystone Group">' if LOGO_URI
                  else '<span style="color:#fff;font-size:.9rem;">◆</span>')
    sys_ok = "db_error" not in st.session_state
    st.sidebar.markdown(f"""
    <div class="th-brand-row">
      <div class="th-logo-chip">{logo_inner}</div>
      <div>
        <div style="font-family:'Bricolage Grotesque';font-weight:800;font-size:1.1rem;
                    letter-spacing:-.3px;line-height:1.15;color:{TOKENS['ink']};">ThreatHunter</div>
        <div style="font-family:'JetBrains Mono';font-size:.6rem;font-weight:600;
                    text-transform:uppercase;letter-spacing:.1em;color:{TOKENS['primary']};">SOC · Keystone Group</div>
      </div>
    </div>
    <div style="display:flex;align-items:center;margin:.35rem 0 .7rem 0;">
      <span class="th-status-dot" style="background:{TOKENS['sev_low'] if sys_ok else TOKENS['primary']};"></span>
      <span style="font-family:'JetBrains Mono';font-size:.64rem;color:{TOKENS['charcoal']};
                   text-transform:uppercase;letter-spacing:.07em;">
        {'System Operational' if sys_ok else 'Degraded — DB Unreachable'}
      </span>
    </div>
    """, unsafe_allow_html=True)

    if "current_page" not in st.session_state:
        st.session_state.current_page = NAV_ITEMS[0][0]
    with st.sidebar.container(key="main_nav"):
        for name, icon in NAV_ITEMS:
            is_active = st.session_state.current_page == name
            if st.button(name, icon=f":material/{icon}:", key=f"nav_{icon}",
                         use_container_width=True,
                         type="primary" if is_active else "secondary"):
                st.session_state.current_page = name
                st.rerun()
    page = st.session_state.current_page
    st.sidebar.divider()

    with st.sidebar.container(key="quick_search"):
        text = st.text_input("Quick search", placeholder="Search IP, hash, description…",
                              label_visibility="collapsed", key="f_quick_search")

    top1, top2 = st.sidebar.columns([2, 1])
    with top1:
        st.markdown('<div class="th-filter-eyebrow">◈ Threat Control</div>', unsafe_allow_html=True)
    with top2:
        if st.button("Reset", icon=":material/restart_alt:", key="btn_reset_filters",
                     use_container_width=True):
            for k in FILTER_KEYS:
                st.session_state.pop(k, None)
            st.rerun()

    # --- Time Range (from / to + presets) ---
    with st.sidebar.expander("TIME RANGE", expanded=True, icon=":material/schedule:"):
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
            start, end = data.preset_range(df_all, preset_fr)
            st.caption(f"{start} → {end}")

    # --- Severity : st.pills natif (multi-select), theme-aware, aucun hack
    #     de checkboxes-en-pastilles a maintenir a la main. ---
    with st.sidebar.expander("SEVERITY", expanded=True, icon=":material/priority_high:"):
        sevs = st.pills("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                         selection_mode="multi",
                         default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                         label_visibility="collapsed", key="f_severity_pills") or []

    # --- Risk score (slider double poignee) ---
    with st.sidebar.expander("RISK SCORE", expanded=True, icon=":material/speed:"):
        rmin, rmax = st.slider("Risk score", 0, 100, (0, 100), step=5,
                                label_visibility="collapsed", key="f_risk_score")

    # --- Detector / MITRE ATT&CK ---
    with st.sidebar.expander("DETECTOR & MITRE", expanded=False, icon=":material/radar:"):
        detectors = ["All"] + (sorted(df_all["detector"].dropna().unique())
                                if not df_all.empty else [])
        det = st.selectbox("Detector", detectors, key="f_detector")
        mitres = ["All"] + (sorted(df_all["mitre"].dropna().unique())
                               if not df_all.empty else [])
        mitre = st.selectbox("MITRE technique", mitres, key="f_mitre")

    # --- Network / IP ---
    with st.sidebar.expander("NETWORK / IP", expanded=False, icon=":material/lan:"):
        src = st.text_input("Source IP contains", key="f_src_ip")
        dst = st.text_input("Destination IP contains", key="f_dst_ip")

    # --- CTI & Correlation ---
    with st.sidebar.expander("CTI & CORRELATION", expanded=False, icon=":material/link:"):
        c3, c4 = st.columns(2)
        cti_only = c3.toggle("CTI ✓", key="f_cti_only")
        corr_only = c4.toggle("Correlated", key="f_corr_only")

    # --- Application des filtres (dashboard_data, inchange) ---
    det_all = "Tous" if det == "All" else det
    mitre_all = "Toutes" if mitre == "All" else mitre
    df = data.filter_by_period(df_all, start, end)
    df = data.filter_alerts(df, severities=sevs, detector=det_all, mitre=mitre_all,
                            min_risk=rmin, max_risk=rmax, src_ip=src or None,
                            dst_ip=dst or None, cti_only=cti_only,
                            correlated_only=corr_only, text=text or None)

    # --- Recapitulatif + export global ---
    st.sidebar.divider()
    st.sidebar.caption(f"**{len(df)} / {len(df_all)}** alerts selected")
    if not df.empty:
        st.sidebar.download_button(
            "Export selection (CSV)", icon=":material/download:",
            data=df.drop(columns=["sev_rank"], errors="ignore").to_csv(index=False)
              .encode("utf-8"),
            file_name="threathunter_selection.csv", mime="text/csv",
            use_container_width=True)
    if st.sidebar.button("Refresh data", icon=":material/refresh:", use_container_width=True):
        st.cache_data.clear()
    return page, df


# ─── Page 1 — Overview ──────────────────────────────────────────
def page_home(df):
    section_header("Overview", eyebrow="Real-time threat posture")
    k = data.compute_kpis(df)
    level, level_detail = threat_level(k)
    threat_level_banner(level, level_detail)

    kpi_strip([
        {"label": "Total Alerts", "value": k["total"]},
        {"label": "Critical Alerts", "value": k["critical"], "accent": True},
        {"label": "High Risk", "value": k["high"]},
        {"label": "IOC Matches", "value": k["cti_hits"]},
        {"label": "Active Incidents", "value": k["correlated"]},
        {"label": "CTI Sources", "value": len(getattr(settings, "CTI_FEEDS", []))},
    ])

    # Ordre impose : Timeline -> Risk Distribution -> MITRE Techniques,
    # puis Top Detectors -> Top IOCs, puis Recent Critical Alerts.
    perforated_divider()
    a, b, c = st.columns(3)
    with a:
        st.subheader("Threat Activity Timeline")
        if df.empty or df["timestamp"].isna().all():
            empty_state("no temporal data")
        else:
            t = df.dropna(subset=["timestamp"])
            per = t.set_index("timestamp").resample("15min").size().reset_index(name="count")
            fig2 = px.area(per, x="timestamp", y="count")
            fig2.update_traces(line_color=TOKENS["primary"], fillcolor="rgba(255,43,60,0.14)")
            fig2.update_layout(height=220)
            st.plotly_chart(themed(fig2), use_container_width=True, key="ov_timeline")
    with b:
        st.subheader("Risk Distribution")
        if k["total"] == 0:
            empty_state("no alerts", hint="Distribution appears once alerts come in.")
        else:
            sc = data.severity_counts(df)
            fig = px.pie(sc, names="severity", values="count", hole=0.55,
                         color="severity", color_discrete_map=data.SEV_COLORS)
            fig.update_layout(height=220, showlegend=True,
                               legend=dict(font=dict(size=10)))
            fig.update_traces(marker=dict(line=dict(color=TOKENS["canvas"], width=2)))
            st.plotly_chart(themed(fig), use_container_width=True, key="ov_severity_pie")
    with c:
        st.subheader("MITRE ATT&CK Techniques")
        ranked_list(_top_list(df, "mitre", 6))

    perforated_divider()
    d, e = st.columns(2)
    with d:
        st.subheader("Top Detectors")
        ranked_list(_top_list(df, "detector", 6))
    with e:
        st.subheader("Top IOCs")
        ranked_list(_top_list(df, "src_ip", 6))

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
    c1, c2, c3, c4 = st.columns(4)
    with c1: kpi_card("Indicator Type", kind, accent=True)
    with c2: kpi_card("IP Matches", len(ip_hits))
    with c3: kpi_card("CTI Hits", len(cti_hits))
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
    fig = px.bar(counts_df, x="count", y=col, orientation="h",
                 color="count", color_continuous_scale=[TOKENS["surface_bone"], TOKENS["primary"]])
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
        st.subheader("Network Anomalies")
        st.caption("Source → destination flow, weighted by connection volume")
        fig3 = threat_flow_map(df)
        if fig3 is None:
            empty_state("no active connections for these filters")
        else:
            st.plotly_chart(themed(fig3), use_container_width=True, key="net_anomalies")


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
    fig2.update_traces(line_color=TOKENS["primary"],
                        fillcolor="rgba(255,43,60,0.14)")
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
    exp1, exp2 = st.columns(2)
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
    "IOC Intelligence": page_ioc,
    "Network Activity": page_network,
    "Threat Timeline": page_timeline,
    "Hunting Queries": page_hunting,
    "Reports": page_reports,
    "Settings": page_settings,
}


def main():
    df_all = load_data()
    page, df = sidebar_filters(df_all)
    if "db_error" in st.session_state:
        st.sidebar.error("MongoDB injoignable — mode degrade")
    PAGES[page](df)


main()
