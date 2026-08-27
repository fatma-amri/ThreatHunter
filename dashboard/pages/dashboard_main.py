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
    inject_theme, app_header, section_header, kpi_card, kpi_strip, severity_badge,
    critical_stamp, mono_chip, code_well, perforated_divider, plotly_layout,
    empty_state, status_row, threat_level_banner, ranked_list,
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
app_header("ThreatHunter", "Threat Hunting & Network Detection Platform",
           "SOC · Keystone Group", logo_data_uri=LOGO_URI)


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
        return "CRITICAL", f"{k['critical']} alerte(s) critique(s) active(s)"
    if k["high"] > 0:
        return "ELEVATED", f"{k['high']} alerte(s) elevee(s)"
    if k["total"] > 0:
        return "NOMINAL", "aucune alerte critique ou elevee"
    return "NOMINAL", "aucune donnee pour ces filtres"


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
def sidebar_filters(df_all: pd.DataFrame):
    logo_inner = (f'<img src="{LOGO_URI}" alt="Keystone Group">' if LOGO_URI
                  else '<span style="color:#fff;font-size:.9rem;">🛡</span>')
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
        text = st.text_input("Recherche rapide", placeholder="🔍  IP, hash, description…",
                              label_visibility="collapsed")

    st.sidebar.markdown('<div class="th-filter-eyebrow">◈ Threat Control</div>', unsafe_allow_html=True)

    # --- Periode (from / to + presets) ---
    with st.sidebar.expander("🕐 PERIODE", expanded=True):
        preset = st.selectbox(
            "Periode", ["Tout", "Dernieres 24h", "7 derniers jours",
                        "30 derniers jours", "Personnalise"], label_visibility="collapsed")
        dmin, dmax = data.date_bounds(df_all)
        if preset == "Personnalise":
            c1, c2 = st.columns(2)
            start = c1.date_input("Du", value=dmin, min_value=dmin, max_value=dmax)
            end = c2.date_input("Au", value=dmax, min_value=dmin, max_value=dmax)
        else:
            start, end = data.preset_range(df_all, preset)
            st.caption(f"Du {start} au {end}")

    # --- Severite (pastilles compactes, une couleur par niveau) ---
    with st.sidebar.expander("🎯 SEVERITE", expanded=True):
        with st.container(key="sev_pills"):
            c_crit = st.checkbox("CRIT", value=True, key="f_sev_critical")
            c_high = st.checkbox("HIGH", value=True, key="f_sev_high")
            c_med = st.checkbox("MED", value=True, key="f_sev_medium")
            c_low = st.checkbox("LOW", value=True, key="f_sev_low")
        sevs = [s for s, v in zip(["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                                   [c_crit, c_high, c_med, c_low]) if v]

    # --- Risk score (slider double poignee) ---
    with st.sidebar.expander("📊 RISK SCORE", expanded=True):
        rmin, rmax = st.slider("Risk score", 0, 100, (0, 100), step=5,
                                label_visibility="collapsed")

    # --- Detecteur / MITRE ---
    with st.sidebar.expander("🔬 DETECTEUR & MITRE", expanded=False):
        detectors = ["Tous"] + (sorted(df_all["detector"].dropna().unique())
                                if not df_all.empty else [])
        det = st.selectbox("Detecteur", detectors)
        mitres = ["Toutes"] + (sorted(df_all["mitre"].dropna().unique())
                               if not df_all.empty else [])
        mitre = st.selectbox("Technique MITRE", mitres)

    # --- IP source / destination ---
    with st.sidebar.expander("🌐 RESEAU (IP)", expanded=False):
        src = st.text_input("IP source contient")
        dst = st.text_input("IP destination contient")

    # --- CTI / correlation ---
    with st.sidebar.expander("🔗 CTI & CORRELATION", expanded=False):
        c3, c4 = st.columns(2)
        cti_only = c3.toggle("CTI ✓")
        corr_only = c4.toggle("Correles")

    # --- Application des filtres ---
    df = data.filter_by_period(df_all, start, end)
    df = data.filter_alerts(df, severities=sevs, detector=det, mitre=mitre,
                            min_risk=rmin, max_risk=rmax, src_ip=src or None,
                            dst_ip=dst or None, cti_only=cti_only,
                            correlated_only=corr_only, text=text or None)

    # --- Recapitulatif + export global ---
    st.sidebar.divider()
    st.sidebar.caption(f"**{len(df)}** / {len(df_all)} alerte(s) apres filtres")
    if not df.empty:
        st.sidebar.download_button(
            "⬇️ Exporter la selection (CSV)",
            df.drop(columns=["sev_rank"], errors="ignore").to_csv(index=False)
              .encode("utf-8"),
            "threathunter_selection.csv", "text/csv",
            use_container_width=True)
    if st.sidebar.button("🔄 Rafraichir", use_container_width=True):
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

    perforated_divider()
    a, b, c = st.columns(3)
    with a:
        st.subheader("Risk Level Distribution")
        if k["total"] == 0:
            empty_state("no alerts", hint="Distribution appears once alerts come in.")
        else:
            sc = data.severity_counts(df)
            fig = px.pie(sc, names="severity", values="count", hole=0.55,
                         color="severity", color_discrete_map=data.SEV_COLORS)
            fig.update_layout(height=230, showlegend=True,
                               legend=dict(font=dict(size=10)))
            fig.update_traces(marker=dict(line=dict(color=TOKENS["canvas"], width=2)))
            st.plotly_chart(themed(fig), use_container_width=True, key="ov_severity_pie")
    with b:
        st.subheader("Threat Activity Timeline")
        if df.empty or df["timestamp"].isna().all():
            empty_state("no temporal data")
        else:
            t = df.dropna(subset=["timestamp"])
            per = t.set_index("timestamp").resample("15min").size().reset_index(name="count")
            fig2 = px.area(per, x="timestamp", y="count")
            fig2.update_traces(line_color=TOKENS["primary"], fillcolor="rgba(255,43,60,0.14)")
            fig2.update_layout(height=230)
            st.plotly_chart(themed(fig2), use_container_width=True, key="ov_timeline")
    with c:
        st.subheader("Top MITRE ATT&CK")
        ranked_list(_top_list(df, "mitre", 6))

    perforated_divider()
    d, e = st.columns([1.4, 1])
    with d:
        st.subheader("Live Threat Map")
        st.caption("Network flow · source → destination (top active connections)")
        fig3 = threat_flow_map(df) if not df.empty else None
        if fig3 is None:
            empty_state("no active connections for these filters")
        else:
            st.plotly_chart(themed(fig3), use_container_width=True, key="ov_threat_map")
    with e:
        st.subheader("Top IOCs")
        ranked_list(_top_list(df, "src_ip", 6))

    perforated_divider()
    f, g = st.columns([1.4, 1])
    with f:
        st.subheader("Network Activity")
        st.caption("Alert volume by detector")
        if df.empty:
            empty_state("no data")
        else:
            st.plotly_chart(themed(_gradient_bar(data.top_counts(df, "detector", 8), "detector")),
                             use_container_width=True, key="ov_network")
    with g:
        st.subheader("Services")
        status_row("MongoDB", online="db_error" not in st.session_state)
        status_row("MISP", online=True, detail=f"{len(getattr(settings,'CTI_FEEDS',[]))} feeds")
        status_row("OpenCTI", online=False, detail="connector stubbed")

    perforated_divider()
    st.subheader("Recent Alerts")
    if df.empty:
        empty_state("no alerts for current filters",
                     hint="Widen the time range or run the pipeline: python3 app.py --pcap <capture>")
        return
    st.dataframe(style_severity(df.head(12)[["timestamp", "severity", "risk_score", "detector",
                              "src_ip", "dst_ip", "mitre"]]),
                 use_container_width=True, hide_index=True)


# ─── Page 2 — Alerts ───────────────────────────────────────────
def page_alerts(df):
    section_header("Alerts", eyebrow="Filtered list + detail")
    if df.empty:
        empty_state("aucune alerte pour ces filtres")
        return
    f = df.sort_values(["sev_rank", "risk_score"], ascending=False)
    st.caption(f"{len(f)} alerte(s)")
    st.dataframe(
        style_severity(f[["timestamp", "severity", "risk_score", "confidence", "detector",
           "src_ip", "dst_ip", "mitre", "correlated_count", "description"]]),
        use_container_width=True, hide_index=True)

    st.subheader("Detail")
    idx = st.selectbox("Choisir une alerte", f.index,
                       format_func=lambda i: f"{f.loc[i,'severity']} — "
                       f"{f.loc[i,'detector']} ({f.loc[i,'src_ip']})")
    row = f.loc[idx]
    # Le tampon CRITICAL n'apparait que sur CETTE alerte-la : le seul
    # orange tolere sur la vue (les autres severites restent en badge neutre).
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
        st.info(f"Incident correle — {row['correlated_count']} alertes "
                f"({', '.join(row['related_detectors'])})")
    if data._is_cti_hit(row["cti_context"]):
        st.success("Enrichissement CTI")
        code_well(_pretty_json(row["cti_context"]), label="CTI CONTEXT")
    with st.expander("Preuves (evidence)"):
        code_well(_pretty_json(row["evidence"]), label="EVIDENCE")


# ─── Page 3 — IOC Intelligence ──────────────────────────────────
def page_ioc(df):
    section_header("IOC Intelligence", eyebrow="IP · domain · hash · CTI tag")
    term = st.text_input("Indicateur", placeholder="ex: 203.0.113.66")
    if not term:
        empty_state("en attente d'un indicateur", hint="IP, domaine, hash ou tag CTI a rechercher.")
        return
    code_well(term, label="QUERY")
    res = data.search_iocs(df, term)
    if res.empty:
        empty_state(f"aucune correspondance pour « {term} »")
        return
    stat_col, _ = st.columns([1, 3])
    with stat_col:
        kpi_card(f"MATCH{'ES' if len(res) > 1 else ''}", len(res), accent=(res["sev_rank"].max() >= 4))
    st.write("")
    st.dataframe(style_severity(res[["timestamp", "severity", "detector", "src_ip", "dst_ip",
                      "mitre", "risk_score", "description"]]),
                 use_container_width=True, hide_index=True)


# ─── Page 4 — Network Activity ─────────────────────────────────
def _gradient_bar(counts_df, col):
    fig = px.bar(counts_df, x="count", y=col, orientation="h",
                 color="count", color_continuous_scale=[TOKENS["surface_bone"], TOKENS["primary"]])
    fig.update_layout(coloraxis_showscale=False, yaxis=dict(categoryorder="total ascending"))
    fig.update_traces(marker_line_width=0)
    return fig


def page_network(df):
    section_header("Network Activity", eyebrow="Top talkers & techniques")
    if df.empty:
        empty_state("aucune alerte pour ces filtres")
        return

    top_src = data.top_counts(df, "src_ip", 10)
    if not top_src.empty:
        offender = top_src.iloc[0]
        oc1, oc2 = st.columns([1, 3])
        with oc1:
            kpi_card("Top offender", int(offender["count"]),
                     delta=f"{offender['src_ip']} · source la plus active", accent=True)
        with oc2:
            st.write("")
    perforated_divider()

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Top IP sources")
        st.plotly_chart(themed(_gradient_bar(top_src, "src_ip")), use_container_width=True,
                         key="net_top_src")
    with c2:
        st.subheader("Top IP destinations")
        st.plotly_chart(themed(_gradient_bar(data.top_counts(df, "dst_ip", 10), "dst_ip")),
                         use_container_width=True, key="net_top_dst")
    c3, c4 = st.columns(2)
    with c3:
        st.subheader("Alertes par detecteur")
        st.plotly_chart(themed(_gradient_bar(data.top_counts(df, "detector", 12), "detector")),
                         use_container_width=True, key="net_detector")
    with c4:
        st.subheader("Techniques MITRE ATT&CK")
        fig = px.pie(data.top_counts(df, "mitre", 12), names="mitre", values="count", hole=0.45)
        fig.update_traces(marker=dict(line=dict(color=TOKENS["canvas"], width=2)))
        st.plotly_chart(themed(fig), use_container_width=True, key="net_mitre_pie")


# ─── Page 5 — Threat Timeline ──────────────────────────────────
SEV_SYMBOLS = {"CRITICAL": "diamond", "HIGH": "triangle-up", "MEDIUM": "circle", "LOW": "circle"}


def page_timeline(df):
    section_header("Threat Timeline", eyebrow="Sequence of events")
    if df.empty or df["timestamp"].isna().all():
        empty_state("pas de donnees temporelles pour ces filtres")
        return
    t = df.dropna(subset=["timestamp"]).copy()
    fig = px.scatter(t, x="timestamp", y="severity", color="severity",
                     color_discrete_map=data.SEV_COLORS,
                     symbol="severity", symbol_map=SEV_SYMBOLS,
                     size=t["risk_score"].fillna(10),
                     hover_data=["detector", "src_ip", "dst_ip", "mitre"],
                     category_orders={"severity": ["LOW","MEDIUM","HIGH","CRITICAL"]})
    fig.update_layout(height=420, showlegend=False)
    fig.update_traces(marker=dict(line=dict(color=TOKENS["canvas"], width=1)))
    st.plotly_chart(themed(fig), use_container_width=True, key="timeline_scatter")
    st.subheader("Volume dans le temps")
    per = t.set_index("timestamp").resample("1min").size().reset_index(name="count")
    fig2 = px.area(per, x="timestamp", y="count", template=data.PLOTLY_TEMPLATE)
    fig2.update_traces(line_color=TOKENS["primary"],
                        fillcolor="rgba(255,43,60,0.14)")
    st.plotly_chart(themed(fig2), use_container_width=True, key="timeline_volume")


# ─── Page 6 — Hunting Queries ──────────────────────────────────
def page_hunting(df):
    section_header("Hunting Queries", eyebrow="Free-form investigation on the current selection")
    if df.empty:
        empty_state("aucune alerte pour ces filtres")
        return
    kpi_strip([
        {"label": "Resultats", "value": len(df)},
        {"label": "Detecteurs", "value": df["detector"].nunique()},
        {"label": "IP sources", "value": df["src_ip"].nunique()},
        {"label": "Risk moyen", "value": int(df["risk_score"].mean()) if df["risk_score"].notna().any() else 0},
    ])
    perforated_divider()
    show = df[["timestamp", "severity", "risk_score", "detector",
               "src_ip", "dst_ip", "mitre", "description"]]
    st.dataframe(style_severity(show), use_container_width=True, hide_index=True)
    st.download_button("⬇️ Exporter ce resultat (CSV)",
                       show.to_csv(index=False).encode("utf-8"),
                       "hunting_export.csv", "text/csv")


# ─── Page 7 — Reports ───────────────────────────────────────────
def page_reports(df):
    section_header("Reports", eyebrow="Executive summary of the current selection")
    k = data.compute_kpis(df)
    level, level_detail = threat_level(k)
    threat_level_banner(level, level_detail)

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
        st.download_button("⬇ Export CSV",
                           df.drop(columns=["sev_rank"], errors="ignore").to_csv(index=False).encode("utf-8"),
                           "threathunter_report.csv", "text/csv", use_container_width=True)
    with exp2:
        summary = {
            "generated_for": f"{len(df)} alerts",
            "threat_level": level,
            "kpis": k,
            "top_mitre": _top_list(df, "mitre", 10),
            "top_detectors": _top_list(df, "detector", 10),
        }
        st.download_button("⬇ Export Summary (JSON)",
                           _pretty_json(summary).encode("utf-8"),
                           "threathunter_report_summary.json", "application/json",
                           use_container_width=True)


# ─── Page 8 — Settings ──────────────────────────────────────────
def page_settings(df):
    section_header("Settings", eyebrow="Read-only")
    st.subheader("Etat des services")
    status_row("MongoDB", online="db_error" not in st.session_state,
                detail="injoignable — mode degrade" if "db_error" in st.session_state else "connecte")
    status_row("MISP", online=True, detail=f"{len(getattr(settings,'CTI_FEEDS',[]))} flux configures")
    status_row("OpenCTI", online=False, detail="connecteur code, non branche")

    perforated_divider()
    st.subheader("Base de donnees")
    code_well(f"MONGO_URI = {getattr(settings,'MONGO_URI','N/A')}\n"
              f"DB_NAME   = {getattr(settings,'DB_NAME','N/A')}")
    st.subheader("Flux CTI")
    feeds = getattr(settings, "CTI_FEEDS", [])
    if feeds:
        st.markdown(" ".join(mono_chip(f) for f in feeds), unsafe_allow_html=True)
    else:
        st.caption("Aucun flux configure.")
    st.subheader("Seuils de detection")
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
