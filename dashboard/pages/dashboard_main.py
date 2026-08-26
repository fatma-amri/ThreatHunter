"""
Dashboard ThreatHunter - Streamlit + Plotly.

7 pages (navigation barre laterale) avec un PANNEAU DE FILTRES GLOBAL
applique a toutes les pages : periode (from/to + presets), severite,
risk score, detecteur, technique MITRE, IP source/destination, CTI
confirmee, incidents correles, recherche libre.

Lancement :
    streamlit run dashboard/main.py --server.port 8501
    # acces depuis le Mac : http://192.168.100.10:8501
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from database.db import Database
from config import settings
from dashboard import data

st.set_page_config(page_title="ThreatHunter SOC", page_icon="🛡️", layout="wide")
MAX_ALERTS = 2000

# ─── Style (touches creatives, CSS leger) ──────────────────────
st.markdown("""
<style>
  .block-container {padding-top: 2rem;}
  div[data-testid="stMetric"] {
      background: #0f172a; border: 1px solid #1e293b; border-radius: 12px;
      padding: 14px 16px; color: #e2e8f0;
  }
  div[data-testid="stMetricValue"] {font-size: 1.8rem;}
  .th-chip {display:inline-block; background:#1e293b; color:#cbd5e1;
      padding:2px 10px; border-radius:999px; font-size:0.75rem; margin:2px;}
  .th-title {font-size:1.6rem; font-weight:700; margin-bottom:0;}
  .th-sub {color:#64748b; margin-top:0;}
</style>
""", unsafe_allow_html=True)


@st.cache_data(ttl=30)
def load_data() -> pd.DataFrame:
    try:
        db = Database()
        return data.to_dataframe(db.get_alerts(limit=MAX_ALERTS))
    except Exception as e:                       # noqa: BLE001
        st.session_state["db_error"] = str(e)
        return data.to_dataframe([])


def sev_badge(sev: str) -> str:
    color = data.SEV_COLORS.get(sev, "#6b7280")
    return f"<span style='background:{color};color:white;padding:2px 8px;" \
           f"border-radius:6px;font-size:0.8em'>{sev}</span>"


def risk_gauge(value: int):
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=value or 0,
        gauge={"axis": {"range": [0, 100]},
               "bar": {"color": "#b91c1c" if (value or 0) >= 70 else "#ca8a04"},
               "steps": [{"range": [0, 45], "color": "#dbeafe"},
                         {"range": [45, 70], "color": "#fef9c3"},
                         {"range": [70, 100], "color": "#fee2e2"}]},
        title={"text": "Risk score max"}))
    fig.update_layout(height=240, margin=dict(l=20, r=20, t=40, b=10))
    return fig


# ═══════════════════════════════════════════════════════════════
#  PANNEAU DE FILTRES GLOBAL (barre laterale) -> DataFrame filtre
# ═══════════════════════════════════════════════════════════════
def sidebar_filters(df_all: pd.DataFrame):
    st.sidebar.title("🛡️ ThreatHunter")
    page = st.sidebar.radio("Navigation", list(PAGES.keys()))
    st.sidebar.divider()
    st.sidebar.subheader("🔎 Filtres")

    # --- Periode (from / to + presets) ---
    preset = st.sidebar.selectbox(
        "Periode", ["Tout", "Dernieres 24h", "7 derniers jours",
                    "30 derniers jours", "Personnalise"])
    dmin, dmax = data.date_bounds(df_all)
    if preset == "Personnalise":
        c1, c2 = st.sidebar.columns(2)
        start = c1.date_input("Du", value=dmin, min_value=dmin, max_value=dmax)
        end = c2.date_input("Au", value=dmax, min_value=dmin, max_value=dmax)
    else:
        start, end = data.preset_range(df_all, preset)
        st.sidebar.caption(f"Du {start} au {end}")

    # --- Severite / risk ---
    sevs = st.sidebar.multiselect(
        "Severite", ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    rmin, rmax = st.sidebar.slider("Risk score", 0, 100, (0, 100), step=5)

    # --- Detecteur / MITRE ---
    detectors = ["Tous"] + (sorted(df_all["detector"].dropna().unique())
                            if not df_all.empty else [])
    det = st.sidebar.selectbox("Detecteur", detectors)
    mitres = ["Toutes"] + (sorted(df_all["mitre"].dropna().unique())
                           if not df_all.empty else [])
    mitre = st.sidebar.selectbox("Technique MITRE", mitres)

    # --- IP / toggles / recherche ---
    src = st.sidebar.text_input("IP source contient")
    dst = st.sidebar.text_input("IP destination contient")
    c3, c4 = st.sidebar.columns(2)
    cti_only = c3.toggle("CTI ✓")
    corr_only = c4.toggle("Correles")
    text = st.sidebar.text_input("Recherche libre")

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


# ─── Page 1 — Home ─────────────────────────────────────────────
def page_home(df):
    st.markdown("<p class='th-title'>Vue d'ensemble</p>"
                "<p class='th-sub'>Synthese des alertes qualifiees</p>",
                unsafe_allow_html=True)
    k = data.compute_kpis(df)
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Alertes", k["total"])
    c2.metric("Critiques", k["critical"])
    c3.metric("Elevees", k["high"])
    c4.metric("Confirmees CTI", k["cti_hits"])
    c5.metric("Incidents correles", k["correlated"])
    c6.metric("Sources", k["distinct_sources"])

    st.divider()
    a, b, c = st.columns([1.2, 1, 1])
    with a:
        st.subheader("Repartition par severite")
        sc = data.severity_counts(df)
        fig = px.pie(sc, names="severity", values="count", hole=0.55,
                     color="severity", color_discrete_map=data.SEV_COLORS,
                     template=data.PLOTLY_TEMPLATE)
        fig.update_layout(height=300, showlegend=True)
        st.plotly_chart(fig, use_container_width=True)
    with b:
        st.subheader("Niveau de risque")
        st.plotly_chart(risk_gauge(k["max_risk"]), use_container_width=True)
        st.caption(f"Risk moyen : {k['avg_risk']}")
    with c:
        st.subheader("Services")
        st.write("🟢 MongoDB")
        st.write(f"🟢 MISP · {len(getattr(settings,'CTI_FEEDS',[]))} flux")
        st.write("🟡 OpenCTI · connecteur code")

    st.divider()
    st.subheader("Alertes recentes")
    if df.empty:
        st.info("Aucune alerte pour ces filtres. Elargis la periode ou lance "
                "le pipeline : `python3 app.py --pcap <capture>`")
        return
    st.dataframe(df.head(12)[["timestamp", "severity", "risk_score", "detector",
                              "src_ip", "dst_ip", "mitre"]],
                 use_container_width=True, hide_index=True)


# ─── Page 2 — Alerts ───────────────────────────────────────────
def page_alerts(df):
    st.markdown("<p class='th-title'>Alertes</p>"
                "<p class='th-sub'>Liste filtree + detail</p>",
                unsafe_allow_html=True)
    if df.empty:
        st.info("Aucune alerte pour ces filtres.")
        return
    f = df.sort_values(["sev_rank", "risk_score"], ascending=False)
    st.caption(f"{len(f)} alerte(s)")
    st.dataframe(
        f[["timestamp", "severity", "risk_score", "confidence", "detector",
           "src_ip", "dst_ip", "mitre", "correlated_count", "description"]],
        use_container_width=True, hide_index=True)

    st.subheader("Detail")
    idx = st.selectbox("Choisir une alerte", f.index,
                       format_func=lambda i: f"{f.loc[i,'severity']} — "
                       f"{f.loc[i,'detector']} ({f.loc[i,'src_ip']})")
    row = f.loc[idx]
    st.markdown(sev_badge(row["severity"]), unsafe_allow_html=True)
    st.write(f"**{row['detector']}** · MITRE {row['mitre']} · "
             f"risk {row['risk_score']} · confidence {row['confidence']}")
    st.write(row["description"])
    if row["correlated_count"] > 1:
        st.info(f"Incident correle — {row['correlated_count']} alertes "
                f"({', '.join(row['related_detectors'])})")
    if data._is_cti_hit(row["cti_context"]):
        st.success("Enrichissement CTI")
        st.json(row["cti_context"])
    with st.expander("Preuves (evidence)"):
        st.json(row["evidence"])


# ─── Page 3 — IOC Search ───────────────────────────────────────
def page_ioc(df):
    st.markdown("<p class='th-title'>Recherche d'IOC</p>"
                "<p class='th-sub'>IP · domaine · hash · tag CTI</p>",
                unsafe_allow_html=True)
    term = st.text_input("Indicateur", placeholder="ex: 203.0.113.66")
    if not term:
        st.caption("Astuce : les filtres de la barre laterale s'appliquent aussi ici.")
        return
    res = data.search_iocs(df, term)
    if res.empty:
        st.warning(f"Aucune alerte ne correspond a « {term} ».")
        return
    st.success(f"{len(res)} alerte(s)")
    st.dataframe(res[["timestamp", "severity", "detector", "src_ip", "dst_ip",
                      "mitre", "risk_score", "description"]],
                 use_container_width=True, hide_index=True)


# ─── Page 4 — Network Activity ─────────────────────────────────
def page_network(df):
    st.markdown("<p class='th-title'>Activite reseau</p>"
                "<p class='th-sub'>Top talkers & techniques</p>",
                unsafe_allow_html=True)
    if df.empty:
        st.info("Aucune alerte pour ces filtres.")
        return
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Top IP sources")
        st.plotly_chart(px.bar(data.top_counts(df, "src_ip", 10),
                        x="count", y="src_ip", orientation="h",
                        template=data.PLOTLY_TEMPLATE), use_container_width=True)
    with c2:
        st.subheader("Top IP destinations")
        st.plotly_chart(px.bar(data.top_counts(df, "dst_ip", 10),
                        x="count", y="dst_ip", orientation="h",
                        template=data.PLOTLY_TEMPLATE), use_container_width=True)
    c3, c4 = st.columns(2)
    with c3:
        st.subheader("Alertes par detecteur")
        st.plotly_chart(px.bar(data.top_counts(df, "detector", 12),
                        x="count", y="detector", orientation="h",
                        template=data.PLOTLY_TEMPLATE), use_container_width=True)
    with c4:
        st.subheader("Techniques MITRE ATT&CK")
        st.plotly_chart(px.pie(data.top_counts(df, "mitre", 12),
                        names="mitre", values="count",
                        template=data.PLOTLY_TEMPLATE), use_container_width=True)


# ─── Page 5 — Threat Timeline ──────────────────────────────────
def page_timeline(df):
    st.markdown("<p class='th-title'>Chronologie</p>"
                "<p class='th-sub'>Sequence des menaces</p>",
                unsafe_allow_html=True)
    if df.empty or df["timestamp"].isna().all():
        st.info("Pas de donnees temporelles pour ces filtres.")
        return
    t = df.dropna(subset=["timestamp"]).copy()
    fig = px.scatter(t, x="timestamp", y="severity", color="severity",
                     color_discrete_map=data.SEV_COLORS,
                     size=t["risk_score"].fillna(10),
                     hover_data=["detector", "src_ip", "dst_ip", "mitre"],
                     category_orders={"severity": ["LOW","MEDIUM","HIGH","CRITICAL"]},
                     template=data.PLOTLY_TEMPLATE)
    fig.update_layout(height=420, showlegend=False)
    st.plotly_chart(fig, use_container_width=True)
    st.subheader("Volume dans le temps")
    per = t.set_index("timestamp").resample("1min").size().reset_index(name="count")
    st.plotly_chart(px.area(per, x="timestamp", y="count",
                    template=data.PLOTLY_TEMPLATE), use_container_width=True)


# ─── Page 6 — Hunting Queries ──────────────────────────────────
def page_hunting(df):
    st.markdown("<p class='th-title'>Requetes de hunting</p>"
                "<p class='th-sub'>Investigation libre sur la selection filtree</p>",
                unsafe_allow_html=True)
    if df.empty:
        st.info("Aucune alerte pour ces filtres.")
        return
    st.caption(f"{len(df)} alerte(s) dans la selection courante "
               "(affinez via la barre laterale)")
    show = df[["timestamp", "severity", "risk_score", "detector",
               "src_ip", "dst_ip", "mitre", "description"]]
    st.dataframe(show, use_container_width=True, hide_index=True)
    st.download_button("⬇️ Exporter ce resultat (CSV)",
                       show.to_csv(index=False).encode("utf-8"),
                       "hunting_export.csv", "text/csv")


# ─── Page 7 — Settings ─────────────────────────────────────────
def page_settings(df):
    st.markdown("<p class='th-title'>Configuration</p>"
                "<p class='th-sub'>Lecture seule</p>", unsafe_allow_html=True)
    st.subheader("Base de donnees")
    st.code(f"MONGO_URI = {getattr(settings,'MONGO_URI','N/A')}\n"
            f"DB_NAME   = {getattr(settings,'DB_NAME','N/A')}")
    st.subheader("Flux CTI")
    for feed in getattr(settings, "CTI_FEEDS", []):
        st.write(f"• {feed}")
    st.subheader("Seuils de detection")
    st.json(getattr(settings, "THRESHOLDS", {}))


PAGES = {
    "🏠 Home": page_home,
    "🚨 Alerts": page_alerts,
    "🔍 IOC Search": page_ioc,
    "🌐 Network Activity": page_network,
    "⏱️ Threat Timeline": page_timeline,
    "🎯 Hunting Queries": page_hunting,
    "⚙️ Settings": page_settings,
}


def main():
    df_all = load_data()
    page, df = sidebar_filters(df_all)
    if "db_error" in st.session_state:
        st.sidebar.error("MongoDB injoignable — mode degrade")
    PAGES[page](df)


main()
