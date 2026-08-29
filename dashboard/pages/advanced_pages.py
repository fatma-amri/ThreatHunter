"""
Pages avancees du dashboard ThreatHunter — outil d'investigation SOC.

  * page_investigation(df)  — drill-down par entite (IP) + vue kill-chain
  * page_attack_matrix(df)  — matrice MITRE ATT&CK (observe vs catalogue cible)

Memes conventions que dashboard_main.py : df est DEJA filtre par Threat
Control (barre laterale), mode degrade = df vide -> empty_state, jamais de
crash. Aucun style nouveau : uniquement les helpers de theme.py et les
tokens existants (aucune couleur introduite).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import html
import pandas as pd
import plotly.express as px
import streamlit as st

import dashboard_data as data
from dashboard.pages.theme import (
    section_header, panel_title, perforated_divider, kpi_card, kpi_strip,
    severity_badge, mono_chip, empty_state, ranked_list, plotly_layout,
    TOKENS,
)

# Formes de marqueur par severite — alignees sur page_timeline (dashboard_main).
SEV_SYMBOLS = {"CRITICAL": "diamond", "HIGH": "triangle-up",
               "MEDIUM": "circle", "LOW": "circle"}


def _themed(fig):
    fig.update_layout(**plotly_layout())
    return fig


def _hex_to_rgb(hexcolor: str) -> str:
    h = hexcolor.lstrip("#")
    return ",".join(str(int(h[i:i + 2], 16)) for i in (0, 2, 4))


def _style_severity(df: pd.DataFrame, column: str = "severity"):
    """Colore la colonne severite d'un dataframe natif — copie locale du
    helper de dashboard_main (importer dashboard_main executerait main())."""
    if column not in df.columns:
        return df

    def _cell(val):
        color = data.SEV_COLORS.get(val, TOKENS["mute"])
        return (f"background-color: rgba({_hex_to_rgb(color)}, 0.16); "
                f"color: {color}; font-weight: 700;")

    return df.style.map(_cell, subset=[column])


def _fmt_ts(ts) -> str:
    if ts is None or pd.isna(ts):
        return "—"
    return pd.Timestamp(ts).strftime("%Y-%m-%d %H:%M")


_ALERT_COLS = ["timestamp", "severity", "risk_score", "confidence", "detector",
               "src_ip", "dst_ip", "mitre", "correlated_count", "description"]

_ALERT_COL_CONFIG = {
    "risk_score": st.column_config.ProgressColumn(
        "Risk", min_value=0, max_value=100, format="%d"),
    "confidence": st.column_config.ProgressColumn(
        "Conf.", min_value=0.0, max_value=1.0, format="%.2f"),
    "correlated_count": st.column_config.NumberColumn("Corr."),
}


# ═══════════════════════════════════════════════════════════════════════
#  PAGE — Investigation (drill-down par entite + kill-chain)
# ═══════════════════════════════════════════════════════════════════════
def page_investigation(df: pd.DataFrame) -> None:
    section_header("Investigation", eyebrow="Entity drill-down")

    if df.empty:
        empty_state("no alerts for current filters",
                    hint="Widen Threat Control filters, or run the pipeline: "
                         "python3 app.py --pcap <capture>")
        return

    entities = data.entity_list(df)
    if not entities:
        empty_state("no host entities in the current selection")
        return

    focus = st.session_state.get("focus_entity")
    default_idx = entities.index(focus) if focus in entities else 0
    ip = st.selectbox("Entity (source or destination IP)", entities,
                      index=default_idx, key="inv_entity")
    # Persiste le focus pour les allers-retours depuis la page Alerts.
    st.session_state.focus_entity = ip

    prof = data.entity_profile(df, ip)

    st.markdown(f"Host fiche — {mono_chip(ip)}", unsafe_allow_html=True)
    kpi_strip([
        {"label": "Aggregated Risk", "value": prof["risk_max"],
         "accent": prof["risk_max"] >= 90},
        {"label": "Alerts", "value": prof["alert_count"]},
        {"label": "Max Severity", "value": (prof["max_severity"] or "—").title()},
        {"label": "CTI Hits", "value": prof["cti_hits"]},
        {"label": "First Seen", "value": _fmt_ts(prof["first_seen"])},
        {"label": "Last Seen", "value": _fmt_ts(prof["last_seen"])},
    ])

    perforated_divider()

    # --- Role de l'IP : source (attaquant) vs destination (cible) ---
    r1, r2, r3 = st.columns(3)
    with r1:
        kpi_card("As Source (attacker)", prof["as_source"],
                 delta=f"{prof['destination_count']} distinct destination(s)")
    with r2:
        kpi_card("As Destination (target)", prof["as_destination"],
                 delta="inbound alerts against this host")
    with r3:
        role = ("Attacker" if prof["as_source"] and not prof["as_destination"]
                else "Target" if prof["as_destination"] and not prof["as_source"]
                else "Both" if prof["as_source"] and prof["as_destination"]
                else "—")
        kpi_card("Observed Role", role,
                 delta=f"{prof['detector_count']} detector(s) triggered")

    perforated_divider()

    c1, c2, c3 = st.columns(3)
    with c1:
        with st.container(key="panel_inv_detectors"):
            panel_title("Detectors Triggered")
            _ranked_from_counts(data.entity_detectors(df, ip, 6), "detector")
    with c2:
        with st.container(key="panel_inv_dests"):
            panel_title("Destinations Contacted", subtitle="as source")
            _ranked_from_counts(data.entity_destinations(df, ip, 6), "dst_ip")
    with c3:
        with st.container(key="panel_inv_mitre"):
            panel_title("MITRE Techniques")
            _ranked_from_counts(data.entity_techniques(df, ip, 6), "mitre")

    perforated_divider()

    # --- Mini-timeline des alertes de l'entite ---
    with st.container(key="panel_inv_timeline"):
        panel_title("Entity Timeline", subtitle="alerts for this host over time")
        tl = data.entity_timeline(df, ip)
        if tl.empty:
            empty_state("no time-stamped alerts for this entity")
        else:
            fig = px.scatter(
                tl, x="timestamp", y="severity", color="severity",
                color_discrete_map=data.SEV_COLORS,
                symbol="severity", symbol_map=SEV_SYMBOLS,
                size=tl["risk_score"].fillna(10),
                hover_data=["detector", "src_ip", "dst_ip", "mitre",
                            "correlated_count"],
                category_orders={"severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]})
            fig.update_layout(height=280, showlegend=False)
            fig.update_traces(marker=dict(line=dict(color=TOKENS["canvas"], width=1)))
            st.plotly_chart(_themed(fig), use_container_width=True,
                            key="inv_timeline", config={"displayModeBar": False})

    perforated_divider()

    # --- Vue KILL-CHAIN ---
    with st.container(key="panel_inv_killchain"):
        panel_title("Attack Kill-Chain",
                    subtitle="sequence reconstructed from this source")
        kc = data.kill_chain(df, ip)
        if not kc["steps"]:
            empty_state("no source-side activity to sequence for this entity",
                        hint="This host only appears as a destination in the "
                             "current selection.")
        else:
            _render_kill_chain(kc)

    perforated_divider()

    # --- Table des alertes de l'entite ---
    with st.container(key="panel_inv_table"):
        panel_title("All Alerts for This Entity")
        sub = data.entity_alerts(df, ip)
        show = (sub.sort_values(["sev_rank", "risk_score"], ascending=False)
                   [_ALERT_COLS])
        st.dataframe(_style_severity(show), use_container_width=True,
                     hide_index=True, column_config=_ALERT_COL_CONFIG)


def _ranked_from_counts(counts_df: pd.DataFrame, col: str) -> None:
    if counts_df is None or counts_df.empty:
        empty_state("nothing to rank yet")
        return
    items = list(zip(counts_df[col].astype(str), counts_df["count"].astype(int)))
    ranked_list(items)


def _render_kill_chain(kc: dict) -> None:
    t = TOKENS

    covered = "".join(
        f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:.72rem;'
        f'color:{t["charcoal"]};border:1px solid {t["hairline"]};border-radius:6px;'
        f'padding:2px 8px;margin:0 6px 6px 0;display:inline-block;">{html.escape(tac)}</span>'
        + ('<span style="color:%s;margin-right:6px;">&#8594;</span>' % t["ash"]
           if i < len(kc["tactics"]) - 1 else "")
        for i, tac in enumerate(kc["tactics"])
    )
    st.markdown(
        f'<div style="margin-bottom:.9rem;">'
        f'<span style="font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;'
        f'color:{t["mute"]};margin-right:10px;">Tactics covered</span>{covered}</div>',
        unsafe_allow_html=True)

    rows = []
    n = len(kc["steps"])
    for i, s in enumerate(kc["steps"]):
        sev_color = data.SEV_COLORS.get(s["severity"], t["mute"])
        connector = (
            f'<div style="width:1px;height:16px;background:{t["hairline_strong"]};'
            f'margin:2px 0 2px 15px;"></div>' if i < n - 1 else "")
        dst = (f' &#8594; {mono_chip(s["dst_ip"])}' if s["dst_ip"] else "")
        tech = mono_chip(s["technique"]) if s["technique"] != "—" else ""
        approx = (' <span style="color:%s;font-size:.68rem;">(approx. time)</span>'
                  % t["ash"]) if s["approx_time"] else ""
        rows.append(f"""
        <div style="display:flex;gap:12px;align-items:flex-start;">
          <div style="width:30px;height:30px;flex-shrink:0;border-radius:8px;
                      display:flex;align-items:center;justify-content:center;
                      background:{t['surface_raised']};border:1px solid {t['hairline']};
                      font-family:'JetBrains Mono',monospace;font-size:.78rem;
                      color:{t['charcoal']};">{i + 1:02d}</div>
          <div style="flex:1;min-width:0;padding-bottom:2px;">
            <div style="font-size:.7rem;text-transform:uppercase;letter-spacing:.07em;
                        color:{t['mute']};">{html.escape(s['phase'])}</div>
            <div style="margin:.2rem 0;">
              <span style="font-weight:600;color:{t['ink']};font-size:.9rem;">{html.escape(s['detector'])}</span>
              &nbsp;<span class="th-sev-tag" style="background:rgba({_hex_to_rgb(sev_color)},0.14);
                    color:{sev_color};border:1px solid rgba({_hex_to_rgb(sev_color)},0.42);">{html.escape(s['severity'] or '—')}</span>
            </div>
            <div style="font-size:.8rem;color:{t['body']};">{tech} {html.escape(s['technique_name'])}{dst}{approx}</div>
            <div style="font-size:.78rem;color:{t['charcoal']};margin-top:.15rem;">{html.escape(s['description'][:200])}</div>
          </div>
        </div>
        {connector}
        """)
    st.markdown("\n".join(line for line in "".join(rows).splitlines() if line.strip()),
                unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════
#  PAGE — ATT&CK Matrix
# ═══════════════════════════════════════════════════════════════════════
def page_attack_matrix(df: pd.DataFrame) -> None:
    section_header("ATT&CK Matrix", eyebrow="MITRE ATT&CK coverage")

    if df.empty:
        empty_state("no alerts for current filters",
                    hint="The matrix lights up techniques observed in the "
                         "current Threat Control selection.")
        return

    grid = data.attack_matrix(df)
    if not grid:
        empty_state("no ATT&CK techniques to display")
        return
    obs = data.observed_techniques(df)
    peak = int(obs["alert_count"].max()) if not obs.empty else 1

    st.caption("Columns = ATT&CK tactics · lit cells = techniques observed in "
               "the current selection (intensity ∝ alert volume) · muted cells "
               "= target catalog, not yet observed.")

    cols = st.columns(len(grid))
    for col, column_data in zip(cols, grid):
        with col:
            with st.container(key=f"panel_atk_{_slug(column_data['tactic'])}"):
                panel_title(column_data["tactic"])
                for cell in column_data["cells"]:
                    _render_matrix_cell(cell, peak)

    sel = st.session_state.get("matrix_technique")
    perforated_divider()
    if not sel:
        empty_state("select a technique above to list its alerts")
        return

    hits = data.technique_alerts(df, sel)
    st.subheader(f"{sel} · {data.technique_name(sel)} — {len(hits)} alert(s)")
    if hits.empty:
        empty_state(f"no alerts mapped to {sel} in the current selection")
        return
    show = hits.sort_values(["sev_rank", "risk_score"], ascending=False)[_ALERT_COLS]
    st.dataframe(_style_severity(show), use_container_width=True, hide_index=True,
                 column_config=_ALERT_COL_CONFIG)


def _slug(text: str) -> str:
    return "".join(c.lower() if c.isalnum() else "_" for c in text)


def _render_matrix_cell(cell: dict, peak: int) -> None:
    t = TOKENS
    tid = cell["id"]
    if cell["observed"]:
        frac = min(1.0, cell["alert_count"] / (peak or 1))
        # Intensite = opacite d'un aplat encre (jamais l'accent rouge, reserve
        # au signal critique) — coherent avec les barres de comptage du reste
        # du dashboard.
        bg = f"rgba({_hex_to_rgb(t['ink'])},{0.06 + 0.20 * frac:.3f})"
        border = t["hairline_strong"]
        meta = f"{cell['alert_count']} alert(s) · max risk {cell['max_risk']}"
        meta_color = t["body"]
    else:
        bg = "transparent"
        border = t["hairline"]
        meta = "target catalog · not yet observed"
        meta_color = t["ash"]

    st.markdown(f"""
    <div style="border:1px solid {border};border-radius:7px;padding:8px 10px;
                margin-bottom:6px;background:{bg};
                {'opacity:.55;' if cell['target'] else ''}">
      <div style="font-family:'JetBrains Mono',monospace;font-size:.74rem;
                  color:{t['ink'] if cell['observed'] else t['mute']};">{html.escape(tid)}</div>
      <div style="font-size:.76rem;color:{t['charcoal']};line-height:1.3;
                  margin:.15rem 0;">{html.escape(cell['name'])}</div>
      <div style="font-size:.68rem;color:{meta_color};">{html.escape(meta)}</div>
    </div>
    """.replace("\n", ""), unsafe_allow_html=True)

    if cell["observed"]:
        if st.button(f"Inspect {tid}", key=f"atk_btn_{_slug(tid)}",
                     use_container_width=True):
            st.session_state.matrix_technique = tid
            st.rerun()
