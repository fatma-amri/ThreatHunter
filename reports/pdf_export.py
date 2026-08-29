"""
Export PDF d'un rapport d'incident ThreatHunter (ReportLab / Platypus).

Le rapport reflete la SELECTION COURANTE du dashboard : la fonction recoit le
DataFrame deja filtre par le module "Threat Control" (filtres globaux) et
n'interroge JAMAIS MongoDB elle-meme. Toutes les agregations proviennent de
`dashboard_data` (couche de donnees pure, factorisee) — aucun calcul refait
ici.

API
---
    build_pdf(alerts, output_path=None, *, period=None, generated_at=None,
              title="Threat Hunting Report") -> bytes

    * `alerts` : pandas.DataFrame issu de dashboard_data.to_dataframe(...)
                 (colonnes attendues : detector, severity, src_ip, dst_ip,
                 mitre, risk_score, confidence, correlated_count, cti_context,
                 evidence, timestamp, description, + sev_rank / cti_hit derivees)
                 — OU une liste de dict / d'objets Alert (converti via
                 dashboard_data.to_dataframe).
    * retourne toujours les octets du PDF (pour st.download_button) ; si
      `output_path` est fourni, ecrit aussi le fichier.
    * cas "aucune alerte" -> PDF minimal valide (page de garde + mention),
      jamais d'exception.

CLI (sans Streamlit)
-------------------
    python -m reports.pdf_export --output /tmp/threathunter_report.pdf
    python -m reports.pdf_export --mongo --limit 2000 -o /tmp/report.pdf
"""
from __future__ import annotations

import io
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional, Union
from xml.sax.saxutils import escape as _xml_escape

import pandas as pd

# --- import de la couche donnees (memes conventions que dashboard_main) ---
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "dashboard" / "pages"))
import dashboard_data as data  # noqa: E402

from reportlab.lib import colors  # noqa: E402
from reportlab.lib.enums import TA_CENTER, TA_LEFT  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # noqa: E402
from reportlab.lib.units import mm  # noqa: E402
from reportlab.lib.utils import ImageReader  # noqa: E402
from reportlab.platypus import (  # noqa: E402
    Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

# ─────────────────────────────────────────────────────────────
#  Palette — alignee sur dashboard/pages/theme.py (TOKENS / SEV)
# ─────────────────────────────────────────────────────────────
KEYSTONE_RED = colors.HexColor("#e01e2b")
INK = colors.HexColor("#0f1216")          # fond sombre (page de garde)
SLATE = colors.HexColor("#1c222b")        # bandeaux d'en-tete de table
PAPER = colors.HexColor("#ffffff")
HAIRLINE = colors.HexColor("#d7dbe0")
BODY = colors.HexColor("#2b2f37")
MUTE = colors.HexColor("#6b7280")
ROW_ALT = colors.HexColor("#f4f5f7")

# Couleurs de severite : reprises telles quelles de la couche donnees.
SEV_HEX = dict(data.SEV_COLORS)
SEV_LIST = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

_LOGO = _ROOT / "dashboard" / "pages" / "keystone-logo-reduced.png"

_PAGE_W, _PAGE_H = A4
_MARGIN = 18 * mm
_CONTENT_W = _PAGE_W - 2 * _MARGIN


# ─────────────────────────────────────────────────────────────
#  Styles
# ─────────────────────────────────────────────────────────────
def _styles() -> dict:
    base = getSampleStyleSheet()
    s = {
        "cover_title": ParagraphStyle(
            "cover_title", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=30, leading=34, textColor=PAPER, alignment=TA_CENTER),
        "cover_sub": ParagraphStyle(
            "cover_sub", parent=base["Normal"], fontSize=11, leading=16,
            textColor=colors.HexColor("#c2c8d2"), alignment=TA_CENTER),
        "cover_meta": ParagraphStyle(
            "cover_meta", parent=base["Normal"], fontSize=10, leading=18,
            textColor=colors.HexColor("#9aa3b0"), alignment=TA_CENTER),
        "h1": ParagraphStyle(
            "h1", parent=base["Heading1"], fontName="Helvetica-Bold",
            fontSize=15, leading=19, textColor=INK, spaceBefore=6, spaceAfter=8),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=11.5, leading=15, textColor=INK, spaceBefore=10, spaceAfter=5),
        "body": ParagraphStyle(
            "body", parent=base["Normal"], fontSize=9.5, leading=14,
            textColor=BODY, alignment=TA_LEFT),
        "cell": ParagraphStyle(
            "cell", parent=base["Normal"], fontSize=8.5, leading=11, textColor=BODY),
        "cell_b": ParagraphStyle(
            "cell_b", parent=base["Normal"], fontSize=8.5, leading=11,
            textColor=INK, fontName="Helvetica-Bold"),
        "level": ParagraphStyle(
            "level", parent=base["Normal"], fontSize=11, leading=15,
            fontName="Helvetica-Bold"),
    }
    return s


def _p(text, style) -> Paragraph:
    """Paragraph avec echappement XML du texte dynamique (donnees reseau)."""
    return Paragraph(_xml_escape(str(text)), style)


_LEVEL_COLOR = {
    "CRITICAL": KEYSTONE_RED,
    "ELEVATED": colors.HexColor("#f5872b"),
    "NOMINAL": colors.HexColor("#3ecf8e"),
}


# ─────────────────────────────────────────────────────────────
#  Normalisation de l'entree
# ─────────────────────────────────────────────────────────────
def _as_dataframe(alerts: Union[pd.DataFrame, Iterable]) -> pd.DataFrame:
    if isinstance(alerts, pd.DataFrame):
        return alerts
    rows = []
    for a in (alerts or []):
        rows.append(a.to_dict() if hasattr(a, "to_dict") else dict(a))
    return data.to_dataframe(rows)


def _fmt_ts(ts) -> str:
    if ts is None or (not isinstance(ts, str) and pd.isna(ts)):
        return "—"
    try:
        return pd.Timestamp(ts).strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return str(ts)


def _period_text(df: pd.DataFrame, period) -> str:
    if period and period[0] and period[1]:
        start, end = period
    else:
        start, end = data.date_bounds(df)
    if df.empty:
        return "no data in selection"
    return f"{start} → {end}"


# ─────────────────────────────────────────────────────────────
#  Habillage de page (fond de garde + pied de page)
# ─────────────────────────────────────────────────────────────
def _first_page(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(INK)
    canvas.rect(0, 0, _PAGE_W, _PAGE_H, fill=1, stroke=0)
    canvas.setFillColor(KEYSTONE_RED)
    canvas.rect(0, _PAGE_H - 6 * mm, _PAGE_W, 6 * mm, fill=1, stroke=0)
    canvas.rect(0, 0, _PAGE_W, 4 * mm, fill=1, stroke=0)
    _footer(canvas, doc, dark=True)
    canvas.restoreState()


def _later_pages(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(KEYSTONE_RED)
    canvas.setLineWidth(1.4)
    canvas.line(_MARGIN, _PAGE_H - 13 * mm, _PAGE_W - _MARGIN, _PAGE_H - 13 * mm)
    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.setFillColor(MUTE)
    canvas.drawString(_MARGIN, _PAGE_H - 11 * mm, "THREATHUNTER — THREAT HUNTING REPORT")
    _footer(canvas, doc, dark=False)
    canvas.restoreState()


def _footer(canvas, doc, dark: bool):
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#9aa3b0") if dark else MUTE)
    canvas.drawString(_MARGIN, 10 * mm, "ThreatHunter · Keystone")
    canvas.drawRightString(_PAGE_W - _MARGIN, 10 * mm, f"Page {doc.page}")


# ─────────────────────────────────────────────────────────────
#  Sections (flowables)
# ─────────────────────────────────────────────────────────────
def _cover(story, st, df, title, generated_at, period):
    story.append(Spacer(1, 45 * mm))
    if _LOGO.exists():
        try:
            iw, ih = ImageReader(str(_LOGO)).getSize()
            w = 40 * mm
            img = Image(str(_LOGO), width=w, height=w * ih / iw)
            img.hAlign = "CENTER"
            story.append(img)
            story.append(Spacer(1, 14 * mm))
        except Exception:  # noqa: BLE001 - un logo illisible ne doit pas casser le PDF
            pass
    story.append(Paragraph(title, st["cover_title"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("ThreatHunter · Keystone Group SOC", st["cover_sub"]))
    story.append(Spacer(1, 20 * mm))
    story.append(Paragraph(
        f"Generated&nbsp;&nbsp;{generated_at.strftime('%Y-%m-%d %H:%M')}", st["cover_meta"]))
    story.append(Paragraph(
        f"Period analysed&nbsp;&nbsp;{_period_text(df, period)}", st["cover_meta"]))
    story.append(Paragraph(
        f"Alerts in scope&nbsp;&nbsp;{len(df)}", st["cover_meta"]))
    story.append(PageBreak())


def _exec_summary(story, st, df, kpis, level, level_detail):
    story.append(Paragraph("Executive Summary", st["h1"]))
    lvl = ParagraphStyle("lvl_c", parent=st["level"],
                         textColor=_LEVEL_COLOR.get(level, MUTE))
    story.append(Paragraph(f"Threat level: {level} — {level_detail}", lvl))
    story.append(Spacer(1, 3 * mm))
    story.append(_p(data.executive_summary(df, kpis, level), st["body"]))
    story.append(Spacer(1, 4 * mm))


def _kpi_block(story, st, df, kpis):
    story.append(Paragraph("Key Indicators", st["h2"]))
    rows = [
        ["Total alerts", str(kpis["total"]), "Correlated incidents", str(kpis["correlated"])],
        ["CTI-confirmed IOCs", str(kpis["cti_hits"]), "Distinct sources", str(kpis["distinct_sources"])],
        ["Max risk score", str(kpis["max_risk"]), "Avg risk score", str(kpis["avg_risk"])],
    ]
    t = Table(rows, colWidths=[_CONTENT_W * x for x in (0.30, 0.15, 0.30, 0.25)])
    t.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, -1), "Helvetica", 9),
        ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 9),
        ("FONT", (2, 0), (2, -1), "Helvetica-Bold", 9),
        ("TEXTCOLOR", (0, 0), (-1, -1), BODY),
        ("TEXTCOLOR", (1, 0), (1, -1), INK),
        ("TEXTCOLOR", (3, 0), (3, -1), INK),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [PAPER, ROW_ALT]),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, HAIRLINE),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph("Severity distribution", st["h2"]))
    sc = data.severity_counts(df).set_index("severity")
    total = int(sc["count"].sum()) or 1
    body = [["Severity", "Count", "Share"]]
    for sev in SEV_LIST:
        cnt = int(sc.loc[sev, "count"]) if sev in sc.index else 0
        body.append([sev, str(cnt), f"{round(100 * cnt / total)}%"])
    t = Table(body, colWidths=[_CONTENT_W * x for x in (0.4, 0.3, 0.3)])
    style = [
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
        ("FONT", (0, 1), (-1, -1), "Helvetica-Bold", 9),
        ("BACKGROUND", (0, 0), (-1, 0), SLATE),
        ("TEXTCOLOR", (0, 0), (-1, 0), PAPER),
        ("TEXTCOLOR", (1, 1), (-1, -1), BODY),
        ("GRID", (0, 0), (-1, -1), 0.4, HAIRLINE),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]
    for i, sev in enumerate(SEV_LIST, start=1):
        style.append(("BACKGROUND", (0, i), (0, i), colors.HexColor(SEV_HEX[sev])))
        style.append(("TEXTCOLOR", (0, i), (0, i), PAPER))
    t.setStyle(TableStyle(style))
    story.append(t)
    story.append(Spacer(1, 5 * mm))


def _top_tables(story, st, df):
    story.append(Paragraph("Top MITRE ATT&amp;CK techniques &amp; detectors", st["h2"]))
    mitre = data.top_counts(df, "mitre", 8)
    det = data.top_counts(df, "detector", 8)
    half = _CONTENT_W * 0.5

    def _mk(counts_df, col, header):
        rows = [["#", header, "Hits"]]
        for i, (_, r) in enumerate(counts_df.iterrows(), start=1):
            rows.append([str(i), _p(r[col], st["cell"]), str(int(r["count"]))])
        if len(rows) == 1:
            rows.append(["—", _p("no data", st["cell"]), "0"])
        tb = Table(rows, colWidths=[8 * mm, half - 6 * mm - 8 * mm - 14 * mm, 14 * mm])
        tb.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8.5),
            ("FONT", (0, 1), (-1, -1), "Helvetica", 8.5),
            ("BACKGROUND", (0, 0), (-1, 0), SLATE),
            ("TEXTCOLOR", (0, 0), (-1, 0), PAPER),
            ("TEXTCOLOR", (0, 1), (-1, -1), BODY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PAPER, ROW_ALT]),
            ("GRID", (0, 0), (-1, -1), 0.3, HAIRLINE),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        return tb

    holder = Table(
        [[_mk(mitre, "mitre", "Technique"), _mk(det, "detector", "Detector")]],
        colWidths=[half, half])
    holder.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (0, 0), 0),
        ("RIGHTPADDING", (-1, 0), (-1, 0), 0),
        ("LEFTPADDING", (1, 0), (1, 0), 6),
    ]))
    story.append(holder)
    story.append(Spacer(1, 5 * mm))


def _alert_table(story, st, df, limit=20):
    story.append(Paragraph(f"Priority alerts (top {limit} by risk score)", st["h2"]))
    top = (df.sort_values("risk_score", ascending=False, na_position="last")
             .head(limit))
    header = ["Time", "Sev", "Risk", "Detector", "Source → Destination", "MITRE"]
    rows = [header]
    sev_seq = []
    for _, r in top.iterrows():
        sev = str(r.get("severity") or "—").upper()
        sev_seq.append(sev)
        risk = r.get("risk_score")
        risk = "—" if pd.isna(risk) else str(int(risk))
        flow = f"{r.get('src_ip') or '—'} → {r.get('dst_ip') or '—'}"
        rows.append([
            _fmt_ts(r.get("timestamp")),
            sev,
            risk,
            _p(r.get("detector") or "—", st["cell"]),
            _p(flow, st["cell"]),
            str(r.get("mitre") or "—"),
        ])
    col_w = [_CONTENT_W * x for x in (0.16, 0.11, 0.08, 0.26, 0.28, 0.11)]
    t = Table(rows, colWidths=col_w, repeatRows=1)
    style = [
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8),
        ("FONT", (0, 1), (-1, -1), "Helvetica", 8),
        ("BACKGROUND", (0, 0), (-1, 0), SLATE),
        ("TEXTCOLOR", (0, 0), (-1, 0), PAPER),
        ("TEXTCOLOR", (0, 1), (-1, -1), BODY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PAPER, ROW_ALT]),
        ("GRID", (0, 0), (-1, -1), 0.3, HAIRLINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (2, 0), (2, -1), "CENTER"),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
    ]
    for i, sev in enumerate(sev_seq, start=1):
        hexc = SEV_HEX.get(sev)
        if hexc:
            style.append(("BACKGROUND", (1, i), (1, i), colors.HexColor(hexc)))
            style.append(("TEXTCOLOR", (1, i), (1, i), PAPER))
            style.append(("FONT", (1, i), (1, i), "Helvetica-Bold", 8))
    t.setStyle(TableStyle(style))
    story.append(t)


# ─────────────────────────────────────────────────────────────
#  Point d'entree
# ─────────────────────────────────────────────────────────────
def build_pdf(alerts: Union[pd.DataFrame, Iterable],
              output_path: Optional[Union[str, Path]] = None,
              *,
              period: Optional[tuple] = None,
              generated_at: Optional[datetime] = None,
              title: str = "Threat Hunting Report") -> bytes:
    """Construit le rapport PDF de la selection et renvoie ses octets.

    Ne leve pas d'exception sur une selection vide (PDF minimal valide).
    """
    df = _as_dataframe(alerts)
    generated_at = generated_at or datetime.now()
    st = _styles()
    kpis = data.compute_kpis(df)
    level, level_detail = data.threat_level(kpis)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=_MARGIN, rightMargin=_MARGIN,
        topMargin=20 * mm, bottomMargin=18 * mm,
        title=title, author="ThreatHunter · Keystone",
        subject="Network threat hunting report",
    )

    story: list = []
    _cover(story, st, df, title, generated_at, period)
    _exec_summary(story, st, df, kpis, level, level_detail)

    if df.empty:
        story.append(Paragraph(
            "No alerts were recorded for the current selection — nothing "
            "further to report.", st["body"]))
    else:
        _kpi_block(story, st, df, kpis)
        _top_tables(story, st, df)
        _alert_table(story, st, df, limit=20)

    doc.build(story, onFirstPage=_first_page, onLaterPages=_later_pages)
    pdf = buf.getvalue()
    buf.close()

    if output_path:
        Path(output_path).write_bytes(pdf)
    return pdf


# ─────────────────────────────────────────────────────────────
#  Donnees de demonstration (CLI, sans Mongo ni Streamlit)
# ─────────────────────────────────────────────────────────────
def _demo_dataframe() -> pd.DataFrame:
    from datetime import timedelta
    t0 = datetime(2026, 8, 20, 9, 0, 0)

    def ts(m):
        return (t0 + timedelta(minutes=m)).isoformat()

    alerts = [
        {"timestamp": ts(4), "detector": "BeaconingDetector", "severity": "CRITICAL",
         "src_ip": "192.168.100.40", "dst_ip": "8.8.8.8", "mitre": "T1071.004",
         "risk_score": 95, "confidence": 0.9, "correlated_count": 3,
         "related_detectors": ["BeaconingDetector", "BruteForceDetector", "PortScanDetector"],
         "description": "Correlated incident: 3 alerts from 192.168.100.40",
         "cti_context": {"found": True, "source": "MISP", "threat": "Cobalt Strike"},
         "evidence": {"mitre_techniques": ["T1046", "T1071.004", "T1110"]}},
        {"timestamp": ts(9), "detector": "HttpsExfiltrationDetector", "severity": "HIGH",
         "src_ip": "192.168.100.40", "dst_ip": "203.0.113.5", "mitre": "T1048",
         "risk_score": 78, "confidence": 0.8, "correlated_count": 1,
         "description": "3.2 MB uploaded over HTTPS to 203.0.113.5",
         "cti_context": {}, "evidence": {}},
        {"timestamp": ts(2), "detector": "PortScanDetector", "severity": "MEDIUM",
         "src_ip": "10.0.0.5", "dst_ip": "192.168.100.50", "mitre": "T1046",
         "risk_score": 44, "confidence": 0.55, "correlated_count": 1,
         "description": "60 ports scanned on 192.168.100.50",
         "cti_context": {}, "evidence": {}},
        {"timestamp": ts(21), "detector": "BruteForceDetector", "severity": "HIGH",
         "src_ip": "10.0.0.9", "dst_ip": "192.168.100.30", "mitre": "T1110",
         "risk_score": 70, "confidence": 0.75, "correlated_count": 1,
         "description": "58 failed SSH logins on 192.168.100.30",
         "cti_context": {}, "evidence": {}},
        {"timestamp": ts(33), "detector": "DnsTunnelDetector", "severity": "LOW",
         "src_ip": "192.168.100.22", "dst_ip": "192.168.100.2", "mitre": "T1071.004",
         "risk_score": 25, "confidence": 0.4, "correlated_count": 1,
         "description": "Slightly elevated DNS entropy from 192.168.100.22",
         "cti_context": {}, "evidence": {}},
    ]
    return data.to_dataframe(alerts)


def _mongo_dataframe(limit: int) -> pd.DataFrame:
    """Charge la selection depuis MongoDB. Mode degrade : DataFrame vide si la
    base est injoignable (jamais d'exception)."""
    try:
        from database.db import Database
        return data.to_dataframe(Database().get_alerts(limit=limit))
    except Exception as exc:  # noqa: BLE001
        print(f"[pdf_export] MongoDB unreachable ({exc}) — empty report.")
        return data.to_dataframe([])


def _main(argv=None) -> int:
    import argparse

    p = argparse.ArgumentParser(description="ThreatHunter — PDF report export")
    p.add_argument("-o", "--output", default="threathunter_report_sample.pdf",
                   help="chemin du PDF a ecrire")
    p.add_argument("--mongo", action="store_true",
                   help="charger les alertes depuis MongoDB (sinon jeu de demo)")
    p.add_argument("--limit", type=int, default=2000,
                   help="nombre max d'alertes a charger depuis MongoDB")
    p.add_argument("--empty", action="store_true",
                   help="forcer une selection vide (test du PDF minimal)")
    args = p.parse_args(argv)

    if args.empty:
        df = data.to_dataframe([])
    elif args.mongo:
        df = _mongo_dataframe(args.limit)
    else:
        df = _demo_dataframe()

    pdf = build_pdf(df, output_path=args.output)
    print(f"[pdf_export] {len(pdf)} bytes -> {args.output}  ({len(df)} alert(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
