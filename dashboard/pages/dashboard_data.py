"""
Couche donnees du dashboard - fonctions pures, sans Streamlit.

Separee de l'interface pour etre testable et reutilisable (dashboard ET
rapports PDF/CSV consomment ces memes fonctions).
"""
from typing import List, Optional
from datetime import datetime, timedelta
import pandas as pd

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SEV_COLORS = {
    "CRITICAL": "#b91c1c",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#2563eb",
}
PLOTLY_TEMPLATE = "plotly_white"


def to_dataframe(alerts: List[dict]) -> pd.DataFrame:
    cols = ["id", "timestamp", "detector", "severity", "src_ip", "dst_ip",
            "mitre", "risk_score", "confidence", "correlated_count",
            "related_detectors", "description", "cti_context", "evidence"]
    if not alerts:
        return pd.DataFrame(columns=cols + ["sev_rank", "cti_hit"])
    df = pd.DataFrame(alerts)
    for c in cols:
        if c not in df.columns:
            df[c] = None
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce")
    df["confidence"] = pd.to_numeric(df["confidence"], errors="coerce")
    df["correlated_count"] = pd.to_numeric(
        df["correlated_count"], errors="coerce").fillna(1).astype(int)
    df["sev_rank"] = df["severity"].map(SEV_ORDER).fillna(0).astype(int)
    df["cti_hit"] = df["cti_context"].apply(_is_cti_hit)
    return df.sort_values("timestamp", ascending=False, na_position="last")


def _is_cti_hit(ctx) -> bool:
    if not isinstance(ctx, dict) or not ctx:
        return False
    if ctx.get("found") is False:
        return False
    if set(ctx.keys()) <= {"error"}:
        return False
    return True


def date_bounds(df: pd.DataFrame):
    if df.empty or df["timestamp"].isna().all():
        today = datetime.now().date()
        return today, today
    ts = df["timestamp"].dropna()
    return ts.min().date(), ts.max().date()


def preset_range(df: pd.DataFrame, preset: str):
    dmin, dmax = date_bounds(df)
    if preset == "Dernieres 24h":
        return max(dmin, dmax - timedelta(days=1)), dmax
    if preset == "7 derniers jours":
        return max(dmin, dmax - timedelta(days=7)), dmax
    if preset == "30 derniers jours":
        return max(dmin, dmax - timedelta(days=30)), dmax
    return dmin, dmax


def filter_by_period(df: pd.DataFrame, start_date, end_date) -> pd.DataFrame:
    if df.empty or start_date is None or end_date is None:
        return df
    ts = df["timestamp"]
    if ts.notna().sum() == 0:
        return df
    start = pd.Timestamp(start_date)
    end = pd.Timestamp(end_date) + pd.Timedelta(days=1)
    return df[(ts >= start) & (ts < end)]


def compute_kpis(df: pd.DataFrame) -> dict:
    if df.empty:
        return {"total": 0, "critical": 0, "high": 0, "cti_hits": 0,
                "max_risk": 0, "avg_risk": 0, "distinct_sources": 0,
                "correlated": 0}
    by_sev = df["severity"].value_counts().to_dict()
    risk = df["risk_score"]
    return {
        "total":            len(df),
        "critical":         int(by_sev.get("CRITICAL", 0)),
        "high":             int(by_sev.get("HIGH", 0)),
        "cti_hits":         int(df["cti_hit"].sum()),
        "max_risk":         int(risk.max()) if risk.notna().any() else 0,
        "avg_risk":         int(risk.mean()) if risk.notna().any() else 0,
        "distinct_sources": int(df["src_ip"].nunique()),
        "correlated":       int((df["correlated_count"] > 1).sum()),
    }


def severity_counts(df: pd.DataFrame) -> pd.DataFrame:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    if df.empty:
        return pd.DataFrame({"severity": order, "count": [0, 0, 0, 0]})
    vc = df["severity"].value_counts()
    return pd.DataFrame({"severity": order,
                         "count": [int(vc.get(s, 0)) for s in order]})


def top_counts(df: pd.DataFrame, col: str, n: int = 10) -> pd.DataFrame:
    if df.empty or col not in df.columns:
        return pd.DataFrame(columns=[col, "count"])
    vc = df[col].dropna().value_counts().head(n)
    return pd.DataFrame({col: vc.index, "count": vc.values})


def filter_alerts(df: pd.DataFrame,
                  severities: Optional[List[str]] = None,
                  detector: Optional[str] = None,
                  mitre: Optional[str] = None,
                  min_risk: int = 0,
                  max_risk: int = 100,
                  src_ip: Optional[str] = None,
                  dst_ip: Optional[str] = None,
                  cti_only: bool = False,
                  correlated_only: bool = False,
                  text: Optional[str] = None) -> pd.DataFrame:
    if df.empty:
        return df
    out = df
    if severities:
        out = out[out["severity"].isin(severities)]
    if detector and detector != "Tous":
        out = out[out["detector"] == detector]
    if mitre and mitre != "Toutes":
        out = out[out["mitre"] == mitre]
    if min_risk:
        out = out[out["risk_score"].fillna(0) >= min_risk]
    if max_risk < 100:
        out = out[out["risk_score"].fillna(0) <= max_risk]
    if src_ip:
        out = out[out["src_ip"].astype(str).str.contains(src_ip, case=False, na=False)]
    if dst_ip:
        out = out[out["dst_ip"].astype(str).str.contains(dst_ip, case=False, na=False)]
    if cti_only:
        out = out[out["cti_hit"]]
    if correlated_only:
        out = out[out["correlated_count"] > 1]
    if text:
        out = search_iocs(out, text)
    return out


def search_iocs(df: pd.DataFrame, term: str) -> pd.DataFrame:
    if df.empty or not term:
        return df.iloc[0:0]
    term = term.strip().lower()
    haystack = (
        df["src_ip"].astype(str).str.lower() + " " +
        df["dst_ip"].astype(str).str.lower() + " " +
        df["description"].astype(str).str.lower() + " " +
        df["cti_context"].astype(str).str.lower() + " " +
        df["evidence"].astype(str).str.lower()
    )
    return df[haystack.str.contains(term, na=False)]
