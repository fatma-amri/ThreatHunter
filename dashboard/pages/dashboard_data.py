"""
Couche donnees du dashboard - fonctions pures, sans Streamlit.

Separee de l'interface pour etre testable et reutilisable (dashboard ET
rapports PDF/CSV consomment ces memes fonctions).
"""
from typing import List, Optional
from datetime import datetime, timedelta
import pandas as pd

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
# Alignes sur dashboard.pages.theme.TOKENS (sev_*) — copies en dur plutot
# qu'importes pour garder ce module utilisable sans streamlit (PDF/CSV).
SEV_COLORS = {
    "CRITICAL": "#e01e2b",   # sev_critical — rouge Keystone / menace
    "HIGH":     "#ff7a1a",   # sev_high — orange / risque eleve
    "MEDIUM":   "#f5c518",   # sev_medium — jaune / moyen
    "LOW":      "#2ecc71",   # sev_low — vert / operationnel
}
PLOTLY_TEMPLATE = None  # habillage complet applique via theme.plotly_layout()


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


# ═══════════════════════════════════════════════════════════════════════
#  SYNTHESE — niveau de menace + resume executif (purs, partages par le
#  dashboard ET l'export PDF/rapports — source de verite unique).
# ═══════════════════════════════════════════════════════════════════════
def threat_level(kpis: dict) -> tuple:
    """Niveau de menace global d'une selection, derive de compute_kpis().
    -> (level in {CRITICAL, ELEVATED, NOMINAL}, phrase de detail)."""
    if kpis.get("critical", 0) > 0:
        return "CRITICAL", f"{kpis['critical']} active critical alert(s)"
    if kpis.get("high", 0) > 0:
        return "ELEVATED", f"{kpis['high']} high-risk alert(s)"
    if kpis.get("total", 0) > 0:
        return "NOMINAL", "no critical or high-risk alerts"
    return "NOMINAL", "no data for current filters"


def executive_summary(df: pd.DataFrame, kpis: dict, level: str) -> str:
    """Paragraphe narratif genere UNIQUEMENT a partir des KPI reels de la
    selection (compute_kpis) — aucune donnee inventee."""
    if df is None or df.empty:
        return ("No alerts were recorded for the current selection — "
                "nothing to report.")
    tm = top_counts(df, "mitre", 1)
    technique = ""
    if not tm.empty:
        technique = (f" The most frequently observed technique was "
                     f"{tm.iloc[0]['mitre']} ({int(tm.iloc[0]['count'])} alert(s)).")
    cti_txt = (f" {kpis['cti_hits']} alert(s) were confirmed against threat "
               f"intelligence." if kpis.get("cti_hits") else "")
    corr_txt = (f" {kpis['correlated']} incident(s) correlate activity across "
                f"multiple detectors." if kpis.get("correlated") else "")
    return (
        f"During the selected period, {kpis['total']} alert(s) were recorded across "
        f"{kpis['distinct_sources']} distinct source(s), including {kpis['critical']} "
        f"critical and {kpis['high']} high-risk event(s). Overall threat level is "
        f"assessed as {level}.{technique}{cti_txt}{corr_txt}"
    )


# ═══════════════════════════════════════════════════════════════════════
#  INVESTIGATION — drill-down par entite (IP) + reconstruction kill-chain
#  ATT&CK MATRIX — mapping technique -> tactique + intensite observee
#
#  Tout ce qui suit reste PUR (pas de Streamlit) : consomme par
#  advanced_pages.py (rendu) ET testable en isolation.
# ═══════════════════════════════════════════════════════════════════════

# --- Referentiel MITRE ATT&CK, restreint aux familles du projet ---------
# (name, tactic). Extensible : ajouter une ligne ici suffit, la matrice et
# la kill-chain s'adaptent. Les techniques REELLEMENT presentes dans les
# donnees : T1046, T1110, T1071, T1071.004, T1048.
MITRE_TACTIC_ORDER = [
    "Discovery",
    "Credential Access",
    "Lateral Movement",
    "Command and Control",
    "Exfiltration",
]

MITRE_TECHNIQUES = {
    # Discovery
    "T1046":     ("Network Service Discovery",                 "Discovery"),
    "T1018":     ("Remote System Discovery",                   "Discovery"),
    # Credential Access
    "T1110":     ("Brute Force",                               "Credential Access"),
    "T1110.001": ("Brute Force: Password Guessing",            "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying",            "Credential Access"),
    # Lateral Movement
    "T1021":     ("Remote Services",                           "Lateral Movement"),
    # Command and Control
    "T1071":     ("Application Layer Protocol",                "Command and Control"),
    "T1071.004": ("Application Layer Protocol: DNS",           "Command and Control"),
    "T1571":     ("Non-Standard Port",                         "Command and Control"),
    "T1572":     ("Protocol Tunneling",                        "Command and Control"),
    "T1095":     ("Non-Application Layer Protocol",            "Command and Control"),
    "T1568":     ("Dynamic Resolution",                        "Command and Control"),
    # Exfiltration
    "T1048":     ("Exfiltration Over Alternative Protocol",    "Exfiltration"),
    "T1041":     ("Exfiltration Over C2 Channel",              "Exfiltration"),
    "T1567":     ("Exfiltration Over Web Service",             "Exfiltration"),
}

# Techniques du CATALOGUE CIBLE : plausibles pour les familles du projet
# mais PAS encore couvertes par un detecteur / pas encore observees.
# Affichees en sourdine et etiquetees "not yet observed" — jamais comme
# detectees.
MITRE_TARGET_CATALOG = {
    "T1018", "T1110.001", "T1110.003", "T1021",
    "T1571", "T1572", "T1095", "T1568", "T1041", "T1567",
}

_UNMAPPED_TACTIC = "Unmapped"


def technique_name(tid: Optional[str]) -> str:
    """Nom lisible d'une technique ATT&CK (ou l'ID brut si inconnu)."""
    if not tid:
        return "—"
    entry = MITRE_TECHNIQUES.get(str(tid))
    return entry[0] if entry else str(tid)


def technique_tactic(tid: Optional[str]) -> str:
    """Tactique (colonne ATT&CK) d'une technique. Retombe sur la tactique du
    parent (T1071.004 -> T1071) puis sur 'Unmapped'."""
    if not tid:
        return _UNMAPPED_TACTIC
    tid = str(tid)
    entry = MITRE_TECHNIQUES.get(tid)
    if entry:
        return entry[1]
    if "." in tid:
        parent = MITRE_TECHNIQUES.get(tid.split(".", 1)[0])
        if parent:
            return parent[1]
    return _UNMAPPED_TACTIC


def _tactic_rank(tactic: str) -> int:
    return (MITRE_TACTIC_ORDER.index(tactic)
            if tactic in MITRE_TACTIC_ORDER else len(MITRE_TACTIC_ORDER))


# --- Liste / profil d'une entite (IP) ---------------------------------
_EMPTY_IP = {"", "none", "nan", "n/a", "-"}


def _ip_sort_key(ip: str):
    parts = str(ip).split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, tuple(int(p) for p in parts), "")
    return (1, (), str(ip))


def entity_list(df: pd.DataFrame) -> List[str]:
    """Toutes les IP vues dans la selection (source OU destination),
    dedupliquees et triees (IPv4 numeriquement)."""
    if df.empty:
        return []
    ips = pd.concat([df["src_ip"], df["dst_ip"]]).dropna().astype(str)
    ips = [ip for ip in ips.unique() if ip.strip().lower() not in _EMPTY_IP]
    return sorted(ips, key=_ip_sort_key)


def entity_alerts(df: pd.DataFrame, ip: Optional[str]) -> pd.DataFrame:
    """Toutes les alertes ou l'entite apparait, comme source OU destination."""
    if df.empty or not ip:
        return df.iloc[0:0]
    ip = str(ip)
    mask = ((df["src_ip"].astype(str) == ip) | (df["dst_ip"].astype(str) == ip))
    return df[mask]


def entity_source_alerts(df: pd.DataFrame, ip: Optional[str]) -> pd.DataFrame:
    """Alertes ou l'entite est la SOURCE (attaquant presume)."""
    sub = entity_alerts(df, ip)
    if sub.empty:
        return sub
    return sub[sub["src_ip"].astype(str) == str(ip)]


def entity_profile(df: pd.DataFrame, ip: Optional[str]) -> dict:
    """Fiche d'hote agregee : risque, volume, severite max, CTI, fenetre
    temporelle, role (source vs destination)."""
    sub = entity_alerts(df, ip)
    base = {
        "ip": ip, "alert_count": 0, "risk_max": 0, "risk_mean": 0,
        "max_severity": None, "cti_hits": 0, "first_seen": None,
        "last_seen": None, "as_source": 0, "as_destination": 0,
        "detector_count": 0, "destination_count": 0,
    }
    if sub.empty:
        return base
    ip = str(ip)
    ts = sub["timestamp"].dropna()
    risk = sub["risk_score"].dropna()
    src_mask = sub["src_ip"].astype(str) == ip
    max_sev = None
    if sub["sev_rank"].notna().any() and int(sub["sev_rank"].max()) > 0:
        max_sev = sub.loc[sub["sev_rank"].idxmax(), "severity"]
    base.update({
        "ip": ip,
        "alert_count": int(len(sub)),
        "risk_max": int(risk.max()) if not risk.empty else 0,
        "risk_mean": int(round(risk.mean())) if not risk.empty else 0,
        "max_severity": max_sev,
        "cti_hits": int(sub["cti_hit"].sum()),
        "first_seen": ts.min() if not ts.empty else None,
        "last_seen": ts.max() if not ts.empty else None,
        "as_source": int(src_mask.sum()),
        "as_destination": int((sub["dst_ip"].astype(str) == ip).sum()),
        "detector_count": int(sub["detector"].nunique()),
        "destination_count": int(sub.loc[src_mask, "dst_ip"].dropna().nunique()),
    })
    return base


def entity_detectors(df: pd.DataFrame, ip: Optional[str], n: int = 10):
    return top_counts(entity_alerts(df, ip), "detector", n)


def entity_destinations(df: pd.DataFrame, ip: Optional[str], n: int = 10):
    """IP destinations contactees par l'entite quand elle est source."""
    return top_counts(entity_source_alerts(df, ip), "dst_ip", n)


def entity_techniques(df: pd.DataFrame, ip: Optional[str], n: int = 10):
    return top_counts(entity_alerts(df, ip), "mitre", n)


def entity_timeline(df: pd.DataFrame, ip: Optional[str]) -> pd.DataFrame:
    """Alertes datees de l'entite, ordre chronologique — pour la mini-timeline."""
    sub = entity_alerts(df, ip)
    if sub.empty:
        return sub
    cols = ["timestamp", "severity", "detector", "src_ip", "dst_ip",
            "mitre", "risk_score", "correlated_count"]
    out = sub.dropna(subset=["timestamp"])[cols]
    return out.sort_values("timestamp")


# --- Kill-chain : reconstruction de la sequence d'attaque -------------
def _kc_step(ts, detector, severity, dst_ip, mitre, description,
             approx_time: bool = False) -> dict:
    phase = technique_tactic(mitre)
    ts_na = ts is None or (not isinstance(ts, str) and pd.isna(ts))
    return {
        "timestamp": None if ts_na else pd.Timestamp(ts),
        "_sort": pd.Timestamp.max if ts_na else pd.Timestamp(ts),
        "detector": str(detector) if detector else "—",
        "severity": (severity or "").upper(),
        "dst_ip": None if (dst_ip is None or pd.isna(dst_ip)) else str(dst_ip),
        "technique": str(mitre) if mitre else "—",
        "technique_name": technique_name(mitre),
        "phase": phase,
        "tactic_rank": _tactic_rank(phase),
        "description": description or "",
        "approx_time": approx_time,
    }


def kill_chain(df: pd.DataFrame, ip: Optional[str]) -> dict:
    """Reconstitue la sequence d'attaque menee DEPUIS l'entite (src_ip).

    Sources d'etapes :
      1. les alertes ou l'entite est source (datees) ;
      2. les 'correlated_alerts' de son/ses incident(s) correle(s) — sous-
         alertes non datees, rattachees au timestamp de l'incident.

    Etapes ordonnees par (temps, ordre de tactique ATT&CK) puis
    dedupliquees sur (detecteur, technique, destination). Retourne aussi
    la liste ordonnee des tactiques couvertes.
    """
    src_rows = entity_source_alerts(df, ip)
    steps: List[dict] = []
    if not src_rows.empty:
        for _, r in src_rows.iterrows():
            steps.append(_kc_step(r["timestamp"], r["detector"], r["severity"],
                                  r["dst_ip"], r["mitre"], r["description"]))
            ev = r["evidence"] if isinstance(r["evidence"], dict) else {}
            for ca in (ev.get("correlated_alerts") or []):
                steps.append(_kc_step(
                    r["timestamp"], ca.get("detector"), ca.get("severity"),
                    ca.get("dst_ip"), ca.get("mitre"), ca.get("description"),
                    approx_time=True))

    steps.sort(key=lambda s: (s["_sort"], s["tactic_rank"]))
    seen, uniq = set(), []
    for s in steps:
        key = (s["detector"], s["technique"], s["dst_ip"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(s)

    tactics: List[str] = []
    for s in uniq:
        if s["phase"] not in tactics:
            tactics.append(s["phase"])
    tactics.sort(key=_tactic_rank)
    return {"steps": uniq, "tactics": tactics}


# --- ATT&CK matrix ----------------------------------------------------
def technique_alerts(df: pd.DataFrame, tid: Optional[str]) -> pd.DataFrame:
    """Alertes d'une technique — inclut les sous-techniques quand un parent
    (ex. T1071) est demande."""
    if df.empty or not tid:
        return df.iloc[0:0]
    tid = str(tid)
    m = df["mitre"].astype(str)
    return df[(m == tid) | (m.str.startswith(tid + "."))]


def observed_techniques(df: pd.DataFrame) -> pd.DataFrame:
    """Techniques REELLEMENT presentes dans la selection : nb d'alertes +
    risque max. Base honnete de la matrice (ce qui s'allume)."""
    cols = ["technique", "alert_count", "max_risk"]
    if df.empty:
        return pd.DataFrame(columns=cols)
    g = (df.dropna(subset=["mitre"]).assign(mitre=lambda d: d["mitre"].astype(str))
           .groupby("mitre")
           .agg(alert_count=("mitre", "size"),
                max_risk=("risk_score", "max"))
           .reset_index().rename(columns={"mitre": "technique"}))
    g["max_risk"] = g["max_risk"].fillna(0).astype(int)
    return g[cols].sort_values("alert_count", ascending=False)


def attack_matrix(df: pd.DataFrame) -> List[dict]:
    """Grille ATT&CK Navigator : une colonne par tactique, des cellules =
    techniques. Chaque cellule :
        {id, name, observed(bool), alert_count, max_risk, target(bool)}
    'target' = technique du catalogue cible, non encore observee.
    """
    obs = observed_techniques(df)
    obs_map = {row["technique"]: (int(row["alert_count"]), int(row["max_risk"]))
               for _, row in obs.iterrows()}

    # Techniques a placer : catalogue de reference + tout ce qui est observe.
    all_ids = set(MITRE_TECHNIQUES) | set(obs_map)
    tactics = list(MITRE_TACTIC_ORDER)
    for tid in obs_map:
        tac = technique_tactic(tid)
        if tac not in tactics:
            tactics.append(tac)

    grid: List[dict] = []
    for tac in tactics:
        cells = []
        for tid in sorted(t for t in all_ids if technique_tactic(t) == tac):
            count, risk = obs_map.get(tid, (0, 0))
            observed = count > 0
            cells.append({
                "id": tid,
                "name": technique_name(tid),
                "observed": observed,
                "alert_count": count,
                "max_risk": risk,
                "target": (tid in MITRE_TARGET_CATALOG) and not observed,
            })
        cells.sort(key=lambda c: (not c["observed"], -c["alert_count"], c["id"]))
        if cells:
            grid.append({"tactic": tac, "cells": cells})
    return grid
