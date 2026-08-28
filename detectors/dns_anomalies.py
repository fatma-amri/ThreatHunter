"""
Famille Anomalies DNS / DGA — 8 engines (ENG-042 -> ENG-049).

S'appuie sur les champs REELS du dns.log Zeek (confirmes dans logs/dns.log) :
  query · qtype_name · rcode_name · answers · rejected · id.orig_h
Aucune modification de core/ : les engines lisent directement ces colonnes.

Signaux couverts :
  ENG-042 NXDOMAIN en rafale ............ DGA                (T1568.002)
  ENG-043 domaines a haute entropie ..... DGA                (T1568.002)
  ENG-044 abus d'enregistrements TXT .... canal C2/exfil DNS (T1071.004)
  ENG-045 qtype inhabituels (NULL/ANY) .. tunneling DNS      (T1071.004)
  ENG-046 fast-flux (1 domaine, N IP) ... resolution dynamique (T1568.001)
  ENG-047 fan-out de domaines ........... resolution dynamique (T1568)
  ENG-048 ratio de reponses en echec .... DGA / probing      (T1568)
  ENG-049 DNS rebinding (domaine->prive)  resolution dynamique (T1568.001)

Nota : famille plus HEURISTIQUE que les autres — seuils a affiner sur trafic
reel. Le trafic d'infrastructure (mDNS/.local, service discovery, PTR) est
exclu comme dans le detecteur DNS tunneling existant.
"""
from typing import List, Dict, Optional
import ipaddress
import re
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor

INFRA_PATTERN = re.compile(
    r"(?:\.in-addr\.arpa|\.ip6\.arpa|\.local|_tcp|_udp|_dns-sd)\.?$", re.IGNORECASE)
_INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


def _first_col(df: pd.DataFrame, candidates) -> Optional[str]:
    for c in candidates:
        if c in df.columns:
            return c
    return None


def _is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETS)


def _sld_label(query: str) -> str:
    """Label de second niveau (candidat au nom aleatoire d'un DGA)."""
    labels = str(query).strip(".").split(".")
    return labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")


def _prep(dns: pd.DataFrame) -> pd.DataFrame:
    """Normalise le dns.log en colonnes standard + filtre l'infrastructure."""
    cols = ["src_ip", "query", "qtype_name", "rcode_name", "answers", "rejected"]
    if dns is None or dns.empty:
        return pd.DataFrame(columns=cols)
    col_src = _first_col(dns, ["id.orig_h", "orig_h", "src_ip"])
    col_q = _first_col(dns, ["query", "dns_query", "name"])
    if not (col_src and col_q):
        return pd.DataFrame(columns=cols)
    out = pd.DataFrame({"src_ip": dns[col_src], "query": dns[col_q].astype(str)})
    for name, cands in (("qtype_name", ["qtype_name", "qtype"]),
                        ("rcode_name", ["rcode_name", "rcode"]),
                        ("answers", ["answers", "answer"]),
                        ("rejected", ["rejected"])):
        col = _first_col(dns, cands)
        out[name] = dns[col].astype(str) if col else ""
    out = out.dropna(subset=["query"])
    out = out[~out["query"].apply(lambda q: bool(INFRA_PATTERN.search(str(q))))]
    return out


def _answer_ips(answers: str):
    ips = []
    for tok in str(answers).replace(";", ",").split(","):
        tok = tok.strip()
        try:
            ipaddress.ip_address(tok)
            ips.append(tok)
        except ValueError:
            continue
    return ips


# ══════════════════════════════════════════════════════════════
class NxdomainDgaDetector(BaseDetector):
    ENGINE_ID = "ENG-042"; NAME = "NxdomainDgaDetector"; FAMILY = "DNS Anomaly"
    SEVERITY = "HIGH"; MITRE = "T1568.002"; LOG = "dns.log"; THRESHOLD_KEY = "dga"
    MIN_NXDOMAIN = 20

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        df = _prep(logs.get("dns"))
        if df.empty:
            return []
        nx = df[df["rcode_name"].str.upper() == "NXDOMAIN"]
        alerts = []
        for src, grp in nx.groupby("src_ip"):
            if len(grp) < self.MIN_NXDOMAIN:
                continue
            alerts.append(self.make_alert(
                src_ip=src,
                description=(f"DGA suspecte : {len(grp)} reponses NXDOMAIN "
                            f"(seuil {self.MIN_NXDOMAIN}) — domaines generes non resolus"),
                evidence={"engine_id": self.ENGINE_ID, "nxdomain_count": int(len(grp)),
                          "sample": grp["query"].head(5).tolist()}))
        return alerts


class HighEntropyDgaDetector(BaseDetector):
    ENGINE_ID = "ENG-043"; NAME = "HighEntropyDgaDetector"; FAMILY = "DNS Anomaly"
    SEVERITY = "HIGH"; MITRE = "T1568.002"; LOG = "dns.log"; THRESHOLD_KEY = "dga"
    MIN_ENTROPY = 3.5; MIN_DOMAINS = 10

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        df = _prep(logs.get("dns"))
        if df.empty:
            return []
        df = df.copy()
        df["sld"] = df["query"].apply(_sld_label)
        df["sld_entropy"] = df["sld"].apply(FeatureExtractor.shannon_entropy)
        hi = df[df["sld_entropy"] >= self.MIN_ENTROPY]
        alerts = []
        for src, grp in hi.groupby("src_ip"):
            distinct = grp["sld"].nunique()
            if distinct < self.MIN_DOMAINS:
                continue
            alerts.append(self.make_alert(
                src_ip=src,
                description=(f"DGA suspecte : {distinct} domaines distincts a haute "
                            f"entropie (>= {self.MIN_ENTROPY}) — noms pseudo-aleatoires"),
                evidence={"engine_id": self.ENGINE_ID, "distinct_domains": int(distinct),
                          "max_entropy": float(grp["sld_entropy"].max()),
                          "sample": grp["query"].head(5).tolist()}))
        return alerts


class TxtAbuseDetector(BaseDetector):
    ENGINE_ID = "ENG-044"; NAME = "TxtAbuseDetector"; FAMILY = "DNS Anomaly"
    SEVERITY = "HIGH"; MITRE = "T1071.004"; LOG = "dns.log"; THRESHOLD_KEY = "dns_anomaly"
    MIN_TXT = 20

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        df = _prep(logs.get("dns"))
        if df.empty:
            return []
        txt = df[df["qtype_name"].str.upper() == "TXT"]
        alerts = []
        for src, grp in txt.groupby("src_ip"):
            if len(grp) < self.MIN_TXT:
                continue
            alerts.append(self.make_alert(
                src_ip=src,
                description=(f"Abus d'enregistrements TXT : {len(grp)} requetes TXT "
                            f"(seuil {self.MIN_TXT}) — canal de donnees / C2 via DNS"),
                evidence={"engine_id": self.ENGINE_ID, "txt_count": int(len(grp)),
                          "sample": grp["query"].head(5).tolist()}))
        return alerts


class UnusualQtypeDetector(BaseDetector):
    ENGINE_ID = "ENG-045"; NAME = "UnusualQtypeDetector"; FAMILY = "DNS Anomaly"
    SEVERITY = "HIGH"; MITRE = "T1071.004"; LOG = "dns.log"; THRESHOLD_KEY = "dns_anomaly"
    UNUSUAL = {"NULL", "ANY"}; MIN_COUNT = 10

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        df = _prep(logs.get("dns"))
        if df.empty:
            return []
        odd = df[df["qtype_name"].str.upper().isin(self.UNUSUAL)]
        alerts = []
        for src, grp in odd.groupby("src_ip"):
            if len(grp) < self.MIN_COUNT:
                continue
            kinds = sorted(grp["qtype_name"].str.upper().unique().tolist())
            alerts.append(self.make_alert(
                src_ip=src,
                description=(f"Types d'enregistrement DNS inhabituels : {len(grp)} requetes "
                            f"{kinds} (seuil {self.MIN_COUNT}) — signature de tunneling DNS"),
                evidence={"engine_id": self.ENGINE_ID, "count": int(len(grp)),
                          "qtypes": kinds, "sample": grp["query"].head(5).tolist()}))
        return alerts


class FastFluxDetector(BaseDetector):
    ENGINE_ID = "ENG-046"; NAME = "FastFluxDetector"; FAMILY = "DNS Anomaly"
    SEVERITY = "HIGH"; MITRE = "T1568.001"; LOG = "dns.log"; THRESHOLD_KEY = "dns_anomaly"
    MIN_IPS = 8

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        df = _prep(logs.get("dns"))
        if df.empty:
            return []
        df = df.copy()
        df["ip_list"] = df["answers"].apply(_answer_ips)
        alerts = []
        for query, grp in df.groupby("query"):
            ips = set()
            for lst in grp["ip_list"]:
                ips.update(lst)
            if len(ips) < self.MIN_IPS:
                continue
            src = grp["src_ip"].iloc[0]
            alerts.append(self.make_alert(
                src_ip=src,
                description=(f"Fast-flux suspecte : le domaine {query} resout vers "
                            f"{len(ips)} IP distinctes (seuil {self.MIN_IPS})"),
                evidence={"engine_id": self.ENGINE_ID, "domain": query,
                          "distinct_ips": len(ips), "ips": sorted(ips)[:20]}))
        return alerts


class DomainFanoutDetector(BaseDetector):
    ENGINE_ID = "ENG-047"; NAME = "DomainFanoutDetector"; FAMILY = "DNS Anomaly"
    SEVERITY = "MEDIUM"; MITRE = "T1568"; LOG = "dns.log"; THRESHOLD_KEY = "dns_anomaly"
    MIN_DISTINCT_DOMAINS = 50

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        df = _prep(logs.get("dns"))
        if df.empty:
            return []
        df = df.copy()
        df["sld"] = df["query"].apply(_sld_label)
        alerts = []
        for src, grp in df.groupby("src_ip"):
            distinct = grp["sld"].nunique()
            if distinct < self.MIN_DISTINCT_DOMAINS:
                continue
            alerts.append(self.make_alert(
                src_ip=src,
                description=(f"Fan-out DNS anormal : {distinct} domaines distincts interroges "
                            f"(seuil {self.MIN_DISTINCT_DOMAINS}) — DGA / enumeration / adware"),
                evidence={"engine_id": self.ENGINE_ID, "distinct_domains": int(distinct)}))
        return alerts


class DnsFailureRatioDetector(BaseDetector):
    ENGINE_ID = "ENG-048"; NAME = "DnsFailureRatioDetector"; FAMILY = "DNS Anomaly"
    SEVERITY = "MEDIUM"; MITRE = "T1568"; LOG = "dns.log"; THRESHOLD_KEY = "dns_anomaly"
    MIN_QUERIES = 30; MAX_FAIL_RATIO = 0.5
    FAIL_CODES = {"NXDOMAIN", "SERVFAIL", "REFUSED"}

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        df = _prep(logs.get("dns"))
        if df.empty:
            return []
        alerts = []
        for src, grp in df.groupby("src_ip"):
            n = len(grp)
            if n < self.MIN_QUERIES:
                continue
            failed = grp["rcode_name"].str.upper().isin(self.FAIL_CODES) | \
                (grp["rejected"].str.upper().isin({"T", "TRUE", "1"}))
            ratio = failed.sum() / n
            if ratio < self.MAX_FAIL_RATIO:
                continue
            alerts.append(self.make_alert(
                src_ip=src,
                description=(f"Ratio d'echecs DNS anormal : {ratio:.0%} de {n} requetes "
                            f"echouees (seuil {self.MAX_FAIL_RATIO:.0%}) — DGA / probing"),
                evidence={"engine_id": self.ENGINE_ID, "queries": int(n),
                          "fail_ratio": round(float(ratio), 3)}))
        return alerts


class DnsRebindingDetector(BaseDetector):
    ENGINE_ID = "ENG-049"; NAME = "DnsRebindingDetector"; FAMILY = "DNS Anomaly"
    SEVERITY = "HIGH"; MITRE = "T1568.001"; LOG = "dns.log"; THRESHOLD_KEY = "dns_anomaly"

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        df = _prep(logs.get("dns"))
        if df.empty:
            return []
        alerts = []
        for _, row in df.iterrows():
            ips = _answer_ips(row["answers"])
            private_ips = [ip for ip in ips if _is_internal(ip)]
            if private_ips:   # domaine externe resolvant vers une IP privee
                alerts.append(self.make_alert(
                    src_ip=row["src_ip"],
                    description=(f"DNS rebinding suspecte : le domaine {row['query']} "
                                f"resout vers une IP privee {private_ips}"),
                    evidence={"engine_id": self.ENGINE_ID, "domain": row["query"],
                              "private_answers": private_ips}))
        # Deduplique par (src, domaine)
        seen, uniq = set(), []
        for a in alerts:
            key = (a.src_ip, a.evidence["domain"])
            if key not in seen:
                seen.add(key); uniq.append(a)
        return uniq
