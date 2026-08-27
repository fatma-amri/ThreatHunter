"""
Detecteur de DNS Tunneling.

Un tunnel DNS encode des donnees dans les sous-domaines des requetes
(dnscat2, iodine...) : noms LONGS + ENTROPIE elevee. On leve une alerte
quand une source emet PLUSIEURS requetes reunissant ces deux criteres.
On exclut le trafic d'infrastructure (mDNS .local, service discovery
_tcp/_udp, PTR inverses .arpa) qui a naturellement des noms longs et
a haute entropie sans etre du tunneling.

Reutilise FeatureExtractor.dns_features (src_ip | query | qlen | entropy).

MITRE ATT&CK : T1071.004 - Application Layer Protocol : DNS
Log utilise   : dns.log
Feature       : dns_entropy + qlen
"""
from typing import List, Dict
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


class DNSTunnelDetector(BaseDetector):
    """Detecte un tunnel DNS a partir de l'entropie et de la longueur des requetes."""

    ENGINE_ID = "ENG-029"    # TODO: aligner sur la fiche "DNS Tunneling" du catalogue
    NAME = "DNSTunnelDetector"
    FAMILY = "Tunneling"
    SEVERITY = "HIGH"
    MITRE = "T1071.004"
    LOG = "dns.log"
    FEATURE = "dns_entropy + qlen"
    THRESHOLD_KEY = "dns_tunnel"

    DEFAULT_MIN_ENTROPY = 3.5
    DEFAULT_MIN_QLEN = 40
    DEFAULT_MIN_QUERIES = 5

    # Motifs d'infrastructure DNS a exclure (jamais du tunneling)
    INFRA_PATTERN = r"(?:\.in-addr\.arpa|\.ip6\.arpa|\.local|_tcp|_udp|_dns-sd)\.?$"

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        dns = logs.get("dns")
        if dns is None or dns.empty:
            return []

        min_entropy = self.thresholds.get("min_entropy", self.DEFAULT_MIN_ENTROPY)
        min_qlen    = self.thresholds.get("min_qlen",    self.DEFAULT_MIN_QLEN)
        min_queries = self.thresholds.get("min_queries", self.DEFAULT_MIN_QUERIES)

        feats = FeatureExtractor.dns_features(dns)
        if feats.empty:
            return []

        # Exclure le trafic d'infrastructure (mDNS, service discovery, PTR)
        feats = feats[~feats["query"].str.contains(
            self.INFRA_PATTERN, case=False, regex=True, na=False
        )]
        if feats.empty:
            return []

        # Requetes suspectes : longues ET a haute entropie
        suspects = feats[
            (feats["entropy"] >= min_entropy) &
            (feats["qlen"]    >= min_qlen)
        ]
        if suspects.empty:
            return []

        # Regroupement par source : il faut assez de requetes suspectes
        alerts: List[Alert] = []
        for src, g in suspects.groupby("src_ip"):
            if len(g) < min_queries:
                continue
            sample = g.sort_values("entropy", ascending=False).iloc[0]
            alerts.append(self.make_alert(
                src_ip=src,
                description=(
                    f"DNS tunneling suspecte : {int(len(g))} requetes longues "
                    f"a haute entropie (entropie max {g['entropy'].max():.2f}, "
                    f"longueur max {int(g['qlen'].max())} ; seuils "
                    f"entropie>={min_entropy}, longueur>={min_qlen})"
                ),
                evidence={
                    "suspicious_queries": int(len(g)),
                    "max_entropy":        float(g["entropy"].max()),
                    "max_qlen":           int(g["qlen"].max()),
                    "sample_query":       str(sample["query"])[:120],
                    "thresholds": {
                        "min_entropy": min_entropy,
                        "min_qlen":    min_qlen,
                        "min_queries": min_queries,
                    },
                },
            ))
        return alerts
