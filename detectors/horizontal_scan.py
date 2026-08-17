"""
Detecteur de Horizontal Scan.

Principe : un horizontal scan teste UN MEME port sur de TRES nombreux
hotes ("qui a le port 445 ouvert sur ce reseau ?"). C'est le miroir du
vertical scan : on compte les HOTES distincts PAR PAIRE (src, port). Si
une source vise un meme port sur beaucoup d'hotes, c'est un balayage
horizontal, typique de la recherche d'une vulnerabilite reseau.

Difference avec VerticalScan : vertical = beaucoup de ports sur 1 cible ;
horizontal = 1 port sur beaucoup d'hotes.

MITRE ATT&CK : T1046 - Network Service Discovery
Log utilise   : conn.log
Feature       : distinct_hosts par paire (src, port)
"""
from typing import List, Dict
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


class HorizontalScanDetector(BaseDetector):
    """Detecte un balayage horizontal (un port teste sur de nombreux hotes)."""

    ENGINE_ID = "ENG-005"
    NAME = "HorizontalScanDetector"
    FAMILY = "Reconnaissance"
    SEVERITY = "MEDIUM"
    MITRE = "T1046"
    LOG = "conn.log"
    FEATURE = "distinct_hosts (par port)"
    THRESHOLD_KEY = "horizontal_scan"

    # Valeur par defaut si le seuil n'est pas defini dans settings.THRESHOLDS
    DEFAULT_MIN_HOSTS = 20

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty:
            return []

        # 1. Features : hotes distincts par paire (src, port)
        features = FeatureExtractor.horizontal_scan_features(conn)
        if features.empty:
            return []

        # 2. Seuil : depuis settings, sinon valeur par defaut
        min_hosts = self.thresholds.get("min_hosts", self.DEFAULT_MIN_HOSTS)

        # 3. Paires (src, port) qui depassent le seuil
        suspects = features[features["distinct_hosts"] >= min_hosts]

        # 4. Une alerte par paire (src, port) suspecte
        alerts: List[Alert] = []
        for _, row in suspects.iterrows():
            alerts.append(self.make_alert(
                src_ip=row["src_ip"],
                description=(
                    f"Horizontal scan detecte : port {int(row['dst_port'])} "
                    f"teste sur {int(row['distinct_hosts'])} hotes distincts "
                    f"(seuil : {min_hosts})"
                ),
                evidence={
                    "dst_port":       int(row["dst_port"]),
                    "distinct_hosts": int(row["distinct_hosts"]),
                    "total_conns":    int(row["total_conns"]),
                    "threshold":      min_hosts,
                },
            ))
        return alerts
