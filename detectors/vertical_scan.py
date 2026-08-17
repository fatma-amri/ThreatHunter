"""
Detecteur de Vertical Scan.

Principe : un vertical scan sonde un TRES grand nombre de ports sur UNE
SEULE cible ("je teste tous les ports de cette machine"). On le detecte
en comptant les ports distincts PAR PAIRE (src, dst) : si une source vise
beaucoup de ports sur une meme destination, c'est un balayage vertical.

Difference avec PortScanDetector : ce dernier agrege les ports toutes
destinations confondues ; VerticalScan les compte par cible, ce qui
distingue le scan concentre (vertical) du scan disperse (horizontal).

MITRE ATT&CK : T1046 - Network Service Discovery
Log utilise   : conn.log
Feature       : distinct_ports par paire (src, dst)
"""
from typing import List, Dict
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


class VerticalScanDetector(BaseDetector):
    """Detecte un balayage vertical (beaucoup de ports sur une seule cible)."""

    ENGINE_ID = "ENG-004"
    NAME = "VerticalScanDetector"
    FAMILY = "Reconnaissance"
    SEVERITY = "MEDIUM"
    MITRE = "T1046"
    LOG = "conn.log"
    FEATURE = "distinct_ports (par cible)"
    THRESHOLD_KEY = "vertical_scan"

    # Valeur par defaut si le seuil n'est pas defini dans settings.THRESHOLDS
    DEFAULT_MIN_PORTS = 50

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty:
            return []

        # 1. Features : ports distincts par paire (src, dst)
        features = FeatureExtractor.vertical_scan_features(conn)
        if features.empty:
            return []

        # 2. Seuil : depuis settings, sinon valeur par defaut
        min_ports = self.thresholds.get("min_ports", self.DEFAULT_MIN_PORTS)

        # 3. Paires qui depassent le seuil
        suspects = features[features["distinct_ports"] >= min_ports]

        # 4. Une alerte par paire (src -> dst) suspecte
        alerts: List[Alert] = []
        for _, row in suspects.iterrows():
            alerts.append(self.make_alert(
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                description=(
                    f"Vertical scan detecte : {int(row['distinct_ports'])} "
                    f"ports distincts sondes sur la cible {row['dst_ip']} "
                    f"(seuil : {min_ports})"
                ),
                evidence={
                    "distinct_ports": int(row["distinct_ports"]),
                    "total_conns":    int(row["total_conns"]),
                    "target":         str(row["dst_ip"]),
                    "threshold":      min_ports,
                },
            ))
        return alerts
