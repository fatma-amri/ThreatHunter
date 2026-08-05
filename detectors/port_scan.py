"""
Detecteur de Port Scan.

Principe : une IP source qui contacte un nombre anormalement eleve de ports
destination DISTINCTS en peu de temps effectue vraisemblablement un balayage
de ports (reconnaissance).

MITRE ATT&CK : T1046 - Network Service Discovery
Log utilise  : conn.log
Feature       : distinct_ports (nombre de ports distincts par source)
"""
from typing import List, Dict
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


class PortScanDetector(BaseDetector):
    """Detecte un balayage de ports a partir de conn.log."""

    NAME = "PortScanDetector"
    SEVERITY = "MEDIUM"
    MITRE = "T1046"
    THRESHOLD_KEY = "port_scan"

    # Valeur par defaut si le seuil n'est pas defini dans settings.THRESHOLDS
    DEFAULT_MIN_PORTS = 50

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty:
            return []

        # 1. Extraction des features comportementales
        features = FeatureExtractor.port_scan_features(conn)
        if features.empty:
            return []

        # 2. Seuil : recupere depuis settings, sinon valeur par defaut
        min_ports = self.thresholds.get("min_ports", self.DEFAULT_MIN_PORTS)

        # 3. On garde les sources qui depassent le seuil
        suspects = features[features["distinct_ports"] >= min_ports]

        # 4. Une alerte par source suspecte
        alerts: List[Alert] = []
        for _, row in suspects.iterrows():
            alerts.append(self.make_alert(
                src_ip=row["src_ip"],
                description=(
                    f"Port scan detecte : {int(row['distinct_ports'])} ports "
                    f"distincts contactes sur {int(row['distinct_hosts'])} hote(s) "
                    f"(seuil : {min_ports})"
                ),
                evidence={
                    "distinct_ports": int(row["distinct_ports"]),
                    "distinct_hosts": int(row["distinct_hosts"]),
                    "total_conns":    int(row["total_conns"]),
                    "threshold":      min_ports,
                },
            ))
        return alerts