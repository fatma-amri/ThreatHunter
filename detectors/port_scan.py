"""
Detecteur de Port Scan (generique).

Une IP source qui contacte un nombre anormalement eleve de ports
destination DISTINCTS (toutes cibles confondues) effectue un balayage.
C'est le detecteur GENERIQUE de reconnaissance ; les variantes SYN,
TCP Connect, UDP, Vertical, Horizontal, Slow, Stealth le specialisent.

MITRE ATT&CK : T1046 - Network Service Discovery
Log utilise  : conn.log
Feature       : distinct_ports (par source)
"""
from typing import List, Dict
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


class PortScanDetector(BaseDetector):
    """Detecte un balayage de ports a partir de conn.log."""

    ENGINE_ID = "ENG-000"
    NAME = "PortScanDetector"
    FAMILY = "Reconnaissance"
    SEVERITY = "MEDIUM"
    MITRE = "T1046"
    LOG = "conn.log"
    FEATURE = "distinct_ports"
    THRESHOLD_KEY = "port_scan"

    DEFAULT_MIN_PORTS = 50

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty:
            return []

        features = FeatureExtractor.port_scan_features(conn)
        if features.empty:
            return []

        min_ports = self.thresholds.get("min_ports", self.DEFAULT_MIN_PORTS)
        suspects = features[features["distinct_ports"] >= min_ports]

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
