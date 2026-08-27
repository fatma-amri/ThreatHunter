"""
Detecteur de UDP Scan.

Principe : nmap -sU sonde de nombreux ports UDP pour decouvrir les
services (DNS, SNMP, NetBIOS...). Comme UDP est sans connexion, la
notion d'etat TCP (S0/SF) ne s'applique pas : on detecte le scan par
le nombre de ports UDP DISTINCTS contactes par une meme source.

MITRE ATT&CK : T1046 - Network Service Discovery
Log utilise   : conn.log
Feature       : distinct_ports (filtre proto = udp)
"""
from typing import List, Dict
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


class UdpScanDetector(BaseDetector):
    """Detecte un balayage de ports UDP a partir de conn.log."""

    ENGINE_ID = "ENG-003"
    NAME = "UdpScanDetector"
    FAMILY = "Reconnaissance"
    SEVERITY = "MEDIUM"
    MITRE = "T1046"
    LOG = "conn.log"
    FEATURE = "distinct_udp_ports"
    THRESHOLD_KEY = "udp_scan"

    # Valeur par defaut si le seuil n'est pas defini dans settings.THRESHOLDS
    DEFAULT_MIN_PORTS = 50

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty:
            return []

        # 1. Features : ports UDP distincts par source
        features = FeatureExtractor.udp_scan_features(conn)
        if features.empty:
            return []

        # 2. Seuil : depuis settings, sinon valeur par defaut
        min_ports = self.thresholds.get("min_ports", self.DEFAULT_MIN_PORTS)

        # 3. Sources qui depassent le seuil
        suspects = features[features["distinct_ports"] >= min_ports]

        # 4. Une alerte par source suspecte
        alerts: List[Alert] = []
        for _, row in suspects.iterrows():
            alerts.append(self.make_alert(
                src_ip=row["src_ip"],
                description=(
                    f"UDP scan detecte : {int(row['distinct_ports'])} "
                    f"ports UDP distincts sur {int(row['distinct_hosts'])} "
                    f"hote(s) (seuil : {min_ports})"
                ),
                evidence={
                    "distinct_ports": int(row["distinct_ports"]),
                    "distinct_hosts": int(row["distinct_hosts"]),
                    "total_conns":    int(row["total_conns"]),
                    "proto":          "udp",
                    "threshold":      min_ports,
                },
            ))
        return alerts
