"""
Detecteur de SYN Scan (balayage TCP half-open).

Principe : nmap -sS envoie un SYN puis coupe avant la fin du handshake
TCP. Cote Zeek, ces connexions restent en etat S0 (SYN vu, aucune
reponse complete). Un grand nombre de ports distincts contactes en S0
par une meme source trahit un scan furtif de type SYN.

Difference avec PortScanDetector : ce dernier compte TOUS les ports
distincts quel que soit l'etat ; SynScanDetector se restreint a l'etat
S0, ce qui identifie precisement la *technique* de scan (half-open).

MITRE ATT&CK : T1046 - Network Service Discovery
Log utilise   : conn.log
Feature       : distinct_ports (filtre conn_state = S0)
"""
from typing import List, Dict
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


class SynScanDetector(BaseDetector):
    """Detecte un SYN scan (half-open) a partir de conn.log."""

    ENGINE_ID = "ENG-001"
    NAME = "SynScanDetector"
    FAMILY = "Reconnaissance"
    SEVERITY = "MEDIUM"
    MITRE = "T1046"
    LOG = "conn.log"
    FEATURE = "distinct_ports (S0)"
    THRESHOLD_KEY = "syn_scan"

    # Valeur par defaut si le seuil n'est pas defini dans settings.THRESHOLDS
    DEFAULT_MIN_PORTS = 50
    SCAN_STATES = {"S0"}   # SYN envoye, pas de handshake complet

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty:
            return []

        # 1. Features : ports distincts, restreints a l'etat S0 (half-open)
        features = FeatureExtractor.port_scan_features(conn, states=self.SCAN_STATES)
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
                    f"SYN scan (half-open) detecte : {int(row['distinct_ports'])} "
                    f"ports distincts en etat S0 sur {int(row['distinct_hosts'])} "
                    f"hote(s) (seuil : {min_ports})"
                ),
                evidence={
                    "distinct_ports": int(row["distinct_ports"]),
                    "distinct_hosts": int(row["distinct_hosts"]),
                    "total_conns":    int(row["total_conns"]),
                    "conn_state":     "S0",
                    "threshold":      min_ports,
                },
            ))
        return alerts
