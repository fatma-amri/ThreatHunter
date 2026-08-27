"""
Detecteur de TCP Connect Scan (balayage TCP complet).

Principe : nmap -sT ouvre une VRAIE connexion TCP (handshake complet)
sur chaque port, puis la referme. Contrairement au SYN scan (half-open,
connexions non etablies), le TCP Connect scan laisse des connexions
ETABLIES : cote Zeek, etats SF (connexion normale terminee) ou RSTR
(etablie puis coupee par un reset). Un grand nombre de ports distincts
ainsi contactes par une meme source trahit un balayage TCP Connect.

Difference avec SynScanDetector : SYN scan = connexions NON etablies
(S0/REJ/RSTO) ; TCP Connect scan = connexions ETABLIES (SF/RSTR).

MITRE ATT&CK : T1046 - Network Service Discovery
Log utilise   : conn.log
Feature       : distinct_ports (filtre conn_state = SF / RSTR)
"""
from typing import List, Dict
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


class TcpConnectScanDetector(BaseDetector):
    """Detecte un TCP Connect scan (connexions etablies) a partir de conn.log."""

    ENGINE_ID = "ENG-002"
    NAME = "TcpConnectScanDetector"
    FAMILY = "Reconnaissance"
    SEVERITY = "MEDIUM"
    MITRE = "T1046"
    LOG = "conn.log"
    FEATURE = "distinct_ports (SF)"
    THRESHOLD_KEY = "tcp_connect_scan"

    # Valeur par defaut si le seuil n'est pas defini dans settings.THRESHOLDS
    DEFAULT_MIN_PORTS = 50
    SCAN_STATES = {"SF", "RSTR"}   # connexions etablies puis fermees

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty:
            return []

        # 1. Features : ports distincts, restreints aux connexions etablies
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
                    f"TCP Connect scan detecte : {int(row['distinct_ports'])} "
                    f"ports distincts etablis sur {int(row['distinct_hosts'])} "
                    f"hote(s) (seuil : {min_ports})"
                ),
                evidence={
                    "distinct_ports": int(row["distinct_ports"]),
                    "distinct_hosts": int(row["distinct_hosts"]),
                    "total_conns":    int(row["total_conns"]),
                    "conn_states":    sorted(self.SCAN_STATES),
                    "threshold":      min_ports,
                },
            ))
        return alerts
