"""
Detecteur de Stealth Scan (FIN / NULL / Xmas).

Principe : pour contourner les pare-feux et IDS qui surveillent les SYN,
un attaquant envoie des paquets TCP aux flags anormaux, SANS SYN :
  - FIN scan  : paquet avec seulement le flag FIN
  - NULL scan : paquet sans aucun flag
  - Xmas scan : paquet FIN + PSH (+ URG) — "sapin de Noel" allume
Sur un port ferme, la cible repond RST ; sur un port ouvert/filtre,
elle ne repond pas. Ces paquets sans SYN sont le marqueur du scan furtif.

On lit les flags envoyes par l'ORIGINATOR via la colonne history de Zeek
(lettres majuscules). Une paire (src, dst) qui accumule des connexions
furtives sur plusieurs ports est un balayage stealth.

MITRE ATT&CK : T1046 - Network Service Discovery
Log utilise   : conn.log (colonne history)
Feature       : flags TCP anormaux (FIN/NULL/Xmas) par paire
"""
from typing import List, Dict
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


class StealthScanDetector(BaseDetector):
    """Detecte un scan furtif FIN/NULL/Xmas a partir des flags TCP."""

    ENGINE_ID = "ENG-007"
    NAME = "StealthScanDetector"
    FAMILY = "Reconnaissance"
    SEVERITY = "MEDIUM"
    MITRE = "T1046"
    LOG = "conn.log"
    FEATURE = "flags TCP anormaux (FIN/NULL/Xmas)"
    THRESHOLD_KEY = "stealth_scan"

    # Valeur par defaut si le seuil n'est pas defini dans settings.THRESHOLDS
    DEFAULT_MIN_PORTS = 20   # nb de ports furtifs distincts pour conclure

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty:
            return []

        # 1. Features : connexions furtives par paire (src, dst)
        features = FeatureExtractor.stealth_scan_features(conn)
        if features.empty:
            return []

        # 2. Seuil : depuis settings, sinon valeur par defaut
        min_ports = self.thresholds.get("min_ports", self.DEFAULT_MIN_PORTS)

        # 3. Paires qui depassent le seuil de ports furtifs
        suspects = features[features["distinct_ports"] >= min_ports]

        # 4. Une alerte par paire suspecte
        alerts: List[Alert] = []
        for _, row in suspects.iterrows():
            alerts.append(self.make_alert(
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                description=(
                    f"Stealth scan ({row['scan_type']}) detecte : "
                    f"{int(row['distinct_ports'])} ports sondes en paquets "
                    f"furtifs sur {row['dst_ip']} (seuil : {min_ports})"
                ),
                evidence={
                    "scan_type":      str(row["scan_type"]),
                    "distinct_ports": int(row["distinct_ports"]),
                    "stealth_conns":  int(row["stealth_conns"]),
                    "target":         str(row["dst_ip"]),
                    "threshold":      min_ports,
                },
            ))
        return alerts
