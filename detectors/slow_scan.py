"""
Detecteur de Slow Scan (balayage lent / evasion temporelle).

Principe : pour echapper aux detecteurs qui comptent "beaucoup de ports
en peu de temps", un attaquant ETALE ses sondes dans le temps (une sonde
toutes les X secondes). Le debit reste sous les seuils classiques, mais
le comportement reste un balayage : plusieurs ports, sur une longue
duree, avec un intervalle moyen eleve entre connexions.

On leve une alerte quand les TROIS conditions sont reunies :
  - assez de ports distincts     (min_ports)
  - intervalle moyen assez grand (min_interval, en secondes)
  - duree totale assez longue    (min_duration, en secondes)

Distinction avec le Beaconing : le beaconing REPETE le meme contact
(peu de ports, forte regularite) ; le slow scan couvre BEAUCOUP de ports.

MITRE ATT&CK : T1046 - Network Service Discovery
Log utilise   : conn.log
Feature       : distinct_ports + duration + mean_interval (par paire)
"""
from typing import List, Dict
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


class SlowScanDetector(BaseDetector):
    """Detecte un balayage lent etale dans le temps (evasion)."""

    ENGINE_ID = "ENG-006"
    NAME = "SlowScanDetector"
    FAMILY = "Reconnaissance"
    SEVERITY = "MEDIUM"
    MITRE = "T1046"
    LOG = "conn.log"
    FEATURE = "distinct_ports + mean_interval"
    THRESHOLD_KEY = "slow_scan"

    # Valeurs par defaut si absentes de settings.THRESHOLDS
    DEFAULT_MIN_PORTS = 20        # assez de ports pour parler de balayage
    DEFAULT_MIN_INTERVAL = 30     # secondes entre 2 sondes (lent)
    DEFAULT_MIN_DURATION = 600    # secondes (10 min) : balayage etale

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty:
            return []

        # 1. Seuils depuis settings, sinon valeurs par defaut
        min_ports    = self.thresholds.get("min_ports",    self.DEFAULT_MIN_PORTS)
        min_interval = self.thresholds.get("min_interval", self.DEFAULT_MIN_INTERVAL)
        min_duration = self.thresholds.get("min_duration", self.DEFAULT_MIN_DURATION)

        # 2. Features temporelles par paire (src, dst)
        features = FeatureExtractor.slow_scan_features(conn)
        if features.empty:
            return []

        # 3. Les TROIS conditions doivent etre reunies
        suspects = features[
            (features["distinct_ports"] >= min_ports) &
            (features["mean_interval"] >= min_interval) &
            (features["duration"]      >= min_duration)
        ]

        # 4. Une alerte par paire suspecte
        alerts: List[Alert] = []
        for _, row in suspects.iterrows():
            alerts.append(self.make_alert(
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                description=(
                    f"Slow scan detecte : {int(row['distinct_ports'])} ports "
                    f"sondes sur {row['dst_ip']} en {row['duration']:.0f}s "
                    f"(intervalle moyen {row['mean_interval']:.0f}s, "
                    f"seuils : {min_ports} ports / {min_interval}s / {min_duration}s)"
                ),
                evidence={
                    "distinct_ports": int(row["distinct_ports"]),
                    "duration":       float(row["duration"]),
                    "mean_interval":  float(row["mean_interval"]),
                    "target":         str(row["dst_ip"]),
                    "thresholds": {
                        "min_ports":    min_ports,
                        "min_interval": min_interval,
                        "min_duration": min_duration,
                    },
                },
            ))
        return alerts
