"""
Detecteur de Beaconing (Command & Control).

Principe : une machine compromise contacte son serveur C2 a intervalles
tres reguliers ("battement de coeur"). Cette regularite se mesure par le
JITTER = ecart-type des intervalles / moyenne des intervalles.
Un jitter FAIBLE (proche de 0) sur un nombre eleve de connexions trahit
un comportement automatise, contrairement au trafic humain, irregulier.

MITRE ATT&CK : T1071 - Application Layer Protocol (C2)
Log utilise  : conn.log
Feature       : jitter (regularite temporelle des connexions)
"""
from typing import List, Dict
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


class BeaconingDetector(BaseDetector):
    """Detecte un beaconing C2 a partir de la regularite des connexions."""

    NAME = "BeaconingDetector"
    SEVERITY = "CRITICAL"
    MITRE = "T1071"
    THRESHOLD_KEY = "beaconing"

    # Valeurs par defaut si absentes de settings.THRESHOLDS
    DEFAULT_MAX_JITTER = 0.10        # jitter < 10 % = trop regulier
    DEFAULT_MIN_CONNECTIONS = 10     # au moins 10 connexions pour conclure

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty:
            return []

        # 1. Seuils depuis settings, sinon valeurs par defaut
        max_jitter = self.thresholds.get("max_jitter", self.DEFAULT_MAX_JITTER)
        min_conns = self.thresholds.get("min_connections", self.DEFAULT_MIN_CONNECTIONS)

        # 2. Extraction des features (jitter par paire src/dst)
        features = FeatureExtractor.beaconing_features(conn)
        if features.empty:
            return []

        # 3. On retient les paires REGULIERES (jitter faible) ET frequentes
        suspects = features[
            (features["jitter"] <= max_jitter) &
            (features["n_conns"] >= min_conns)
        ]

        # 4. Une alerte par paire (src -> dst) suspecte
        alerts: List[Alert] = []
        for _, row in suspects.iterrows():
            alerts.append(self.make_alert(
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                description=(
                    f"Beaconing C2 detecte : {int(row['n_conns'])} connexions "
                    f"tres regulieres (jitter {row['jitter']:.1%}, "
                    f"intervalle moyen {row['mean_interval']:.0f}s, "
                    f"seuil jitter {max_jitter:.0%})"
                ),
                evidence={
                    "n_conns":       int(row["n_conns"]),
                    "jitter":        float(row["jitter"]),
                    "mean_interval": float(row["mean_interval"]),
                    "max_jitter":    max_jitter,
                },
            ))
        return alerts
