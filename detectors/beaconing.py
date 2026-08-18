"""
Detecteur de Beaconing (Command & Control).

Une machine compromise contacte son C2 a intervalles tres reguliers.
Regularite mesuree par le JITTER = ecart-type des intervalles / moyenne.
Un jitter FAIBLE sur de nombreuses connexions trahit un comportement
automatise.

IMPORTANT : on exige aussi un INTERVALLE MOYEN MINIMUM. Une rafale de
connexions quasi simultanees (scan de ports, chargement de page) a un
jitter faible mais un intervalle proche de 0s -> ce n'est PAS un beacon.
Un vrai C2 bat toutes les dizaines de secondes.

MITRE ATT&CK : T1071 - Application Layer Protocol (C2)
Log utilise  : conn.log
Feature       : jitter + mean_interval (regularite temporelle)
"""
from typing import List, Dict
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


class BeaconingDetector(BaseDetector):
    """Detecte un beaconing C2 a partir de la regularite des connexions."""

    ENGINE_ID = "ENG-015"    # TODO: aligner sur la fiche "Beaconing" du catalogue
    NAME = "BeaconingDetector"
    FAMILY = "Beaconing"
    SEVERITY = "CRITICAL"
    MITRE = "T1071"
    LOG = "conn.log"
    FEATURE = "jitter + mean_interval"
    THRESHOLD_KEY = "beaconing"

    # Valeurs par defaut si absentes de settings.THRESHOLDS
    DEFAULT_MAX_JITTER = 0.30         # jitter < 30 % = tres regulier
    DEFAULT_MIN_CONNECTIONS = 10      # au moins 10 connexions pour conclure
    DEFAULT_MIN_INTERVAL = 5.0        # intervalle moyen >= 5s (sinon = rafale)

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty:
            return []

        # 1. Seuils depuis settings, sinon valeurs par defaut
        max_jitter   = self.thresholds.get("max_jitter", self.DEFAULT_MAX_JITTER)
        min_conns    = self.thresholds.get("min_connections", self.DEFAULT_MIN_CONNECTIONS)
        min_interval = self.thresholds.get("min_interval", self.DEFAULT_MIN_INTERVAL)

        # 2. Extraction des features (jitter par paire src/dst)
        features = FeatureExtractor.beaconing_features(conn)
        if features.empty:
            return []

        # 3. Paires REGULIERES (jitter faible), FREQUENTES (assez de conns)
        #    ET ESPACEES (intervalle moyen suffisant -> ecarte les rafales)
        suspects = features[
            (features["jitter"] <= max_jitter) &
            (features["n_conns"] >= min_conns) &
            (features["mean_interval"] >= min_interval)
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
                    f"seuils jitter {max_jitter:.0%} / intervalle >= {min_interval:.0f}s)"
                ),
                evidence={
                    "n_conns":       int(row["n_conns"]),
                    "jitter":        float(row["jitter"]),
                    "mean_interval": float(row["mean_interval"]),
                    "max_jitter":    max_jitter,
                    "min_interval":  min_interval,
                },
            ))
        return alerts
