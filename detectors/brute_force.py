"""
Detecteur de Brute Force SSH.

Principe : une IP source qui enchaine un grand nombre de tentatives de
connexion ECHOUEES sur le port SSH (22) mene vraisemblablement une attaque
par force brute (essais de mots de passe).

MITRE ATT&CK : T1110 - Brute Force
Log utilise  : conn.log
Feature       : failed_attempts (echecs de connexion sur le port 22)
"""
from typing import List, Dict
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


class BruteForceDetector(BaseDetector):
    """Detecte une attaque brute force SSH a partir de conn.log."""

    NAME = "BruteForceDetector"
    SEVERITY = "HIGH"
    MITRE = "T1110"
    THRESHOLD_KEY = "brute_force"

    # Valeurs par defaut si absentes de settings.THRESHOLDS
    DEFAULT_MIN_ATTEMPTS = 10
    DEFAULT_PORT = 22

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty:
            return []

        # 1. Seuils depuis settings, sinon valeurs par defaut
        min_attempts = self.thresholds.get("min_attempts", self.DEFAULT_MIN_ATTEMPTS)
        port = self.thresholds.get("port", self.DEFAULT_PORT)

        # 2. Extraction des features comportementales
        features = FeatureExtractor.brute_force_features(conn, port=port)
        if features.empty:
            return []

        # 3. Sources depassant le seuil d'echecs
        suspects = features[features["failed_attempts"] >= min_attempts]

        # 4. Une alerte par source suspecte
        alerts: List[Alert] = []
        for _, row in suspects.iterrows():
            dst = row.get("dst_ip")
            alerts.append(self.make_alert(
                src_ip=row["src_ip"],
                dst_ip=dst if isinstance(dst, str) else None,
                description=(
                    f"Brute force SSH detecte : {int(row['failed_attempts'])} "
                    f"tentatives echouees sur le port {port} "
                    f"(seuil : {min_attempts})"
                ),
                evidence={
                    "failed_attempts": int(row["failed_attempts"]),
                    "port":            port,
                    "threshold":       min_attempts,
                },
            ))
        return alerts
