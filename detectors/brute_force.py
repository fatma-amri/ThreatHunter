"""
Detecteur de Brute Force SSH.

Une IP source qui enchaine de nombreuses tentatives de connexion
ECHOUEES sur le port SSH (22) mene vraisemblablement une attaque par
force brute (essais de mots de passe).

MITRE ATT&CK : T1110 - Brute Force
Log utilise  : conn.log
Feature       : failed_attempts (echecs sur le port 22)
"""
from typing import List, Dict
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


class BruteForceDetector(BaseDetector):
    """Detecte une attaque brute force SSH a partir de conn.log."""

    ENGINE_ID = "ENG-008"
    NAME = "BruteForceDetector"
    FAMILY = "Brute Force"
    SEVERITY = "HIGH"
    MITRE = "T1110"
    LOG = "conn.log"
    FEATURE = "failed_attempts"
    THRESHOLD_KEY = "brute_force"

    DEFAULT_MIN_ATTEMPTS = 10
    DEFAULT_PORT = 22

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty:
            return []

        min_attempts = self.thresholds.get("min_attempts", self.DEFAULT_MIN_ATTEMPTS)
        port = self.thresholds.get("port", self.DEFAULT_PORT)

        features = FeatureExtractor.brute_force_features(conn, port=port)
        if features.empty:
            return []

        suspects = features[features["failed_attempts"] >= min_attempts]

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
