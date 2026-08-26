"""
Detecteur de Data Exfiltration.

Principe : une exfiltration de donnees se traduit par un volume d'octets
SORTANTS anormalement eleve depuis une machine interne vers une destination.
On somme les octets envoyes par chaque paire (source, destination) et on
alerte au-dela d'un seuil.

MITRE ATT&CK : T1048 - Exfiltration Over Alternative Protocol
Log utilise  : conn.log
Feature      : total_orig_bytes (volume sortant par paire src/dst)
ENGINE_ID    : ENG-022 (famille Exfiltration)
"""
from typing import List, Dict
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


class ExfiltrationDetector(BaseDetector):
    """Detecte une exfiltration de donnees a partir du volume sortant."""

    NAME = "ExfiltrationDetector"
    SEVERITY = "HIGH"
    MITRE = "T1048"
    THRESHOLD_KEY = "exfiltration"

    # Valeur par defaut : 1 Mo de donnees sortantes vers une seule destination
    DEFAULT_MAX_BYTES = 1_000_000

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty:
            return []

        # 1. Seuil depuis settings, sinon valeur par defaut
        max_bytes = self.thresholds.get("max_bytes", self.DEFAULT_MAX_BYTES)

        # 2. Extraction des features (volume sortant par paire src/dst)
        features = FeatureExtractor.exfil_features(conn)
        if features.empty:
            return []

        # 3. Paires depassant le seuil de volume sortant
        suspects = features[features["total_orig_bytes"] >= max_bytes]
        if suspects.empty:
            return []

        # 4. Une alerte par paire suspecte
        alerts: List[Alert] = []
        for _, row in suspects.iterrows():
            mb = row["total_orig_bytes"] / 1_000_000
            alerts.append(self.make_alert(
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                description=(
                    f"Exfiltration suspecte : {mb:.1f} Mo envoyes vers "
                    f"{row['dst_ip']} sur {int(row['n_conns'])} connexion(s) "
                    f"(seuil {max_bytes / 1_000_000:.1f} Mo)"
                ),
                evidence={
                    "total_orig_bytes": int(row["total_orig_bytes"]),
                    "total_mb":         round(mb, 2),
                    "n_conns":          int(row["n_conns"]),
                    "threshold_bytes":  max_bytes,
                },
            ))
        return alerts
