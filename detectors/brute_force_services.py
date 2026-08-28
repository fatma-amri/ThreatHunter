"""
Famille Brute Force — engines par service (ENG-009 -> ENG-014).

Meme comportement que le brute force SSH (ENG-008) : une IP source qui enchaine
de nombreuses tentatives de connexion ECHOUEES vers un service donne. Seul le
SERVICE / PORT change. On generalise donc `BruteForceDetector` (SSH) en une
classe de base parametree, dont chaque engine concret herite en quelques lignes.

MITRE ATT&CK : T1110 - Brute Force
Log utilise  : conn.log
Feature       : failed_attempts (echecs sur le(s) port(s) du service)

Tous ces engines reutilisent :
  - FeatureExtractor.brute_force_features(conn, port=<port>)  (inchange)
  - le meme seuil settings.THRESHOLDS["brute_force"]          (inchange)
donc AUCUNE modification de core/ ni de config/settings.py n'est requise.
"""
from typing import List, Dict
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


class ServiceBruteForceDetector(BaseDetector):
    """
    Base generique de detection de brute force par service.

    A specialiser via les attributs de classe :
      ENGINE_ID, NAME, SERVICE, PORTS (liste d'entiers).
    Le reste (severite, MITRE, feature, seuil) est commun a la famille.
    """

    # --- Identite de famille (commune) ---
    FAMILY = "Brute Force"
    SEVERITY = "HIGH"
    MITRE = "T1110"
    LOG = "conn.log"
    FEATURE = "failed_attempts"
    THRESHOLD_KEY = "brute_force"        # reutilise le seuil existant (min_attempts)
    DEFAULT_MIN_ATTEMPTS = 10

    # --- A redefinir dans chaque engine concret ---
    ENGINE_ID = "ENG-0XX"
    NAME = "ServiceBruteForceDetector"
    SERVICE = "generic"
    PORTS: List[int] = []                # un ou plusieurs ports pour ce service

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty or not self.PORTS:
            return []

        min_attempts = self.thresholds.get("min_attempts", self.DEFAULT_MIN_ATTEMPTS)

        alerts: List[Alert] = []
        # Un service peut ecouter sur plusieurs ports (ex : bases de donnees) :
        # on evalue chaque port independamment, une alerte par (source, port).
        for port in self.PORTS:
            features = FeatureExtractor.brute_force_features(conn, port=port)
            if features.empty:
                continue
            suspects = features[features["failed_attempts"] >= min_attempts]
            for _, row in suspects.iterrows():
                dst = row.get("dst_ip")
                alerts.append(self.make_alert(
                    src_ip=row["src_ip"],
                    dst_ip=dst if isinstance(dst, str) else None,
                    description=(
                        f"Brute force {self.SERVICE} detecte : "
                        f"{int(row['failed_attempts'])} tentatives echouees sur le "
                        f"port {port} (seuil : {min_attempts})"
                    ),
                    evidence={
                        "service":         self.SERVICE,
                        "engine_id":       self.ENGINE_ID,
                        "failed_attempts": int(row["failed_attempts"]),
                        "port":            port,
                        "threshold":       min_attempts,
                    },
                ))
        return alerts


# ─────────────────────────────────────────────────────────────
#  Engines concrets — un fichier, 6 detecteurs (chacun ~4 lignes)
# ─────────────────────────────────────────────────────────────
class FtpBruteForceDetector(ServiceBruteForceDetector):
    ENGINE_ID = "ENG-009"
    NAME = "FtpBruteForceDetector"
    SERVICE = "FTP"
    PORTS = [21]


class RdpBruteForceDetector(ServiceBruteForceDetector):
    ENGINE_ID = "ENG-010"
    NAME = "RdpBruteForceDetector"
    SERVICE = "RDP"
    PORTS = [3389]


class SmbBruteForceDetector(ServiceBruteForceDetector):
    ENGINE_ID = "ENG-011"
    NAME = "SmbBruteForceDetector"
    SERVICE = "SMB"
    PORTS = [445]


class TelnetBruteForceDetector(ServiceBruteForceDetector):
    ENGINE_ID = "ENG-012"
    NAME = "TelnetBruteForceDetector"
    SERVICE = "Telnet"
    PORTS = [23]


class VncBruteForceDetector(ServiceBruteForceDetector):
    ENGINE_ID = "ENG-013"
    NAME = "VncBruteForceDetector"
    SERVICE = "VNC"
    PORTS = [5900]


class DbBruteForceDetector(ServiceBruteForceDetector):
    ENGINE_ID = "ENG-014"
    NAME = "DbBruteForceDetector"
    SERVICE = "Database (MySQL/PostgreSQL/MSSQL)"
    PORTS = [3306, 5432, 1433]
