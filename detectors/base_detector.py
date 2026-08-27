"""
Classe abstraite dont heritent tous les detecteurs.
Garantit une interface uniforme pour le moteur de detection.
"""
from abc import ABC, abstractmethod
from typing import List, Dict
import pandas as pd

from core.alerts import Alert
from config import settings


class BaseDetector(ABC):
    """Contrat commun a tous les detecteurs."""

    # A redefinir dans chaque detecteur enfant
    NAME: str = "BaseDetector"
    SEVERITY: str = "LOW"
    MITRE: str = ""
    THRESHOLD_KEY: str = ""    # cle dans settings.THRESHOLDS

    def __init__(self):
        # Chaque detecteur recupere automatiquement ses seuils
        self.thresholds = settings.THRESHOLDS.get(self.THRESHOLD_KEY, {})

    @abstractmethod
    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        """
        Analyse les logs Zeek et renvoie une liste d'alertes.
        logs : dict des DataFrames, ex {'conn': df_conn, 'dns': df_dns}
        Methode OBLIGATOIRE dans chaque detecteur enfant.
        """
        raise NotImplementedError

    def make_alert(self, src_ip: str, description: str,
                   dst_ip: str = None, evidence: dict = None) -> Alert:
        """Fabrique une alerte pre-remplie avec les infos du detecteur."""
        return Alert(
            detector=self.NAME,
            severity=self.SEVERITY,
            src_ip=str(src_ip),
            dst_ip=str(dst_ip) if dst_ip else None,
            description=description,
            mitre=self.MITRE,
            evidence=evidence or {},
        )

    def __str__(self) -> str:
        return f"{self.NAME} (severite={self.SEVERITY}, MITRE={self.MITRE})"
