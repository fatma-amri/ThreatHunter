"""
Moteur d'orchestration : charge les logs, execute les detecteurs,
collecte et stocke les alertes.
"""
from pathlib import Path
from typing import List, Dict
import pandas as pd

from core.zeek_parser import ZeekParser
from core.alerts import Alert
from detectors.base_detector import BaseDetector
from database.db import Database
from config import settings


class DetectionEngine:
    """Orchestre l'execution des detecteurs sur les logs Zeek."""

    def __init__(self, logs_dir: Path = None, db: Database = None):
        self.logs_dir = Path(logs_dir or settings.LOGS_DIR)
        self.parser = ZeekParser(self.logs_dir)
        self.db = db or Database()
        self.detectors: List[BaseDetector] = []

    def register(self, detector: BaseDetector):
        """Ajoute un detecteur au moteur."""
        self.detectors.append(detector)
        print(f"[Engine] Detecteur enregistre : {detector}")
        return self

    def load_logs(self) -> Dict[str, pd.DataFrame]:
        """Charge tous les logs Zeek disponibles en DataFrames."""
        logs = {
            "conn": self.parser.conn(),
            "dns":  self.parser.dns(),
            "http": self.parser.http(),
            "ssl":  self.parser.ssl(),
        }
        loaded = {k: v for k, v in logs.items() if not v.empty}
        print(f"[Engine] Logs charges : {list(loaded.keys())}")
        return logs

    def run(self, store: bool = True) -> List[Alert]:
        """
        Execute tous les detecteurs sur les logs.
        store=True -> enregistre les alertes en base.
        """
        if not self.detectors:
            print("[Engine] Aucun detecteur enregistre.")
            return []

        logs = self.load_logs()
        all_alerts: List[Alert] = []

        for detector in self.detectors:
            try:
                alerts = detector.analyze(logs)
                all_alerts.extend(alerts)
                print(f"[Engine] {detector.NAME} -> {len(alerts)} alerte(s)")
            except Exception as e:
                # Un detecteur qui plante ne doit pas arreter les autres
                print(f"[Engine] ERREUR dans {detector.NAME} : {e}")

        if store and all_alerts:
            n = self.db.insert_many(all_alerts)
            print(f"[Engine] {n} alerte(s) enregistree(s) en base")

        print(f"[Engine] Total : {len(all_alerts)} alerte(s)")
        return all_alerts
