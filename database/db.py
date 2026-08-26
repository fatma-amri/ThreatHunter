"""
Interface MongoDB pour les alertes de la plateforme ThreatHunter.

Collection : alerts
Mode dégradé : si MongoDB est injoignable, le pipeline continue (retours
vides / None) au lieu de planter.
"""
import os
from typing import List, Optional
from pymongo import MongoClient, DESCENDING, ASCENDING
from pymongo.errors import PyMongoError
from config import settings
from core.alerts import Alert


class Database:
    """Interface MongoDB pour les alertes."""

    def __init__(self, uri: str = None, dbname: str = None):
        self.uri = uri or settings.MONGO_URI
        self.dbname = dbname or settings.DB_NAME
        # timeout court => mode dégradé rapide si la base est injoignable
        self.client = MongoClient(self.uri, serverSelectionTimeoutMS=3000)
        self.db = self.client[self.dbname]
        self.alerts = self.db["alerts"]
        self._ensure_indexes()

    def _ensure_indexes(self):
        """Index créés une seule fois (idempotent)."""
        self.alerts.create_index([("timestamp", DESCENDING)])
        self.alerts.create_index([("severity", ASCENDING)])
        self.alerts.create_index([("src_ip", ASCENDING)])
        self.alerts.create_index([("detector", ASCENDING)])
        self.alerts.create_index([("risk_score", DESCENDING)])

    @staticmethod
    def _to_doc(alert: Alert) -> dict:
        """Alert -> document Mongo. evidence/cti_context restent des dicts natifs."""
        return {
            "timestamp":         alert.timestamp,
            "detector":          alert.detector,
            "severity":          alert.severity,
            "src_ip":            alert.src_ip,
            "dst_ip":            alert.dst_ip,
            "description":       alert.description,
            "mitre":             alert.mitre,
            "evidence":          alert.evidence or {},
            "cti_context":       alert.cti_context or {},
            # ─── Champs Qualification (couche 7) ───────────────
            "risk_score":        alert.risk_score,
            "confidence":        alert.confidence,
            # ─── Champs Corrélation (couche 6) ─────────────────
            "correlated_count":  alert.correlated_count,
            "related_detectors": alert.related_detectors or [],
        }

    def insert_alert(self, alert: Alert):
        """Insère une alerte, renvoie son _id (ou None si base injoignable)."""
        try:
            return self.alerts.insert_one(self._to_doc(alert)).inserted_id
        except PyMongoError as e:
            print(f"[db] MongoDB indisponible, alerte non persistée : {e}")
            return None

    def insert_many(self, alerts: List[Alert]) -> int:
        """Insère plusieurs alertes en une passe, renvoie le nombre inséré."""
        docs = [self._to_doc(a) for a in alerts]
        if not docs:
            return 0
        try:
            return len(self.alerts.insert_many(docs, ordered=False).inserted_ids)
        except PyMongoError as e:
            print(f"[db] MongoDB indisponible, alertes non persistées : {e}")
            return 0

    def get_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[dict]:
        """Alertes les plus récentes. Format de sortie stable pour le dashboard."""
        query = {"severity": severity} if severity else {}
        try:
            cursor = self.alerts.find(query).sort("timestamp", DESCENDING).limit(limit)
        except PyMongoError as e:
            print(f"[db] MongoDB indisponible : {e}")
            return []
        result = []
        for doc in cursor:
            doc["id"] = str(doc.pop("_id"))   # _id (ObjectId) -> id (str)
            doc.setdefault("evidence", {})
            doc.setdefault("cti_context", {})
            # Valeurs par défaut pour les documents antérieurs (pré-qualification)
            doc.setdefault("risk_score", None)
            doc.setdefault("confidence", None)
            doc.setdefault("correlated_count", 1)
            doc.setdefault("related_detectors", [])
            result.append(doc)
        return result

    def count(self) -> int:
        try:
            return self.alerts.count_documents({})
        except PyMongoError:
            return 0

    def clear(self):
        """Vide la collection (utile pour les tests)."""
        self.alerts.delete_many({})