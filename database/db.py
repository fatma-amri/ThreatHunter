
import sqlite3
import json
from pathlib import Path
from typing import List, Optional

from config import settings
from core.alerts import Alert


class Database:
    """Interface SQLite pour les alertes."""

    def __init__(self, db_path: Path = None):
        self.db_path = Path(db_path or settings.DB_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._create_tables()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row   # accès aux colonnes par nom
        return conn

    def _create_tables(self):
        """Cree la table alerts si elle n'existe pas."""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT    NOT NULL,
                    detector    TEXT    NOT NULL,
                    severity    TEXT    NOT NULL,
                    src_ip      TEXT    NOT NULL,
                    dst_ip      TEXT,
                    description TEXT    NOT NULL,
                    mitre       TEXT,
                    evidence    TEXT,
                    cti_context TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON alerts(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sev ON alerts(severity)")

    def insert_alert(self, alert: Alert) -> int:
        """Insere une alerte, renvoie son id."""
        with self._connect() as conn:
            cur = conn.execute("""
                INSERT INTO alerts
                (timestamp, detector, severity, src_ip, dst_ip,
                 description, mitre, evidence, cti_context)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.timestamp, alert.detector, alert.severity,
                alert.src_ip, alert.dst_ip, alert.description, alert.mitre,
                json.dumps(alert.evidence),      # dict -> texte JSON
                json.dumps(alert.cti_context),
            ))
            return cur.lastrowid

    def insert_many(self, alerts: List[Alert]) -> int:
        """Insere plusieurs alertes, renvoie le nombre insere."""
        return sum(1 for a in alerts if self.insert_alert(a))

    def get_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[dict]:
        """Recupere les alertes les plus recentes."""
        query = "SELECT * FROM alerts"
        params = []
        if severity:
            query += " WHERE severity = ?"
            params.append(severity)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        result = []
        for r in rows:
            d = dict(r)
            d["evidence"] = json.loads(d["evidence"] or "{}")
            d["cti_context"] = json.loads(d["cti_context"] or "{}")
            result.append(d)
        return result

    def count(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def clear(self):
        """Vide la table (utile pour les tests)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM alerts")
