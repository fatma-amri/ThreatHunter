"""
Alert Correlation (couche 6 du pipeline).

Objectif : reduire le bruit. Plusieurs detecteurs peuvent lever des alertes
distinctes pour une meme activite malveillante venant d'une meme source
(ex : un scan de ports PUIS un brute force depuis la meme IP). La correlation
regroupe ces alertes liees — meme IP source + fenetre de temps proche — en un
seul INCIDENT correle, tout en gardant la trace de chaque detecteur implique.

    N alertes  ->  1 alerte correlee (correlated_count = N)

Regle de regroupement : meme src_ip ET timestamps espaces de moins de
`window_seconds` (settings.THRESHOLDS["correlation"]).
"""
from typing import List
from datetime import datetime

from core.alerts import Alert
from config import settings

# Ordre de gravite : sert a choisir l'alerte "representante" d'un incident
_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


class Correlator:
    """Regroupe les alertes liees (meme source, meme periode)."""

    DEFAULT_WINDOW = 300  # secondes

    def __init__(self):
        cfg = settings.THRESHOLDS.get("correlation", {})
        self.window = cfg.get("window_seconds", self.DEFAULT_WINDOW)

    # ------------------------------------------------------------------ #
    def correlate(self, alerts: List[Alert]) -> List[Alert]:
        """Prend une liste d'alertes brutes -> liste d'incidents correles."""
        if not alerts:
            return []

        # 1. Regrouper par IP source
        by_src: dict = {}
        for a in alerts:
            by_src.setdefault(a.src_ip, []).append(a)

        incidents: List[Alert] = []

        # 2. Pour chaque source, decouper en fenetres temporelles
        for src_ip, group in by_src.items():
            group.sort(key=lambda a: self._ts(a))
            window_bucket: List[Alert] = [group[0]]

            for prev, cur in zip(group, group[1:]):
                if self._ts(cur) - self._ts(prev) <= self.window:
                    window_bucket.append(cur)
                else:
                    incidents.append(self._merge(window_bucket))
                    window_bucket = [cur]
            incidents.append(self._merge(window_bucket))

        return incidents

    # ------------------------------------------------------------------ #
    def _merge(self, bucket: List[Alert]) -> Alert:
        """Fusionne un groupe d'alertes en un seul incident correle."""
        if len(bucket) == 1:
            a = bucket[0]
            a.related_detectors = [a.detector]
            return a

        # Alerte representante = la plus grave (puis la plus ancienne)
        rep = max(bucket, key=lambda a: (_SEV_ORDER.get(a.severity, 0), -self._ts(a)))

        detectors = sorted({a.detector for a in bucket})
        techniques = sorted({a.mitre for a in bucket if a.mitre})

        # Union du contexte CTI (le premier non vide gagne par cle)
        merged_cti: dict = {}
        for a in bucket:
            for k, v in (a.cti_context or {}).items():
                merged_cti.setdefault(k, v)

        rep.correlated_count = len(bucket)
        rep.related_detectors = detectors
        rep.cti_context = merged_cti or rep.cti_context
        rep.description = (
            f"Incident correle : {len(bucket)} alertes depuis {rep.src_ip} "
            f"({', '.join(detectors)}). Alerte principale — {rep.description}"
        )
        rep.evidence = dict(rep.evidence or {})
        rep.evidence["correlated_alerts"] = [
            {
                "detector": a.detector,
                "severity": a.severity,
                "mitre": a.mitre,
                "dst_ip": a.dst_ip,
                "description": a.description,
            }
            for a in bucket
        ]
        rep.evidence["mitre_techniques"] = techniques
        return rep

    # ------------------------------------------------------------------ #
    @staticmethod
    def _ts(alert: Alert) -> float:
        """Convertit le timestamp ISO en secondes (epoch). Tolerant aux erreurs."""
        try:
            return datetime.fromisoformat(alert.timestamp).timestamp()
        except (ValueError, TypeError):
            return 0.0
