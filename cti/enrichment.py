"""
Enrichissement des alertes par la Cyber Threat Intelligence.

Interroge la CTI (MISP + OpenCTI, via le CTIManager) sur les indicateurs
des alertes. Si un indicateur est connu d'au moins une source, le contexte
de menace est ajoute dans le champ `cti_context` de l'alerte.

L'enrichissement intervient APRES la detection : la CTI ajoute du contexte
a ce qui a deja ete detecte par comportement, elle ne detecte pas.
"""
from __future__ import annotations
from typing import List

from cti.manager import CTIManager
from core.alerts import Alert


class Enricher:
    """Enrichit une liste d'alertes avec le contexte CTI (MISP + OpenCTI)."""

    def __init__(self, manager: CTIManager = None):
        self.manager = manager or CTIManager()

    def _values_to_check(self, alert: Alert) -> List[str]:
        """
        Indicateurs a rechercher pour une alerte. En threat hunting reseau,
        l'IP destination (serveur contacte : C2, exfiltration...) est le plus
        pertinent ; on verifie aussi la source par prudence.
        """
        values = []
        if alert.dst_ip and alert.dst_ip != "N/A":
            values.append(alert.dst_ip)
        if alert.src_ip:
            values.append(alert.src_ip)
        return values

    def enrich(self, alert: Alert) -> Alert:
        """Enrichit une seule alerte (modifie son champ cti_context)."""
        if not self.manager.connected:
            return alert

        for value in self._values_to_check(alert):
            context = self.manager.lookup(value)
            if context:
                alert.cti_context = context
                if alert.severity in ("LOW", "MEDIUM"):
                    alert.severity = "HIGH"
                break
        return alert

    def enrich_all(self, alerts: List[Alert]) -> List[Alert]:
        """Enrichit toutes les alertes d'une liste."""
        if not self.manager.connected:
            print("[Enrichissement] Aucune source CTI connectee, "
                  "alertes non enrichies.")
            return alerts

        enriched_count = 0
        for alert in alerts:
            self.enrich(alert)
            if alert.cti_context:
                enriched_count += 1

        print(f"[Enrichissement] {enriched_count}/{len(alerts)} "
              f"alerte(s) enrichie(s) par la CTI (MISP + OpenCTI).")
        return alerts
