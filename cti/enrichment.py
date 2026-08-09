"""
Enrichissement des alertes par la Cyber Threat Intelligence.

Ce module prend les alertes produites par les detecteurs et interroge
la CTI (MISP) sur leurs indicateurs. Si un indicateur est connu, le
contexte de menace est ajoute dans le champ `cti_context` de l'alerte.

C'est l'etape qui transforme une alerte BRUTE (comportement detecte) en
une alerte QUALIFIEE (comportement + contexte de menace connu).

Important : l'enrichissement intervient APRES la detection. La CTI
n'a jamais servi a detecter — elle ajoute du contexte a ce qui a
deja ete detecte par comportement.
"""
from __future__ import annotations
from typing import List

from cti.connector import MISPConnector
from core.alerts import Alert


class Enricher:
    """Enrichit une liste d'alertes avec le contexte CTI (MISP)."""

    def __init__(self, connector: MISPConnector = None):
        self.connector = connector or MISPConnector()

    def _values_to_check(self, alert: Alert) -> List[str]:
        """
        Determine les indicateurs a rechercher dans MISP pour une alerte.
        Pour du threat hunting reseau, l'indicateur cle est l'IP destination
        (le serveur contacte : C2, exfiltration...). On verifie aussi la
        source par prudence.
        """
        values = []
        # La destination est l'indicateur le plus pertinent (serveur distant)
        if alert.dst_ip and alert.dst_ip != "N/A":
            values.append(alert.dst_ip)
        # La source peut aussi etre un indicateur (machine attaquante connue)
        if alert.src_ip:
            values.append(alert.src_ip)
        return values

    def enrich(self, alert: Alert) -> Alert:
        """Enrichit une seule alerte (modifie son champ cti_context)."""
        if not self.connector.connected:
            return alert

        for value in self._values_to_check(alert):
            context = self.connector.lookup(value)
            if context:
                # Indicateur connu de MISP : on enrichit et on s'arrete
                alert.cti_context = context
                # Un match CTI eleve la severite (menace confirmee)
                if alert.severity in ("LOW", "MEDIUM"):
                    alert.severity = "HIGH"
                break
        return alert

    def enrich_all(self, alerts: List[Alert]) -> List[Alert]:
        """Enrichit toutes les alertes d'une liste."""
        if not self.connector.connected:
            print("[Enrichissement] MISP non connecte, alertes non enrichies.")
            return alerts

        enriched_count = 0
        for alert in alerts:
            self.enrich(alert)
            if alert.cti_context:
                enriched_count += 1

        print(f"[Enrichissement] {enriched_count}/{len(alerts)} "
              f"alerte(s) enrichie(s) par MISP.")
        return alerts