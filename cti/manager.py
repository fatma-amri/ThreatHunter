"""
Gestionnaire multi-sources de Cyber Threat Intelligence.

Le CTIManager regroupe plusieurs connecteurs (MISP, OpenCTI, ...) derriere
une interface unique. Pour un indicateur donne, il interroge TOUS les
connecteurs connectes et consolide leurs reponses.

Avantage : l'Enricher ne connait qu'UN objet (le manager), et l'ajout
d'une nouvelle source CTI ne demande aucune modification de l'Enricher.
"""
from __future__ import annotations
from typing import List, Optional

from cti.connector import MISPConnector
from cti.opencti import OpenCTIConnector


class CTIManager:
    """Interroge plusieurs sources CTI et consolide les resultats."""

    def __init__(self, connectors: Optional[list] = None):
        # Par defaut : MISP + OpenCTI. Chacun se connecte via le .env ;
        # un connecteur non joignable reste simplement 'non connecte'.
        if connectors is None:
            connectors = [MISPConnector(), OpenCTIConnector()]
        self.connectors = connectors

        actifs = [str(c) for c in self.connectors]
        print(f"[CTIManager] Connecteurs : {', '.join(actifs)}")

    @property
    def connected(self) -> bool:
        """True si AU MOINS une source CTI est joignable."""
        return any(getattr(c, "connected", False) for c in self.connectors)

    def lookup(self, value: str) -> Optional[dict]:
        """
        Interroge toutes les sources connectees pour un indicateur.
        Retourne un contexte consolide (ou None si aucune source ne connait
        l'indicateur).

        Format consolide :
            {
              "sources":  ["MISP", "OpenCTI"],   # sources ayant un match
              "matched_value": <str>,
              "tags":     [...],                 # union des tags/labels
              "details":  { "MISP": {...}, "OpenCTI": {...} },
            }
        """
        matches = {}
        all_tags: List[str] = []

        for connector in self.connectors:
            if not getattr(connector, "connected", False):
                continue
            try:
                ctx = connector.lookup(value)
            except Exception as e:
                print(f"[CTIManager] Erreur {getattr(connector, 'SOURCE', '?')} "
                      f"sur {value} : {e}")
                ctx = None
            if ctx:
                source = ctx.get("source", getattr(connector, "SOURCE", "?"))
                matches[source] = ctx
                for t in ctx.get("tags", []) or []:
                    if t and t not in all_tags:
                        all_tags.append(t)

        if not matches:
            return None  # aucun connecteur ne connait cet indicateur

        return {
            "sources":       list(matches.keys()),
            "matched_value": value,
            "tags":          all_tags,
            "details":       matches,
        }
