"""
Interface commune a tous les connecteurs CTI (MISP, OpenCTI, ...).

Chaque connecteur implemente lookup(value) -> dict | None avec le MEME
format de retour, ce qui permet au CTIManager de les interroger de
maniere uniforme et a l'Enricher de ne pas dependre d'une source
particuliere.

Format de retour attendu de lookup() (ou None si indicateur inconnu) :
    {
        "source":        "MISP" | "OpenCTI",
        "matched_value": <str>,        # l'indicateur trouve
        "type":          <str|None>,   # ip / domain / hash ...
        "tags":          [<str>, ...], # categories de menace
        ...                            # champs libres selon la source
    }
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional


class BaseCTI(ABC):
    """Contrat commun a tous les connecteurs de Threat Intelligence."""

    # Nom de la source, redefini par chaque connecteur (ex: "MISP", "OpenCTI")
    SOURCE: str = "BaseCTI"

    #: True si le connecteur a pu se connecter a sa source
    connected: bool = False

    @abstractmethod
    def lookup(self, value: str) -> Optional[dict]:
        """
        Recherche un indicateur (IP, domaine, hash) dans la source CTI.
        Retourne un dict de contexte si connu, sinon None.
        """
        raise NotImplementedError

    def __str__(self) -> str:
        etat = "connecte" if self.connected else "non connecte"
        return f"{self.SOURCE} ({etat})"
