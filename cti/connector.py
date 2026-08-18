"""
Connecteur vers la plateforme MISP (Cyber Threat Intelligence).

Ce module interroge MISP via PyMISP pour rechercher un indicateur
(IP, domaine, hash) et renvoyer le contexte de menace associe.

La couche CTI est concue pour etre modulaire : MISP et OpenCTI
implementent la meme interface BaseCTI.

Securite (RNF-09) : l'URL et la cle API sont lues depuis le fichier .env,
jamais ecrites en dur dans le code.
"""
from __future__ import annotations
import os
from typing import Optional

from cti.base_cti import BaseCTI

try:
    from pymisp import PyMISP
    PYMISP_AVAILABLE = True
except ImportError:
    PYMISP_AVAILABLE = False


class MISPConnector(BaseCTI):
    """Interroge MISP pour enrichir les indicateurs des alertes."""

    SOURCE = "MISP"

    def __init__(self, url: Optional[str] = None, key: Optional[str] = None,
                 verify_ssl: bool = False):
        # Lecture depuis .env si non fourni explicitement
        self.url = url or os.environ.get("MISP_URL")
        self.key = key or os.environ.get("MISP_KEY")
        self.verify_ssl = verify_ssl
        self.misp = None
        self.connected = False

        if not PYMISP_AVAILABLE:
            print("[MISP] PyMISP non installe (pip install pymisp).")
            return
        if not (self.url and self.key):
            print("[MISP] URL ou cle API absente du .env.")
            return

        try:
            self.misp = PyMISP(self.url, self.key, self.verify_ssl)
            self.connected = True
            print(f"[MISP] Connexion etablie : {self.url}")
        except Exception as e:
            print(f"[MISP] Connexion impossible : {e}")

    # ─────────────────────────────────────────────────────────
    def lookup(self, value: str) -> Optional[dict]:
        """
        Recherche un indicateur (IP, domaine, hash) dans MISP.
        Retourne un dictionnaire de contexte si l'indicateur est connu,
        sinon None. Le contexte contient : la source, l'evenement associe,
        les tags (categories de menace) et le niveau de confiance.
        """
        if not self.connected:
            return None

        try:
            # Recherche des attributs correspondant a la valeur
            result = self.misp.search(controller="attributes",
                                      value=value, pythonify=True)
        except Exception as e:
            print(f"[MISP] Erreur de recherche pour {value} : {e}")
            return None

        if not result:
            return None  # indicateur inconnu de MISP

        # On prend le premier attribut correspondant
        attr = result[0]
        event = getattr(attr, "Event", None)

        # Extraction des tags (categories de menace)
        tags = []
        for t in getattr(attr, "tags", []) or []:
            tags.append(getattr(t, "name", str(t)))

        context = {
            "source": "MISP",
            "matched_value": value,
            "category": getattr(attr, "category", None),
            "type": getattr(attr, "type", None),
            "event_id": getattr(event, "id", None) if event else None,
            "event_info": getattr(event, "info", None) if event else None,
            "tags": tags,
            "comment": getattr(attr, "comment", None),
        }
        return context

    # ─────────────────────────────────────────────────────────
    def version(self) -> Optional[str]:
        """Retourne la version de l'instance MISP (test de connexion)."""
        if not self.connected:
            return None
        try:
            return self.misp.misp_instance_version.get("version")
        except Exception:
            return None