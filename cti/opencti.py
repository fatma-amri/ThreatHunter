"""
Connecteur vers la plateforme OpenCTI (Cyber Threat Intelligence).

Interroge OpenCTI via la bibliotheque pycti pour rechercher un
indicateur (IP, domaine, hash) et renvoyer le contexte de menace,
au MEME format que le connecteur MISP (pour que l'Enricher soit
agnostique de la source).

Securite (RNF-09) : l'URL et le token sont lus depuis le fichier .env,
jamais ecrits en dur dans le code.
    OPENCTI_URL=http://192.168.100.XX:8080
    OPENCTI_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
"""
from __future__ import annotations
import os
from typing import Optional

from cti.base_cti import BaseCTI

try:
    from pycti import OpenCTIApiClient
    PYCTI_AVAILABLE = True
except ImportError:
    PYCTI_AVAILABLE = False


class OpenCTIConnector(BaseCTI):
    """Interroge OpenCTI pour enrichir les indicateurs des alertes."""

    SOURCE = "OpenCTI"

    def __init__(self, url: Optional[str] = None, token: Optional[str] = None,
                 ssl_verify: bool = False):
        # Lecture depuis .env si non fourni explicitement
        self.url = url or os.environ.get("OPENCTI_URL")
        self.token = token or os.environ.get("OPENCTI_TOKEN")
        self.ssl_verify = ssl_verify
        self.api = None
        self.connected = False

        if not PYCTI_AVAILABLE:
            print("[OpenCTI] pycti non installe (pip install pycti).")
            return
        if not (self.url and self.token):
            print("[OpenCTI] URL ou token absent du .env.")
            return

        try:
            # log_level='error' pour ne pas noyer la sortie de pycti
            self.api = OpenCTIApiClient(self.url, self.token,
                                        ssl_verify=self.ssl_verify,
                                        log_level="error")
            self.connected = True
            print(f"[OpenCTI] Connexion etablie : {self.url}")
        except Exception as e:
            print(f"[OpenCTI] Connexion impossible : {e}")

    # ─────────────────────────────────────────────────────────
    def lookup(self, value: str) -> Optional[dict]:
        """
        Recherche un indicateur dans OpenCTI (observable STIX).
        Retourne un dict de contexte si connu, sinon None.
        Meme format que MISPConnector.lookup().
        """
        if not self.connected:
            return None

        try:
            # Recherche d'un observable (Stix Cyber Observable) par valeur
            observable = self.api.stix_cyber_observable.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "value", "values": [value]}],
                    "filterGroups": [],
                }
            )
        except Exception as e:
            print(f"[OpenCTI] Erreur de recherche pour {value} : {e}")
            return None

        if not observable:
            return None  # indicateur inconnu d'OpenCTI

        # Extraction des labels (categories de menace) et du score
        labels = []
        for lbl in observable.get("objectLabel", []) or []:
            if isinstance(lbl, dict):
                labels.append(lbl.get("value", ""))
            else:
                labels.append(str(lbl))

        # Le score OpenCTI (0-100) -> niveau de menace lisible
        score = None
        for ind in observable.get("indicators", []) or []:
            if isinstance(ind, dict) and ind.get("x_opencti_score") is not None:
                score = ind["x_opencti_score"]
                break

        context = {
            "source": "OpenCTI",
            "matched_value": value,
            "type": observable.get("entity_type"),
            "observable_id": observable.get("id"),
            "score": score,
            "tags": [l for l in labels if l],
            "created_by": (observable.get("createdBy") or {}).get("name")
                          if observable.get("createdBy") else None,
        }
        return context
