"""
cti/opencti.py — Connecteur OpenCTI (pycti 7.x / OpenCTI 7.x).
Respecte le contrat BaseCTI : lookup(value) -> dict | None,
attribut `connected`, instanciation SANS argument (config via .env/settings).
Interroge le hub OpenCTI (agrège MISP + AlienVault + CVE).
"""
from __future__ import annotations
import os
import logging
from typing import Optional

from pycti import OpenCTIApiClient
from cti.base_cti import BaseCTI

log = logging.getLogger("cti.opencti")

try:
    from config import settings as _settings
except Exception:
    _settings = None


def _cfg(name: str, default=None):
    """Lit une valeur depuis config.settings puis l'environnement."""
    if _settings is not None and hasattr(_settings, name):
        return getattr(_settings, name)
    return os.environ.get(name, default)


def _as_bool(v, default=False) -> bool:
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


class OpenCTIConnector(BaseCTI):
    SOURCE = "OpenCTI"

    def __init__(self, url: str = None, token: str = None, ssl_verify=None):
        # IMPORTANT : ne JAMAIS lever — sinon le CTIManager entier plante.
        self.connected = False
        self.api = None

        if not _as_bool(_cfg("OPENCTI_ENABLED", "true"), default=True):
            log.info("OpenCTI désactivé (OPENCTI_ENABLED=false)")
            return

        self.url = url or _cfg("OPENCTI_URL")
        token = token or _cfg("OPENCTI_TOKEN") or os.environ.get("TOKEN")
        if ssl_verify is None:
            ssl_verify = _as_bool(_cfg("OPENCTI_SSL_VERIFY", "false"))

        if not self.url or not token:
            log.warning("OpenCTI : URL ou token absent de la config (.env)")
            return

        try:
            self.api = OpenCTIApiClient(self.url, token,
                                        ssl_verify=ssl_verify, log_level="error")
            self.connected = True   # le health check pycti a réussi
            print(f"[OpenCTI] connecté à {self.url}")
        except Exception as e:
            log.warning("OpenCTI non joignable : %s", e)
            self.connected = False

    # --- contrat BaseCTI ---
    def lookup(self, value: str, itype: str = None) -> Optional[dict]:
        if not self.connected or self.api is None:
            return None
        try:
            obs = self._find_observable(value)
            if obs:
                return self._format(value, obs, "observable")
            ind = self._find_indicator(value)
            if ind:
                return self._format(value, ind, "indicator")
            return None                      # inconnu → None (pas un dict !)
        except Exception as e:
            log.warning("OpenCTI lookup %s : %s", value, e)
            return None

    def _find_observable(self, value):
        obs = self.api.stix_cyber_observable.read(
            filters={
                "mode": "and",
                "filters": [{"key": "value", "values": [value],
                             "operator": "eq", "mode": "or"}],
                "filterGroups": [],
            }
        )
        if obs:
            return obs
        res = self.api.stix_cyber_observable.list(search=value, first=1)
        return res[0] if res else None

    def _find_indicator(self, value):
        res = self.api.indicator.list(search=value, first=1)
        return res[0] if res else None

    def _format(self, value, obj, kind) -> dict:
        score = obj.get("x_opencti_score") or 0
        tags = [l.get("value") for l in (obj.get("objectLabel") or []) if l.get("value")]
        origin = (obj.get("createdBy") or {}).get("name")
        return {
            "source":        self.SOURCE,
            "matched_value": value,
            "type":          obj.get("entity_type"),
            "tags":          tags,           # → repris dans l'union du manager
            "score":         score,          # 0-100
            "threat_level":  self._level(score),
            "origin":        origin,         # MISP / AlienVault / CVE / CIRCL...
            "kind":          kind,
        }

    @staticmethod
    def _level(score):
        if score >= 80: return "CRITICAL"
        if score >= 60: return "HIGH"
        if score >= 40: return "MEDIUM"
        return "LOW"


# --- test standalone : export TOKEN=... ; python3 cti/opencti.py ---
if __name__ == "__main__":
    import json
    os.environ.setdefault("OPENCTI_URL", "http://192.168.100.50:8080")
    c = OpenCTIConnector()
    print("connected =", c.connected)
    if c.connected:
        sample = c.api.stix_cyber_observable.list(first=5)
        for o in sample:
            print("  -", o.get("observable_value"))
        if sample:
            val = sample[0].get("observable_value")
            print(f"\nLookup sur : {val}\n")
            print(json.dumps(c.lookup(val), indent=2, ensure_ascii=False))