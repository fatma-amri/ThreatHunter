"""
cti/upstream_matcher.py — Matching CTI EN AMONT de la détection.

Parcourt les logs Zeek parsés, extrait les indicateurs externes
(IP publiques, domaines DNS, hosts HTTP, SNI TLS), les croise avec la CTI
(OpenCTI + MISP via le CTIManager) et émet une alerte pour chaque IOC
CONFIRMÉ MALVEILLANT — avant toute détection comportementale.

Complémentaire de l'enrichissement aval (cti/enrichment.py), qui ajoute
du contexte aux alertes déjà détectées.

Deux garde-fous essentiels :
  1. Filtre d'infrastructure  : ignore mDNS / multicast / IPv6 link-local /
     domaines légitimes (Microsoft, Apple, Google, Ubuntu...).
  2. Seuil de malveillance    : « présent dans la CTI » ne suffit PAS ;
     on n'alerte que si le score est élevé OU si un label de menace est présent.
"""
from __future__ import annotations
import ipaddress
import logging
from typing import List, Dict

import pandas as pd

from core.alerts import Alert
from cti.manager import CTIManager

log = logging.getLogger("cti.upstream")

# ── Réseaux privés / non routables (on ne matche que l'externe) ──
_PRIVATE = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "0.0.0.0/8",
)]

# ── Bruit d'infrastructure à exclure (mDNS, service-discovery, domaines légitimes) ──
_INFRA_SUFFIXES = (".local", ".arpa", "_tcp", "_udp", ".in-addr")
_INFRA_DOMAINS = (
    "microsoft.com", "msedge.net", "windows.com", "windowsupdate.com",
    "apple.com", "icloud.com", "google.com", "gstatic.com", "googleapis.com",
    "ubuntu.com", "canonical.com", "mozilla.org", "office.com", "office365.com",
    "akamaized.net", "cloudflare.com", "amazonaws.com",
)


def _is_external_ip(value: str) -> bool:
    """True si l'IP est publique (routable sur Internet)."""
    try:
        addr = ipaddress.ip_address(value)
        return not any(addr in net for net in _PRIVATE)
    except ValueError:
        return False


def _is_ipv6_local(value: str) -> bool:
    """True pour les IPv6 link-local / multicast / privées (bruit interne)."""
    try:
        a = ipaddress.ip_address(value)
        return a.version == 6 and (a.is_link_local or a.is_multicast or a.is_private)
    except ValueError:
        return False


def _is_infra_noise(value: str) -> bool:
    """True si la valeur est du bruit d'infrastructure légitime (mDNS, MS, Apple...)."""
    v = value.lower()
    if any(s in v for s in _INFRA_SUFFIXES):
        return True
    if any(v == d or v.endswith("." + d) for d in _INFRA_DOMAINS):
        return True
    return False


class UpstreamMatcher:
    """Croise les indicateurs des logs avec la CTI, avant la détection."""

    SOURCE = "CTIMatchDetector"

    # Garde-fou mémoire : nombre max d'indicateurs distincts interrogés.
    MAX_LOOKUPS = 300

    # Un IOC n'est retenu comme menace que si le score >= SCORE_MIN
    # OU si un label de menace est présent. « Présent » seul ne suffit pas.
    SCORE_MIN = 50
    MALICIOUS_LABELS = {
        "malicious-activity", "malicious", "c2", "command-and-control",
        "malware", "phishing", "botnet", "exfiltration", "ransomware",
        "trojan", "apt", "attack-pattern",
    }

    def __init__(self, manager: CTIManager = None):
        self.manager = manager or CTIManager()

    # ─────────────────────────────────────────────────────────
    def match(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        """Retourne une liste d'alertes pour les IOC malveillants confirmés."""
        if not self.manager.connected:
            print("[CTI amont] Aucune source CTI connectée, matching amont ignoré.")
            return []

        candidates = self._extract_indicators(logs)
        total = len(candidates)
        if total > self.MAX_LOOKUPS:
            print(f"[CTI amont] {total} indicateurs uniques — "
                  f"limité aux {self.MAX_LOOKUPS} premiers (garde-fou mémoire).")
            candidates = dict(list(candidates.items())[:self.MAX_LOOKUPS])

        alerts: List[Alert] = []
        seen = 0        # présents dans la CTI
        skipped = 0     # présents mais pas confirmés malveillants
        for value, meta in candidates.items():
            ctx = self.manager.lookup(value)
            if not ctx:
                continue
            seen += 1
            if not self._is_malicious(ctx):
                skipped += 1
                continue
            alerts.append(self._make_alert(value, meta, ctx))

        print(f"[CTI amont] {len(alerts)} IOC MALVEILLANT(s) confirmé(s) "
              f"({seen} présent(s) dans la CTI, {skipped} écarté(s) "
              f"car score/labels faibles) sur {total} indicateur(s) unique(s).")
        return alerts

    # ─────────────────────────────────────────────────────────
    def _is_malicious(self, ctx: dict) -> bool:
        """« Présent » ne suffit pas : exige un score élevé OU un label de menace."""
        details = ctx.get("details", {}) or {}
        detail = details.get("OpenCTI") or next(iter(details.values()), {})
        score = detail.get("score", 0) or 0
        tags = [t for t in (ctx.get("tags", []) or []) if t]

        if score >= self.SCORE_MIN:
            return True
        if tags:                       # tout label de tes feeds = marqueur de menace
            return True
        return False

    # ─────────────────────────────────────────────────────────
    def _extract_indicators(self, logs: Dict[str, pd.DataFrame]) -> Dict[str, dict]:
        """
        Construit {indicateur: {src, dst, logs:[...]}} à partir des logs.
        Vectorisé (unique() par colonne, pas de iterrows) → économe en mémoire.
        Le bruit d'infrastructure est écarté dès l'ajout.
        """
        out: Dict[str, dict] = {}

        def add(value, src=None, dst=None, origin_log=None):
            if not value or value in ("-", "N/A", "nan", "", "None"):
                return
            if _is_infra_noise(value) or _is_ipv6_local(value):
                return   # mDNS / multicast / infra légitime → ignoré
            entry = out.setdefault(value, {"src": src, "dst": dst, "logs": []})
            if origin_log and origin_log not in entry["logs"]:
                entry["logs"].append(origin_log)

        # conn : IP destination/orig externes uniques
        conn = logs.get("conn")
        if conn is not None and not conn.empty and "id.resp_h" in conn.columns:
            for d in conn["id.resp_h"].dropna().astype(str).unique():
                if _is_external_ip(d):
                    add(d, dst=d, origin_log="conn")
            if "id.orig_h" in conn.columns:
                for o in conn["id.orig_h"].dropna().astype(str).unique():
                    if _is_external_ip(o):
                        add(o, src=o, origin_log="conn")

        # dns : domaines interrogés uniques
        dns = logs.get("dns")
        if dns is not None and not dns.empty and "query" in dns.columns:
            for q in dns["query"].dropna().astype(str).unique():
                q = q.strip(".").lower()
                if q and "." in q:
                    add(q, origin_log="dns")

        # http : hosts uniques
        http = logs.get("http")
        if http is not None and not http.empty and "host" in http.columns:
            for h in http["host"].dropna().astype(str).unique():
                h = h.strip().lower()
                if h:
                    add(h, origin_log="http")

        # ssl : SNI (server_name) uniques
        ssl = logs.get("ssl")
        if ssl is not None and not ssl.empty and "server_name" in ssl.columns:
            for s in ssl["server_name"].dropna().astype(str).unique():
                s = s.strip().lower()
                if s:
                    add(s, origin_log="ssl")

        return out

    # ─────────────────────────────────────────────────────────
    def _make_alert(self, value, meta, ctx) -> Alert:
        details = ctx.get("details", {}) or {}
        detail = details.get("OpenCTI") or next(iter(details.values()), {})
        score = detail.get("score", 0) or 0
        sev = self._severity(detail.get("threat_level"), score)
        sources = ", ".join(ctx.get("sources", []))

        a = Alert(
            detector=self.SOURCE,
            src_ip=meta.get("src") or value,
            dst_ip=meta.get("dst"),
            severity=sev,
            mitre="",   # un hit CTI n'est pas une technique ATT&CK unique
            description=(f"IOC connu identifié EN AMONT : {value} "
                         f"(CTI : {sources}, score {score}, "
                         f"origine {detail.get('origin')})"),
        )
        a.cti_context = ctx
        a.evidence = {
            "cti_match": True,
            "indicator": value,
            "origin": detail.get("origin"),
            "score": score,
            "threat_level": detail.get("threat_level"),
            "labels": ctx.get("tags", []),
            "seen_in": meta.get("logs", []),
        }
        return a

    # ─────────────────────────────────────────────────────────
    @staticmethod
    def _severity(threat_level, score):
        if threat_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return threat_level
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        return "LOW"


# ── test standalone : python3 -m cti.upstream_matcher ──
if __name__ == "__main__":
    import os
    os.environ.setdefault("OPENCTI_URL", "http://192.168.100.50:8080")
    m = UpstreamMatcher()
    print("manager connecté :", m.manager.connected)
    # petit auto-test des filtres
    for v in ("ff02::fb", "x._udp.local", "settings-win.data.microsoft.com",
              "8.8.8.8", "evil-c2.example.com"):
        print(f"  {v:45s} infra={_is_infra_noise(v)} "
              f"ipv6local={_is_ipv6_local(v)} externe={_is_external_ip(v)}")