"""
Test unitaire du DNSTunnelDetector.

A lancer depuis la RACINE du depot :
    python3 -m tests.test_dns_tunnel
    (ou : pytest tests/test_dns_tunnel.py)

Verifie deux choses :
  1. un tunnel DNS (20 requetes longues + haute entropie) leve 1 alerte ;
  2. du DNS legitime (noms courts et lisibles) ne declenche PAS le detecteur.
"""
import random
import string
import pandas as pd

from detectors.dns_tunnel import DNSTunnelDetector

BASE_TS = 1_700_000_000


def _rand_label(n: int) -> str:
    """Sous-domaine aleatoire (base32-like) : long + haute entropie."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def build_dns() -> pd.DataFrame:
    rows = []

    # 1. Tunnel DNS : .40 -> 20 requetes ~50 chars, encodees sous evil.com
    for _ in range(20):
        q = f"{_rand_label(48)}.evil.com"
        rows.append({
            "ts": BASE_TS,
            "id.orig_h": "192.168.100.40",
            "query": q,
        })

    # 2. DNS legitime : .35 -> noms courts, lisibles, faible entropie
    for q in ["www.google.com", "mail.google.com", "api.github.com",
              "cdn.cloudflare.com", "www.wikipedia.org", "ntp.ubuntu.com"]:
        rows.append({
            "ts": BASE_TS,
            "id.orig_h": "192.168.100.35",
            "query": q,
        })

    return pd.DataFrame(rows)


def test_dns_tunnel():
    logs = {"dns": build_dns()}
    alerts = DNSTunnelDetector().analyze(logs)

    # NB : si ton objet Alert expose des attributs differents
    # (ex: source_ip / details au lieu de src_ip / evidence),
    # adapte les lignes ci-dessous a ta classe Alert.
    assert len(alerts) == 1, f"Attendu 1 alerte, obtenu {len(alerts)}"
    a = alerts[0]
    assert a.src_ip == "192.168.100.40", "Mauvaise source detectee"
    assert a.evidence["suspicious_queries"] >= 10, "Trop peu de requetes suspectes"
    assert a.evidence["max_entropy"] >= 3.5, "Entropie max trop faible"

    print("OK : 1 alerte DNS tunneling (.40, 20 requetes longues haute entropie).")
    print("OK : DNS legitime (.35, noms courts) ignore -> pas de faux positif.")


if __name__ == "__main__":
    test_dns_tunnel()
