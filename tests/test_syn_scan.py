"""
Test unitaire du SynScanDetector.

A lancer depuis la RACINE du depot :
    python3 -m tests.test_syn_scan
    (ou : pytest tests/test_syn_scan.py)

Verifie deux choses :
  1. un SYN scan (1000 ports distincts en etat S0) leve exactement 1 alerte ;
  2. un trafic benin (connexions completes SF) ne declenche AUCUNE alerte.
"""
import random
import pandas as pd

from detectors.syn_scan import SynScanDetector

BASE_TS = 1_700_000_000


def build_conn() -> pd.DataFrame:
    rows = []

    # 1. SYN scan : Kali (.40) -> Victim (.30), 1000 ports en etat S0
    for p in range(1, 1001):
        rows.append({
            "ts": BASE_TS + random.uniform(0, 60),
            "id.orig_h": "192.168.100.40",
            "id.resp_h": "192.168.100.30",
            "id.resp_p": p,
            "proto": "tcp",
            "conn_state": "S0",          # SYN vu, pas de handshake -> half-open
        })

    # 2. Trafic benin : navigation normale (.35) en SF sur 4 ports
    #    -> etat SF, donc EXCLU par le filtre S0 : ne doit PAS alerter.
    for i in range(40):
        rows.append({
            "ts": BASE_TS + random.uniform(0, 60),
            "id.orig_h": "192.168.100.35",
            "id.resp_h": "192.168.100.30",
            "id.resp_p": random.choice([80, 443, 22, 53]),
            "proto": "tcp",
            "conn_state": "SF",          # connexion complete
        })

    return pd.DataFrame(rows)


def test_syn_scan():
    logs = {"conn": build_conn()}
    alerts = SynScanDetector().analyze(logs)

    # NB : si ton objet Alert expose des attributs differents
    # (ex: source_ip / details au lieu de src_ip / evidence),
    # adapte les deux lignes ci-dessous a ta classe Alert.
    assert len(alerts) == 1, f"Attendu 1 alerte, obtenu {len(alerts)}"
    a = alerts[0]
    assert a.src_ip == "192.168.100.40", "Mauvaise source detectee"
    assert a.evidence["distinct_ports"] == 1000, "Comptage de ports incorrect"
    assert a.evidence["conn_state"] == "S0", "Etat attendu : S0"

    print("OK : 1 alerte SYN scan (.40, 1000 ports S0).")
    print("OK : trafic benin SF (.35) correctement ignore -> 0 faux positif.")


if __name__ == "__main__":
    test_syn_scan()
