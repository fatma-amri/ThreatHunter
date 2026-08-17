"""
Test unitaire du HorizontalScanDetector.

A lancer depuis la RACINE du depot :
    python3 -m tests.test_horizontal_scan
    (ou : pytest tests/test_horizontal_scan.py)

Verifie deux choses :
  1. un horizontal scan (port 445 teste sur 200 hotes) leve 1 alerte ;
  2. un vertical scan (beaucoup de ports sur 1 seule cible) ne declenche
     PAS ce detecteur -> on ne confond pas horizontal et vertical.
"""
import random
import pandas as pd

from detectors.horizontal_scan import HorizontalScanDetector

BASE_TS = 1_700_000_000


def build_conn() -> pd.DataFrame:
    rows = []

    # 1. Horizontal scan : .40 teste le port 445 sur 200 hotes distincts
    for h in range(1, 201):
        rows.append({
            "ts": BASE_TS + random.uniform(0, 60),
            "id.orig_h": "192.168.100.40",
            "id.resp_h": f"192.168.100.{h}",
            "id.resp_p": 445,
            "proto": "tcp",
            "conn_state": "REJ",
        })

    # 2. Vertical scan (.41) : 1000 ports sur UNE seule cible.
    #    Beaucoup de ports mais 1 seul hote par port -> ce n'est PAS
    #    un horizontal scan, ne doit PAS alerter.
    for p in range(1, 1001):
        rows.append({
            "ts": BASE_TS + random.uniform(0, 60),
            "id.orig_h": "192.168.100.41",
            "id.resp_h": "192.168.100.30",
            "id.resp_p": p,
            "proto": "tcp",
            "conn_state": "REJ",
        })

    return pd.DataFrame(rows)


def test_horizontal_scan():
    logs = {"conn": build_conn()}
    alerts = HorizontalScanDetector().analyze(logs)

    # NB : si ton objet Alert expose des attributs differents
    # (ex: source_ip / details au lieu de src_ip / evidence),
    # adapte les lignes ci-dessous a ta classe Alert.
    assert len(alerts) == 1, f"Attendu 1 alerte, obtenu {len(alerts)}"
    a = alerts[0]
    assert a.src_ip == "192.168.100.40", "Mauvaise source detectee"
    assert a.evidence["dst_port"] == 445, "Mauvais port"
    assert a.evidence["distinct_hosts"] == 200, "Comptage d'hotes incorrect"

    print("OK : 1 alerte horizontal scan (.40, port 445 sur 200 hotes).")
    print("OK : vertical scan (.41, 1000 ports sur 1 hote) ignore -> pas de confusion.")


if __name__ == "__main__":
    test_horizontal_scan()
