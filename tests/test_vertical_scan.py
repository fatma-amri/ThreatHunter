"""
Test unitaire du VerticalScanDetector.

A lancer depuis la RACINE du depot :
    python3 -m tests.test_vertical_scan
    (ou : pytest tests/test_vertical_scan.py)

Verifie deux choses :
  1. un vertical scan (1000 ports sur UNE cible) leve exactement 1 alerte ;
  2. un trafic disperse (beaucoup d'hotes mais peu de ports par cible) ne
     declenche PAS ce detecteur -> on ne confond pas vertical et horizontal.
"""
import random
import pandas as pd

from detectors.vertical_scan import VerticalScanDetector

BASE_TS = 1_700_000_000


def build_conn() -> pd.DataFrame:
    rows = []

    # 1. Vertical scan : .40 -> UNE cible (.30), 1000 ports distincts
    for p in range(1, 1001):
        rows.append({
            "ts": BASE_TS + random.uniform(0, 60),
            "id.orig_h": "192.168.100.40",
            "id.resp_h": "192.168.100.30",
            "id.resp_p": p,
            "proto": "tcp",
            "conn_state": "REJ",
        })

    # 2. Trafic disperse (.41) : 1 seul port (445) sur 200 hotes differents.
    #    Beaucoup de connexions, mais seulement 1 port par cible
    #    -> ce n'est PAS un vertical scan, ne doit PAS alerter.
    for h in range(1, 201):
        rows.append({
            "ts": BASE_TS + random.uniform(0, 60),
            "id.orig_h": "192.168.100.41",
            "id.resp_h": f"10.0.0.{h}",
            "id.resp_p": 445,
            "proto": "tcp",
            "conn_state": "REJ",
        })

    return pd.DataFrame(rows)


def test_vertical_scan():
    logs = {"conn": build_conn()}
    alerts = VerticalScanDetector().analyze(logs)

    # NB : si ton objet Alert expose des attributs differents
    # (ex: source_ip / details au lieu de src_ip / evidence),
    # adapte les lignes ci-dessous a ta classe Alert.
    assert len(alerts) == 1, f"Attendu 1 alerte, obtenu {len(alerts)}"
    a = alerts[0]
    assert a.src_ip == "192.168.100.40", "Mauvaise source detectee"
    assert a.evidence["distinct_ports"] == 1000, "Comptage de ports incorrect"
    assert a.evidence["target"] == "192.168.100.30", "Mauvaise cible"

    print("OK : 1 alerte vertical scan (.40 -> .30, 1000 ports).")
    print("OK : trafic disperse (.41, 1 port sur 200 hotes) ignore -> pas de confusion.")


if __name__ == "__main__":
    test_vertical_scan()
