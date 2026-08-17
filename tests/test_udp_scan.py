"""
Test unitaire du UdpScanDetector.

A lancer depuis la RACINE du depot :
    python3 -m tests.test_udp_scan
    (ou : pytest tests/test_udp_scan.py)

Verifie deux choses :
  1. un UDP scan (1000 ports UDP distincts) leve exactement 1 alerte ;
  2. du trafic TCP (meme volume de ports) ne declenche PAS ce detecteur
     -> le filtre proto == udp fonctionne.
"""
import random
import pandas as pd

from detectors.udp_scan import UdpScanDetector

BASE_TS = 1_700_000_000


def build_conn() -> pd.DataFrame:
    rows = []

    # 1. UDP scan : Kali (.40) -> Victim (.30), 1000 ports UDP distincts
    for p in range(1, 1001):
        rows.append({
            "ts": BASE_TS + random.uniform(0, 60),
            "id.orig_h": "192.168.100.40",
            "id.resp_h": "192.168.100.30",
            "id.resp_p": p,
            "proto": "udp",
            "conn_state": "S0",
        })

    # 2. Trafic TCP (.41) sur 1000 ports : NE doit PAS etre remonte
    #    par le detecteur UDP (filtre proto == udp).
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


def test_udp_scan():
    logs = {"conn": build_conn()}
    alerts = UdpScanDetector().analyze(logs)

    # NB : si ton objet Alert expose des attributs differents
    # (ex: source_ip / details au lieu de src_ip / evidence),
    # adapte les deux lignes ci-dessous a ta classe Alert.
    assert len(alerts) == 1, f"Attendu 1 alerte, obtenu {len(alerts)}"
    a = alerts[0]
    assert a.src_ip == "192.168.100.40", "Mauvaise source detectee"
    assert a.evidence["distinct_ports"] == 1000, "Comptage de ports incorrect"
    assert a.evidence["proto"] == "udp", "Protocole attendu : udp"

    print("OK : 1 alerte UDP scan (.40, 1000 ports UDP).")
    print("OK : trafic TCP (.41) correctement ignore -> filtre proto == udp OK.")


if __name__ == "__main__":
    test_udp_scan()
