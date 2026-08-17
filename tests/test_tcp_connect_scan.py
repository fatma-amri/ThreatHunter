"""
Test unitaire du TcpConnectScanDetector.

A lancer depuis la RACINE du depot :
    python3 -m tests.test_tcp_connect_scan
    (ou : pytest tests/test_tcp_connect_scan.py)

Verifie deux choses :
  1. un TCP Connect scan (1000 ports distincts en etat SF) leve 1 alerte ;
  2. un trafic non etabli (etat S0, typique d'un SYN scan) ne declenche
     PAS ce detecteur -> pas de confusion entre les deux techniques.
"""
import random
import pandas as pd

from detectors.tcp_connect_scan import TcpConnectScanDetector

BASE_TS = 1_700_000_000


def build_conn() -> pd.DataFrame:
    rows = []

    # 1. TCP Connect scan : Kali (.40) -> Victim (.30), 1000 ports en SF
    for p in range(1, 1001):
        rows.append({
            "ts": BASE_TS + random.uniform(0, 60),
            "id.orig_h": "192.168.100.40",
            "id.resp_h": "192.168.100.30",
            "id.resp_p": p,
            "proto": "tcp",
            "conn_state": "SF",          # connexion complete puis fermee
        })

    # 2. Trafic NON etabli (.41) en S0 : c'est un SYN scan, PAS un
    #    TCP Connect scan -> ce detecteur ne doit PAS le remonter.
    for p in range(1, 501):
        rows.append({
            "ts": BASE_TS + random.uniform(0, 60),
            "id.orig_h": "192.168.100.41",
            "id.resp_h": "192.168.100.30",
            "id.resp_p": p,
            "proto": "tcp",
            "conn_state": "S0",          # half-open -> exclu par le filtre SF/RSTR
        })

    return pd.DataFrame(rows)


def test_tcp_connect_scan():
    logs = {"conn": build_conn()}
    alerts = TcpConnectScanDetector().analyze(logs)

    # NB : si ton objet Alert expose des attributs differents
    # (ex: source_ip / details au lieu de src_ip / evidence),
    # adapte les deux lignes ci-dessous a ta classe Alert.
    assert len(alerts) == 1, f"Attendu 1 alerte, obtenu {len(alerts)}"
    a = alerts[0]
    assert a.src_ip == "192.168.100.40", "Mauvaise source detectee"
    assert a.evidence["distinct_ports"] == 1000, "Comptage de ports incorrect"

    print("OK : 1 alerte TCP Connect scan (.40, 1000 ports SF).")
    print("OK : trafic S0 (.41, SYN scan) correctement ignore -> pas de confusion.")


if __name__ == "__main__":
    test_tcp_connect_scan()
