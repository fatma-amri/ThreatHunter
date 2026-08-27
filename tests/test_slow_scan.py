"""
Test unitaire du SlowScanDetector.

A lancer depuis la RACINE du depot :
    python3 -m tests.test_slow_scan
    (ou : pytest tests/test_slow_scan.py)

Verifie deux choses :
  1. un slow scan (40 ports, 1 sonde/60s, sur ~40 min) leve 1 alerte ;
  2. un scan RAPIDE (memes ports en quelques secondes) ne declenche PAS
     ce detecteur -> c'est bien la lenteur qui est detectee, pas le volume.
"""
import pandas as pd

from detectors.slow_scan import SlowScanDetector

BASE_TS = 1_700_000_000


def build_conn() -> pd.DataFrame:
    rows = []

    # 1. Slow scan : .40 -> .30, 40 ports, une sonde toutes les 60 s
    #    => duree ~ 39*60 = 2340 s (39 min), intervalle moyen 60 s
    for i, p in enumerate(range(1, 41)):
        rows.append({
            "ts": BASE_TS + i * 60,          # 1 sonde par minute
            "id.orig_h": "192.168.100.40",
            "id.resp_h": "192.168.100.30",
            "id.resp_p": p,
            "proto": "tcp",
            "conn_state": "REJ",
        })

    # 2. Scan RAPIDE (.41) : 40 ports en quelques secondes
    #    => intervalle moyen tres court -> ne doit PAS alerter en slow scan
    for i, p in enumerate(range(1, 41)):
        rows.append({
            "ts": BASE_TS + i * 0.1,         # 100 ms entre sondes
            "id.orig_h": "192.168.100.41",
            "id.resp_h": "192.168.100.30",
            "id.resp_p": p,
            "proto": "tcp",
            "conn_state": "REJ",
        })

    return pd.DataFrame(rows)


def test_slow_scan():
    logs = {"conn": build_conn()}
    alerts = SlowScanDetector().analyze(logs)

    # NB : si ton objet Alert expose des attributs differents
    # (ex: source_ip / details au lieu de src_ip / evidence),
    # adapte les lignes ci-dessous a ta classe Alert.
    assert len(alerts) == 1, f"Attendu 1 alerte, obtenu {len(alerts)}"
    a = alerts[0]
    assert a.src_ip == "192.168.100.40", "Mauvaise source detectee"
    assert a.evidence["distinct_ports"] == 40, "Comptage de ports incorrect"
    assert a.evidence["mean_interval"] >= 30, "Intervalle moyen trop court"

    print("OK : 1 alerte slow scan (.40, 40 ports, 1 sonde/60s).")
    print("OK : scan rapide (.41, memes ports en <5s) ignore -> lenteur detectee.")


if __name__ == "__main__":
    test_slow_scan()
