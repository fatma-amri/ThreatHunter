"""
Test unitaire du StealthScanDetector.

A lancer depuis la RACINE du depot :
    python3 -m tests.test_stealth_scan
    (ou : pytest tests/test_stealth_scan.py)

Verifie deux choses :
  1. un FIN scan (30 ports, history 'F' sans SYN) leve 1 alerte ;
  2. un trafic normal (SYN complet, history 'ShADadfF') ne declenche PAS
     ce detecteur -> la presence de SYN ecarte le scan furtif.
"""
import pandas as pd

from detectors.stealth_scan import StealthScanDetector

BASE_TS = 1_700_000_000


def build_conn() -> pd.DataFrame:
    rows = []

    # 1. FIN scan : .40 -> .30, 30 ports, history 'F' (FIN seul, pas de SYN)
    for p in range(1, 31):
        rows.append({
            "ts": BASE_TS + p,
            "id.orig_h": "192.168.100.40",
            "id.resp_h": "192.168.100.30",
            "id.resp_p": p,
            "proto": "tcp",
            "conn_state": "REJ",
            "history": "F",             # FIN envoye par l'originator, pas de S
        })

    # 2. Trafic normal (.42) : connexions TCP completes AVEC SYN
    #    history 'ShADadfF' contient un S -> ecarte, pas de scan furtif.
    for p in [80, 443, 22]:
        rows.append({
            "ts": BASE_TS + 100 + p,
            "id.orig_h": "192.168.100.42",
            "id.resp_h": "192.168.100.30",
            "id.resp_p": p,
            "proto": "tcp",
            "conn_state": "SF",
            "history": "ShADadfF",      # handshake complet (contient S)
        })

    return pd.DataFrame(rows)


def test_stealth_scan():
    logs = {"conn": build_conn()}
    alerts = StealthScanDetector().analyze(logs)

    # NB : si ton objet Alert expose des attributs differents
    # (ex: source_ip / details au lieu de src_ip / evidence),
    # adapte les lignes ci-dessous a ta classe Alert.
    assert len(alerts) == 1, f"Attendu 1 alerte, obtenu {len(alerts)}"
    a = alerts[0]
    assert a.src_ip == "192.168.100.40", "Mauvaise source detectee"
    assert a.evidence["scan_type"] == "FIN", "Type de scan attendu : FIN"
    assert a.evidence["distinct_ports"] == 30, "Comptage de ports incorrect"

    print("OK : 1 alerte stealth scan FIN (.40, 30 ports, flag F sans SYN).")
    print("OK : trafic normal avec SYN (.42) ignore -> pas de faux positif.")


if __name__ == "__main__":
    test_stealth_scan()
