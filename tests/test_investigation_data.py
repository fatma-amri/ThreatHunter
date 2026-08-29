"""
Tests des fonctions PURES ajoutees a dashboard_data pour l'outil
d'investigation SOC : drill-down par entite, kill-chain, matrice ATT&CK.

A lancer depuis la racine du depot :
    pytest tests/test_investigation_data.py
"""
from datetime import datetime, timedelta

import pandas as pd
import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dashboard" / "pages"))

import dashboard_data as data  # noqa: E402

T0 = datetime(2026, 8, 20, 9, 0, 0)


def _ts(minutes: int) -> str:
    return (T0 + timedelta(minutes=minutes)).isoformat()


ATTACKER = "192.168.100.40"
VICTIM = "192.168.100.30"


def sample_alerts() -> list[dict]:
    """Jeu realiste : un incident correle x3 (scan -> brute force -> beaconing
    depuis la meme IP source) + une exfiltration de la meme source + du bruit
    provenant d'une autre IP + un hit CTI."""
    correlated_alerts = [
        {"detector": "PortScanDetector", "severity": "HIGH", "mitre": "T1046",
         "dst_ip": VICTIM, "description": "1000 ports scanned on 192.168.100.30"},
        {"detector": "BruteForceDetector", "severity": "HIGH", "mitre": "T1110",
         "dst_ip": VICTIM, "description": "42 failed SSH logins on 192.168.100.30"},
        {"detector": "BeaconingDetector", "severity": "CRITICAL", "mitre": "T1071.004",
         "dst_ip": "8.8.8.8", "description": "Regular DNS beacon to 8.8.8.8, jitter 4%"},
    ]
    return [
        # --- Incident correle x3 : alerte representante (la plus grave) ---
        {
            "id": "inc1", "timestamp": _ts(4), "detector": "BeaconingDetector",
            "severity": "CRITICAL", "src_ip": ATTACKER, "dst_ip": "8.8.8.8",
            "mitre": "T1071.004", "risk_score": 95, "confidence": 0.9,
            "correlated_count": 3,
            "related_detectors": ["BeaconingDetector", "BruteForceDetector",
                                  "PortScanDetector"],
            "description": "Incident correle : 3 alertes depuis 192.168.100.40",
            "cti_context": {}, "evidence": {
                "correlated_alerts": correlated_alerts,
                "mitre_techniques": ["T1046", "T1071.004", "T1110"],
            },
        },
        # --- Exfiltration de la meme source (etape suivante de la chaine) ---
        {
            "id": "exf1", "timestamp": _ts(9), "detector": "HttpsExfiltrationDetector",
            "severity": "HIGH", "src_ip": ATTACKER, "dst_ip": "203.0.113.5",
            "mitre": "T1048", "risk_score": 78, "confidence": 0.8,
            "correlated_count": 1, "related_detectors": [],
            "description": "3.2 MB uploaded over HTTPS to 203.0.113.5",
            "cti_context": {}, "evidence": {},
        },
        # --- Hit CTI sur la source ---
        {
            "id": "cti1", "timestamp": _ts(2), "detector": "UpstreamMatcher",
            "severity": "HIGH", "src_ip": ATTACKER, "dst_ip": "45.9.148.99",
            "mitre": "T1071", "risk_score": 82, "confidence": 0.85,
            "correlated_count": 1, "related_detectors": [],
            "description": "Contact with known C2 IP 45.9.148.99",
            "cti_context": {"found": True, "source": "MISP", "threat": "Cobalt Strike"},
            "evidence": {},
        },
        # --- Bruit : autre attaquant, autre cible ---
        {
            "id": "n1", "timestamp": _ts(30), "detector": "PortScanDetector",
            "severity": "MEDIUM", "src_ip": "10.0.0.5", "dst_ip": "192.168.100.50",
            "mitre": "T1046", "risk_score": 40, "confidence": 0.5,
            "correlated_count": 1, "related_detectors": [],
            "description": "60 ports scanned on 192.168.100.50",
            "cti_context": {}, "evidence": {},
        },
        # --- Alerte ou l'attaquant est la CIBLE (role destination) ---
        {
            "id": "n2", "timestamp": _ts(45), "detector": "BruteForceDetector",
            "severity": "LOW", "src_ip": "10.0.0.9", "dst_ip": ATTACKER,
            "mitre": "T1110", "risk_score": 22, "confidence": 0.4,
            "correlated_count": 1, "related_detectors": [],
            "description": "12 failed logins against 192.168.100.40",
            "cti_context": {}, "evidence": {},
        },
    ]


@pytest.fixture
def df() -> pd.DataFrame:
    return data.to_dataframe(sample_alerts())


# ── entity_list / entity_profile ────────────────────────────────────────
def test_entity_list_union_src_and_dst(df):
    ips = data.entity_list(df)
    # union des colonnes src_ip ET dst_ip de premier niveau
    assert ATTACKER in ips                       # source ET destination
    assert "203.0.113.5" in ips                  # uniquement destination
    assert "8.8.8.8" in ips and "10.0.0.5" in ips
    # trie numeriquement : 8.8.8.8 avant 10.0.0.5 avant 192.168.x
    assert ips.index("8.8.8.8") < ips.index("10.0.0.5") < ips.index(ATTACKER)


def test_entity_list_empty_df():
    assert data.entity_list(data.to_dataframe([])) == []


def test_entity_profile_aggregates(df):
    p = data.entity_profile(df, ATTACKER)
    assert p["alert_count"] == 4                 # 3 en source + 1 en destination
    assert p["as_source"] == 3
    assert p["as_destination"] == 1
    assert p["max_severity"] == "CRITICAL"
    assert p["risk_max"] == 95
    assert p["cti_hits"] == 1
    assert p["detector_count"] == 4
    assert p["destination_count"] == 3           # 8.8.8.8, 203.0.113.5, 45.9.148.99
    assert p["first_seen"] == pd.Timestamp(_ts(2))
    assert p["last_seen"] == pd.Timestamp(_ts(45))


def test_entity_profile_unknown_ip(df):
    p = data.entity_profile(df, "1.2.3.4")
    assert p["alert_count"] == 0 and p["max_severity"] is None
    assert p["risk_max"] == 0


# ── kill_chain ─────────────────────────────────────────────────────────
def test_kill_chain_sequences_the_incident(df):
    kc = data.kill_chain(df, ATTACKER)
    assert kc["steps"], "kill-chain vide"
    # Les 4 phases de l'histoire d'attaque, dans l'ordre ATT&CK
    assert kc["tactics"] == [
        "Discovery", "Credential Access", "Command and Control", "Exfiltration",
    ]
    phases_in_order = [s["phase"] for s in kc["steps"]]
    # Discovery apparait avant Exfiltration
    assert phases_in_order.index("Discovery") < phases_in_order.index("Exfiltration")
    # Chaque etape est mappee a une technique connue
    techniques = {s["technique"] for s in kc["steps"]}
    assert {"T1046", "T1110", "T1071.004", "T1048"} <= techniques


def test_kill_chain_pulls_correlated_subalerts(df):
    kc = data.kill_chain(df, ATTACKER)
    detectors = {s["detector"] for s in kc["steps"]}
    # PortScan / BruteForce ne sont PAS des alertes de premier niveau pour
    # cette IP : ils viennent des correlated_alerts de l'incident.
    assert {"PortScanDetector", "BruteForceDetector"} <= detectors
    approx = [s for s in kc["steps"] if s["approx_time"]]
    assert approx, "les sous-alertes correlees doivent etre marquees approx_time"


def test_kill_chain_destination_only_entity(df):
    # 8.8.8.8 n'est jamais source -> pas de chaine
    kc = data.kill_chain(df, "8.8.8.8")
    assert kc["steps"] == [] and kc["tactics"] == []


# ── attack_matrix / techniques ────────────────────────────────────────
def test_attack_matrix_structure_and_observed(df):
    grid = data.attack_matrix(df)
    tactics = [c["tactic"] for c in grid]
    for expected in ["Discovery", "Credential Access", "Command and Control",
                     "Exfiltration"]:
        assert expected in tactics

    cells = {c["id"]: c for col in grid for c in col["cells"]}
    # Observees dans les donnees
    assert cells["T1046"]["observed"] and cells["T1046"]["alert_count"] >= 1
    assert cells["T1048"]["observed"]
    assert cells["T1071.004"]["observed"]
    # Catalogue cible : present, en sourdine, jamais marque comme observe
    assert cells["T1567"]["target"] is True
    assert cells["T1567"]["observed"] is False
    assert cells["T1041"]["target"] is True


def test_attack_matrix_cell_max_risk(df):
    grid = data.attack_matrix(df)
    cells = {c["id"]: c for col in grid for c in col["cells"]}
    assert cells["T1071.004"]["max_risk"] == 95


def test_technique_alerts_includes_subtechniques(df):
    # Demander le parent T1071 -> inclut T1071.004
    hits = data.technique_alerts(df, "T1071")
    mitres = set(hits["mitre"])
    assert "T1071" in mitres and "T1071.004" in mitres


def test_technique_alerts_exact(df):
    hits = data.technique_alerts(df, "T1048")
    assert len(hits) == 1 and hits.iloc[0]["detector"] == "HttpsExfiltrationDetector"


def test_observed_techniques_counts(df):
    obs = data.observed_techniques(df).set_index("technique")
    # Seules les techniques de PREMIER NIVEAU comptent (pas les sous-alertes
    # correlees) : T1046 uniquement via le bruit, T1071.004 via l'incident.
    assert obs.loc["T1046", "alert_count"] == 1
    assert obs.loc["T1071.004", "alert_count"] == 1
    assert obs.loc["T1110", "alert_count"] == 1   # uniquement l'alerte "destination"


def test_technique_helpers():
    assert data.technique_tactic("T1046") == "Discovery"
    assert data.technique_tactic("T1071.004") == "Command and Control"
    assert data.technique_tactic("T1071.999") == "Command and Control"  # parent
    assert data.technique_tactic("T9999") == "Unmapped"
    assert data.technique_tactic(None) == "Unmapped"
    assert data.technique_name("T1110") == "Brute Force"
    assert data.technique_name("T9999") == "T9999"


# ── entite : ranked lists / timeline ──────────────────────────────────
def test_entity_destinations_source_only(df):
    dests = data.entity_destinations(df, ATTACKER)
    assert set(dests["dst_ip"]) == {"8.8.8.8", "203.0.113.5", "45.9.148.99"}


def test_entity_timeline_sorted_and_timestamped(df):
    tl = data.entity_timeline(df, ATTACKER)
    assert list(tl["timestamp"]) == sorted(tl["timestamp"])
    assert tl["timestamp"].notna().all()
