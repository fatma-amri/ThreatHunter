"""
Tests de rendu des 2 nouvelles pages (Investigation, ATT&CK Matrix) via
streamlit.testing.v1.AppTest, avec MongoDB simule par mongomock.

Verifie qu'aucune des deux pages ne leve d'exception :
  - avec des donnees (incident correle x3 injecte dans le mock) ;
  - en mode degrade (MongoClient qui echoue -> df vide -> empty_state).

A lancer depuis la racine du depot :
    pytest tests/test_advanced_pages.py
"""
import sys
from pathlib import Path

import mongomock
import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dashboard" / "pages"))

from tests.test_investigation_data import sample_alerts, ATTACKER  # noqa: E402

APP = str(ROOT / "dashboard" / "pages" / "dashboard_main.py")


def _mock_client_with_data():
    client = mongomock.MongoClient()
    docs = []
    for a in sample_alerts():
        d = dict(a)
        d.pop("id", None)
        docs.append(d)
    client["threathunter"]["alerts"].insert_many(docs)
    return client


def _boot(monkeypatch, client, page):
    monkeypatch.setattr("database.db.MongoClient", lambda *a, **k: client)
    at = AppTest.from_file(APP, default_timeout=30)
    at.session_state["th_auth_ok"] = True
    at.session_state["th_auth_user"] = "tester"
    at.session_state["current_page"] = page
    return at


@pytest.fixture(autouse=True)
def _clear_cache():
    import streamlit as st
    st.cache_data.clear()
    yield
    st.cache_data.clear()


# ── avec donnees ──────────────────────────────────────────────────────
def test_investigation_page_renders(monkeypatch):
    at = _boot(monkeypatch, _mock_client_with_data(), "Investigation")
    at.session_state["focus_entity"] = ATTACKER
    at.run()
    assert not at.exception
    assert any("Investigation" in h.value for h in at.markdown if isinstance(h.value, str)) \
        or at.selectbox  # la fiche d'hote s'est affichee (selectbox d'entite)


def test_attack_matrix_page_renders(monkeypatch):
    at = _boot(monkeypatch, _mock_client_with_data(), "ATT&CK Matrix")
    at.run()
    assert not at.exception


def test_attack_matrix_technique_selected(monkeypatch):
    at = _boot(monkeypatch, _mock_client_with_data(), "ATT&CK Matrix")
    at.session_state["matrix_technique"] = "T1071"
    at.run()
    assert not at.exception
    # le tableau d'alertes de la technique doit apparaitre
    assert any("T1071" in str(el.value) for el in at.subheader)


def test_investigation_entity_switch(monkeypatch):
    at = _boot(monkeypatch, _mock_client_with_data(), "Investigation")
    at.run()
    assert not at.exception
    # bascule d'entite via le selectbox -> pas d'exception
    at.selectbox(key="inv_entity").select("10.0.0.5").run()
    assert not at.exception


# ── mode degrade (pas de base) ───────────────────────────────────────
class _BoomClient:
    def __init__(self, *a, **k):
        raise RuntimeError("mongo down")


def test_investigation_degraded_mode(monkeypatch):
    at = _boot(monkeypatch, None, "Investigation")
    monkeypatch.setattr("database.db.MongoClient", _BoomClient)
    at.run()
    assert not at.exception


def test_attack_matrix_degraded_mode(monkeypatch):
    at = _boot(monkeypatch, None, "ATT&CK Matrix")
    monkeypatch.setattr("database.db.MongoClient", _BoomClient)
    at.run()
    assert not at.exception


# ── la page Alerts garde son bouton "Investigate this source" ─────────
def test_alerts_page_has_investigate_button(monkeypatch):
    at = _boot(monkeypatch, _mock_client_with_data(), "Alerts")
    at.run()
    assert not at.exception
    labels = [b.label for b in at.button]
    assert any("Investigate this source" in lbl for lbl in labels)
