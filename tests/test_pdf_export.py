"""
Tests de l'export PDF (reports/pdf_export.build_pdf) + presence du bouton
"Export PDF" sur la page Reports du dashboard.

    pytest tests/test_pdf_export.py
"""
import sys
from pathlib import Path

import mongomock
import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dashboard" / "pages"))

import dashboard_data as data  # noqa: E402
from reports.pdf_export import build_pdf, _demo_dataframe  # noqa: E402
from tests.test_investigation_data import sample_alerts  # noqa: E402


def _is_pdf(b: bytes) -> bool:
    return isinstance(b, bytes) and b[:5] == b"%PDF-" and b"%%EOF" in b[-1024:]


# ── build_pdf : bytes valides ────────────────────────────────────────
def test_build_pdf_returns_valid_bytes():
    df = data.to_dataframe(sample_alerts())
    pdf = build_pdf(df)
    assert _is_pdf(pdf) and len(pdf) > 2000


def test_build_pdf_writes_file(tmp_path):
    out = tmp_path / "r.pdf"
    pdf = build_pdf(_demo_dataframe(), output_path=out)
    assert out.exists() and out.read_bytes() == pdf
    assert _is_pdf(pdf)


def test_build_pdf_empty_selection_is_valid():
    pdf = build_pdf(data.to_dataframe([]))
    assert _is_pdf(pdf)


def test_build_pdf_accepts_list_of_dicts():
    pdf = build_pdf(sample_alerts())
    assert _is_pdf(pdf)


def test_build_pdf_accepts_alert_objects():
    from core.alerts import Alert
    alerts = [Alert(detector="PortScanDetector", severity="HIGH",
                    src_ip="10.0.0.1", dst_ip="10.0.0.2", mitre="T1046",
                    description="scan", risk_score=60, confidence=0.7)]
    assert _is_pdf(build_pdf(alerts))


def test_build_pdf_period_override():
    pdf = build_pdf(_demo_dataframe(), period=("2026-08-01", "2026-08-31"))
    assert _is_pdf(pdf)


# ── page Reports : bouton Export PDF ─────────────────────────────────
@pytest.fixture(autouse=True)
def _clear_cache():
    import streamlit as st
    st.cache_data.clear()
    yield
    st.cache_data.clear()


def _mock_client():
    client = mongomock.MongoClient()
    docs = [{k: v for k, v in a.items() if k != "id"} for a in sample_alerts()]
    client["threathunter"]["alerts"].insert_many(docs)
    return client


def test_reports_page_has_pdf_download(monkeypatch):
    monkeypatch.setattr("database.db.MongoClient", lambda *a, **k: _mock_client())
    at = AppTest.from_file(str(ROOT / "dashboard" / "pages" / "dashboard_main.py"),
                           default_timeout=30)
    at.session_state["th_auth_ok"] = True
    at.session_state["th_auth_user"] = "tester"
    at.session_state["current_page"] = "Reports"
    at.run()
    assert not at.exception
    labels = [b.label for b in at.download_button]
    assert "Export PDF" in labels
    assert "Export CSV" in labels and "Export Summary (JSON)" in labels
