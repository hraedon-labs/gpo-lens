"""Existing web surfaces render F1 settings and source notes safely."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from gpo_lens.ingest import load_estate
from gpo_lens.store import init_db, save_estate
from gpo_lens.web.app import create_app

FIXTURE = Path(__file__).parent / "fixtures/cse_audit_pki"
GPO_ID = "a" * 32
GUID = "0cce923f69ae11d9bed3505054503030"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "lab-test-token")
    monkeypatch.delenv("GPO_LENS_ALLOWED_HOSTS", raising=False)
    source = tmp_path / "source"
    source.mkdir()
    text = (
        (FIXTURE / "report.xml")
        .read_text()
        .replace("Lab Portal", "Lab &lt;script&gt;alert(1)&lt;/script&gt;")
    )
    (source / "AllGPOs.xml").write_text(text)
    csv_dir = (
        source
        / "SYSVOL-Policies/{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
        / "MACHINE/Microsoft/Windows NT/Audit"
    )
    csv_dir.mkdir(parents=True)
    (csv_dir / "audit.csv").write_bytes(
        (FIXTURE / "audit.csv").read_bytes().replace(b",,3", b",,1")
    )
    db = tmp_path / "lab.db"
    with sqlite3.connect(db) as conn:
        init_db(conn)
        save_estate(conn, load_estate(source))
    with TestClient(
        create_app(str(db)),
        base_url="http://localhost",
        headers={"Authorization": "Bearer lab-test-token"},
    ) as test_client:
        yield test_client


def test_dossier_ledger_source_notes_and_escaping(client):
    page = client.get(f"/gpo/{GPO_ID}")
    assert page.status_code == 200
    for text in (
        GUID,
        "Audit Credential Validation",
        "Success and Failure",
        "EFS key length",
        "deprecated",
        "Audit sources disagree",
    ):
        assert text in page.text
    assert "<script>alert(1)</script>" not in page.text
    assert "[REDACTED]" in page.text
    assert len(page.context["ledger"]) == 15


@pytest.mark.parametrize("format", ["md", "csv"])
def test_ledger_and_search_exports_deterministic_authorized(client, format):
    url = f"/gpo/{GPO_ID}?view=ledger&format={format}"
    first = client.get(url)
    assert first.status_code == 200
    assert first.content == client.get(url).content
    assert GUID in first.text and "EFSSettings:KeyLen" in first.text
    assert "source_note" in first.text.replace("\\_", "_") and "deprecated" in first.text
    search = client.get(f"/search?q={GUID}&format={format}")
    assert search.status_code == 200 and GUID in search.text
    assert client.get(url, headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_setting_centric_and_search(client):
    page = client.get(
        "/setting",
        params={"identity": GUID, "cse": "Advanced Audit Configuration", "side": "Computer"},
    )
    assert page.status_code == 200 and "Success and Failure" in page.text
    search = client.get("/search", params={"q": "EFS key length"})
    assert search.status_code == 200 and "2048" in search.text


def test_host_and_csrf_boundaries_remain(client):
    assert (
        client.get(f"/gpo/{GPO_ID}", headers={"Host": "outside.lab.example.com"}).status_code == 400
    )
    response = client.post("/baseline-diff", headers={"Origin": "http://outside.lab.example.com"})
    assert response.status_code == 403
