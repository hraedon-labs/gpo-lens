"""Web route tests for /admx-coverage (WI-075)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from gpo_lens.web.app import create_app

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def fixture_db(tmp_path):
    from gpo_lens.ingest import load_estate as ingest_load_estate
    from gpo_lens.store import init_db, save_estate

    db = tmp_path / "admx_test.db"
    conn = sqlite3.connect(str(db))
    init_db(conn)
    estate = ingest_load_estate(FIXTURE_DIR)
    save_estate(conn, estate)
    conn.close()
    return str(db)


@pytest.fixture
def empty_db(tmp_path):
    db = tmp_path / "empty.db"
    conn = sqlite3.connect(str(db))
    from gpo_lens.store import init_db

    init_db(conn)
    conn.close()
    return str(db)


@pytest.fixture
def client(fixture_db, monkeypatch):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    app = create_app(fixture_db)
    return TestClient(
        app,
        headers={
            "origin": "http://localhost",
            "Authorization": "Bearer test-secret-token",
        },
    )


@pytest.fixture
def empty_client(empty_db, monkeypatch):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    app = create_app(empty_db)
    return TestClient(
        app,
        headers={
            "origin": "http://localhost",
            "Authorization": "Bearer test-secret-token",
        },
    )


class TestAdmxCoverageRoute:
    def test_get_returns_200_with_report(self, client) -> None:
        resp = client.get("/admx-coverage")
        assert resp.status_code == 200
        assert "ADMX Coverage" in resp.text
        assert "total policies" in resp.text.lower() or "total_policies" in resp.text

    def test_get_on_empty_db_returns_200(self, empty_client) -> None:
        resp = empty_client.get("/admx-coverage")
        assert resp.status_code == 200
        assert "ADMX Coverage" in resp.text
        assert "0" in resp.text

    def test_get_on_blank_file_db_returns_200(self, tmp_path, monkeypatch) -> None:
        db = tmp_path / "blank.db"
        db.touch()
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(str(db))
        c = TestClient(
            app,
            headers={
                "origin": "http://localhost",
                "Authorization": "Bearer test-secret-token",
            },
        )
        resp = c.get("/admx-coverage")
        assert resp.status_code == 200
        assert "ADMX Coverage" in resp.text

    def test_report_shows_gap_section(self, client) -> None:
        resp = client.get("/admx-coverage")
        assert resp.status_code == 200
        assert "Gaps" in resp.text or "gaps" in resp.text.lower()


def test_startup_with_poisoned_templates(fixture_db, tmp_path, monkeypatch):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    pd_dir = tmp_path / "PolicyDefinitions"
    pd_dir.mkdir()
    (pd_dir / "poison.admx").write_bytes(b'<?xml version="1.0" encoding="unicode"?><x>\xff</x>')
    app = create_app(fixture_db, admx_dir=str(pd_dir))
    with TestClient(app, headers={"Authorization": "Bearer test-secret-token"}) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "1 template files could not be read" in response.text
        response = client.get("/admx-coverage")
        assert response.status_code == 200
        assert "poison.admx" in response.text
        assert "UnicodeDecodeError" in response.text


@pytest.mark.parametrize("auto_detect", [False, True])
def test_startup_when_template_loading_fails_wholesale(
    fixture_db, tmp_path, monkeypatch, auto_detect
):
    from gpo_lens import admx_parser

    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    monkeypatch.delenv("GPO_LENS_ADMX_DIR", raising=False)
    pd_dir = tmp_path / "PolicyDefinitions"
    pd_dir.mkdir()

    def fail(_path):
        raise LookupError("synthetic failure")

    monkeypatch.setattr(admx_parser, "parse_admx_dir", fail)
    monkeypatch.setattr(admx_parser, "find_admx_dir", lambda _path: pd_dir)
    app = create_app(fixture_db, admx_dir=None if auto_detect else str(pd_dir))
    assert app.state.admx is None
    with TestClient(app, headers={"Authorization": "Bearer test-secret-token"}) as client:
        for route in ["/", "/admx-coverage"]:
            response = client.get(route)
            assert response.status_code == 200
            assert "ADMX templates could not be loaded" in response.text
