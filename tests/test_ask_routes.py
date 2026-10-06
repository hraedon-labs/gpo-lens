"""Ask routing errors and deterministic result isolation from page narration."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

try:
    import fastapi  # noqa: F401

    _HAS_WEB = True
except ImportError:
    _HAS_WEB = False

pytestmark = pytest.mark.skipif(
    not _HAS_WEB,
    reason="web extra not installed",
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture()
def fixture_db() -> str:
    from gpo_lens.ingest import load_estate as ingest_load_estate
    from gpo_lens.store import init_db, save_estate

    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
        path = f.name
    conn = sqlite3.connect(path)
    init_db(conn)
    estate = ingest_load_estate(FIXTURE_DIR)
    save_estate(conn, estate)
    conn.close()
    try:
        yield path
    finally:
        os.unlink(path)


@pytest.fixture()
def client(fixture_db: str, monkeypatch):
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    app = create_app(fixture_db)
    return TestClient(
        app,
        headers={
            "origin": "http://localhost",
            "Authorization": "Bearer test-secret-token",
        },
    )


class TestAskGet:
    def test_get_ask_renders_form(self, client):
        resp = client.get("/ask")
        assert resp.status_code == 200
        assert "ask" in resp.text.lower()

    def test_get_ask_shows_not_configured_without_key(self, client):
        with patch.dict(os.environ, {"GPO_LENS_API_KEY": ""}, clear=False):
            resp = client.get("/ask")
        assert resp.status_code == 200
        assert "AI narration is not configured" in resp.text


class TestAskPostNoApiKey:
    def test_post_ask_without_api_key_graceful_degradation(self, client):
        with patch.dict(os.environ, {"GPO_LENS_API_KEY": ""}, clear=False):
            resp = client.post("/ask", data={"question": "How many GPOs?"})
        assert resp.status_code == 200
        assert "Narration is not configured" in resp.text


class TestAskPostLlmErrors:
    def test_post_ask_route_question_unreachable(self, client):
        from gpo_lens.narration import NarrationUnavailable

        mock_route = MagicMock(
            side_effect=NarrationUnavailable("LLM transport error: connection refused")
        )
        with patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key"}):
            with patch("gpo_lens.narration.route_question", mock_route):
                resp = client.post("/ask", data={"question": "How many GPOs?"})
        assert resp.status_code == 200
        assert "LLM transport error" in resp.text or "transport error" in resp.text.lower()

    def test_post_ask_call_llm_unreachable(self, client):
        from gpo_lens.narration import NarrationUnavailable

        mock_route = MagicMock(return_value={"query": "estate_summary", "params": {}})
        mock_call = MagicMock(side_effect=NarrationUnavailable("LLM transport error"))
        with patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key"}):
            with patch("gpo_lens.narration.route_question", mock_route):
                with patch("gpo_lens.narration.call_llm", mock_call):
                    resp = client.post("/ask", data={"question": "How many GPOs?"})
        assert resp.status_code == 200

    def test_post_ask_call_llm_generic_exception(self, client):
        mock_route = MagicMock(return_value={"query": "estate_summary", "params": {}})
        mock_call = MagicMock(side_effect=RuntimeError("unexpected failure"))
        with patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key"}):
            with patch("gpo_lens.narration.route_question", mock_route):
                with patch("gpo_lens.narration.call_llm", mock_call):
                    resp = client.post("/ask", data={"question": "How many GPOs?"})
        assert resp.status_code == 200
        assert "Underlying Facts" in resp.text
        assert "Explain these facts" in resp.text
        mock_call.assert_not_called()


class TestAskPostRoutingErrors:
    def test_post_ask_cannot_route(self, client):
        mock_route = MagicMock(
            return_value={"error": "cannot_route", "reason": "not a GPO question"}
        )
        with patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key"}):
            with patch("gpo_lens.narration.route_question", mock_route):
                resp = client.post("/ask", data={"question": "What is the weather?"})
        assert resp.status_code == 200
        assert "Cannot answer" in resp.text

    def test_post_ask_unknown_query_name(self, client):
        mock_route = MagicMock(return_value={"query": "nonexistent_query", "params": {}})
        with patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key"}):
            with patch("gpo_lens.narration.route_question", mock_route):
                resp = client.post("/ask", data={"question": "Summary?"})
        assert resp.status_code == 200
        assert "not implemented" in resp.text


class TestAskPostValidation:
    def test_post_ask_missing_question_field_returns_422(self, client):
        resp = client.post("/ask", data={})
        assert resp.status_code == 422

    def test_post_ask_empty_question_returns_422(self, client):
        with patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key"}):
            resp = client.post("/ask", data={"question": ""})
        assert resp.status_code == 422

    def test_post_ask_whitespace_question_with_key(self, client):
        mock_route = MagicMock(return_value={"error": "cannot_route", "reason": "empty question"})
        with patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key"}):
            with patch("gpo_lens.narration.route_question", mock_route):
                resp = client.post("/ask", data={"question": " "})
        assert resp.status_code == 200


class TestAskPostAuditEvent:
    def test_post_ask_without_key_emits_audit_event(self, client, fixture_db: str):
        with patch.dict(os.environ, {"GPO_LENS_API_KEY": ""}, clear=False):
            client.post("/ask", data={"question": "test question"})

        conn = sqlite3.connect(fixture_db)
        try:
            rows = conn.execute(
                "SELECT payload FROM events WHERE event_type = ?",
                ("audit.narrate",),
            ).fetchall()
        finally:
            conn.close()
        assert len(rows) == 1
        import json

        payload = json.loads(rows[0][0])
        assert payload["outcome"] == "not_configured"

    def test_post_ask_with_llm_error_emits_audit_event(self, client, fixture_db: str):
        from gpo_lens.narration import NarrationUnavailable

        mock_route = MagicMock(side_effect=NarrationUnavailable("LLM unreachable"))
        with patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key"}):
            with patch("gpo_lens.narration.route_question", mock_route):
                client.post("/ask", data={"question": "test question"})

        conn = sqlite3.connect(fixture_db)
        try:
            rows = conn.execute(
                "SELECT payload FROM events WHERE event_type = ?",
                ("audit.narrate",),
            ).fetchall()
        finally:
            conn.close()
        assert len(rows) == 1
        import json

        payload = json.loads(rows[0][0])
        assert payload["outcome"] == "error"
