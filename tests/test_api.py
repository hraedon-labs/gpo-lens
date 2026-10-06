"""Tests for the REST API surface (WI-057)."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

try:
    from fastapi.testclient import TestClient

    from gpo_lens.query_dispatch import VALID_QUERIES
    from gpo_lens.web.app import create_app

    _HAS_WEB = True
except ImportError:
    _HAS_WEB = False
    VALID_QUERIES = frozenset()  # type: ignore[assignment]

pytestmark = pytest.mark.skipif(not _HAS_WEB, reason="web extra not installed")

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture()
def _fixture_db():
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
def _client(_fixture_db, monkeypatch):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    app = create_app(_fixture_db)
    return TestClient(
        app,
        headers={"Authorization": "Bearer test-secret-token"},
    )


@pytest.fixture()
def _empty_db():
    """A DB with the schema initialised but no snapshots (no estate loaded)."""
    from gpo_lens.store import init_db

    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
        path = f.name
    conn = sqlite3.connect(path)
    init_db(conn)
    conn.close()
    try:
        yield path
    finally:
        os.unlink(path)


@pytest.fixture()
def _empty_client(_empty_db, monkeypatch):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    app = create_app(_empty_db)
    return TestClient(
        app,
        headers={"Authorization": "Bearer test-secret-token"},
    )


class TestApiQueries:
    def test_list_queries(self, _client) -> None:
        resp = _client.get("/api/v1/queries")
        assert resp.status_code == 200
        body = resp.json()
        assert "queries" in body
        # Every HTTP-callable query should appear with a description. Queries
        # requiring an in-process object use dedicated upload routes instead.
        from gpo_lens.query_dispatch import VALID_QUERIES

        assert "golden_diff" not in body["queries"]
        for name in VALID_QUERIES - {"golden_diff"}:
            assert name in body["queries"]
            assert "description" in body["queries"][name]
            assert "required_params" in body["queries"][name]

    def test_list_queries_has_required_params(self, _client) -> None:
        resp = _client.get("/api/v1/queries")
        body = resp.json()
        assert body["queries"]["settings_at_som"]["required_params"] == ["ou_path"]
        assert body["queries"]["effective_scope"]["required_params"] == ["gpo_id"]
        assert body["queries"]["estate_summary"]["required_params"] == []


class TestApiQueryExecution:
    def test_query_estate_summary(self, _client) -> None:
        resp = _client.get("/api/v1/query/estate_summary")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert "data" in body
        assert body["data"]["gpo_count"] > 0

    def test_query_with_params(self, _client) -> None:
        resp = _client.get(
            "/api/v1/query/settings_at_som",
            params={"ou_path": "ou=child,dc=fakefixture,dc=local"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert "data" in body

    def test_unknown_query_404(self, _client) -> None:
        resp = _client.get("/api/v1/query/nonexistent")
        assert resp.status_code == 404
        body = resp.json()
        assert body["status"] == "error"
        assert "Unknown query" in body["detail"]

    def test_object_parameter_query_not_exposed_over_get(self, _client) -> None:
        resp = _client.get(
            "/api/v1/query/golden_diff",
            params={"golden_estate": "not-an-estate"},
        )
        assert resp.status_code == 404

    def test_missing_required_param_400(self, _client) -> None:
        resp = _client.get("/api/v1/query/settings_at_som")
        assert resp.status_code == 400
        body = resp.json()
        assert body["status"] == "error"
        assert "ou_path" in body["detail"]

    def test_cpassword_masked(self, _client, secret_corpus) -> None:
        resp = _client.get("/api/v1/query/cpassword_scan")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        hits = body["data"]
        assert isinstance(hits, list)
        assert len(hits) > 0
        for hit in hits:
            cpw = hit["cpassword"]
            # The raw cpassword must never appear in the response.
            assert cpw not in secret_corpus
            # Masked form: first 4 chars + "****" (or "****" for short values).
            assert cpw.endswith("****")


class TestApiHealth:
    def test_health(self, _fixture_db, monkeypatch) -> None:
        # Health endpoint must work WITHOUT auth credentials.
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(_fixture_db)
        no_auth_client = TestClient(app)
        resp = no_auth_client.get("/api/v1/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert "version" in body

    def test_health_no_db_path_leak(self, _fixture_db, monkeypatch) -> None:
        # The health response must not leak the DB path (basename or otherwise)
        # — it could reveal estate/domain identity.
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(_fixture_db)
        no_auth_client = TestClient(app)
        resp = no_auth_client.get("/api/v1/health")
        assert resp.status_code == 200
        body = resp.json()
        assert "db_path" not in body
        assert "db" not in body


class TestApiSnapshots:
    def test_snapshots(self, _client) -> None:
        resp = _client.get("/api/v1/snapshots")
        assert resp.status_code == 200
        body = resp.json()
        assert "snapshots" in body
        assert isinstance(body["snapshots"], list)
        assert len(body["snapshots"]) > 0
        snap = body["snapshots"][0]
        assert "id" in snap
        assert "domain" in snap
        assert "taken_at" in snap


class TestApiRoot:
    def test_api_root(self, _client) -> None:
        resp = _client.get("/api/v1/")
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "gpo-lens API"
        assert body["version"] == "v1"
        paths = [e["path"] for e in body["endpoints"]]
        assert "/api/v1/queries" in paths
        assert "/api/v1/query/{query_name}" in paths
        assert "/api/v1/health" in paths
        assert "/api/v1/snapshots" in paths
        assert "/api/v1/trends" in paths


class TestApiAuth:
    def test_auth_required(self, _fixture_db, monkeypatch) -> None:
        # When a token is configured, requests without it must get 401.
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(_fixture_db)
        no_auth_client = TestClient(app)
        resp = no_auth_client.get("/api/v1/queries")
        assert resp.status_code == 401

    def test_snapshots_requires_auth(self, _fixture_db, monkeypatch) -> None:
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(_fixture_db)
        no_auth_client = TestClient(app)
        resp = no_auth_client.get("/api/v1/snapshots")
        assert resp.status_code == 401


class TestApiErrorEnvelope:
    """Auth failures and other HTTP errors under /api/v1/ must use the
    ``{"status": "error", "detail": "..."}`` envelope, not bare ``{"detail": ...}``.
    """

    def test_auth_error_uses_api_envelope(self, _fixture_db, monkeypatch) -> None:
        # Request without auth to an authenticated API endpoint must return
        # the API error envelope, not just {"detail": "..."}.
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(_fixture_db)
        no_auth_client = TestClient(app)
        resp = no_auth_client.get("/api/v1/queries")
        assert resp.status_code == 401
        body = resp.json()
        assert body["status"] == "error"
        assert "detail" in body

    def test_query_empty_db_400(self, _empty_client) -> None:
        # Querying a DB with no snapshots must return 400 (client error),
        # not 500 (internal server error), with the API envelope.
        resp = _empty_client.get("/api/v1/query/estate_summary")
        assert resp.status_code == 400
        body = resp.json()
        assert body["status"] == "error"
        assert "detail" in body


class TestApiSnapshotsEmpty:
    def test_snapshots_empty_db(self, _empty_client) -> None:
        # A DB with no snapshots should return 200 with an empty list,
        # not an error.
        resp = _empty_client.get("/api/v1/snapshots")
        assert resp.status_code == 200
        body = resp.json()
        assert body == {"snapshots": []}


class TestApiQuerySmoke:
    """Smoke-test every valid query to ensure none crash with a 500."""

    # Queries that require specific fixture data and can't be easily
    # parametrised with a single value — we still run them but only assert
    # they don't return 500.
    _FIXTURE_PARAMS = {
        "settings_at_som": {"ou_path": "ou=child,dc=fakefixture,dc=local"},
        "effective_scope": {"gpo_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        "principal_resultant": {
            "principal_sid": "S-1-5-21-100-200-300-1001",
        },
    }

    @pytest.mark.parametrize("query_name", sorted(VALID_QUERIES - {"golden_diff"}))
    def test_query_all_valid_queries_smoke(self, _client, query_name: str) -> None:
        params = self._FIXTURE_PARAMS.get(query_name, {})
        resp = _client.get(f"/api/v1/query/{query_name}", params=params)
        # The key assertion: no query should crash with a 500.
        assert resp.status_code != 500, f"Query '{query_name}' returned 500 — see logged traceback"
        # All responses should use the API envelope.
        body = resp.json()
        assert "status" in body


class TestApiOptionalParams:
    def test_optional_params_forwarded(self, _client) -> None:
        # principal_resultant accepts computer_sid as an optional param.
        # Providing it must not cause a 400 — it should be forwarded to the
        # query (which returns 200 on a valid SID).
        resp = _client.get(
            "/api/v1/query/principal_resultant",
            params={
                "principal_sid": "S-1-5-21-100-200-300-1001",
                "computer_sid": "S-1-5-21-100-200-300-5001",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"

    def test_optional_params_listed(self, _client) -> None:
        # The queries listing should include optional_params so API consumers
        # can discover them.
        resp = _client.get("/api/v1/queries")
        assert resp.status_code == 200
        body = resp.json()
        assert "optional_params" in body["queries"]["principal_resultant"]
        assert "computer_sid" in body["queries"]["principal_resultant"]["optional_params"]


class TestApiAdmxThreading:
    """ADMX resolver must be injected from app.state.admx (WI-075)."""

    def test_admx_coverage_returns_ok(self, _client) -> None:
        resp = _client.get("/api/v1/query/admx_coverage")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert "data" in body
        summary = body["data"]["summary"]
        assert "total_policies" in summary
        assert "referenced_policies" in summary

    def test_admx_coverage_with_admx_dir(self, _fixture_db, tmp_path, monkeypatch) -> None:
        """When ADMX templates are available, admx_coverage should use them."""
        from gpo_lens.web.app import create_app

        pd = tmp_path / "PolicyDefinitions"
        pd.mkdir()
        admx = """\
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions
    xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"
    revision="1.0" schemaVersion="1.0">
  <policyNamespaces>
    <target prefix="test" namespace="Microsoft.Policies.Test" />
  </policyNamespaces>
  <resources minRequiredRevision="1.0" />
  <policies>
    <policy name="FakePolicy" class="Both"
            displayName="$(string.FakePolicy)"
            key="HKLM\\Software\\Fake"
            valueName="FakeValue" />
  </policies>
</policyDefinitions>
"""
        adml = """\
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitionResources
    xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"
    revision="1.0" schemaVersion="1.0">
  <resources>
    <stringTable>
      <string id="FakePolicy">Fake Policy</string>
    </stringTable>
  </resources>
</policyDefinitionResources>
"""
        (pd / "TestPolicies.admx").write_text(admx, encoding="utf-8")
        en_us = pd / "en-US"
        en_us.mkdir()
        (en_us / "TestPolicies.adml").write_text(adml, encoding="utf-8")

        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(_fixture_db, admx_dir=str(pd))
        c = TestClient(
            app,
            headers={"Authorization": "Bearer test-secret-token"},
        )
        resp = c.get("/api/v1/query/admx_coverage")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        summary = body["data"]["summary"]
        assert summary["total_policies"] >= 1
