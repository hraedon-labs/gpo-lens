from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sqlite3
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from _arch import CORE_MODULES, forbidden_imports_in

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


def _make_admx_dir(tmp_path: Path) -> Path:
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
    <policy name="FakeValue" class="Both"
            displayName="$(string.FakeValue)"
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
      <string id="FakeValue">Prohibit Fake Value</string>
    </stringTable>
  </resources>
</policyDefinitionResources>
"""
    (pd / "TestPolicies.admx").write_text(admx, encoding="utf-8")
    en_us = pd / "en-US"
    en_us.mkdir()
    (en_us / "TestPolicies.adml").write_text(adml, encoding="utf-8")
    return pd


def _make_baseline_zip() -> bytes:
    gpreport = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<GPO>\n"
        "  <Identifier>\n"
        "    <Identifier>{99999999-9999-9999-9999-999999999999}</Identifier>\n"
        "    <Domain>baseline.local</Domain>\n"
        "  </Identifier>\n"
        "  <Name>Baseline Policy</Name>\n"
        "  <CreatedTime>2024-01-01T00:00:00</CreatedTime>\n"
        "  <ModifiedTime>2024-01-01T00:00:00</ModifiedTime>\n"
        "  <ReadTime>2024-01-01T00:00:00</ReadTime>\n"
        "  <Computer>\n"
        "    <Enabled>true</Enabled>\n"
        "    <VersionDirectory>1</VersionDirectory>\n"
        "    <VersionSysvol>1</VersionSysvol>\n"
        "    <ExtensionData>\n"
        "      <Name>Security</Name>\n"
        "      <Extension>\n"
        '        <Security Name="Audit policy" Type="Policy">\n'
        "          <SettingBoolean>true</SettingBoolean>\n"
        "        </Security>\n"
        "      </Extension>\n"
        "    </ExtensionData>\n"
        "    <ExtensionData>\n"
        "      <Name>Registry</Name>\n"
        "      <Extension>\n"
        '        <Registry KeyName="HKLM\\Software\\Fake" ValueName="FakeValue">2</Registry>\n'
        "      </Extension>\n"
        "    </ExtensionData>\n"
        "    <ExtensionData>\n"
        "      <Name>Registry</Name>\n"
        "      <Extension>\n"
        '        <Registry KeyName="HKLM\\Baseline" ValueName="Test">1</Registry>\n'
        "      </Extension>\n"
        "    </ExtensionData>\n"
        "  </Computer>\n"
        "  <User>\n"
        "    <Enabled>true</Enabled>\n"
        "    <VersionDirectory>1</VersionDirectory>\n"
        "    <VersionSysvol>1</VersionSysvol>\n"
        "  </User>\n"
        "  <FilterDataAvailable>false</FilterDataAvailable>\n"
        "</GPO>\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "GPOs/{99999999-9999-9999-9999-999999999999}/gpreport.xml",
            gpreport,
        )
    return buf.getvalue()


@pytest.fixture()
def tmp_db() -> str:
    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
        path = f.name
    conn = sqlite3.connect(path)
    from gpo_lens.store import init_db

    init_db(conn)
    conn.close()
    try:
        yield path
    finally:
        os.unlink(path)


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


def _serve_args(**overrides: object) -> argparse.Namespace:
    defaults = {"db": ":memory:", "host": "127.0.0.1", "port": 8000, "open": False, "root_path": ""}
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestCreateApp:
    def test_returns_fastapi_app(self, tmp_db: str) -> None:
        from fastapi import FastAPI

        from gpo_lens.web.app import create_app

        app = create_app(tmp_db)
        assert isinstance(app, FastAPI)

    @pytest.mark.anyio
    async def test_home_route_returns_200(self, tmp_db: str, monkeypatch) -> None:
        from httpx import ASGITransport, AsyncClient

        from gpo_lens.web.app import create_app

        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(tmp_db)
        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"Authorization": "Bearer test-secret-token"},
        ) as client:
            resp = await client.get("/")
            assert resp.status_code == 200
            assert "gpo-lens" in resp.text

    def test_db_path_stored_on_app_state(self, tmp_db: str) -> None:
        from gpo_lens.web.app import create_app

        app = create_app(tmp_db)
        assert app.state.db_path == tmp_db

    def test_readonly_db_connection(self, tmp_db: str) -> None:
        from gpo_lens.web.app import create_app

        app = create_app(tmp_db)
        db_path = app.state.db_path
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("CREATE TABLE _should_fail (_id INTEGER PRIMARY KEY)")
        finally:
            conn.close()

    def test_root_path_passed_through(self, tmp_db: str) -> None:
        from gpo_lens.web.app import create_app

        app = create_app(tmp_db, root_path="/prefix")
        assert app.root_path == "/prefix"

    @pytest.mark.anyio
    async def test_pages_render_under_root_path(
        self, tmp_db: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from httpx import ASGITransport, AsyncClient

        from gpo_lens.web.app import create_app

        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(tmp_db, root_path="/gpo")
        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"Authorization": "Bearer test-secret-token"},
        ) as client:
            resp = await client.get("/")
            assert resp.status_code == 200
            assert "gpo-lens" in resp.text


class TestLoopbackGuard:
    def test_non_loopback_exits_nonzero(self, monkeypatch) -> None:
        from gpo_lens.cli._serve import cmd_serve

        # Hermetic: a GPO_LENS_AUTH_TOKEN leaked by another test in the same
        # worker would legitimately satisfy the guard — and then cmd_serve
        # would REALLY bind uvicorn on 0.0.0.0:8000 and hang the suite. The
        # uvicorn mock is the backstop so a guard regression fails fast
        # instead of hanging.
        monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
        args = _serve_args(host="0.0.0.0")
        with patch("uvicorn.run") as mock_run:
            ret = cmd_serve(args)
        assert ret == 1
        mock_run.assert_not_called()

    def test_localhost_allowed(self) -> None:
        from gpo_lens.cli._serve import cmd_serve

        args = _serve_args(host="localhost")
        with patch("uvicorn.run") as mock_run:
            ret = cmd_serve(args)
        assert ret == 0
        mock_run.assert_called_once()

    def test_ipv6_loopback_allowed(self) -> None:
        from gpo_lens.cli._serve import cmd_serve

        args = _serve_args(host="::1")
        with patch("uvicorn.run") as mock_run:
            ret = cmd_serve(args)
        assert ret == 0
        mock_run.assert_called_once()


class TestMissingWebExtra:
    def test_serve_errors_helpfully_when_web_missing(self) -> None:
        from gpo_lens.cli._serve import cmd_serve

        args = _serve_args()
        with patch.dict(sys.modules, {"gpo_lens.web": None, "gpo_lens.web.app": None}):
            real_import = (
                __builtins__["__import__"]
                if isinstance(__builtins__, dict)
                else __builtins__.__import__
            )

            def _fake_import(name, *a, **kw):
                if name in ("gpo_lens.web", "gpo_lens.web.app"):
                    raise ImportError("no web")
                return real_import(name, *a, **kw)

            with patch("builtins.__import__", side_effect=_fake_import):
                ret = cmd_serve(args)
        assert ret == 1


class TestArchitecture:
    @pytest.mark.parametrize("module_name", list(CORE_MODULES))
    def test_core_modules_do_not_import_web(self, module_name: str) -> None:
        violations = forbidden_imports_in(module_name, forbidden=("web",))
        assert not violations, (
            f"{module_name}.py imports forbidden package(s): {sorted(violations)}"
        )

    def test_query_dispatch_tables_consistent(self) -> None:
        from gpo_lens.query_dispatch import (
            _PARAM_VALIDATORS,
            _QUERY_DISPATCH,
            QUERY_REQUIRED_PARAMS,
        )

        for name in QUERY_REQUIRED_PARAMS:
            assert name in _QUERY_DISPATCH, (
                f"QUERY_REQUIRED_PARAMS references '{name}' not in _QUERY_DISPATCH"
            )
        for name in _PARAM_VALIDATORS:
            assert name in _QUERY_DISPATCH, (
                f"_PARAM_VALIDATORS references '{name}' not in _QUERY_DISPATCH"
            )


class TestDashboard:
    def test_dashboard_returns_200(self, client) -> None:
        resp = client.get("/")
        assert resp.status_code == 200

    def test_dashboard_contains_doctor_findings(self, client) -> None:
        resp = client.get("/")
        html = resp.text
        assert "Doctor findings" in html
        assert "gp-pill critical" in html

    def test_dashboard_shows_severity_badges(self, client) -> None:
        resp = client.get("/")
        html = resp.text
        assert "gp-pill critical" in html
        assert "gp-pill high" in html
        assert "gp-pill medium" in html
        assert "gp-pill low" in html

    def test_dashboard_findings_link_to_gpo_detail(self, client) -> None:
        resp = client.get("/")
        html = resp.text
        assert "/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in html
        assert "/gpo/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" in html
        assert "/gpo/cccccccccccccccccccccccccccccccc" in html

    def test_posture_cards_deeplink_into_findings(self, client) -> None:
        html = client.get("/").text
        # At least one fired posture card is an anchor that filters the findings
        # table by category and jumps to it.
        assert 'class="gp-ind' in html
        assert "?category=" in html
        assert "#findings" in html

    def test_posture_category_filter_narrows_findings(self, client) -> None:
        import re

        html = client.get("/").text
        m = re.search(r"\?category=([A-Za-z0-9_%:]+)#findings", html)
        assert m, "expected at least one clickable posture card"
        category = m.group(1)
        resp = client.get(f"/?category={category}")
        assert resp.status_code == 200
        # The active-filter chip (with its clear ✕) is shown.
        assert "✕" in resp.text

    def test_unknown_category_is_safe(self, client) -> None:
        # A bogus category must not error — it simply matches nothing.
        resp = client.get("/?category=does_not_exist")
        assert resp.status_code == 200

    def test_dashboard_severity_order(self, client) -> None:
        resp = client.get("/")
        html = resp.text
        critical_pos = html.find("gp-pill critical")
        high_pos = html.find("gp-pill high")
        medium_pos = html.find("gp-pill medium")
        low_pos = html.find("gp-pill low")
        assert critical_pos < high_pos
        assert high_pos < medium_pos
        assert medium_pos < low_pos


class TestGpoDetail:
    def test_gpo_detail_returns_200(self, client) -> None:
        resp = client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        assert resp.status_code == 200

    def test_gpo_detail_returns_404_for_unknown(self, client) -> None:
        resp = client.get("/gpo/00000000000000000000000000000000")
        assert resp.status_code == 404

    def test_gpo_detail_shows_version_skew_flag(self, client) -> None:
        resp = client.get("/gpo/cccccccccccccccccccccccccccccccc")
        html = resp.text
        assert "SKEW" in html

    def test_gpo_detail_shows_disabled_but_populated_warning(self, client) -> None:
        resp = client.get("/gpo/11111111111111111111111111111111")
        html = resp.text
        assert "Disabled but populated" in html

    def test_gpo_detail_shows_settings_grouped_by_side(self, client) -> None:
        resp = client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        html = resp.text
        assert "Computer Side Settings" in html or "User Side Settings" in html

    def test_gpo_detail_shows_gpo_name(self, client) -> None:
        resp = client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        html = resp.text
        assert "gpo-cpassword" in html

    def test_gpo_detail_version_skew_computer_side(self, client) -> None:
        resp = client.get("/gpo/cccccccccccccccccccccccccccccccc")
        html = resp.text
        assert "gp-chip crit" in html


class TestOuBrowser:
    def test_ou_list_returns_200_with_som_names(self, client) -> None:
        resp = client.get("/ou")
        assert resp.status_code == 200
        assert "fakefixture.local" in resp.text
        assert "child" in resp.text

    def test_ou_detail_returns_200_for_known_som(self, client) -> None:
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        assert "fakefixture.local" in resp.text

    def test_ou_detail_shows_effective_gpo_chain(self, client) -> None:
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        assert "gpo-cpassword" in resp.text
        assert "gpo-version-skew" in resp.text

    def test_ou_detail_shows_loopback_banner(self, client) -> None:
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        assert "Loopback processing" in resp.text

    # WI-083 — CSE facet + in-table search on the effective-settings table.

    def test_ou_detail_has_settings_filter_bar(self, client) -> None:
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        assert 'name="cse"' in resp.text
        # facet dropdown lists the CSEs present (6 Registry, 2 Security)
        assert "Registry (6)" in resp.text
        assert "Security (2)" in resp.text

    def test_ou_detail_cse_facet_narrows(self, client) -> None:
        resp = client.get(
            "/ou/dc=fakefixture,dc=local", params={"cse": "Security", "per_page": "all"}
        )
        assert resp.status_code == 200
        assert 'value="Security" selected' in resp.text
        # Count badge reflects the narrowing: 2 of 8 effective settings. (The
        # identity won't do — settings also surface in the conflicts table,
        # which is intentionally not filtered.)
        assert "2 / 8" in resp.text

    def test_ou_detail_search_narrows(self, client) -> None:
        resp = client.get(
            "/ou/dc=fakefixture,dc=local", params={"q": "BadValue", "per_page": "all"}
        )
        assert resp.status_code == 200
        assert "1 / 8" in resp.text

    def test_ou_detail_no_match_shows_empty_state(self, client) -> None:
        resp = client.get("/ou/dc=fakefixture,dc=local", params={"q": "zzz-no-such-setting"})
        assert resp.status_code == 200
        assert "No settings match" in resp.text


class TestIngest:
    def _make_fixture_zip(self) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in FIXTURE_DIR.rglob("*"):
                if path.is_file():
                    arcname = path.relative_to(FIXTURE_DIR)
                    zf.write(path, arcname)
        return buf.getvalue()

    def test_ingest_page_returns_200(self, client) -> None:
        resp = client.get("/ingest")
        assert resp.status_code == 200
        assert "Upload" in resp.text

    def test_upload_valid_fixture_zip_redirects(self, client) -> None:
        data = self._make_fixture_zip()
        resp = client.post(
            "/ingest",
            files={"file": ("fixture.zip", data, "application/zip")},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"].endswith("/")

    def test_upload_malformed_zip_shows_error(self, client) -> None:
        resp = client.post(
            "/ingest",
            files={"file": ("bad.zip", b"not a zip", "application/zip")},
        )
        assert resp.status_code == 400
        assert "Malformed zip" in resp.text or "Invalid" in resp.text

    def test_upload_zip_slip_returns_400(self, client) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
        resp = client.post(
            "/ingest",
            files={"file": ("evil.zip", buf.getvalue(), "application/zip")},
        )
        assert resp.status_code == 400
        assert "Malformed" in resp.text or "malformed" in resp.text.lower()

    def test_concurrent_upload_returns_409(self, client) -> None:
        app = client.app
        lock = app.state.ingest_lock
        assert lock.acquire(blocking=False)
        try:
            data = self._make_fixture_zip()
            resp = client.post(
                "/ingest",
                files={"file": ("fixture.zip", data, "application/zip")},
                follow_redirects=False,
            )
            assert resp.status_code == 409
        finally:
            lock.release()

    def test_concurrent_upload_succeeds_after_lock_release(self, client) -> None:
        app = client.app
        lock = app.state.ingest_lock
        assert lock.acquire(blocking=False)
        try:
            data = self._make_fixture_zip()
            resp = client.post(
                "/ingest",
                files={"file": ("fixture.zip", data, "application/zip")},
                follow_redirects=False,
            )
            assert resp.status_code == 409
        finally:
            lock.release()
        data = self._make_fixture_zip()
        resp = client.post(
            "/ingest",
            files={"file": ("fixture.zip", data, "application/zip")},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"].endswith("/")

    def test_upload_exceeds_size_limit_returns_413(self, client) -> None:
        data = b"x" * 128
        with patch("gpo_lens.web.app._MAX_UPLOAD_BYTES", 100):
            resp = client.post(
                "/ingest",
                files={"file": ("big.zip", data, "application/zip")},
            )
        assert resp.status_code == 413
        assert "Upload exceeds" in resp.text


def test_file_lock_blocks_cross_process(tmp_path):
    """WI-043: _FileLock must block across processes, not just threads.

    The threading.Lock fast-path only handles same-process contention.
    This test verifies the underlying fcntl.flock (Unix) / msvcrt.locking
    (Windows) actually prevents a separate process from acquiring the lock.
    """
    import subprocess

    from gpo_lens.web.app import _FileLock

    lock_path = str(tmp_path / "cross.lock")
    lock = _FileLock(lock_path)
    assert lock.acquire(blocking=False)

    child_script = (
        "import sys; "
        "from gpo_lens.web.app import _FileLock; "
        f"lock = _FileLock({lock_path!r}); "
        "acquired = lock.acquire(blocking=False); "
        "lock.release() if acquired else None; "
        "sys.exit(0 if acquired else 1)"
    )

    try:
        result = subprocess.run(
            [sys.executable, "-c", child_script],
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 1, (
            "Child should NOT acquire lock held by parent; "
            f"exit={result.returncode} stderr={result.stderr.decode()}"
        )
    finally:
        lock.release()

    # After release, a new process should acquire.
    result = subprocess.run(
        [sys.executable, "-c", child_script],
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, (
        "Child should acquire lock after parent released; "
        f"exit={result.returncode} stderr={result.stderr.decode()}"
    )


class TestAsk:
    def test_ask_page_returns_200(self, client) -> None:
        resp = client.get("/ask")
        assert resp.status_code == 200

    def test_ask_page_shows_not_configured_without_key(self, client) -> None:
        with patch.dict(os.environ, {"GPO_LENS_API_KEY": ""}, clear=False):
            resp = client.get("/ask")
        assert resp.status_code == 200
        assert "AI narration is not configured" in resp.text

    def test_post_ask_mocked_returns_deterministic_facts(self, client) -> None:
        mock_route = MagicMock(return_value={"query": "estate_summary", "params": {}})
        mock_call = MagicMock(return_value="There are 3 GPOs in the estate.")
        routing_ctx = patch("gpo_lens.narration.route_question", mock_route)
        call_ctx = patch("gpo_lens.narration.call_llm", mock_call)
        env_ctx = patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key"})
        with env_ctx, routing_ctx, call_ctx:
            resp = client.post("/ask", data={"question": "How many GPOs?"})
        assert resp.status_code == 200
        assert "There are 3 GPOs in the estate." not in resp.text
        mock_call.assert_not_called()
        assert "Explain these facts" in resp.text
        assert "Underlying Facts" in resp.text

    def test_post_ask_emits_audit_event(self, client, fixture_db: str) -> None:
        mock_route = MagicMock(return_value={"query": "estate_summary", "params": {}})
        mock_call = MagicMock(return_value="answer")
        ctx_route = patch("gpo_lens.narration.route_question", mock_route)
        ctx_call = patch("gpo_lens.narration.call_llm", mock_call)
        ctx_env = patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key"})
        with ctx_env, ctx_route, ctx_call:
            client.post("/ask", data={"question": "test question"})

        conn = sqlite3.connect(fixture_db)
        try:
            rows = conn.execute(
                "SELECT event_type, payload FROM events WHERE event_type = ?",
                ("audit.narrate",),
            ).fetchall()
        finally:
            conn.close()
        assert len(rows) == 1
        payload = json.loads(rows[0][1])
        assert payload["principal"] == "local-analyst"
        assert payload["question"] == "test question"

    def test_ask_audit_logs_sanitized_question(self, client, fixture_db: str) -> None:
        mock_route = MagicMock(return_value={"query": "estate_summary", "params": {}})
        mock_call = MagicMock(return_value="answer")
        ctx_route = patch("gpo_lens.narration.route_question", mock_route)
        ctx_call = patch("gpo_lens.narration.call_llm", mock_call)
        ctx_env = patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key"})
        raw_question = "what\x00about\nGPOs\r?"
        with ctx_env, ctx_route, ctx_call:
            client.post("/ask", data={"question": raw_question})

        conn = sqlite3.connect(fixture_db)
        try:
            row = conn.execute(
                "SELECT payload FROM events"
                " WHERE event_type = 'audit.narrate'"
                " ORDER BY id DESC LIMIT 1"
            ).fetchone()
        finally:
            conn.close()
        assert row is not None
        payload = json.loads(row[0])
        assert "\x00" not in payload["question"]
        assert "\n" not in payload["question"]
        assert "\r" not in payload["question"]

    def test_post_ask_viewer_gets_403(self, fixture_db: str) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app
        from gpo_lens.web.auth import Permission, Principal, get_principal

        viewer = Principal(
            name="viewer",
            role="viewer",
            permissions=frozenset([Permission.VIEW]),
        )
        app = create_app(fixture_db)
        app.dependency_overrides[get_principal] = lambda authorization=None: viewer
        try:
            client = TestClient(app, headers={"origin": "http://localhost"})
            resp = client.post("/ask", data={"question": "test"})
        finally:
            app.dependency_overrides.clear()
        assert resp.status_code == 403


@pytest.fixture()
def changelog_db():
    from gpo_lens.ingest import load_estate as ingest_load_estate
    from gpo_lens.model import Setting
    from gpo_lens.store import init_db, save_estate

    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
        path = f.name
    conn = sqlite3.connect(path)
    init_db(conn)
    estate = ingest_load_estate(FIXTURE_DIR)
    snap_a = save_estate(conn, estate)

    for g in estate.gpos:
        if g.computer_ver_ds is not None:
            g.computer_ver_ds += 1
        if g.computer_ver_sysvol is not None:
            g.computer_ver_sysvol += 1

    gpo_a = estate.gpos[0]
    gpo_a.settings.append(
        Setting(
            gpo_id=gpo_a.id,
            side="Computer",
            cse="Registry",
            identity="Software\\New:NewSetting",
            display_name="NewSetting",
            display_value="enabled",
            raw={"tag": "NewSetting", "text": "enabled"},
            from_disabled_side=False,
            source_state="normal",
        )
    )

    snap_b = save_estate(conn, estate)
    conn.close()
    try:
        yield path, snap_a, snap_b
    finally:
        os.unlink(path)


@pytest.fixture()
def changelog_client(changelog_db, monkeypatch):
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    db_path, _, _ = changelog_db
    app = create_app(db_path)
    return TestClient(
        app,
        headers={
            "origin": "http://localhost",
            "Authorization": "Bearer test-secret-token",
        },
    )


class TestChangelog:
    def test_changelog_page_returns_200(self, changelog_client) -> None:
        resp = changelog_client.get("/changelog")
        assert resp.status_code == 200

    def test_changelog_with_two_snapshots_shows_entries(self, changelog_db, monkeypatch) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app

        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        db_path, snap_a, snap_b = changelog_db
        client = TestClient(
            create_app(db_path),
            headers={
                "origin": "http://localhost",
                "Authorization": "Bearer test-secret-token",
            },
        )
        resp = client.get(f"/changelog?snap_a={snap_a}&snap_b={snap_b}")
        assert resp.status_code == 200
        html = resp.text
        assert "Changes" in html

    def test_changelog_distinguishes_entry_types(self, changelog_db, monkeypatch) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app

        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        db_path, snap_a, snap_b = changelog_db
        client = TestClient(
            create_app(db_path),
            headers={
                "origin": "http://localhost",
                "Authorization": "Bearer test-secret-token",
            },
        )
        resp = client.get(f"/changelog?snap_a={snap_a}&snap_b={snap_b}")
        html = resp.text
        assert "metadata only" in html
        assert "settings detail" in html


class TestBaseline:
    def test_baseline_page_returns_200(self, client) -> None:
        resp = client.get("/baseline")
        assert resp.status_code == 200

    def test_baseline_diff_shows_status_badges(self, client) -> None:
        data = _make_baseline_zip()
        resp = client.post(
            "/baseline",
            files={"file": ("baseline.zip", data, "application/zip")},
        )
        assert resp.status_code == 200
        html = resp.text
        has_badge = "gp-chip" in html and (
            "drift" in html or "compliant" in html or "missing" in html or "extra" in html
        )
        assert has_badge

    def test_baseline_diff_shows_admx_names(self, client) -> None:
        data = _make_baseline_zip()
        resp = client.post(
            "/baseline",
            files={"file": ("baseline.zip", data, "application/zip")},
        )
        assert resp.status_code == 200
        html = resp.text
        assert "ADMX" in html
        assert "no ADMX policy name" in html

    def test_upload_exceeds_size_limit_returns_413(self, client) -> None:
        data = b"x" * 128
        with patch("gpo_lens.web.app._MAX_UPLOAD_BYTES", 100):
            resp = client.post(
                "/baseline",
                files={"file": ("big.zip", data, "application/zip")},
            )
        assert resp.status_code == 413
        assert "Upload exceeds" in resp.text


class TestSafeExtract:
    def test_zip_slip_blocked(self, tmp_path: Path) -> None:
        from gpo_lens.web.app import _safe_extract

        dest = tmp_path / "dest"
        dest.mkdir()
        zip_path = tmp_path / "evil.zip"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
        zip_path.write_bytes(buf.getvalue())

        with pytest.raises(ValueError, match="zip-slip blocked"):
            _safe_extract(zip_path, dest)

        assert list(dest.rglob("*")) == [], "rejected zip should leave dest empty"

    def test_symlink_blocked(self, tmp_path: Path) -> None:
        from gpo_lens.web.app import _safe_extract

        dest = tmp_path / "dest"
        dest.mkdir()
        zip_path = tmp_path / "evil.zip"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            info = zipfile.ZipInfo("evil_link")
            info.create_system = 3  # Unix
            info.external_attr = (0o777 | 0xA000) << 16  # symlink type
            zf.writestr(info, "/etc/passwd")
        zip_path.write_bytes(buf.getvalue())

        with pytest.raises(ValueError, match="zip symlink blocked"):
            _safe_extract(zip_path, dest)

        assert list(dest.rglob("*")) == [], "rejected zip should leave dest empty"

    def test_valid_zip_extracts(self, tmp_path: Path) -> None:
        from gpo_lens.web.app import _safe_extract

        dest = tmp_path / "dest"
        dest.mkdir()
        zip_path = tmp_path / "good.zip"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("subdir/file.txt", "hello world")
        zip_path.write_bytes(buf.getvalue())

        _safe_extract(zip_path, dest)
        extracted_file = dest / "subdir" / "file.txt"
        assert extracted_file.exists()
        assert extracted_file.read_text() == "hello world"

    def test_zip_bomb_rejected(self, tmp_path: Path) -> None:
        from gpo_lens.web.app import _safe_extract

        dest = tmp_path / "dest"
        dest.mkdir()
        zip_path = tmp_path / "bomb.zip"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.txt", "x" * 200)
        zip_path.write_bytes(buf.getvalue())

        with patch("gpo_lens.web.app._MAX_UNCOMPRESSED_BYTES", 100):
            with pytest.raises(ValueError, match="exceeds limit"):
                _safe_extract(zip_path, dest)

    def test_spoofed_file_size_still_enforced(self, tmp_path: Path) -> None:
        """Zip-bomb: streaming reader catches large content regardless of headers.

        _safe_extract uses SizeLimitedReader which counts actual
        decompressed bytes during streaming, not info.file_size.

        NOTE: Python's zipfile validates CRC and truncates output to
        file_size bytes, so binary header spoofing is caught at the
        zipfile layer.  The real protection is against legitimately
        large entries where streaming enforcement catches the cap
        violation during decompression, not after.
        """
        from gpo_lens.web.app import _safe_extract

        dest = tmp_path / "dest"
        dest.mkdir()
        zip_path = tmp_path / "big.zip"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.txt", "x" * 200)
        zip_path.write_bytes(buf.getvalue())

        with patch("gpo_lens.web.app._MAX_UNCOMPRESSED_BYTES", 100):
            with pytest.raises(ValueError, match="exceeds limit"):
                _safe_extract(zip_path, dest)

    def test_absolute_path_blocked(self, tmp_path: Path) -> None:
        from gpo_lens.web.app import _safe_extract

        dest = tmp_path / "dest"
        dest.mkdir()
        zip_path = tmp_path / "evil.zip"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("/etc/passwd", "root:x:0:0:root:/root:/bin/bash")
        zip_path.write_bytes(buf.getvalue())

        with pytest.raises(ValueError, match="zip-slip blocked"):
            _safe_extract(zip_path, dest)

        assert list(dest.rglob("*")) == [], "rejected zip should leave dest empty"

    def test_post_extract_failure_cleans_up(self, tmp_path: Path) -> None:
        """A zip that passes pre-extract checks but fails post-extract must
        leave no files behind in the destination.

        This tests the cleanup-on-failure behaviour: when extraction raises
        after files have been written to disk, those partial files must be
        removed before re-raising.
        """
        from gpo_lens.web.app import _safe_extract

        dest = tmp_path / "dest"
        dest.mkdir()
        zip_path = tmp_path / "postfail.zip"

        # Create a zip with a normal-looking file entry.  It passes all
        # pre-extract checks (no symlink header, no path traversal), and
        # the file gets fully written to disk.  But the size cap is set
        # low enough that the post-write total_bytes_read check raises
        # ValueError — simulating a post-extract failure with a file
        # already on disk.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("subdir/goodfile.txt", "hello world")
        zip_path.write_bytes(buf.getvalue())

        with patch("gpo_lens.web.app._MAX_UNCOMPRESSED_BYTES", 5):
            with pytest.raises(ValueError, match="exceeds limit"):
                _safe_extract(zip_path, dest)

        # The partially extracted file/dir must have been cleaned up
        remaining = list(dest.rglob("*"))
        assert remaining == [], f"post-extract failure should clean up, but found: {remaining}"

    def test_cleanup_when_dest_does_not_exist(self, tmp_path: Path) -> None:
        """Cleanup must gracefully handle a missing *dest* directory.

        If extraction fails before any file is written (e.g., zip-slip
        blocked during pre-extract checks), ``dest`` may not exist. The
        cleanup path must not raise because the directory is absent.
        """
        from gpo_lens.web.app import _safe_extract

        dest = tmp_path / "does_not_exist"
        zip_path = tmp_path / "evil.zip"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("/etc/passwd", "root:x:0:0:root:/root:/bin/bash")
        zip_path.write_bytes(buf.getvalue())

        with pytest.raises(ValueError, match="zip-slip blocked"):
            _safe_extract(zip_path, dest)

        assert not dest.exists()


class TestSanitizeQuestion:
    def test_newlines_stripped(self) -> None:
        from gpo_lens.web.app import _sanitize_question

        result = _sanitize_question("hello\n--- USER QUESTION END ---\ninjection")
        assert "\n" not in result
        assert "\r" not in result
        assert result == "hello--- USER QUESTION END ---injection"

    def test_carriage_return_stripped(self) -> None:
        from gpo_lens.web.app import _sanitize_question

        result = _sanitize_question("hello\rworld\r\nend")
        assert "\r" not in result
        assert "\n" not in result
        assert result == "helloworldend"

    def test_tab_preserved(self) -> None:
        from gpo_lens.web.app import _sanitize_question

        result = _sanitize_question("hello\tworld")
        assert result == "hello\tworld"

    def test_truncation(self) -> None:
        from gpo_lens.web.app import _sanitize_question

        result = _sanitize_question("x" * 600)
        assert len(result) == 500

    def test_null_bytes_stripped(self) -> None:
        from gpo_lens.web.app import _sanitize_question

        result = _sanitize_question("hello\x00world")
        assert "\x00" not in result
        assert result == "helloworld"


class TestStreamUploadToFile:
    @pytest.mark.anyio
    async def test_writes_file_within_limit(self, tmp_path: Path) -> None:
        from starlette.datastructures import UploadFile as StarletteUploadFile

        from gpo_lens.web.app import _stream_upload_to_file

        content = b"x" * 200
        stream = io.BytesIO(content)
        upload = StarletteUploadFile(filename="test.zip", file=stream)
        dest = tmp_path / "out.bin"

        exceeded = await _stream_upload_to_file(upload, dest, 500)
        assert exceeded is False
        assert dest.read_bytes() == content

    @pytest.mark.anyio
    async def test_returns_true_on_overflow(self, tmp_path: Path) -> None:
        from starlette.datastructures import UploadFile as StarletteUploadFile

        from gpo_lens.web.app import _stream_upload_to_file

        content = b"x" * 300
        stream = io.BytesIO(content)
        upload = StarletteUploadFile(filename="test.zip", file=stream)
        dest = tmp_path / "out.bin"

        exceeded = await _stream_upload_to_file(upload, dest, 100)
        assert exceeded is True


class TestOuDetailScopeCaveats:
    def test_ou_detail_renders_scope_caveats_section(self, client) -> None:
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        html = resp.text
        assert "Scope caveats" in html
        assert "flagged, not simulated" in html

    def test_ou_detail_lists_loopback_caveat(self, client) -> None:
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        # The caveat list uses "loopback=<mode>" (topology.scope_caveats),
        # not the fallback text "no loopback, ..." — this assertion only
        # passes when a real loopback caveat is actually rendered.
        assert "loopback=" in resp.text.lower()


class TestOuDetailGateChips:
    """Plan 019 Phase A — per-candidate gate attribution on the chain rows."""

    def test_ou_detail_shows_security_filter_chip_with_trustees(self, client) -> None:
        # AC-1: a security-filtered GPO shows its Apply-Group-Policy trustees
        # on its own row, not only in the aggregate caveat list.
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        assert "filtered" in resp.text.lower()
        assert "Helpdesk Operators" in resp.text

    def test_ou_detail_shows_wmi_chip_and_marks_broken(self, client) -> None:
        # AC-2: WMI filter name on its row; broken ref flagged.
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        assert "WMI:" in resp.text
        assert "Fake WMI Filter" in resp.text
        assert "Nonexistent WMI Filter" in resp.text
        assert "broken" in resp.text.lower()

    def test_ou_detail_shows_loopback_mode_chip(self, client) -> None:
        # AC-3: loopback mode rendered per row (not a fabricated mode).
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        assert "loopback: replace" in resp.text.lower()
        assert "loopback: merge" in resp.text.lower()

    def test_ou_detail_shows_disabled_side_chip(self, client) -> None:
        # AC-4: a disabled user/computer side shows on its row.
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        assert "computer side off" in resp.text.lower()
        assert "user side off" in resp.text.lower()

    def test_ou_detail_shows_applies_to_all_for_no_gate_gpo(self, client) -> None:
        # AC-5: a no-gate GPO shows the quiet "applies to all in scope" affordance.
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        assert "applies to all in scope" in resp.text

    def test_ou_detail_chain_renders_without_errors_and_keeps_existing_chips(self, client) -> None:
        # AC-7: strict superset — the chain still renders with the existing
        # enforced/order/link-off chips alongside the new gate strip.
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        assert "gp-chain" in resp.text
        assert "gpo-cpassword" in resp.text
        assert "enforced" in resp.text  # GPO C (version_skew) has an enforced link
        assert "#1" in resp.text  # order chip for the first chain entry

    def test_ou_detail_gate_chip_carries_non_evaluation_tooltip(self, client) -> None:
        # AC-6: every gate carries the "not evaluated" caveat via a title tooltip.
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        assert "not modeled" in resp.text  # security filtering tooltip
        assert "not evaluated" in resp.text  # WMI / ILT tooltip


class TestGpoDetailScopeCaveats:
    def test_gpo_detail_renders_scope_caveats_section(self, client) -> None:
        resp = client.get("/gpo/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
        assert resp.status_code == 200
        html = resp.text
        assert "Scope caveats" in html
        assert "flagged, not simulated" in html

    def test_gpo_detail_lists_loopback_caveat(self, client) -> None:
        resp = client.get("/gpo/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
        assert resp.status_code == 200
        assert "Loopback mode:" in resp.text


class TestSecurityHeaders:
    def test_csp_header_present(self, client) -> None:
        resp = client.get("/")
        assert resp.status_code == 200
        csp = resp.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        assert "style-src 'self' 'unsafe-inline'" in csp

    def test_csp_forbids_inline_scripts(self, client) -> None:
        resp = client.get("/")
        csp = resp.headers.get("content-security-policy", "")
        assert "script-src 'self'" in csp
        assert "script-src 'unsafe-inline'" not in csp


class TestUiEnhancements:
    def test_favicon_link_present(self, client) -> None:
        resp = client.get("/")
        assert 'rel="icon"' in resp.text
        assert "favicon.svg" in resp.text

    def test_gpo_detail_has_breadcrumb(self, client) -> None:
        resp = client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        assert "gp-breadcrumb" in resp.text
        assert "aria-current" in resp.text

    def test_ou_detail_has_breadcrumb(self, client) -> None:
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert "gp-breadcrumb" in resp.text
        assert "Directory" in resp.text

    def test_ingest_page_has_confirm_overlay(self, client) -> None:
        resp = client.get("/ingest")
        assert "confirm-overlay" in resp.text
        assert 'role="dialog"' in resp.text
        assert "aria-modal" in resp.text

    def test_ingest_page_uses_upload_js(self, client) -> None:
        resp = client.get("/ingest")
        assert "upload.js" in resp.text

    def test_baseline_page_has_drag_drop_zone(self, client) -> None:
        resp = client.get("/baseline")
        assert "drop-zone" in resp.text
        assert "upload.js" in resp.text

    def test_ou_list_has_type_column(self, client) -> None:
        resp = client.get("/ou")
        assert "gp-chip info" in resp.text or "gp-chip muted" in resp.text

    def test_ou_list_shows_site_chip(self, client) -> None:
        resp = client.get("/ou")
        html = resp.text
        assert "Site" in html

    def test_ask_input_has_maxlength(self, client) -> None:
        resp = client.get("/ask")
        assert 'maxlength="500"' in resp.text

    def test_changelog_shows_guidance_with_few_snapshots(self, client) -> None:
        resp = client.get("/changelog")
        assert "Need at least two snapshots" in resp.text

    def test_error_page_404_shows_detail(self, client) -> None:
        resp = client.get("/gpo/00000000000000000000000000000000")
        assert resp.status_code == 404
        assert "GPO not found" in resp.text


class TestDashboardFiltering:
    """WI-025: filter / search / sort on the dashboard findings table.

    Fixture estate has 24 findings (1 critical, 3 high, 2 medium, 12 low, 6 info).
    """

    # Findings-table rows render as <td><span class="gp-pill {sev}">; the header
    # summary pills are NOT inside <td>, so this targets only finding rows.
    @staticmethod
    def _sev_sequence(html: str) -> list[str]:
        return re.findall(r'<td><span class="gp-pill (\w+)">', html)

    def test_filter_by_severity_shows_subset(self, client) -> None:
        resp = client.get("/?severity=critical")
        assert resp.status_code == 200
        # critical filter → 1 of 24; the badge shows "N of total" only when filtered
        assert "1 of 24" in resp.text
        assert "gpo-cpassword" in resp.text

    def test_unfiltered_shows_total_without_of(self, client) -> None:
        # "All (incl. info)" is the only truly-unfiltered view; the bare default
        # hides info, so it legitimately shows "N of 24".
        resp = client.get("/?severity=all")
        assert "24" in resp.text
        assert " of 24" not in resp.text

    def test_default_view_hides_info_findings(self, client) -> None:
        # The actionable default suppresses info-level rows and offers a "Show
        # all" escape hatch so a large estate's bulk info doesn't bury findings.
        default = client.get("/").text
        assert self._sev_sequence(default)  # actionable findings still present
        assert "info" not in self._sev_sequence(default)
        assert "Show all" in default
        # ...and they reappear under the explicit all view.
        assert "info" in self._sev_sequence(client.get("/?severity=all").text)

    def test_search_filters_by_text(self, client) -> None:
        resp = client.get("/?q=cpassword")
        assert resp.status_code == 200
        # "cpassword" matches the cpassword finding (summary) AND the
        # local_admin_push finding (GPO name "gpo-cpassword") → 2 of 24.
        assert "2 of 24" in resp.text
        assert "gpo-cpassword" in resp.text

    def test_search_no_matches_shows_empty_state(self, client) -> None:
        resp = client.get("/?q=zzzznomatch")
        assert resp.status_code == 200
        assert "No findings match" in resp.text

    def test_sort_severity_desc_reverses_order(self, client) -> None:
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        # severity=all so the full ladder (incl. info) is present to reverse.
        default = self._sev_sequence(client.get("/?severity=all").text)
        desc = self._sev_sequence(client.get("/?severity=all&sort=severity_desc").text)
        assert default  # findings present
        assert desc
        # default ascending (worst first); desc reversed (least severe first)
        assert default[0] == "critical"
        assert desc[0] == "info"
        assert [rank[s] for s in default] == sorted(rank[s] for s in default)
        assert [rank[s] for s in desc] == sorted((rank[s] for s in desc), reverse=True)

    def test_sort_by_gpo_reflected_in_dropdown(self, client) -> None:
        resp = client.get("/?sort=gpo")
        assert resp.status_code == 200
        assert 'value="gpo" selected' in resp.text

    def test_invalid_sort_falls_back_to_severity(self, client) -> None:
        resp = client.get("/?sort=nonsense")
        assert resp.status_code == 200
        assert 'value="severity" selected' in resp.text

    def test_clear_link_visible_only_when_filtered(self, client) -> None:
        filtered = client.get("/?severity=critical").text
        default = client.get("/").text
        assert ">Clear<" in filtered
        assert ">Clear<" not in default


class TestPagination:
    """WI-026: server-side pagination of large tables."""

    def test_dashboard_pagination_controls(self, client) -> None:
        resp = client.get("/?severity=all&per_page=5")
        assert resp.status_code == 200
        assert "gp-pagination" in resp.text
        assert "page 1 of 5" in resp.text  # ceil(24/5) = 5

    def test_dashboard_pagination_page2_has_prev(self, client) -> None:
        resp = client.get("/?severity=all&per_page=5&page=2")
        assert "page 2 of 5" in resp.text
        assert 'rel="prev"' in resp.text

    def test_dashboard_per_page_all_no_controls(self, client) -> None:
        resp = client.get("/?per_page=all")
        assert resp.status_code == 200
        assert "gp-pagination" not in resp.text

    def test_dashboard_per_page_capped_at_max(self, client) -> None:
        # per_page beyond MAX_PER_PAGE (200) is capped; 24 findings → 1 page
        resp = client.get("/?per_page=99999")
        assert resp.status_code == 200
        assert "gp-pagination" not in resp.text

    def test_dashboard_invalid_page_clamped_to_last(self, client) -> None:
        resp = client.get("/?severity=all&per_page=5&page=999")
        assert resp.status_code == 200
        assert "page 5 of 5" in resp.text

    def test_dashboard_pagination_preserves_filters(self, client) -> None:
        # 12 low-severity findings → 3 pages at per_page=5; page links must
        # carry the severity filter so navigation doesn't drop it.
        resp = client.get("/?severity=low&per_page=5")
        assert resp.status_code == 200
        assert "page 1 of 3" in resp.text
        assert "severity=low" in resp.text  # present in pagination hrefs
        # next link must include the filter
        assert "severity=low" in resp.text and "page=2" in resp.text

    def test_ou_list_pagination(self, client) -> None:
        resp = client.get("/ou?per_page=2")
        assert resp.status_code == 200
        assert "gp-pagination" in resp.text
        assert "page 1 of 2" in resp.text  # ceil(4/2) = 2

    def test_ou_detail_settings_pagination(self, client) -> None:
        resp = client.get("/ou/dc=fakefixture,dc=local?per_page=3")
        assert resp.status_code == 200
        assert "gp-pagination" in resp.text
        assert "page 1 of 3" in resp.text  # ceil(8/3) = 3


class TestDirectorySearch:
    """Plan 017 Phase A: search, type filter, sort on the Directory page."""

    def test_search_filters_by_name(self, client) -> None:
        resp = client.get("/ou?q=child")
        assert resp.status_code == 200
        assert "child" in resp.text
        assert "fakefixture.local" not in resp.text

    def test_search_filters_by_dn(self, client) -> None:
        resp = client.get("/ou?q=ou=child")
        assert resp.status_code == 200
        assert "child" in resp.text

    def test_search_no_matches_shows_empty_state(self, client) -> None:
        resp = client.get("/ou?q=zzzznomatch")
        assert resp.status_code == 200
        assert "No scopes match" in resp.text

    def test_type_filter_domain(self, client) -> None:
        resp = client.get("/ou?type=domain")
        assert resp.status_code == 200
        assert "fakefixture.local" in resp.text
        assert "Default-First-Site-Name" not in resp.text

    def test_type_filter_ou(self, client) -> None:
        resp = client.get("/ou?type=ou")
        assert resp.status_code == 200
        assert "child" in resp.text
        assert "fakefixture.local" not in resp.text

    def test_type_filter_site(self, client) -> None:
        resp = client.get("/ou?type=site")
        assert resp.status_code == 200
        assert "Default-First-Site-Name" in resp.text
        assert "Branch-Office" in resp.text
        assert "fakefixture.local" not in resp.text

    def test_sort_by_links_descending(self, client) -> None:
        resp = client.get("/ou?sort=links")
        assert resp.status_code == 200
        html = resp.text
        domain_pos = html.find("fakefixture.local")
        child_pos = html.find(">child<")
        assert domain_pos != -1
        assert child_pos != -1
        assert domain_pos < child_pos

    def test_sort_by_name_default(self, client) -> None:
        resp = client.get("/ou?sort=name")
        assert resp.status_code == 200
        html = resp.text
        branch_pos = html.find("Branch-Office")
        child_pos = html.find(">child<")
        assert branch_pos != -1
        assert child_pos != -1
        assert branch_pos < child_pos

    def test_sort_by_type(self, client) -> None:
        resp = client.get("/ou?sort=type")
        assert resp.status_code == 200
        html = resp.text
        domain_pos = html.find("fakefixture.local")
        ou_pos = html.find(">child<")
        site_pos = html.find("Default-First-Site-Name")
        assert domain_pos < ou_pos
        assert ou_pos < site_pos

    def test_invalid_type_ignored(self, client) -> None:
        resp = client.get("/ou?type=nonsense")
        assert resp.status_code == 200
        assert "fakefixture.local" in resp.text

    def test_invalid_sort_falls_back_to_name(self, client) -> None:
        resp = client.get("/ou?sort=nonsense")
        assert resp.status_code == 200
        assert 'value="name" selected' in resp.text

    def test_pagination_preserves_filters(self, client) -> None:
        resp = client.get("/ou?q=fixture&per_page=1")
        assert resp.status_code == 200
        assert "q=fixture" in resp.text
        assert "page=2" in resp.text

    def test_no_params_no_regression(self, client) -> None:
        resp = client.get("/ou")
        assert resp.status_code == 200
        assert "fakefixture.local" in resp.text
        assert "child" in resp.text
        assert "Default-First-Site-Name" in resp.text
        assert "Branch-Office" in resp.text

    def test_clear_link_visible_when_filtered(self, client) -> None:
        filtered = client.get("/ou?q=child").text
        default = client.get("/ou").text
        assert ">Clear<" in filtered
        assert ">Clear<" not in default

    def test_filtered_count_shown_when_filtered(self, client) -> None:
        resp = client.get("/ou?type=site")
        assert resp.status_code == 200
        assert "2 of 4" in resp.text


class TestExport:
    """WI-027: in-app data export (CSV/JSON), requiring VIEW permission."""

    def test_export_findings_csv(self, client) -> None:
        resp = client.get("/export/findings?format=csv")
        assert resp.status_code == 200
        assert resp.headers["content-type"].split(";")[0] == "text/csv"
        assert "attachment" in resp.headers["content-disposition"]
        assert "gpo-lens-findings.csv" in resp.headers["content-disposition"]
        assert resp.text.startswith("severity,category,gpo_id,gpo_name,summary,detail")
        assert "gpo-cpassword" in resp.text

    def test_export_findings_csv_row_count(self, client) -> None:
        resp = client.get("/export/findings?format=csv")
        rows = list(csv.reader(io.StringIO(resp.text)))
        assert len(rows) == 25  # header + 24 findings

    def test_export_findings_csv_sanitizes_formula_cells(self, client) -> None:
        # CSV injection (CWE-1236): cells starting with = + - @ trigger formula
        # evaluation in spreadsheets. Verify the mitigation prefixes them.
        from gpo_lens.web.app import _csv_sanitize_cell

        assert _csv_sanitize_cell("=cmd|'/C calc'!A0") == "'=cmd|'/C calc'!A0"
        assert _csv_sanitize_cell("+1+1") == "'+1+1"
        assert _csv_sanitize_cell("@SUM(a1)") == "'@SUM(a1)"
        assert _csv_sanitize_cell("-2+3") == "'-2+3"
        # benign values pass through unchanged
        assert _csv_sanitize_cell("normal value") == "normal value"
        assert _csv_sanitize_cell("") == ""
        assert _csv_sanitize_cell(42) == 42

    def test_export_findings_ignores_dashboard_filters(self, client) -> None:
        # Export is a complete data dump, independent of session filter state.
        resp = client.get("/export/findings?format=json&severity=critical&q=x")
        assert resp.status_code == 200
        data = json.loads(resp.text)
        assert len(data) == 24  # all findings, not the filtered subset

    def test_export_findings_invalid_format_400(self, client) -> None:
        resp = client.get("/export/findings?format=xlsx")
        assert resp.status_code == 400

    def test_export_ou_invalid_format_400(self, client) -> None:
        resp = client.get("/export/ou/dc=fakefixture,dc=local?format=xml")
        assert resp.status_code == 400

    def test_export_findings_default_is_csv(self, client) -> None:
        resp = client.get("/export/findings")
        assert resp.headers["content-type"].split(";")[0] == "text/csv"

    def test_export_findings_json(self, client) -> None:
        resp = client.get("/export/findings?format=json")
        assert resp.status_code == 200
        assert resp.headers["content-type"].split(";")[0] == "application/json"
        assert "attachment" in resp.headers["content-disposition"]
        data = json.loads(resp.text)
        assert isinstance(data, list)
        assert len(data) == 24
        assert "critical" in {row["severity"] for row in data}

    def test_export_gpo_json(self, client) -> None:
        resp = client.get("/export/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?format=json")
        assert resp.status_code == 200
        assert resp.headers["content-type"].split(";")[0] == "application/json"
        data = json.loads(resp.text)
        assert data["name"] == "gpo-cpassword"
        assert data["id"] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    def test_export_gpo_unknown_404(self, client) -> None:
        resp = client.get("/export/gpo/00000000000000000000000000000000?format=json")
        assert resp.status_code == 404

    def test_export_gpo_rejects_csv(self, client) -> None:
        # GPO is a nested object — JSON only. CSV is explicitly unsupported.
        resp = client.get("/export/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?format=csv")
        assert resp.status_code == 400

    def test_export_ou_csv(self, client) -> None:
        resp = client.get("/export/ou/dc=fakefixture,dc=local?format=csv")
        assert resp.status_code == 200
        assert resp.headers["content-type"].split(";")[0] == "text/csv"
        assert resp.text.startswith("cse,side,identity,display_name,display_value")
        rows = list(csv.reader(io.StringIO(resp.text)))
        assert len(rows) == 9  # header + 8 effective settings

    def test_export_ou_json(self, client) -> None:
        resp = client.get("/export/ou/dc=fakefixture,dc=local?format=json")
        assert resp.status_code == 200
        data = json.loads(resp.text)
        assert isinstance(data, list)
        assert len(data) == 8

    def test_export_ou_unknown_404(self, client) -> None:
        resp = client.get("/export/ou/dc=nonexistent,dc=local?format=csv")
        assert resp.status_code == 404

    def test_export_requires_auth(self, tmp_db, monkeypatch) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app

        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(tmp_db)
        unauthed = TestClient(app)  # no Authorization header
        resp = unauthed.get("/export/findings?format=csv")
        assert resp.status_code == 401


class TestHealthAndVersion:
    """Unauthenticated liveness/version probes for IIS supervision."""

    def test_healthz_returns_200_without_auth_header(self, tmp_db, monkeypatch) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app

        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(tmp_db)
        unauthed = TestClient(app)  # no Authorization header
        resp = unauthed.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_api_version_returns_200_without_auth_header(self, tmp_db, monkeypatch) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens import __version__
        from gpo_lens.web.app import create_app

        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(tmp_db)
        unauthed = TestClient(app)
        resp = unauthed.get("/api/version")
        assert resp.status_code == 200
        body = resp.json()
        assert body["version"] == __version__
        assert body["name"] == "gpo-lens"

    def test_healthz_reachable_with_no_token_configured(self, tmp_db, monkeypatch) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app

        monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
        app = create_app(tmp_db)
        unauthed = TestClient(app)
        resp = unauthed.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


@pytest.fixture()
def audit_client(fixture_db: str, tmp_path: Path, monkeypatch) -> object:
    """A TestClient whose audit log writes to tmp_path/audit.log."""
    from fastapi.testclient import TestClient

    from gpo_lens.web import app as appmod
    from gpo_lens.web.app import create_app

    monkeypatch.setenv("GPO_LENS_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setattr(appmod, "_audit_logger", None)
    monkeypatch.setattr(appmod, "_audit_log_configured_path", None)
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    app = create_app(fixture_db)
    return TestClient(
        app,
        headers={
            "origin": "http://localhost",
            "Authorization": "Bearer test-secret-token",
        },
    )


class TestAuditLog:
    """Best-effort JSON-lines audit trail for privileged operations (ingest)."""

    @staticmethod
    def _make_fixture_zip() -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in FIXTURE_DIR.rglob("*"):
                if path.is_file():
                    arcname = path.relative_to(FIXTURE_DIR)
                    zf.write(path, arcname)
        return buf.getvalue()

    @staticmethod
    def _read_audit_log(path: Path) -> list[dict[str, object]]:
        if not path.exists():
            return []
        entries: list[dict[str, object]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                entries.append(json.loads(line))
        return entries

    def test_audit_log_path_defaults_to_db_dir(self, tmp_path: Path) -> None:
        from gpo_lens.web.app import _audit_log_path

        db = tmp_path / "estate.sqlite3"
        db.write_text("")
        assert _audit_log_path(str(db)) == tmp_path / "audit.log"

    def test_audit_log_path_env_override(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from gpo_lens.web.app import _audit_log_path

        custom = tmp_path / "custom" / "audit.jsonl"
        monkeypatch.setenv("GPO_LENS_AUDIT_LOG", str(custom))
        assert _audit_log_path("/any/db.sqlite3") == custom

    def test_ingest_success_writes_audit_entry(self, audit_client: object, tmp_path: Path) -> None:
        data = self._make_fixture_zip()
        resp = audit_client.post(  # type: ignore[union-attr]
            "/ingest",
            files={"file": ("fixture.zip", data, "application/zip")},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        entries = self._read_audit_log(tmp_path / "audit.log")
        assert len(entries) == 1
        entry = entries[0]
        assert entry["action"] == "ingest"
        assert entry["outcome"] == "success"
        assert entry["principal"] == "local-analyst"
        assert "fixture.zip" in str(entry["detail"])
        assert entry["request_id"] is not None

    def test_ingest_failure_writes_audit_entry(self, audit_client: object, tmp_path: Path) -> None:
        resp = audit_client.post(  # type: ignore[union-attr]
            "/ingest",
            files={"file": ("bad.zip", b"not a zip", "application/zip")},
        )
        assert resp.status_code == 400
        entries = self._read_audit_log(tmp_path / "audit.log")
        assert len(entries) == 1
        entry = entries[0]
        assert entry["action"] == "ingest"
        assert entry["outcome"] == "failure"

    def test_audit_log_write_failure_does_not_break_ingest(
        self, fixture_db: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web import app as appmod
        from gpo_lens.web.app import create_app

        # Point the audit log at a path whose parent is a file, not a
        # directory, so the FileHandler open fails with OSError.
        blocker = tmp_path / "blocker"
        blocker.write_text("not a dir")
        monkeypatch.setenv("GPO_LENS_AUDIT_LOG", str(blocker / "audit.log"))
        monkeypatch.setattr(appmod, "_audit_logger", None)
        monkeypatch.setattr(appmod, "_audit_log_configured_path", None)
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(fixture_db)
        client = TestClient(
            app,
            headers={
                "origin": "http://localhost",
                "Authorization": "Bearer test-secret-token",
            },
        )
        data = self._make_fixture_zip()
        resp = client.post(
            "/ingest",
            files={"file": ("fixture.zip", data, "application/zip")},
            follow_redirects=False,
        )
        assert resp.status_code == 303


class TestAdmxWeb:
    def test_gpo_detail_shows_admx_policy_name(
        self, fixture_db: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app

        pd_dir = _make_admx_dir(tmp_path)
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(fixture_db, admx_dir=str(pd_dir))
        client = TestClient(
            app,
            headers={
                "origin": "http://localhost",
                "Authorization": "Bearer test-secret-token",
            },
        )
        resp = client.get("/gpo/cccccccccccccccccccccccccccccccc")
        assert resp.status_code == 200
        html = resp.text
        assert "Prohibit Fake Value" in html
        assert "HKLM\\Software\\Fake:FakeValue" in html
        assert "<th>Setting</th>" in html

    def test_gpo_detail_without_admx_is_unchanged(self, client) -> None:
        resp = client.get("/gpo/cccccccccccccccccccccccccccccccc")
        assert resp.status_code == 200
        html = resp.text
        assert "<th>Identity</th>" in html
        assert "<th>Name</th>" in html
        assert "FakeValue" in html
        assert "Prohibit Fake Value" not in html

    def test_gpo_detail_admx_fallback_to_display_name(
        self, fixture_db: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app

        pd_dir = _make_admx_dir(tmp_path)
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(fixture_db, admx_dir=str(pd_dir))
        client = TestClient(
            app,
            headers={
                "origin": "http://localhost",
                "Authorization": "Bearer test-secret-token",
            },
        )
        resp = client.get("/gpo/dddddddddddddddddddddddddddddddd")
        assert resp.status_code == 200
        html = resp.text
        assert "BadValue" in html
        assert "HKLM\\Software\\Fake:BadValue" in html
        assert "Prohibit Fake Value" not in html

    def test_admx_parsed_once(
        self, fixture_db: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app

        pd_dir = _make_admx_dir(tmp_path)
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(fixture_db, admx_dir=str(pd_dir))
        client = TestClient(
            app,
            headers={
                "origin": "http://localhost",
                "Authorization": "Bearer test-secret-token",
            },
        )
        admx = app.state.admx
        assert admx is not None
        client.get("/gpo/cccccccccccccccccccccccccccccccc")
        client.get("/gpo/dddddddddddddddddddddddddddddddd")
        assert app.state.admx is admx


class TestServeAdmxFlag:
    def test_serve_admx_dir_flag_passes_to_create_app(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from unittest.mock import patch

        from gpo_lens.cli._serve import cmd_serve

        pd_dir = _make_admx_dir(tmp_path)
        monkeypatch.delenv("GPO_LENS_ADMX_DIR", raising=False)
        args = _serve_args(admx_dir=str(pd_dir))
        with patch("uvicorn.run") as mock_run, patch("gpo_lens.web.app.create_app") as mock_create:
            ret = cmd_serve(args)
        assert ret == 0
        mock_run.assert_called_once()
        mock_create.assert_called_once_with(args.db, root_path=args.root_path, admx_dir=str(pd_dir))


class TestResultantRoute:
    def test_get_returns_200(self, client) -> None:
        resp = client.get("/resultant")
        assert resp.status_code == 200
        assert "Principal Resultant" in resp.text

    def test_get_shows_form(self, client) -> None:
        resp = client.get("/resultant")
        assert resp.status_code == 200
        assert "principal_sid" in resp.text
        assert "Compute resultant" in resp.text

    def test_post_empty_sid_shows_error(self, client) -> None:
        resp = client.post("/resultant", data={"principal_sid": ""})
        assert resp.status_code == 200
        assert "A principal SID or name is required" in resp.text

    def test_post_whitespace_sid_shows_error(self, client) -> None:
        resp = client.post("/resultant", data={"principal_sid": "   "})
        assert resp.status_code == 200
        assert "A principal SID or name is required" in resp.text

    def test_post_valid_sid_returns_result(self, client) -> None:
        resp = client.post(
            "/resultant",
            data={
                "principal_sid": "S-1-5-21-100-200-300-1001",
            },
        )
        assert resp.status_code == 200
        assert "Resultant for" in resp.text

    def test_post_with_computer_sid(self, client) -> None:
        resp = client.post(
            "/resultant",
            data={
                "principal_sid": "S-1-5-21-100-200-300-1001",
                "computer_sid": "S-1-5-21-100-200-300-5001",
            },
        )
        assert resp.status_code == 200
        assert "Resultant for" in resp.text

    def test_post_with_dn(self, client) -> None:
        resp = client.post(
            "/resultant",
            data={
                "principal_sid": "S-1-5-21-100-200-300-1001",
                "dn": "cn=test,ou=users,dc=fakefixture,dc=local",
            },
        )
        assert resp.status_code == 200

    def test_post_shows_caveat_summary(self, client) -> None:
        resp = client.post(
            "/resultant",
            data={
                "principal_sid": "S-1-5-21-100-200-300-1001",
            },
        )
        assert resp.status_code == 200
        assert "resultant given collected inputs" in resp.text.lower()

    def test_post_viewer_gets_200(self, fixture_db: str) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app
        from gpo_lens.web.auth import Permission, Principal, get_principal

        viewer = Principal(
            name="viewer",
            role="viewer",
            permissions=frozenset([Permission.VIEW]),
        )
        app = create_app(fixture_db)
        app.dependency_overrides[get_principal] = lambda authorization=None: viewer
        try:
            c = TestClient(app, headers={"origin": "http://localhost"})
            resp = c.get("/resultant")
        finally:
            app.dependency_overrides.clear()
        assert resp.status_code == 200

    def test_post_viewer_can_compute(self, fixture_db: str) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app
        from gpo_lens.web.auth import Permission, Principal, get_principal

        viewer = Principal(
            name="viewer",
            role="viewer",
            permissions=frozenset([Permission.VIEW]),
        )
        app = create_app(fixture_db)
        app.dependency_overrides[get_principal] = lambda authorization=None: viewer
        try:
            c = TestClient(app, headers={"origin": "http://localhost"})
            resp = c.post(
                "/resultant",
                data={
                    "principal_sid": "S-1-5-21-100-200-300-1001",
                },
            )
        finally:
            app.dependency_overrides.clear()
        assert resp.status_code == 200
        assert "Resultant for" in resp.text

    def test_post_exception_shows_error(self, client) -> None:
        with patch(
            "gpo_lens.merge.principal_resultant",
            side_effect=ValueError("test explosion"),
        ):
            resp = client.post(
                "/resultant",
                data={
                    "principal_sid": "S-1-5-21-100-200-300-1001",
                },
            )
        assert resp.status_code == 200
        # L-3: exception details must not be disclosed to the client.
        assert "test explosion" not in resp.text
        assert "Computation failed" in resp.text


class TestInventory:
    """The Inventory tab lists every GPO and drills into detail."""

    def test_inventory_returns_200_and_lists_gpos(self, client) -> None:
        resp = client.get("/inventory")
        assert resp.status_code == 200
        assert "Inventory" in resp.text
        # drill-in links to GPO detail pages
        assert "/gpo/" in resp.text

    def test_inventory_search_filters(self, client) -> None:
        resp = client.get("/inventory?q=cpassword")
        assert resp.status_code == 200
        assert "gpo-cpassword" in resp.text

    def test_inventory_no_match_shows_empty_state(self, client) -> None:
        resp = client.get("/inventory?q=zzzznosuchgpo")
        assert resp.status_code == 200
        assert "No GPOs match" in resp.text

    def test_inventory_invalid_status_and_sort_are_safe(self, client) -> None:
        resp = client.get("/inventory?status=bogus&sort=bogus")
        assert resp.status_code == 200

    def test_explore_has_inventory_link(self, client) -> None:
        resp = client.get("/explore")
        assert ">Inventory<" in resp.text
        assert "/inventory" in resp.text


class TestConflicts:
    """The Conflicts page surfaces both lenses estate-wide."""

    def test_conflicts_page_200_with_tabs(self, client) -> None:
        resp = client.get("/conflicts")
        assert resp.status_code == 200
        assert "Conflicts" in resp.text
        assert "gp-tab" in resp.text  # resolved / defined tabs

    def test_defined_view_lists_inconsistent_setting(self, client) -> None:
        # The fixture defines loopback processing mode with differing values
        # across GPOs -> a definitional conflict.
        resp = client.get("/conflicts?view=defined")
        assert resp.status_code == 200
        assert "loopback processing mode" in resp.text

    def test_resolved_view_shows_winner(self, client) -> None:
        resp = client.get("/conflicts?view=resolved")
        assert resp.status_code == 200
        # winner column header + a resolved row
        assert "Winner" in resp.text
        assert "Scopes" in resp.text

    def test_view_switch_and_invalid_view_safe(self, client) -> None:
        assert client.get("/conflicts?view=resolved").status_code == 200
        # bogus view falls back, does not error
        assert client.get("/conflicts?view=bogus").status_code == 200

    def test_search_filters_and_empty_is_safe(self, client) -> None:
        resp = client.get("/conflicts?view=defined&q=loopback")
        assert resp.status_code == 200
        assert "loopback processing mode" in resp.text
        empty = client.get("/conflicts?view=defined&q=zzzznomatch")
        assert empty.status_code == 200
        assert "No conflicts match" in empty.text

    def test_nav_and_posture_card_link_to_conflicts(self, client) -> None:
        home = client.get("/").text
        assert ">Conflicts<" in client.get("/explore").text
        assert "/conflicts" in home  # retained dashboard posture card


class TestSnapshotDelete:
    """Removing an estate import from the web UI."""

    def _add_snapshot(self, db_path: str) -> int:
        import sqlite3
        from pathlib import Path

        from gpo_lens import ingest as _ing
        from gpo_lens import store as _st

        conn = sqlite3.connect(db_path)
        sid = _st.save_estate(conn, _ing.load_estate(Path("tests/fixtures")))
        conn.commit()
        conn.close()
        return sid

    def test_ingest_page_shows_delete_and_current(self, client) -> None:
        resp = client.get("/ingest")
        assert resp.status_code == 200
        assert "Delete" in resp.text
        assert "current" in resp.text  # newest snapshot marked

    def test_delete_removes_snapshot_and_cascades(self, client, fixture_db: str) -> None:
        import sqlite3

        from gpo_lens import store as _st

        extra = self._add_snapshot(fixture_db)  # newest; fixture itself is older
        resp = client.post("/ingest/delete", data={"snapshot_id": extra}, follow_redirects=False)
        assert resp.status_code == 303
        conn = sqlite3.connect(fixture_db)
        try:
            ids = [s[0] for s in _st.list_snapshots(conn)]
            assert extra not in ids
            orphans = conn.execute(
                "SELECT COUNT(*) FROM setting WHERE snapshot_id=?", (extra,)
            ).fetchone()[0]
            assert orphans == 0
        finally:
            conn.close()

    def test_delete_missing_snapshot_404(self, client) -> None:
        resp = client.post("/ingest/delete", data={"snapshot_id": 999999})
        assert resp.status_code == 404
        assert "not found" in resp.text.lower()

    def test_delete_requires_same_origin(self, client) -> None:
        resp = client.post(
            "/ingest/delete",
            data={"snapshot_id": 1},
            headers={"origin": "http://evil.example"},
        )
        assert resp.status_code == 403

    def test_delete_all_returns_to_empty_estate(self, client, fixture_db: str) -> None:
        import sqlite3

        from gpo_lens import store as _st

        conn = sqlite3.connect(fixture_db)
        ids = [s[0] for s in _st.list_snapshots(conn)]
        conn.close()
        for sid in ids:
            client.post("/ingest/delete", data={"snapshot_id": sid})
        # dashboard still renders (empty estate), does not 500
        assert client.get("/").status_code == 200
        assert client.get("/ingest").status_code == 200

    def test_delete_returns_409_when_lock_held(self, client) -> None:
        """ingest_delete must acquire the ingest lock — returns 409 if held."""
        # Acquire the lock from the app state (simulating a concurrent ingest)
        app = client.app
        lock = app.state.ingest_lock
        assert lock.acquire(blocking=False)
        try:
            resp = client.post("/ingest/delete", data={"snapshot_id": 1})
            assert resp.status_code == 409
            assert "in progress" in resp.text.lower()
        finally:
            lock.release()
