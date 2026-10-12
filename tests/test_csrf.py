"""Comprehensive direct tests for the CSRF origin/referer validation middleware.

WI-005: The CSRF middleware was hardened but lacked dedicated test coverage.
This file documents and verifies the exact behavior of the middleware.

CSRF Middleware Logic (app.py::_csrf_check):
  Only POST requests are checked. For POSTs, a request is same-origin
  (and allowed) if Origin — or Referer when Origin is absent — is:
    - loopback (direct browser access to uvicorn), OR
    - same-host as the request's own Host header (reverse-proxy / IIS
      deployment, where the browser's Origin carries the proxy hostname).
  Otherwise the POST is blocked with 403:
    - Origin present, neither loopback nor same-host      → 403
    - No Origin, Referer neither loopback nor same-host   → 403
    - No Origin AND no Referer                             → 403

  loopback host = ("localhost", "127.0.0.1", "::1",
                   "localhost.localdomain")
  same-host = Origin/Referer netloc (host:port) == request Host header

  NOTE: 0.0.0.0 is intentionally NOT allow-listed — it is the bind-any
  wildcard, not a legitimate client Origin. A cross-origin POST can spoof
  Origin: http://0.0.0.0, so allowing it would defeat the CSRF guard.

Threat model: gpo-lens binds loopback and runs behind a same-host
TLS-terminating reverse proxy (IIS/HttpPlatformHandler, often via SNI on
:443). The browser's Origin therefore carries the proxy hostname (e.g.
https://gpo-lens.example.com), not loopback, so a loopback-only allowlist
would reject every legitimate POST. Same-host validation accepts those
while still blocking cross-host CSRF: an attacker cannot make the victim's
browser send an Origin whose host matches the target's Host header. The
"no Origin, no Referer" rejection means API-style tools (curl, etc.) must
send an Origin or Referer header.

NOTE: The earlier reflection (2026-06-12-mimo-v2.5-pro.md) stated
"POST requests with no Origin AND no Referer pass through" — this
described an earlier version. The current code rejects such requests.
"""

from __future__ import annotations

import sqlite3

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from gpo_lens.store import init_db
from gpo_lens.web.app import create_app
from gpo_lens.web.auth import Permission, Principal, get_principal


@pytest.fixture()
def csrf_db(tmp_path):
    """Create a temporary database for CSRF testing."""
    db = tmp_path / "csrf_test.db"
    conn = sqlite3.connect(str(db))
    init_db(conn)
    conn.close()
    return str(db)


@pytest.fixture()
def csrf_client(csrf_db: str):
    """TestClient with admin principal override and NO default headers.

    By default, TestClient sends no Origin or Referer, which lets
    each test control the exact headers sent.
    """
    admin = Principal(
        name="csrf-test-admin",
        role="admin",
        permissions=frozenset([Permission.VIEW, Permission.INGEST, Permission.NARRATE]),
    )
    app = create_app(csrf_db)
    app.dependency_overrides[get_principal] = lambda authorization=None: admin
    yield TestClient(app)
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 1. GET requests are not CSRF-checked
# ---------------------------------------------------------------------------


class TestCsrfGetRequests:
    """GET requests bypass CSRF checks entirely — they are safe (no side effects)."""

    def test_get_home_no_origin(self, csrf_client) -> None:
        resp = csrf_client.get("/")
        assert resp.status_code == 200

    def test_get_home_external_origin(self, csrf_client) -> None:
        """Even a suspicious external Origin doesn't block GETs."""
        resp = csrf_client.get("/", headers={"origin": "https://evil.com"})
        assert resp.status_code == 200

    def test_get_home_no_referer(self, csrf_client) -> None:
        resp = csrf_client.get("/")
        assert resp.status_code == 200

    def test_get_ask_page(self, csrf_client) -> None:
        resp = csrf_client.get("/ask")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 2. POST with matching (localhost) Origin passes
# ---------------------------------------------------------------------------


class TestCsrfMatchingOrigin:
    """POST requests with a localhost Origin header are allowed."""

    @pytest.mark.parametrize(
        "origin",
        [
            "http://localhost",
            "http://localhost:8000",
            "http://127.0.0.1",
            "http://127.0.0.1:8080",
            "http://[::1]",
            "http://[::1]:8000",
            "http://localhost.localdomain",
        ],
    )
    def test_post_with_localhost_origin_passes(self, csrf_client, origin: str) -> None:
        resp = csrf_client.post("/ingest", headers={"origin": origin})
        assert resp.status_code != 403

    def test_post_with_localhost_origin_ignores_evil_referer(self, csrf_client) -> None:
        """When Origin is localhost, Referer is not checked."""
        resp = csrf_client.post(
            "/ingest",
            headers={
                "origin": "http://localhost",
                "referer": "https://evil.com/attack",
            },
        )
        assert resp.status_code != 403


# ---------------------------------------------------------------------------
# 3. POST with mismatched (external) Origin is rejected
# ---------------------------------------------------------------------------


class TestCsrfMismatchedOrigin:
    """POST requests with a non-localhost Origin are blocked (403)."""

    @pytest.mark.parametrize(
        "origin",
        [
            "https://evil.com",
            "http://evil.com",
            "https://attacker.example.com",
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://localhost.evil.com",  # hostname is NOT "localhost"
            "http://0.0.0.0",  # bind-any wildcard — spoofable, not allow-listed
            "http://0.0.0.0:8000",
        ],
    )
    def test_post_with_external_origin_rejected(self, csrf_client, origin: str) -> None:
        resp = csrf_client.post("/ingest", headers={"origin": origin})
        assert resp.status_code == 403
        assert "CSRF" in resp.json()["detail"]

    def test_spoofed_external_origin_to_localhost_server(self, csrf_client) -> None:
        """An attacker sends a cross-origin POST with their own Origin.

        This is the core CSRF attack: the attacker's site triggers a POST
        to the localhost-bound gpo-lens server. The browser sends the
        attacker's Origin, which is not localhost, so it's rejected.
        """
        resp = csrf_client.post(
            "/ingest",
            headers={
                "origin": "https://attacker.com",
                "referer": "https://attacker.com/evil-page",
            },
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 4. POST with matching (localhost) Referer and no Origin passes
# ---------------------------------------------------------------------------


class TestCsrfMatchingReferer:
    """When no Origin header is present, Referer is checked as fallback."""

    @pytest.mark.parametrize(
        "referer",
        [
            "http://localhost:8000/ask",
            "http://localhost/ingest",
            "http://127.0.0.1:8000/ask",
            "http://[::1]:8000/ask",
            "http://localhost.localdomain:8000/ask",
        ],
    )
    def test_post_with_localhost_referer_no_origin_passes(self, csrf_client, referer: str) -> None:
        resp = csrf_client.post("/ingest", headers={"referer": referer})
        assert resp.status_code != 403


# ---------------------------------------------------------------------------
# 5. POST with mismatched (external) Referer and no Origin is rejected
# ---------------------------------------------------------------------------


class TestCsrfMismatchedReferer:
    """When no Origin is present and Referer is non-localhost, blocked."""

    @pytest.mark.parametrize(
        "referer",
        [
            "https://evil.com/page",
            "http://evil.com/attack",
            "https://attacker.example.com/csrf",
            "http://localhost.evil.com/page",  # hostname is NOT "localhost"
        ],
    )
    def test_post_with_external_referer_no_origin_rejected(self, csrf_client, referer: str) -> None:
        resp = csrf_client.post("/ingest", headers={"referer": referer})
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 6. POST with neither Origin nor Referer is rejected
# ---------------------------------------------------------------------------


class TestCsrfNoOriginNoReferer:
    """POST requests with neither Origin nor Referer are rejected.

    Current behavior: 403 CSRF validation failed.

    Rationale: In normal browser usage, same-origin POSTs always send
    either Origin or Referer. Absence of both suggests a non-browser
    client or a stripped-header redirect — either way, rejecting is
    the safe default.

    Threat model note: For loopback-only deployment, this is acceptable
    because legitimate browser requests will always include one of these
    headers. API-style tools (curl, scripts) must add an Origin or
    Referer header explicitly.

    If a future use case requires headerless POSTs, consider adding
    a CSRF token mechanism instead of relaxing this check.
    """

    def test_post_with_no_origin_no_referer_returns_403(self, csrf_client) -> None:
        resp = csrf_client.post("/ingest")
        assert resp.status_code == 403

    def test_csrf_blocks_ingest_without_headers(self, csrf_client) -> None:
        resp = csrf_client.post("/ingest")
        assert resp.status_code == 403

    def test_csrf_blocks_ask_without_headers(self, csrf_client) -> None:
        resp = csrf_client.post("/ask", data={"question": "test"})
        assert resp.status_code == 403

    def test_csrf_blocks_baseline_without_headers(self, csrf_client) -> None:
        resp = csrf_client.post("/baseline")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 7. POST with spoofed external Origin to localhost-bound server is rejected
# ---------------------------------------------------------------------------


class TestCsrfSpoofedExternalOrigin:
    """Cross-origin POST from an attacker's site to the localhost server.

    This is the primary CSRF threat: the victim's browser sends a POST
    to gpo-lens (bound to localhost) from a malicious page. The browser
    automatically includes the attacker's Origin header, which the
    middleware correctly rejects.
    """

    def test_cross_origin_ingest_blocked(self, csrf_client) -> None:
        """Attacker tries to trigger a GPO ingest via CSRF."""
        resp = csrf_client.post(
            "/ingest",
            headers={"origin": "https://evil.com"},
        )
        assert resp.status_code == 403

    def test_cross_origin_ask_blocked(self, csrf_client) -> None:
        """Attacker tries to submit a question via CSRF."""
        resp = csrf_client.post(
            "/ask",
            headers={"origin": "https://evil.com"},
            data={"question": "exfiltrate data"},
        )
        assert resp.status_code == 403

    def test_cross_origin_baseline_blocked(self, csrf_client) -> None:
        """Attacker tries to upload a malicious baseline via CSRF."""
        resp = csrf_client.post(
            "/baseline",
            headers={"origin": "https://evil.com"},
        )
        assert resp.status_code == 403

    def test_cross_origin_ingest_post_blocked(self, csrf_client) -> None:
        resp = csrf_client.post(
            "/ingest",
            headers={"origin": "https://evil.com"},
        )
        assert resp.status_code == 403

    def test_form_submit_from_attacker_site_blocked(self, csrf_client) -> None:
        """Simulates a form submit from attacker's site.

        The browser sends Referer (not Origin in some older cases).
        """
        resp = csrf_client.post(
            "/ingest",
            headers={"referer": "https://evil.com/attack-form"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 8. POST via reverse proxy (IIS + SNI) — same-host Origin
# ---------------------------------------------------------------------------


def _proxy_client(db_path: str, base_url: str) -> TestClient:
    """Authenticated TestClient whose Host header is driven by *base_url*.

    Mirrors a real browser at *base_url* (e.g. an IIS + SNI site on
    https://gpo-lens.example.com/). TestClient uses an in-process ASGI
    transport, so the https scheme never opens a socket — the scheme only
    sets the Host header the way a proxied browser request would.
    """
    admin = Principal(
        name="csrf-test-admin",
        role="admin",
        permissions=frozenset([Permission.VIEW, Permission.INGEST, Permission.NARRATE]),
    )
    app = create_app(db_path)
    app.dependency_overrides[get_principal] = lambda authorization=None: admin
    return TestClient(app, base_url=base_url)


class TestCsrfSameHostOrigin:
    """Same-origin POSTs through a TLS-terminating reverse proxy (IIS + SNI).

    The browser browses https://gpo-lens.example.com/ (IIS terminates TLS,
    HttpPlatformHandler proxies to loopback uvicorn). Its Origin carries the
    proxy hostname, not loopback, so a loopback-only allowlist would reject
    these. The guard must accept an Origin whose host:port matches the
    request's own Host header.
    """

    # Not named ``base_url``: pytest-base-url (a pytest-playwright dependency)
    # owns that fixture name and its autouse check would collide.
    @pytest.mark.parametrize(
        ("proxy_url", "origin"),
        [
            # IIS + SNI on :443 (default port omitted by browser on both sides).
            ("https://gpo-lens.example.com", "https://gpo-lens.example.com"),
            # IIS on a dedicated port (non-default port carried on both sides).
            ("https://gpo-lens.example.com:8443", "https://gpo-lens.example.com:8443"),
        ],
    )
    def test_same_host_origin_passes(self, csrf_db, proxy_url, origin) -> None:
        client = _proxy_client(csrf_db, proxy_url)
        resp = client.post("/ingest", headers={"origin": origin})
        assert resp.status_code != 403

    def test_same_host_referer_no_origin_passes(self, csrf_db) -> None:
        client = _proxy_client(csrf_db, "https://gpo-lens.example.com")
        resp = client.post(
            "/ingest",
            headers={"referer": "https://gpo-lens.example.com/ingest"},
        )
        assert resp.status_code != 403

    def test_mismatched_host_origin_rejected(self, csrf_db) -> None:
        # Origin host != Host header (gpo-lens.example.com) -> CSRF blocked.
        client = _proxy_client(csrf_db, "https://gpo-lens.example.com")
        resp = client.post("/ingest", headers={"origin": "https://evil.example.com"})
        assert resp.status_code == 403
        assert "CSRF" in resp.json()["detail"]

    def test_mismatched_host_referer_rejected(self, csrf_db) -> None:
        client = _proxy_client(csrf_db, "https://gpo-lens.example.com")
        resp = client.post(
            "/ingest",
            headers={"referer": "https://evil.example.com/attack"},
        )
        assert resp.status_code == 403


class TestCsrfSameHostEdgeCases:
    """Edge cases for the same-host check (default ports, casing, suffixes).

    These lock in the normalization and guard against the empty-netloc bypass
    surfaced by adversarial review.
    """

    def test_explicit_default_port_matches_bare_host(self, csrf_db) -> None:
        # Origin carries :443 explicitly; Host (from base_url) omits it.
        # Default-port stripping must make these match (curl/scripts send this).
        client = _proxy_client(csrf_db, "https://gpo-lens.example.com")
        resp = client.post("/ingest", headers={"origin": "https://gpo-lens.example.com:443"})
        assert resp.status_code != 403

    def test_case_insensitive_host_matches(self, csrf_db) -> None:
        # Origin uppercased; Host lowercased by the browser/proxy.
        client = _proxy_client(csrf_db, "https://gpo-lens.example.com")
        resp = client.post("/ingest", headers={"origin": "https://GPO-LENS.EXAMPLE.COM"})
        assert resp.status_code != 403

    def test_subdomain_suffix_rejected(self, csrf_db) -> None:
        # A name ending in the real host is NOT the real host.
        client = _proxy_client(csrf_db, "https://gpo-lens.example.com")
        resp = client.post(
            "/ingest",
            headers={"origin": "https://gpo-lens.example.com.evil.com"},
        )
        assert resp.status_code == 403

    def test_null_origin_rejected(self, csrf_db) -> None:
        # Browsers send "Origin: null" from sandboxed iframes / data: URIs.
        client = _proxy_client(csrf_db, "https://gpo-lens.example.com")
        resp = client.post("/ingest", headers={"origin": "null"})
        assert resp.status_code == 403

    def test_empty_netloc_origin_rejected(self, csrf_db) -> None:
        # Origin with no host ("https://") must never match, even when the
        # request carries a valid Host — guards the empty==empty bypass.
        client = _proxy_client(csrf_db, "https://gpo-lens.example.com")
        resp = client.post("/ingest", headers={"origin": "https://"})
        assert resp.status_code == 403


class TestCsrfStateChangingMethods:
    @pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
    def test_state_changing_method_without_origin_blocked(self, csrf_client, method: str) -> None:
        resp = csrf_client.request(method, "/ingest", headers={"origin": "https://evil.com"})
        assert resp.status_code == 403
        assert "CSRF" in resp.json()["detail"]

    @pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
    def test_state_changing_method_no_headers_blocked(self, csrf_client, method: str) -> None:
        resp = csrf_client.request(method, "/ingest")
        assert resp.status_code == 403
        assert "CSRF" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# L-1: _is_localhost_origin rejects non-http(s) schemes
# ---------------------------------------------------------------------------


class TestNonHttpSchemeOriginRejected:
    """An Origin with a non-http(s) scheme (ftp, data, javascript) must be
    rejected even if the hostname is localhost — such schemes cannot originate
    from a legitimate browser navigation."""

    @pytest.mark.parametrize(
        "origin",
        [
            "ftp://localhost",
            "data:text/html,<script>1</script>",
            "javascript:alert(1)",
            "file:///etc/passwd",
        ],
    )
    def test_non_http_scheme_origin_rejected(self, csrf_client, origin: str) -> None:
        resp = csrf_client.post("/ingest", headers={"origin": origin})
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# L-5: Body size limit on form-only POST routes
# ---------------------------------------------------------------------------


class TestBodySizeLimit:
    """POST bodies >10MB on non-upload routes are rejected with 413.
    Upload routes (/ingest, /baseline, /golden-diff) are excluded."""

    def test_form_post_over_10mb_returns_413(self, csrf_client) -> None:
        """An 11MB POST to a form-only route is rejected."""
        # /resultant is a form-only POST route (not an upload route)
        big_body = "x" * (11 * 1024 * 1024)
        resp = csrf_client.post(
            "/resultant",
            data={"principal_sid": "S-1-1-0", "padding": big_body},
            headers={"origin": "http://localhost"},
        )
        assert resp.status_code == 413

    def test_upload_route_over_10mb_not_rejected(self, csrf_client) -> None:
        """An 11MB POST to /ingest (upload route) is NOT rejected by the
        body-size middleware — it has its own 500MB limit."""
        # 11MB upload to /ingest — should pass the body-size gate
        data = b"\0" * (11 * 1024 * 1024)
        resp = csrf_client.post(
            "/ingest",
            files={"file": ("test.zip", data, "application/zip")},
            headers={"origin": "http://localhost"},
        )
        # The upload will fail (not a valid zip), but should NOT be a 413
        # from the body-size middleware. It should be 400 (malformed zip).
        assert resp.status_code != 413
