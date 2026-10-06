"""Authority validation precedes every trust, mutation and URL path."""

from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from gpo_lens.web.app import create_app


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/v1/query"),
        ("GET", "/gpo/lab"),
        ("GET", "/briefing"),
        ("POST", "/findings/1/triage"),
        ("POST", "/ingest"),
        ("POST", "/ingest/delete"),
        ("POST", "/explain"),
        ("GET", "/tools/"),
    ],
)
def test_rebinding_rejected_before_auth_csrf_and_redirects(tmp_path, monkeypatch, method, path):
    monkeypatch.delenv("GPO_LENS_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
    client = TestClient(
        create_app(str(tmp_path / "lab.sqlite3")),
        base_url="http://rebind.attacker.invalid",
        client=("127.0.0.1", 50000),
    )
    response = client.request(
        method,
        path,
        headers={
            "Origin": "http://rebind.attacker.invalid",
            "Content-Length": str(20 * 1024 * 1024),
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "GPO_LENS_ALLOWED_HOSTS" in response.text
    assert "location" not in response.headers


@pytest.mark.parametrize(
    "host", ["localhost", "LOCALHOST:8443", "127.0.0.1:9999", "[::1]", "[::1]:8080"]
)
def test_unset_allows_only_loopback_authorities(tmp_path, monkeypatch, host):
    monkeypatch.delenv("GPO_LENS_ALLOWED_HOSTS", raising=False)
    client = TestClient(create_app(str(tmp_path / "lab.sqlite3")), client=("127.0.0.1", 50000))
    assert client.get("/api/version", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize(
    "host",
    [
        "",
        "0.0.0.0",
        "localhost.localdomain",
        "localhost.attacker.invalid",
        "localhost@attacker.invalid",
        "localhost,attacker.invalid",
        "localhost:bad",
        "localhost:99999",
        "::1",
        "localhost.",
        " localhost",
        "localhost/path",
    ],
)
def test_invalid_and_nonloopback_host_rejected(tmp_path, monkeypatch, host):
    monkeypatch.delenv("GPO_LENS_ALLOWED_HOSTS", raising=False)
    client = TestClient(create_app(str(tmp_path / "lab.sqlite3")))
    assert client.get("/api/version", headers={"Host": host}).status_code == 400


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("lab.example.com", 200),
        ("LAB.EXAMPLE.COM:8443", 200),
        ("lens.lab.example.com:8443", 200),
        ("lens.lab.example.com:8444", 400),
        ("[2001:db8::1]:8443", 200),
        ("[::ffff:192.0.2.1]:8443", 200),
        ("[::ffff:c000:201]:8443", 200),
        ("localhost", 400),
        ("lab.example.com.attacker.invalid", 400),
    ],
)
def test_configured_authorities(tmp_path, monkeypatch, host, expected):
    monkeypatch.setenv(
        "GPO_LENS_ALLOWED_HOSTS",
        " lab.example.com , lens.lab.example.com:8443, [2001:db8::1]:8443, "
        "[::ffff:192.0.2.1]:8443 ",
    )
    client = TestClient(create_app(str(tmp_path / "lab.sqlite3")))
    assert client.get("/api/version", headers={"Host": host}).status_code == expected


def test_duplicate_host_headers_are_rejected(tmp_path, monkeypatch):
    monkeypatch.delenv("GPO_LENS_ALLOWED_HOSTS", raising=False)
    client = TestClient(create_app(str(tmp_path / "lab.sqlite3")))
    assert (
        client.get(
            "/api/version", headers=[("Host", "localhost"), ("Host", "attacker.invalid")]
        ).status_code
        == 400
    )


def test_host_validation_precedes_authentication(tmp_path, monkeypatch):
    monkeypatch.delenv("GPO_LENS_ALLOWED_HOSTS", raising=False)
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "synthetic-token")
    client = TestClient(create_app(str(tmp_path / "lab.sqlite3")))
    assert client.get("/briefing", headers={"Host": "rebind.attacker.invalid"}).status_code == 400
    assert client.get("/briefing", headers={"Host": "localhost"}).status_code == 401


def test_validated_authority_drives_redirects(tmp_path, monkeypatch):
    monkeypatch.setenv("GPO_LENS_ALLOWED_HOSTS", "lab.example.com:8443")
    client = TestClient(
        create_app(str(tmp_path / "lab.sqlite3")), base_url="https://lab.example.com:8443"
    )
    response = client.get("/tools/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "https://lab.example.com:8443/tools"


def test_rebinding_cannot_read_or_delete_populated_snapshot(tmp_path, monkeypatch):
    import sqlite3
    from pathlib import Path

    from gpo_lens.ingest import load_estate
    from gpo_lens.store import init_db, save_estate

    monkeypatch.delenv("GPO_LENS_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
    db = tmp_path / "lab.sqlite3"
    estate = load_estate(Path(__file__).parent / "fixtures")
    with closing(sqlite3.connect(db)) as conn, conn:
        init_db(conn)
        sid = save_estate(conn, estate)
    client = TestClient(
        create_app(str(db)), base_url="http://rebind.attacker.invalid", client=("127.0.0.1", 50000)
    )
    response = client.get("/gpo/" + estate.gpos[0].id)
    assert response.status_code == 400
    assert estate.gpos[0].name not in response.text
    response = client.post(
        "/ingest/delete",
        data={"snapshot_id": sid},
        headers={"Origin": "http://rebind.attacker.invalid"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    with closing(sqlite3.connect(db)) as conn, conn:
        assert conn.execute("SELECT count(*) FROM snapshot").fetchone()[0] == 1


def test_configured_proxy_preserves_existing_anonymous_loopback_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("GPO_LENS_ALLOWED_HOSTS", "lab.example.com")
    monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
    client = TestClient(
        create_app(str(tmp_path / "lab.sqlite3")),
        base_url="https://lab.example.com:8443",
        client=("127.0.0.1", 50000),
    )
    assert client.get("/briefing").status_code == 200
    # Existing anonymous IIS trust still passes auth and CSRF; the missing
    # upload is rejected by form validation, as before the Host boundary.
    response = client.post("/ingest", headers={"Origin": "https://lab.example.com:8443"})
    assert response.status_code == 422
