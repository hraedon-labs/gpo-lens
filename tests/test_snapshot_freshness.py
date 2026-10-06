"""Freshness describes the newest import, even when viewing history."""

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from gpo_lens.briefing import briefing_lines, build_briefing
from gpo_lens.model import Estate
from gpo_lens.store import init_db, save_estate
from gpo_lens.web.app import create_app

NOW = datetime(2026, 10, 6, 12, tzinfo=UTC)


@pytest.mark.parametrize(
    "age,stale",
    [(timedelta(days=8), False), (timedelta(days=8, seconds=1), True), (timedelta(days=9), True)],
)
def test_default_threshold_exact_boundary(age, stale):
    with sqlite3.connect(":memory:") as conn:
        init_db(conn)
        save_estate(conn, Estate(domain="lab.example.com"), taken_at=NOW - age)
        briefing = build_briefing(conn, now=NOW)
        assert briefing.freshness.age_seconds == int(age.total_seconds())
        assert briefing.freshness.is_stale is stale
        assert any("Collection may have stopped" in p for p in briefing.problems) is stale
        assert any("Newest snapshot" in line for line in briefing_lines(briefing))


def test_historical_selection_uses_newest_snapshot_age():
    with sqlite3.connect(":memory:") as conn:
        init_db(conn)
        old = save_estate(conn, Estate(domain="lab.example.com"), taken_at=NOW - timedelta(days=30))
        newest = save_estate(
            conn, Estate(domain="lab.example.com"), taken_at=NOW - timedelta(days=1)
        )
        briefing = build_briefing(conn, as_of_snapshot=old, now=NOW)
        assert briefing.snapshot_id == old
        assert briefing.freshness.snapshot_id == newest
        assert briefing.freshness.age_seconds == 86400
        assert not briefing.freshness.is_stale


@pytest.mark.parametrize(
    "timestamp", ["unparseable", "2026-10-05T12:00:00", (NOW + timedelta(days=1)).isoformat()]
)
def test_unreliable_timestamp_warns(timestamp):
    with sqlite3.connect(":memory:") as conn:
        init_db(conn)
        save_estate(conn, Estate(domain="lab.example.com"), taken_at=NOW)
        conn.execute("UPDATE snapshot SET taken_at=?", (timestamp,))
        briefing = build_briefing(conn, now=NOW)
        assert briefing.freshness.age_seconds is None
        assert any("freshness cannot be verified" in p for p in briefing.problems)


def test_web_threshold_and_deterministic_exports(tmp_path, monkeypatch):
    db = tmp_path / "estate.db"
    with sqlite3.connect(db) as conn:
        init_db(conn)
        save_estate(conn, Estate(domain="lab.example.com"), taken_at=NOW - timedelta(days=3))
    monkeypatch.setenv("GPO_LENS_STALE_SNAPSHOT_DAYS", "2")
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "synthetic-test-token")
    with TestClient(
        create_app(str(db)), headers={"Authorization": "Bearer synthetic-test-token"}
    ) as client:
        query = {"as_of": NOW.isoformat()}
        page = client.get("/briefing", params=query)
        assert page.status_code == 200
        assert "Collection may have stopped" in page.text
        assert "Newest snapshot #1 is 3 days old" in page.text
        for format in ("csv", "md"):
            query["format"] = format
            first = client.get("/briefing", params=query)
            second = client.get("/briefing", params=query)
            assert first.status_code == 200
            assert first.content == second.content
            assert "Collection may have stopped" in first.text


@pytest.mark.parametrize("value", ["0", "-2", "invalid", "nan"])
def test_invalid_web_threshold_falls_back_to_eight(tmp_path, monkeypatch, value):
    monkeypatch.setenv("GPO_LENS_STALE_SNAPSHOT_DAYS", value)
    app = create_app(str(tmp_path / "estate.db"))
    assert app.state.stale_snapshot_days == 8


def test_briefing_export_clock_is_pinned_in_url_and_metadata(tmp_path, monkeypatch):
    import re
    from html import unescape
    from urllib.parse import parse_qs, urlparse

    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "synthetic-test-token")
    db = tmp_path / "estate.db"
    with sqlite3.connect(db) as conn:
        init_db(conn)
        save_estate(conn, Estate(domain="lab.example.com"), taken_at=NOW)
    with TestClient(
        create_app(str(db)), headers={"Authorization": "Bearer synthetic-test-token"}
    ) as client:
        redirect = client.get("/briefing?format=csv", follow_redirects=False)
        assert redirect.status_code == 307
        pinned = redirect.headers["location"]
        timestamp = parse_qs(urlparse(pinned).query)["as_of"][0]
        assert datetime.fromisoformat(timestamp).utcoffset() is not None
        assert timestamp in client.get(pinned).text
        assert client.get(pinned).content == client.get(pinned).content
        page = client.get("/briefing", params={"as_of": NOW.isoformat()})
        hrefs = re.findall(r'href="([^"]+)"', page.text)
        downloads = [
            parse_qs(urlparse(unescape(href)).query) for href in hrefs if "format=" in href
        ]
        assert len(downloads) == 2
        assert all(query["as_of"] == [NOW.isoformat()] for query in downloads)
