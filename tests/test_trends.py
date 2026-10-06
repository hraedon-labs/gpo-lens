"""Tests for posture-over-time trend analysis (WI-056)."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import warnings
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gpo_lens.trend import changes_only, compute_trend, sparkline

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

# A dangerous registry setting (WDigest plaintext credential caching) used
# to create a second snapshot with different posture metrics.
_WDIGEST_ID = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseLogonCredential"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_db_with_snapshots(n: int = 3) -> str:
    """Create a temp DB with *n* snapshots of the fixture estate.

    Snapshot 2 adds a WDigest dangerous setting (danger count increases);
    snapshot 3 removes it (danger count returns to baseline).  Only 3
    snapshots are meaningfully different; extra copies are identical.
    """
    from gpo_lens.ingest import load_estate as ingest_load_estate
    from gpo_lens.model import Setting
    from gpo_lens.store import init_db, save_estate

    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
        path = f.name
    conn = sqlite3.connect(path)
    try:
        init_db(conn)
        estate = ingest_load_estate(FIXTURE_DIR)

        # Snapshot 1 — base estate.
        save_estate(conn, estate, taken_at=datetime(2025, 1, 1, tzinfo=UTC))

        if n >= 2:
            # Snapshot 2 — add a dangerous WDigest setting.
            gpo = estate.gpos[0]
            gpo.settings.append(
                Setting(
                    gpo_id=gpo.id,
                    side="Computer",
                    cse="Registry",
                    identity=_WDIGEST_ID,
                    display_name="UseLogonCredential",
                    display_value="1",
                    raw={},
                    from_disabled_side=False,
                )
            )
            save_estate(conn, estate, taken_at=datetime(2025, 1, 2, tzinfo=UTC))

        if n >= 3:
            # Snapshot 3 — remove the dangerous setting (back to baseline).
            gpo.settings.pop()
            save_estate(conn, estate, taken_at=datetime(2025, 1, 3, tzinfo=UTC))

        # Extra identical snapshots if requested.
        for i in range(4, n + 1):
            save_estate(
                conn,
                estate,
                taken_at=datetime(2025, 1, i, tzinfo=UTC),
            )
    finally:
        conn.close()
    return path


# ---------------------------------------------------------------------------
# Core: compute_trend
# ---------------------------------------------------------------------------


class TestComputeTrend:
    def test_returns_correct_number_of_points(self) -> None:
        path = _make_db_with_snapshots(3)
        try:
            conn = sqlite3.connect(path)
            try:
                points = compute_trend(conn)
            finally:
                conn.close()
            assert len(points) == 3
        finally:
            os.unlink(path)

    def test_ordered_oldest_first(self) -> None:
        path = _make_db_with_snapshots(3)
        try:
            conn = sqlite3.connect(path)
            try:
                points = compute_trend(conn)
            finally:
                conn.close()
            ids = [p.snapshot_id for p in points]
            assert ids == sorted(ids)
            # Dates should also be ascending.
            dates = [p.taken_at for p in points]
            assert dates == sorted(dates)
        finally:
            os.unlink(path)

    def test_metrics_match_estate_summary(self) -> None:
        from gpo_lens.queries import estate_summary
        from gpo_lens.store import load_estate

        path = _make_db_with_snapshots(3)
        try:
            conn = sqlite3.connect(path)
            try:
                points = compute_trend(conn)
                # Recompute estate_summary for each snapshot and compare.
                for p in points:
                    estate = load_estate(conn, p.snapshot_id)
                    summary = estate_summary(estate)
                    assert p.gpo_count == summary.gpo_count
                    assert p.danger_finding_count == summary.danger_finding_count
                    assert p.cpassword_hit_count == summary.cpassword_hit_count
                    assert p.ms16_072_vulnerable_count == summary.ms16_072_vulnerable_count
                    assert p.version_skew_count == summary.version_skew_count
                    assert p.broken_ref_count == summary.broken_ref_count
                    assert p.unlinked_count == summary.unlinked_count
                    assert p.empty_count == summary.empty_count
                    assert p.total_settings == summary.total_settings
                    assert p.coverage_gap_count == summary.coverage_gap_count
            finally:
                conn.close()
        finally:
            os.unlink(path)

    def test_danger_count_changes_between_snapshots(self) -> None:
        path = _make_db_with_snapshots(3)
        try:
            conn = sqlite3.connect(path)
            try:
                points = compute_trend(conn)
            finally:
                conn.close()
            # Snapshot 2 has the WDigest setting -> danger count should be higher.
            assert points[1].danger_finding_count > points[0].danger_finding_count
            # Snapshot 3 removed it -> back to baseline.
            assert points[2].danger_finding_count == points[0].danger_finding_count
        finally:
            os.unlink(path)

    def test_empty_db_returns_empty_list(self) -> None:
        from gpo_lens.store import init_db

        with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
            path = f.name
        try:
            conn = sqlite3.connect(path)
            try:
                init_db(conn)
                assert compute_trend(conn) == []
            finally:
                conn.close()
        finally:
            os.unlink(path)

    def test_skips_failed_load(self, monkeypatch) -> None:
        path = _make_db_with_snapshots(3)
        try:
            conn = sqlite3.connect(path)
            try:
                # Patch load_estate to raise for snapshot 2.
                import gpo_lens.trend as trend_mod

                original_load = trend_mod.load_estate

                def patched_load(c, snapshot_id=None):
                    if snapshot_id == 2:
                        raise ValueError("Simulated corruption")
                    return original_load(c, snapshot_id)

                monkeypatch.setattr(trend_mod, "load_estate", patched_load)
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    points = compute_trend(conn)
                assert len(points) == 2
                ids = [p.snapshot_id for p in points]
                assert 2 not in ids
                # A warning should have been issued.
                assert any("Skipping snapshot 2" in str(w.message) for w in caught)
            finally:
                conn.close()
        finally:
            os.unlink(path)

    def test_trendpoint_is_frozen(self) -> None:
        path = _make_db_with_snapshots(1)
        try:
            conn = sqlite3.connect(path)
            try:
                points = compute_trend(conn)
            finally:
                conn.close()
            p = points[0]
            with pytest.raises((AttributeError, Exception)):
                p.gpo_count = 999  # type: ignore[misc]
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# changes_only
# ---------------------------------------------------------------------------


class TestChangesOnly:
    def test_first_point_always_included(self) -> None:
        path = _make_db_with_snapshots(3)
        try:
            conn = sqlite3.connect(path)
            try:
                points = compute_trend(conn)
            finally:
                conn.close()
            filtered = changes_only(points)
            assert filtered[0] == points[0]
        finally:
            os.unlink(path)

    def test_filters_identical_points(self) -> None:
        path = _make_db_with_snapshots(4)
        try:
            conn = sqlite3.connect(path)
            try:
                points = compute_trend(conn)
            finally:
                conn.close()
            filtered = changes_only(points)
            # Snapshots 1 (base), 2 (danger added), 3 (danger removed) are
            # different.  Snapshot 4 is identical to 3 -> filtered out.
            assert len(filtered) == 3
        finally:
            os.unlink(path)

    def test_empty_list(self) -> None:
        assert changes_only([]) == []

    def test_single_point(self) -> None:
        path = _make_db_with_snapshots(1)
        try:
            conn = sqlite3.connect(path)
            try:
                points = compute_trend(conn)
            finally:
                conn.close()
            filtered = changes_only(points)
            assert len(filtered) == 1
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# sparkline
# ---------------------------------------------------------------------------


class TestSparkline:
    def test_empty(self) -> None:
        assert sparkline([]) == ""

    def test_all_zeros(self) -> None:
        result = sparkline([0, 0, 0])
        assert len(result) == 3
        assert all(c == "\u2581" for c in result)

    def test_increasing(self) -> None:
        result = sparkline([0, 1, 2, 3])
        assert len(result) == 4
        # Last char should be the highest block.
        assert result[-1] == "\u2588"

    def test_max_maps_to_highest(self) -> None:
        result = sparkline([0, 5])
        assert result[0] == "\u2581"
        assert result[1] == "\u2588"

    def test_single_value(self) -> None:
        result = sparkline([42])
        assert len(result) == 1
        assert result == "\u2588"

    def test_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            sparkline([-1])

    def test_mixed_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            sparkline([0, 5, -3])


# ---------------------------------------------------------------------------
# CLI parity
# ---------------------------------------------------------------------------


class TestTrendsCli:
    def test_trends_cli_table(self, capsys) -> None:
        from gpo_lens.cli import main

        path = _make_db_with_snapshots(3)
        try:
            rc = main(["--db", path, "trends"])
            out = capsys.readouterr().out
            assert rc == 0
            assert "Snapshot ID" in out
            assert "Dangers" in out
            # Three data rows.
            assert "1" in out and "2" in out and "3" in out
        finally:
            os.unlink(path)

    def test_trends_cli_json(self, capsys) -> None:
        from gpo_lens.cli import main

        path = _make_db_with_snapshots(3)
        try:
            rc = main(["--db", path, "trends", "--json"])
            out = capsys.readouterr().out
            assert rc == 0
            env = json.loads(out)
            assert env["schema_version"] == 2
            assert env["kind"] == "trends"
            data = env["data"]
            assert isinstance(data, list)
            assert len(data) == 3
            expected_fields = {
                "snapshot_id",
                "taken_at",
                "gpo_count",
                "danger_finding_count",
                "cpassword_hit_count",
                "ms16_072_vulnerable_count",
                "version_skew_count",
                "broken_ref_count",
                "unlinked_count",
                "empty_count",
                "total_settings",
                "coverage_gap_count",
            }
            assert expected_fields <= set(data[0])
        finally:
            os.unlink(path)

    def test_trends_cli_changes_only(self, capsys) -> None:
        from gpo_lens.cli import main

        path = _make_db_with_snapshots(4)
        try:
            rc = main(["--db", path, "trends", "--changes-only", "--json"])
            out = capsys.readouterr().out
            assert rc == 0
            env = json.loads(out)
            data = env["data"]
            # Snapshots 1, 2, 3 differ; 4 is identical to 3 -> excluded.
            assert len(data) == 3
        finally:
            os.unlink(path)

    def test_trends_cli_no_snapshots(self, capsys) -> None:
        from gpo_lens.cli import main
        from gpo_lens.store import init_db

        with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
            path = f.name
        try:
            conn = sqlite3.connect(path)
            try:
                init_db(conn)
            finally:
                conn.close()
            rc = main(["--db", path, "trends"])
            out = capsys.readouterr().out
            assert rc == 0
            assert "No snapshots found" in out
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Web + API
# ---------------------------------------------------------------------------

try:
    import fastapi  # noqa: F401

    _HAS_WEB = True
except ImportError:
    _HAS_WEB = False

pytestmark_web = pytest.mark.skipif(not _HAS_WEB, reason="web extra not installed")


@pytest.fixture()
def _multi_snapshot_db():
    path = _make_db_with_snapshots(3)
    try:
        yield path
    finally:
        os.unlink(path)


@pytest.fixture()
def _client(_multi_snapshot_db, monkeypatch):
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    app = create_app(_multi_snapshot_db)
    return TestClient(
        app,
        headers={
            "origin": "http://localhost",
            "Authorization": "Bearer test-secret-token",
        },
    )


@pytest.mark.skipif(not _HAS_WEB, reason="web extra not installed")
class TestTrendsWebRoute:
    def test_trends_route_returns_200(self, _client) -> None:
        resp = _client.get("/trends")
        assert resp.status_code == 200
        assert "Trends" in resp.text

    def test_trends_route_shows_table(self, _client) -> None:
        resp = _client.get("/trends")
        assert resp.status_code == 200
        assert "Snapshot ID" in resp.text
        assert "Dangers" in resp.text

    def test_trends_route_shows_sparklines(self, _client) -> None:
        resp = _client.get("/trends")
        assert resp.status_code == 200
        assert "Sparklines" in resp.text
        # At least one block character should appear.
        assert any(c in resp.text for c in "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588")

    def test_trends_route_highlights_worse(self, _client) -> None:
        resp = _client.get("/trends")
        assert resp.status_code == 200
        # Snapshot 2 had increased danger count -> should have red background.
        assert "rgba(220,53,69" in resp.text


@pytest.mark.skipif(not _HAS_WEB, reason="web extra not installed")
class TestTrendsApi:
    def test_api_trends_returns_200(self, _client) -> None:
        resp = _client.get("/api/v1/trends")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        data = body["data"]
        assert isinstance(data, list)
        assert len(data) == 3

    def test_api_trends_data_fields(self, _client) -> None:
        resp = _client.get("/api/v1/trends")
        body = resp.json()
        point = body["data"][0]
        expected = {
            "snapshot_id",
            "taken_at",
            "gpo_count",
            "danger_finding_count",
            "cpassword_hit_count",
            "ms16_072_vulnerable_count",
            "version_skew_count",
            "broken_ref_count",
            "unlinked_count",
            "empty_count",
            "total_settings",
            "coverage_gap_count",
        }
        assert expected <= set(point)

    def test_api_trends_ordered_oldest_first(self, _client) -> None:
        resp = _client.get("/api/v1/trends")
        data = resp.json()["data"]
        ids = [p["snapshot_id"] for p in data]
        assert ids == sorted(ids)

    def test_api_trends_empty_db(self, monkeypatch) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.store import init_db
        from gpo_lens.web.app import create_app

        with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
            path = f.name
        try:
            conn = sqlite3.connect(path)
            try:
                init_db(conn)
            finally:
                conn.close()
            monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
            app = create_app(path)
            client = TestClient(
                app,
                headers={
                    "origin": "http://localhost",
                    "Authorization": "Bearer test-secret-token",
                },
            )
            resp = client.get("/api/v1/trends")
            assert resp.status_code == 200
            assert resp.json()["data"] == []
        finally:
            os.unlink(path)
