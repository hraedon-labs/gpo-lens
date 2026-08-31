"""Tests for WI-5: triage annotations + findings inbox."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from gpo_lens._legacy_findings import update_finding_lifecycle
from gpo_lens.findings import (
    load_finding_triage,
    load_finding_triage_map,
    triage_finding,
)
from gpo_lens.store import init_db
from gpo_lens.web.routes.findings import _latest_snapshot_gpo_ids

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def _make_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    return conn


def _make_finding(category: str, gpo_id: str, severity="medium", summary="test"):
    return MagicMock(
        category=category,
        gpo_id=gpo_id,
        gpo_name=f"GPO-{gpo_id[:8]}",
        severity=severity,
        summary=summary,
        detail="",
        subject_key=(),
    )


class TestLatestSnapshotGpoIds:
    @staticmethod
    def _insert_gpo(conn: sqlite3.Connection, snapshot_id: int, gpo_id: str) -> None:
        conn.execute(
            """
            INSERT INTO gpo (
                snapshot_id, id, name, domain, computer_enabled, user_enabled,
                filter_data_available
            ) VALUES (?, ?, ?, 'example.test', 1, 1, 1)
            """,
            (snapshot_id, gpo_id, f"GPO {gpo_id}"),
        )

    def test_returns_only_latest_snapshot_gpo_ids(self) -> None:
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) "
                "VALUES (1, 'example.test', '2025-01-01')"
            )
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) "
                "VALUES (2, 'example.test', '2025-01-02')"
            )
            self._insert_gpo(conn, 1, "old-gpo")
            self._insert_gpo(conn, 2, "current-gpo")

            assert _latest_snapshot_gpo_ids(conn) == {"current-gpo"}
        finally:
            conn.close()

    def test_returns_empty_set_without_snapshot(self) -> None:
        conn = _make_db()
        try:
            assert _latest_snapshot_gpo_ids(conn) == set()
        finally:
            conn.close()


class TestTriage:
    def test_triage_append_only(self) -> None:
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            update_finding_lifecycle(conn, 1, [_make_finding("cpassword", "gpo1")])
            from gpo_lens.findings import load_active_findings

            active = load_active_findings(conn)
            finding_id = active[0].id

            triage_finding(conn, finding_id, "acknowledged", "looking into it", "alice")
            triage_finding(conn, finding_id, "accepted_risk", "approved by CISO", "bob")

            history = load_finding_triage(conn, finding_id)
            assert len(history) == 2
            assert history[0]["status"] == "acknowledged"
            assert history[0]["actor"] == "alice"
            assert history[1]["status"] == "accepted_risk"
            assert history[1]["actor"] == "bob"
        finally:
            conn.close()

    def test_triage_map_returns_latest(self) -> None:
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            update_finding_lifecycle(conn, 1, [_make_finding("cpassword", "gpo1")])
            from gpo_lens.findings import load_active_findings

            finding_id = load_active_findings(conn)[0].id

            triage_finding(conn, finding_id, "acknowledged", "", "alice")
            # WI-092: accepted_risk goes through the Plan 024 event store,
            # which requires a rationale (the note doubles as it).
            triage_finding(conn, finding_id, "accepted_risk", "approved by CISO", "bob")

            triage_map = load_finding_triage_map(conn)
            assert finding_id in triage_map
            assert triage_map[finding_id]["status"] == "accepted_risk"
            assert triage_map[finding_id]["actor"] == "bob"
        finally:
            conn.close()

    def test_accepted_risk_requires_note(self) -> None:
        """WI-092: the shim honors Plan 024 §8 — risk acceptance needs a rationale."""
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            update_finding_lifecycle(conn, 1, [_make_finding("cpassword", "gpo1")])
            from gpo_lens.findings import load_active_findings

            finding_id = load_active_findings(conn)[0].id
            with pytest.raises(ValueError, match="rationale"):
                triage_finding(conn, finding_id, "accepted_risk", "", "alice")
        finally:
            conn.close()

    def test_triage_lands_in_plan024_event_store(self) -> None:
        """WI-092 AC: v1-surface triage must be visible to the Plan 024 layer.

        A triage action made through the v1 API (the path the web endpoint
        uses) must be readable via ``load_triage_status_map`` — before this
        fix it landed in the legacy ``finding_triage`` table, invisible to
        every Plan 024 query.
        """
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            update_finding_lifecycle(conn, 1, [_make_finding("cpassword", "gpo1")])
            from gpo_lens.findings import load_active_findings, load_triage_status_map

            finding_id = load_active_findings(conn)[0].id
            triage_finding(conn, finding_id, "acknowledged", "looking into it", "alice")

            status_map = load_triage_status_map(conn)
            assert finding_id in status_map
            assert status_map[finding_id].status == "acknowledged"
            assert status_map[finding_id].actor == "alice"

            # And the event log itself holds the row (occurrence ids are
            # finding ids — both triage generations key off ``finding.id``).
            row = conn.execute(
                "SELECT action, actor, note FROM finding_triage_event WHERE occurrence_id = ?",
                (finding_id,),
            ).fetchone()
            assert row == ("acknowledged", "alice", "looking into it")

            # The legacy v1 table is no longer written.
            assert conn.execute("SELECT COUNT(*) FROM finding_triage").fetchone()[0] == 0
        finally:
            conn.close()

    def test_invalid_status_raises(self) -> None:
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            update_finding_lifecycle(conn, 1, [_make_finding("cpassword", "gpo1")])
            from gpo_lens.findings import load_active_findings

            finding_id = load_active_findings(conn)[0].id
            try:
                triage_finding(conn, finding_id, "invalid_status", "", "alice")
                raise AssertionError("should have raised")
            except ValueError:
                pass
        finally:
            conn.close()

    def test_triage_survives_reingest(self) -> None:
        """Triage annotations survive re-ingest of the same estate."""
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            update_finding_lifecycle(conn, 1, [_make_finding("cpassword", "gpo1")])
            from gpo_lens.findings import load_active_findings

            finding_id = load_active_findings(conn)[0].id
            triage_finding(conn, finding_id, "acknowledged", "noted", "alice")

            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (2, 'test', '2025-01-02')"
            )
            update_finding_lifecycle(conn, 2, [_make_finding("cpassword", "gpo1")])

            triage_map = load_finding_triage_map(conn)
            assert finding_id in triage_map
            assert triage_map[finding_id]["status"] == "acknowledged"
        finally:
            conn.close()


class TestFindingsInboxWeb:
    @pytest.fixture(autouse=True)
    def _auth_env(self, monkeypatch):
        # monkeypatch (not bare os.environ) so the token never leaks into
        # other tests in the same worker — a leaked token defeats the
        # no-token loopback bind guard and lets cmd_serve tests really
        # start uvicorn on 0.0.0.0 (observed as a suite hang / flaky
        # TestLoopbackGuard failure under xdist).
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")

    @pytest.fixture(autouse=True)
    def _db_dir(self, tmp_path):
        # Each test gets its own scratch DB. A shared DB under
        # tests/fixtures/ raced across xdist workers (its transient
        # -shm/-wal sidecars broke copytree-based tests) and coupled
        # tests through leftover rows.
        self._db_path = str(tmp_path / "gpo-lens-test.sqlite3")

    @property
    def _client(self):
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app

        db_path = self._db_path
        from gpo_lens.ingest import load_estate
        from gpo_lens.store import init_db, save_estate

        estate = load_estate(FIXTURE_DIR)
        conn = sqlite3.connect(db_path)
        try:
            init_db(conn)
            save_estate(conn, estate)
        finally:
            conn.close()

        app = create_app(db_path)
        return TestClient(app)

    def test_findings_page_renders(self) -> None:
        client = self._client
        resp = client.get(
            "/findings",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        html = resp.text
        assert "Findings inbox" in html or "Findings" in html

    def _seed_render_link_case(self, *, gpo_id: str, in_latest_snapshot: bool):
        from gpo_lens.finding_model import EvidenceRef, FindingCandidate
        from gpo_lens.findings import create_evaluation_run, run_evaluation
        from gpo_lens.store import list_snapshots

        client = self._client
        conn = sqlite3.connect(self._db_path)
        try:
            older_snapshot_id = list_snapshots(conn)[0][0]
            cursor = conn.execute(
                "INSERT INTO snapshot (domain, taken_at) "
                "VALUES ('example.test', '2025-02-01T00:00:00+00:00')"
            )
            latest_snapshot_id = cursor.lastrowid
            assert latest_snapshot_id is not None

            target_snapshot_id = latest_snapshot_id if in_latest_snapshot else older_snapshot_id
            TestLatestSnapshotGpoIds._insert_gpo(conn, target_snapshot_id, gpo_id)
            conn.commit()

            candidate = FindingCandidate(
                detector_id="route-link-test",
                detector_version="1",
                category="route-link-test",
                severity="medium",
                subject_type="gpo",
                subject_key=(gpo_id,),
                summary=f"Finding for {gpo_id}",
                evidence_refs=(
                    EvidenceRef(
                        snapshot_id=latest_snapshot_id,
                        gpo_id=gpo_id,
                        source="test",
                        field_path="test",
                        safe_projection="safe test evidence",
                    ),
                ),
                gpo_name=f"GPO {gpo_id}",
            )
            run_id = create_evaluation_run(conn, latest_snapshot_id)
            run_evaluation(conn, run_id, [candidate])
        finally:
            conn.close()

        return client

    def test_finding_gpo_only_in_older_snapshot_renders_plain_text(self) -> None:
        gpo_id = "older-only-gpo"
        resp = self._seed_render_link_case(
            gpo_id=gpo_id,
            in_latest_snapshot=False,
        ).get(
            "/findings",
            headers={"Authorization": "Bearer test-secret-token"},
        )

        assert resp.status_code == 200
        assert f"/gpo/{gpo_id}" not in resp.text
        assert f">GPO {gpo_id}</a>" not in resp.text
        assert f"GPO {gpo_id}" in resp.text

    def test_finding_gpo_in_latest_snapshot_renders_detail_link(self) -> None:
        gpo_id = "current-gpo"
        resp = self._seed_render_link_case(
            gpo_id=gpo_id,
            in_latest_snapshot=True,
        ).get(
            "/findings",
            headers={"Authorization": "Bearer test-secret-token"},
        )

        assert resp.status_code == 200
        assert f"/gpo/{gpo_id}" in resp.text
        assert f">GPO {gpo_id}</a>" in resp.text

    def test_findings_page_does_not_reconstruct_estate(self, monkeypatch) -> None:
        client = self._client
        monkeypatch.setattr(
            "gpo_lens.store.load_estate",
            MagicMock(side_effect=AssertionError("unexpected estate reconstruction")),
        )

        resp = client.get(
            "/findings",
            headers={"Authorization": "Bearer test-secret-token"},
        )

        assert resp.status_code == 200

    def test_findings_page_renders_without_snapshot(self) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app

        conn = sqlite3.connect(self._db_path)
        try:
            init_db(conn)
        finally:
            conn.close()

        resp = TestClient(create_app(self._db_path)).get(
            "/findings",
            headers={"Authorization": "Bearer test-secret-token"},
        )

        assert resp.status_code == 200
        assert "No findings match the current filters" in resp.text

    def test_findings_page_has_filter_bar(self) -> None:
        client = self._client
        resp = client.get(
            "/findings",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        html = resp.text
        assert "severity" in html.lower()
        assert "triage" in html.lower()

    def _seed_finding(self) -> None:
        # Create a finding so we can triage it. Requires the DB to exist:
        # build the client (which runs init_db + save_estate) first.
        conn = sqlite3.connect(self._db_path)
        try:
            from gpo_lens.store import list_snapshots

            snaps = list_snapshots(conn)
            if snaps:
                sid = snaps[0][0]
                from gpo_lens._legacy_findings import update_finding_lifecycle

                update_finding_lifecycle(
                    conn, sid, [_make_finding("test_rule", "test_gpo", "medium", "test finding")]
                )
        finally:
            conn.close()

    def test_triage_post_allowed_with_triage_permission(self) -> None:
        client = self._client
        self._seed_finding()
        # TestClient follows redirects by default, so a successful triage
        # returns 200 (the findings page) after a 303 redirect
        resp = client.post(
            "/findings/1/triage",
            data={"status": "acknowledged", "note": "test"},
            headers={
                "Authorization": "Bearer test-secret-token",
                "Origin": "http://testserver",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303

    def _client_as(self, permissions: frozenset) -> object:
        """A client whose principal has exactly *permissions* (WI-088)."""
        from gpo_lens.web.auth import Principal, get_principal

        client = self._client
        client.app.dependency_overrides[get_principal] = lambda: Principal(
            name="test-user", role="test", permissions=permissions
        )
        return client

    def test_triage_denied_with_ingest_but_no_triage_permission(self) -> None:
        # WI-088 / Plan 024 §8: triage is its own permission — holding
        # INGEST alone must no longer authorize finding triage.
        from gpo_lens.web.auth import Permission

        client = self._client_as(frozenset({Permission.VIEW, Permission.INGEST}))
        self._seed_finding()
        resp = client.post(
            "/findings/1/triage",
            data={"status": "acknowledged", "note": "test"},
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )
        assert resp.status_code == 403

    def test_triage_allowed_without_ingest_permission(self) -> None:
        # The converse: a triage-only principal can acknowledge a finding
        # but must not be able to upload snapshots.
        from gpo_lens.web.auth import Permission

        client = self._client_as(frozenset({Permission.VIEW, Permission.TRIAGE}))
        self._seed_finding()
        resp = client.post(
            "/findings/1/triage",
            data={"status": "acknowledged", "note": "test"},
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        resp = client.post(
            "/ingest",
            files={"file": ("export.zip", b"not-a-zip", "application/zip")},
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )
        assert resp.status_code == 403

    def test_web_triage_visible_to_plan024_queries(self) -> None:
        """WI-092 AC: a triage action made through the web path must be
        visible via ``load_triage_status_map()`` and ``finding_inbox()``.

        Before the convergence, the web endpoint wrote the legacy
        ``finding_triage`` table, which no Plan 024 query reads — a silent
        data-loss trap once the inbox moves onto ``finding_inbox()``.
        """
        from gpo_lens.findings import (
            evaluate_finding_lifecycle_v2,
            finding_inbox,
            load_active_findings,
            load_triage_status_map,
        )
        from gpo_lens.ingest import load_estate
        from gpo_lens.store import list_snapshots

        client = self._client  # builds DB + saves the fixture estate
        estate = load_estate(FIXTURE_DIR)
        conn = sqlite3.connect(self._db_path)
        try:
            sid = list_snapshots(conn)[0][0]
            evaluate_finding_lifecycle_v2(conn, sid, estate)
            finding_id = load_active_findings(conn)[0].id
        finally:
            conn.close()

        resp = client.post(
            f"/findings/{finding_id}/triage",
            data={"status": "acknowledged", "note": "triaged from the web"},
            headers={
                "Authorization": "Bearer test-secret-token",
                "Origin": "http://testserver",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303

        conn = sqlite3.connect(self._db_path)
        try:
            status_map = load_triage_status_map(conn)
            assert finding_id in status_map
            assert status_map[finding_id].status == "acknowledged"
            assert status_map[finding_id].note == "triaged from the web"

            inbox = finding_inbox(conn, triage_status="acknowledged")
            assert any(v.occurrence_id == finding_id for v in inbox)

            # And the legacy v1 table stays empty — one triage store only.
            assert conn.execute("SELECT COUNT(*) FROM finding_triage").fetchone()[0] == 0
        finally:
            conn.close()
