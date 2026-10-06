"""Daybreak Blue data-integrity reproductions, using synthetic fixtures only."""

import shutil
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from gpo_lens.briefing import build_briefing
from gpo_lens.findings import (
    accepted_risk_register,
    append_triage_event,
    candidates_from_estate,
    create_evaluation_run,
    finding_inbox,
    fold_triage,
    get_triage_status,
    load_triage_events,
    load_triage_status_map,
    run_evaluation,
)
from gpo_lens.ingest import load_estate
from gpo_lens.store import init_db, save_estate

FIXTURES = Path(__file__).parent / "fixtures"


def test_v120_public_api_reopen_survives_upgrade(tmp_path):
    # Generated from the real v1.2 DB by scripts/build_v120_reopen_fixture.py,
    # using both released APIs, as the reviewer's probe does (never current APIs).
    db = tmp_path / "upgrade.sqlite3"
    shutil.copyfile(FIXTURES / "released_databases/v1.2.0-with-reopen.sqlite3", db)
    with sqlite3.connect(db) as conn:
        oid = conn.execute(
            "SELECT finding_id FROM finding_triage WHERE status='accepted_risk' ORDER BY id LIMIT 1"
        ).fetchone()[0]
        original = conn.execute("SELECT * FROM finding_triage_event ORDER BY id").fetchall()
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 7
        for _ in range(2):
            init_db(conn)
            assert get_triage_status(conn, oid).status == "open"
            assert load_triage_status_map(conn)[oid].status == "open"
            assert oid in {
                v.occurrence_id
                for v in finding_inbox(conn, lifecycle_state="all", triage_status="open")
            }
            events = load_triage_events(conn, oid)
            assert [e.action for e in events] == ["accepted_risk", "accepted_risk", "reopened"]
            assert fold_triage(list(reversed(events))).status == "open"
            risk = next(r for r in accepted_risk_register(conn) if r.occurrence_id == oid)
            assert risk.revoked_by == "lab-reviewer"
            assert risk.revoked_at is not None
            assert all(
                row in conn.execute("SELECT * FROM finding_triage_event").fetchall()
                for row in original
            )


def test_triage_timestamp_and_id_order_in_every_fold():
    with sqlite3.connect(":memory:") as conn:
        init_db(conn)
        sid = save_estate(conn, load_estate(FIXTURES))
        candidates = candidates_from_estate(load_estate(FIXTURES), snapshot_id=sid)
        run = create_evaluation_run(conn, sid)
        run_evaluation(conn, run, candidates)
        oid = finding_inbox(conn, lifecycle_state="all")[0].occurrence_id
        append_triage_event(conn, oid, "reopened", "lab-reviewer")
        append_triage_event(conn, oid, "accepted_risk", "lab-owner", rationale="lab approval")
        conn.execute(
            "UPDATE finding_triage_event SET occurred_at=CASE action "
            "WHEN 'reopened' THEN '2026-01-01T02:00:00+00:00' "
            "ELSE '2026-01-01T03:00:00+02:00' END"
        )
        conn.commit()
        assert get_triage_status(conn, oid).status == "open"
        assert load_triage_status_map(conn)[oid].status == "open"
        risk = next(
            r
            for r in accepted_risk_register(conn, as_of=datetime(2030, 1, 1, tzinfo=UTC))
            if r.occurrence_id == oid
        )
        assert risk.revoked_at is not None
        conn.execute("UPDATE finding_triage_event SET occurred_at='2026-01-01T00:00:00+00:00'")
        conn.commit()
        assert get_triage_status(conn, oid).status == "accepted_risk"  # equal time: stable id


def test_enforced_links_have_complete_identity_and_do_not_inherit_collapsed_triage():
    estate = load_estate(FIXTURES)
    with sqlite3.connect(":memory:") as conn:
        init_db(conn)
        sid = save_estate(conn, estate)
        links = [
            c
            for c in candidates_from_estate(estate, snapshot_id=sid)
            if c.category == "enforced_link"
        ]
        assert len(links) == 3
        assert all(set(dict(c.dimensions)) == {"som_path", "order", "target"} for c in links)
        old = replace(links[0], dimensions=())
        run_evaluation(conn, create_evaluation_run(conn, sid), [old])
        oid = finding_inbox(conn, lifecycle_state="all")[0].occurrence_id
        append_triage_event(
            conn, oid, "accepted_risk", "lab-owner", rationale="ambiguous old acceptance"
        )
        run = create_evaluation_run(conn, sid)
        result = run_evaluation(conn, run, links)
        assert result.new_count == 3
        assert result.duplicate_fingerprint_count == 0
        assert len(finding_inbox(conn, lifecycle_state="all", triage_status="open")) == 3
        assert get_triage_status(conn, oid).status == "accepted_risk"
        assert (
            conn.execute("SELECT resolved_run_id FROM finding WHERE id=?", (oid,)).fetchone()[0]
            == run
        )
        assert (
            "Legacy enforced-link"
            in conn.execute(
                "SELECT error_summary FROM evaluation_run WHERE id=?", (run,)
            ).fetchone()[0]
        )


def test_duplicate_fingerprint_degrades_analysis_without_resolving_missing_findings():
    estate = load_estate(FIXTURES)
    with sqlite3.connect(":memory:") as conn:
        init_db(conn)
        sid = save_estate(conn, estate)
        candidates = candidates_from_estate(estate, snapshot_id=sid)
        run_evaluation(conn, create_evaluation_run(conn, sid), candidates)
        run = create_evaluation_run(conn, sid)
        result = run_evaluation(conn, run, [candidates[0], candidates[0]])
        assert result.duplicate_fingerprint_count == 1
        assert result.resolved_count == 0
        status, error = conn.execute(
            "SELECT status,error_summary FROM evaluation_run WHERE id=?", (run,)
        ).fetchone()
        assert status == "partial"
        assert "duplicate fingerprint" in error
        briefing = build_briefing(conn)
        assert not briefing.analysis_complete
        assert any("duplicate fingerprint" in p for p in briefing.problems)


def test_historical_activity_and_severity_use_selected_run():
    estate = load_estate(FIXTURES)
    with sqlite3.connect(":memory:") as conn:
        init_db(conn)
        totals = [(2, 1), (1, 0), (0, 0), (1, 1)]
        sample = candidates_from_estate(estate, snapshot_id=1)[0]
        for i, candidates in enumerate(
            [
                [
                    replace(sample, severity="critical"),
                    replace(sample, subject_key=("new-lab-id",), severity="high"),
                ],
                [replace(sample, severity="low")],
                [],
                [replace(sample, severity="critical")],
            ],
            1,
        ):
            sid = save_estate(conn, estate)
            run_evaluation(conn, create_evaluation_run(conn, sid), candidates)
        for sid, (active, critical) in enumerate(totals, 1):
            briefing = build_briefing(conn, as_of_snapshot=sid)
            assert {v.key: v.value for v in briefing.vitals}["active_findings"] == active
            assert {v.key: v.value for v in briefing.vitals}["critical_findings"] == critical


def test_future_schema_refusal_is_byte_preserving(tmp_path):
    import pytest

    db = tmp_path / "future.sqlite3"
    with sqlite3.connect(db) as conn:
        conn.executescript(
            "CREATE TABLE future_only(payload TEXT); "
            "INSERT INTO future_only VALUES ('lab sentinel'); PRAGMA user_version=99;"
        )
    before = db.read_bytes()
    conn = sqlite3.connect(db)
    try:
        schema = conn.execute("SELECT * FROM sqlite_master").fetchall()
        trace = []
        conn.set_trace_callback(trace.append)
        with pytest.raises(RuntimeError, match="schema version 99"):
            init_db(conn)
        assert trace == ["PRAGMA user_version"]
        assert conn.execute("SELECT * FROM sqlite_master").fetchall() == schema
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert db.read_bytes() == before
    finally:
        conn.close()
    assert db.read_bytes() == before
    assert not Path(str(db) + "-wal").exists()
