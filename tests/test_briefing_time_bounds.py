"""Briefing dates remain usable at the limits of the accepted datetime range."""

from contextlib import closing
from datetime import UTC, datetime, timedelta, tzinfo

import pytest

from gpo_lens.briefing import build_briefing
from gpo_lens.finding_model import EvidenceRef, FindingCandidate
from gpo_lens.findings import (
    append_triage_event,
    create_evaluation_run,
    finding_inbox,
    run_evaluation,
)
from gpo_lens.store import init_db


@pytest.fixture
def briefing_db(tmp_path):
    import sqlite3

    db_path = tmp_path / "briefing.sqlite3"
    with closing(sqlite3.connect(db_path)) as conn:
        init_db(conn)
        conn.execute(
            "INSERT INTO snapshot (id, domain, taken_at) "
            "VALUES (1, 'example.test', '2000-01-01T00:00:00+00:00')"
        )
        conn.commit()
        run = create_evaluation_run(conn, 1)
        run_evaluation(
            conn,
            run,
            [
                FindingCandidate(
                    detector_id="synthetic",
                    detector_version="1",
                    category="synthetic",
                    severity="high",
                    subject_type="gpo",
                    subject_key=("a" * 32,),
                    summary="Synthetic finding",
                    evidence_refs=(EvidenceRef(1, "a" * 32, "test", "field", "safe"),),
                    gpo_name="Synthetic policy",
                )
            ],
        )
        yield conn, db_path, finding_inbox(conn)[0].occurrence_id


def _accept(conn, occurrence_id, expires_at):
    event_id = append_triage_event(
        conn,
        occurrence_id,
        "accepted_risk",
        "synthetic-analyst",
        rationale="Synthetic acceptance",
        expires_at=expires_at,
    )
    # Fixture events precede every as-of date without relying on the wall clock.
    conn.execute(
        "UPDATE finding_triage_event SET occurred_at='2000-01-01T00:00:00+00:00' WHERE id=?",
        (event_id,),
    )
    conn.commit()


@pytest.mark.parametrize(
    ("now", "expires_at", "included"),
    [
        ("2030-01-01T00:00:00Z", "2030-01-15T00:00:00Z", True),
        ("2030-01-01T00:00:00Z", "2030-01-15T00:00:00.000001Z", False),
        ("2030-01-01T00:00:00Z", "2001-01-01T00:00:00Z", True),
        ("9999-12-17T00:00:00Z", "9999-12-31T00:00:00Z", True),
        ("9999-12-17T00:00:00Z", "9999-12-31T00:00:00.000001Z", False),
        ("9999-12-18T00:00:00Z", "9999-12-31T00:00:00Z", True),
        ("9999-12-31T23:59:59.999999Z", "9999-12-31T23:59:59.999999Z", True),
        ("9999-12-18T00:00:00Z", "2001-01-01T00:00:00Z", True),
        ("9999-12-18T00:00:00+14:00", "9999-12-31T09:59:59Z", True),
        ("9999-12-18T00:00:00+14:00", "9999-12-31T10:00:00Z", True),
        ("9999-12-18T00:00:00+14:00", "9999-12-31T10:00:00.000001Z", False),
        ("9999-12-18T00:00:00-12:00", "9999-12-31T23:59:59.999999Z", True),
    ],
)
def test_acceptance_horizon_at_datetime_boundaries(briefing_db, now, expires_at, included):
    conn, _, occurrence_id = briefing_db
    now = datetime.fromisoformat(now)
    expires_at = datetime.fromisoformat(expires_at)
    _accept(conn, occurrence_id, expires_at)

    briefing = build_briefing(conn, now=now)

    assert briefing is not None
    assert [r.occurrence_id for r in briefing.expiring] == ([occurrence_id] if included else [])
    accepted = next(v for v in briefing.vitals if v.key == "accepted_risks")
    assert accepted.value == int(expires_at > now)
    if included:
        assert briefing.expiring[0].already_expired == (expires_at <= now)


def test_representable_horizon_keeps_its_local_clock_deadline(briefing_db):
    class AutumnClock(tzinfo):
        def utcoffset(self, dt):
            return timedelta(hours=-4 if dt.month == 10 else -5)

    conn, _, occurrence_id = briefing_db
    now = datetime(2030, 10, 27, tzinfo=AutumnClock())
    # A synthetic clock change keeps this test independent of system tzdata.
    # Fourteen local days include 05:00 UTC, fourteen elapsed days plus an hour.
    _accept(conn, occurrence_id, datetime(2030, 11, 10, 5, tzinfo=UTC))
    briefing = build_briefing(conn, now=now)
    assert briefing is not None
    assert [r.occurrence_id for r in briefing.expiring] == [occurrence_id]


@pytest.mark.parametrize("state", ["absent", "unlimited", "revoked"])
def test_nonexpiring_or_revoked_acceptances_at_maximum_time(briefing_db, state):
    conn, _, occurrence_id = briefing_db
    if state != "absent":
        _accept(
            conn, occurrence_id, None if state == "unlimited" else datetime.max.replace(tzinfo=UTC)
        )
    if state == "revoked":
        append_triage_event(conn, occurrence_id, "risk_acceptance_revoked", "synthetic-analyst")
    briefing = build_briefing(conn, now=datetime.max.replace(tzinfo=UTC))
    assert briefing is not None
    assert briefing.expiring == ()
    accepted = next(v for v in briefing.vitals if v.key == "accepted_risks")
    assert accepted.value == int(state == "unlimited")


@pytest.mark.parametrize("format", ["", "csv", "md"])
@pytest.mark.parametrize(
    "as_of",
    ["9999-12-17T00:00:00Z", "9999-12-18T00:00:00Z", "9999-12-31T23:59:59Z"],
)
def test_briefing_views_and_exports_accept_upper_dates(briefing_db, monkeypatch, format, as_of):
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    conn, db_path, occurrence_id = briefing_db
    _accept(conn, occurrence_id, datetime(9999, 12, 31, tzinfo=UTC))
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "synthetic-briefing-token")
    with TestClient(
        create_app(str(db_path)),
        headers={"Authorization": "Bearer synthetic-briefing-token"},
        raise_server_exceptions=False,
    ) as client:
        params = {"as_of": as_of, "format": format}
        first = client.get("/briefing", params=params)
        assert first.status_code == 200
        assert "9999-12-31" in first.text
        if format:
            assert first.content == client.get("/briefing", params=params).content
