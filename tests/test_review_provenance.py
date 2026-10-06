"""Detector upgrades retain decisions while recording the evaluating version."""

import sqlite3
from contextlib import closing

import pytest

from gpo_lens import findings, store
from gpo_lens.finding_model import FindingCandidate
from gpo_lens.model import Estate


@pytest.mark.parametrize("check", ["digest", "stored_version"])
def test_detector_version_provenance_with_triage_continuity(monkeypatch, check):
    version = "1"

    def candidates(*args, **kwargs):
        return [
            FindingCandidate(
                detector_id="broken_ref:missing_script",
                detector_version=version,
                category="broken_ref:missing_script",
                severity="low",
                subject_type="gpo",
                subject_key=("a" * 32,),
                dimensions=(("ref_value", "lab.cmd"),),
                summary="Lab missing script",
            )
        ]

    monkeypatch.setattr(findings, "candidates_from_estate", candidates)
    with closing(sqlite3.connect(":memory:")) as conn:
        store.init_db(conn)
        e = Estate(domain="lab.example.com")
        sid = store.save_estate(conn, e)
        first = findings.evaluate_finding_lifecycle_v2(conn, sid, e)
        row = findings.finding_inbox(conn)[0]
        fingerprint = conn.execute(
            "SELECT finding_key FROM finding WHERE id=?", (row.occurrence_id,)
        ).fetchone()
        findings.append_triage_event(
            conn, row.occurrence_id, "accepted_risk", "lab-reviewer", rationale="Lab control"
        )
        version = "2"
        sid = store.save_estate(conn, e)
        second = findings.evaluate_finding_lifecycle_v2(conn, sid, e)
        later = findings.finding_inbox(conn)[0]
        assert later.occurrence_id == row.occurrence_id
        assert later.triage_status == "accepted_risk"
        assert (
            conn.execute(
                "SELECT finding_key FROM finding WHERE id=?", (row.occurrence_id,)
            ).fetchone()
            == fingerprint
        )
        assert conn.execute(
            "SELECT first_seen_run_id, last_seen_run_id FROM finding WHERE id=?",
            (row.occurrence_id,),
        ).fetchone() == (first.run_id, second.run_id)
        if check == "digest":
            digests = conn.execute(
                "SELECT detector_set_digest FROM evaluation_run ORDER BY id"
            ).fetchall()
            assert digests[0] != digests[1]
        else:
            assert conn.execute(
                "SELECT detector_version FROM finding WHERE id=?", (row.occurrence_id,)
            ).fetchone() == ("2",)
