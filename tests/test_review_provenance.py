"""Detector upgrades retain decisions while recording the evaluating version."""

import sqlite3
from contextlib import closing

import pytest

from gpo_lens import findings, store
from gpo_lens.finding_model import FindingCandidate
from gpo_lens.model import Estate


@pytest.mark.parametrize("check", ["digest", "stored_version", "observation_versions"])
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
    monkeypatch.setitem(findings.INTRINSIC_DETECTOR_VERSIONS, "broken_ref:*", version)
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
        monkeypatch.setitem(findings.INTRINSIC_DETECTOR_VERSIONS, "broken_ref:*", version)
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
        elif check == "stored_version":
            assert conn.execute(
                "SELECT detector_version FROM finding WHERE id=?", (row.occurrence_id,)
            ).fetchone() == ("2",)
        else:
            assert conn.execute(
                "SELECT detector_version FROM finding_observation ORDER BY id"
            ).fetchall() == [("1",), ("2",)]
            history = findings.finding_history(conn, row.occurrence_id)
            assert [o.detector_version for o in history.observations] == ["1", "2"]
            assert [
                o["detector_version"]
                for o in findings.finding_observation_history(conn, row.occurrence_id)
            ] == ["1", "2"]


def test_pipeline_digest_is_independent_of_findings(monkeypatch):
    emitted = []
    monkeypatch.setattr(findings, "candidates_from_estate", lambda *args, **kwargs: emitted)
    with closing(sqlite3.connect(":memory:")) as conn:
        store.init_db(conn)
        estate = Estate(domain="lab.example.com")
        store.save_evaluated_estate(conn, estate)
        emitted.append(
            FindingCandidate(
                detector_id="admx_gap",
                detector_version="2",
                category="admx_gap",
                severity="low",
                subject_type="gpo",
                subject_key=("a" * 32,),
                summary="Synthetic gap",
            )
        )
        store.save_evaluated_estate(conn, estate)
        (first,), (second,) = conn.execute(
            "SELECT detector_set_digest FROM evaluation_run ORDER BY id"
        ).fetchall()
        assert first == second


@pytest.mark.parametrize("change", ["detector_version", "rule_content"])
def test_pipeline_digest_records_checks_with_no_findings(monkeypatch, change):
    from dataclasses import replace

    from gpo_lens import danger

    rules = danger.load_danger_rules()
    monkeypatch.setattr(danger, "load_danger_rules", lambda: rules)
    monkeypatch.setattr(findings, "candidates_from_estate", lambda *args, **kwargs: [])
    with closing(sqlite3.connect(":memory:")) as conn:
        store.init_db(conn)
        estate = Estate(domain="lab.example.com")
        store.save_evaluated_estate(conn, estate)
        if change == "detector_version":
            monkeypatch.setitem(findings.INTRINSIC_DETECTOR_VERSIONS, "cpassword", "2")
        else:
            rules = [replace(rules[0], value="synthetic revised expected value"), *rules[1:]]
        store.save_evaluated_estate(conn, estate)
        (first,), (second,) = conn.execute(
            "SELECT detector_set_digest FROM evaluation_run ORDER BY id"
        ).fetchall()
        assert first != second
        assert conn.execute("SELECT count(*) FROM finding_observation").fetchone() == (0,)
