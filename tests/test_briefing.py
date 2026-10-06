"""Plan 025 WI-2: the deterministic briefing.

Two layers. The golden tests pin exact prose against hand-built ``Briefing``
models — no database, no clock, so a wording change is a visible diff rather
than a silent drift. The integration tests then prove ``build_briefing`` derives
those facts correctly from a real store.
"""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from gpo_lens.briefing import (
    Briefing,
    BriefingVital,
    ExpiringAcceptance,
    briefing_lines,
    build_briefing,
)
from gpo_lens.finding_model import EvidenceRef, FindingCandidate
from gpo_lens.findings import (
    append_triage_event,
    create_evaluation_run,
    run_evaluation,
)
from gpo_lens.store import init_db

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def _vitals(
    *,
    critical: int = 0,
    active: int = 0,
    gaps: int = 0,
    accepted: int = 0,
    gpos: int = 0,
) -> tuple[BriefingVital, ...]:
    return (
        BriefingVital("critical_findings", "Critical findings", critical, "muted"),
        BriefingVital("active_findings", "Active findings", active, "muted"),
        BriefingVital("coverage_gaps", "Coverage gaps", gaps, "muted"),
        BriefingVital("accepted_risks", "Accepted risks", accepted, "muted"),
        BriefingVital("gpo_count", "GPOs", gpos, "muted"),
    )


def _briefing(**overrides: object) -> Briefing:
    base: dict[str, object] = {
        "domain": "example.test",
        "snapshot_id": 2,
        "snapshot_taken_at": _NOW,
        "prior_snapshot_id": 1,
        "is_first_snapshot": False,
        "analysis_complete": True,
        "problems": (),
        "gpos_added": 0,
        "gpos_removed": 0,
        "gpos_changed": 0,
        "findings_new": 0,
        "findings_resolved": 0,
        "findings_regressed": 0,
        "expiring": (),
        "vitals": _vitals(),
    }
    base.update(overrides)
    return Briefing(**base)  # type: ignore[arg-type]


class TestBriefingGolden:
    """Exact-text goldens for the four scenarios Plan 025 WI-2 names."""

    def test_first_snapshot(self) -> None:
        briefing = _briefing(
            snapshot_id=1,
            prior_snapshot_id=None,
            is_first_snapshot=True,
            vitals=_vitals(gpos=12, active=3),
        )
        assert briefing_lines(briefing) == (
            "This is the first snapshot of example.test (#1), so there is "
            "nothing to compare it against yet. It holds 12 GPOs and 3 active "
            "findings.",
        )

    def test_ordinary_delta(self) -> None:
        briefing = _briefing(
            gpos_changed=2,
            findings_new=1,
            findings_resolved=3,
        )
        assert briefing_lines(briefing) == (
            "Since snapshot #1: 2 GPOs changed, 1 finding is new, and 3 resolved.",
        )

    def test_no_change(self) -> None:
        assert briefing_lines(_briefing()) == (
            "Nothing changed between snapshot #1 and #2: no GPO edits, and no "
            "findings opened or resolved.",
        )

    def test_degraded_analysis_reports_no_delta(self) -> None:
        # A partial evaluation must not be laundered into a confident delta:
        # the problem leads and no "Since snapshot" sentence is emitted at all.
        briefing = _briefing(
            analysis_complete=False,
            problems=(
                "The latest evaluation run finished with status 'failed' "
                "(detector crashed) — this is an incomplete analysis, not a "
                "clean delta.",
            ),
            gpos_changed=9,
            findings_new=9,
        )
        lines = briefing_lines(briefing)
        assert lines == (
            "The latest evaluation run finished with status 'failed' "
            "(detector crashed) — this is an incomplete analysis, not a clean "
            "delta.",
            "Analysis of snapshot #2 is incomplete, so no delta against snapshot #1 is reported.",
        )
        assert not any("Since snapshot" in line for line in lines)


class TestBriefingProminence:
    def test_problems_precede_favorable_counts(self) -> None:
        # Plan 025 WI-2 AC: coverage and provenance gaps are at least as
        # prominent as favorable counts. Ordering is the guarantee.
        briefing = _briefing(
            problems=(
                "4 coverage gaps in this snapshot — some GPOs could not be "
                "read, so absence of a finding is not evidence of its absence.",
            ),
            findings_resolved=7,
        )
        lines = briefing_lines(briefing)
        gap_index = next(i for i, line in enumerate(lines) if "coverage gap" in line)
        good_index = next(i for i, line in enumerate(lines) if "resolved" in line)
        assert gap_index < good_index

    def test_singular_and_plural_agree(self) -> None:
        one = briefing_lines(_briefing(gpos_changed=1, findings_new=1))[0]
        assert "1 GPO changed" in one
        assert "1 finding is new" in one
        many = briefing_lines(_briefing(gpos_changed=2, findings_new=2))[0]
        assert "2 GPOs changed" in many
        assert "2 findings are new" in many

    def test_expired_acceptance_is_called_actionable_again(self) -> None:
        expired = ExpiringAcceptance(
            occurrence_id=5,
            category="cpassword",
            summary="s",
            severity="high",
            actor="alice",
            expires_at=_NOW - timedelta(days=1),
            already_expired=True,
        )
        lines = briefing_lines(_briefing(gpos_changed=1, expiring=(expired,)))
        assert any("expired and is actionable again" in line for line in lines)


# ---------------------------------------------------------------------------
# Integration: the facts are derived from a real store
# ---------------------------------------------------------------------------


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    return conn


def _snapshot(conn: sqlite3.Connection, snapshot_id: int) -> None:
    conn.execute(
        "INSERT INTO snapshot (id, domain, taken_at) VALUES (?, 'example.test', ?)",
        (snapshot_id, f"2026-07-{snapshot_id:02d}T00:00:00+00:00"),
    )
    conn.commit()


def _candidate(detector: str, gpo: str, severity: str = "high") -> FindingCandidate:
    return FindingCandidate(
        detector_id=detector,
        detector_version="1",
        category=detector,
        severity=severity,
        subject_type="gpo",
        subject_key=(gpo,),
        summary=f"{detector} on {gpo}",
        evidence_refs=(
            EvidenceRef(
                snapshot_id=1,
                gpo_id=gpo,
                source="test",
                field_path="f",
                safe_projection="p",
            ),
        ),
        gpo_name=gpo,
    )


class TestBuildBriefing:
    def test_returns_none_without_snapshots(self) -> None:
        conn = _db()
        try:
            assert build_briefing(conn, now=_NOW) is None
        finally:
            conn.close()

    def test_first_snapshot_flagged(self) -> None:
        conn = _db()
        try:
            _snapshot(conn, 1)
            run = create_evaluation_run(conn, 1)
            run_evaluation(conn, run, [_candidate("cpassword", "gpo1")])

            briefing = build_briefing(conn, now=_NOW)
            assert briefing is not None
            assert briefing.is_first_snapshot
            assert briefing.prior_snapshot_id is None
            assert briefing.analysis_complete
        finally:
            conn.close()

    def test_finding_delta_between_runs(self) -> None:
        conn = _db()
        try:
            _snapshot(conn, 1)
            _snapshot(conn, 2)
            run1 = create_evaluation_run(conn, 1)
            run_evaluation(
                conn,
                run1,
                [
                    _candidate("cpassword", "gpo1"),
                    _candidate("ms16_072", "gpo2"),
                ],
            )
            run2 = create_evaluation_run(conn, 2)
            run_evaluation(
                conn,
                run2,
                [
                    _candidate("ms16_072", "gpo2"),
                    _candidate("broken_ref", "gpo3"),
                ],
            )

            briefing = build_briefing(conn, now=_NOW)
            assert briefing is not None
            assert briefing.snapshot_id == 2
            assert briefing.prior_snapshot_id == 1
            assert briefing.findings_new == 1
            assert briefing.findings_resolved == 1
            assert briefing.has_change
        finally:
            conn.close()

    def test_incomplete_run_marks_analysis_degraded(self) -> None:
        conn = _db()
        try:
            _snapshot(conn, 1)
            _snapshot(conn, 2)
            run1 = create_evaluation_run(conn, 1)
            run_evaluation(conn, run1, [_candidate("cpassword", "gpo1")])
            run2 = create_evaluation_run(conn, 2)
            run_evaluation(conn, run2, [_candidate("cpassword", "gpo1")])
            conn.execute(
                "UPDATE evaluation_run SET status = 'failed', "
                "error_summary = 'detector crashed' WHERE id = ?",
                (run2,),
            )
            conn.commit()

            briefing = build_briefing(conn, now=_NOW)
            assert briefing is not None
            assert not briefing.analysis_complete
            assert any("failed" in p for p in briefing.problems)
            assert not any("Since snapshot" in line for line in briefing_lines(briefing))
        finally:
            conn.close()

    def test_coverage_gap_becomes_a_problem(self) -> None:
        conn = _db()
        try:
            _snapshot(conn, 1)
            conn.execute(
                "INSERT INTO coverage_gap (snapshot_id, gpo_id, kind, detail) "
                "VALUES (1, 'gpo9', 'unreadable_sysvol', 'denied')"
            )
            conn.commit()
            run = create_evaluation_run(conn, 1)
            run_evaluation(conn, run, [])

            briefing = build_briefing(conn, now=_NOW)
            assert briefing is not None
            assert any("coverage gap" in p for p in briefing.problems)
            gaps = next(v for v in briefing.vitals if v.key == "coverage_gaps")
            assert gaps.value == 1
            assert gaps.tone == "crit"
        finally:
            conn.close()

    def test_as_of_snapshot_compares_against_its_own_predecessor(self) -> None:
        # Historical selection must diff 2-vs-1, not 2-vs-3: the prior snapshot
        # is the one before the selected snapshot, not the current runner-up.
        conn = _db()
        try:
            for snap in (1, 2, 3):
                _snapshot(conn, snap)
                run = create_evaluation_run(conn, snap)
                findings = {
                    1: [replace(_candidate("cpassword", "gpo1"), severity="critical")],
                    2: [],
                    3: [_candidate("cpassword", "gpo2")],
                }[snap]
                run_evaluation(conn, run, findings)

            latest = build_briefing(conn, now=_NOW)
            assert latest is not None
            assert (latest.snapshot_id, latest.prior_snapshot_id) == (3, 2)

            historical = build_briefing(conn, as_of_snapshot=2, now=_NOW)
            assert historical is not None
            assert (historical.snapshot_id, historical.prior_snapshot_id) == (2, 1)
            assert next(v.value for v in latest.vitals if v.key == "active_findings") == 1
            assert next(v.value for v in historical.vitals if v.key == "active_findings") == 0
            first = build_briefing(conn, as_of_snapshot=1, now=_NOW)
            assert first is not None
            assert next(v.value for v in first.vitals if v.key == "critical_findings") == 1

            assert build_briefing(conn, as_of_snapshot=999, now=_NOW) is None
        finally:
            conn.close()

    def test_expiring_acceptance_surfaces_and_sorts(self) -> None:
        # ``accepted_risk_register`` only considers events at or before *as_of*,
        # and append_triage_event stamps occurred_at from the real clock — so
        # these tests anchor on the wall clock rather than the golden _NOW,
        # which would sit in the past and silently filter every event out.
        now = datetime.now(UTC)
        conn = _db()
        try:
            _snapshot(conn, 1)
            run = create_evaluation_run(conn, 1)
            run_evaluation(
                conn,
                run,
                [
                    _candidate("cpassword", "gpo1"),
                    _candidate("ms16_072", "gpo2"),
                ],
            )
            from gpo_lens.findings import finding_inbox

            occ = [v.occurrence_id for v in finding_inbox(conn)]
            # One already expired, one expiring inside the horizon.
            append_triage_event(
                conn,
                occ[0],
                "accepted_risk",
                "alice",
                rationale="r",
                expires_at=now - timedelta(days=2),
            )
            append_triage_event(
                conn,
                occ[1],
                "accepted_risk",
                "bob",
                rationale="r",
                expires_at=now + timedelta(days=3),
            )

            briefing = build_briefing(conn, now=now + timedelta(seconds=1))
            assert briefing is not None
            assert len(briefing.expiring) == 2
            # Sorted by expiry, so the overdue one leads.
            assert briefing.expiring[0].already_expired
            assert not briefing.expiring[1].already_expired
            # The still-valid acceptance counts as an active accepted risk; the
            # expired one does not.
            accepted = next(v for v in briefing.vitals if v.key == "accepted_risks")
            assert accepted.value == 1
        finally:
            conn.close()

    def test_far_future_acceptance_is_not_surfaced(self) -> None:
        now = datetime.now(UTC)
        conn = _db()
        try:
            _snapshot(conn, 1)
            run = create_evaluation_run(conn, 1)
            run_evaluation(conn, run, [_candidate("cpassword", "gpo1")])
            from gpo_lens.findings import finding_inbox

            occ = finding_inbox(conn)[0].occurrence_id
            append_triage_event(
                conn,
                occ,
                "accepted_risk",
                "alice",
                rationale="r",
                expires_at=now + timedelta(days=365),
            )

            briefing = build_briefing(conn, now=now + timedelta(seconds=1))
            assert briefing is not None
            # Not expiring soon — but it must still be counted as accepted, or
            # this assertion would pass simply because the register was empty.
            assert briefing.expiring == ()
            accepted = next(v for v in briefing.vitals if v.key == "accepted_risks")
            assert accepted.value == 1
        finally:
            conn.close()

    def test_briefing_does_not_rerun_detectors(self, monkeypatch) -> None:
        # The briefing is intended to become the landing page, so it must read
        # materialized state rather than re-evaluating the estate per view.
        conn = _db()
        try:
            _snapshot(conn, 1)
            run = create_evaluation_run(conn, 1)
            run_evaluation(conn, run, [_candidate("cpassword", "gpo1")])

            def fail(*_args: object, **_kwargs: object) -> object:
                raise AssertionError("briefing must not re-run detectors")

            monkeypatch.setattr("gpo_lens.danger.danger_findings", fail)
            monkeypatch.setattr("gpo_lens.queries.estate_doctor", fail)

            assert build_briefing(conn, now=_NOW) is not None
        finally:
            conn.close()
