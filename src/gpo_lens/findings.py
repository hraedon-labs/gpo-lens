"""Finding evaluation, triage, and queries (Plan 024).

This module owns the Plan 024 finding surface: evaluation runs, the
occurrence/observation model, durable finding identity (fingerprints), the
append-only triage event log, and the core queries (``finding_inbox``,
``finding_history``, ``finding_delta``, ``accepted_risk_register``,
``evaluation_runs``). The legacy Plan 023 lifecycle writer (``finding_key``,
``update_finding_lifecycle``) moved to :mod:`gpo_lens._legacy_findings`.

Plan 024 features:

- **Evaluation provenance** — ``evaluation_run`` records track which detector,
  rules, catalogue, comparator, snapshot, and software version produced each
  claim.
- **Occurrence/observation separation** — an occurrence is one continuous
  interval; an observation is presence/absence in one run.
- **Enhanced triage** — risk acceptance with expiry/revocation, deterministic
  fold, append-only events.
- **Core queries** — ``finding_inbox``, ``finding_history``, ``finding_delta``,
  ``accepted_risk_register``, ``evaluation_runs``.

Stable finding key: ``(rule_id, subject_identity)`` where subject identity
reuses the normalized identities (GPO GUID, setting identity, trustee SID, …).
Keys are deterministic and stable across snapshot re-ingest of identical data.

**Single estate per store (WI-1.5).** The lifecycle engine assumes one estate
(one domain's snapshot series) per SQLite database. Finding fingerprints do not
include an estate/domain dimension, so pointing two different domains at the
same ``--db`` would fold their findings into one lifecycle series. Multi-estate
comparison (WI-059) is a separate, post-1.0 concern with its own model.

This module is a core module — no ``narration`` or ``web`` imports.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from gpo_lens.finding_model import (
    FINGERPRINT_VERSION,
    ClaimLevel,
    EvidenceRef,
    FindingCandidate,
    FindingDelta,
    FindingHistory,
    FindingObservation,
    FindingOccurrence,
    FindingView,
    OccurrenceState,
    RiskAcceptance,
    TriageAction,
    TriageEvent,
    TriageStatus,
    compute_fingerprint,
    series_key,
)
from gpo_lens.normalize import parse_dt

if TYPE_CHECKING:
    from gpo_lens.danger import DangerFinding
    from gpo_lens.model import AdmxResolver, Estate
    from gpo_lens.queries._doctor import DoctorFinding


@dataclass(frozen=True)
class FindingRecord:
    """One finding's lifecycle state."""

    id: int
    finding_key: str
    rule_id: str
    subject_identity: str
    severity: str
    summary: str
    detail: str
    remediation: str
    gpo_id: str
    gpo_name: str
    first_seen_snapshot: int
    last_seen_snapshot: int
    resolved_in_snapshot: int | None
    predecessor_id: int | None


def load_active_findings(conn: sqlite3.Connection) -> list[FindingRecord]:
    """Load all active (non-resolved) findings, newest first."""
    rows = conn.execute(
        "SELECT id, finding_key, rule_id, subject_identity, severity, summary, "
        "detail, remediation, "
        "gpo_id, gpo_name, first_seen_snapshot, last_seen_snapshot, "
        "resolved_in_snapshot, predecessor_id "
        "FROM finding WHERE resolved_in_snapshot IS NULL "
        "ORDER BY last_seen_snapshot DESC"
    ).fetchall()
    return [
        FindingRecord(
            id=row[0],
            finding_key=row[1],
            rule_id=row[2],
            subject_identity=row[3],
            severity=row[4],
            summary=row[5],
            detail=row[6],
            remediation=row[7],
            gpo_id=row[8],
            gpo_name=row[9],
            first_seen_snapshot=row[10],
            last_seen_snapshot=row[11],
            resolved_in_snapshot=row[12],
            predecessor_id=row[13],
        )
        for row in rows
    ]


# WI-092: v1 triage statuses mapped onto Plan 024 actions. ``open`` becomes
# ``reopened`` — the v2 action that folds a triaged finding back to open.
_V1_STATUS_TO_ACTION: dict[str, TriageAction] = {
    "open": "reopened",
    "acknowledged": "acknowledged",
    "accepted_risk": "accepted_risk",
}


def load_finding_triage(conn: sqlite3.Connection, finding_id: int) -> list[dict[str, Any]]:
    """Load triage history for a finding (append-only, oldest first).

    WI-092: this is a legacy-shaped projection of the Plan 024
    ``finding_triage_event`` log (the single triage store). The v2 action
    ``reopened`` projects back to the v1 status ``open``; all other actions
    pass through by name — including v2-only actions (``commented``,
    ``risk_acceptance_expired``, ``risk_acceptance_revoked``), so consumers
    expecting strictly v1 statuses (``open``/``acknowledged``/
    ``accepted_risk``) must tolerate the wider vocabulary.
    """
    events = load_triage_events(conn, finding_id)
    return [
        {
            "id": ev.id,
            "status": "open" if ev.action == "reopened" else ev.action,
            "note": ev.note,
            "actor": ev.actor,
            "timestamp": ev.occurred_at.isoformat(),
        }
        for ev in events
    ]


def triage_finding(
    conn: sqlite3.Connection,
    finding_id: int,
    status: str,
    note: str,
    actor: str,
) -> None:
    """Append a triage annotation to a finding.

    Triage is append-only (the provenance instinct applies to local state too):
    each ack/accept-risk/open transition is a new row, never an update-in-place.

    *status* must be one of ``open``, ``acknowledged``, ``accepted_risk``.
    *actor* is the authenticated principal name (from forwarded-user or token).

    WI-092: compatibility shim over the Plan 024 event store — statuses map to
    v2 actions (``open`` -> ``reopened``) and the append lands in
    ``finding_triage_event`` so the v1 and Plan 024 query surfaces can never
    disagree. Accepting risk requires a non-empty note, which doubles as the
    Plan 024-required rationale (``accepted_risk`` without one raises).
    """
    if status not in ("open", "acknowledged", "accepted_risk"):
        raise ValueError(f"invalid triage status: {status!r}")
    note = (note or "")[:2000]
    actor = (actor or "unknown")[:256]

    row = conn.execute(
        "SELECT resolved_run_id, resolved_in_snapshot FROM finding WHERE id = ?",
        (finding_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"finding {finding_id} not found")
    if row[0] is not None or row[1] is not None:
        raise ValueError(f"finding {finding_id} is already resolved")

    action = _V1_STATUS_TO_ACTION[status]
    append_triage_event(
        conn,
        finding_id,
        action,
        actor,
        note=note,
        rationale=note if status == "accepted_risk" else "",
    )


def load_finding_triage_map(
    conn: sqlite3.Connection,
) -> dict[int, dict[str, Any]]:
    """Load the latest triage state for each finding.

    Returns ``{finding_id: {status, note, actor, timestamp}}``.

    WI-092: legacy-shaped projection of the Plan 024 fold
    (:func:`load_triage_status_map`). Occurrence ids are finding ids, so the
    keys are unchanged; only findings with at least one triage event appear.
    """
    return {
        fid: {
            "status": s.status,
            "note": s.note,
            "actor": s.actor,
            "timestamp": s.updated_at.isoformat(),
        }
        for fid, s in load_triage_status_map(conn).items()
    }


# ---------------------------------------------------------------------------
# Plan 024 — Evaluation provenance, lifecycle engine, enhanced triage,
# and core queries.
# ---------------------------------------------------------------------------

_VALID_TRIAGE_ACTIONS: frozenset[str] = frozenset(
    {
        "commented",
        "acknowledged",
        "reopened",
        "accepted_risk",
        "risk_acceptance_expired",
        "risk_acceptance_revoked",
    }
)

# Triage actions that assert something about the finding *beyond this
# evaluation* — a decision the operator expects to still hold next run. These
# are refused on occurrences with no stable subject (Plan 024 §4). ``commented``
# is honestly scoped to the occurrence it is attached to, and the reopen/expiry
# actions must stay available so the expiry sweep can unwind an acceptance
# recorded before the subject became unstable.
_CARRIES_ACROSS_SNAPSHOTS: frozenset[str] = frozenset({"acknowledged", "accepted_risk"})


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Analysis input + evaluation run
# ---------------------------------------------------------------------------


def register_analysis_input(
    conn: sqlite3.Connection,
    kind: str,
    canonical_digest: str,
    version: str = "unknown",
    metadata: dict[str, Any] | None = None,
) -> int:
    """Register or reuse an analysis input (danger rules, ADMX catalogue, etc.).

    Returns the ``analysis_input.id``. If an input with the same kind + digest
    already exists, it is reused (idempotent).
    """
    meta_json = json.dumps(metadata or {}, sort_keys=True)
    conn.execute(
        "INSERT OR IGNORE INTO analysis_input "
        "(kind, canonical_digest, version, metadata_json, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (kind, canonical_digest, version, meta_json, _now_iso()),
    )
    row = conn.execute(
        "SELECT id FROM analysis_input WHERE kind = ? AND canonical_digest = ?",
        (kind, canonical_digest),
    ).fetchone()
    assert row is not None
    return int(row[0])


def create_evaluation_run(
    conn: sqlite3.Connection,
    snapshot_id: int,
    *,
    evaluation_kind: str = "intrinsic",
    detector_set_digest: str = "",
    comparator_input_id: int | None = None,
    application_version: str = "",
    status: str = "completed",
    error_summary: str = "",
) -> int:
    """Create an evaluation run record and return its ``id``.

    The run records *which* snapshot, detector set, comparator, and software
    version produced the findings in this evaluation. This is the provenance
    anchor for all observations and occurrence transitions.

    *status* must be one of ``completed``, ``failed``, ``partial``. Only
    ``completed`` runs resolve absent findings (Plan 024 §7).
    """
    if status not in ("completed", "failed", "partial"):
        raise ValueError(f"invalid run status: {status!r}")
    started = _now_iso()
    cursor = conn.execute(
        "INSERT INTO evaluation_run "
        "(snapshot_id, evaluation_kind, detector_set_digest, "
        "comparator_input_id, application_version, started_at, completed_at, "
        "status, error_summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            snapshot_id,
            evaluation_kind,
            detector_set_digest,
            comparator_input_id,
            application_version,
            started,
            started,
            status,
            error_summary,
        ),
    )
    assert cursor.lastrowid is not None
    conn.commit()
    return cursor.lastrowid


def complete_evaluation_run(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    status: str = "completed",
    error_summary: str = "",
) -> None:
    """Mark an evaluation run as completed (or failed/partial)."""
    if status not in ("completed", "failed", "partial"):
        raise ValueError(f"invalid run status: {status!r}")
    conn.execute(
        "UPDATE evaluation_run SET completed_at = ?, status = ?, error_summary = ? WHERE id = ?",
        (_now_iso(), status, error_summary, run_id),
    )
    conn.commit()


def list_evaluation_runs(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int | None = None,
    series: str | None = None,
) -> list[dict[str, Any]]:
    """List evaluation runs, optionally filtered by snapshot or series key."""
    sql = (
        "SELECT id, snapshot_id, evaluation_kind, detector_set_digest, "
        "comparator_input_id, application_version, started_at, completed_at, "
        "status, error_summary FROM evaluation_run"
    )
    params: list[Any] = []
    clauses: list[str] = []
    if snapshot_id is not None:
        clauses.append("snapshot_id = ?")
        params.append(snapshot_id)
    if series is not None:
        escaped = series.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append("detector_set_digest LIKE ? ESCAPE '\\'")
        params.append(f"%{escaped}%")
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC"
    rows = conn.execute(sql, params).fetchall()
    return [
        {
            "id": r[0],
            "snapshot_id": r[1],
            "evaluation_kind": r[2],
            "detector_set_digest": r[3],
            "comparator_input_id": r[4],
            "application_version": r[5],
            "started_at": r[6],
            "completed_at": r[7],
            "status": r[8],
            "error_summary": r[9],
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Lifecycle engine (Plan 024 §7)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LifecycleResult:
    """Summary of what happened during a Plan 024 lifecycle update."""

    run_id: int
    new_count: int
    persisting_count: int
    resolved_count: int
    regressed_count: int
    indeterminate_count: int
    duplicate_fingerprint_count: int = 0


def absence_is_meaningful(
    gpo_id: str,
    collected_gpo_ids: set[str] | None,
    coverage_complete: bool,
) -> bool:
    """Decide whether a finding's absence from the current scan means resolved.

    Absence only implies resolution when the subject was actually re-evaluated.
    A partial collection (a denied SYSVOL subtree, a per-GPO collection error)
    must never mark a finding *resolved* just because the GPO it belongs to was
    not collected this time — that would silently report a real risk as fixed.
    """
    if coverage_complete:
        return True
    if gpo_id and collected_gpo_ids is not None and gpo_id in collected_gpo_ids:
        return True
    return False


def run_evaluation(
    conn: sqlite3.Connection,
    run_id: int,
    candidates: list[FindingCandidate],
    *,
    collected_gpo_ids: set[str] | None = None,
    coverage_complete: bool = True,
    run_status: str = "completed",
) -> LifecycleResult:
    """Process FindingCandidate records through the Plan 024 lifecycle engine.

    For each candidate (Plan 024 §7):

    1. Compute fingerprint.
    2. Reject duplicate fingerprints within one detector result (detector bug).
    3. Match candidates to open occurrences in the same series.
    4. Append observations and update ``last_seen_run_id``.
    5. Resolve unmatched open occurrences only if the detector completed
       successfully and coverage was sufficient for absence to be meaningful.
    6. Create new occurrences for unmatched candidates, linking a resolved
       predecessor with the same fingerprint as a regression.
    7. Commit evaluation, observations, occurrence transitions in one
       transaction.

    A failed or partial evaluation never resolves unseen findings (AC: "Failed
    or incomplete analysis never implies resolution").
    """
    if run_status not in ("completed", "failed", "partial"):
        raise ValueError(f"invalid run_status: {run_status!r}")

    # Step 1+2: Canonicalize and validate candidates, reject duplicates.
    fingerprint_map: dict[str, FindingCandidate] = {}
    duplicate_count = 0
    for c in candidates:
        fp = compute_fingerprint(c)
        if fp in fingerprint_map:
            duplicate_count += 1
            continue
        fingerprint_map[fp] = c

    warnings: list[str] = []
    if duplicate_count:
        run_status = "partial"
        warnings.append(
            f"Degraded analysis: {duplicate_count} duplicate fingerprint(s); "
            "colliding candidates omitted and unseen findings left unresolved."
        )

    # Load all active (non-resolved) occurrences.
    # NOTE: Each run_evaluation call is expected to include candidates from
    # ALL detector families (see evaluate_finding_lifecycle_v2). Filtering
    # by detector_id here would break the resolution logic — a finding from
    # detector A must be resolved when detector A produces no candidates in
    # this run, even if detector B's candidates are the only ones present.
    active_rows = conn.execute(
        "SELECT id, finding_key, fingerprint_version, series_key, "
        "detector_id, detector_version, rule_id, subject_type, "
        "subject_key_json, first_seen_run_id, last_seen_run_id, "
        "resolved_run_id, predecessor_id, gpo_id "
        "FROM finding WHERE resolved_run_id IS NULL "
        "AND resolved_in_snapshot IS NULL"
    ).fetchall()

    active_by_fp: dict[str, dict[str, Any]] = {}
    for row in active_rows:
        active_by_fp[row[1]] = {
            "id": row[0],
            "fingerprint": row[1],
            "fingerprint_version": row[2],
            "series_key": row[3],
            "detector_id": row[4],
            "detector_version": row[5],
            "category": row[6],
            "subject_type": row[7],
            "subject_key_json": row[8],
            "first_seen_run_id": row[9],
            "last_seen_run_id": row[10],
            "resolved_run_id": row[11],
            "predecessor_id": row[12],
            "gpo_id": row[13],
        }

    # A legacy GPO-wide enforced-link acceptance cannot identify a link.
    # Keep its occurrence/events intact for history; new per-link identities
    # deliberately start open. Do not copy a blanket acceptance onto every link.
    legacy_link_ids: set[int] = set()
    for candidate in fingerprint_map.values():
        if candidate.detector_id == "enforced_link" and candidate.dimensions:
            old_fp = compute_fingerprint(dataclasses.replace(candidate, dimensions=()))
            if old_fp in active_by_fp:
                legacy_link_ids.add(active_by_fp[old_fp]["id"])
    if legacy_link_ids:
        warnings.append(
            "Legacy enforced-link identities replaced by per-link findings. "
            "Prior triage remains in occurrence history; review each new link "
            "before accepting risk. Historical occurrence IDs: "
            + ", ".join(str(oid) for oid in sorted(legacy_link_ids))
        )

    new_count = 0
    persisting_count = 0
    regressed_count = 0

    try:
        # Steps 3-6: Process each candidate.
        for fp, cand in fingerprint_map.items():
            sk = series_key(cand.detector_id, cand.comparator_series)
            subject_key_json = json.dumps(list(cand.subject_key))
            evidence_json = json.dumps(
                [
                    {
                        "snapshot_id": e.snapshot_id,
                        "gpo_id": e.gpo_id,
                        "source": e.source,
                        "field_path": e.field_path,
                        "safe_projection": e.safe_projection[:500],
                    }
                    for e in cand.evidence_refs
                ],
                sort_keys=True,
            )
            compliance_json = json.dumps(list(cand.compliance))
            gpo_id = cand.subject_key[0] if cand.subject_type == "gpo" and cand.subject_key else ""
            # Store the detector's real detail (WI-1.5); fall back to the
            # summary when a candidate carries none, and bound it like the
            # legacy path did so a pathological detector can't bloat the row.
            cand_detail = (cand.detail or cand.summary)[:16_000]

            if fp in active_by_fp:
                # Step 4: Persisting — append observation, update last_seen.
                existing = active_by_fp[fp]
                occ_id = existing["id"]
                conn.execute(
                    "UPDATE finding SET last_seen_run_id = ?, "
                    "last_seen_snapshot = (SELECT snapshot_id FROM "
                    "evaluation_run WHERE id = ?), "
                    "severity = ?, summary = ?, detail = ?, remediation = ? "
                    "WHERE id = ?",
                    (
                        run_id,
                        run_id,
                        cand.severity,
                        cand.summary,
                        cand_detail,
                        cand.remediation,
                        occ_id,
                    ),
                )
                conn.execute(
                    "INSERT INTO finding_observation "
                    "(run_id, occurrence_id, severity, summary, evidence_json, "
                    "claim_level, remediation, compliance_json, gpo_id, gpo_name) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        run_id,
                        occ_id,
                        cand.severity,
                        cand.summary,
                        evidence_json,
                        cand.claim,
                        cand.remediation,
                        compliance_json,
                        gpo_id,
                        cand.gpo_name,
                    ),
                )
                persisting_count += 1
            else:
                # Step 6: New occurrence — check for resolved predecessor.
                predecessor_row = conn.execute(
                    "SELECT id FROM finding WHERE finding_key = ? "
                    "AND (resolved_run_id IS NOT NULL "
                    "OR resolved_in_snapshot IS NOT NULL) "
                    "ORDER BY COALESCE(resolved_run_id, 0) DESC, "
                    "resolved_in_snapshot DESC LIMIT 1",
                    (fp,),
                ).fetchone()
                predecessor_id = predecessor_row[0] if predecessor_row else None
                if predecessor_id is not None:
                    regressed_count += 1

                # Get snapshot_id from the run.
                run_row = conn.execute(
                    "SELECT snapshot_id FROM evaluation_run WHERE id = ?",
                    (run_id,),
                ).fetchone()
                snapshot_id = run_row[0] if run_row else 0

                cursor = conn.execute(
                    "INSERT INTO finding "
                    "(finding_key, rule_id, subject_identity, severity, "
                    "summary, detail, remediation, gpo_id, gpo_name, "
                    "first_seen_snapshot, last_seen_snapshot, "
                    "resolved_in_snapshot, predecessor_id, "
                    "fingerprint_version, series_key, detector_id, "
                    "detector_version, subject_type, subject_key_json, "
                    "first_seen_run_id, last_seen_run_id, resolved_run_id, "
                    "subject_stable) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, "
                    "?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)",
                    (
                        fp,
                        cand.detector_id,
                        gpo_id,
                        cand.severity,
                        cand.summary,
                        cand_detail,
                        cand.remediation,
                        gpo_id,
                        cand.gpo_name,
                        snapshot_id,
                        snapshot_id,
                        predecessor_id,
                        FINGERPRINT_VERSION,
                        sk,
                        cand.detector_id,
                        cand.detector_version,
                        cand.subject_type,
                        subject_key_json,
                        run_id,
                        run_id,
                        int(cand.subject_stable),
                    ),
                )
                occ_id = cursor.lastrowid
                conn.execute(
                    "INSERT INTO finding_observation "
                    "(run_id, occurrence_id, severity, summary, evidence_json, "
                    "claim_level, remediation, compliance_json, gpo_id, gpo_name) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        run_id,
                        occ_id,
                        cand.severity,
                        cand.summary,
                        evidence_json,
                        cand.claim,
                        cand.remediation,
                        compliance_json,
                        gpo_id,
                        cand.gpo_name,
                    ),
                )
                new_count += 1

        # Step 5: Resolve unmatched open occurrences — but only when the
        # run completed successfully and absence is meaningful.
        resolved_count = 0
        indeterminate_count = 0

        if run_status == "completed":
            for fp, existing in active_by_fp.items():
                if fp in fingerprint_map:
                    continue
                if not absence_is_meaningful(
                    existing["gpo_id"], collected_gpo_ids, coverage_complete
                ):
                    indeterminate_count += 1
                    continue
                conn.execute(
                    "UPDATE finding SET resolved_run_id = ?, "
                    "resolved_in_snapshot = (SELECT snapshot_id FROM "
                    "evaluation_run WHERE id = ?) "
                    "WHERE id = ?",
                    (run_id, run_id, existing["id"]),
                )
                resolved_count += 1

        if warnings:
            conn.execute(
                "UPDATE evaluation_run SET status = ?, error_summary = ? WHERE id = ?",
                (run_status, " ".join(warnings), run_id),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return LifecycleResult(
        run_id=run_id,
        new_count=new_count,
        persisting_count=persisting_count,
        resolved_count=resolved_count,
        regressed_count=regressed_count,
        indeterminate_count=indeterminate_count,
        duplicate_fingerprint_count=duplicate_count,
    )


# ---------------------------------------------------------------------------
# Enhanced triage (Plan 024 §8)
# ---------------------------------------------------------------------------


def append_triage_event(
    conn: sqlite3.Connection,
    occurrence_id: int,
    action: TriageAction,
    actor: str,
    *,
    note: str = "",
    rationale: str = "",
    expires_at: datetime | None = None,
    supersedes_event_id: int | None = None,
) -> int:
    """Append a triage event to a finding occurrence.

    Triage is append-only (Plan 024 §8). Each event is a new row; current
    status is a deterministic fold over events (see :func:`fold_triage`).

    *action* must be one of the :data:`TriageAction` literals.
    *actor* is the authenticated principal name.
    *rationale* is required for ``accepted_risk`` (Plan 024 §8: "Accepted risk
    requires actor, rationale, timestamp, and optional expiry").
    *expires_at* is the optional expiry for risk acceptance.
    """
    if action not in _VALID_TRIAGE_ACTIONS:
        raise ValueError(f"invalid triage action: {action!r}")
    if action == "accepted_risk" and not rationale.strip():
        raise ValueError("accepted_risk requires a non-empty rationale")
    if action in _CARRIES_ACROSS_SNAPSHOTS:
        # Plan 024 §4: an occurrence with no stable subject "cannot be
        # acknowledged across snapshots". Its fingerprint moves with the
        # detector's wording, so the next run resolves it and mints a fresh
        # occurrence — and the decision recorded here would silently attach to
        # a finding that no longer exists while the real problem returns as
        # untriaged. Refuse rather than record a decision that will not hold.
        # ``commented`` and the reopen/expiry actions are still allowed: a note
        # is honest about being about this occurrence, and the expiry sweep
        # must be able to unwind whatever already exists.
        row = conn.execute(
            "SELECT subject_stable FROM finding WHERE id = ?", (occurrence_id,)
        ).fetchone()
        if row is not None and not row[0]:
            raise ValueError(
                f"occurrence {occurrence_id} is snapshot_scoped: its subject "
                "cannot be identified across snapshots, so a "
                f"{action!r} decision would not survive the next evaluation. "
                "Give the detector a stable subject_key first."
            )

    note = (note or "")[:2000]
    rationale = (rationale or "")[:2000]
    actor = (actor or "unknown")[:256]
    expires_iso = expires_at.isoformat() if expires_at else None

    cursor = conn.execute(
        "INSERT INTO finding_triage_event "
        "(occurrence_id, action, actor, occurred_at, note, rationale, "
        "expires_at, supersedes_event_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            occurrence_id,
            action,
            actor,
            _now_iso(),
            note,
            rationale,
            expires_iso,
            supersedes_event_id,
        ),
    )
    assert cursor.lastrowid is not None
    conn.commit()
    return cursor.lastrowid


def _utc(value: datetime) -> datetime:
    """Legacy timestamps without an offset are interpreted as UTC."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _parse_dt(text: str | None) -> datetime | None:
    value = parse_dt(text)
    return _utc(value) if value is not None else None


def _triage_order(event: TriageEvent) -> tuple[datetime, bool, int]:
    """Equal-instant removal wins over approval, including migrated approvals.

    IDs remain immutable (supersedes references rely on them). When the clocks
    cannot establish causal order, retain visibility rather than reinstate risk
    acceptance. IDs break ties only within the same precedence class.
    """
    removes_acceptance = event.action in {
        "reopened",
        "risk_acceptance_expired",
        "risk_acceptance_revoked",
    }
    return _utc(event.occurred_at), removes_acceptance, event.id


def fold_triage(events: list[TriageEvent]) -> TriageStatus:
    """Deterministically fold triage events into current status.

    Fold rules (Plan 024 §8):

    - Start: ``open``
    - ``commented`` → no status change (note-only)
    - ``acknowledged`` → ``acknowledged``
    - ``accepted_risk`` → ``accepted_risk`` (captures expiry + rationale)
    - ``reopened`` → ``open``
    - ``risk_acceptance_expired`` → ``open`` (if current was ``accepted_risk``)
    - ``risk_acceptance_revoked`` → ``open`` (if current was ``accepted_risk``)
    """
    status = "open"
    actor = ""
    note = ""
    updated_at = datetime.min.replace(tzinfo=UTC)
    expires_at: datetime | None = None
    rationale = ""

    for ev in sorted(events, key=_triage_order):
        updated_at = _utc(ev.occurred_at)
        actor = ev.actor
        if ev.action == "commented":
            note = ev.note
            continue
        if ev.action == "acknowledged":
            status = "acknowledged"
            note = ev.note
            expires_at = None
            rationale = ""
        elif ev.action == "accepted_risk":
            status = "accepted_risk"
            note = ev.note
            rationale = ev.rationale
            expires_at = _utc(ev.expires_at) if ev.expires_at is not None else None
        elif ev.action == "reopened":
            status = "open"
            note = ev.note
            expires_at = None
            rationale = ""
        elif ev.action in ("risk_acceptance_expired", "risk_acceptance_revoked"):
            if status == "accepted_risk":
                status = "open"
                expires_at = None
                rationale = ""
            note = ev.note

    return TriageStatus(
        status=status,
        actor=actor,
        note=note,
        updated_at=updated_at,
        expires_at=expires_at,
        rationale=rationale,
    )


def load_triage_events(
    conn: sqlite3.Connection,
    occurrence_id: int,
) -> list[TriageEvent]:
    """Load all triage events for an occurrence (oldest first)."""
    rows = conn.execute(
        "SELECT id, occurrence_id, action, actor, occurred_at, note, "
        "rationale, expires_at, supersedes_event_id "
        "FROM finding_triage_event WHERE occurrence_id = ? "
        "ORDER BY occurred_at, id ASC",
        (occurrence_id,),
    ).fetchall()
    return sorted(
        [
            TriageEvent(
                id=r[0],
                occurrence_id=r[1],
                action=r[2],
                actor=r[3],
                occurred_at=_parse_dt(r[4]) or datetime.min.replace(tzinfo=UTC),
                note=r[5],
                rationale=r[6],
                expires_at=_parse_dt(r[7]),
                supersedes_event_id=r[8],
            )
            for r in rows
        ],
        key=_triage_order,
    )


def get_triage_status(
    conn: sqlite3.Connection,
    occurrence_id: int,
) -> TriageStatus:
    """Get the current triage status for an occurrence (deterministic fold)."""
    events = load_triage_events(conn, occurrence_id)
    return fold_triage(events)


def load_triage_status_map(
    conn: sqlite3.Connection,
) -> dict[int, TriageStatus]:
    """Load the current triage status for all occurrences.

    Returns ``{occurrence_id: TriageStatus}``.
    """
    # Single scan of the event log, grouped in Python, instead of one
    # load_triage_events query per occurrence (WI-1.3: kills the N+1 that the
    # accepted-risk register and any status-map consumer paid on large estates).
    rows = conn.execute(
        "SELECT id, occurrence_id, action, actor, occurred_at, note, "
        "rationale, expires_at, supersedes_event_id "
        "FROM finding_triage_event ORDER BY occurrence_id, occurred_at, id ASC"
    ).fetchall()
    events_by_occ: dict[int, list[TriageEvent]] = {}
    for r in rows:
        events_by_occ.setdefault(r[1], []).append(
            TriageEvent(
                id=r[0],
                occurrence_id=r[1],
                action=r[2],
                actor=r[3],
                occurred_at=_parse_dt(r[4]) or datetime.min.replace(tzinfo=UTC),
                note=r[5],
                rationale=r[6],
                expires_at=_parse_dt(r[7]),
                supersedes_event_id=r[8],
            )
        )
    return {occ_id: fold_triage(events) for occ_id, events in events_by_occ.items()}


def expire_risk_acceptances(
    conn: sqlite3.Connection,
    *,
    now: datetime | None = None,
) -> int:
    """Expire risk acceptances whose expiry has passed.

    Appends a ``risk_acceptance_expired`` event to each occurrence whose
    current triage status is ``accepted_risk`` with an ``expires_at`` in the
    past. Returns the number of expirations processed.

    This is the sweep that makes expired risk acceptance re-enter the
    actionable inbox (Plan 024 §8, AC: "Expired risk acceptance re-enters the
    actionable inbox").
    """
    if now is None:
        now = datetime.now(UTC)

    status_map = load_triage_status_map(conn)
    expired_count = 0
    try:
        for occ_id, status in status_map.items():
            if status.status != "accepted_risk":
                continue
            if status.expires_at is None:
                continue
            if status.expires_at > now:
                continue
            conn.execute(
                "INSERT INTO finding_triage_event "
                "(occurrence_id, action, actor, occurred_at, note, rationale, "
                "expires_at, supersedes_event_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    occ_id,
                    "risk_acceptance_expired",
                    "system",
                    _now_iso(),
                    f"Risk acceptance expired at {status.expires_at.isoformat()}",
                    "",
                    None,
                    None,
                ),
            )
            expired_count += 1
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return expired_count


# ---------------------------------------------------------------------------
# Core queries (Plan 024 §9)
# ---------------------------------------------------------------------------

# Latest observation's claim level for an occurrence (observation-level, so not
# a column on finding); used both as a filter and as a select column.
_LATEST_CLAIM_SQ = (
    "(SELECT claim_level FROM finding_observation o "
    "WHERE o.occurrence_id = f.id ORDER BY o.id DESC LIMIT 1)"
)

# Occurrences with no evaluation-run provenance are pre-Plan-024 rows (see the
# WI-1.4 note in ``_inbox_predicate``); every inbox query excludes them.
_INBOX_BASE_WHERE = (
    "f.resolved_run_id IS NULL "
    "AND f.resolved_in_snapshot IS NULL "
    "AND f.first_seen_run_id IS NOT NULL"
)


def _like_escape(term: str) -> str:
    """Escape LIKE wildcards so a search term matches literally.

    Backslash is the ``ESCAPE`` character used by every LIKE in this module, so
    it must be escaped first or it would consume the escapes added after it.
    """
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _inbox_predicate(
    conn: sqlite3.Connection,
    *,
    as_of_run: int | None,
    lifecycle_state: str | None,
    triage_status: str | None,
    category: str | None,
    category_prefix: str | None,
    severity: str | None,
    severities: Sequence[str] | None,
    search: str | None,
    gpo_id: str | None,
    subject_type: str | None,
    claim_level: str | None,
    status_map: dict[int, TriageStatus] | None,
) -> tuple[str, list[Any], dict[int, TriageStatus]]:
    """Build the shared ``WHERE`` fragment for the inbox queries.

    Returns ``(where_sql, params, status_map)``. ``finding_inbox`` and
    ``finding_inbox_count`` both use this so a page of rows and its total can
    never disagree about what "matching" means — the bug that a separately
    hand-written count query invites.

    Every filter lands in SQL, which is what keeps the WI-1.2 guarantee true
    for callers that paginate: ``LIMIT``/``OFFSET`` bound the matching set, not
    a pre-filter superset.
    """
    # Current triage status is a fold over the append-only event log, not a
    # stored column, so resolve it once (batched) and translate the requested
    # triage_status into a pre-LIMIT id-set predicate. "open" is the implicit
    # status of an occurrence with no events, so it filters by *excluding*
    # occurrences whose folded status is non-open.
    resolved_status_map = load_triage_status_map(conn) if status_map is None else status_map

    # WI-1.4: only rows with evaluation-run provenance are v2 findings. Every
    # deployed ingest path (CLI cmd_ingest, web _persist) runs the v2 engine,
    # which always stamps first_seen_run_id; the legacy Plan 023 writer is
    # test-only, so no deployed store holds provenance-less rows. Excluding
    # them keeps a hypothetical pre-lifecycle row from surfacing as a spurious
    # "new" finding with no run history — mixed-mode rows are never silently
    # blended into the v2 inbox.
    clauses: list[str] = [_INBOX_BASE_WHERE]
    params: list[Any] = []

    if as_of_run is not None:
        clauses.append("f.last_seen_run_id = ?")
        params.append(as_of_run)
    if category is not None:
        clauses.append("f.rule_id = ?")
        params.append(category)
    if category_prefix is not None:
        # A category selects itself plus its ``parent:child`` descendants, so
        # picking "delegation" also returns "delegation:excessive_writers".
        clauses.append("(f.rule_id = ? OR f.rule_id LIKE ? ESCAPE '\\')")
        params.extend([category_prefix, _like_escape(category_prefix) + ":%"])
    if severity is not None:
        clauses.append("f.severity = ?")
        params.append(severity)
    if severities:
        placeholders = ",".join("?" * len(severities))
        clauses.append(f"f.severity IN ({placeholders})")
        params.extend(severities)
    if search:
        # SQLite's LIKE is case-insensitive for ASCII, which matches the
        # case-insensitive substring search the page previously did in Python.
        needle = f"%{_like_escape(search)}%"
        clauses.append(
            "(f.gpo_name LIKE ? ESCAPE '\\' "
            "OR f.summary LIKE ? ESCAPE '\\' "
            "OR f.rule_id LIKE ? ESCAPE '\\')"
        )
        params.extend([needle, needle, needle])
    if gpo_id is not None:
        clauses.append("f.gpo_id = ?")
        params.append(gpo_id)
    if subject_type is not None:
        clauses.append("f.subject_type = ?")
        params.append(subject_type)
    # Every run-relative state below is qualified by ``subject_stable = 1``.
    # An occurrence with no stable subject renders as ``snapshot_scoped``, so
    # letting it match ``new`` here would put a row on the page whose displayed
    # state contradicts the filter that selected it — the same page/filter
    # divergence this predicate exists to prevent.
    if lifecycle_state == "new":
        clauses.append("f.subject_stable = 1 AND f.first_seen_run_id = f.last_seen_run_id")
    elif lifecycle_state == "persisting":
        clauses.append("f.subject_stable = 1 AND f.first_seen_run_id < f.last_seen_run_id")
    elif lifecycle_state == "regressed":
        clauses.append("f.subject_stable = 1 AND f.predecessor_id IS NOT NULL")
    elif lifecycle_state == "snapshot_scoped":
        clauses.append("f.subject_stable = 0")
    elif lifecycle_state == "new_or_regressed":
        # Plan 025 WI-1's actionable default: first appearance, or a
        # reappearance after being resolved. A regression is actionable even
        # when it has been observed across several runs since returning.
        clauses.append(
            "f.subject_stable = 1 "
            "AND (f.first_seen_run_id = f.last_seen_run_id "
            "OR f.predecessor_id IS NOT NULL)"
        )
    if claim_level is not None:
        clauses.append(f"COALESCE({_LATEST_CLAIM_SQ}, 'confirmed') = ?")
        params.append(claim_level)
    if triage_status is not None:
        if triage_status == "open":
            non_open = [oid for oid, ts in resolved_status_map.items() if ts.status != "open"]
            if non_open:
                ph = ",".join("?" * len(non_open))
                clauses.append(f"f.id NOT IN ({ph})")
                params.extend(non_open)
        else:
            matching = [
                oid for oid, ts in resolved_status_map.items() if ts.status == triage_status
            ]
            if matching:
                ph = ",".join("?" * len(matching))
                clauses.append(f"f.id IN ({ph})")
                params.extend(matching)
            else:
                # No occurrence holds this status → empty result set.
                clauses.append("0")

    return " WHERE " + " AND ".join(clauses), params, resolved_status_map


def finding_inbox_categories(conn: sqlite3.Connection) -> list[tuple[str, int]]:
    """Rule-id facet counts over every active occurrence, sorted by rule id.

    Deliberately unfiltered: the category picker must show what the operator
    could select next, not only what survives the filters already applied.
    Summing the counts also gives the unfiltered active total, so the page gets
    both from one scan.
    """
    rows = conn.execute(
        f"SELECT f.rule_id, COUNT(*) FROM finding f WHERE {_INBOX_BASE_WHERE} "
        "GROUP BY f.rule_id ORDER BY f.rule_id"
    ).fetchall()
    return [(str(r[0]), int(r[1])) for r in rows]


def finding_inbox_count(
    conn: sqlite3.Connection,
    *,
    as_of_run: int | None = None,
    lifecycle_state: str | None = None,
    triage_status: str | None = None,
    category: str | None = None,
    category_prefix: str | None = None,
    severity: str | None = None,
    severities: Sequence[str] | None = None,
    search: str | None = None,
    gpo_id: str | None = None,
    subject_type: str | None = None,
    claim_level: str | None = None,
    status_map: dict[int, TriageStatus] | None = None,
) -> int:
    """Count the occurrences ``finding_inbox`` would return, ignoring limits.

    Shares ``_inbox_predicate`` with ``finding_inbox``, so this is the true
    total for the same filters — what a paginating caller needs in order to
    show a page count without loading every row.

    Pass *status_map* (from ``load_triage_status_map``) to reuse one triage
    fold across this call and the matching ``finding_inbox`` call.
    """
    where, params, _ = _inbox_predicate(
        conn,
        as_of_run=as_of_run,
        lifecycle_state=lifecycle_state,
        triage_status=triage_status,
        category=category,
        category_prefix=category_prefix,
        severity=severity,
        severities=severities,
        search=search,
        gpo_id=gpo_id,
        subject_type=subject_type,
        claim_level=claim_level,
        status_map=status_map,
    )
    row = conn.execute(f"SELECT COUNT(*) FROM finding f{where}", params).fetchone()
    return int(row[0]) if row else 0


def finding_inbox(
    conn: sqlite3.Connection,
    *,
    as_of_run: int | None = None,
    lifecycle_state: str | None = None,
    triage_status: str | None = None,
    category: str | None = None,
    category_prefix: str | None = None,
    severity: str | None = None,
    severities: Sequence[str] | None = None,
    search: str | None = None,
    gpo_id: str | None = None,
    subject_type: str | None = None,
    claim_level: str | None = None,
    limit: int = 500,
    offset: int = 0,
    status_map: dict[int, TriageStatus] | None = None,
) -> list[FindingView]:
    """Query the finding inbox with filters (Plan 024 §9).

    Returns active (non-resolved) findings by default, with their current
    triage status. Filters narrow by lifecycle state, triage status, category,
    severity, GPO, subject type, and claim level.

    *as_of_run* limits to findings observed in the given evaluation run.

    *lifecycle_state* accepts ``new``, ``persisting``, ``regressed``,
    ``new_or_regressed`` (Plan 025 WI-1's actionable default), and
    ``snapshot_scoped`` (occurrences with no stable subject, which the
    run-relative states deliberately exclude).

    *category* matches a rule id exactly; *category_prefix* also matches its
    ``parent:child`` descendants. *severity* matches one severity;
    *severities* matches any in the sequence. *search* is a case-insensitive
    substring match over GPO name, summary, and rule id.

    All filters — including ``claim_level``, ``triage_status``, and ``search``
    — are applied in SQL *before* ``LIMIT``/``OFFSET`` (WI-1.2), so a filtered
    page can never silently truncate: the bounds apply to the matching set, not
    a pre-filter superset. Pair with ``finding_inbox_count`` for the total.

    Pass *status_map* (from ``load_triage_status_map``) to reuse one triage fold
    across this call and a matching ``finding_inbox_count`` call.
    """
    where, params, resolved_status_map = _inbox_predicate(
        conn,
        as_of_run=as_of_run,
        lifecycle_state=lifecycle_state,
        triage_status=triage_status,
        category=category,
        category_prefix=category_prefix,
        severity=severity,
        severities=severities,
        search=search,
        gpo_id=gpo_id,
        subject_type=subject_type,
        claim_level=claim_level,
        status_map=status_map,
    )

    sql = (
        "SELECT f.id, f.finding_key, f.detector_id, f.rule_id, "
        "f.severity, f.summary, f.detail, f.remediation, "
        "f.gpo_id, f.gpo_name, f.subject_type, f.subject_key_json, "
        "f.first_seen_run_id, f.last_seen_run_id, f.resolved_run_id, "
        "f.predecessor_id, "
        f"COALESCE({_LATEST_CLAIM_SQ}, 'confirmed') AS claim_level, "
        "f.subject_stable "
        "FROM finding f" + where
    )
    # ``f.id`` is the tiebreaker so the order is total, not merely sorted —
    # OFFSET paging over a partial order can repeat or skip rows between pages.
    sql += (
        " ORDER BY CASE f.severity WHEN 'critical' THEN 0"
        " WHEN 'high' THEN 1 WHEN 'medium' THEN 2"
        " WHEN 'low' THEN 3 ELSE 4 END, f.rule_id, f.id LIMIT ? OFFSET ?"
    )
    params.extend([limit, max(0, offset)])

    rows = conn.execute(sql, params).fetchall()

    views: list[FindingView] = []
    for r in rows:
        occ_id = r[0]
        c_level = r[16] or "confirmed"

        ts = resolved_status_map.get(occ_id)
        t_status = ts.status if ts else "open"
        t_actor = ts.actor if ts else ""
        t_note = ts.note if ts else ""
        t_expires = ts.expires_at if ts else None

        subject_key = tuple(json.loads(r[11])) if r[11] else ()

        first_run = r[12] or 0
        last_run = r[13] or 0
        lc_state: OccurrenceState
        if not r[17]:
            # No stable subject to key on, so "new" and "persisting" would both
            # be assertions the data cannot support — the fingerprint moves
            # with the wording. Report the honest state instead (Plan 024 §4).
            lc_state = "snapshot_scoped"
        elif first_run == last_run:
            lc_state = "new"
        else:
            lc_state = "persisting"

        views.append(
            FindingView(
                occurrence_id=occ_id,
                fingerprint=r[1],
                detector_id=r[2] or r[1][:8],
                category=r[3],
                severity=r[4],
                summary=r[5],
                detail=r[6] or r[5],
                remediation=r[7] or "",
                gpo_id=r[8],
                gpo_name=r[9],
                subject_type=r[10] or "",
                subject_key=subject_key,
                claim_level=c_level,  # type: ignore[arg-type]
                lifecycle_state=lc_state,
                triage_status=t_status,
                triage_actor=t_actor,
                triage_note=t_note,
                triage_expires_at=t_expires,
                first_seen_run_id=r[12] or 0,
                last_seen_run_id=r[13] or 0,
                resolved_run_id=r[14],
                predecessor_id=r[15],
                compliance=(),
            )
        )

    return views


def finding_history(
    conn: sqlite3.Connection,
    occurrence_id: int,
) -> FindingHistory:
    """Get the full history of a finding occurrence (Plan 024 §9).

    Returns the occurrence record, all observations, and all triage events.
    """
    row = conn.execute(
        "SELECT id, finding_key, fingerprint_version, series_key, "
        "detector_id, detector_version, rule_id, subject_type, "
        "subject_key_json, first_seen_run_id, last_seen_run_id, "
        "resolved_run_id, predecessor_id "
        "FROM finding WHERE id = ?",
        (occurrence_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"Occurrence {occurrence_id} not found")

    occurrence = FindingOccurrence(
        id=row[0],
        fingerprint=row[1],
        fingerprint_version=row[2],
        series_key=row[3],
        detector_id=row[4],
        detector_version=row[5],
        category=row[6],
        subject_type=row[7],
        subject_key=tuple(json.loads(row[8])) if row[8] else (),
        first_seen_run_id=row[9] or 0,
        last_seen_run_id=row[10] or 0,
        resolved_run_id=row[11],
        predecessor_id=row[12],
    )

    obs_rows = conn.execute(
        "SELECT run_id, occurrence_id, severity, summary, evidence_json, "
        "claim_level, remediation, compliance_json "
        "FROM finding_observation WHERE occurrence_id = ? "
        "ORDER BY id ASC",
        (occurrence_id,),
    ).fetchall()
    observations = tuple(
        FindingObservation(
            run_id=r[0],
            occurrence_id=r[1],
            severity=r[2],
            summary=r[3],
            evidence_json=r[4],
            claim_level=r[5],
            remediation=r[6],
            compliance_json=r[7],
        )
        for r in obs_rows
    )

    triage_events = tuple(load_triage_events(conn, occurrence_id))

    return FindingHistory(
        occurrence=occurrence,
        observations=observations,
        triage_events=triage_events,
    )


def finding_observation_history(
    conn: sqlite3.Connection,
    occurrence_id: int,
) -> list[dict[str, Any]]:
    """Observations of an occurrence, each with its evaluation run's provenance.

    ``finding_history`` returns observations alone, which cannot answer "did the
    finding change, or did the rules change?" — the question the occurrence view
    exists to settle. Joining ``evaluation_run`` attaches the detector-set
    digest, comparator input, application version, and run status to each
    observation, so a severity or claim change can be attributed to the estate
    or to a detector revision.

    Oldest run first. Evidence is returned parsed and already bounded by the
    ``safe_projection`` cap applied at write time.
    """
    rows = conn.execute(
        "SELECT o.run_id, o.severity, o.summary, o.evidence_json, "
        "o.claim_level, o.remediation, o.compliance_json, "
        "r.evaluation_kind, r.detector_set_digest, r.comparator_input_id, "
        "r.application_version, r.started_at, r.completed_at, r.status, "
        "r.error_summary, r.snapshot_id "
        "FROM finding_observation o "
        "JOIN evaluation_run r ON r.id = o.run_id "
        "WHERE o.occurrence_id = ? ORDER BY o.run_id ASC, o.id ASC",
        (occurrence_id,),
    ).fetchall()
    history: list[dict[str, Any]] = []
    for r in rows:
        history.append(
            {
                "run_id": r[0],
                "severity": r[1],
                "summary": r[2],
                "evidence": _safe_json_list(r[3]),
                "claim_level": r[4],
                "remediation": r[5],
                "compliance": _safe_json_list(r[6]),
                "evaluation_kind": r[7],
                "detector_set_digest": r[8] or "",
                "comparator_input_id": r[9],
                "application_version": r[10] or "",
                "started_at": r[11] or "",
                "completed_at": r[12] or "",
                "status": r[13] or "",
                "error_summary": r[14] or "",
                "snapshot_id": r[15],
            }
        )
    return history


def _safe_json_list(raw: str | None) -> list[Any]:
    """Parse a JSON list column, tolerating NULL and malformed content.

    A single unparseable evidence blob must not take down the occurrence page —
    the rest of the history is still worth showing.
    """
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


def finding_delta(
    conn: sqlite3.Connection,
    run_a: int,
    run_b: int,
) -> FindingDelta:
    """Compute the difference between two evaluation runs (Plan 024 §9).

    Returns fingerprints that are new, resolved, persisting, or regressed
    between run_a (earlier) and run_b (later).
    """
    # Occurrence IDs observed in each run.
    run_a_occ_ids = {
        r[0]
        for r in conn.execute(
            "SELECT occurrence_id FROM finding_observation WHERE run_id = ?",
            (run_a,),
        ).fetchall()
    }
    run_b_occ_ids = {
        r[0]
        for r in conn.execute(
            "SELECT occurrence_id FROM finding_observation WHERE run_id = ?",
            (run_b,),
        ).fetchall()
    }

    # Map occurrence_id → fingerprint.
    all_occ_ids = run_a_occ_ids | run_b_occ_ids
    if not all_occ_ids:
        return FindingDelta(
            new_fingerprints=(),
            resolved_fingerprints=(),
            persisting_fingerprints=(),
            regressed_fingerprints=(),
        )
    placeholders = ",".join("?" * len(all_occ_ids))
    fp_map = {
        r[0]: r[1]
        for r in conn.execute(
            f"SELECT id, finding_key FROM finding WHERE id IN ({placeholders})",
            list(all_occ_ids),
        ).fetchall()
    }

    a_fps = {fp_map[oid] for oid in run_a_occ_ids if oid in fp_map}
    b_fps = {fp_map[oid] for oid in run_b_occ_ids if oid in fp_map}

    new = tuple(sorted(b_fps - a_fps))
    resolved = tuple(sorted(a_fps - b_fps))
    persisting = tuple(sorted(a_fps & b_fps))

    # Regressed: new in run_b (not in run_a) but the occurrence has a
    # resolved predecessor — meaning it was resolved then reappeared.
    regressed: list[str] = []
    for oid in run_b_occ_ids:
        if oid not in fp_map:
            continue
        fp = fp_map[oid]
        if fp in a_fps:
            continue
        row = conn.execute(
            "SELECT predecessor_id FROM finding WHERE id = ?",
            (oid,),
        ).fetchone()
        if row and row[0] is not None:
            regressed.append(fp)

    return FindingDelta(
        new_fingerprints=new,
        resolved_fingerprints=resolved,
        persisting_fingerprints=persisting,
        regressed_fingerprints=tuple(sorted(regressed)),
    )


def accepted_risk_register(
    conn: sqlite3.Connection,
    *,
    as_of: datetime | None = None,
) -> list[RiskAcceptance]:
    """List all risk acceptances (active and expired) as of a point in time.

    Plan 024 §9: ``accepted_risk_register(as_of) -> list[RiskAcceptance]``.
    """
    if as_of is None:
        as_of = datetime.now(UTC)

    rows = conn.execute(
        "SELECT e.id, e.occurrence_id, e.action, e.actor, e.occurred_at, "
        "e.note, e.rationale, e.expires_at, e.supersedes_event_id, "
        "f.finding_key, f.rule_id, f.severity, f.summary "
        "FROM finding_triage_event e "
        "JOIN finding f ON f.id = e.occurrence_id "
        "ORDER BY e.occurrence_id, e.occurred_at, e.id"
    ).fetchall()
    events_by_occurrence: dict[int, list[tuple[TriageEvent, tuple[Any, ...]]]] = {}
    for row in rows:
        event = TriageEvent(
            id=row[0],
            occurrence_id=row[1],
            action=row[2],
            actor=row[3],
            occurred_at=_parse_dt(row[4]) or datetime.min.replace(tzinfo=UTC),
            note=row[5],
            rationale=row[6],
            expires_at=_parse_dt(row[7]),
            supersedes_event_id=row[8],
        )
        if event.occurred_at <= as_of:
            events_by_occurrence.setdefault(event.occurrence_id, []).append((event, row[9:13]))

    result: list[RiskAcceptance] = []
    for occ_id, event_rows in events_by_occurrence.items():
        accepted_ev: TriageEvent | None = None
        revoked_ev: TriageEvent | None = None
        explicitly_expired = False
        finding_row: tuple[Any, ...] | None = None
        for ev, details in sorted(event_rows, key=lambda row: _triage_order(row[0])):
            if ev.action == "accepted_risk":
                accepted_ev = ev
                revoked_ev = None
                explicitly_expired = False
                finding_row = details
            elif ev.action == "risk_acceptance_revoked":
                if accepted_ev is not None:
                    revoked_ev = ev
            elif ev.action == "reopened":
                # A reopen after an active acceptance cancels it (fold_triage
                # returns the finding to "open"); record the revocation so the
                # register shows a cancelled acceptance rather than a live one.
                if accepted_ev is not None:
                    revoked_ev = ev
            elif ev.action == "risk_acceptance_expired" and accepted_ev is not None:
                explicitly_expired = True

        if accepted_ev is None or finding_row is None:
            continue

        is_expired = explicitly_expired or (
            accepted_ev.expires_at is not None and accepted_ev.expires_at <= as_of
        )

        result.append(
            RiskAcceptance(
                occurrence_id=occ_id,
                fingerprint=finding_row[0],
                category=finding_row[1],
                severity=finding_row[2],
                summary=finding_row[3] or finding_row[2],
                actor=accepted_ev.actor,
                rationale=accepted_ev.rationale,
                accepted_at=accepted_ev.occurred_at,
                expires_at=accepted_ev.expires_at,
                is_expired=is_expired,
                revoked_at=revoked_ev.occurred_at if revoked_ev else None,
                revoked_by=revoked_ev.actor if revoked_ev else "",
            )
        )

    return result


def evaluation_runs(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int | None = None,
    series_key: str | None = None,
) -> list[dict[str, Any]]:
    """List evaluation runs, optionally filtered (Plan 024 §9).

    ``evaluation_runs(snapshot_id | series_key) -> list[EvaluationRun]``.
    """
    return list_evaluation_runs(
        conn,
        snapshot_id=snapshot_id,
        series=series_key,
    )


# ---------------------------------------------------------------------------
# Detector adapter — convert existing detectors to FindingCandidate (Plan 024 §10)
# ---------------------------------------------------------------------------


def _doctor_finding_to_candidate(
    f: DoctorFinding,
    snapshot_id: int,
) -> FindingCandidate:
    """Convert a ``DoctorFinding`` to a ``FindingCandidate``.

    The adapter maps the existing detector output to the Plan 024 protocol:

    - ``detector_id``: the finding category (e.g. ``cpassword``, ``ms16_072``)
    - ``subject_type``: ``"gpo"`` for GPO-scoped findings, ``"estate"`` for
      estate-level findings (empty ``gpo_id``)
    - ``subject_key``: ``(gpo_id,)`` for GPO findings, or the declared
      ``subject_key`` tuple for estate-level findings
    - ``dimensions``: identity-bearing fields that distinguish multiple
      findings on the same subject (e.g. side, ref_type, file path)
    - ``claim``: ``"confirmed"`` for directly observed findings,
      ``"probable"`` for inferred structural findings
    """
    gpo_id = getattr(f, "gpo_id", "") or ""
    declared_sk = getattr(f, "subject_key", ()) or ()

    # A GPO-scoped finding's subject is the GPO GUID; any extra identity
    # (a coverage gap's kind, etc.) rides in ``dimensions`` so ``gpo_id`` can
    # be recovered from ``subject_key[0]`` downstream. Estate-scoped findings
    # (no GPO) carry their full identity in the declared ``subject_key``.
    # A GPO-less finding that declares no subject_key leaves the prose summary
    # as the only thing to key on, so its fingerprint moves whenever the
    # wording does — the WI-1.1 failure class, one layer up in ``subject_key``
    # rather than in ``dimensions``. Every deployed detector declares a subject
    # (locked by test_doctor_contract.py), so this is a guard against a future
    # one forgetting, not a live path. Keep the prose key so the finding is
    # still reported, but mark it unstable: Plan 024 §4 says such findings are
    # ``snapshot_scoped`` and cannot be tracked across snapshots, and saying so
    # beats presenting a churning identity as a genuine new/persisting finding.
    subject_stable = True
    if gpo_id:
        subject_type = "gpo"
        subject_key: tuple[str, ...] = (gpo_id,)
    elif declared_sk:
        subject_type = "estate"
        subject_key = declared_sk
    else:
        subject_type = "estate"
        subject_key = (getattr(f, "summary", ""),)
        subject_stable = False

    # Identity-bearing dimensions are declared by the detector as typed
    # key/value pairs (WI-1.1) — never parsed out of the prose summary/detail,
    # which can change between observations without changing identity.
    dims: list[tuple[str, str]] = [
        (str(k), str(v)) for k, v in (getattr(f, "dimensions", ()) or ())
    ]
    summary = getattr(f, "summary", "") or ""
    category = getattr(f, "category", "") or ""

    # Evidence reference (safe projection — no raw secrets).
    evidence = (
        EvidenceRef(
            snapshot_id=snapshot_id,
            gpo_id=gpo_id,
            source="estate_doctor",
            field_path=category,
            safe_projection=summary[:200],
        ),
    )

    compliance = getattr(f, "compliance", ()) or ()
    compliance_tuples = tuple((c.framework, c.control_id) for c in compliance) if compliance else ()

    # Claim level: directly observed = confirmed, inferred = probable.
    confirmed_categories = frozenset(
        {
            "cpassword",
            "ms16_072",
            "version_skew",
            "dangling_link",
            "disabled_but_populated",
            "unlinked",
            "empty",
            "enforced_link",
            "coverage_gap",
            "broken_wmi_ref",
            "orphaned_wmi_filter",
            "ilt_gpo",
            "stale_gpo",
            "admx_gap",
        }
    )
    probable_categories = frozenset(
        {
            "deny_ace",
            "excessive_writer",
            "topology_discrepancy",
        }
    )
    if category in confirmed_categories or category.startswith("broken_ref:"):
        claim: ClaimLevel = "confirmed"
    elif category in probable_categories:
        claim = "probable"
    elif category.startswith("danger:"):
        claim = "probable"
    else:
        claim = "possible"

    return FindingCandidate(
        detector_id=category,
        detector_version="1",
        category=category,
        severity=getattr(f, "severity", "info"),
        subject_type=subject_type,
        subject_key=subject_key,
        dimensions=tuple(dims),
        summary=summary,
        detail=getattr(f, "detail", "") or "",
        evidence_refs=evidence,
        claim=claim,
        remediation=getattr(f, "remediation", "") or "",
        compliance=compliance_tuples,
        gpo_name=getattr(f, "gpo_name", "") or "",
        subject_stable=subject_stable,
    )


def _danger_finding_to_candidate(
    f: DangerFinding,
    snapshot_id: int,
) -> FindingCandidate:
    """Convert a ``DangerFinding`` to a ``FindingCandidate``."""
    gpo_id = getattr(f, "gpo_id", "") or ""
    check_id = getattr(f, "check_id", "") or ""
    category = f"danger:{check_id}"

    if gpo_id:
        subject_type = "gpo"
        subject_key: tuple[str, ...] = (gpo_id,)
    else:
        subject_type = "estate"
        subject_key = (check_id,)

    title = getattr(f, "title", "") or ""

    # Identity-bearing dimensions are declared by the detector as typed
    # key/value pairs (WI-1.1) — e.g. the trustee/owner SID that distinguishes
    # multiple non-admin writers on one GPO — never parsed from prose.
    dims: list[tuple[str, str]] = [
        (str(k), str(v)) for k, v in (getattr(f, "dimensions", ()) or ())
    ]

    evidence = (
        EvidenceRef(
            snapshot_id=snapshot_id,
            gpo_id=gpo_id,
            source="danger_detector",
            field_path=check_id,
            safe_projection=title[:200],
        ),
    )

    compliance = getattr(f, "compliance", ()) or ()
    compliance_tuples = tuple((c.framework, c.control_id) for c in compliance) if compliance else ()

    return FindingCandidate(
        detector_id=category,
        detector_version="1",
        category=category,
        severity=getattr(f, "severity", "medium"),
        subject_type=subject_type,
        subject_key=subject_key,
        dimensions=tuple(dims),
        summary=title,
        detail=getattr(f, "detail", "") or "",
        evidence_refs=evidence,
        claim="probable",
        remediation=getattr(f, "remediation", "") or "",
        compliance=compliance_tuples,
        gpo_name=getattr(f, "gpo_name", "") or "",
    )


def candidates_from_estate(
    estate: Estate,
    *,
    snapshot_id: int = 0,
    admx: AdmxResolver | None = None,
) -> list[FindingCandidate]:
    """Run intrinsic detectors and convert to FindingCandidate records.

    This is the Plan 024 adapter for the existing intrinsic detector family
    (Plan 024 §10.2: "Adapt one narrow intrinsic detector family and qualify
    lifecycle behavior"). It runs the estate doctor + danger detectors and
    converts each finding to a ``FindingCandidate`` with declared identity
    dimensions.

    The adapter documents:

    - **Subject key:** GPO GUID for GPO-scoped findings; declared subject_key
      tuple for estate-level findings.
    - **Dimensions:** identity-bearing fields (side, ref_value, trustee SID)
      that distinguish multiple findings on the same subject.
    - **Rule versioning:** ``detector_version="1"`` for all intrinsic
      detectors. A future rule-semantics change bumps the version and must
      declare whether it continues the old lifecycle series or starts a new
      one.
    - **Evidence projection:** summary text truncated to 200 chars; no raw
      cpassword values, SDDL strings, or credentials stored.
    - **Coverage requirements:** absence is meaningful only when the subject
      GPO was actually re-collected (handled by ``run_evaluation``).
    """
    from gpo_lens.danger import danger_findings
    from gpo_lens.queries import estate_doctor

    danger = danger_findings(estate, admx=admx)
    doctor_findings = estate_doctor(estate, admx=admx, danger=danger)

    candidates: list[FindingCandidate] = []
    for doc_f in doctor_findings:
        # ``estate_doctor`` re-wraps every DangerFinding as a DoctorFinding for
        # its own display list, and that wrapper carries neither the danger
        # finding's ``dimensions`` nor a ``subject_key``. Converting those
        # wrappers too produced a *second* candidate for the same real problem,
        # with a different fingerprint, so one finding became two occurrences:
        #
        #   - GPO-scoped: the wrapper lost ``dimensions``, so two non-admin
        #     writers on one GPO collapsed to one loosely-keyed occurrence
        #     alongside the correctly-keyed pair.
        #   - Estate-scoped (``absent`` rules, gpo_id ""): the wrapper had no
        #     subject at all, so the copy keyed on the rule *title* — prose,
        #     churning on every rewording.
        #
        # The danger family is converted below from the DangerFinding itself,
        # which keeps its dimensions and keys on check_id. Skip the wrappers
        # rather than making both paths agree by coincidence of fingerprint.
        if doc_f.category.startswith("danger:"):
            continue
        candidates.append(_doctor_finding_to_candidate(doc_f, snapshot_id))
    for dang_f in danger:
        candidates.append(_danger_finding_to_candidate(dang_f, snapshot_id))

    return candidates


def evaluate_finding_lifecycle_v2(
    conn: sqlite3.Connection,
    snapshot_id: int,
    estate: Estate,
    *,
    admx: AdmxResolver | None = None,
    application_version: str = "",
) -> LifecycleResult:
    """Run the Plan 024 evaluation pipeline end-to-end.

    This is the single ingest-time evaluation path for the Plan 024 model.
    It:

    1. Creates an evaluation run (recording snapshot, detector set, version).
    2. Runs intrinsic detectors and converts to FindingCandidate records.
    3. Processes candidates through the lifecycle engine.
    4. Returns the lifecycle result.

    The v2 path is additive — it writes both the old columns
    (for backward compatibility with the existing web UI) and the new
    columns (for Plan 024 queries). The legacy Plan 023 writer
    (``update_finding_lifecycle``) now lives in
    :mod:`gpo_lens._legacy_findings` and is test-only.
    """
    candidates = candidates_from_estate(
        estate,
        snapshot_id=snapshot_id,
        admx=admx,
    )

    detector_set_digest = hashlib.sha256(
        "|".join(sorted({c.detector_id for c in candidates})).encode()
    ).hexdigest()[:16]

    run_id = create_evaluation_run(
        conn,
        snapshot_id,
        evaluation_kind="intrinsic",
        detector_set_digest=detector_set_digest,
        application_version=application_version,
        status="partial",
    )

    try:
        result = run_evaluation(
            conn,
            run_id,
            candidates,
            collected_gpo_ids={g.id for g in estate.gpos},
            coverage_complete=not estate.coverage_gaps,
        )
        warning_row = conn.execute(
            "SELECT error_summary FROM evaluation_run WHERE id = ?", (run_id,)
        ).fetchone()
        complete_evaluation_run(
            conn,
            run_id,
            status="partial" if result.duplicate_fingerprint_count else "completed",
            error_summary=warning_row[0] if warning_row else "",
        )
    except Exception:
        complete_evaluation_run(
            conn,
            run_id,
            status="failed",
            error_summary="evaluation run failed",
        )
        raise
    return result
