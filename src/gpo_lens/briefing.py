"""Deterministic estate briefing (Plan 025 WI-2).

Answers one operator question — *do I need to care today?* — as typed facts plus
deterministic prose. This is **not** Tier 3 narration: no model is involved, the
sentences come from formatters over the facts, and the same inputs always
produce byte-identical output. That is what makes the briefing golden-testable.

Two deliberate design constraints:

**No detector re-runs.** Every number here comes from materialized lifecycle and
snapshot tables, not from re-evaluating the estate. The dashboard re-runs
``danger_findings`` and ``estate_doctor`` on each page view; the briefing must
not, because it is intended to become the landing page.

**No links in the core.** This module is a core module (no ``web`` imports), so
vitals carry a stable *key* rather than a URL and the template maps keys to
routes. Plan 025 WI-2 forbids an unlinked stat tile; keeping the key here and the
href there means the web layer cannot render a tile it has no destination for.

Honesty rules the plan calls out explicitly:

- With one snapshot there is no delta, so the briefing says so rather than
  implying a clean comparison against nothing.
- When the latest evaluation did not complete, the briefing reports the analysis
  as incomplete instead of presenting its partial counts as a clean delta.
- Coverage and provenance problems are ordered *before* favorable counts, so a
  reassuring "3 resolved" can never appear above the reason it is untrustworthy.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from gpo_lens.finding_model import RiskAcceptance

# An acceptance expiring within this window is worth surfacing on the briefing;
# past it, the accepted-risk register is the right place to look.
EXPIRY_HORIZON = timedelta(days=14)

# Vital keys the template must know how to link. Kept here so a new vital
# cannot be added without the web layer being told where it points.
VITAL_KEYS = (
    "active_findings",
    "critical_findings",
    "coverage_gaps",
    "gpo_count",
    "accepted_risks",
)


@dataclass(frozen=True)
class BriefingVital:
    """One linked estate vital. *key* names the destination, not the URL."""

    key: str
    label: str
    value: int
    tone: str  # "crit" | "warn" | "info" | "muted"


@dataclass(frozen=True)
class ExpiringAcceptance:
    """An accepted-risk decision at or near the end of its life."""

    occurrence_id: int
    category: str
    summary: str
    severity: str
    actor: str
    expires_at: datetime
    already_expired: bool


@dataclass(frozen=True)
class SnapshotFreshness:
    """Newest import age; unknown/future timestamps cannot establish freshness."""

    snapshot_id: int
    taken_at: datetime | None
    age_seconds: int | None
    stale_after_days: int
    is_stale: bool

    @property
    def description(self) -> str:
        if self.age_seconds is None:
            return (
                f"Newest snapshot #{self.snapshot_id} freshness cannot be verified; "
                "check its timestamp and the collector clock."
            )
        days, remainder = divmod(self.age_seconds, 86400)
        hours = remainder // 3600
        age = _count(days, "day") if days else _count(hours, "hour")
        return (
            f"Newest snapshot #{self.snapshot_id} is {age} old "
            f"(warning threshold: {self.stale_after_days} days)."
        )


@dataclass(frozen=True)
class Briefing:
    """Typed briefing facts. Prose is derived, never stored."""

    domain: str
    snapshot_id: int
    snapshot_taken_at: datetime | None
    prior_snapshot_id: int | None
    is_first_snapshot: bool

    analysis_complete: bool
    problems: tuple[str, ...]

    gpos_added: int
    gpos_removed: int
    gpos_changed: int

    findings_new: int
    findings_resolved: int
    findings_regressed: int

    expiring: tuple[ExpiringAcceptance, ...]
    vitals: tuple[BriefingVital, ...]
    freshness: SnapshotFreshness | None = None

    @property
    def has_change(self) -> bool:
        """True when anything moved since the prior snapshot."""
        return bool(
            self.gpos_added
            or self.gpos_removed
            or self.gpos_changed
            or self.findings_new
            or self.findings_resolved
            or self.findings_regressed
        )


def _latest_run_for_snapshot(
    conn: sqlite3.Connection, snapshot_id: int
) -> tuple[int, str, str] | None:
    """Newest evaluation run for a snapshot as ``(id, status, error_summary)``."""
    row = conn.execute(
        "SELECT id, status, error_summary FROM evaluation_run "
        "WHERE snapshot_id = ? ORDER BY id DESC LIMIT 1",
        (snapshot_id,),
    ).fetchone()
    if row is None:
        return None
    return int(row[0]), str(row[1] or ""), str(row[2] or "")


def _scalar(conn: sqlite3.Connection, sql: str, params: tuple[object, ...] = ()) -> int:
    row = conn.execute(sql, params).fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def build_briefing(
    conn: sqlite3.Connection,
    *,
    as_of_snapshot: int | None = None,
    now: datetime | None = None,
    stale_after_days: int = 8,
) -> Briefing | None:
    """Assemble the briefing facts, or ``None`` when no snapshot is ingested.

    *as_of_snapshot* produces the briefing as of that snapshot rather than the
    newest, so the history axis can ask "what did this look like then?" — the
    prior snapshot is the one immediately before it, not the current runner-up.

    *now* is injected rather than read from the clock so expiry classification
    is testable and the output stays deterministic.
    """
    from gpo_lens.findings import accepted_risk_register, finding_delta
    from gpo_lens.snapshot_diff import snapshot_diff
    from gpo_lens.store import list_snapshots

    if now is None:
        now = datetime.now(UTC)

    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must include a UTC offset")
    if stale_after_days <= 0:
        raise ValueError("stale_after_days must be positive")

    snapshots = list_snapshots(conn)  # newest first
    if not snapshots:
        return None

    if as_of_snapshot is None:
        current = snapshots[0]
    else:
        matching = [s for s in snapshots if s[0] == as_of_snapshot]
        if not matching:
            return None
        current = matching[0]

    snapshot_id, domain, taken_at = current
    # Snapshots are ordered newest first, so the prior one is the next entry
    # with a lower id — not simply snapshots[1], which would be wrong whenever
    # as_of_snapshot is historical.
    older = [s for s in snapshots if s[0] < snapshot_id]
    prior_snapshot_id = older[0][0] if older else None
    is_first = prior_snapshot_id is None

    problems: list[str] = []
    newest_id, _, newest_taken = snapshots[0]
    age = (
        now - newest_taken
        if newest_taken is not None
        and newest_taken.tzinfo is not None
        and newest_taken.utcoffset() is not None
        else None
    )
    freshness = SnapshotFreshness(
        snapshot_id=newest_id,
        taken_at=newest_taken,
        age_seconds=int(age.total_seconds()) if age is not None and age >= timedelta(0) else None,
        stale_after_days=stale_after_days,
        is_stale=age is not None and age > timedelta(days=stale_after_days),
    )
    if freshness.is_stale:
        problems.append(
            freshness.description
            + " Collection may have stopped; check the scheduled task and ingest a new export."
        )
    elif freshness.age_seconds is None:
        problems.append(freshness.description)

    coverage_gaps = _scalar(
        conn,
        "SELECT COUNT(*) FROM coverage_gap WHERE snapshot_id = ?",
        (snapshot_id,),
    )
    if coverage_gaps:
        problems.append(
            f"{coverage_gaps} coverage gap{'s' if coverage_gaps != 1 else ''} "
            "in this snapshot — some GPOs could not be read, so absence of a "
            "finding is not evidence of its absence."
        )

    current_run = _latest_run_for_snapshot(conn, snapshot_id)
    analysis_complete = True
    if current_run is None:
        analysis_complete = False
        problems.append(
            "No evaluation run recorded for this snapshot — findings below, if "
            "any, predate it. Re-run analysis before trusting the delta."
        )
    elif current_run[1] != "completed":
        analysis_complete = False
        detail = f" ({current_run[2]})" if current_run[2] else ""
        problems.append(
            f"The latest evaluation run finished with status "
            f"'{current_run[1]}'{detail} — this is an incomplete analysis, not "
            "a clean delta."
        )

    if current_run is not None and current_run[1] == "completed" and current_run[2]:
        problems.append(current_run[2])

    gpos_added = gpos_removed = gpos_changed = 0
    findings_new = findings_resolved = findings_regressed = 0

    if not is_first and prior_snapshot_id is not None:
        diff = snapshot_diff(conn, prior_snapshot_id, snapshot_id)
        gpos_added = len(diff.gpos_added)
        gpos_removed = len(diff.gpos_removed)
        # One GPO can change in several dimensions; count distinct GPOs so the
        # sentence says "2 GPOs changed" rather than double-counting one GPO
        # that changed both a setting and a link.
        gpos_changed = len(
            set(diff.settings_changed)
            | set(diff.links_changed)
            | set(diff.delegation_changed)
            | set(diff.version_skew_changed)
        )

        prior_run = _latest_run_for_snapshot(conn, prior_snapshot_id)
        if current_run is not None and prior_run is not None:
            delta = finding_delta(conn, prior_run[0], current_run[0])
            findings_new = len(delta.new_fingerprints)
            findings_resolved = len(delta.resolved_fingerprints)
            findings_regressed = len(delta.regressed_fingerprints)
        elif current_run is not None:
            problems.append(
                "The prior snapshot has no evaluation run, so no finding delta "
                "can be computed against it."
            )

    # Scope presence and severity to the selected evaluation, including runs
    # preserved by later resolution/regression. Current occurrence severity is
    # mutable; the observation is the historical evidence.
    selected_run_id = current_run[0] if current_run else 0
    # Lead with observed high-severity dangers even when low-priority hygiene
    # dominates the estate. Use selected-run observations, never mutable current
    # occurrence prose, so historical briefings keep their original evidence.
    top_dangers = conn.execute(
        "SELECT o.severity, o.summary, f.gpo_name FROM finding f "
        "JOIN finding_observation o ON o.occurrence_id = f.id "
        "WHERE o.run_id = ? AND f.rule_id LIKE 'danger:%' "
        "AND o.severity IN ('critical', 'high') "
        "ORDER BY CASE o.severity WHEN 'critical' THEN 0 ELSE 1 END, f.id LIMIT 5",
        (selected_run_id,),
    ).fetchall()
    problems.extend(f"{severity}: {summary} ({name})" for severity, summary, name in top_dangers)
    historical_counts = conn.execute(
        "SELECT COUNT(*), COALESCE(SUM(o.severity = 'critical'), 0) "
        "FROM finding f JOIN finding_observation o ON o.occurrence_id = f.id "
        "AND o.run_id = (SELECT MAX(o2.run_id) FROM finding_observation o2 "
        "WHERE o2.occurrence_id = f.id AND o2.run_id <= ?) "
        "WHERE f.first_seen_run_id <= ? "
        "AND (f.resolved_run_id IS NULL OR f.resolved_run_id > ?)",
        (selected_run_id, selected_run_id, selected_run_id),
    ).fetchone()
    active_findings, critical_findings = historical_counts
    gpo_count = _scalar(conn, "SELECT COUNT(*) FROM gpo WHERE snapshot_id = ?", (snapshot_id,))

    register = accepted_risk_register(conn, as_of=now)
    active_acceptances = [r for r in register if r.revoked_at is None and not r.is_expired]
    expiring = tuple(
        _to_expiring(r)
        for r in sorted(
            (
                r
                for r in register
                if r.revoked_at is None
                and r.expires_at is not None
                and r.expires_at <= now + EXPIRY_HORIZON
            ),
            key=lambda r: (r.expires_at or now, r.occurrence_id),
        )
    )

    vitals = (
        BriefingVital(
            key="critical_findings",
            label="Critical findings",
            value=critical_findings,
            tone="crit" if critical_findings else "muted",
        ),
        BriefingVital(
            key="active_findings",
            label="Active findings",
            value=active_findings,
            tone="warn" if active_findings else "muted",
        ),
        BriefingVital(
            key="coverage_gaps",
            label="Coverage gaps",
            value=coverage_gaps,
            tone="crit" if coverage_gaps else "muted",
        ),
        BriefingVital(
            key="accepted_risks",
            label="Accepted risks",
            value=len(active_acceptances),
            tone="info" if active_acceptances else "muted",
        ),
        BriefingVital(
            key="gpo_count",
            label="GPOs",
            value=gpo_count,
            tone="muted",
        ),
    )

    return Briefing(
        domain=domain,
        snapshot_id=snapshot_id,
        snapshot_taken_at=taken_at,
        prior_snapshot_id=prior_snapshot_id,
        is_first_snapshot=is_first,
        analysis_complete=analysis_complete,
        problems=tuple(problems),
        gpos_added=gpos_added,
        gpos_removed=gpos_removed,
        gpos_changed=gpos_changed,
        findings_new=findings_new,
        findings_resolved=findings_resolved,
        findings_regressed=findings_regressed,
        expiring=expiring,
        vitals=vitals,
        freshness=freshness,
    )


def _to_expiring(acceptance: RiskAcceptance) -> ExpiringAcceptance:
    expires = acceptance.expires_at
    if expires is None:  # pragma: no cover - filtered on before construction
        raise ValueError(f"acceptance {acceptance.occurrence_id} has no expiry to report")
    return ExpiringAcceptance(
        occurrence_id=acceptance.occurrence_id,
        category=acceptance.category,
        summary=acceptance.summary,
        severity=acceptance.severity,
        actor=acceptance.actor,
        expires_at=expires,
        already_expired=acceptance.is_expired,
    )


def _count(value: int, singular: str, plural: str | None = None) -> str:
    word = singular if value == 1 else (plural or singular + "s")
    return f"{value} {word}"


def briefing_lines(briefing: Briefing) -> tuple[str, ...]:
    """Render the briefing as deterministic sentences, most important first.

    Problems lead. Plan 025 WI-2 requires coverage and provenance gaps to be at
    least as prominent as favorable counts, and the cheapest way to guarantee
    that is ordering: a reassuring count can never be rendered above the reason
    it is untrustworthy.
    """
    lines: list[str] = []
    lines.extend(briefing.problems)
    if (
        briefing.freshness
        and briefing.freshness.age_seconds is not None
        and not briefing.freshness.is_stale
    ):
        lines.append(briefing.freshness.description)

    if briefing.is_first_snapshot:
        lines.append(
            f"This is the first snapshot of {briefing.domain} "
            f"(#{briefing.snapshot_id}), so there is nothing to compare it "
            f"against yet. It holds "
            f"{_count(_vital(briefing, 'gpo_count'), 'GPO')} and "
            f"{_count(_vital(briefing, 'active_findings'), 'active finding')}."
        )
        return tuple(lines)

    if not briefing.analysis_complete:
        # Deliberately no delta sentence: the counts behind it are partial, and
        # stating them as a comparison would launder incomplete analysis into a
        # confident answer.
        lines.append(
            f"Analysis of snapshot #{briefing.snapshot_id} is incomplete, so no "
            f"delta against snapshot #{briefing.prior_snapshot_id} is reported."
        )
        return tuple(lines)

    if not briefing.has_change:
        lines.append(
            f"Nothing changed between snapshot #{briefing.prior_snapshot_id} "
            f"and #{briefing.snapshot_id}: no GPO edits, and no findings "
            f"opened or resolved."
        )
        return tuple(lines)

    changes: list[str] = []
    if briefing.gpos_changed:
        changes.append(f"{_count(briefing.gpos_changed, 'GPO')} changed")
    if briefing.gpos_added:
        changes.append(f"{_count(briefing.gpos_added, 'GPO')} added")
    if briefing.gpos_removed:
        changes.append(f"{_count(briefing.gpos_removed, 'GPO')} removed")
    if briefing.findings_new:
        changes.append(
            f"{_count(briefing.findings_new, 'finding')} "
            f"{'is' if briefing.findings_new == 1 else 'are'} new"
        )
    if briefing.findings_regressed:
        changes.append(f"{_count(briefing.findings_regressed, 'finding')} regressed")
    if briefing.findings_resolved:
        changes.append(f"{briefing.findings_resolved} resolved")

    lines.append(f"Since snapshot #{briefing.prior_snapshot_id}: " + _join_clauses(changes) + ".")

    if briefing.expiring:
        overdue = [e for e in briefing.expiring if e.already_expired]
        soon = [e for e in briefing.expiring if not e.already_expired]
        if overdue:
            lines.append(
                f"{_count(len(overdue), 'accepted-risk decision')} "
                f"{'has' if len(overdue) == 1 else 'have'} expired and "
                f"{'is' if len(overdue) == 1 else 'are'} actionable again."
            )
        if soon:
            lines.append(
                f"{_count(len(soon), 'accepted-risk decision')} "
                f"{'expires' if len(soon) == 1 else 'expire'} within "
                f"{EXPIRY_HORIZON.days} days."
            )

    return tuple(lines)


def _vital(briefing: Briefing, key: str) -> int:
    for vital in briefing.vitals:
        if vital.key == key:
            return vital.value
    return 0


def _join_clauses(clauses: list[str]) -> str:
    """Join with commas and a trailing "and", Oxford-comma free for two items."""
    if not clauses:
        return "nothing changed"
    if len(clauses) == 1:
        return clauses[0]
    if len(clauses) == 2:
        return f"{clauses[0]} and {clauses[1]}"
    return ", ".join(clauses[:-1]) + f", and {clauses[-1]}"
