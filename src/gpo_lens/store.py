"""SQLite persistence for ``Estate`` snapshots."""

from __future__ import annotations

import json
import os
import sqlite3
import warnings
from datetime import UTC, datetime
from typing import Any

from gpo_lens.events import init_events_table
from gpo_lens.model import (
    CoverageGap,
    DelegationEntry,
    Estate,
    Gpo,
    GpoLink,
    GroupMembership,
    OuRecord,
    ResolvedPrincipal,
    Setting,
    Som,
    SomLink,
    WmiFilter,
)
from gpo_lens.normalize import parse_dt

# Schema version stored in PRAGMA user_version by ``_migrate_schema``.
# v1 = original ``init_db`` schema.
# v2 = adds the nullable ``description`` column to the ``gpo`` table.
# v3 = adds the ``principal`` + ``group_member`` tables (Plan 020/021), so the
#      collected principal-resolution inputs survive a snapshot round-trip
#      instead of being dropped on the ``--db`` read path.
# v4 = adds the ``finding`` + ``finding_triage`` tables (Plan 023 WI-4/WI-5),
#      durable finding identity/lifecycle + local triage annotations.
# v5 = persists bounded finding evidence/remediation so read paths never need
#      to re-run whole-estate detectors (WI-090).
# v6 = Plan 024: evaluation provenance + occurrence/observation separation +
#      enhanced triage. Adds ``analysis_input``, ``evaluation_run``,
#      ``finding_observation``, ``finding_triage_event`` tables; adds
#      ``fingerprint_version``, ``series_key``, ``detector_id``,
#      ``detector_version``, ``subject_type``, ``subject_key``,
#      ``first_seen_run_id``, ``last_seen_run_id``, ``resolved_run_id``
#      columns to ``finding``; adds ``expires_at``, ``supersedes_event_id``,
#      ``rationale`` columns to ``finding_triage``.
# v7 = fix coverage_gap PK to include ``kind`` so multiple gap types per GPO
#      (e.g. unreadable_sysvol + corrupt_gpp_xml) are not silently dropped.
# v8 = WI-092: unify triage storage on the Plan 024 ``finding_triage_event``
#      log. Existing ``finding_triage`` (v1) rows are copied into the event
#      log; the legacy table remains (unused) for audit. Writes to
#      ``finding_triage`` stop entirely — v1 triage APIs become shims over
#      the event log.
CURRENT_SCHEMA_VERSION: int = 9


def _safe_json_loads(raw: str | None, default: Any) -> Any:
    """Load JSON from a DB column, returning *default* for NULL.

    Raises ``json.JSONDecodeError`` for corrupt JSON — the previous behavior
    of silently returning *default* hid data corruption, violating the
    coverage-honesty charter (WI-049).
    """
    if raw is None:
        return default
    return json.loads(raw)


def init_db(conn: sqlite3.Connection) -> None:
    """Create tables (idempotent, ``IF NOT EXISTS``)."""
    user_version = conn.execute("PRAGMA user_version").fetchone()[0]

    if user_version > CURRENT_SCHEMA_VERSION:
        raise RuntimeError(
            f"Database schema version {user_version} is newer than this "
            f"gpo-lens release supports (version {CURRENT_SCHEMA_VERSION}). "
            "Please upgrade gpo-lens to open this database."
        )

    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    restrict_db_permissions(conn)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS snapshot (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            taken_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS gpo (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            id TEXT NOT NULL,
            name TEXT NOT NULL,
            domain TEXT NOT NULL,
            created TEXT,
            modified TEXT,
            read TEXT,
            computer_enabled INTEGER NOT NULL,
            user_enabled INTEGER NOT NULL,
            computer_ver_ds INTEGER,
            computer_ver_sysvol INTEGER,
            user_ver_ds INTEGER,
            user_ver_sysvol INTEGER,
            sddl TEXT,
            owner TEXT,
            filter_data_available INTEGER NOT NULL,
            wmi_filter TEXT,
            sysvol_path TEXT,
            description TEXT,
            PRIMARY KEY (snapshot_id, id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS gpo_link (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            gpo_id TEXT NOT NULL,
            som_name TEXT NOT NULL,
            som_path TEXT NOT NULL,
            link_enabled INTEGER NOT NULL,
            enforced INTEGER NOT NULL,
            PRIMARY KEY (snapshot_id, gpo_id, som_name, som_path)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS setting (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            gpo_id TEXT NOT NULL,
            side TEXT NOT NULL,
            cse TEXT NOT NULL,
            identity TEXT NOT NULL,
            display_name TEXT NOT NULL,
            display_value TEXT NOT NULL,
            raw TEXT NOT NULL,
            from_disabled_side INTEGER NOT NULL,
            source_state TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS delegation (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            gpo_id TEXT NOT NULL,
            trustee TEXT NOT NULL,
            trustee_sid TEXT,
            permission TEXT NOT NULL,
            allowed INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS som (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            path TEXT NOT NULL,
            name TEXT NOT NULL,
            container_type TEXT NOT NULL,
            inheritance_blocked INTEGER NOT NULL,
            PRIMARY KEY (snapshot_id, path)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS som_link (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            som_path TEXT NOT NULL,
            gpo_id TEXT NOT NULL,
            order_ INTEGER NOT NULL,
            enabled INTEGER NOT NULL,
            enforced INTEGER NOT NULL,
            target TEXT NOT NULL,
            PRIMARY KEY (snapshot_id, som_path, gpo_id, order_, target)
        )
        """
    )
    # Indexes for query performance
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_setting_snapshot_gpo
        ON setting(snapshot_id, gpo_id)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_gpo_link_snapshot_gpo
        ON gpo_link(snapshot_id, gpo_id)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_delegation_snapshot_gpo
        ON delegation(snapshot_id, gpo_id)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_som_link_snapshot_som
        ON som_link(snapshot_id, som_path)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_som_link_snapshot_gpo
        ON som_link(snapshot_id, gpo_id)
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS wmi_filter (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            query TEXT NOT NULL,
            PRIMARY KEY (snapshot_id, name)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ou_tree (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            dn TEXT NOT NULL,
            name TEXT NOT NULL,
            gp_link TEXT,
            gp_options INTEGER,
            PRIMARY KEY (snapshot_id, dn)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS coverage_gap (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            gpo_id TEXT NOT NULL,
            display_name TEXT,
            kind TEXT NOT NULL,
            detail TEXT NOT NULL,
            PRIMARY KEY (snapshot_id, gpo_id, kind)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS principal (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            sid TEXT NOT NULL,
            name TEXT NOT NULL,
            sam TEXT NOT NULL,
            principal_type TEXT NOT NULL,
            domain TEXT NOT NULL,
            resolved INTEGER NOT NULL,
            PRIMARY KEY (snapshot_id, sid)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS group_member (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            sid TEXT NOT NULL,
            name TEXT NOT NULL,
            members TEXT NOT NULL,
            member_count INTEGER NOT NULL,
            implicit TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (snapshot_id, sid)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS finding (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_key TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            subject_identity TEXT NOT NULL,
            severity TEXT NOT NULL,
            summary TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT '',
            remediation TEXT NOT NULL DEFAULT '',
            gpo_id TEXT NOT NULL DEFAULT '',
            gpo_name TEXT NOT NULL DEFAULT '',
            first_seen_snapshot INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            last_seen_snapshot INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            resolved_in_snapshot INTEGER REFERENCES snapshot(id) ON DELETE SET NULL,
            predecessor_id INTEGER REFERENCES finding(id) ON DELETE SET NULL
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_finding_key
        ON finding(finding_key)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_finding_active
        ON finding(resolved_in_snapshot)
        WHERE resolved_in_snapshot IS NULL
        """
    )
    # WI-092 (schema v8): triage unified on ``finding_triage_event``. This
    # legacy v1 table is retained as the migration source for pre-v8 DBs and
    # for audit — it is never written post-v8. Do not drop it: the v7->v8
    # migration in ``_migrate_schema`` reads from it.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_triage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
            status TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            actor TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_finding_triage_finding
        ON finding_triage(finding_id)
        """
    )
    # Plan 024: evaluation provenance tables.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analysis_input (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            canonical_digest TEXT NOT NULL,
            version TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_analysis_input_digest
        ON analysis_input(kind, canonical_digest)
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS evaluation_run (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            evaluation_kind TEXT NOT NULL DEFAULT 'intrinsic',
            detector_set_digest TEXT NOT NULL DEFAULT '',
            comparator_input_id INTEGER REFERENCES analysis_input(id) ON DELETE SET NULL,
            application_version TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL,
            completed_at TEXT,
            status TEXT NOT NULL DEFAULT 'completed',
            error_summary TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_evaluation_run_snapshot
        ON evaluation_run(snapshot_id)
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_observation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL REFERENCES evaluation_run(id) ON DELETE CASCADE,
            occurrence_id INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
            severity TEXT NOT NULL,
            summary TEXT NOT NULL DEFAULT '',
            evidence_json TEXT NOT NULL DEFAULT '{}',
            claim_level TEXT NOT NULL DEFAULT 'confirmed',
            remediation TEXT NOT NULL DEFAULT '',
            compliance_json TEXT NOT NULL DEFAULT '[]',
            gpo_id TEXT NOT NULL DEFAULT '',
            gpo_name TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_finding_observation_run
        ON finding_observation(run_id)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_finding_observation_occurrence
        ON finding_observation(occurrence_id)
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_triage_event (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            occurrence_id INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            rationale TEXT NOT NULL DEFAULT '',
            expires_at TEXT,
            supersedes_event_id INTEGER REFERENCES finding_triage_event(id) ON DELETE SET NULL
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_finding_triage_event_occurrence
        ON finding_triage_event(occurrence_id)
        """
    )
    init_events_table(conn)
    _migrate_schema(conn)
    # Indexes on the Plan 024 run-id / series columns (WI-1.3). These live
    # after _migrate_schema because the columns they cover are added there via
    # ALTER on a fresh DB — creating them in the CREATE block above would race
    # ahead of the columns' existence. IF NOT EXISTS keeps this idempotent and
    # backfills the indexes onto DBs already stamped at the current version.
    for index_ddl in (
        "CREATE INDEX IF NOT EXISTS idx_finding_last_seen_run ON finding(last_seen_run_id)",
        "CREATE INDEX IF NOT EXISTS idx_finding_first_seen_run ON finding(first_seen_run_id)",
        "CREATE INDEX IF NOT EXISTS idx_finding_resolved_run ON finding(resolved_run_id)",
        "CREATE INDEX IF NOT EXISTS idx_finding_series_key ON finding(series_key)",
    ):
        conn.execute(index_ddl)
    conn.commit()


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    """True if ``column`` exists on ``table`` (used by additive migrations)."""
    if not table.isidentifier():
        raise ValueError(f"unsafe table identifier: {table!r}")
    rows = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
    return any(r[1] == column for r in rows)


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    """True if ``table`` exists. Lets the read path tolerate pre-v3 DBs that
    were written before the ``principal`` / ``group_member`` tables existed."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def _coverage_gap_pk_has_kind(conn: sqlite3.Connection) -> bool:
    """True if the ``coverage_gap`` PK includes the ``kind`` column (v7+)."""
    if not _table_exists(conn, "coverage_gap"):
        return True
    cols = conn.execute("PRAGMA table_info('coverage_gap')").fetchall()
    pk_cols = [c[1] for c in cols if c[5] > 0]
    return "kind" in pk_cols


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Additive column migrations for DBs created by older gpo-lens versions.

    Migration state is tracked via ``PRAGMA user_version``. The version stamp
    lets us fail fast when opening a DB written by a newer gpo-lens, while the
    per-column ``_column_exists`` checks keep individual migrations idempotent in
    case a partially-migrated DB is opened again.

    ``CREATE TABLE IF NOT EXISTS`` won't add columns to an existing table, so
    each additive column needs an ``ALTER TABLE`` here guarded by a column
    check. Only additive (NULLable) columns — never renames or drops.
    """
    user_version = conn.execute("PRAGMA user_version").fetchone()[0]

    if user_version > CURRENT_SCHEMA_VERSION:
        raise RuntimeError(
            f"Database schema version {user_version} is newer than this "
            f"gpo-lens release supports (version {CURRENT_SCHEMA_VERSION}). "
            "Please upgrade gpo-lens to open this database."
        )

    if user_version < CURRENT_SCHEMA_VERSION:
        # v1 -> v2: add nullable description column to the gpo table.
        if not _column_exists(conn, "gpo", "description"):
            conn.execute("ALTER TABLE gpo ADD COLUMN description TEXT")

        # v4 -> v5: retain the evidence already produced at ingest so the
        # findings inbox remains actionable without detector recomputation.
        if not _column_exists(conn, "finding", "detail"):
            conn.execute("ALTER TABLE finding ADD COLUMN detail TEXT NOT NULL DEFAULT ''")
        if not _column_exists(conn, "finding", "remediation"):
            conn.execute("ALTER TABLE finding ADD COLUMN remediation TEXT NOT NULL DEFAULT ''")

        # v5 -> v6: Plan 024 — evaluation provenance, occurrence/observation
        # separation, enhanced triage. Add columns to existing tables so the
        # new model is backward-compatible with existing finding rows.
        new_finding_cols = {
            "fingerprint_version": "INTEGER NOT NULL DEFAULT 1",
            "series_key": "TEXT NOT NULL DEFAULT ''",
            "detector_id": "TEXT NOT NULL DEFAULT ''",
            "detector_version": "TEXT NOT NULL DEFAULT '1'",
            "subject_type": "TEXT NOT NULL DEFAULT ''",
            "subject_key_json": "TEXT NOT NULL DEFAULT '[]'",
            "first_seen_run_id": "INTEGER",
            "last_seen_run_id": "INTEGER",
            "resolved_run_id": "INTEGER",
        }
        for col, ddl in new_finding_cols.items():
            if not _column_exists(conn, "finding", col):
                conn.execute(f"ALTER TABLE finding ADD COLUMN {col} {ddl}")

        new_triage_cols = {
            "expires_at": "TEXT",
            "supersedes_event_id": "INTEGER",
            "rationale": "TEXT NOT NULL DEFAULT ''",
        }
        for col, ddl in new_triage_cols.items():
            if not _column_exists(conn, "finding_triage", col):
                conn.execute(f"ALTER TABLE finding_triage ADD COLUMN {col} {ddl}")

        # v6 -> v7: fix coverage_gap PK to include ``kind`` so multiple gap
        # types per GPO are not silently dropped by INSERT OR IGNORE.
        if not _coverage_gap_pk_has_kind(conn):
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS coverage_gap_new (
                    snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
                    gpo_id TEXT NOT NULL,
                    display_name TEXT,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    PRIMARY KEY (snapshot_id, gpo_id, kind)
                )
                """
            )
            conn.execute("INSERT OR IGNORE INTO coverage_gap_new SELECT * FROM coverage_gap")
            conn.execute("DROP TABLE coverage_gap")
            conn.execute("ALTER TABLE coverage_gap_new RENAME TO coverage_gap")

        # v7 -> v8 (WI-092): migrate legacy ``finding_triage`` rows into the
        # Plan 024 ``finding_triage_event`` log so triage state lives in one
        # store. Status mapping: ``open`` -> ``reopened`` (the v2 action that
        # folds to open); ``acknowledged``/``accepted_risk`` carry over. For
        # accepted-risk rows, fall back to the note as the rationale when the
        # v1 row recorded none (v1 had no rationale concept) — nothing is
        # fabricated beyond the operator's own text. The NOT EXISTS guard
        # keeps a re-run after an interrupted migration a no-op. Match every
        # stored payload field so distinct same-timestamp events are preserved.
        # Orphaned legacy rows are skipped defensively: old databases may have
        # been modified while foreign-key enforcement was disabled.
        # Released v1.1/v1.2 exposed both APIs. Existing event IDs (including
        # supersedes references) remain immutable; converted rows get stable IDs
        # in legacy chronological order. Readers use UTC instants, with removal
        # actions after approvals at equal instants, then immutable event IDs.
        # A migrated approval cannot override a newer or equal-time reopen.
        conn.execute(
            """
            INSERT INTO finding_triage_event
                (occurrence_id, action, actor, occurred_at, note, rationale,
                 expires_at, supersedes_event_id)
            SELECT t.finding_id,
                   CASE t.status WHEN 'open' THEN 'reopened' ELSE t.status END,
                   t.actor, t.timestamp, t.note,
                   CASE WHEN t.status = 'accepted_risk'
                        THEN COALESCE(NULLIF(t.rationale, ''), t.note, '')
                        ELSE '' END,
                   t.expires_at, NULL
            FROM finding_triage t
            JOIN finding f ON f.id = t.finding_id
            WHERE NOT EXISTS (
                SELECT 1 FROM finding_triage_event e
                WHERE e.occurrence_id = t.finding_id
                  AND e.action = CASE t.status
                                     WHEN 'open' THEN 'reopened'
                                     ELSE t.status END
                  AND e.occurred_at = t.timestamp
                  AND e.actor = t.actor
                  AND e.note = t.note
                  AND e.rationale = CASE
                      WHEN t.status = 'accepted_risk'
                      THEN COALESCE(NULLIF(t.rationale, ''), t.note, '')
                      ELSE '' END
                  AND e.expires_at IS t.expires_at
            )
            ORDER BY t.timestamp, t.id
            """
        )

        # v8 -> v9 (Plan 024 §4): record whether an occurrence's subject can be
        # identified stably across snapshots. A detector that emits no GPO and
        # declares no ``subject_key`` leaves the adapter nothing to key on but
        # the prose summary, so the occurrence's identity churns whenever the
        # wording changes. Plan 024 says such findings are ``snapshot_scoped``
        # and cannot be tracked across runs; this column is what lets the
        # queries say so instead of silently presenting them as new/persisting.
        # Defaulting to 1 is correct for existing rows: every deployed detector
        # declares a subject today (locked by a contract test), so no stored
        # occurrence is retroactively unstable.
        if not _column_exists(conn, "finding", "subject_stable"):
            conn.execute("ALTER TABLE finding ADD COLUMN subject_stable INTEGER NOT NULL DEFAULT 1")

    conn.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")


def restrict_db_permissions(conn: sqlite3.Connection) -> None:
    """Tighten the DB file to owner-only (0600).

    The snapshot DB holds the full estate (GPO names, delegation, settings,
    cpassword metadata) — on a shared host it should not be world/group
    readable. SQLite creates files with the process umask (often 0644), so we
    tighten on every ``init_db``. Best-effort: in-memory and non-local paths
    are skipped.
    """
    row = conn.execute("PRAGMA database_list").fetchone()
    if not row or not row[2]:
        return
    path = row[2]
    try:
        os.chmod(path, 0o600)
    except (OSError, ValueError) as exc:
        warnings.warn(f"Could not restrict DB permissions on {path}: {exc}", stacklevel=1)
    for suffix in ("-wal", "-shm"):
        sidecar = f"{path}{suffix}"
        if os.path.exists(sidecar):
            try:
                os.chmod(sidecar, 0o600)
            except (OSError, ValueError) as exc:
                warnings.warn(
                    f"Could not restrict DB permissions on {sidecar}: {exc}",
                    stacklevel=1,
                )


def _dt_to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.isoformat()


def save_estate(conn: sqlite3.Connection, estate: Estate, taken_at: datetime | None = None) -> int:
    """Save an estate as a new snapshot; returns the new ``snapshot_id``."""
    if taken_at is None:
        taken_at = datetime.now(UTC)
    cursor = conn.execute(
        "INSERT INTO snapshot (domain, taken_at) VALUES (?, ?)",
        (estate.domain, taken_at.isoformat()),
    )
    snapshot_id = cursor.lastrowid
    if snapshot_id is None:
        raise RuntimeError("save_estate: cursor.lastrowid returned None")

    # Batching: per-GPO rows are materialized into Python lists before the
    # executemany calls below. This raises peak memory proportionally to the
    # estate size — an acceptable trade for WI-085.
    gpo_link_rows: list[tuple[Any, ...]] = []
    setting_rows: list[tuple[Any, ...]] = []
    delegation_rows: list[tuple[Any, ...]] = []

    for g in estate.gpos:
        conn.execute(
            """
            INSERT INTO gpo (
                snapshot_id, id, name, domain, created, modified, read,
                computer_enabled, user_enabled, computer_ver_ds, computer_ver_sysvol,
                user_ver_ds, user_ver_sysvol, sddl, owner, filter_data_available,
                wmi_filter, sysvol_path, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                g.id,
                g.name,
                g.domain,
                _dt_to_iso(g.created),
                _dt_to_iso(g.modified),
                _dt_to_iso(g.read),
                int(g.computer_enabled),
                int(g.user_enabled),
                g.computer_ver_ds,
                g.computer_ver_sysvol,
                g.user_ver_ds,
                g.user_ver_sysvol,
                g.sddl,
                g.owner,
                int(g.filter_data_available),
                g.wmi_filter,
                g.sysvol_path,
                g.description,
            ),
        )
        for link in g.links:
            gpo_link_rows.append(
                (
                    snapshot_id,
                    link.gpo_id,
                    link.som_name,
                    link.som_path,
                    int(link.link_enabled),
                    int(link.enforced),
                )
            )
        for s in g.settings:
            setting_rows.append(
                (
                    snapshot_id,
                    s.gpo_id,
                    s.side,
                    s.cse,
                    s.identity,
                    s.display_name,
                    s.display_value,
                    json.dumps(s.raw, sort_keys=True),
                    int(s.from_disabled_side),
                    s.source_state,
                )
            )
        for d in g.delegation:
            delegation_rows.append(
                (
                    snapshot_id,
                    d.gpo_id,
                    d.trustee,
                    d.trustee_sid,
                    d.permission,
                    int(d.allowed),
                )
            )

    conn.executemany(
        """
        INSERT INTO gpo_link (
            snapshot_id, gpo_id, som_name, som_path, link_enabled, enforced
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        gpo_link_rows,
    )
    conn.executemany(
        """
        INSERT INTO setting (
            snapshot_id, gpo_id, side, cse, identity, display_name,
            display_value, raw, from_disabled_side, source_state
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        setting_rows,
    )
    conn.executemany(
        """
        INSERT INTO delegation (
            snapshot_id, gpo_id, trustee, trustee_sid, permission, allowed
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        delegation_rows,
    )

    som_link_rows: list[tuple[Any, ...]] = []

    for som in estate.soms:
        conn.execute(
            """
            INSERT INTO som (
                snapshot_id, path, name, container_type, inheritance_blocked
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                som.path,
                som.name,
                som.container_type,
                int(som.inheritance_blocked),
            ),
        )
        for som_link in som.links:
            som_link_rows.append(
                (
                    snapshot_id,
                    som.path,
                    som_link.gpo_id,
                    som_link.order,
                    int(som_link.enabled),
                    int(som_link.enforced),
                    som_link.target,
                )
            )

    conn.executemany(
        """
        INSERT INTO som_link (
            snapshot_id, som_path, gpo_id, order_, enabled, enforced, target
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        som_link_rows,
    )

    conn.executemany(
        "INSERT INTO wmi_filter (snapshot_id, name, query) VALUES (?, ?, ?)",
        [(snapshot_id, wf.name, wf.query) for wf in estate.wmi_filters],
    )
    conn.executemany(
        "INSERT INTO ou_tree (snapshot_id, dn, name, gp_link, gp_options) VALUES (?, ?, ?, ?, ?)",
        [(snapshot_id, ou.dn, ou.name, ou.gp_link, ou.gp_options) for ou in estate.ou_tree],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO coverage_gap "
        "(snapshot_id, gpo_id, display_name, kind, detail) VALUES (?, ?, ?, ?, ?)",
        [
            (snapshot_id, gap.gpo_id, gap.display_name, gap.kind, gap.detail)
            for gap in estate.coverage_gaps
        ],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO principal "
        "(snapshot_id, sid, name, sam, principal_type, domain, resolved) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (snapshot_id, p.sid, p.name, p.sam, p.principal_type, p.domain, int(p.resolved))
            for p in estate.principals.values()
        ],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO group_member "
        "(snapshot_id, sid, name, members, member_count, implicit) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            (
                snapshot_id,
                gm.sid,
                gm.name,
                json.dumps(list(gm.members)),
                gm.member_count,
                gm.implicit,
            )
            for gm in estate.group_members.values()
        ],
    )

    conn.commit()
    restrict_db_permissions(conn)
    return snapshot_id


def load_estate(conn: sqlite3.Connection, snapshot_id: int | None = None) -> Estate:
    """Reconstruct an ``Estate`` from a snapshot (default: most recent)."""
    if snapshot_id is None:
        row = conn.execute(
            "SELECT id, domain, taken_at FROM snapshot ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise ValueError("No snapshots found in database")
        snapshot_id = row[0]
    else:
        row = conn.execute(
            "SELECT id, domain, taken_at FROM snapshot WHERE id = ?", (snapshot_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"Snapshot {snapshot_id} not found")

    domain = row[1]

    # Load GPOs — collect related rows first, then construct each Gpo fully
    # (WI-050: no partially-constructed state).
    gpo_rows: dict[str, tuple[Any, ...]] = {}
    for row in conn.execute(
        """
        SELECT id, name, domain, created, modified, read,
               computer_enabled, user_enabled, computer_ver_ds, computer_ver_sysvol,
               user_ver_ds, user_ver_sysvol, sddl, owner, filter_data_available,
               wmi_filter, sysvol_path, description
        FROM gpo WHERE snapshot_id = ?
        ORDER BY id
        """,
        (snapshot_id,),
    ):
        gpo_rows[row[0]] = row

    # Collect links per GPO
    links_by_gpo: dict[str, list[GpoLink]] = {}
    for row in conn.execute(
        """
        SELECT gpo_id, som_name, som_path, link_enabled, enforced
        FROM gpo_link WHERE snapshot_id = ?
        ORDER BY gpo_id, som_path
        """,
        (snapshot_id,),
    ):
        links_by_gpo.setdefault(row[0], []).append(
            GpoLink(
                gpo_id=row[0],
                som_name=row[1],
                som_path=row[2],
                link_enabled=bool(row[3]),
                enforced=bool(row[4]),
            )
        )

    # Collect settings per GPO
    settings_by_gpo: dict[str, list[Setting]] = {}
    for row in conn.execute(
        """
        SELECT gpo_id, side, cse, identity, display_name, display_value,
               raw, from_disabled_side, source_state
        FROM setting WHERE snapshot_id = ?
        ORDER BY gpo_id, side, cse, identity
        """,
        (snapshot_id,),
    ):
        settings_by_gpo.setdefault(row[0], []).append(
            Setting(
                gpo_id=row[0],
                side=row[1],
                cse=row[2],
                identity=row[3],
                display_name=row[4],
                display_value=row[5],
                raw=_safe_json_loads(row[6], {}),
                from_disabled_side=bool(row[7]),
                source_state=row[8],
            )
        )

    # Collect delegation per GPO
    delegation_by_gpo: dict[str, list[DelegationEntry]] = {}
    for row in conn.execute(
        """
        SELECT gpo_id, trustee, trustee_sid, permission, allowed
        FROM delegation WHERE snapshot_id = ?
        ORDER BY gpo_id, trustee
        """,
        (snapshot_id,),
    ):
        delegation_by_gpo.setdefault(row[0], []).append(
            DelegationEntry(
                gpo_id=row[0],
                trustee=row[1],
                trustee_sid=row[2],
                permission=row[3],
                allowed=bool(row[4]),
            )
        )

    # Construct fully-populated Gpo objects
    gpos: dict[str, Gpo] = {}
    for gpo_id, row in gpo_rows.items():
        gpo = Gpo(
            id=row[0],
            name=row[1],
            domain=row[2],
            created=parse_dt(row[3]),
            modified=parse_dt(row[4]),
            read=parse_dt(row[5]),
            computer_enabled=bool(row[6]),
            user_enabled=bool(row[7]),
            computer_ver_ds=row[8],
            computer_ver_sysvol=row[9],
            user_ver_ds=row[10],
            user_ver_sysvol=row[11],
            sddl=row[12],
            owner=row[13],
            filter_data_available=bool(row[14]),
            wmi_filter=row[15],
            sysvol_path=row[16],
            description=row[17],
            links=links_by_gpo.get(gpo_id, []),
            settings=settings_by_gpo.get(gpo_id, []),
            delegation=delegation_by_gpo.get(gpo_id, []),
        )
        gpos[gpo.id] = gpo

    # Load SOMs
    soms: dict[str, Som] = {}
    for row in conn.execute(
        "SELECT path, name, container_type, inheritance_blocked "
        "FROM som WHERE snapshot_id = ? ORDER BY path",
        (snapshot_id,),
    ):
        som = Som(
            path=row[0],
            name=row[1],
            container_type=row[2],
            inheritance_blocked=bool(row[3]),
        )
        soms[som.path] = som

    for row in conn.execute(
        """
        SELECT som_path, gpo_id, order_, enabled, enforced, target
        FROM som_link WHERE snapshot_id = ?
        ORDER BY som_path, order_
        """,
        (snapshot_id,),
    ):
        if row[0] not in soms:
            continue
        som = soms[row[0]]
        som.links.append(
            SomLink(
                gpo_id=row[1],
                order=row[2],
                enabled=bool(row[3]),
                enforced=bool(row[4]),
                target=row[5],
            )
        )

    wmi_filters: list[WmiFilter] = []
    for row in conn.execute(
        "SELECT name, query FROM wmi_filter WHERE snapshot_id = ? ORDER BY name",
        (snapshot_id,),
    ):
        wmi_filters.append(WmiFilter(name=row[0], query=row[1]))

    ou_tree: list[OuRecord] = []
    for row in conn.execute(
        "SELECT dn, name, gp_link, gp_options FROM ou_tree WHERE snapshot_id = ? ORDER BY dn",
        (snapshot_id,),
    ):
        ou_tree.append(OuRecord(dn=row[0], name=row[1], gp_link=row[2], gp_options=row[3]))

    coverage_gaps: list[CoverageGap] = []
    for row in conn.execute(
        "SELECT gpo_id, display_name, kind, detail FROM coverage_gap "
        "WHERE snapshot_id = ? ORDER BY gpo_id",
        (snapshot_id,),
    ):
        coverage_gaps.append(
            CoverageGap(gpo_id=row[0], display_name=row[1], kind=row[2], detail=row[3])
        )

    # principal / group_member tables arrived in schema v3; tolerate older DBs.
    principals: dict[str, ResolvedPrincipal] = {}
    if _table_exists(conn, "principal"):
        for row in conn.execute(
            "SELECT sid, name, sam, principal_type, domain, resolved FROM principal "
            "WHERE snapshot_id = ? ORDER BY sid",
            (snapshot_id,),
        ):
            principals[row[0]] = ResolvedPrincipal(
                sid=row[0],
                name=row[1],
                sam=row[2],
                principal_type=row[3],
                domain=row[4],
                resolved=bool(row[5]),
            )

    group_members: dict[str, GroupMembership] = {}
    if _table_exists(conn, "group_member"):
        for row in conn.execute(
            "SELECT sid, name, members, member_count, implicit FROM group_member "
            "WHERE snapshot_id = ? ORDER BY sid",
            (snapshot_id,),
        ):
            raw_members = _safe_json_loads(row[2], [])
            group_members[row[0]] = GroupMembership(
                sid=row[0],
                name=row[1],
                members=tuple(raw_members) if isinstance(raw_members, list) else (),
                member_count=row[3],
                implicit=row[4],
            )

    return Estate(
        domain=domain,
        gpos=list(gpos.values()),
        soms=list(soms.values()),
        wmi_filters=wmi_filters,
        ou_tree=ou_tree,
        coverage_gaps=coverage_gaps,
        principals=principals,
        group_members=group_members,
    )


def list_snapshots(conn: sqlite3.Connection) -> list[tuple[int, str, datetime | None]]:
    """Return ``(id, domain, taken_at)`` newest first."""
    rows = conn.execute("SELECT id, domain, taken_at FROM snapshot ORDER BY id DESC").fetchall()
    return [(row[0], row[1], parse_dt(row[2])) for row in rows]


def delete_snapshot(conn: sqlite3.Connection, snapshot_id: int) -> bool:
    """Delete one imported snapshot and all its rows; True if it existed.

    Every child table declares ``ON DELETE CASCADE`` against ``snapshot(id)``,
    so removing the parent row removes the estate wholesale — but SQLite only
    enforces that when ``PRAGMA foreign_keys = ON`` is set on the connection
    (``get_rw_conn`` does). Re-assert it here so a direct caller can't silently
    orphan child rows.
    """
    conn.execute("PRAGMA foreign_keys = ON")
    cur = conn.execute("DELETE FROM snapshot WHERE id = ?", (snapshot_id,))
    conn.commit()
    return cur.rowcount > 0
