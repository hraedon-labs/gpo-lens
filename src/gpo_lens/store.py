"""SQLite persistence for ``Estate`` snapshots."""

from __future__ import annotations

import json
import math
import os
import sqlite3
import warnings
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from gpo_lens.analyst_text import (
    LEGACY_TRIAGE_ACTIONS,
    legacy_triage_field_ok,
    migrated_value,
)
from gpo_lens.events import (
    append_event,
    init_events_table,
    rehash_event_chain,
    verify_event_chain,
)
from gpo_lens.model import (
    AdmxResolver,
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
from gpo_lens.redaction import (
    _JSON_ESCAPE,
    CPASSWORD_FINDING_DETAIL,
    CPASSWORD_MARKER,
    Chaser,
    CpasswordResidualError,
    CredentialInIdentityError,
    chase,
    chase_joined,
    describe_error,
    estate_cpassword_values,
    forget_cpassword_values,
    guarded_diagnostics,
    iter_strings,
    joined_hits,
    mentions_cpassword,
    redact_inline,
    redact_structure,
    release_serialized,
    sanitize_for_storage,
    stored_json,
    sysvol_values_at,
)

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
# v9 = stable-subject flag on occurrences.
# v10 = nullable per-observation detector version; NULL means pre-1.4, unknown.
# v11 = no GPP cpassword value at rest. Opening an older DB read-write scrubs
#       every stored value (setting raw/identity/display text, the four-char
#       prefix earlier cpassword findings kept, event payloads, any other text
#       column), then VACUUMs and truncates the WAL so the old bytes are not left
#       in free pages. The stamp moves to 11 only after that purge succeeds; a
#       DB left at 10 is scrubbed and purged again on its next read-write open.
CURRENT_SCHEMA_VERSION: int = 11
_CPASSWORD_SCRUB_VERSION: int = 11


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
    # A database with no tables yet has nothing to scrub or purge.
    fresh = conn.execute("SELECT count(*) FROM sqlite_master").fetchone()[0] == 0

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
    scrub = _migrate_schema(conn, fresh=fresh)
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
    if scrub is not None:
        _purge_free_pages(conn, scrub)


@dataclass(frozen=True)
class _ScrubResult:
    """What the v11 scrub changed, and what the purge must re-check."""

    changed: dict[str, int]
    values: frozenset[str]
    allowed_broken_events: frozenset[int]


# Text columns a copy of a cpassword value may be rewritten in (descriptive
# text). Every other text column is identity/structural truth (GUIDs, SIDs,
# paths, CSE names, keys, timestamps, event types, hashes): a copy there makes
# the migration refuse instead of corrupting it. Mirrors
# ``redaction.REWRITABLE_FIELDS`` for the stored schema.
REWRITABLE_COLUMNS: dict[str, frozenset[str]] = {
    "gpo": frozenset({"name", "description"}),
    "gpo_link": frozenset({"som_name"}),
    "setting": frozenset({"identity", "display_name", "display_value", "raw"}),
    "som": frozenset({"name"}),
    "wmi_filter": frozenset({"query"}),
    "ou_tree": frozenset({"name"}),
    "coverage_gap": frozenset({"display_name", "detail"}),
    "principal": frozenset({"name"}),
    "group_member": frozenset({"name"}),
    "finding": frozenset({"summary", "detail", "remediation", "gpo_name"}),
    "finding_observation": frozenset({"summary", "evidence_json", "remediation", "gpo_name"}),
    # rationale (added in v6) is analyst text like note; it was missing here, so a
    # labelled cpassword in a legacy rationale refused the v11 upgrade.
    "finding_triage": frozenset({"note", "rationale"}),
    "finding_triage_event": frozenset({"note", "rationale"}),
    "evaluation_run": frozenset({"error_summary"}),
    "analysis_input": frozenset({"metadata_json"}),
    "events": frozenset({"payload"}),
}
_JSON_COLUMNS = frozenset(
    {
        ("setting", "raw"),
        ("events", "payload"),
        ("finding_observation", "evidence_json"),
        ("analysis_input", "metadata_json"),
    }
)
_SETTING_TEXT = ("identity", "display_name", "display_value", "raw")


def _text_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    """Every column: SQLite is dynamically typed, so a column of any declared
    affinity can hold a TEXT or BLOB value at runtime."""
    return [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]


def _detect_views(value: object) -> list[str]:
    """Every text reading of a stored value, for discovery and verification.

    TEXT as is; a BLOB as Latin-1 (byte-exact, covers ASCII/UTF-8) and as
    UTF-16 at both byte alignments (covers UTF-16LE/BE). Numbers and NULL hold
    no text.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, (bytes, memoryview)):
        data = bytes(value)
        return [
            data.decode("latin-1"),
            data.decode("utf-16-le", errors="replace"),
            data[1:].decode("utf-16-le", errors="replace"),
        ]
    return []


_Encoding = tuple[str, bytes, bytes] | None


def _rewrite_views(value: object) -> list[tuple[str, _Encoding]]:
    """Readings of a stored value that can be written back exactly, with how to
    re-encode them (``None`` for TEXT; else encoding plus the bytes before and
    after the decoded part, so a misaligned or odd-length UTF-16 BLOB keeps
    its extra byte)."""
    if isinstance(value, str):
        return [(value, None)]
    if not isinstance(value, (bytes, memoryview)):
        return []
    data = bytes(value)
    views: list[tuple[str, _Encoding]] = [(data.decode("latin-1"), ("latin-1", b"", b""))]
    for offset in (0, 1):
        end = offset + (len(data) - offset) // 2 * 2
        body = data[offset:end]
        for encoding in ("utf-16-le", "utf-16-be"):
            try:
                text = body.decode(encoding)
            except UnicodeDecodeError:
                continue
            views.append((text, (encoding, data[:offset], data[end:])))
    return views


def _encode(text: str, encoding: _Encoding) -> object:
    if encoding is None:
        return text
    name, prefix, suffix = encoding
    return prefix + text.encode(name) + suffix


# Replacement for a BLOB cell whose value shows only in a reading that cannot
# be written back exactly: the whole cell goes, so it can never pin the
# database below v11 (v1.4.0 never wrote BLOBs; such a cell was modified).
_WHOLE_CELL_JSON = json.dumps({"redacted": CPASSWORD_MARKER})


def _whole_cell(table: str, column: str) -> str:
    return _WHOLE_CELL_JSON if (table, column) in _JSON_COLUMNS else CPASSWORD_MARKER


def _labelled_value(table: str, column: str, value: object) -> tuple[object, set[str]]:
    """``_labelled`` for a stored value of any storage class."""
    found: set[str] = set()
    for view in _detect_views(value):
        found |= _labelled(table, column, view)[1]
    for view, encoding in _rewrite_views(value):
        new, _ = _labelled(table, column, view)
        if new != view:
            return _encode(new, encoding), found
    return value, found


def _chased_value(
    table: str, column: str, value: object, chaser: Chaser, pieces: set[str] | None = None
) -> object:
    """``_chased`` for a stored value of any storage class."""
    for view, encoding in _rewrite_views(value):
        new = _chased(table, column, view, chaser, pieces)
        if new != view:
            return _encode(new, encoding)
    return value


def _value_hits(value: object, chaser: Chaser) -> bool:
    return bool(chaser) and any(chaser.hits(view) for view in _detect_views(value))


def _user_tables(conn: sqlite3.Connection) -> list[str]:
    return [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    ]


def _json_container(text: str) -> Any:
    if not text.lstrip().startswith(("{", "[")):
        return None
    try:
        parsed = json.loads(text)
    except ValueError:
        return None
    return parsed if isinstance(parsed, (dict, list)) else None


def _labelled(table: str, column: str, value: str) -> tuple[str, set[str]]:
    """Labelled-form redaction of one stored value (JSON-aware)."""
    if (table, column) in _JSON_COLUMNS:
        parsed = _json_container(value)
        if parsed is not None:
            redacted, found = redact_structure(parsed)
            if redacted == parsed:
                return value, found
            return json.dumps(redacted, sort_keys=True), found
    return redact_inline(value)


def _chased(
    table: str, column: str, value: str, chaser: Chaser, pieces: set[str] | None = None
) -> str:
    location = f"{table}.{column}"
    if (table, column) in _JSON_COLUMNS:
        parsed = _json_container(value)
        if parsed is not None:
            new = chase(parsed, chaser, location, rewritable=True, field=location)
            if not chaser.local:
                new = chase_joined(
                    new, chaser, location, rewritable=True, field=location, pieces=pieces
                )
            return value if new is parsed else json.dumps(new, sort_keys=True)
    return chaser.sub(value) if chaser.hits(value) else value


def _register_candidates(conn: sqlite3.Connection, chaser: Chaser) -> None:
    """SQL prefilters that are supersets of what discovery and the chase can see.

    Plain text holds only inline assignments, which ``redact_inline`` finds by
    the same contiguous ``cpassword`` regex. Stored JSON can also split the word
    across mixed-content nodes (a node with both ``text`` and ``children``) or
    hide letters behind ``\\u`` escapes, so those rows are always parsed.
    """

    def one_text(value: str) -> bool:
        return mentions_cpassword(value) or (bool(chaser) and chaser.contains(value))

    def one_json(value: str) -> bool:
        return (
            mentions_cpassword(value)
            or ('"children"' in value and '"text"' in value)
            or "\\u" in value
            or (bool(chaser) and chaser.hits_json(value))
        )

    # Any storage class: a BLOB is tested in every reading (``_detect_views``).
    def text(value: object) -> int:
        return int(any(one_text(view) for view in _detect_views(value)))

    def json_text(value: object) -> int:
        return int(any(one_json(view) for view in _detect_views(value)))

    conn.create_function("gpo_lens_cpw_text", 1, text, deterministic=True)
    conn.create_function("gpo_lens_cpw_json", 1, json_text, deterministic=True)
    # Whether the functions carry a chaser: a constant per statement (SQLite
    # factors deterministic zero-argument calls), kept on the connection.
    active = int(bool(chaser))
    conn.create_function("gpo_lens_cpw_active", 0, lambda: active, deterministic=True)


def _candidate_where(conn: sqlite3.Connection, table: str, column: str) -> str:
    """SQL condition selecting the rows the candidate functions would select.

    Without a chaser, printable-ASCII TEXT is decided in SQL: there SQLite's
    ASCII ``lower`` plus ``instr`` is exactly the case-insensitive ``cpassword``
    test (non-ASCII folds such as long s or the Kelvin sign only occur in the
    other branch). Numbers and NULL hold no text. Everything else, and every
    value when a chaser is active, goes to the Python functions.
    """
    is_json = (table, column) in _JSON_COLUMNS
    fn = "gpo_lens_cpw_json" if is_json else "gpo_lens_cpw_text"
    col = f'"{column}"'
    python = f"{fn}({col})"
    sql_hit = f"instr(lower({col}), 'cpassword') > 0"
    if is_json:
        sql_hit += (
            f" OR (instr({col}, '\"children\"') > 0 AND instr({col}, '\"text\"') > 0)"
            f" OR instr({col}, '\\u') > 0"
        )
    return (
        f"(CASE WHEN gpo_lens_cpw_active() THEN {python} "
        f"WHEN typeof({col}) IN ('integer', 'real', 'null') THEN 0 "
        f"WHEN typeof({col}) = 'text' AND {col} NOT GLOB '*[^ -~]*' THEN ({sql_hit}) "
        f"ELSE {python} END)"
    )


def _candidate_rows(conn: sqlite3.Connection, table: str, column: str) -> list[tuple[int, Any]]:
    return conn.execute(
        f'SELECT rowid, "{column}" FROM "{table}" WHERE {_candidate_where(conn, table, column)}'
    ).fetchall()


def _discover_at_rest(conn: sqlite3.Connection, tables: list[str]) -> set[str]:
    """Every cpassword value in any stored form, in any text column of any table.

    Uses the superset prefilters of ``_register_candidates`` (no SQL ``LIKE``).
    Also re-reads collected SYSVOL still present at a stored ``sysvol_path``,
    so copies of a SYSVOL value can be chased (v1.4.0 never stored the value).
    """
    _register_candidates(conn, Chaser(()))
    found: set[str] = set()
    for table in tables:
        for column in _text_columns(conn, table):
            for _, value in _candidate_rows(conn, table, column):
                found |= _labelled_value(table, column, value)[1]
    if "gpo" in tables and _column_exists(conn, "gpo", "sysvol_path"):
        paths = [
            row[0]
            for row in conn.execute(
                "SELECT DISTINCT sysvol_path FROM gpo WHERE sysvol_path IS NOT NULL"
            )
        ]
        found |= sysvol_values_at(p for p in paths if os.path.isdir(p))
    return found


def _value_residual(table: str, column: str, value: object, chaser: Chaser) -> bool:
    """A labelled value, or a copy the chase rules cover, is still in *value*
    (in any reading of any storage class)."""
    return any(_view_residual(table, column, view, chaser) for view in _detect_views(value))


def _view_residual(table: str, column: str, value: str, chaser: Chaser) -> bool:
    if _labelled(table, column, value)[1]:
        return True
    if not chaser:
        return False
    if (table, column) in _JSON_COLUMNS:
        parsed = _json_container(value)
        if parsed is not None:
            return any(chaser.hits(text) for text in iter_strings(parsed)) or joined_hits(
                parsed, chaser
            )
    return chaser.hits(value)


def _residual_at_rest(conn: sqlite3.Connection, tables: list[str], chaser: Chaser) -> list[str]:
    """Independent re-check of every text column after the scrub."""
    _register_candidates(conn, chaser)
    out: list[str] = []
    for table in tables:
        for column in _text_columns(conn, table):
            if any(
                _value_residual(table, column, value, chaser)
                for _, value in _candidate_rows(conn, table, column)
            ):
                out.append(f"{table}.{column}")
    return out


def _scrub_cpassword_at_rest(conn: sqlite3.Connection) -> _ScrubResult | None:
    """Erase every stored GPP cpassword value and its copies (schema v11).

    1. Discover values in every stored form, in every text column (and SYSVOL
       still on disk), before changing anything.
    2. Plan every rewrite: labelled forms anywhere; copies (``redaction.Chaser``
       rules, compared canonically) in the descriptive columns of
       ``REWRITABLE_COLUMNS``; a setting's own values through that setting
       row. A labelled form or copy in any other (structural) column refuses
       the whole migration, unchanged.
    3. Apply; cpassword findings drop the four-character prefix older releases
       kept. Re-hash the event chain from the first rewritten event, keeping
       any break that existed before (it is not blessed), then verify that no
       new break exists.
    4. Verify independently: rediscover over every text column and search for
       every discovered value. If anything remains, roll the whole scrub back
       (so the labelled sources stay discoverable), warn, and return ``None``:
       the schema stays below v11 and the same check runs on every read-write
       open. Otherwise record a ``maintenance.cpassword_scrub`` event (counts
       and event ids, never a value).
    """
    with guarded_diagnostics() as pool:
        return _scrub_guarded(conn, pool)


def _scrub_guarded(conn: sqlite3.Connection, pool: set[str]) -> _ScrubResult | None:
    tables = _user_tables(conn)
    broken_before = frozenset(verify_event_chain(conn)[1]) if "events" in tables else frozenset()
    values = _discover_at_rest(conn, tables)
    pool |= values
    chaser = Chaser(values)
    _register_candidates(conn, chaser)
    plan: dict[tuple[str, str], list[tuple[object, int]]] = {}
    refused: set[str] = set()

    def stage(table: str, column: str, rowid: int, old: object, new: object) -> None:
        if new != old:
            plan.setdefault((table, column), []).append((new, rowid))

    if "setting" in tables:
        # A setting's own labelled values also chase through that same row.
        where = " OR ".join(_candidate_where(conn, "setting", c) for c in _SETTING_TEXT)
        for rowid, *texts in conn.execute(
            f"SELECT rowid, {', '.join(_SETTING_TEXT)} FROM setting WHERE {where}"
        ).fetchall():
            labelled: dict[str, object] = {}
            own: set[str] = set()
            for column, text in zip(_SETTING_TEXT, texts, strict=True):
                labelled[column], found = _labelled_value("setting", column, text)
                own |= found
            local = Chaser(own, local=True)
            pieces: set[str] = set()
            planned: dict[str, object] = {}
            # raw first: pieces of a split copy then chase the derived columns.
            for column in ("raw", "identity", "display_name", "display_value"):
                text = texts[_SETTING_TEXT.index(column)]
                new = _chased_value("setting", column, labelled[column], local)
                new = _chased_value("setting", column, new, chaser, pieces)
                if column != "raw" and pieces:
                    new = _chased_value("setting", column, new, Chaser(pieces, local=True))
                if isinstance(text, (bytes, memoryview)) and _value_residual(
                    "setting", column, new, chaser
                ):
                    new = _whole_cell("setting", column)
                planned[column] = new
            for column, text in zip(_SETTING_TEXT, texts, strict=True):
                stage("setting", column, rowid, text, planned[column])
    for table in tables:
        rewritable = REWRITABLE_COLUMNS.get(table, frozenset())
        for column in _text_columns(conn, table):
            if table == "setting" and column in _SETTING_TEXT:
                continue
            for rowid, value in _candidate_rows(conn, table, column):
                new, found = _labelled_value(table, column, value)
                if column in rewritable:
                    new = _chased_value(table, column, new, chaser)
                    if isinstance(value, (bytes, memoryview)) and _value_residual(
                        table, column, new, chaser
                    ):
                        new = _whole_cell(table, column)
                    stage(table, column, rowid, value, new)
                elif found or _value_hits(value, chaser):
                    refused.add(f"{table}.{column}")
    if refused:
        conn.rollback()
        raise CredentialInIdentityError(", ".join(sorted(refused)))

    changed: dict[str, int] = {}
    for (table, column), updates in plan.items():
        conn.executemany(f'UPDATE "{table}" SET "{column}" = ? WHERE rowid = ?', updates)
        changed[f"{table}.{column}"] = len(updates)
    if "finding" in tables:
        where = "rule_id = 'cpassword'"
        if _column_exists(conn, "finding", "detector_id"):
            where += " OR detector_id = 'cpassword'"
        cur = conn.execute(
            f"UPDATE finding SET detail = ? WHERE ({where}) AND detail != ?",
            (CPASSWORD_FINDING_DETAIL, CPASSWORD_FINDING_DETAIL),
        )
        if cur.rowcount:
            changed["finding.detail"] = changed.get("finding.detail", 0) + cur.rowcount

    rewritten = sorted(rowid for _, rowid in plan.get(("events", "payload"), []))
    rehashed = (
        rehash_event_chain(conn, rewritten[0], keep_broken=broken_before) if rewritten else []
    )
    if "events" in tables:
        # Exactly the same breaks: none healed, none added (rewritten events
        # that verified before must verify now).
        broken_after = frozenset(verify_event_chain(conn)[1])
        if broken_after != broken_before:
            conn.rollback()
            raise RuntimeError(
                "cpassword scrub: re-hashing changed which events verify (breaks before "
                f"{sorted(broken_before)}, after {sorted(broken_after)}); nothing was changed."
            )
    residual = _residual_at_rest(conn, tables, chaser)
    if residual:
        conn.rollback()
        warnings.warn(
            "cpassword scrub could not be verified (a value remains in "
            f"{', '.join(residual)}); nothing was changed. The database stays at "
            f"schema {_CPASSWORD_SCRUB_VERSION - 1} and the check runs again on every "
            "read-write open.",
            stacklevel=3,
        )
        return None
    if changed and "events" in tables:
        append_event(
            conn,
            "maintenance.cpassword_scrub",
            {
                "changed": dict(sorted(changed.items())),
                "discovered_value_count": len(values),
                "rewritten_event_ids": rewritten,
                "rehashed_event_ids": rehashed,
                "pre_existing_broken_event_ids": sorted(broken_before),
            },
            commit=False,
        )
    if broken_before:
        warnings.warn(
            "cpassword scrub: the event hash chain was already broken at "
            f"{sorted(broken_before)} before migration; those breaks were kept, not re-hashed.",
            stacklevel=3,
        )
    return _ScrubResult(changed, frozenset(chaser.values), broken_before)


_SIDECARS = ("", "-wal", "-shm", "-journal")


def _bytes_hold_any(path: str, chaser: Chaser) -> bool:
    """A discovered value (canonically, as stored text or JSON) in a file's bytes,
    read as Latin-1 (ASCII/UTF-8) and as UTF-16 at both alignments."""
    if not chaser or not os.path.exists(path):
        return False
    overlap = 1 << 16
    tail = ""
    with open(path, "rb") as handle:
        while chunk := handle.read(4 << 20):
            window = tail + chunk.decode("latin-1")
            readings = (
                window,
                window.encode("latin-1").decode("utf-16-le", errors="replace"),
                window.encode("latin-1")[1:].decode("utf-16-le", errors="replace"),
            )
            if any(chaser.hits(_JSON_ESCAPE.sub(" ", text)) for text in readings):
                return True
            tail = window[-overlap:]
    return False


def _database_path(conn: sqlite3.Connection) -> str:
    row = conn.execute("PRAGMA database_list").fetchone()
    return row[2] if row and row[2] else ""


def _file_role(path: str) -> str:
    for suffix in ("-wal", "-shm", "-journal"):
        if path.endswith(suffix):
            return f"the database {suffix} file"
    return "the database file"


def cpassword_file_hits(path: str, values: Iterable[str]) -> list[str]:
    """Of a database's files (main, -wal, -shm, -journal), those whose raw bytes
    hold a discovered value."""
    chaser = Chaser(values)
    if not path or not chaser:
        return []
    return [f"{path}{suffix}" for suffix in _SIDECARS if _bytes_hold_any(f"{path}{suffix}", chaser)]


def cpassword_bytes_present(conn: sqlite3.Connection, values: Iterable[str]) -> list[str]:
    """``cpassword_file_hits`` for the database behind *conn*."""
    return cpassword_file_hits(_database_path(conn), values)


def verify_committed_estate(conn: sqlite3.Connection, estate: Estate) -> None:
    """Post-commit check of a fresh ingest: no discovered value in the file bytes.

    A hit can only come from bytes outside the verified rows (uncommitted WAL
    frames, earlier free pages); they are purged with a truncating checkpoint
    and ``VACUUM`` and checked again. Raises ``CpasswordResidualError`` if a
    value still remains.
    """
    values = estate_cpassword_values(estate)
    try:
        with guarded_diagnostics(set(values)):
            if cpassword_bytes_present(conn, values):
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                conn.execute("VACUUM")
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                remaining = cpassword_bytes_present(conn, values)
                if remaining:
                    # Name the files by role; the database path is operator input.
                    raise CpasswordResidualError(", ".join(_file_role(path) for path in remaining))
    finally:
        forget_cpassword_values(estate)


def _purge_free_pages(conn: sqlite3.Connection, scrub: _ScrubResult) -> None:
    """Physically remove scrubbed bytes, verify, then stamp the current version.

    An UPDATE leaves the previous cell content in free space, free pages and
    the WAL. ``VACUUM`` rebuilds the database from live rows only; in WAL mode
    the rebuilt pages land in the WAL, and only a complete ``TRUNCATE``
    checkpoint overwrites (and shrinks) the main file and empties the WAL. The
    version is stamped only when, after that, the event chain has no new break
    and no discovered value occurs (canonically) in the bytes of the main file,
    ``-wal``, ``-shm`` or ``-journal``. Otherwise it
    stays below ``_CPASSWORD_SCRUB_VERSION`` and the next read-write open
    scrubs (a no-op by then) and purges again.
    """
    retry = (
        "The cpassword scrub is committed, but the old bytes may remain in unused "
        "database pages until the purge succeeds; it is retried on the next "
        "read-write open."
    )
    try:
        conn.execute("VACUUM")
        busy = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    except sqlite3.OperationalError as exc:
        warnings.warn(f"cpassword purge: VACUUM failed ({exc}). {retry}", stacklevel=2)
        return
    if busy is not None and busy[0]:
        warnings.warn(
            f"cpassword purge: another connection prevented the WAL checkpoint. {retry}",
            stacklevel=2,
        )
        return
    if _table_exists(conn, "events"):
        broken = frozenset(verify_event_chain(conn)[1])
        if broken != scrub.allowed_broken_events:
            warnings.warn(
                "cpassword purge: the set of events failing verification changed "
                f"({sorted(scrub.allowed_broken_events)} -> {sorted(broken)}); schema not stamped.",
                stacklevel=2,
            )
            return
    if cpassword_bytes_present(conn, scrub.values):
        warnings.warn(
            f"cpassword purge: a discovered value is still in the file. {retry}", stacklevel=2
        )
        return
    conn.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")


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


def _value_key(value: Any) -> tuple[str, Any]:
    """A hashable form of a stored non-NULL value that is equal for two values
    exactly when SQLite's ``=`` says they are (no affinity, as between two
    TEXT-affinity columns): equal storage class, INTEGER and REAL compared as
    numbers. Python's own ``int``/``float`` equality and hashing are exact
    (``1 == 1.0``, ``2**53 + 1 != float(2**53)``), as SQLite's comparison is."""
    if isinstance(value, bytearray | memoryview):
        value = bytes(value)
    if isinstance(value, bool | int | float):
        return ("num", value)
    if isinstance(value, bytes):
        return ("blob", value)
    if isinstance(value, str):
        return ("text", value)
    return ("other", object())  # never stored by SQLite: equal to nothing


def _is_null(value: Any) -> bool:
    # SQLite stores a NaN REAL as NULL.
    return value is None or (isinstance(value, float) and math.isnan(value))


def _match_key(value: Any) -> tuple[str, Any]:
    """``=`` semantics: NULL equals nothing, so it gets a key no other value
    shares."""
    return ("null", object()) if _is_null(value) else _value_key(value)


def _is_key(value: Any) -> tuple[str, Any]:
    """``IS`` semantics: NULL equals NULL."""
    return ("null", None) if _is_null(value) else _value_key(value)


# The columns of ``finding_triage_event`` a legacy copy writes, in the order
# legacy_triage_matches compares them (expires_at last, with IS), and the ones
# a legacy copy always leaves NULL. With ``id`` they are every column of the
# table (a test enumerates the schema), so a pre-fix copy is recognised by all
# of them.
LEGACY_COPY_COMPARED: tuple[str, ...] = (
    "occurrence_id",
    "action",
    "occurred_at",
    "actor",
    "note",
    "rationale",
    "expires_at",
)
LEGACY_COPY_NULL: tuple[str, ...] = ("supersedes_event_id",)


def legacy_triage_matches(
    legacy: list[tuple[int, tuple[Any, ...]]], events: list[tuple[int, tuple[Any, ...]]]
) -> dict[int, int]:
    """One-to-one assignment of legacy rows to existing events with exactly
    the same stored fields (``(id, fields)`` pairs in
    :data:`LEGACY_COPY_COMPARED` order; ``expires_at`` last, compared with
    ``IS``). Exact equality is an equivalence relation, so the compatibility
    graph is a disjoint union of complete bipartite groups and pairing rows and
    events in id order within each group is a maximum matching. Returns
    ``{legacy_id: event_id}``."""

    def key(fields: tuple[Any, ...]) -> tuple[Any, ...]:
        *compared, expires = fields
        return (*map(_match_key, compared), _is_key(expires))

    free: dict[tuple[Any, ...], list[int]] = {}
    for event_id, fields in sorted(events):
        free.setdefault(key(fields), []).append(event_id)
    matched: dict[int, int] = {}
    for legacy_id, fields in sorted(legacy):
        group = free.get(key(fields))
        if group:
            matched[legacy_id] = group.pop(0)
    return matched


def _migrate_legacy_triage(conn: sqlite3.Connection) -> None:
    """v7 -> v8 (WI-092): copy legacy ``finding_triage`` rows into the Plan 024
    ``finding_triage_event`` log so triage state lives in one store.

    Status mapping: ``open`` -> ``reopened`` (the v2 action that folds to
    open); ``acknowledged``/``accepted_risk`` carry over. For accepted-risk
    rows, fall back to the note as the rationale when the v1 row recorded none
    (v1 had no rationale concept) — nothing is fabricated beyond the
    operator's own text. Orphaned legacy rows are skipped defensively: old
    databases may have been modified while foreign-key enforcement was
    disabled. Released v1.1/v1.2 exposed both APIs. Existing event IDs
    (including supersedes references) remain immutable; converted rows get
    stable IDs in legacy chronological order. Readers normalize timestamps to
    UTC and prefer reopen/revoke/expiry at equal instants before the ID
    tie-breaker, so migrated approvals cannot reinstate a reopened risk.

    **When this runs.** On every open while the schema is below the current
    version: an upgrade from any older release, including v8-v10 databases
    whose release already copied these rows verbatim, and every open while the
    v11 cpassword scrub has not been stamped (the additive migrations commit
    first, so the copy is already committed when a scrub is refused or its
    purge is retried).

    **Provenance.** Each copied or recognised legacy row is recorded in
    ``finding_triage_legacy_copy`` (legacy row id -> event id) in the same
    transaction as the copy, so a re-run copies exactly the legacy rows not
    yet recorded and never guesses. Legacy rows with no record can only have
    been copied by a release before this table existed, which copied them
    verbatim: those are recognised by exact equality of every stored field
    (one event per legacy row, :func:`legacy_triage_matches`), recorded, and
    left as they are — the triage log is not rewritten; ``analyst-text-check``
    lists a refused value there.

    **What is copied.** Operator text passes ``analyst_text.migrated_value``:
    TEXT the guard would refuse, and any BLOB (gpo-lens never writes one there,
    and a BLOB has no declared encoding to check), is copied as a marker
    (``[refused principal name]`` / ``[refused analyst text]``); NULL, INTEGER
    and REAL are copied. The legacy row is left exactly as it was, so
    ``gpo-lens analyst-text-check`` still lists it, and substitutions are
    recorded by legacy row id and field only (a
    ``maintenance.analyst_text_substituted`` event and a warning). The upgrade
    is not refused: nobody can edit the legacy table from the app, and a
    database stuck below v8 would never reach the v11 cpassword scrub.
    """
    if not conn.execute("SELECT 1 FROM finding_triage LIMIT 1").fetchone():
        return  # nothing to copy: create nothing (an up-to-date open writes nothing)
    # Provenance of this copy: which event a legacy row became (NULL: withheld,
    # see below), so a re-run handles exactly the rows not yet recorded. Ids
    # only. The DDL runs inside the copy's own transaction (Python's sqlite3
    # would otherwise run it outside one), so a crash leaves no trace.
    if not conn.in_transaction:
        conn.execute("BEGIN")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_triage_legacy_copy (
            legacy_id INTEGER PRIMARY KEY
                REFERENCES finding_triage(id) ON DELETE CASCADE,
            event_id INTEGER UNIQUE
                REFERENCES finding_triage_event(id) ON DELETE CASCADE
        )
        """
    )
    legacy = conn.execute(
        """
        SELECT t.id, t.finding_id, t.status, t.actor, t.timestamp, t.note,
               t.rationale, t.expires_at
        FROM finding_triage t
        JOIN finding f ON f.id = t.finding_id
        WHERE t.id NOT IN (SELECT legacy_id FROM finding_triage_legacy_copy)
        ORDER BY t.timestamp, t.id
        """
    ).fetchall()
    if not legacy:
        return
    # Rows copied before provenance existed: recognise them exactly, by what a
    # pre-fix release wrote (status mapped by its CASE, rationale falling back
    # to the note, supersedes NULL).
    compared = ", ".join(LEGACY_COPY_COMPARED)
    unset = " AND ".join(f"{column} IS NULL" for column in LEGACY_COPY_NULL)
    events = conn.execute(
        f"SELECT id, {compared} FROM finding_triage_event WHERE {unset} "  # noqa: S608
        "AND id NOT IN (SELECT event_id FROM finding_triage_legacy_copy "
        "WHERE event_id IS NOT NULL)"
    ).fetchall()
    rows = [_legacy_triage_view(*row) for row in legacy]
    recognised = legacy_triage_matches(
        [(row["legacy_id"], row["prefix_fields"]) for row in rows],
        [(event[0], tuple(event[1:])) for event in events],
    )
    substitutions: list[dict[str, Any]] = []
    withheld = 0
    for row in rows:
        legacy_id = row["legacy_id"]
        event_id = recognised.get(legacy_id)
        if event_id is None:
            event_id = _copy_legacy_triage_row(conn, row, substitutions)
            withheld += event_id is None
        conn.execute(
            "INSERT INTO finding_triage_legacy_copy (legacy_id, event_id) VALUES (?, ?)",
            (legacy_id, event_id),
        )
    if substitutions:
        append_event(
            conn,
            "maintenance.analyst_text_substituted",
            {"source_table": "finding_triage", "substitutions": substitutions},
            commit=False,
        )
        warnings.warn(
            f"triage migration: {len(substitutions)} legacy field(s) carried GPP "
            "cpassword material, could not be inspected, or were not a v1 status or "
            "timestamp; they were copied as a marker (an unknown status as a "
            f"'commented' event), and {withheld} row(s) with a malformed timestamp "
            "were not copied. The legacy rows are unchanged (gpo-lens "
            "analyst-text-check lists them; the maintenance.analyst_text_substituted "
            "event names row ids and fields).",
            stacklevel=3,
        )


def _legacy_triage_view(
    legacy_id: int,
    finding_id: Any,
    status: Any,
    actor: Any,
    timestamp: Any,
    note: Any,
    rationale: Any,
    expires: Any,
) -> dict[str, Any]:
    """One legacy row, plus the fields a pre-fix release wrote for it (its
    ``CASE`` status mapping, and ``COALESCE(NULLIF(rationale, ''), note, '')``
    for accepted risk), in :data:`LEGACY_COPY_COMPARED` order."""
    accepted = isinstance(status, str) and status == "accepted_risk"
    prefix_action = "reopened" if isinstance(status, str) and status == "open" else status
    if accepted:
        kept = None if isinstance(rationale, str) and rationale == "" else rationale
        prefix_rationale = kept if not _is_null(kept) else (note if not _is_null(note) else "")
    else:
        prefix_rationale = ""
    return {
        "legacy_id": legacy_id,
        "finding_id": finding_id,
        "status": status,
        "actor": actor,
        "timestamp": timestamp,
        "note": note,
        "rationale": prefix_rationale,
        "expires": expires,
        "prefix_fields": (
            finding_id,
            prefix_action,
            timestamp,
            actor,
            note,
            prefix_rationale,
            expires,
        ),
    }


def _copy_legacy_triage_row(
    conn: sqlite3.Connection, row: dict[str, Any], substitutions: list[dict[str, Any]]
) -> int | None:
    """Copy one legacy row the safe way, or withhold it. Returns the new event
    id, or None when the row is withheld.

    Structural fields must hold what v1 wrote (``legacy_triage_field_ok``): an
    unknown status becomes a ``commented`` event (no status effect; its
    decision is not carried over); a malformed timestamp or expiry withholds
    the row, since neither has a neutral replacement (an invented time would
    misorder history; a dropped expiry would make a risk acceptance permanent).
    Operator text passes ``migrated_value``. Every substitution is recorded by
    legacy row id and field only."""
    legacy_id = row["legacy_id"]

    def note(field: str, kind: str) -> None:
        substitutions.append({"row_id": legacy_id, "field": field, "kind": kind})

    bad_times = [
        field
        for field, value in (("timestamp", row["timestamp"]), ("expires_at", row["expires"]))
        if not legacy_triage_field_ok(field, value)
    ]
    if bad_times:
        for field in bad_times:
            note(field, "uninspectable")
        return None
    if legacy_triage_field_ok("status", row["status"]):
        action = LEGACY_TRIAGE_ACTIONS[row["status"]]
        rationale = row["rationale"]
    else:
        note("status", "uninspectable")
        action, rationale = "commented", ""
    copied_actor, actor_kind = migrated_value(row["actor"], "actor")
    copied_note, note_kind = migrated_value(row["note"], "note")
    copied_rationale, rationale_kind = migrated_value(rationale, "rationale")
    for field, kind in (("actor", actor_kind), ("note", note_kind), ("rationale", rationale_kind)):
        if kind is not None:
            note(field, kind)
    return conn.execute(
        """
        INSERT INTO finding_triage_event
            (occurrence_id, action, actor, occurred_at, note, rationale,
             expires_at, supersedes_event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
        """,
        (
            row["finding_id"],
            action,
            copied_actor,
            row["timestamp"],
            copied_note,
            copied_rationale,
            row["expires"],
        ),
    ).lastrowid


def _migrate_schema(conn: sqlite3.Connection, *, fresh: bool = False) -> _ScrubResult | None:
    """Additive column migrations for DBs created by older gpo-lens versions.

    Migration state is tracked via ``PRAGMA user_version``. The version stamp
    lets us fail fast when opening a DB written by a newer gpo-lens, while the
    per-column ``_column_exists`` checks keep individual migrations idempotent in
    case a partially-migrated DB is opened again.

    ``CREATE TABLE IF NOT EXISTS`` won't add columns to an existing table, so
    each additive column needs an ``ALTER TABLE`` here guarded by a column
    check. Only additive (NULLable) columns — never renames or drops. The one
    data rewrite is the v11 cpassword scrub, which is idempotent.

    One table is not created by ``init_db``: ``finding_triage_legacy_copy``,
    the provenance of the v7 -> v8 triage copy, is created by
    :func:`_migrate_legacy_triage` inside the copy's transaction and only when
    there are legacy rows, so an open that has nothing to copy writes nothing.

    Returns the scrub result when the caller must purge free pages
    (``_purge_free_pages``) after committing; the version is then stamped one
    below the scrub version until that purge and its checks succeed. A fresh
    database (no tables before ``init_db``) is stamped current directly.
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
        # Plan 024 ``finding_triage_event`` log; see _migrate_legacy_triage.
        _migrate_legacy_triage(conn)

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

        # Preserve historical uncertainty: occurrence versions are mutable and
        # cannot establish which detector evaluated an older observation.
        if not _column_exists(conn, "finding_observation", "detector_version"):
            conn.execute("ALTER TABLE finding_observation ADD COLUMN detector_version TEXT")

    if user_version < _CPASSWORD_SCRUB_VERSION and not fresh:
        # v10 -> v11: no cpassword value at rest. secure_delete zeroes the old
        # cell content this connection frees; the VACUUM after commit removes
        # what earlier deletes left in free pages.
        # The additive migrations above are committed first, so a scrub that
        # is refused or cannot be verified rolls back only its own rewrites.
        if user_version != _CPASSWORD_SCRUB_VERSION - 1:
            conn.execute(f"PRAGMA user_version = {_CPASSWORD_SCRUB_VERSION - 1}")
        conn.commit()
        previous = conn.execute("PRAGMA secure_delete").fetchone()[0]
        conn.execute("PRAGMA secure_delete = ON")
        try:
            return _scrub_cpassword_at_rest(conn)
        finally:
            conn.execute(f"PRAGMA secure_delete = {int(previous)}")

    if user_version != CURRENT_SCHEMA_VERSION:  # no write on an up-to-date DB
        conn.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")
    return None


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
        warnings.warn(
            f"Could not restrict permissions on the database file: {describe_error(exc)}",
            stacklevel=1,
        )
    for suffix in ("-wal", "-shm"):
        sidecar = f"{path}{suffix}"
        if os.path.exists(sidecar):
            try:
                os.chmod(sidecar, 0o600)
            except (OSError, ValueError) as exc:
                warnings.warn(
                    f"Could not restrict permissions on the database {suffix} file: "
                    f"{describe_error(exc)}",
                    stacklevel=1,
                )


def _dt_to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.isoformat()


def save_estate(
    conn: sqlite3.Connection,
    estate: Estate,
    taken_at: datetime | None = None,
    *,
    commit: bool = True,
    _cpassword_values: frozenset[str] | None = None,
) -> int:
    """Save an estate as a new snapshot; returns the new ``snapshot_id``.

    GPP cpassword values are redacted and their copies chased through the
    estate first (in place; ``redaction.sanitize_for_storage``), unless the
    caller already did and passes the values (``_cpassword_values``). A copy
    in an identity field raises ``CredentialInIdentityError`` before anything
    is written. The rows written are then read back and verified
    independently (``_verify_snapshot_rows``); a residual raises
    ``CpasswordResidualError`` and the caller must roll back.
    """
    with guarded_diagnostics() as pool:
        return _save_estate(conn, estate, taken_at, commit, _cpassword_values, pool)


def _save_estate(
    conn: sqlite3.Connection,
    estate: Estate,
    taken_at: datetime | None,
    commit: bool,
    _cpassword_values: frozenset[str] | None,
    pool: set[str],
) -> int:
    values = sanitize_for_storage(estate) if _cpassword_values is None else _cpassword_values
    pool |= values
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
                    stored_json(s.raw),
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
    release_serialized()
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

    if _cpassword_values is None:  # save_evaluated_estate verifies after evaluation
        residual = _verify_snapshot_rows(conn, snapshot_id, values)
        if residual:
            raise CpasswordResidualError(", ".join(residual))
    if commit:
        conn.commit()
    restrict_db_permissions(conn)
    return snapshot_id


def _verify_snapshot_rows(
    conn: sqlite3.Connection, snapshot_id: int, values: Iterable[str]
) -> list[str]:
    """Read back one snapshot's rows (and its finding rows) and re-check them.

    Independent of the in-memory estate: labelled discovery runs again on the
    stored text and JSON, and every discovered value is searched canonically.
    """
    chaser = Chaser(values)
    _register_candidates(conn, chaser)
    out: list[str] = []
    for table in _user_tables(conn):
        columns = {row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')}
        if "snapshot_id" in columns:
            where, args = "snapshot_id = ?", (snapshot_id,)
        elif table == "finding" and "last_seen_snapshot" in columns:
            where, args = "last_seen_snapshot = ?", (snapshot_id,)
        elif table == "finding_observation":
            where = "run_id IN (SELECT id FROM evaluation_run WHERE snapshot_id = ?)"
            args = (snapshot_id,)
        else:
            continue
        for column in _text_columns(conn, table):
            for (value,) in conn.execute(
                f'SELECT "{column}" FROM "{table}" '
                f"WHERE {where} AND {_candidate_where(conn, table, column)}",
                args,
            ):
                if _value_residual(table, column, value, chaser):
                    out.append(f"{table}.{column}")
                    break
    return out


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


def delete_snapshot(conn: sqlite3.Connection, snapshot_id: int, *, commit: bool = True) -> bool:
    """Delete one imported snapshot and all its rows; True if it existed.

    Every child table declares ``ON DELETE CASCADE`` against ``snapshot(id)``,
    so removing the parent row removes the estate wholesale — but SQLite only
    enforces that when ``PRAGMA foreign_keys = ON`` is set on the connection
    (``get_rw_conn`` does). Re-assert it here so a direct caller can't silently
    orphan child rows.
    """
    conn.execute("PRAGMA foreign_keys = ON")
    cur = conn.execute("DELETE FROM snapshot WHERE id = ?", (snapshot_id,))
    if commit:
        conn.commit()
    return cur.rowcount > 0


def save_evaluated_estate(
    conn: sqlite3.Connection,
    estate: Estate,
    *,
    admx: AdmxResolver | None = None,
    commit: bool = True,
) -> int:
    """Atomically import a snapshot and its required finding evaluation.

    Failed evaluation also rolls back observations and transitions on earlier
    occurrences. Deleting just the new snapshot cannot undo those transitions.
    Call after init_db. With commit=False the caller owns the transaction and
    can include required audit/events before committing. Failures roll back.
    """
    with guarded_diagnostics() as pool:
        return _save_evaluated_estate(conn, estate, admx, commit, pool)


def _save_evaluated_estate(
    conn: sqlite3.Connection,
    estate: Estate,
    admx: AdmxResolver | None,
    commit: bool,
    pool: set[str],
) -> int:
    from gpo_lens import __version__
    from gpo_lens.findings import evaluate_finding_lifecycle_v2

    try:
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        values = sanitize_for_storage(estate)
        pool |= values
        sid = save_estate(conn, estate, commit=False, _cpassword_values=values)
        evaluate_finding_lifecycle_v2(
            conn,
            sid,
            estate,
            admx=admx,
            application_version=__version__,
            commit=False,
            cpassword_values=values,
        )
        residual = _verify_snapshot_rows(conn, sid, values)
        if residual:
            raise CpasswordResidualError(", ".join(residual))
        if commit:
            conn.commit()
            verify_committed_estate(conn, estate)
        return sid
    except (CredentialInIdentityError, CpasswordResidualError):
        conn.rollback()
        # Frames written before the rollback may linger in the WAL file.
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        raise
    except Exception as exc:
        conn.rollback()
        raise RuntimeError("Import failed; nothing was imported.") from exc
