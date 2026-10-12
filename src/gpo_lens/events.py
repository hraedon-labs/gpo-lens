"""Append-only event store for tracking GPO estate changes."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any


def init_events_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            schema_version INTEGER NOT NULL DEFAULT 1,
            payload TEXT NOT NULL
        )
        """
    )
    try:
        conn.execute("ALTER TABLE events ADD COLUMN prev_hash TEXT")
    except sqlite3.OperationalError:
        pass
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_events_timestamp
        ON events(timestamp)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_events_event_type
        ON events(event_type)
        """
    )
    conn.commit()


def _compute_hash(prev_hash: str | None, timestamp: str, event_type: str, payload: str) -> str:
    return hashlib.sha256(
        f"{prev_hash or ''}|{timestamp}|{event_type}|{payload}".encode()
    ).hexdigest()


def _escape_like(value: str) -> str:
    """Escape LIKE metacharacters in user input."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def append_event(
    conn: sqlite3.Connection,
    event_type: str,
    payload: dict[str, Any],
    schema_version: int = 1,
    *,
    commit: bool = True,
) -> int:
    ts = datetime.now(UTC).isoformat()
    payload_str = json.dumps(payload, sort_keys=True)
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    row = conn.execute("SELECT prev_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = row[0] if row else None
    new_hash = _compute_hash(prev_hash, ts, event_type, payload_str)
    cursor = conn.execute(
        "INSERT INTO events (timestamp, event_type, schema_version, payload, prev_hash) "
        "VALUES (?, ?, ?, ?, ?)",
        (ts, event_type, schema_version, payload_str, new_hash),
    )
    if commit:
        conn.commit()
    return cursor.lastrowid  # type: ignore[return-value]


def append_events(
    conn: sqlite3.Connection,
    events: list[tuple[str, dict[str, Any]]],
    *,
    schema_version: int = 1,
    commit: bool = True,
) -> list[int]:
    ts = datetime.now(UTC).isoformat()
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    row = conn.execute("SELECT prev_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = row[0] if row else None
    ids: list[int] = []
    for event_type, payload in events:
        payload_str = json.dumps(payload, sort_keys=True)
        new_hash = _compute_hash(prev_hash, ts, event_type, payload_str)
        cursor = conn.execute(
            "INSERT INTO events (timestamp, event_type, schema_version, payload, prev_hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (ts, event_type, schema_version, payload_str, new_hash),
        )
        ids.append(cursor.lastrowid)  # type: ignore[arg-type]
        prev_hash = new_hash
    if commit:
        conn.commit()
    return ids


# Marks a stored hash kept invalid on purpose by ``rehash_event_chain``.
_UNVERIFIED_PREFIX = "unverified-before-rehash:"


def rehash_event_chain(
    conn: sqlite3.Connection, from_id: int, *, keep_broken: Iterable[int] = ()
) -> list[int]:
    """Recompute stored hashes from event ``from_id`` onward; return changed ids.

    Only for a documented, audited rewrite of stored payloads (the v11
    cpassword scrub). The caller must append an event that records the rewrite,
    so the re-chained history still says it was changed and from where.
    Unhashed (``prev_hash IS NULL``) rows stay unhashed, as in
    :func:`verify_event_chain`. Rows in ``keep_broken`` (breaks that existed
    before the rewrite) keep their stored hash, so the rewrite never blesses
    earlier tampering; if a rewritten payload would make one verify, its hash
    is replaced by a marked non-hash, so it still fails verification.
    """
    keep = set(keep_broken)
    row = conn.execute(
        "SELECT prev_hash FROM events WHERE id < ? ORDER BY id DESC LIMIT 1", (from_id,)
    ).fetchone()
    prev_hash: str | None = row[0] if row else None
    changed: list[int] = []
    rows = conn.execute(
        "SELECT id, timestamp, event_type, payload, prev_hash FROM events "
        "WHERE id >= ? ORDER BY id ASC",
        (from_id,),
    ).fetchall()
    for event_id, timestamp, event_type, payload, stored in rows:
        if stored is None:
            prev_hash = None
            continue
        if event_id in keep:
            # A pre-existing break must stay a break. If the rewritten payload
            # now happens (or was crafted) to match the stored hash, store a
            # deterministic non-hash so the row still fails verification.
            if stored == _compute_hash(prev_hash, timestamp, event_type, payload):
                stored = f"{_UNVERIFIED_PREFIX}{stored}"
                conn.execute("UPDATE events SET prev_hash = ? WHERE id = ?", (stored, event_id))
                changed.append(event_id)
            prev_hash = stored
            continue
        expected = _compute_hash(prev_hash, timestamp, event_type, payload)
        if expected != stored:
            conn.execute("UPDATE events SET prev_hash = ? WHERE id = ?", (expected, event_id))
            changed.append(event_id)
        prev_hash = expected
    return changed


def verify_event_chain(conn: sqlite3.Connection) -> tuple[bool, list[int]]:
    """Verify the SHA-256 hash chain of all events.

    Returns ``(True, [])`` if all post-migration events' hashes are intact,
    or ``(False, [broken_ids])`` listing events whose stored hash does not
    match the recomputed value.

    Events with ``prev_hash IS NULL`` (pre-dating the hash-chain migration)
    are skipped — they cannot be verified but are not flagged as tampered.
    """
    try:
        rows = conn.execute(
            "SELECT id, timestamp, event_type, payload, prev_hash FROM events ORDER BY id ASC"
        ).fetchall()
    except sqlite3.OperationalError:
        return True, []
    broken: list[int] = []
    prev_hash: str | None = None
    for row in rows:
        if row[4] is None:
            prev_hash = None
            continue
        expected = _compute_hash(prev_hash, row[1], row[2], row[3])
        if expected != row[4]:
            broken.append(row[0])
        prev_hash = row[4]
    return (len(broken) == 0, broken)


def query_events(
    conn: sqlite3.Connection,
    *,
    since: str | None = None,
    event_type: str | None = None,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if since:
        clauses.append("timestamp >= ?")
        params.append(since)
    if event_type:
        clauses.append("event_type LIKE ? ESCAPE '\\'")
        params.append(f"%{_escape_like(event_type)}%")
    where = " AND ".join(clauses) if clauses else "1=1"
    sql = (
        "SELECT id, timestamp, event_type, schema_version, payload, prev_hash "
        f"FROM events WHERE {where} ORDER BY id ASC LIMIT ?"
    )
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    results: list[dict[str, Any]] = []
    for row in rows:
        results.append(
            {
                "id": row[0],
                "timestamp": row[1],
                "event_type": row[2],
                "schema_version": row[3],
                "payload": json.loads(row[4]),
                "prev_hash": row[5],
            }
        )
    return results
