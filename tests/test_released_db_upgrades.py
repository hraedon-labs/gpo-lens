"""Upgrade actual released databases, including all stored payloads.

Fixtures are immutable output from released CLI/web/API code; tests copy them
before opening. See fixtures/released_databases/README.md for provenance.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
from collections import Counter
from contextlib import closing
from dataclasses import asdict
from pathlib import Path

import pytest

from gpo_lens.events import query_events, verify_event_chain
from gpo_lens.findings import accepted_risk_register, finding_history, load_triage_status_map
from gpo_lens.store import CURRENT_SCHEMA_VERSION, init_db, list_snapshots, load_estate, save_estate

FIXTURES = Path(__file__).parent / "fixtures/released_databases"
TAGS = ("v0.5.0", "v0.7.0", "v0.7.1", "v1.0.0", "v1.1.0", "v1.2.0", "v1.3.1")


def test_previous_release_refuses_schema_10_without_writes(tmp_path: Path) -> None:
    # Exercise the actual released version guard, not a simulated old constant.
    root = Path(__file__).resolve().parent.parent
    old_source = subprocess.check_output(
        ["git", "show", "v1.3.1:src/gpo_lens/store.py"], cwd=root, text=True
    )
    namespace = {"__name__": "gpo_lens._released_store"}
    exec(compile(old_source, "<v1.3.1-store>", "exec"), namespace)  # noqa: S102
    db = tmp_path / "upgraded.sqlite3"
    shutil.copyfile(FIXTURES / "v1.3.1.sqlite3", db)
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        before = list(conn.iterdump())
        with pytest.raises(RuntimeError, match=r"schema version 10.*supports \(version 9\)"):
            namespace["init_db"](conn)
        assert list(conn.iterdump()) == before


def _contents(conn: sqlite3.Connection) -> dict[str, tuple[list[str], list[tuple]]]:
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    )
    result = {}
    for (name,) in tables:
        columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
        result[name] = columns, conn.execute(f'SELECT * FROM "{name}"').fetchall()
    return result


def _preserved(conn: sqlite3.Connection, original: dict) -> None:
    for table, (columns, rows) in original.items():
        projection = ", ".join(f'"{column}"' for column in columns)
        actual = Counter(conn.execute(f'SELECT {projection} FROM "{table}"').fetchall())
        expected = Counter(rows)
        if table == "finding_triage_event":
            # v8 adds converted legacy events; existing Plan 024 events stay exact.
            assert not expected - actual, table
        else:
            assert actual == expected, table


@pytest.mark.parametrize("tag", TAGS)
def test_released_database_upgrade_preserves_every_entity(tag: str, tmp_path: Path) -> None:
    manifest = json.loads((FIXTURES / f"{tag}.json").read_text())
    source = FIXTURES / f"{tag}.sqlite3"
    with closing(sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True)) as conn, conn:
        original = _contents(conn)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == manifest["schema_version"]
        assert {table: len(rows) for table, (_, rows) in original.items()} == manifest["counts"]
        # These guard against trivial/empty fixtures passing preservation checks.
        for table in (
            "gpo",
            "setting",
            "delegation",
            "som",
            "som_link",
            "gpo_link",
            "ou_tree",
            "coverage_gap",
            "events",
        ):
            assert manifest["counts"][table] > 0, table
        assert manifest["counts"]["snapshot"] == 2
        estates = {sid: asdict(load_estate(conn, sid)) for sid, _, _ in list_snapshots(conn)}
        event_columns, event_rows = original["events"]
        events = [dict(zip(event_columns, row, strict=True)) for row in event_rows]
        for event in events:
            event["payload"] = json.loads(event["payload"])
    db = tmp_path / "restored.sqlite3"
    shutil.copyfile(source, db)
    audit_path = None
    if manifest["audit_file"]:
        audit_path = tmp_path / "audit.log"
        shutil.copyfile(FIXTURES / manifest["audit_file"], audit_path)
        audit_bytes = audit_path.read_bytes()
        audit_entries = [json.loads(line) for line in audit_bytes.splitlines()]
        assert audit_entries
        assert any(entry["action"] == "ingest" for entry in audit_entries)
    first_open = None
    for _ in range(2):
        with closing(sqlite3.connect(db)) as conn, conn:
            init_db(conn)
            assert CURRENT_SCHEMA_VERSION == 10
            assert "detector_version" in {
                row[1] for row in conn.execute("PRAGMA table_info(finding_observation)")
            }
            assert conn.execute(
                "SELECT count(*) FROM finding_observation WHERE detector_version IS NOT NULL"
            ).fetchone() == (0,)
            assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION
            assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
            _preserved(conn, original)
            assert {
                sid: asdict(load_estate(conn, sid)) for sid, _, _ in list_snapshots(conn)
            } == estates
            # v0.5.0's DB-resident audit.ingest is preserved; later releases
            # log web audit separately. Unhashed old events gain only a NULL hash.
            actual_events = query_events(conn)
            assert [{k: e[k] for k in events[0]} for e in actual_events] == events
            assert verify_event_chain(conn) == (True, [])
            pk = [row[1] for row in conn.execute("PRAGMA table_info(coverage_gap)") if row[5]]
            assert pk == ["snapshot_id", "gpo_id", "kind"]
            if "finding" in original:
                assert manifest["counts"]["finding"] >= 3
                assert manifest["counts"]["finding_observation"] > 0
                columns, findings = original["finding"]
                for row in findings:
                    history = finding_history(conn, row[columns.index("id")])
                    assert history.occurrence.id == row[columns.index("id")]
                    assert conn.execute(
                        "SELECT subject_stable FROM finding WHERE id = ?", (history.occurrence.id,)
                    ).fetchone() == (1,)
                statuses = load_triage_status_map(conn)
                assert {s.status for s in statuses.values()} == {"acknowledged", "accepted_risk"}
                risks = accepted_risk_register(conn)
                assert len(risks) == 2
                assert {risk.actor for risk in risks} == {"lab-owner", "lab-reviewer"}
                assert {risk.rationale for risk in risks} == {
                    "Lab exception approved",
                    "Lab compensating control",
                }
                # Both deployed legacy events are copied even when a caller
                # already used the public Plan 024 append_triage_event API.
                assert conn.execute("SELECT count(*) FROM finding_triage_event").fetchone()[0] == 3
            current = _contents(conn)
            if first_open is None:
                first_open = current
            else:
                assert current == first_open
        if audit_path:
            assert audit_path.read_bytes() == audit_bytes


@pytest.mark.parametrize("tag", TAGS)
def test_iis_online_backup_restores_released_database(tag: str, tmp_path: Path) -> None:
    """Exercise README's sqlite3.Connection.backup recipe with live WAL data."""
    manifest = json.loads((FIXTURES / f"{tag}.json").read_text())
    live = tmp_path / "live"
    live.mkdir()
    db = live / "gpo-lens.sqlite3"
    shutil.copyfile(FIXTURES / f"{tag}.sqlite3", db)
    restored = tmp_path / "restore"
    restored.mkdir()
    if manifest["audit_file"]:
        shutil.copyfile(FIXTURES / manifest["audit_file"], live / "audit.log")
    app = sqlite3.connect(db)
    try:
        init_db(app)
        app.execute("PRAGMA journal_mode=WAL")
        app.execute("PRAGMA wal_autocheckpoint=0")
        estate = load_estate(app)
        sid = save_estate(app, estate)
        assert sid == 3
        assert Path(f"{db}-wal").stat().st_size > 0
        before = _contents(app)
        # A distinct backup connection, while the app connection remains open.
        with (
            closing(sqlite3.connect(db)) as src,
            src,
            closing(sqlite3.connect(restored / db.name)) as dst,
            dst,
        ):
            src.backup(dst)
        if manifest["audit_file"]:
            shutil.copyfile(live / "audit.log", restored / "audit.log")
        with closing(sqlite3.connect(restored / db.name)) as conn, conn:
            init_db(conn)
            assert _contents(conn) == before
            assert asdict(load_estate(conn, sid)) == asdict(estate)
            assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        if manifest["audit_file"]:
            assert (restored / "audit.log").read_bytes() == (live / "audit.log").read_bytes()
    finally:
        app.close()
