from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from contextlib import closing

import pytest

from gpo_lens import model, store
from gpo_lens.events import (
    append_event,
    append_events,
    init_events_table,
    query_events,
    verify_event_chain,
)

GPO_LENS = [sys.executable, "-m", "gpo_lens.cli"]


@pytest.fixture
def conn(tmp_path):
    db = tmp_path / "test.db"
    with closing(sqlite3.connect(str(db))) as c:
        store.init_db(c)
        yield c


class TestEventsTable:
    def test_init_events_table_creates_table(self, conn):
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
        ).fetchall()
        assert len(rows) == 1

    def test_init_events_table_idempotent(self, conn):
        init_events_table(conn)
        init_events_table(conn)
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
        ).fetchall()
        assert len(rows) == 1


class TestAppendEvent:
    def test_append_event_round_trip(self, conn):
        eid = append_event(conn, "gpo.created", {"gpo_id": "abc", "gpo_name": "Test"})
        assert isinstance(eid, int)
        rows = conn.execute("SELECT id, event_type, payload FROM events").fetchall()
        assert len(rows) == 1
        assert rows[0][0] == eid
        assert rows[0][1] == "gpo.created"
        import json

        payload = json.loads(rows[0][2])
        assert payload["gpo_id"] == "abc"

    def test_append_events_batch(self, conn):
        events = [
            ("gpo.created", {"gpo_id": "aaa", "gpo_name": "GPO A"}),
            ("gpo.created", {"gpo_id": "bbb", "gpo_name": "GPO B"}),
            ("ingest.summary", {"snapshot_id": 1, "gpo_count": 2}),
        ]
        ids = append_events(conn, events)
        assert len(ids) == 3
        rows = conn.execute("SELECT COUNT(*) FROM events").fetchone()
        assert rows[0] == 3

    def test_append_event_auto_timestamp(self, conn):
        append_event(conn, "test", {})
        row = conn.execute("SELECT timestamp FROM events").fetchone()
        assert row[0] is not None
        assert "T" in row[0]


class TestQueryEvents:
    def test_query_all(self, conn):
        append_events(
            conn,
            [
                ("gpo.created", {"gpo_id": "a"}),
                ("gpo.modified", {"gpo_id": "b"}),
            ],
        )
        results = query_events(conn)
        assert len(results) == 2
        assert results[0]["event_type"] == "gpo.created"
        assert results[1]["event_type"] == "gpo.modified"

    def test_query_since_filter(self, conn):
        append_events(
            conn,
            [
                ("gpo.created", {"gpo_id": "a"}),
            ],
        )
        conn.execute(
            "INSERT INTO events (timestamp, event_type, schema_version, payload) "
            "VALUES ('2020-01-01T00:00:00+00:00', 'old.event', 1, '{}')"
        )
        conn.commit()
        results = query_events(conn, since="2025-01-01")
        assert len(results) == 1
        assert results[0]["event_type"] == "gpo.created"

    def test_query_event_type_filter(self, conn):
        append_events(
            conn,
            [
                ("gpo.created", {"gpo_id": "a"}),
                ("gpo.modified", {"gpo_id": "b"}),
                ("gpo.deleted", {"gpo_id": "c"}),
            ],
        )
        results = query_events(conn, event_type="modified")
        assert len(results) == 1
        assert results[0]["event_type"] == "gpo.modified"

    def test_query_event_type_substring(self, conn):
        append_events(
            conn,
            [
                ("gpo.created", {"gpo_id": "a"}),
                ("ingest.summary", {"snapshot_id": 1}),
            ],
        )
        results = query_events(conn, event_type="gpo")
        assert len(results) == 1
        assert results[0]["event_type"] == "gpo.created"

    def test_query_limit(self, conn):
        batch = [("gpo.created", {"gpo_id": str(i)}) for i in range(10)]
        append_events(conn, batch)
        results = query_events(conn, limit=3)
        assert len(results) == 3


class TestDoubleIngestEvents:
    def test_first_ingest_produces_created_events(self, conn):
        empty_estate = model.Estate(domain="test.local", gpos=[])
        prev_sid = store.save_estate(conn, empty_estate)

        estate = model.Estate(
            domain="test.local",
            gpos=[
                model.Gpo(
                    id="gpo-1",
                    name="GPO One",
                    domain="test.local",
                    created=None,
                    modified=None,
                    read=None,
                    computer_enabled=True,
                    user_enabled=True,
                    computer_ver_ds=1,
                    computer_ver_sysvol=1,
                    user_ver_ds=0,
                    user_ver_sysvol=0,
                    sddl=None,
                    owner=None,
                    filter_data_available=False,
                    wmi_filter=None,
                    sysvol_path=None,
                    settings=[
                        model.Setting(
                            gpo_id="gpo-1",
                            side="Computer",
                            cse="Security",
                            identity="Key1",
                            display_name="Key1",
                            display_value="5",
                            raw={},
                            from_disabled_side=False,
                        ),
                    ],
                ),
            ],
        )
        sid1 = store.save_estate(conn, estate)
        from gpo_lens.cli._estate import _emit_ingest_events

        _emit_ingest_events(conn, prev_sid, sid1, 1)
        events = query_events(conn)
        types = [e["event_type"] for e in events]
        assert "gpo.created" in types
        assert "ingest.summary" in types

    def test_second_ingest_produces_modified_events(self, conn):

        estate_v1 = model.Estate(
            domain="test.local",
            gpos=[
                model.Gpo(
                    id="gpo-1",
                    name="GPO One",
                    domain="test.local",
                    created=None,
                    modified=None,
                    read=None,
                    computer_enabled=True,
                    user_enabled=True,
                    computer_ver_ds=1,
                    computer_ver_sysvol=1,
                    user_ver_ds=0,
                    user_ver_sysvol=0,
                    sddl=None,
                    owner=None,
                    filter_data_available=False,
                    wmi_filter=None,
                    sysvol_path=None,
                    settings=[
                        model.Setting(
                            gpo_id="gpo-1",
                            side="Computer",
                            cse="Security",
                            identity="Key1",
                            display_name="Key1",
                            display_value="5",
                            raw={},
                            from_disabled_side=False,
                        ),
                    ],
                ),
            ],
        )
        sid1 = store.save_estate(conn, estate_v1)

        estate_v2 = model.Estate(
            domain="test.local",
            gpos=[
                model.Gpo(
                    id="gpo-1",
                    name="GPO One",
                    domain="test.local",
                    created=None,
                    modified=None,
                    read=None,
                    computer_enabled=True,
                    user_enabled=True,
                    computer_ver_ds=2,
                    computer_ver_sysvol=2,
                    user_ver_ds=0,
                    user_ver_sysvol=0,
                    sddl=None,
                    owner=None,
                    filter_data_available=False,
                    wmi_filter=None,
                    sysvol_path=None,
                    settings=[
                        model.Setting(
                            gpo_id="gpo-1",
                            side="Computer",
                            cse="Security",
                            identity="Key1",
                            display_name="Key1",
                            display_value="10",
                            raw={},
                            from_disabled_side=False,
                        ),
                    ],
                ),
            ],
        )
        sid2 = store.save_estate(conn, estate_v2)
        from gpo_lens.cli._estate import _emit_ingest_events

        _emit_ingest_events(conn, sid1, sid2, 1)

        events = query_events(conn)
        modified = [e for e in events if e["event_type"] == "gpo.modified"]
        assert len(modified) >= 1
        delta = modified[0]["payload"]["deltas"][0]
        assert delta["identity"] == "Key1"
        assert delta["old"] == "5"
        assert delta["new"] == "10"

    def test_deleted_gpo_event(self, conn):

        estate_v1 = model.Estate(
            domain="test.local",
            gpos=[
                model.Gpo(
                    id="gpo-1",
                    name="GPO One",
                    domain="test.local",
                    created=None,
                    modified=None,
                    read=None,
                    computer_enabled=True,
                    user_enabled=True,
                    computer_ver_ds=1,
                    computer_ver_sysvol=1,
                    user_ver_ds=0,
                    user_ver_sysvol=0,
                    sddl=None,
                    owner=None,
                    filter_data_available=False,
                    wmi_filter=None,
                    sysvol_path=None,
                ),
                model.Gpo(
                    id="gpo-2",
                    name="GPO Two",
                    domain="test.local",
                    created=None,
                    modified=None,
                    read=None,
                    computer_enabled=True,
                    user_enabled=True,
                    computer_ver_ds=1,
                    computer_ver_sysvol=1,
                    user_ver_ds=0,
                    user_ver_sysvol=0,
                    sddl=None,
                    owner=None,
                    filter_data_available=False,
                    wmi_filter=None,
                    sysvol_path=None,
                ),
            ],
        )
        sid1 = store.save_estate(conn, estate_v1)

        estate_v2 = model.Estate(
            domain="test.local",
            gpos=[
                model.Gpo(
                    id="gpo-1",
                    name="GPO One",
                    domain="test.local",
                    created=None,
                    modified=None,
                    read=None,
                    computer_enabled=True,
                    user_enabled=True,
                    computer_ver_ds=1,
                    computer_ver_sysvol=1,
                    user_ver_ds=0,
                    user_ver_sysvol=0,
                    sddl=None,
                    owner=None,
                    filter_data_available=False,
                    wmi_filter=None,
                    sysvol_path=None,
                ),
            ],
        )
        sid2 = store.save_estate(conn, estate_v2)
        from gpo_lens.cli._estate import _emit_ingest_events

        _emit_ingest_events(conn, sid1, sid2, 1)

        events = query_events(conn)
        deleted = [e for e in events if e["event_type"] == "gpo.deleted"]
        assert len(deleted) == 1
        assert deleted[0]["payload"]["gpo_id"] == "gpo-2"

    def test_delta_capping_over_100_changes(self, conn):
        """When a GPO has >100 setting changes, deltas should be truncated."""

        # v1: GPO with 150 settings
        settings_v1 = [
            model.Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity=f"Key{i}",
                display_name=f"Key{i}",
                display_value=str(i),
                raw={},
                from_disabled_side=False,
            )
            for i in range(150)
        ]
        estate_v1 = model.Estate(
            domain="test.local",
            gpos=[
                model.Gpo(
                    id="gpo-1",
                    name="GPO Many",
                    domain="test.local",
                    created=None,
                    modified=None,
                    read=None,
                    computer_enabled=True,
                    user_enabled=True,
                    computer_ver_ds=1,
                    computer_ver_sysvol=1,
                    user_ver_ds=0,
                    user_ver_sysvol=0,
                    sddl=None,
                    owner=None,
                    filter_data_available=False,
                    wmi_filter=None,
                    sysvol_path=None,
                    settings=settings_v1,
                ),
            ],
        )
        sid1 = store.save_estate(conn, estate_v1)

        # v2: change all 150 setting values
        settings_v2 = [
            model.Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity=f"Key{i}",
                display_name=f"Key{i}",
                display_value=str(i + 1000),
                raw={},
                from_disabled_side=False,
            )
            for i in range(150)
        ]
        estate_v2 = model.Estate(
            domain="test.local",
            gpos=[
                model.Gpo(
                    id="gpo-1",
                    name="GPO Many",
                    domain="test.local",
                    created=None,
                    modified=None,
                    read=None,
                    computer_enabled=True,
                    user_enabled=True,
                    computer_ver_ds=2,
                    computer_ver_sysvol=2,
                    user_ver_ds=0,
                    user_ver_sysvol=0,
                    sddl=None,
                    owner=None,
                    filter_data_available=False,
                    wmi_filter=None,
                    sysvol_path=None,
                    settings=settings_v2,
                ),
            ],
        )
        sid2 = store.save_estate(conn, estate_v2)

        from gpo_lens.cli._estate import _emit_ingest_events

        _emit_ingest_events(conn, sid1, sid2, 1)

        events = query_events(conn)
        modified = [e for e in events if e["event_type"] == "gpo.modified"]
        assert len(modified) == 1
        payload = modified[0]["payload"]
        assert payload["truncated"] is True
        assert payload["total_count"] == 150
        assert len(payload["deltas"]) == 100


class TestAppendOnly:
    def test_no_update_or_delete_sql_against_events(self):
        import pathlib

        src_dir = pathlib.Path(__file__).resolve().parent.parent / "src" / "gpo_lens"
        for py_file in src_dir.rglob("*.py"):
            text = py_file.read_text()
            for line_no, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                stripped_upper = stripped.upper()
                is_dml = (
                    stripped_upper.startswith("SELECT")
                    or stripped_upper.startswith("INSERT")
                    or stripped_upper.startswith("UPDATE")
                    or stripped_upper.startswith("DELETE")
                )
                if not is_dml:
                    continue
                if "EVENTS" not in stripped_upper:
                    continue
                if "ON DELETE" in stripped_upper:
                    continue
                if "IF NOT EXISTS" in stripped_upper:
                    continue
                if stripped_upper.startswith("INSERT"):
                    continue
                if stripped_upper.startswith("SELECT"):
                    continue
                raise AssertionError(
                    f"Possible UPDATE/DELETE on events table at {py_file}:{line_no}: {stripped!r}"
                )


class TestEventsCLI:
    def test_events_subcommand(self, tmp_path):
        db = tmp_path / "test.db"
        conn = sqlite3.connect(str(db))
        store.init_db(conn)
        append_events(
            conn,
            [
                ("gpo.created", {"gpo_id": "aaa", "gpo_name": "Test GPO"}),
            ],
        )
        conn.close()

        r = subprocess.run(
            GPO_LENS + ["--db", str(db), "events"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "gpo.created" in r.stdout

    def test_events_json(self, tmp_path):
        db = tmp_path / "test.db"
        conn = sqlite3.connect(str(db))
        store.init_db(conn)
        append_events(
            conn,
            [
                ("gpo.created", {"gpo_id": "aaa", "gpo_name": "Test GPO"}),
            ],
        )
        conn.close()

        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(db), "events"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        import json

        data = json.loads(r.stdout)["data"]
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["event_type"] == "gpo.created"

    def test_events_type_filter(self, tmp_path):
        db = tmp_path / "test.db"
        conn = sqlite3.connect(str(db))
        store.init_db(conn)
        append_events(
            conn,
            [
                ("gpo.created", {"gpo_id": "aaa"}),
                ("ingest.summary", {"snapshot_id": 1}),
            ],
        )
        conn.close()

        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(db), "events", "--type", "ingest"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        import json

        data = json.loads(r.stdout)["data"]
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["event_type"] == "ingest.summary"

    def test_events_since_filter(self, tmp_path):
        db = tmp_path / "test.db"
        conn = sqlite3.connect(str(db))
        store.init_db(conn)
        conn.execute(
            "INSERT INTO events (timestamp, event_type, schema_version, payload) "
            "VALUES ('2020-01-01T00:00:00+00:00', 'old.event', 1, '{}')"
        )
        append_events(
            conn,
            [
                ("gpo.created", {"gpo_id": "aaa"}),
            ],
        )
        conn.close()

        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(db), "events", "--since", "2025-01-01"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        import json

        data = json.loads(r.stdout)["data"]
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["event_type"] == "gpo.created"

    def test_events_empty(self, tmp_path):
        db = tmp_path / "test.db"
        conn = sqlite3.connect(str(db))
        store.init_db(conn)
        conn.close()

        r = subprocess.run(
            GPO_LENS + ["--db", str(db), "events"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "No events found" in r.stdout


class TestHashChain:
    def test_single_event_prev_hash(self, conn):
        eid = append_event(conn, "gpo.created", {"gpo_id": "abc"})
        row = conn.execute(
            "SELECT timestamp, event_type, payload, prev_hash FROM events WHERE id = ?",
            (eid,),
        ).fetchone()
        ts, event_type, payload_str, prev_hash = row
        expected = hashlib.sha256(f"|{ts}|{event_type}|{payload_str}".encode()).hexdigest()
        assert prev_hash == expected

    def test_chain_of_three_events(self, conn):
        prev_hash = None
        for i in range(3):
            eid = append_event(conn, "test.event", {"index": i})
            row = conn.execute(
                "SELECT timestamp, event_type, payload, prev_hash FROM events WHERE id = ?",
                (eid,),
            ).fetchone()
            ts, event_type, payload_str, stored_hash = row
            expected = hashlib.sha256(
                f"{prev_hash or ''}|{ts}|{event_type}|{payload_str}".encode()
            ).hexdigest()
            assert stored_hash == expected
            prev_hash = stored_hash

    def test_verify_clean_chain(self, conn):
        append_events(
            conn,
            [
                ("gpo.created", {"gpo_id": "a"}),
                ("gpo.modified", {"gpo_id": "b"}),
                ("gpo.deleted", {"gpo_id": "c"}),
            ],
        )
        ok, broken = verify_event_chain(conn)
        assert ok is True
        assert broken == []

    def test_verify_tampered_chain(self, conn):
        eid = append_event(conn, "gpo.created", {"gpo_id": "abc"})
        append_event(conn, "gpo.modified", {"gpo_id": "abc", "name": "new"})
        conn.execute(
            "UPDATE events SET payload = ? WHERE id = ?",
            (json.dumps({"gpo_id": "abc", "name": "TAMPERED"}, sort_keys=True), eid),
        )
        conn.commit()
        ok, broken = verify_event_chain(conn)
        assert ok is False
        assert eid in broken

    def test_append_events_batch_chain(self, conn):
        events = [
            ("gpo.created", {"gpo_id": "a"}),
            ("gpo.modified", {"gpo_id": "b"}),
            ("ingest.summary", {"count": 2}),
        ]
        append_events(conn, events)
        ok, broken = verify_event_chain(conn)
        assert ok is True
        assert broken == []

    def test_init_events_table_adds_prev_hash_column(self, tmp_path):
        db = tmp_path / "migrate.db"
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE events ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, "
            "event_type TEXT NOT NULL, "
            "schema_version INTEGER NOT NULL DEFAULT 1, "
            "payload TEXT NOT NULL)"
        )
        conn.commit()
        cols_before = {r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()}
        assert "prev_hash" not in cols_before
        init_events_table(conn)
        cols_after = {r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()}
        assert "prev_hash" in cols_after
        conn.close()
