"""Tests for CLI events and events-export commands."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import unittest.mock

import pytest

GPO_LENS = [sys.executable, "-m", "gpo_lens.cli"]


@pytest.fixture
def events_db(tmp_path):
    from gpo_lens import store
    from gpo_lens.events import append_events

    db = tmp_path / "events.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    append_events(
        conn,
        [
            ("gpo.created", {"gpo_id": "aaa", "gpo_name": "GPO Alpha"}),
            ("gpo.modified", {"gpo_id": "bbb", "gpo_name": "GPO Beta"}),
            ("ingest.summary", {"old_snapshot_id": 1, "new_snapshot_id": 2}),
        ],
    )
    conn.close()
    return db


@pytest.fixture
def empty_events_db(tmp_path):
    from gpo_lens import store

    db = tmp_path / "empty_events.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    conn.close()
    return db


class TestEventsCommand:
    def test_events_no_events(self, empty_events_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(empty_events_db), "events"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "No events found" in r.stdout

    def test_events_with_events(self, events_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(events_db), "events"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "gpo.created" in r.stdout
        assert "gpo.modified" in r.stdout
        assert "ingest.summary" in r.stdout

    def test_events_since_filter_excludes_all(self, events_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(events_db), "events", "--since", "2099-01-01"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "No events found" in r.stdout

    def test_events_since_filter_includes_all(self, events_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(events_db), "events", "--since", "2000-01-01"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "gpo.created" in r.stdout

    def test_events_type_filter(self, events_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(events_db), "events", "--type", "gpo.created"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "gpo.created" in r.stdout
        assert "gpo.modified" not in r.stdout
        assert "ingest.summary" not in r.stdout

    def test_events_type_filter_substring(self, events_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(events_db), "events", "--type", "gpo"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "gpo.created" in r.stdout
        assert "gpo.modified" in r.stdout
        assert "ingest.summary" not in r.stdout

    def test_events_json_envelope(self, events_db):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(events_db), "events"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        env = json.loads(r.stdout)
        assert env["schema_version"] == 2
        assert env["kind"] == "events"
        assert isinstance(env["data"], list)
        assert len(env["data"]) == 3
        assert env["data"][0]["event_type"] == "gpo.created"
        assert "payload" in env["data"][0]

    def test_events_limit(self, events_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(events_db), "events", "--limit", "1"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "gpo.created" in r.stdout
        assert "ingest.summary" not in r.stdout


class TestEventsExportCommand:
    def test_events_export_ndjson_to_file(self, events_db, tmp_path):
        ndjson_path = tmp_path / "events.ndjson"
        r = subprocess.run(
            GPO_LENS
            + [
                "--db",
                str(events_db),
                "events-export",
                "--ndjson",
                str(ndjson_path),
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert ndjson_path.exists()
        lines = ndjson_path.read_text().strip().split("\n")
        assert len(lines) == 3
        for line in lines:
            entry = json.loads(line)
            assert "event_type" in entry
            assert "payload" in entry
            assert "timestamp" in entry

    def test_events_export_splunk_hec_not_configured(self, events_db):
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("GPO_LENS_HEC_URL", "GPO_LENS_HEC_TOKEN")
        }
        r = subprocess.run(
            GPO_LENS
            + [
                "--db",
                str(events_db),
                "events-export",
                "--sink",
                "hec",
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        assert r.returncode == 0
        assert "HEC not configured" in r.stderr

    def test_events_export_no_events(self, empty_events_db, tmp_path):
        ndjson_path = tmp_path / "empty.ndjson"
        r = subprocess.run(
            GPO_LENS
            + [
                "--db",
                str(empty_events_db),
                "events-export",
                "--ndjson",
                str(ndjson_path),
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert ndjson_path.exists()
        content = ndjson_path.read_text().strip()
        assert content == ""

    def test_events_export_no_events_no_ndjson(self, empty_events_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(empty_events_db), "events-export"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert r.stdout == ""

    def test_events_export_json_flag_accepted(self, events_db):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(events_db), "events-export"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0

    def test_events_export_ndjson_failure(self, events_db, tmp_path):
        bad_path = str(tmp_path / "nonexistent_dir" / "events.ndjson")
        r = subprocess.run(
            GPO_LENS
            + [
                "--db",
                str(events_db),
                "events-export",
                "--ndjson",
                bad_path,
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1
        assert "NDJSON export failed" in r.stderr

    def test_events_export_hec_format_via_mock(self, events_db):
        with unittest.mock.patch.dict(
            os.environ,
            {
                "GPO_LENS_HEC_URL": "https://fake-splunk.local:8088",
                "GPO_LENS_HEC_TOKEN": "fake-token",
            },
        ):
            with unittest.mock.patch(
                "gpo_lens.sinks.HecSink._post",
                return_value=True,
            ) as mock_post:
                from gpo_lens.cli import main

                ret = main(
                    [
                        "--db",
                        str(events_db),
                        "events-export",
                        "--sink",
                        "hec",
                    ]
                )
        assert ret == 0
        mock_post.assert_called_once()
        payload = mock_post.call_args[0][0]
        lines = payload.strip().split("\n")
        assert len(lines) == 3
        for line in lines:
            obj = json.loads(line)
            assert "event" in obj
            assert obj["sourcetype"] == "gpo_lens:change"

    def test_events_export_since_filter(self, events_db, tmp_path):
        ndjson_path = tmp_path / "filtered.ndjson"
        r = subprocess.run(
            GPO_LENS
            + [
                "--db",
                str(events_db),
                "events-export",
                "--ndjson",
                str(ndjson_path),
                "--since",
                "2099-01-01",
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert ndjson_path.exists()
        content = ndjson_path.read_text().strip()
        assert content == ""
