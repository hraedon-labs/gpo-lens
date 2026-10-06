"""A failed required evaluation leaves the database exactly as it was."""

import sqlite3
import zipfile
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gpo_lens import __version__, findings, store
from gpo_lens.cli import main
from gpo_lens.ingest import load_estate
from gpo_lens.web.app import create_app

FIXTURE = Path(__file__).parent / "fixtures/cse_audit_pki/report.xml"


@pytest.mark.parametrize("surface", ["cli", "web"])
@pytest.mark.parametrize(
    "stage",
    [
        "save_estate",
        "candidates_from_estate",
        "create_evaluation_run",
        "run_evaluation",
        "complete_evaluation_run",
    ],
)
def test_failed_ingest_is_atomic(tmp_path, monkeypatch, capsys, surface, stage):
    source = tmp_path / "source"
    source.mkdir()
    (source / "AllGPOs.xml").write_bytes(FIXTURE.read_bytes())
    db = tmp_path / "estate.db"
    with closing(sqlite3.connect(db)) as conn:
        store.init_db(conn)
        estate = load_estate(source)
        sid = store.save_estate(conn, estate)
        findings.evaluate_finding_lifecycle_v2(conn, sid, estate)
        finding_id = conn.execute("SELECT id FROM finding LIMIT 1").fetchone()[0]
        findings.triage_finding(conn, finding_id, "acknowledged", "lab-reviewer", "Lab decision")
        before = list(conn.iterdump())

    module = store if stage == "save_estate" else findings
    original = getattr(module, stage)

    def fail_after(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("synthetic lifecycle failure")

    monkeypatch.setattr(module, stage, fail_after)
    if surface == "cli":
        assert main(["--db", str(db), "ingest", str(source)]) != 0
        captured = capsys.readouterr()
        assert "nothing was imported" in captured.err.lower()
        assert "snapshot=" not in captured.out
    else:
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "lab-test-token")
        archive = tmp_path / "collector.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("AllGPOs.xml", FIXTURE.read_bytes())
        audits = []
        import gpo_lens.web.routes.ingest as route

        monkeypatch.setattr(route, "_audit", lambda *args: audits.append(args))
        with TestClient(
            create_app(str(db)),
            base_url="http://localhost",
            headers={"Authorization": "Bearer lab-test-token", "Origin": "http://localhost"},
        ) as client:
            response = client.post(
                "/ingest",
                files={"file": ("collector.zip", archive.read_bytes())},
                follow_redirects=False,
            )
        assert response.status_code == 500
        assert "nothing was imported" in response.text.lower()
        assert "location" not in response.headers
        assert not any(a[2] == "success" for a in audits)
    with closing(sqlite3.connect(db)) as conn:
        assert list(conn.iterdump()) == before
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)


@pytest.mark.parametrize("surface", ["web", "cli"])
def test_ingest_event_failure_rolls_back_even_after_event_insert(
    tmp_path, monkeypatch, capsys, surface
):
    from gpo_lens import events

    source = tmp_path / "source"
    source.mkdir()
    (source / "AllGPOs.xml").write_bytes(FIXTURE.read_bytes())
    db = tmp_path / "estate.db"
    with closing(sqlite3.connect(db)) as conn:
        store.init_db(conn)
        store.save_evaluated_estate(conn, load_estate(source))
        before = list(conn.iterdump())
    name = "append_event" if surface == "web" else "append_events"
    original = getattr(events, name)

    def fail_after(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("synthetic database audit failure")

    monkeypatch.setattr(events, name, fail_after)
    if surface == "cli":
        assert main(["--db", str(db), "ingest", str(source), "--diff-latest"]) == 1
        output = capsys.readouterr()
        assert "snapshot=" not in output.out
        assert "nothing was imported" in output.err.lower()
    else:
        response = _web_ingest(db, monkeypatch)
        assert response.status_code == 500
        assert "nothing was imported" in response.text.lower()
    with closing(sqlite3.connect(db)) as conn:
        assert list(conn.iterdump()) == before
        assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def _web_ingest(db, monkeypatch):
    import io

    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "lab-test-token")
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("AllGPOs.xml", FIXTURE.read_bytes())
    with TestClient(
        create_app(str(db)),
        base_url="http://localhost",
        headers={"Authorization": "Bearer lab-test-token", "Origin": "http://localhost"},
    ) as client:
        return client.post(
            "/ingest",
            files={"file": ("collector.zip", archive.getvalue())},
            follow_redirects=False,
        )


@pytest.mark.parametrize("surface", ["web", "cli"])
def test_normal_ingest_records_application_version(tmp_path, monkeypatch, surface):
    db = tmp_path / "estate.db"
    if surface == "web":
        assert _web_ingest(db, monkeypatch).status_code == 303
    else:
        source = tmp_path / "source"
        source.mkdir()
        (source / "AllGPOs.xml").write_bytes(FIXTURE.read_bytes())
        assert main(["--db", str(db), "ingest", str(source)]) == 0
    with closing(sqlite3.connect(db)) as conn:
        assert conn.execute("SELECT application_version FROM evaluation_run").fetchall() == [
            (__version__,)
        ]


def test_snapshot_delete_audit_failure_rolls_back(tmp_path, monkeypatch):
    from gpo_lens import events

    db = tmp_path / "estate.db"
    assert _web_ingest(db, monkeypatch).status_code == 303
    with closing(sqlite3.connect(db)) as conn:
        before = list(conn.iterdump())
    original = events.append_event

    def fail_after(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("synthetic delete audit failure")

    monkeypatch.setattr(events, "append_event", fail_after)
    with TestClient(
        create_app(str(db)),
        base_url="http://localhost",
        headers={"Authorization": "Bearer lab-test-token", "Origin": "http://localhost"},
        raise_server_exceptions=False,
    ) as client:
        response = client.post("/ingest/delete", data={"snapshot_id": 1}, follow_redirects=False)
    assert response.status_code == 500
    with closing(sqlite3.connect(db)) as conn:
        assert list(conn.iterdump()) == before


def test_postcommit_file_audit_setup_failure_keeps_success(tmp_path, monkeypatch, caplog):
    import gpo_lens.web.app as web

    def fail(*args):
        raise RuntimeError("synthetic file audit setup failure")

    monkeypatch.setattr(web, "_ensure_audit_logger", fail)
    db = tmp_path / "estate.db"
    assert _web_ingest(db, monkeypatch).status_code == 303
    assert "Audit log write failed" in caplog.text
    with closing(sqlite3.connect(db)) as conn:
        assert conn.execute("SELECT count(*) FROM snapshot").fetchone() == (1,)
        assert conn.execute("SELECT event_type FROM events").fetchall() == [("audit.ingest",)]


@pytest.mark.parametrize("surface", ["cli", "web"])
def test_ingest_temporary_cleanup_failure_rolls_back(tmp_path, monkeypatch, capsys, surface):
    from tempfile import TemporaryDirectory

    db = tmp_path / "estate.db"
    with closing(sqlite3.connect(db)) as conn:
        store.init_db(conn)
        before = list(conn.iterdump())
    original = TemporaryDirectory.__exit__

    def fail_after(self, *args):
        original(self, *args)
        raise OSError("synthetic upload cleanup failure")

    monkeypatch.setattr(TemporaryDirectory, "__exit__", fail_after)
    if surface == "cli":
        archive = tmp_path / "collector.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("AllGPOs.xml", FIXTURE.read_bytes())
        assert main(["--db", str(db), "ingest", str(archive)]) == 1
        output = capsys.readouterr()
        assert "snapshot=" not in output.out
        assert "nothing was imported" in output.err.lower()
    else:
        response = _web_ingest(db, monkeypatch)
        assert response.status_code == 500
        assert "nothing was imported" in response.text.lower()
    with closing(sqlite3.connect(db)) as conn:
        assert list(conn.iterdump()) == before
