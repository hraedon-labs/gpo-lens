"""A failed required evaluation leaves the database exactly as it was."""

import sqlite3
import zipfile
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gpo_lens import findings, store
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
