"""Reject excessive archive metadata before opening any member."""

import shutil
import sqlite3
import zipfile
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gpo_lens import collection_zip
from gpo_lens.cli import main
from gpo_lens.web.app import create_app


@pytest.mark.parametrize(
    "limit,members",
    [
        ("MAX_MEMBERS", ["AllGPOs.xml", "one", "two"]),
        ("MAX_DIRECTORIES", ["AllGPOs.xml", "a/b/c/file"]),
        ("MAX_FILENAME_BYTES", ["AllGPOs.xml", "long-filename"]),
        ("MAX_PATH_DEPTH", ["AllGPOs.xml", "a/b/c/file"]),
    ],
)
@pytest.mark.parametrize("surface", ["extract", "cli", "web"])
def test_zip_metadata_preflight(tmp_path, monkeypatch, capsys, limit, members, surface):
    monkeypatch.setattr(collection_zip, limit, 2, raising=False)
    archive = tmp_path / "collector.zip"
    with zipfile.ZipFile(archive, "w") as output:
        for name in members:
            output.writestr(name, "<GPOs/>")
    opened = []
    original = zipfile.ZipFile.open

    def recording_open(self, *args, **kwargs):
        opened.append(args[0])
        return original(self, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", recording_open)
    if surface == "extract":
        dest = tmp_path / "extract"
        dest.mkdir()
        with pytest.raises(ValueError, match="zip .* limit"):
            collection_zip.safe_extract(archive, dest)
        assert not list(dest.iterdir())
    elif surface == "cli":
        db = tmp_path / "estate.db"
        assert main(["--db", str(db), "ingest", str(archive)]) != 0
        assert "limit" in capsys.readouterr().err
        assert not db.exists()
    else:
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "lab-test-token")
        db = tmp_path / "estate.db"
        with TestClient(
            create_app(str(db)),
            base_url="http://localhost",
            headers={"Authorization": "Bearer lab-test-token", "Origin": "http://localhost"},
        ) as client:
            response = client.post(
                "/ingest", files={"file": ("collector.zip", archive.read_bytes())}
            )
        assert response.status_code == 400
        assert "limit" in response.text
        with closing(sqlite3.connect(db)) as conn:
            assert conn.execute("SELECT count(*) FROM snapshot").fetchone() == (0,)
    assert opened == []


def test_rejected_cli_upload_does_not_migrate_a_released_database(tmp_path, monkeypatch):
    db = tmp_path / "released.db"
    shutil.copyfile(Path(__file__).parent / "fixtures/released_databases/v1.3.1.sqlite3", db)
    with closing(sqlite3.connect(db)) as conn:
        before = list(conn.iterdump())
        version = conn.execute("PRAGMA user_version").fetchone()
    monkeypatch.setattr(collection_zip, "MAX_MEMBERS", 1)
    archive = tmp_path / "rejected.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("AllGPOs.xml", "<GPOs/>")
        output.writestr("extra", "")
    assert main(["--db", str(db), "ingest", str(archive)]) == 1
    with closing(sqlite3.connect(db)) as conn:
        assert conn.execute("PRAGMA user_version").fetchone() == version
        assert list(conn.iterdump()) == before
