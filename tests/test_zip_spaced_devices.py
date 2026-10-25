"""Windows device aliases remain reserved with spaces before an extension."""

from __future__ import annotations

import sqlite3
import zipfile
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gpo_lens.cli import main
from gpo_lens.collection_zip import safe_extract
from gpo_lens.web.app import create_app


def write_zip(path: Path, members: list[tuple[str, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in members:
            archive.writestr(name, content)
    return path


@pytest.mark.parametrize(
    "alias", ["CON .txt", "nUl  .json", "Com¹ .xml", "lPt9 .ini", "PRN .txt", "AUX   .tmp"]
)
@pytest.mark.parametrize("pattern", ["{}", "folder/{}", "{}/child.txt", "folder\\{}\\child.txt"])
def test_spaced_device_alias_is_refused_and_partial_files_removed(tmp_path, alias, pattern):
    member = pattern.format(alias)
    archive = write_zip(
        tmp_path / "device.zip", [("first.txt", b"synthetic"), (member, b"synthetic")]
    )
    dest = tmp_path / "extracted"
    dest.mkdir()
    with pytest.raises(ValueError, match=r"^zip-slip blocked \(member 2\)$"):
        safe_extract(archive, dest)
    assert list(dest.iterdir()) == []


@pytest.mark.parametrize(
    "name",
    [
        "normal .txt",
        "CONductor .txt",
        "COM1port .txt",
        "NUL-value .xml",
        "COM10 .txt",
        "my CON .txt",
    ],
)
def test_nondevice_names_keep_spaces_and_exact_content(tmp_path, name):
    archive = write_zip(tmp_path / "ordinary.zip", [("folder/" + name, b"exact synthetic content")])
    dest = tmp_path / "extracted"
    dest.mkdir()
    safe_extract(archive, dest)
    assert (dest / "folder" / name).read_bytes() == b"exact synthetic content"


def collector_members() -> list[tuple[str, bytes]]:
    return [("AllGPOs.xml", (Path(__file__).parent / "fixtures/AllGPOs.xml").read_bytes())]


def test_cli_refuses_spaced_device_before_creating_database(tmp_path, capsys):
    archive = write_zip(
        tmp_path / "collector.zip", collector_members() + [("NUL .txt", b"synthetic")]
    )
    database = tmp_path / "estate.db"
    assert main(["--db", str(database), "ingest", str(archive)]) != 0
    error = capsys.readouterr().err
    assert "zip-slip blocked (member 2)" in error
    assert "NUL .txt" not in error
    assert not database.exists()


def test_web_refuses_spaced_device_without_snapshot_and_accepts_next_upload(tmp_path, monkeypatch):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "synthetic-test-token")
    archive = write_zip(
        tmp_path / "collector.zip", collector_members() + [("CON .txt", b"synthetic")]
    )
    database = tmp_path / "estate.db"
    with TestClient(
        create_app(str(database)),
        base_url="http://localhost",
        headers={"Authorization": "Bearer synthetic-test-token", "Origin": "http://localhost"},
    ) as client:
        response = client.post(
            "/ingest", files={"file": ("collector.zip", archive.read_bytes(), "application/zip")}
        )
        assert response.status_code == 400
        assert "zip-slip blocked (member 2)" in response.text
        assert "CON .txt" not in response.text
        with closing(sqlite3.connect(database)) as conn:
            assert conn.execute("SELECT count(*) FROM snapshot").fetchone() == (0,)
            assert conn.execute("SELECT count(*) FROM evaluation_run").fetchone() == (0,)
        valid = write_zip(tmp_path / "valid.zip", collector_members())
        assert (
            client.post(
                "/ingest",
                files={"file": ("valid.zip", valid.read_bytes(), "application/zip")},
                follow_redirects=False,
            ).status_code
            == 303
        )
    with closing(sqlite3.connect(database)) as conn:
        assert conn.execute("SELECT count(*) FROM snapshot").fetchone() == (1,)
        assert conn.execute("SELECT count(*) FROM evaluation_run").fetchone() == (1,)
