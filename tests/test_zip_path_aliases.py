"""ZIP namespaces must not split Windows-equivalent collector paths on Linux."""

from __future__ import annotations

import json
import sqlite3
import zipfile
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gpo_lens.cli import main
from gpo_lens.collection_zip import collector_root, safe_extract
from gpo_lens.ingest import load_estate
from gpo_lens.web.app import create_app


def write_zip(path: Path, members: list[tuple[str, str | bytes]]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in members:
            archive.writestr(name, content)
    return path


@pytest.mark.parametrize(
    "names",
    [
        ["Export/one", "export/two"],
        ["Export/Layer/one", "Export/layer/two"],
        ["Export/", "export/one"],
        ["Export/one", "export/"],
        ["Export\\one", "export\\two"],
        ["Export/Layer/one", "Export\\layer\\two"],
        ["Entry", "Entry/child"],
        ["Entry/child", "Entry"],
        ["Entry", "entry/child"],
    ],
)
def test_conflicting_component_namespace_is_refused_before_member_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, names: list[str]
) -> None:
    archive = write_zip(tmp_path / "conflicting.zip", [(name, "synthetic") for name in names])
    opened = []
    original = zipfile.ZipFile.open

    def recording_open(self, *args, **kwargs):
        opened.append(args[0])
        return original(self, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", recording_open)
    dest = tmp_path / "extracted"
    dest.mkdir()
    with pytest.raises(ValueError, match="duplicate path.*member 2"):
        safe_extract(archive, dest)
    assert opened == []
    assert list(dest.iterdir()) == []


@pytest.mark.parametrize("explicit_first", [True, False])
@pytest.mark.parametrize("separator", ["/", "\\"])
def test_consistent_explicit_and_implicit_directories_remain_valid(
    tmp_path: Path, explicit_first: bool, separator: str
) -> None:
    directory = ("Export/", "")
    file = ("Export/Layer/value.txt", "exact synthetic value")
    members = [directory, file] if explicit_first else [file, directory]
    archive = write_zip(
        tmp_path / "consistent.zip", [(p.replace("/", separator), v) for p, v in members]
    )
    dest = tmp_path / "extracted"
    dest.mkdir()
    safe_extract(archive, dest)
    assert (dest / "Export/Layer/value.txt").read_text() == "exact synthetic value"


def collector_members(folder: str) -> list[tuple[str, str | bytes]]:
    return [
        ("Export/AllGPOs.xml", (Path(__file__).parent / "fixtures/AllGPOs.xml").read_bytes()),
        (
            folder + "/gpo-inventory.json",
            json.dumps(
                [
                    {
                        "Id": "11111111-2222-4333-8444-555555555555",
                        "DisplayName": "Synthetic missing GPO",
                    }
                ]
            ),
        ),
    ]


def test_consistent_wrapper_keeps_missing_inventory_gpo_visible(tmp_path: Path) -> None:
    archive = write_zip(tmp_path / "collector.zip", collector_members("Export"))
    dest = tmp_path / "extracted"
    dest.mkdir()
    safe_extract(archive, dest)
    estate = load_estate(collector_root(dest))
    inventory_gaps = [gap for gap in estate.coverage_gaps if gap.kind == "inaccessible"]
    assert len(inventory_gaps) == 1
    assert estate.gpos
    assert inventory_gaps[0].gpo_id == "11111111222243338444555555555555"


def test_cli_refuses_split_wrapper_before_creating_database(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = write_zip(tmp_path / "collector.zip", collector_members("export"))
    database = tmp_path / "estate.db"
    assert main(["--db", str(database), "ingest", str(archive)]) != 0
    err = capsys.readouterr().err
    assert "duplicate path" in err
    assert "member 2" in err
    assert "Export/" not in err and "export/" not in err
    assert not database.exists()


def test_web_refuses_split_wrapper_without_persisting_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "synthetic-test-token")
    archive = write_zip(tmp_path / "collector.zip", collector_members("export"))
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
        with closing(sqlite3.connect(database)) as connection:
            assert connection.execute("SELECT count(*) FROM snapshot").fetchone() == (0,)
            assert connection.execute("SELECT count(*) FROM evaluation_run").fetchone() == (0,)
        valid = write_zip(tmp_path / "valid.zip", collector_members("Export"))
        followup = client.post(
            "/ingest",
            files={"file": ("valid.zip", valid.read_bytes(), "application/zip")},
            follow_redirects=False,
        )
        assert followup.status_code == 303
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT count(*) FROM snapshot").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM evaluation_run").fetchone() == (1,)
