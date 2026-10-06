"""Synthetic collector archives, including Windows PowerShell 5.1 paths."""

from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

from gpo_lens.cli import main
from gpo_lens.web.app import _safe_extract

FIXTURE = Path(__file__).parent / "fixtures"


def collector_zip(path: Path, separator: str = "/", prefix: str = "") -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(FIXTURE.rglob("*")):
            if file.is_file() and file.suffix != ".py":
                member = prefix + file.relative_to(FIXTURE).as_posix()
                archive.write(file, member.replace("/", separator))
    return path


@pytest.mark.parametrize("separator,prefix", [("/", ""), ("\\", ""), ("\\", "export/")])
def test_cli_ingests_zip_and_removes_temporary_files(
    tmp_path, capsys, monkeypatch, separator, prefix
):
    import gpo_lens.ingest as ingest

    original = ingest.load_estate
    loaded = []

    def recording_load(source):
        loaded.append(Path(source))
        return original(source)

    monkeypatch.setattr(ingest, "load_estate", recording_load)
    archive = collector_zip(tmp_path / "collector.ZIP", separator, prefix)
    database = tmp_path / "estate.db"
    main(["--db", str(database), "ingest", str(archive), "--json", "--diff-latest"])
    result = json.loads(capsys.readouterr().out)["data"]
    assert result["gpo_count"] == 14
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM snapshot").fetchone()[0] == 1
        assert (
            conn.execute("SELECT COUNT(*) FROM evaluation_run WHERE status='completed'").fetchone()[
                0
            ]
            == 1
        )
    assert len(loaded) == 1
    assert not loaded[0].exists()
    assert archive.exists()


def test_cli_zip_cleanup_on_invalid_estate(tmp_path, monkeypatch):
    import gpo_lens.ingest as ingest

    loaded = []

    def failing_load(source):
        loaded.append(Path(source))
        raise ValueError("invalid synthetic estate")

    monkeypatch.setattr(ingest, "load_estate", failing_load)
    archive = collector_zip(tmp_path / "collector.zip")
    assert main(["--db", str(tmp_path / "estate.db"), "ingest", str(archive)]) != 0
    assert len(loaded) == 1
    assert not loaded[0].exists()
    assert not (tmp_path / "estate.db").exists()


def test_backslash_paths_extract_as_directories(tmp_path):
    archive = tmp_path / "collector.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("reports\\", "")
        zf.writestr("reports\\lab.xml", "synthetic")
    dest = tmp_path / "extracted"
    dest.mkdir()
    _safe_extract(archive, dest)
    assert (dest / "reports" / "lab.xml").read_text() == "synthetic"


@pytest.mark.parametrize(
    "member",
    [
        "..\\escape.txt",
        "sub/..\\..\\escape.txt",
        "C:\\escape.txt",
        "\\\\server\\share\\file",
        "sub/file:stream",
    ],
)
def test_windows_unsafe_paths_rejected_and_partial_files_removed(tmp_path, member):
    archive = tmp_path / "collector.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("safe.txt", "synthetic")
        zf.writestr(member, "synthetic")
    dest = tmp_path / "extracted"
    dest.mkdir()
    with pytest.raises(ValueError, match="zip-slip blocked"):
        _safe_extract(archive, dest)
    assert not list(dest.iterdir())


def test_ratio_limit_is_shared_with_web(tmp_path):
    archive = tmp_path / "collector.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("repetitive.txt", b"x" * 2_000_000)
    dest = tmp_path / "extracted"
    dest.mkdir()
    with pytest.raises(ValueError, match="compression ratio exceeds limit"):
        _safe_extract(archive, dest)
    assert not list(dest.iterdir())


def test_cli_rejects_bad_zip_without_creating_database(tmp_path, capsys):
    archive = tmp_path / "collector.zip"
    archive.write_text("not a zip")
    assert main(["--db", str(tmp_path / "estate.db"), "ingest", str(archive)]) != 0
    assert "File is not a zip file" in capsys.readouterr().err
    assert not (tmp_path / "estate.db").exists()


@pytest.mark.parametrize("limit", ["archive", "total"])
def test_shared_size_limits(tmp_path, limit):
    from gpo_lens.collection_zip import safe_extract

    archive = tmp_path / "collector.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("first.txt", "synthetic")
        zf.writestr("second.txt", "synthetic")
    dest = tmp_path / "extracted"
    dest.mkdir()
    limits = {"max_archive_bytes": 1} if limit == "archive" else {"max_uncompressed_bytes": 12}
    with pytest.raises(ValueError, match="size exceeds limit"):
        safe_extract(archive, dest, **limits)
    assert not list(dest.iterdir())


@pytest.mark.parametrize("reports", [[], ["first/AllGPOs.xml", "second/AllGPOs.xml"]])
def test_cli_rejects_missing_or_ambiguous_estate(tmp_path, capsys, reports):
    archive = tmp_path / "collector.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for report in reports:
            zf.writestr(report, "<GPOs/>")
    assert main(["--db", str(tmp_path / "estate.db"), "ingest", str(archive)]) != 0
    assert "exactly one AllGPOs.xml" in capsys.readouterr().err
    assert not (tmp_path / "estate.db").exists()


@pytest.mark.parametrize("kind", ["traversal", "symlink", "ratio"])
def test_cli_uses_shared_rejection_policy(tmp_path, capsys, kind):
    archive = tmp_path / "collector.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AllGPOs.xml", (FIXTURE / "AllGPOs.xml").read_bytes())
        if kind == "traversal":
            zf.writestr("..\\outside.txt", "synthetic")
        elif kind == "symlink":
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            zf.writestr(info, "AllGPOs.xml")
        else:
            zf.writestr("repetitive.txt", b"x" * 2_000_000)
    assert main(["--db", str(tmp_path / "estate.db"), "ingest", str(archive)]) != 0
    error = capsys.readouterr().err
    assert {"traversal": "zip-slip", "symlink": "symlink", "ratio": "ratio"}[kind] in error
    assert not (tmp_path / "estate.db").exists()


def test_separator_aliases_cannot_overwrite_files(tmp_path):
    archive = tmp_path / "collector.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("reports/lab.xml", "synthetic one")
        zf.writestr("reports\\lab.xml", "synthetic two")
    dest = tmp_path / "extracted"
    dest.mkdir()
    with pytest.raises(ValueError, match="duplicate"):
        _safe_extract(archive, dest)
    assert not list(dest.iterdir())


def test_web_upload_accepts_wrapped_windows_zip(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "synthetic-test-token")
    archive = collector_zip(tmp_path / "collector.zip", "\\", "export/")
    database = tmp_path / "estate.db"
    with TestClient(
        create_app(str(database)),
        headers={"Authorization": "Bearer synthetic-test-token", "Origin": "http://localhost"},
    ) as client:
        response = client.post(
            "/ingest",
            files={"file": ("collector.zip", archive.read_bytes(), "application/zip")},
            follow_redirects=False,
        )
        assert response.status_code == 303
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM gpo").fetchone()[0] == 14


def test_expansion_cap_is_enforced_before_writing_beyond_budget(tmp_path, monkeypatch):
    import builtins
    from contextlib import contextmanager

    from gpo_lens import collection_zip

    archive = tmp_path / "collector.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("first.txt", "synthetic")
        zf.writestr("second.txt", "synthetic")
    dest = tmp_path / "extracted"
    dest.mkdir()
    written = bytearray()

    @contextmanager
    def recording_open(path, mode):
        with builtins.open(path, mode) as output:

            class Writer:
                def write(self, data):
                    written.extend(data)
                    return output.write(data)

            yield Writer()

    monkeypatch.setattr(collection_zip, "open", recording_open, raising=False)
    with pytest.raises(ValueError, match="size exceeds limit"):
        collection_zip.safe_extract(archive, dest, max_uncompressed_bytes=12)
    assert len(written) <= 12
    assert not list(dest.iterdir())


def test_cli_second_zip_ingest_emits_diff_events(tmp_path, capsys):
    archive = collector_zip(tmp_path / "collector.zip")
    database = tmp_path / "estate.db"
    command = ["--db", str(database), "ingest", str(archive), "--json", "--diff-latest"]
    assert main(command) == 0
    capsys.readouterr()
    assert main(command) == 0
    result = json.loads(capsys.readouterr().out)["data"]
    assert result["snapshot_id"] == 2
    assert result["changelog"] == []
    with sqlite3.connect(database) as conn:
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM events WHERE event_type='ingest.summary'"
            ).fetchone()[0]
            == 1
        )


def test_cli_and_zip_helper_load_without_web_dependencies():
    import subprocess
    import sys

    check = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; sys.modules['fastapi'] = None; sys.modules['gpo_lens.web'] = None; "
                "import gpo_lens.cli; import gpo_lens.collection_zip"
            ),
        ],
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stderr


@pytest.mark.parametrize(
    "member",
    [
        "AllGPOs.xml.",
        "reports /file",
        ".. /outside.txt",
        "NUL.txt",
        "CON",
        "COM1.xml",
        "LPT9",
        "CONOUT$",
        "reports//file",
        "./AllGPOs.xml",
    ],
)
def test_windows_canonicalization_and_device_paths_rejected(tmp_path, member):
    archive = tmp_path / "collector.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(member, "synthetic")
    dest = tmp_path / "extracted"
    dest.mkdir()
    with pytest.raises(ValueError, match="zip-slip blocked"):
        _safe_extract(archive, dest)
    assert not list(dest.iterdir())
