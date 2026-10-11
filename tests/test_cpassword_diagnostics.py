"""No discovered cpassword value in any human-facing diagnostic (review r4 B-01).

Hostile fixtures exercise skipped, malformed and rejected inputs. Every warning,
log record, exception message and CLI stdout/stderr line produced along the way
is captured and searched for each discovered value and its canonical
equivalents (whitespace-split, URL-safe, unpadded).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import warnings
import zipfile
from contextlib import closing
from pathlib import Path

import pytest

from gpo_lens import ingest
from gpo_lens.redaction import Chaser

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests/fixtures/released_databases/v1.4.0-cpassword.sqlite3"
V = base64.b64encode(b"PROBEcpwR4EXCEPT").decode()  # Sol's round-4 probe value


def _leaks(text: str, values: tuple[str, ...] = (V,)) -> bool:
    return any(v in text for v in values) or Chaser(values).contains(text)


def _gpo(guid: str, name: str, *, owner: str = "LAB\\Owner", cpassword: str = V) -> str:
    return (
        f"<GPO><Identifier><Identifier>{guid}</Identifier><Domain>LABDOMAIN</Domain>"
        f"</Identifier><Name>{name}</Name><Description>safe</Description>"
        f"<SecurityDescriptor><Owner><Name>{owner}</Name></Owner></SecurityDescriptor>"
        "<Computer><Enabled>true</Enabled><VersionDirectory>1</VersionDirectory>"
        "<VersionSysvol>1</VersionSysvol><ExtensionData><Name>Drive Maps</Name><Extension>"
        '<Drives><Drive uid="{11111111-1111-1111-1111-000000000001}" name="probe">'
        f'<Properties action="U" path="\\\\server\\probe" cpassword="{cpassword}"/>'
        "</Drive></Drives></Extension></ExtensionData></Computer><User><Enabled>true</Enabled>"
        "<VersionDirectory>1</VersionDirectory><VersionSysvol>1</VersionSysvol></User></GPO>"
    )


# Sol's probe: the malformed GPO's identifier and name are the labelled value.
MALFORMED = "<GPOs>" + _gpo(V, V) + "</GPOs>"
# A labelled source in one GPO and the skipped malformed GPO named after it.
MIXED = (
    "<GPOs>"
    + _gpo("{71717171-7171-7171-7171-717171717171}", "source")
    + _gpo("not-a-guid", f"copy-{V}", cpassword="")
    + "</GPOs>"
)


def _export(tmp_path: Path, report: str, name: str = "export") -> Path:
    export = tmp_path / name
    export.mkdir()
    (export / "AllGPOs.xml").write_text(report, encoding="utf-8")
    return export


class _Captured:
    def __init__(self) -> None:
        self.texts: list[str] = []

    def add(self, *texts: object) -> None:
        self.texts.extend(str(t) for t in texts)

    def leaked(self) -> list[str]:
        return [t for t in self.texts if _leaks(t)]


@pytest.fixture
def captured(caplog, capsys):
    caplog.set_level(logging.DEBUG)
    sink = _Captured()
    with warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")
        yield sink
    out, err = capsys.readouterr()
    sink.add(out, err, *(str(w.message) for w in recorded))
    sink.add(*(record.getMessage() for record in caplog.records))
    sink.add(*(r.exc_text or "" for r in caplog.records))
    assert sink.leaked() == []


def _cli_subprocess(tmp_path: Path, *argv: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONWARNINGS": "default"}
    return subprocess.run(
        [sys.executable, "-m", "gpo_lens", *argv],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.parametrize("report", [MALFORMED, MIXED], ids=["sol-probe", "mixed"])
def test_skipped_malformed_gpo_directory_bytes_and_cli(tmp_path: Path, captured, report) -> None:
    from gpo_lens.cli import main

    export = _export(tmp_path, report)
    estate = ingest.load_estate(export)
    captured.add(json.dumps([g.name for g in estate.gpos]))
    ingest.parse_report_xml(report.encode())
    ingest.parse_report(export / "AllGPOs.xml")
    db = tmp_path / "in-process.sqlite3"
    main(["--db", str(db), "ingest", str(export)])
    proc = _cli_subprocess(tmp_path, "--db", str(tmp_path / "cli.sqlite3"), "ingest", str(export))
    captured.add(proc.stdout, proc.stderr)
    assert "no valid identifier" in proc.stderr  # the skip is still reported


def test_baseline_zip_with_skipped_and_broken_entries(tmp_path: Path, captured) -> None:
    archive = tmp_path / "baseline.zip"
    with zipfile.ZipFile(archive, "w") as out:
        out.writestr("GPOs/a/gpreport.xml", _gpo("{72727272-7272-7272-7272-727272727272}", "a"))
        out.writestr("GPOs/b/gpreport.xml", _gpo("bad-guid", f"copy {V}", cpassword=""))
        out.writestr("GPOs/c/gpreport.xml", f"<GPO><Name>{V}</Name>")  # not well-formed
    gpos = ingest.load_baseline_from_zip(archive)
    captured.add(json.dumps([g.name for g in gpos]))


def test_web_upload_of_hostile_collector_zip(tmp_path: Path, captured, monkeypatch) -> None:
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "diagnostics-token")
    archive = tmp_path / "collector.zip"
    with zipfile.ZipFile(archive, "w") as out:
        out.writestr("AllGPOs.xml", MIXED)
    with TestClient(
        create_app(str(tmp_path / "web.sqlite3")),
        headers={"Authorization": "Bearer diagnostics-token", "Origin": "http://localhost"},
    ) as client:
        response = client.post(
            "/ingest",
            files={"file": ("collector.zip", archive.read_bytes(), "application/zip")},
            follow_redirects=False,
        )
        captured.add(response.text, json.dumps(dict(response.headers)))
        captured.add(client.get("/ingest").text)


def test_rejected_identity_copy(tmp_path: Path, captured) -> None:
    from gpo_lens.redaction import CredentialInIdentityError

    report = "<GPOs>" + _gpo("{73737373-7373-7373-7373-737373737373}", "x", owner=V) + "</GPOs>"
    export = _export(tmp_path, report)
    with pytest.raises(CredentialInIdentityError) as caught:
        ingest.load_estate(export)
    captured.add(str(caught.value), repr(caught.value))
    proc = _cli_subprocess(tmp_path, "--db", str(tmp_path / "cli.sqlite3"), "ingest", str(export))
    assert proc.returncode != 0
    captured.add(proc.stdout, proc.stderr)


def test_residual_error_names_positions_not_values(tmp_path: Path, captured, monkeypatch) -> None:
    from gpo_lens import redaction
    from gpo_lens.redaction import CpasswordResidualError

    monkeypatch.setattr(redaction.Chaser, "sub", lambda self, text: text)
    report = (
        "<GPOs>"
        + _gpo("{74747474-7474-7474-7474-747474747474}", "x")
        + _gpo("{75757575-7575-7575-7575-757575757575}", f"copy-{V}", cpassword="")
        + "</GPOs>"
    )
    export = _export(tmp_path, report)
    with pytest.raises(CpasswordResidualError) as caught:
        ingest.load_estate(export)
    captured.add(str(caught.value), repr(caught.value))


def test_migration_refusal_and_unverifiable_scrub(tmp_path: Path, captured, monkeypatch) -> None:
    from gpo_lens import redaction
    from gpo_lens.store import init_db

    refused = tmp_path / "refused.sqlite3"
    shutil.copyfile(FIXTURE, refused)
    with closing(sqlite3.connect(refused)) as conn:
        conn.execute(
            "UPDATE gpo SET computer_enabled = ? WHERE rowid = (SELECT rowid FROM gpo LIMIT 1)",
            (f'cpassword="{V}"',),
        )
        conn.commit()
    with closing(sqlite3.connect(refused)) as conn:
        with pytest.raises(ValueError) as caught:
            init_db(conn)
        captured.add(str(caught.value))
    rolled_back = tmp_path / "rolled-back.sqlite3"
    shutil.copyfile(FIXTURE, rolled_back)
    with closing(sqlite3.connect(rolled_back)) as conn:
        conn.execute(
            "UPDATE gpo SET description = ? WHERE rowid = (SELECT rowid FROM gpo LIMIT 1)",
            (f'cpassword="{V}" and copy {V}',),
        )
        conn.commit()
    monkeypatch.setattr(redaction.Chaser, "sub", lambda self, text: text)
    with closing(sqlite3.connect(rolled_back)) as conn:
        init_db(conn)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 10


def test_zip_member_names_are_never_echoed(tmp_path: Path, captured) -> None:
    archive = tmp_path / "hostile.zip"
    with zipfile.ZipFile(archive, "w") as out:
        out.writestr("AllGPOs.xml", MIXED)
        out.writestr(f"../{V}", "x")
    proc = _cli_subprocess(tmp_path, "--db", str(tmp_path / "zip.sqlite3"), "ingest", str(archive))
    assert proc.returncode != 0 and "zip-slip blocked" in proc.stderr
    captured.add(proc.stdout, proc.stderr)


def test_guard_scrubs_log_records_and_exceptions(captured) -> None:
    from gpo_lens.redaction import guarded_diagnostics

    logger = logging.getLogger("gpo_lens.diagnostics_probe")
    with pytest.raises(RuntimeError) as caught, guarded_diagnostics({V}):
        logger.warning("value %s inline cpassword=%s", V, "PROBEcpwINLINE4444")
        warnings.warn(f"copy {V[:8]}\n{V[8:]}", stacklevel=1)  # whitespace-split copy
        raise RuntimeError(f"failed on {V}") from ValueError(V)
    captured.add(str(caught.value), str(caught.value.__cause__))


# --- Round 5: orchestration sinks and extraction errors ---------------------------


def _collector_zip(path: Path, extra: list[tuple[str, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as out:
        out.writestr("AllGPOs.xml", MIXED)
        for name, data in extra:
            out.writestr(name, data)
    return path


def _corrupt_crc(path: Path, marker: bytes) -> None:
    data = path.read_bytes()
    index = data.index(marker)
    path.write_bytes(data[:index] + b"j" + data[index + 1 :])


@pytest.mark.parametrize("kind", ["name-too-long", "bad-crc", "file-dir-collision"])
def test_zip_extraction_errors_never_echo_member_names(
    tmp_path: Path, captured, monkeypatch, kind: str
) -> None:
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    archive = tmp_path / "hostile.zip"
    if kind == "name-too-long":
        _collector_zip(archive, [("A" * 280 + V + "B" * 10, b"x")])
    elif kind == "bad-crc":
        _collector_zip(archive, [(V, b"hello crc world")])
        _corrupt_crc(archive, b"hello crc world")
    else:
        _collector_zip(archive, [(V, b"file"), (f"{V}/inner", b"x")])
    proc = _cli_subprocess(tmp_path, "--db", str(tmp_path / "cli.sqlite3"), "ingest", str(archive))
    assert proc.returncode != 0 and "could not be extracted" in proc.stderr
    captured.add(proc.stdout, proc.stderr)
    audit = tmp_path / "audit.log"
    monkeypatch.setenv("GPO_LENS_AUDIT_LOG", str(audit))
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "diagnostics-token")
    with TestClient(
        create_app(str(tmp_path / "web.sqlite3")),
        headers={"Authorization": "Bearer diagnostics-token", "Origin": "http://localhost"},
    ) as client:
        response = client.post(
            "/ingest",
            files={"file": (f"{V}.zip", archive.read_bytes(), "application/zip")},
            follow_redirects=False,
        )
        assert response.status_code == 400
        captured.add(response.text)
    captured.add(audit.read_bytes().decode("latin-1") if audit.exists() else "")


def test_cli_path_arguments_are_not_echoed(tmp_path: Path, captured) -> None:
    export = _export(tmp_path, MIXED)
    missing = tmp_path / f"admx-{V}"
    proc = _cli_subprocess(
        tmp_path,
        "--db",
        str(tmp_path / "admx.sqlite3"),
        "ingest",
        "--admx-dir",
        str(missing),
        str(export),
    )
    assert proc.returncode == 0 and "--admx-dir path #1 not found" in proc.stderr
    captured.add(proc.stdout, proc.stderr)
    proc = _cli_subprocess(tmp_path, "--db", str(tmp_path / "x.sqlite3"), "ingest", str(missing))
    captured.add(proc.stdout, proc.stderr)


def test_web_upload_filename_never_reaches_audit_log(tmp_path: Path, captured, monkeypatch) -> None:
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    archive = _collector_zip(tmp_path / "collector.zip", [])
    audit = tmp_path / "audit.log"
    monkeypatch.setenv("GPO_LENS_AUDIT_LOG", str(audit))
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "diagnostics-token")
    with TestClient(
        create_app(str(tmp_path / "web.sqlite3")),
        headers={"Authorization": "Bearer diagnostics-token", "Origin": "http://localhost"},
    ) as client:
        response = client.post(
            "/ingest",
            files={"file": (f"{V}.zip", archive.read_bytes(), "application/zip")},
            follow_redirects=False,
        )
        assert response.status_code == 303
    data = audit.read_bytes()
    assert b'"outcome": "success"' in data
    captured.add(data.decode("latin-1"))


def test_exception_groups_and_structured_arguments_are_scrubbed(captured) -> None:
    from gpo_lens.redaction import guarded_diagnostics

    with pytest.raises(ExceptionGroup) as caught, guarded_diagnostics({V}):
        raise ExceptionGroup("group", [ValueError(f"inner {V}"), RuntimeError({"field": V})])
    captured.add(repr(caught.value), *(repr(e) for e in caught.value.exceptions))
    with pytest.raises(json.JSONDecodeError) as decode, guarded_diagnostics({V}):
        json.loads(f'{{"copy": "{V}", broken')
    captured.add(repr(decode.value), decode.value.doc)


def test_log_records_scrubbed_after_factory_swap_and_in_threads(captured) -> None:
    import threading

    from gpo_lens.redaction import guarded_diagnostics

    original = logging.getLogRecordFactory()
    logging.setLogRecordFactory(lambda *a, **k: logging.LogRecord(*a, **k))
    try:
        with guarded_diagnostics({V}):
            logging.getLogger("gpo_lens.diagnostics_probe").warning("swap %s", V)
            worker = threading.Thread(
                target=lambda: logging.getLogger("gpo_lens.diagnostics_probe").warning(
                    "thread %s", V
                )
            )
            worker.start()
            worker.join()
    finally:
        logging.setLogRecordFactory(original)
