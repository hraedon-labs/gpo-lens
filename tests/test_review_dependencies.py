"""Malformed references and Windows namespaces never hide estate results."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gpo_lens import dependencies, queries, store
from gpo_lens.cli import main
from gpo_lens.ingest import parse_report_xml
from gpo_lens.model import Estate, Setting
from gpo_lens.web.app import create_app


def estate(target, tmp_path):
    gpo = parse_report_xml(
        (Path(__file__).parent / "fixtures/cse_audit_pki/report.xml").read_bytes()
    )[0]
    gpo.sysvol_path = str(tmp_path)
    gpo.settings = [Setting(gpo.id, "Computer", "Scripts", "Startup:lab", "Lab", target, {}, False)]
    return Estate(domain="lab.example.com", gpos=[gpo])


@pytest.mark.parametrize("surface", ["cli", "web"])
@pytest.mark.parametrize("command", ["dependencies", "doctor"])
def test_malformed_own_sysvol_is_reported(tmp_path, monkeypatch, capsys, surface, command):
    target = r"\\lab.example.com\SYSVOL\lab.example.com\Policies\not-a-guid\Machine\Scripts\lab.cmd"
    e = estate(target, tmp_path)
    db = tmp_path / "estate.db"
    with closing(sqlite3.connect(db)) as conn:
        store.init_db(conn)
        store.save_estate(conn, e)
    if surface == "cli":
        assert main(["--db", str(db), "--json", command]) == 0
        rows = json.loads(capsys.readouterr().out)["data"]
        if command == "doctor":
            assert any(r["category"] == "broken_ref:malformed_path" for r in rows["findings"])
    else:
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "lab-test-token")
        with TestClient(
            create_app(str(db)),
            base_url="http://localhost",
            headers={"Authorization": "Bearer lab-test-token"},
        ) as client:
            response = client.get("/?severity=all" if command == "doctor" else "/dependencies")
        assert response.status_code == 200
        if command == "doctor":
            assert any(
                f.category == "broken_ref:malformed_path" for f in response.context["findings"]
            )
    assert queries.broken_refs(e)[0].ref_type == "malformed_path"
    assert queries.external_dependencies(e) == []


@pytest.mark.parametrize(
    "target,host,share,kind",
    [
        (r"\\?\UNC\files.example.com\share\team", "files.example.com", "share", "unc"),
        (r"\\files.example.com@SSL\DavWWWRoot\team", "files.example.com", "davwwwroot", "webdav"),
        (
            r"\\files.example.com@SSL@8443\DavWWWRoot\team",
            "files.example.com",
            "davwwwroot",
            "webdav",
        ),
        (r"\\.\pipe\lab-pipe", "", "", "named_pipe"),
        (r"\\?\pipe\lab-pipe", "", "", "named_pipe"),
        (r"\\.\PhysicalDrive0", "", "", "device"),
        (r"\\?\C:\lab\file", "", "", "device"),
        (r"\\user@files.example.com\share", "user@files.example.com", "share", "unc"),
    ],
)
def test_windows_path_classification(tmp_path, target, host, share, kind):
    e = estate(target, tmp_path)
    groups = queries.external_dependencies(e)
    assert [(g.server, g.shares) for g in groups] == ([(host, (share,))] if host else [])
    assert queries.broken_refs(e) == []
    classified = dependencies.classify_windows_path(target)
    assert classified.kind == kind
