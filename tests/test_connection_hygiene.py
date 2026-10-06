"""Check explicit closure, including errors, without depending on GC timing.

ResourceWarning alone becomes an unraisable exception in sqlite's destructor;
tracked connections also catch leaks on Python 3.12, which emits no warning.
"""

from __future__ import annotations

import argparse
import ast
import gc
import sqlite3
import warnings
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient
from performance_estate import collector_zip, comparator_zip, make_estate

from gpo_lens.cli import _diff, main
from gpo_lens.web import _helpers
from gpo_lens.web.app import create_app

pytestmark = pytest.mark.filterwarnings("error::ResourceWarning")


@pytest.fixture
def connections(monkeypatch):
    opened = []
    original = sqlite3.connect

    class TrackedConnection(sqlite3.Connection):
        closed = False

        def close(self):
            self.closed = True
            super().close()

    def connect(*args, **kwargs):
        kwargs["factory"] = TrackedConnection
        conn = original(*args, **kwargs)
        opened.append(conn)
        return conn

    monkeypatch.setattr(sqlite3, "connect", connect)
    yield opened
    leaks = [c for c in opened if not c.closed]
    for conn in leaks:
        conn.close()
    gc.collect()
    assert not leaks, f"{len(leaks)} connections were not explicitly closed"


def test_changelog_closes_after_query_error(tmp_path, connections, monkeypatch):
    def fail(*args, **kwargs):
        raise ValueError("synthetic query error")

    monkeypatch.setattr(_diff.snapshot_diff, "snapshot_changelog", fail)
    with pytest.raises(ValueError, match="synthetic query error"):
        _diff.cmd_changelog(
            argparse.Namespace(db=str(tmp_path / "lab.db"), snapshot_a=1, snapshot_b=2)
        )
    assert connections and all(c.closed for c in connections)


def test_rw_setup_closes_after_error(tmp_path, connections, monkeypatch):
    def fail(conn):
        raise RuntimeError("synthetic setup error")

    monkeypatch.setattr(_helpers._store, "restrict_db_permissions", fail)
    with pytest.raises(RuntimeError, match="synthetic setup error"):
        _helpers.get_rw_conn(str(tmp_path / "lab.db"))
    assert connections and all(c.closed for c in connections)


def test_rw_pragma_closes_after_error(tmp_path, connections, monkeypatch):
    original = sqlite3.connect

    def denied(*args, **kwargs):
        conn = original(*args, **kwargs)
        conn.set_authorizer(lambda *args: sqlite3.SQLITE_DENY)
        return conn

    monkeypatch.setattr(sqlite3, "connect", denied)
    with pytest.raises(sqlite3.DatabaseError):
        _helpers.get_rw_conn(str(tmp_path / "lab.db"))
    assert connections and all(c.closed for c in connections)


def test_route_query_errors_close_connections(tmp_path, connections, monkeypatch):
    from gpo_lens import store

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("synthetic read failure")

    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "lab-token")
    app = create_app(str(tmp_path / "lab.db"))
    monkeypatch.setattr(store, "load_estate", fail)
    with TestClient(
        app,
        raise_server_exceptions=False,
        headers={
            "Authorization": "Bearer lab-token",
            "Origin": "http://testserver",
        },
    ) as client:
        for route in (
            "/ou",
            "/api/v1/query/enforced_links",
            "/export/findings?format=json",
            "/setting?identity=Lab",
            "/inventory",
            "/",
        ):
            assert client.get(route).status_code == 500, route
            assert all(c.closed for c in connections), route
        for route in ("/golden-diff", "/baseline"):
            assert (
                client.post(
                    route,
                    files={
                        "file": ("lab.zip", comparator_zip(2, 4), "application/zip"),
                    },
                ).status_code
                == 500
            )
            assert all(c.closed for c in connections), route


def test_benchmark_script_closes_connection(connections, monkeypatch, capsys):
    import runpy
    import sys

    monkeypatch.setattr(
        sys, "argv", ["benchmark", "--gpos", "2", "--settings", "2", "--repeats", "1"]
    )
    runpy.run_path(
        str(Path(__file__).parents[1] / "scripts/benchmark_findings_gpo_ids.py"),
        run_name="__main__",
    )
    capsys.readouterr()
    assert connections and all(c.closed for c in connections)


def test_web_and_cli_connections(tmp_path, connections, monkeypatch, capsys):
    from gpo_lens.ingest import load_estate
    from gpo_lens.store import init_db, save_estate

    path = tmp_path / "lab.db"
    conn = sqlite3.connect(path)
    try:
        init_db(conn)
        estate = load_estate(Path(__file__).parent / "fixtures")
        save_estate(conn, estate)
        save_estate(conn, estate)
    finally:
        conn.close()
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "lab-token")
    with warnings.catch_warnings():
        warnings.simplefilter("error", ResourceWarning)
        with TestClient(
            create_app(str(path)),
            headers={
                "Authorization": "Bearer lab-token",
                "Origin": "http://testserver",
            },
        ) as client:
            gid = estate.gpos[0].id
            routes = (
                "/",
                "/findings",
                "/findings/1",
                "/findings/99999",
                "/findings?lifecycle=all&format=csv",
                "/accepted-risks",
                "/api/v1/health",
                "/api/v1/snapshots",
                "/api/v1/trends",
                "/api/v1/query/enforced_links",
                "/api/v1/query/estate_doctor",
                "/search?q=Lab",
                "/ou",
                f"/ou/{estate.soms[0].path}",
                f"/gpo/{gid}",
                f"/gpo/{gid}/ledger",
                "/gpo/unknown",
                "/changelog?snapshot_a=1&snapshot_b=2",
                "/trends",
                "/briefing",
                "/delegation",
                "/admx-coverage",
                "/conflicts",
                "/export/findings?format=json",
                f"/export/gpo/{gid}",
                "/setting?identity=unknown",
                "/setting?identity=unknown&snapshot=99999",
                "/ingest",
            )
            for route in routes:
                result = client.get(route)
                assert result.status_code in (200, 400, 404), (route, result.status_code)
                assert all(c.closed for c in connections), route
            for route in ("/golden-diff", "/baseline"):
                result = client.post(
                    route,
                    files={
                        "file": ("lab.zip", comparator_zip(2, 4), "application/zip"),
                    },
                )
                assert result.status_code == 200
                assert all(c.closed for c in connections), route
            result = client.post(
                "/ingest",
                files={
                    "file": ("bad.zip", b"bad zip", "application/zip"),
                },
            )
            assert result.status_code == 400
            result = client.post("/findings/99999/triage", data={"status": "acknowledged"})
            assert result.status_code == 400
            result = client.post(
                "/ingest",
                files={
                    "file": (
                        "lab-estate.zip",
                        collector_zip(
                            make_estate(
                                gpos=2,
                                soms=4,
                                settings=4,
                                links=2,
                            )
                        ),
                        "application/zip",
                    ),
                },
                follow_redirects=False,
            )
            assert result.status_code == 303
            assert all(c.closed for c in connections)
        commands = (
            ["danger"],
            ["doctor"],
            ["enforced"],
            ["snapshots"],
            ["diff", "1", "2"],
            ["diff-settings", "1", "2"],
            ["changelog", "1", "2"],
            ["trends"],
            ["events"],
            ["export", "findings", "--lifecycle", "all", "--format", "csv"],
        )
        for command in commands:
            assert main(["--db", str(path), *command]) == 0, command
            assert all(c.closed for c in connections), command
            capsys.readouterr()
        gc.collect()


def test_scripts_do_not_mistake_transaction_for_close():
    """The fixture builders execute released code, so audit their ownership syntax."""
    root = Path(__file__).parents[1]
    paths = [*(root / "scripts").glob("*.py"), *(root / "tests").glob("*.py")]
    for path in paths:
        source = path.read_text()
        # Include the Python worker embedded in the reopen-fixture builder.
        trees = [ast.parse(source)]
        trees += [
            ast.parse(node.value)
            for node in ast.walk(trees[0])
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and "import sqlite3" in node.value
        ]
        for tree in trees:
            for node in ast.walk(tree):
                if not isinstance(node, ast.With):
                    continue
                for item in node.items:
                    call = item.context_expr
                    assert not (
                        isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Attribute)
                        and isinstance(call.func.value, ast.Name)
                        and call.func.value.id == "sqlite3"
                        and call.func.attr == "connect"
                    ), f"{path.name}: sqlite transaction context does not close the connection"
