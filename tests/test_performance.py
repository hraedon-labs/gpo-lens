"""Structural budgets run in CI; the full calibration is explicitly opt-in."""

from __future__ import annotations

import os
import sqlite3
import time
from contextlib import closing

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient
from performance_estate import LAB_SECRET, collector_zip, comparator_zip, make_estate, populate_db

from gpo_lens.exports import occurrence_run_ids
from gpo_lens.web.app import create_app


def legacy_occurrence_run_ids(conn, occurrence_ids):
    """Frozen v1.3 algorithm, including missing IDs and resolved provenance."""
    runs = set()
    for oid in sorted(set(occurrence_ids)):
        row = conn.execute(
            "SELECT first_seen_run_id,last_seen_run_id,resolved_run_id FROM finding WHERE id=?",
            (oid,),
        ).fetchone()
        if row:
            runs.update(run for run in row if run is not None)
        runs.update(
            row[0]
            for row in conn.execute(
                "SELECT run_id FROM finding_observation WHERE occurrence_id=?", (oid,)
            )
        )
    return sorted(runs)


@pytest.fixture
def performance_db(tmp_path):
    path = tmp_path / "lab.sqlite3"
    estate = make_estate(gpos=12, soms=80, settings=12, links=8)
    with closing(sqlite3.connect(path)) as conn:
        populate_db(conn, estate, findings_per_gpo=12)
    return path


def test_provenance_query_budget(performance_db):
    with closing(sqlite3.connect(performance_db)) as conn:
        ids = [r[0] for r in conn.execute("SELECT id FROM finding")]
        expected = legacy_occurrence_run_ids(conn, ids)
        statements = []
        conn.set_trace_callback(statements.append)
        assert occurrence_run_ids(conn, ids) == expected
        assert len(statements) <= 4, f"N+1 provenance queries: {len(statements)}"


@pytest.mark.parametrize("format", ["md", "csv"])
def test_findings_export_identical_and_bounded(performance_db, monkeypatch, format):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "lab-token")
    import anyio.to_thread as concurrency

    import gpo_lens.web.routes.findings as route

    handoffs = 0
    original = concurrency.run_sync

    async def counted(*args, **kwargs):
        nonlocal handoffs
        handoffs += 1
        return await original(*args, **kwargs)

    monkeypatch.setattr(concurrency, "run_sync", counted)
    with TestClient(create_app(str(performance_db))) as client:
        url = f"/findings?lifecycle=all&per_page=all&format={format}"
        headers = {"Authorization": "Bearer lab-token"}
        start = time.perf_counter()
        response = client.get(url, headers=headers)
        elapsed = time.perf_counter() - start
        assert response.status_code == 200
        assert LAB_SECRET not in response.text
        assert "Lab finding" in response.text
        assert handoffs < 100, f"Per-field threadpool handoffs: {handoffs}"
        assert elapsed < 10
        monkeypatch.setattr(route, "occurrence_run_ids", legacy_occurrence_run_ids)
        # Chunking must also preserve the bytes of the original line stream.
        import gpo_lens.web.routes.export as export_route

        monkeypatch.setattr(export_route, "_export_chunks", lambda lines: lines)
        old = client.get(url, headers=headers)
        assert old.content == response.content
        assert old.headers["content-type"] == response.headers["content-type"]


def test_generator_is_seeded():
    assert make_estate(gpos=6, soms=8, settings=4, links=3) == make_estate(
        gpos=6, soms=8, settings=4, links=3
    )
    assert comparator_zip(3, 4) == comparator_zip(3, 4)
    assert collector_zip(make_estate(gpos=3, soms=4, settings=4, links=2)) == collector_zip(
        make_estate(gpos=3, soms=4, settings=4, links=2)
    )
    assert make_estate(seed=141, gpos=6, soms=8, settings=4, links=3) != make_estate(
        gpos=6, soms=8, settings=4, links=3
    )


def test_redaction_preparation_budget(monkeypatch):
    import gpo_lens.safe_output as output

    calls = 0
    original = output.secret_values

    def counted(value):
        nonlocal calls
        calls += 1
        return original(value)

    monkeypatch.setattr(output, "secret_values", counted)
    payload = [{"summary": f"Lab row {i}", "detail": LAB_SECRET} for i in range(200)]
    projected = output.safe_data(payload, secrets=(LAB_SECRET,))
    assert all(row["detail"] == "[REDACTED]" for row in projected)
    assert calls == 1, f"Repeated credential discovery: {calls}"


def test_shared_evidence_discovered_once(monkeypatch):
    import gpo_lens.safe_output as output

    shared = {"raw": {"password": LAB_SECRET}, "summary": "Lab evidence"}
    visits = 0
    original = output._mapping

    def counted(obj):
        nonlocal visits
        if obj is shared:
            visits += 1
        return original(obj)

    monkeypatch.setattr(output, "_mapping", counted)
    assert output.secret_values([shared] * 200) == (LAB_SECRET,)
    assert visits == 1, f"Repeated discovery of shared evidence: {visits}"


@pytest.mark.parametrize("count", [0, 1, 499, 500, 501, 1205])
def test_provenance_retains_all_sources_across_batches(count):
    with closing(sqlite3.connect(":memory:")) as conn:
        conn.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
        conn.executescript(
            "CREATE TABLE finding (id INTEGER PRIMARY KEY, first_seen_run_id INTEGER, "
            "last_seen_run_id INTEGER, resolved_run_id INTEGER);"
            "CREATE TABLE finding_observation (occurrence_id INTEGER, run_id INTEGER);"
        )
        conn.executemany(
            "INSERT INTO finding VALUES (?, ?, ?, ?)",
            [(i, i * 10 + 1, None, i * 10 + 3) for i in range(count)],
        )
        conn.executemany(
            "INSERT INTO finding_observation VALUES (?, ?)", [(i, i * 10 + 2) for i in range(count)]
        )
        # An observation without a finding still supplies provenance in v1.3.
        conn.execute("INSERT INTO finding_observation VALUES (?, ?)", (count + 1, 99_999))
        ids = list(range(count)) + [count + 1, count + 2, count + 1]
        expected = legacy_occurrence_run_ids(conn, ids)
        statements = []
        conn.set_trace_callback(statements.append)
        assert occurrence_run_ids(conn, iter(ids)) == expected
        assert len(statements) == 2 * ((count + 2 + 499) // 500)
        statements.clear()
        assert occurrence_run_ids(conn, []) == []
        assert statements == []


def test_export_chunks_bound_memory_and_preserve_utf8():
    from gpo_lens.web.routes.export import _export_chunks

    lines = ["", "Lab 🧪\n", "é" * 200, "end\n"]
    chunks = list(_export_chunks(iter(lines), size=7))
    assert b"".join(chunks) == "".join(lines).encode("utf-8")
    assert all(0 < len(c) <= 7 for c in chunks)
    assert list(_export_chunks(["tail"], size=7)) == [b"tail"]
    assert list(_export_chunks([])) == []
    with pytest.raises(ValueError, match="positive"):
        list(_export_chunks(lines, size=0))

    def lazy():
        yield "x" * 70_000
        raise AssertionError("read past first chunk")

    stream = _export_chunks(lazy())
    assert next(stream) == b"x" * 65_536
    stream.close()


def test_prepared_redaction_matches_legacy_text():
    import html

    from gpo_lens import safe_output as output

    secret = "LAB<&|` CREDENTIAL"
    data = {
        "password": secret,
        "nested": [
            secret,
            html.escape(secret),
            secret.replace("`", "&#96;"),
            html.escape(secret.replace("|", "\\|"), quote=False),
            "https://user:lab%20credential@lab.example.com/path",
            "Copied lab credential",
            "password='lab credential'",
            "policy MinimumPasswordLength=14",
            "[REDACTED]",
        ],
    }
    secrets = output.secret_values(data)

    # Freeze v1.3's per-string preparation, independent of the new helpers.
    def legacy_text(value):
        values = set(secrets) | set(output.secret_values(value))
        variants = set()
        for item in values:
            variants.update(
                {
                    item,
                    html.escape(item),
                    html.escape(item, quote=False),
                    item.replace("`", "&#96;"),
                    html.escape(item.replace("|", "\\|").replace("\n", " "), quote=False),
                }
            )
        for item in sorted(
            (v for v in variants if v and v != output.REDACTED), key=lambda v: (-len(v), v)
        ):
            value = value.replace(item, output.REDACTED)
        return output._ASSIGNMENT.sub(lambda m: m[1] + "=" + output.REDACTED, value)

    projected = output.safe_data(data)
    assert projected["password"] == output.REDACTED
    assert projected["nested"] == [legacy_text(v) for v in data["nested"]]
    assert output.safe_data({"summary": "LAB-long"}, secrets=("LAB", "LAB-long")) == {
        "summary": output.REDACTED
    }


@pytest.mark.parametrize(
    "route",
    [
        "/golden-diff",
        "/baseline",
        "/api/v1/query/enforced_links",
        "/dependencies?format=md",
        "/dependencies?format=csv",
    ],
)
def test_secondary_paths_budget(performance_db, monkeypatch, route):
    import gpo_lens.web.routes.api as api
    import gpo_lens.web.routes.baseline as baseline
    import gpo_lens.web.routes.dependencies as dependencies
    import gpo_lens.web.routes.golden as golden
    from gpo_lens.web import _helpers

    statements = []
    original = _helpers.get_ro_conn

    def counted(path):
        conn = original(path)
        conn.set_trace_callback(statements.append)
        return conn

    for module in (api, baseline, golden, dependencies):
        monkeypatch.setattr(module, "get_ro_conn", counted)
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "lab-token")
    with TestClient(
        create_app(str(performance_db)),
        headers={
            "Authorization": "Bearer lab-token",
            "Origin": "http://testserver",
        },
    ) as client:
        start = time.perf_counter()
        result = (
            client.get(route)
            if route.startswith(("/api", "/dependencies"))
            else client.post(
                route, files={"file": ("lab.zip", comparator_zip(12, 12), "application/zip")}
            )
        )
        assert result.status_code == 200
        assert "Invalid" not in result.text
        assert LAB_SECRET not in result.text
        if route.startswith("/dependencies"):
            assert "lab-fs00" in result.text
            assert "printer_connection" in result.text.replace(r"\_", "_")
            assert result.content == client.get(route).content
        assert len(statements) < 50, f"N+1 estate queries: {len(statements)}"
        assert time.perf_counter() - start < 10


@pytest.mark.slow
@pytest.mark.skipif(os.environ.get("GPO_LENS_BENCHMARK") != "1", reason="opt-in large benchmark")
def test_large_estate_benchmark(tmp_path, monkeypatch):
    """GPO_LENS_BENCHMARK=1 pytest -n0 -s tests/test_performance.py -m slow."""
    path = tmp_path / "large-lab.sqlite3"
    estate = make_estate()
    with closing(sqlite3.connect(path)) as conn:
        populate_db(conn, estate)
        for table, expected in (
            ("gpo", 390),
            ("som", 4500),
            ("setting", 14040),
            ("som_link", 99000),
            ("finding", 4680),
            ("finding_observation", 14040),
        ):
            assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == expected
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "lab-token")
    with TestClient(
        create_app(str(path)),
        headers={
            "Authorization": "Bearer lab-token",
            "Origin": "http://testserver",
        },
    ) as client:
        for format in ("md", "csv"):
            start = time.perf_counter()
            result = client.get(f"/findings?lifecycle=all&per_page=all&format={format}")
            elapsed = time.perf_counter() - start
            print(f"findings {format}: {elapsed:.3f}s, {len(result.content)} bytes")
            assert result.status_code == 200
            assert elapsed < 15
            assert LAB_SECRET not in result.text
            start = time.perf_counter()
            result = client.get(f"/dependencies?format={format}")
            elapsed = time.perf_counter() - start
            print(f"dependencies {format}: {elapsed:.3f}s, {len(result.content)} bytes")
            assert result.status_code == 200
            assert elapsed < 15
            assert LAB_SECRET not in result.text
            assert "lab-fs00" in result.text
            assert result.content == client.get(f"/dependencies?format={format}").content
        upload = comparator_zip()
        for route in ("/golden-diff", "/baseline"):
            start = time.perf_counter()
            result = client.post(route, files={"file": ("lab.zip", upload, "application/zip")})
            print(f"{route}: {time.perf_counter() - start:.3f}s, {len(result.content)} bytes")
            assert result.status_code == 200
        start = time.perf_counter()
        result = client.get("/api/v1/query/enforced_links")
        print(f"enforced_links: {time.perf_counter() - start:.3f}s, {len(result.content)} bytes")
        assert result.status_code == 200
        # Exercise collector parsing, persistence and detector evaluation too.
        start = time.perf_counter()
        result = client.post(
            "/ingest",
            files={
                "file": ("lab-estate.zip", collector_zip(estate), "application/zip"),
            },
            follow_redirects=False,
        )
        print(f"ingest: {time.perf_counter() - start:.3f}s")
        assert result.status_code == 303
    import io
    from contextlib import redirect_stdout

    from gpo_lens.cli import main

    for command in ("danger", "doctor"):
        with redirect_stdout(io.StringIO()):
            start = time.perf_counter()
            status = main(["--db", str(path), command])
            elapsed = time.perf_counter() - start
        print(f"CLI {command}: {elapsed:.3f}s")
        assert status == 0
