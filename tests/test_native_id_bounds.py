"""Public record selectors handle IDs that SQLite cannot bind as integers."""

import csv
import io
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from gpo_lens.finding_model import EvidenceRef, FindingCandidate
from gpo_lens.findings import create_evaluation_run, finding_history, run_evaluation
from gpo_lens.ingest import load_estate as ingest_estate
from gpo_lens.store import init_db, load_estate, save_estate

_MAX = 2**63 - 1
_MIN = -(2**63)


@pytest.fixture
def records(tmp_path):
    path = tmp_path / "records.sqlite3"
    estate = ingest_estate(Path(__file__).parent / "fixtures")
    gpo = estate.gpos[0]
    with closing(sqlite3.connect(path)) as conn:
        init_db(conn)
        snapshot_id = save_estate(conn, estate)
        run = create_evaluation_run(conn, snapshot_id)
        run_evaluation(
            conn,
            run,
            [
                FindingCandidate(
                    detector_id="synthetic",
                    detector_version="1",
                    category="synthetic",
                    severity="high",
                    subject_type="gpo",
                    subject_key=(gpo.id,),
                    summary="Synthetic finding",
                    evidence_refs=(EvidenceRef(snapshot_id, gpo.id, "test", "field", "safe"),),
                    gpo_name=gpo.name,
                )
            ],
        )
        yield conn, path, gpo.id


@pytest.mark.parametrize("identifier", [_MIN, _MAX, _MIN - 1, _MAX + 1, -(10**100), 10**100])
@pytest.mark.parametrize("query", [load_estate, finding_history])
def test_missing_ids_use_the_existing_value_error_contract(records, query, identifier):
    conn, _, _ = records
    with pytest.raises(ValueError, match="not found"):
        query(conn, identifier)


def test_oversized_snapshot_id_never_aliases_a_real_maximum_id(records):
    conn, _, _ = records
    conn.execute(
        "INSERT INTO snapshot (id, domain, taken_at) VALUES (?, 'maximum.example.test', ?)",
        (_MAX, "2030-01-01T00:00:00+00:00"),
    )
    conn.commit()
    assert load_estate(conn, _MAX).domain == "maximum.example.test"
    with pytest.raises(ValueError, match="not found"):
        load_estate(conn, _MAX + 1)
    assert load_estate(conn, 1).gpos


@pytest.fixture
def client(records, monkeypatch):
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    _, path, _ = records
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "synthetic-native-id-token")
    with TestClient(
        create_app(str(path)),
        headers={"Authorization": "Bearer synthetic-native-id-token"},
        raise_server_exceptions=False,
    ) as app_client:
        yield app_client


@pytest.mark.parametrize("identifier", [_MAX, _MAX + 1, _MIN - 1])
@pytest.mark.parametrize("format", ["", "csv", "md"])
@pytest.mark.parametrize("view", ["finding", "gpo"])
def test_missing_record_views_return_404_for_oversized_ids(
    records, client, identifier, format, view
):
    _, _, gpo = records
    if view == "finding":
        response = client.get(f"/findings/{identifier}", params={"format": format})
    else:
        response = client.get(f"/gpo/{gpo}", params={"snapshot": identifier, "format": format})
    assert response.status_code == 404
    assert "not found" in response.text.lower()


@pytest.mark.parametrize("side", ["snap_a", "snap_b"])
@pytest.mark.parametrize(
    "value",
    [
        pytest.param(str(_MAX + 1), id="outside-sqlite-range"),
        pytest.param("9" * 5000, id="outside-python-digit-limit"),
        pytest.param("²", id="isdigit-but-not-integer"),
    ],
)
def test_changelog_ignores_unusable_numeric_selectors_like_other_invalid_text(client, side, value):
    params = {"snap_a": "1", "snap_b": "1", side: value}
    response = client.get("/changelog", params=params)
    assert response.status_code == 200
    assert "<h1>Changelog</h1>" in response.text


@pytest.mark.parametrize("format", ["csv", "md"])
def test_changelog_exports_ignore_unrepresentable_numeric_selector(client, format):
    response = client.get(
        "/changelog", params={"snap_a": str(_MAX + 1), "snap_b": "1", "format": format}
    )
    assert response.status_code == 200
    if format == "csv":
        rows = csv.DictReader(io.StringIO(response.text))
        metadata = {row["field"]: row["value"] for row in rows if row["section"] == "metadata"}
        assert json.loads(metadata["filters"]) == {"snap_a": None, "snap_b": 1}
        assert json.loads(metadata["snapshot_ids"]) == [1]
    else:
        assert "Snapshot diff" in response.text


@pytest.mark.parametrize("identifier", [_MAX + 1, _MIN - 1])
def test_triage_post_returns_404_for_oversized_finding_id(client, identifier):
    response = client.post(
        f"/findings/{identifier}/triage",
        data={"status": "acknowledged", "note": ""},
        headers={"X-Requested-With": "XMLHttpRequest", "Origin": "http://testserver"},
    )
    assert response.status_code == 404
    assert "not found" in response.text.lower()


@pytest.mark.parametrize("identifier", [_MAX + 1, _MIN - 1, 10**100])
def test_snapshot_delete_post_returns_404_for_oversized_id(records, client, identifier):
    conn, _, _ = records
    before = conn.execute("SELECT COUNT(*) FROM snapshot").fetchone()[0]
    response = client.post(
        "/ingest/delete",
        data={"snapshot_id": str(identifier)},
        headers={"Origin": "http://testserver"},
    )
    assert response.status_code == 404
    assert "not found" in response.text.lower()
    assert conn.execute("SELECT COUNT(*) FROM snapshot").fetchone()[0] == before
