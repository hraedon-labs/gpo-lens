"""Cross-stream contracts for the 1.4 release candidate, using synthetic inputs."""

from __future__ import annotations

import csv
import io
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from performance_estate import LAB_SECRET, make_estate

from gpo_lens import queries, store
from gpo_lens.briefing import briefing_lines, build_briefing
from gpo_lens.finding_model import FindingCandidate
from gpo_lens.findings import (
    complete_evaluation_run,
    create_evaluation_run,
    evaluate_finding_lifecycle_v2,
    finding_inbox,
    run_evaluation,
)
from gpo_lens.safe_output import REDACTED
from gpo_lens.web.app import create_app

AUDIT_GUID = "0cce923f69ae11d9bed3505054503030"
NOW = datetime(2026, 10, 6, 12, tzinfo=UTC)


@pytest.fixture
def integrated_client(tmp_path, monkeypatch):
    estate = make_estate(gpos=12, soms=80, settings=12, links=8)
    path = tmp_path / "integrated.sqlite3"
    with closing(sqlite3.connect(path)) as conn:
        store.init_db(conn)
        sid = store.save_estate(conn, estate, taken_at=NOW - timedelta(days=10))
        evaluate_finding_lifecycle_v2(conn, sid, estate)
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "lab-integration-token")
    with TestClient(
        create_app(str(path)), headers={"Authorization": "Bearer lab-integration-token"}
    ) as client:
        yield client, path, estate


@pytest.mark.parametrize("format", ["md", "csv"])
def test_audit_pki_fast_exports_preserve_bytes_values_and_redaction(
    integrated_client, monkeypatch, format
):
    import gpo_lens.web.routes.export as transport

    client, _, estate = integrated_client
    gpo_id = estate.gpos[0].id
    urls = [
        f"/gpo/{gpo_id}?view=ledger&format={format}",
        f"/search?q={AUDIT_GUID}&format={format}",
        f"/search?q=EFS&format={format}",
        f"/findings?lifecycle=all&triage=all&per_page=all&format={format}",
    ]
    optimized = [client.get(url) for url in urls]
    for response in optimized:
        assert response.status_code == 200
        assert LAB_SECRET not in response.text
        assert response.content == client.get(response.request.url).content
    ledger = optimized[0].text
    assert AUDIT_GUID in ledger and "Success and Failure" in ledger
    assert "EFSSettings:KeyLen" in ledger and "2048" in ledger
    assert "AutoEnrollmentSettings:Enabled" in ledger
    assert REDACTED in ledger.replace(r"\[", "[").replace(r"\]", "]")
    assert AUDIT_GUID in optimized[1].text
    assert "2048" in optimized[2].text
    # Frozen line transport proves F3 chunking preserves F1's new rows too.
    monkeypatch.setattr(transport, "_export_chunks", lambda lines: lines)
    for url, response in zip(urls, optimized, strict=True):
        old = client.get(url)
        assert old.content == response.content
        assert old.headers["content-type"] == response.headers["content-type"]


def test_aggregated_admx_findings_export_once_per_gpo_and_excludes_audit_pki(integrated_client):
    client, path, estate = integrated_client
    doctor = queries.estate_doctor(estate)
    gaps = [f for f in doctor if f.category == "admx_gap"]
    assert len(gaps) == len(estate.gpos)
    for gap in gaps:
        assert "12 registry settings" in gap.summary
        assert len(gap.detail.splitlines()) == 12
        assert AUDIT_GUID not in gap.detail
        assert "EFSSettings" not in gap.detail and "AutoEnrollmentSettings" not in gap.detail
    # A GPO containing only F1 settings cannot need a registry template.
    for gpo in estate.gpos:
        gpo.settings = [
            s for s in gpo.settings if s.cse in {"Advanced Audit Configuration", "Public Key"}
        ]
    assert not queries.admx_gaps(estate)
    assert not [f for f in queries.estate_doctor(estate) if f.category == "admx_gap"]
    with closing(sqlite3.connect(path)) as conn:
        views = [
            v
            for v in finding_inbox(conn, lifecycle_state=None, triage_status=None)
            if v.category == "admx_gap"
        ]
        assert len(views) == 12
        assert all("12 registry settings" in v.summary for v in views)
    response = client.get("/findings?category=admx_gap&lifecycle=all&triage=all&format=csv")
    assert response.status_code == 200
    rows = list(csv.DictReader(io.StringIO(response.text)))
    categories = [r for r in rows if r["section"] == "findings" and r["field"] == "category"]
    assert len(categories) == 12
    assert {r["value"] for r in categories} == {"admx_gap"}
    assert LAB_SECRET not in response.text
    assert response.content == client.get(response.request.url).content


def test_stale_warning_coexists_with_observed_severity_order_and_history(tmp_path):
    estate = make_estate(gpos=1, soms=1, settings=2, links=1)
    gpo = estate.gpos[0]
    with closing(sqlite3.connect(tmp_path / "briefing.sqlite3")) as conn:
        store.init_db(conn)
        sid = store.save_estate(conn, estate, taken_at=NOW - timedelta(days=10))
        run = create_evaluation_run(conn, sid)
        candidates = [
            FindingCandidate(
                detector_id=f"danger:lab-{severity}",
                detector_version="1",
                category=f"danger:lab-{severity}",
                severity=severity,
                subject_type="gpo",
                subject_key=(gpo.id,),
                gpo_name=gpo.name,
                summary=f"Lab {severity} evidence",
            )
            for severity in ("low", "high", "critical")
        ]
        run_evaluation(conn, run, candidates)
        complete_evaluation_run(conn, run)
        # Mutable occurrence names/prose cannot leak into historical briefings.
        conn.execute("UPDATE finding SET gpo_name='Later lab name', summary='Later prose'")
        conn.commit()
        briefing = build_briefing(conn, now=NOW)
        assert briefing is not None and briefing.freshness.is_stale
        assert any("Collection may have stopped" in p for p in briefing.problems)
        dangers = [p for p in briefing.problems if p.startswith(("critical:", "high:"))]
        assert dangers == [
            f"critical: Lab critical evidence ({gpo.name})",
            f"high: Lab high evidence ({gpo.name})",
        ]
        lines = briefing_lines(briefing)
        counts = next(i for i, line in enumerate(lines) if "active finding" in line)
        assert all(lines.index(danger) < counts for danger in dangers)
        assert "Later lab name" not in "\n".join(lines)
