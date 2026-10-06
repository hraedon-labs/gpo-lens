"""Template class matching and per-GPO gap continuity."""

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from gpo_lens import queries, store
from gpo_lens.admx_parser import AdmxPolicy, PolicyDefinitions
from gpo_lens.findings import append_triage_event, evaluate_finding_lifecycle_v2, finding_inbox
from gpo_lens.ingest import parse_report_xml
from gpo_lens.model import Estate, Setting
from gpo_lens.web._helpers import setting_label


def definitions(scope):
    return PolicyDefinitions(
        policies=[AdmxPolicy("Lab", scope, r"SYSTEM\Lab", "Value", "", "Lab policy", "")]
    )


def estate(side="Computer"):
    g = parse_report_xml(
        (Path(__file__).parent / "fixtures/cse_audit_pki/report.xml").read_bytes()
    )[0]
    g.settings = [Setting(g.id, side, "Registry", r"SYSTEM\Lab:Value", "Value", "1", {}, False)]
    return Estate(gpos=[g])


@pytest.mark.parametrize(
    "side,scope,covered",
    [
        ("Computer", "Machine", True),
        ("Computer", "Both", True),
        ("Computer", "User", False),
        ("User", "User", True),
        ("User", "Both", True),
        ("User", "Machine", False),
    ],
)
def test_admx_side_is_used_by_every_setting_surface(side, scope, covered):
    pd = definitions(scope)
    e = estate(side)
    (s,) = e.gpos[0].settings
    expected = "Lab policy" if covered else None
    assert pd.resolve_display_name(s.identity, side=side) == expected
    assert len(queries.admx_gaps(e, pd)) == (0 if covered else 1)
    assert sum(f.category == "admx_gap" for f in queries.estate_doctor(e, admx=pd)) == (
        0 if covered else 1
    )
    assert queries.baseline_diff(e, queries.load_baseline_from_estate(e), pd)[0].admx_name == (
        expected or ""
    )
    assert queries.golden_diff(e, e, pd)[0].admx_name == (expected or "")
    coverage = queries.admx_coverage(e, pd)
    assert coverage.summary.referenced_policies == (1 if covered else 0)
    assert setting_label(s, pd)[0] == (expected or s.display_name)
    assert queries.settings_ledger(e, e.gpos[0].id, admx=pd)[0].admx_name == (expected or "")


def test_admx_side_membership_keeps_existing_aggregate_triage(tmp_path):
    pd = definitions("User")
    e = estate()
    original = e.gpos[0].settings[0]
    original.identity = r"SYSTEM\Lab:Missing"
    with closing(sqlite3.connect(tmp_path / "history.db")) as conn:
        store.init_db(conn)
        sid = store.save_estate(conn, e)
        evaluate_finding_lifecycle_v2(conn, sid, e, admx=pd)
        row = next(r for r in finding_inbox(conn) if r.category == "admx_gap")
        append_triage_event(
            conn, row.occurrence_id, "accepted_risk", "lab-reviewer", rationale="Lab control"
        )
        e.gpos[0].settings.extend(estate().gpos[0].settings)
        sid = store.save_estate(conn, e)
        evaluate_finding_lifecycle_v2(conn, sid, e, admx=pd)
        later = next(r for r in finding_inbox(conn) if r.category == "admx_gap")
        assert later.occurrence_id == row.occurrence_id
        assert later.triage_status == "accepted_risk"
        detail = conn.execute(
            "SELECT detail FROM finding WHERE id=?", (row.occurrence_id,)
        ).fetchone()[0]
        assert "SYSTEM\\Lab:Value" in detail
        assert conn.execute(
            "SELECT count(*) FROM finding_observation WHERE occurrence_id=?", (row.occurrence_id,)
        ).fetchone() == (2,)
