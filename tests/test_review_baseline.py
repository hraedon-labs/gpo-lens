"""Comparison must retain side and conflicting values."""

import csv
import io
import json
import re
import sqlite3
from contextlib import closing
from copy import deepcopy
from pathlib import Path

import pytest

from gpo_lens.ingest import parse_report_xml
from gpo_lens.model import Estate
from gpo_lens.queries import baseline_diff, golden_diff, load_baseline_from_estate


def estate():
    result = Estate(
        domain="lab.example.com",
        gpos=parse_report_xml(
            (Path(__file__).parent / "fixtures/cse_audit_pki/report.xml").read_bytes()
        ),
    )
    result.gpos[0].settings = [result.gpos[0].settings[0]]
    return result


def test_baseline_wrong_side_is_missing_and_extra():
    baseline = estate()
    live = deepcopy(baseline)
    live.gpos[0].settings[0].side = "User"
    rows = baseline_diff(live, load_baseline_from_estate(baseline))
    assert {(r.status, r.side) for r in rows} == {("missing", "Computer"), ("extra", "User")}


@pytest.mark.parametrize("reverse", [False, True])
def test_baseline_mixed_values_show_every_source_as_drift(reverse):
    baseline = estate()
    live = deepcopy(baseline)
    other = deepcopy(live.gpos[0])
    other.id = "b" * 32
    other.settings[0].gpo_id = other.id
    other.settings[0].display_value = "Failure"
    live.gpos.append(other)
    if reverse:
        live.gpos.reverse()
    rows = baseline_diff(live, load_baseline_from_estate(baseline))
    assert rows and all(r.status == "drift" for r in rows)
    assert {(r.gpo_id, r.actual_value) for r in rows} == {
        ("a" * 32, "Success and Failure"),
        ("b" * 32, "Failure"),
    }


@pytest.mark.parametrize("conflicting_side", ["live", "golden"])
def test_golden_conflicting_duplicate_is_never_compliant(conflicting_side):
    golden = estate()
    live = deepcopy(golden)
    target = live if conflicting_side == "live" else golden
    duplicate = deepcopy(target.gpos[0].settings[0])
    duplicate.display_value = "Failure"
    target.gpos[0].settings.append(duplicate)
    (row,) = golden_diff(live, golden)
    assert row.status == "changed"
    assert "Failure" in (row.live_value if conflicting_side == "live" else row.golden_value)


@pytest.mark.parametrize("side", ["Computer", "User"])
@pytest.mark.parametrize("enabled_elsewhere", [False, True])
def test_baseline_disabled_side_cannot_supply_compliance(side, enabled_elsewhere):
    baseline = estate()
    baseline.gpos[0].settings[0].side = side
    live = deepcopy(baseline)
    setattr(live.gpos[0], f"{side.lower()}_enabled", False)
    live.gpos[0].settings[0].from_disabled_side = True
    if enabled_elsewhere:
        active = deepcopy(baseline.gpos[0])
        active.id = "b" * 32
        active.settings[0].gpo_id = active.id
        live.gpos.append(active)
    (row,) = baseline_diff(live, load_baseline_from_estate(baseline))
    assert row.status == ("compliant" if enabled_elsewhere else "missing")
    assert row.gpo_id == ("b" * 32 if enabled_elsewhere else "")
    assert load_baseline_from_estate(Estate(gpos=[live.gpos[0]])) == []


@pytest.mark.parametrize("side", ["Computer", "User"])
@pytest.mark.parametrize("disabled", ["live", "golden", "both"])
def test_golden_disabled_side_is_absent_in_both_directions(side, disabled):
    golden = estate()
    golden.gpos[0].settings[0].side = side
    live = deepcopy(golden)
    for name, target in [("live", live), ("golden", golden)]:
        if disabled in {name, "both"}:
            setattr(target.gpos[0], f"{side.lower()}_enabled", False)
            target.gpos[0].settings[0].from_disabled_side = True
    rows = golden_diff(live, golden)
    if disabled == "both":
        assert rows == []
    else:
        (row,) = rows
        assert row.status == ("removed" if disabled == "live" else "added")
        assert (row.live_value if disabled == "live" else row.golden_value) == ""


@pytest.mark.parametrize("side", ["Computer", "User"])
@pytest.mark.parametrize("format", ["html", "md", "csv", "json"])
@pytest.mark.parametrize(
    "case",
    ["baseline_disabled", "baseline_enabled", "golden_live", "golden_reference", "golden_both"],
)
def test_disabled_comparison_contract_across_outputs(
    tmp_path, monkeypatch, capsys, side, format, case
):
    from fastapi.testclient import TestClient

    from gpo_lens import ingest, store
    from gpo_lens.cli import main
    from gpo_lens.web.app import create_app

    reference = estate()
    reference.gpos[0].settings[0].side = side
    live = deepcopy(reference)
    if case != "golden_reference":
        setattr(live.gpos[0], f"{side.lower()}_enabled", False)
        live.gpos[0].settings[0].from_disabled_side = True
    if case in {"golden_reference", "golden_both"}:
        setattr(reference.gpos[0], f"{side.lower()}_enabled", False)
        reference.gpos[0].settings[0].from_disabled_side = True
    if case == "baseline_enabled":
        active = deepcopy(reference.gpos[0])
        active.id = "b" * 32
        active.settings[0].gpo_id = active.id
        live.gpos.append(active)
    baseline = case.startswith("baseline")
    expected = {
        "baseline_disabled": ["missing"],
        "baseline_enabled": ["compliant"],
        "golden_live": ["removed"],
        "golden_reference": ["added"],
        "golden_both": [],
    }[case]
    db = tmp_path / "live.db"
    with closing(sqlite3.connect(db)) as conn:
        store.init_db(conn)
        store.save_estate(conn, live)
    monkeypatch.setattr(ingest, "load_baseline_from_zip", lambda path: reference.gpos)
    if format == "json":
        command = "baseline-diff" if baseline else "golden-diff"
        assert main(["--db", str(db), "--json", command, "synthetic.zip"]) == 0
        data = json.loads(capsys.readouterr().out)["data"]
        rows = data if baseline else data["entries"]
        assert [row["status"] for row in rows] == expected
        if case == "baseline_enabled":
            assert rows[0]["gpo_id"] == "b" * 32
        return
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "lab-test-token")
    with TestClient(
        create_app(str(db)),
        base_url="http://localhost",
        headers={"Authorization": "Bearer lab-test-token", "Origin": "http://localhost"},
    ) as client:
        response = client.post(
            "/baseline" if baseline else "/golden-diff",
            files={"file": ("synthetic.zip", b"test")},
            data={"format": "" if format == "html" else format},
        )
    assert response.status_code == 200
    if format == "csv":
        statuses = [
            row["value"]
            for row in csv.DictReader(io.StringIO(response.text))
            if row["section"] == "comparison" and row["field"] == "status"
        ]
    elif format == "md":
        statuses = re.findall(r"\| comparison \| \d+ \| status \| (\w+) \|", response.text)
    elif baseline:
        statuses = re.findall(r'<span class="gp-chip \w+">(\w+)</span>', response.text)
    else:
        # Group headings use uppercase chips; inspect only setting row chips.
        statuses = re.findall(r'<span class="gp-chip \w+">([a-z_]+)</span>', response.text)
    assert statuses == expected
