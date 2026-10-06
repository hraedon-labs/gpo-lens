"""Comparison must retain side and conflicting values."""

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
