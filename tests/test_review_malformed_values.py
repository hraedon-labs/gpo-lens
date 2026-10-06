"""Invalid typed source evidence is retained but never baseline-comparable."""

from pathlib import Path

import pytest

from gpo_lens.ingest import parse_report_xml
from gpo_lens.model import Estate
from gpo_lens.queries import load_baseline_from_estate

FIXTURE = Path(__file__).parent / "fixtures/cse_audit_pki/report.xml"


@pytest.mark.parametrize(
    "value", [None, "", "nonnumeric", "-1", "+1", "4294967296", "9" * 5000, "16"]
)
def test_invalid_per_user_audit_flags_are_blocked(value):
    text = FIXTURE.read_text().replace("<a:PolicyTarget>System", "<a:PolicyTarget>S-1-5-21-1-2-3-4")
    text = text.replace(
        "<a:SettingValue>3</a:SettingValue>",
        "" if value is None else f"<a:SettingValue>{value}</a:SettingValue>",
    )
    e = Estate(gpos=parse_report_xml(text.encode()))
    (row,) = [s for s in e.gpos[0].settings if s.cse == "Advanced Audit Configuration"]
    assert row.source_state == "blocked"
    assert "flags" in row.raw["source_note"].lower()
    assert not any(s.identity == row.identity for s in load_baseline_from_estate(e))


@pytest.mark.parametrize(
    "field,old", [("KeyLen", "2048"), ("Options", "2"), ("AllowEFS", "true"), ("Enabled", "true")]
)
@pytest.mark.parametrize("value", [None, "", "nonnumeric", "-1", "+1", "4294967296"])
def test_invalid_known_pki_scalar_is_blocked(field, old, value):
    text = FIXTURE.read_text().replace(
        f"<p:{field}>{old}</p:{field}>",
        f"<p:{field}/>" if value is None else f"<p:{field}>{value}</p:{field}>",
    )
    e = Estate(gpos=parse_report_xml(text.encode()))
    (row,) = [s for s in e.gpos[0].settings if s.identity.endswith(":" + field)]
    assert row.source_state == "blocked"
    assert "invalid" in row.raw["source_note"].lower()
    assert not any(s.identity == row.identity for s in load_baseline_from_estate(e))
