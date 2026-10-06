"""Final release regressions; all estates and credentials are synthetic."""

import json
import re
from pathlib import Path
from urllib.parse import quote, quote_plus

import pytest

from gpo_lens.danger import DangerRule, evaluate_danger_rules
from gpo_lens.ingest import parse_report_xml
from gpo_lens.model import Estate
from gpo_lens.safe_output import REDACTED, safe_data, safe_text

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("side", ["Computer", "User"])
@pytest.mark.parametrize("predicate", ["present", "absent"])
def test_danger_disabled_setting_cannot_match_or_suppress_absence(side, predicate):
    gpo = parse_report_xml((ROOT / "tests/fixtures/cse_audit_pki/report.xml").read_bytes())[0]
    setting = gpo.settings[0]
    setting.side = side
    setting.cse = "Registry"
    setting.identity = r"HKLM\Software\Synthetic:Unsafe"
    setting.display_value = "1"
    setting.from_disabled_side = True
    gpo.settings = [setting]
    rule = DangerRule(
        id="synthetic_rule",
        title="Synthetic rule",
        severity="high",
        applies="Machine" if side == "Computer" else "User",
        identity=setting.identity,
        predicate=predicate,
        value="",
        reference="https://example.invalid/rule",
    )
    estate = Estate(domain="lab.example.com", gpos=[gpo])
    assert [f.check_id for f in evaluate_danger_rules(estate, [rule])] == (
        [rule.id] if predicate == "absent" else []
    )
    # The same authored setting does participate when its side is active.
    setting.from_disabled_side = False
    assert [f.check_id for f in evaluate_danger_rules(estate, [rule])] == (
        [] if predicate == "absent" else [rule.id]
    )


def _unicode_escape(secret, upper=False):
    encoded = secret.encode("utf-16-be")
    return "".join(
        "\\u" + format(int.from_bytes(encoded[i : i + 2], "big"), "04X" if upper else "04x")
        for i in range(0, len(encoded), 2)
    )


@pytest.mark.parametrize("secret", ["a@", 'a"', "a b", "long secret", "0", "aé", "a😀"])
@pytest.mark.parametrize(
    "encoding", ["percent_upper", "percent_lower", "plus", "json", "unicode", "unicode_upper"]
)
def test_discovered_secret_encoded_copies_are_masked(secret, encoding):
    percent = quote(secret, safe="")
    encoded = {
        "percent_upper": percent,
        "percent_lower": re.sub(r"%[0-9A-F]{2}", lambda m: m[0].lower(), percent),
        "plus": quote_plus(secret, safe=""),
        "json": json.dumps(secret)[1:-1],
        "unicode": _unicode_escape(secret),
        "unicode_upper": _unicode_escape(secret, upper=True),
    }[encoding]
    projected = safe_data({"password": secret, "copy": "copy=" + encoded})
    assert projected == {"password": REDACTED, "copy": "copy=" + REDACTED}
    assert safe_text("copy=" + encoded, secrets=[secret]) == "copy=" + REDACTED
    if len(secret) < 6 or secret.isnumeric():
        # Every encoded spelling inherits the original secret's token boundary.
        identifier = "id-" + encoded + "-end"
        assert safe_text(identifier, secrets=[secret]) == identifier


@pytest.mark.parametrize("document", ["CHANGELOG.md", "docs/handover.md"])
def test_upgrade_notes_require_backup_and_explain_schema10_rollback(document):
    text = (ROOT / document).read_text()
    if document == "CHANGELOG.md":
        assert "No schema migration is needed" not in text.split("## v1.3.1", 1)[0]
    section = (
        text.split("### Upgrade notes", 1)[1].split("## v1.3.1", 1)[0]
        if document == "CHANGELOG.md"
        else text.split("## 6. Upgrading", 1)[1].split("## 7.", 1)[0]
    )
    section = " ".join(section.split())
    assert "schema 10" in section
    assert "required" in section and "before upgrading" in section
    assert "database" in section and "audit.log" in section
    assert "v1.3.1 and earlier cannot open" in section
    assert "restore the pre-upgrade backup" in section
    assert "No new schema migration" not in section
