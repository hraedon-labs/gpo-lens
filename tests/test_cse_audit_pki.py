"""Synthetic F1 contracts: audit/PKI truth, reconciliation, and existing surfaces."""

from __future__ import annotations

import json
import shutil
import sqlite3
import zipfile
from contextlib import closing
from dataclasses import asdict
from pathlib import Path

import pytest

from gpo_lens import queries, store
from gpo_lens.danger import danger_findings
from gpo_lens.ingest import load_baseline_from_zip, load_estate, parse_report_xml
from gpo_lens.model import Estate, Som, SomLink
from gpo_lens.snapshot_diff import snapshot_settings_diff
from gpo_lens.topology import settings_at_som

FIXTURE = Path(__file__).parent / "fixtures/cse_audit_pki"
GUID = "0cce923f69ae11d9bed3505054503030"
GPO_ID = "a" * 32
AUDIT_CSE = "Advanced Audit Configuration"


def report(**replacements: str) -> bytes:
    text = (FIXTURE / "report.xml").read_text()
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text.encode()


def estate(data: bytes | None = None) -> Estate:
    return Estate(domain="lab.example.com", gpos=parse_report_xml(data or report()))


def audit(e: Estate):
    return [s for s in e.gpos[0].settings if s.cse == AUDIT_CSE]


@pytest.mark.parametrize(
    "number,label", [(0, "No Auditing"), (1, "Success"), (2, "Failure"), (3, "Success and Failure")]
)
def test_audit_guid_and_values(number, label):
    e = estate(report(**{"<a:SettingValue>3": f"<a:SettingValue>{number}"}))
    (s,) = audit(e)
    assert (s.identity, s.display_name, s.display_value, s.side) == (
        GUID,
        "Audit Credential Validation",
        label,
        "Computer",
    )
    assert s.raw["cse_parser"] == "advanced_audit"
    assert s.raw["children"][-1]["text"] == str(number)
    renamed = estate(
        report(
            **{
                "Audit Credential Validation": "Localized audit label",
                "{0CCE923F-69AE-11D9-BED3-505054503030}": GUID,
            }
        )
    )
    assert audit(renamed)[0].identity == GUID


def test_pki_golden_scalar_rows_and_certificate_identity():
    e = estate()
    rows = [
        (s.identity, s.display_name, s.display_value)
        for s in e.gpos[0].settings
        if s.cse == "Public Key"
    ]
    assert [list(r) for r in rows] == json.loads((FIXTURE / "pki_golden.json").read_text())
    assert all(
        s.raw["cse_parser"] == "public_key" for s in e.gpos[0].settings if s.cse == "Public Key"
    )
    changed = estate(
        report(**{"<p:KeyLen>2048": "<p:KeyLen>4096", "Lab Root CA": "Renamed Lab CA"})
    )
    assert [s.identity for s in changed.gpos[0].settings] == [
        s.identity for s in e.gpos[0].settings
    ]


def test_disabled_computer_and_legacy_note():
    e = estate(report(**{"<Computer><Enabled>true": "<Computer><Enabled>false"}))
    assert all(s.from_disabled_side for s in e.gpos[0].settings if s.side == "Computer")
    (legacy,) = [s for s in e.gpos[0].settings if s.cse == "Internet Explorer Maintenance"]
    assert legacy.source_state == "legacy_deprecated"
    assert "deprecated" in legacy.raw["source_note"]
    rows = queries.settings_ledger(e, GPO_ID)
    assert "deprecated" in next(r for r in rows if r.cse == legacy.cse).source_note
    assert any(
        f.category == "legacy_extension" and f.severity == "info" for f in queries.estate_doctor(e)
    )


def collected(tmp_path, csv_bytes=None, xml=None):
    (tmp_path / "AllGPOs.xml").write_bytes(xml or report())
    path = (
        tmp_path
        / "SYSVOL-Policies"
        / "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
        / "MACHINE/Microsoft/Windows NT/Audit"
    )
    path.mkdir(parents=True)
    if csv_bytes is not None:
        (path / "AUDIT.CSV").write_bytes(csv_bytes)
    return load_estate(tmp_path)


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16"])
def test_csv_agrees_without_duplicate_and_round_trips(tmp_path, encoding):
    data = (FIXTURE / "audit.csv").read_text().encode(encoding)
    e = collected(tmp_path, data)
    (s,) = audit(e)
    assert s.identity == GUID
    assert s.raw["audit_csv"]["Setting Value"] == "3"
    assert not [f for f in queries.estate_doctor(e) if f.category == "audit_source_disagreement"]
    with closing(sqlite3.connect(":memory:")) as conn, conn:
        store.init_db(conn)
        sid = store.save_estate(conn, e)
        assert sorted(
            (asdict(s) for s in store.load_estate(conn, sid).gpos[0].settings),
            key=lambda s: (s["side"], s["cse"], s["identity"]),
        ) == sorted(
            (asdict(s) for s in e.gpos[0].settings),
            key=lambda s: (s["side"], s["cse"], s["identity"]),
        )


def test_csv_disagreement_is_flagged_and_xml_kept(tmp_path):
    data = (FIXTURE / "audit.csv").read_bytes().replace(b",,3", b",,1")
    e = collected(tmp_path, data)
    (s,) = audit(e)
    assert s.display_value == "Success and Failure"
    assert s.raw["audit_csv"]["Setting Value"] == "1"
    findings = [f for f in queries.estate_doctor(e) if f.category == "audit_source_disagreement"]
    assert len(findings) == 1
    assert findings[0].dimensions == (("side", "Computer"), ("identity", GUID))
    assert "XML" in findings[0].detail and "CSV" in findings[0].detail
    assert (
        "disagree"
        in next(r for r in queries.settings_ledger(e, GPO_ID) if r.identity == GUID).source_note
    )


def test_csv_only_supplies_first_class_setting(tmp_path):
    xml = report().decode()
    start, end = (
        xml.index("<a:AuditSetting>"),
        xml.index("</a:AuditSetting>") + len("</a:AuditSetting>"),
    )
    e = collected(
        tmp_path, (FIXTURE / "audit.csv").read_bytes(), (xml[:start] + xml[end:]).encode()
    )
    (s,) = audit(e)
    assert (s.identity, s.display_value, s.source_state) == (
        GUID,
        "Success and Failure",
        "audit_csv",
    )
    assert not s.from_disabled_side


@pytest.mark.parametrize("replacement", ["9", "bad", ""])
def test_unknown_audit_value_is_never_no_auditing(replacement):
    e = estate(report(**{"<a:SettingValue>3": f"<a:SettingValue>{replacement}"}))
    (s,) = audit(e)
    assert "Unknown" in s.display_value
    assert s.source_state == "blocked"
    assert any(f.category == "audit_parse_warning" for f in queries.estate_doctor(e))


def test_per_user_audit_not_collapsed_into_system_identity():
    e = estate(report(**{"<a:PolicyTarget>System": "<a:PolicyTarget>S-1-5-21-100-200-300-400"}))
    (s,) = audit(e)
    assert s.identity == GUID + ":S-1-5-21-100-200-300-400"
    assert "Per-user" in s.raw["source_note"]


def force_report(
    value="1", key=r"MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy"
):
    security = (
        "<ExtensionData><Name>Security</Name><Extension><SecurityOptions>"
        f"<KeyName>{key}</KeyName><SettingNumber>{value}</SettingNumber>"
        "</SecurityOptions></Extension></ExtensionData>"
    )
    return report(**{"</Computer>": security + "</Computer>"})


@pytest.mark.parametrize("value,expected", [("1", 0), ("0", 1), ("", 1), ("2", 1)])
def test_force_option_detector_is_gpo_local(value, expected):
    e = estate(force_report(value))
    hits = [f for f in danger_findings(e) if f.check_id == "audit_subcategory_override"]
    assert len(hits) == expected
    if hits:
        assert "this GPO" in hits[0].detail and "effective" in hits[0].detail
        assert hits[0].reference.startswith("https://learn.microsoft.com/")


def test_force_missing_disabled_and_unrelated_path():
    assert any(f.check_id == "audit_subcategory_override" for f in danger_findings(estate()))
    disabled = estate(report(**{"<Computer><Enabled>true": "<Computer><Enabled>false"}))
    assert not any(f.check_id == "audit_subcategory_override" for f in danger_findings(disabled))
    unrelated = estate(force_report(key=r"MACHINE\Software\Lab\SCENoApplyLegacyAuditPolicy"))
    assert any(f.check_id == "audit_subcategory_override" for f in danger_findings(unrelated))


def test_audit_baseline_zip_golden_snapshot_and_search(tmp_path):
    before = estate()
    after = estate(
        report(
            **{
                "<a:SettingValue>3": "<a:SettingValue>1",
                "Audit Credential Validation": "Localized label",
            }
        )
    )
    zip_path = tmp_path / "baseline.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("GPOs/lab/gpreport.xml", report().decode().encode("utf-16"))
    baseline_estate = Estate(domain="lab.example.com", gpos=load_baseline_from_zip(zip_path))
    baseline = queries.load_baseline_from_estate(baseline_estate)
    diff = [d for d in queries.baseline_diff(after, baseline) if d.identity == GUID]
    assert len(diff) == 1 and diff[0].status == "drift"
    golden = [d for d in queries.golden_diff(after, before) if d.identity == GUID]
    assert len(golden) == 1 and golden[0].status == "changed"
    with closing(sqlite3.connect(":memory:")) as conn, conn:
        store.init_db(conn)
        a, b = store.save_estate(conn, before), store.save_estate(conn, after)
        changes = snapshot_settings_diff(conn, a, b)
        assert [(d.identity, d.change_type) for d in changes] == [(GUID, "modified")]
    assert queries.search(before, GUID, scope="settings")
    assert queries.search(before, "Credential Validation", scope="settings")
    assert queries.search(before, "EFS key length", scope="settings")


def test_audit_and_pki_ou_precedence():
    e = estate()
    other = estate(
        report(
            **{
                "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}": "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}",
                "<a:SettingValue>3": "<a:SettingValue>1",
                "<p:KeyLen>2048": "<p:KeyLen>4096",
            }
        )
    ).gpos[0]
    e.gpos.append(other)
    path = "OU=Lab,DC=lab,DC=example,DC=com"
    e.soms = [
        Som(
            path=path,
            name="Lab",
            container_type="ou",
            inheritance_blocked=False,
            links=[
                SomLink(gpo_id=GPO_ID, order=1, enabled=True, enforced=False, target=path),
                SomLink(gpo_id=other.id, order=2, enabled=True, enforced=False, target=path),
            ],
        )
    ]
    effective = settings_at_som(e, path)
    (row,) = [r for r in effective if r.identity == GUID]
    assert (row.winner_gpo_id, row.display_value) == (other.id, "Success")
    (row,) = [r for r in effective if r.identity == "EFSSettings:KeyLen"]
    assert (row.winner_gpo_id, row.display_value) == (other.id, "4096")


def test_old_database_opens_and_accepts_new_cses(tmp_path):
    path = tmp_path / "old.sqlite3"
    shutil.copyfile(Path(__file__).parent / "fixtures/released_databases/v1.2.0.sqlite3", path)
    with closing(sqlite3.connect(path)) as conn, conn:
        store.init_db(conn)
        assert store.load_estate(conn).gpos
        sid = store.save_estate(conn, estate())
        assert audit(store.load_estate(conn, sid))[0].identity == GUID
        store.init_db(conn)
        assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)


def test_invalid_guid_is_flagged_without_generic_fallback():
    e = estate(report(**{"{0CCE923F-69AE-11D9-BED3-505054503030}": "not-a-guid"}))
    (s,) = audit(e)
    assert s.source_state == "blocked"
    assert s.raw["cse_parser"] == "advanced_audit"
    assert any(f.category == "audit_parse_warning" for f in queries.estate_doctor(e))


@pytest.mark.parametrize(
    "data",
    [
        b"bad,headers\n1,2\n",
        b"\xff",
        (FIXTURE / "audit.csv").read_bytes().replace(b",,3", b",,bad"),
        (FIXTURE / "audit.csv").read_bytes().replace(b",,3", b",,3,extra"),
    ],
)
def test_bad_csv_is_visible(tmp_path, data):
    e = collected(tmp_path, data)
    assert audit(e)[0].display_value == "Success and Failure"
    assert any(
        f.category in {"audit_parse_warning", "audit_source_disagreement"}
        for f in queries.estate_doctor(e)
    )


def test_csv_disabled_side_and_unknown_options_are_not_active(tmp_path):
    xml = report(**{"<Computer><Enabled>true": "<Computer><Enabled>false"})
    csv = (FIXTURE / "audit.csv").read_bytes() + b"LAB-PC,,Option:CrashOnAuditFail,,Enabled,,1\n"
    e = collected(tmp_path, csv, xml)
    assert all(s.from_disabled_side for s in audit(e))
    assert any(s.source_state == "blocked" for s in audit(e))
    assert not any(f.check_id == "audit_subcategory_override" for f in danger_findings(e))


def test_csv_symlink_outside_copied_gpo_is_refused(tmp_path):
    e = collected(tmp_path)
    target = tmp_path / "outside.csv"
    target.write_bytes((FIXTURE / "audit.csv").read_bytes())
    base = Path(e.gpos[0].sysvol_path)
    (base / "MACHINE/Microsoft/Windows NT/Audit/AUDIT.CSV").symlink_to(target)
    from gpo_lens.ingest import augment_audit_from_csv

    augment_audit_from_csv(e.gpos)
    assert any(
        "outside" in f.detail
        for f in queries.estate_doctor(e)
        if f.category == "audit_parse_warning"
    )


def test_missing_csv_row_and_extra_csv_row_are_reconciled(tmp_path):
    csv = (FIXTURE / "audit.csv").read_bytes().replace(b"0CCE923F", b"0CCE9215")
    e = collected(tmp_path, csv)
    assert {s.identity for s in audit(e)} == {GUID, "0cce921569ae11d9bed3505054503030"}
    findings = [f for f in queries.estate_doctor(e) if f.category == "audit_source_disagreement"]
    assert len(findings) == 2
    assert {dict(f.dimensions)["identity"] for f in findings} == {s.identity for s in audit(e)}


def test_duplicate_csv_conflict_preserves_all_evidence(tmp_path):
    csv = (FIXTURE / "audit.csv").read_bytes()
    csv += csv.splitlines(keepends=True)[1].replace(b",,3", b",,1")
    e = collected(tmp_path, csv)
    (s,) = audit(e)
    assert [r["Setting Value"] for r in s.raw["audit_csv_rows"]] == ["3", "1"]
    assert s.display_value == "Success and Failure"
    assert (
        len([f for f in queries.estate_doctor(e) if f.category == "audit_source_disagreement"]) == 1
    )


def test_pki_unknown_certificate_is_not_dropped():
    e = estate(report(**{"<p:Thumbprint>AA BB CC DD</p:Thumbprint>": ""}))
    (cert,) = [
        s
        for s in e.gpos[0].settings
        if "Certificate" in s.identity and "Lab Root CA" in s.display_name
    ]
    assert cert.source_state == "blocked"
    assert "thumbprint" in cert.raw["source_note"]
    assert cert.raw["children"]


def test_pki_scalar_raw_keeps_parent_attributes():
    e = estate(report(**{"<p:EFSSettings>": '<p:EFSSettings version="lab-v1">'}))
    (s,) = [s for s in e.gpos[0].settings if s.identity == "EFSSettings:KeyLen"]
    assert s.raw["@attr"] == {"version": "lab-v1"}
    assert s.raw["property_path"] == "EFSSettings:KeyLen"


@pytest.mark.parametrize("hive", ["HKLM", "HKEY_LOCAL_MACHINE"])
def test_force_registry_form_is_recognized(hive):
    xml = (
        "<ExtensionData><Name>Registry</Name><Extension>"
        f"<RegistrySetting><KeyPath>{hive}\\System\\CurrentControlSet\\Control\\LSA</KeyPath>"
        "<Value><Name>SCENoApplyLegacyAuditPolicy</Name><Number>1</Number></Value>"
        "</RegistrySetting></Extension></ExtensionData>"
    )
    e = estate(report(**{"</Computer>": xml + "</Computer>"}))
    assert not any(f.check_id == "audit_subcategory_override" for f in danger_findings(e))


def test_other_gpo_force_and_user_setting_do_not_suppress_caveat():
    e = estate()
    other = estate(force_report()).gpos[0]
    other.id = "b" * 32
    other.settings = [s for s in other.settings if s.cse == "Security"]
    for s in other.settings:
        s.gpo_id = other.id
    e.gpos.append(other)
    assert [f.gpo_id for f in danger_findings(e) if f.check_id == "audit_subcategory_override"] == [
        GPO_ID
    ]
    e.gpos[0].settings.extend(other.settings)
    other.settings[0].side = "User"
    assert [f.gpo_id for f in danger_findings(e) if f.check_id == "audit_subcategory_override"] == [
        GPO_ID
    ]


def test_force_conflicting_duplicate_not_reported_as_enabled():
    e = estate(force_report())
    from copy import deepcopy

    other = deepcopy(next(s for s in e.gpos[0].settings if s.cse == "Security"))
    other.display_value = "0"
    e.gpos[0].settings.append(other)
    assert any(f.check_id == "audit_subcategory_override" for f in danger_findings(e))


def test_no_audit_does_not_create_override_finding():
    e = estate()
    e.gpos[0].settings = [s for s in e.gpos[0].settings if s.cse != AUDIT_CSE]
    assert not any(f.check_id == "audit_subcategory_override" for f in danger_findings(e))


def test_duplicate_xml_has_one_stable_identity_with_visible_conflict():
    text = report().decode()
    block = text[
        text.index("<a:AuditSetting>") : text.index("</a:AuditSetting>") + len("</a:AuditSetting>")
    ]
    text = text.replace(block, block + block.replace("<a:SettingValue>3", "<a:SettingValue>1"))
    e = estate(text.encode())
    (s,) = audit(e)
    assert s.identity == GUID and s.display_value == "Success and Failure"
    assert len(s.raw["duplicate_xml"]) == 1
    assert any(f.category == "audit_source_disagreement" for f in queries.estate_doctor(e))


@pytest.mark.parametrize("target", ["", "unexpected"])
def test_missing_or_unknown_policy_target_is_blocked(target):
    e = estate(report(**{"<a:PolicyTarget>System": f"<a:PolicyTarget>{target}"}))
    (s,) = audit(e)
    assert s.source_state == "blocked"
    assert "target" in s.raw["source_note"].lower()


@pytest.mark.parametrize("extension", ["", "<Blocked/>"])
def test_legacy_extension_empty_or_blocked_is_still_classified(extension):
    text = report().decode()
    start = text.index("<FavoriteURL>")
    end = text.index("</FavoriteURL>") + len("</FavoriteURL>")
    e = estate((text[:start] + extension + text[end:]).encode())
    (s,) = [s for s in e.gpos[0].settings if s.cse == "Internet Explorer Maintenance"]
    assert s.raw["cse_parser"] == "legacy_deprecated"
    assert "deprecated" in s.raw["source_note"]
    assert any(f.category == "legacy_extension" for f in queries.estate_doctor(e))
