"""v1.3.1: GPP diagnostic locators are descriptive text, not raw XML."""

from __future__ import annotations

import html
import json
import sqlite3
import xml.etree.ElementTree as ET

import pytest
from fastapi.testclient import TestClient

from gpo_lens.cli import main
from gpo_lens.detection import broken_refs
from gpo_lens.findings import evaluate_finding_lifecycle_v2
from gpo_lens.ingest import load_estate
from gpo_lens.safe_output import REDACTED, safe_data, secret_values
from gpo_lens.store import init_db, save_estate
from gpo_lens.web.app import create_app

GID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DETAILS = (
    "GPP User/Preferences/Drives/Drives.xml <Drive/Properties @path>: UNC path",
    "GPP User/Preferences/Printers/Printers.xml <SharedPrinter/Properties @path>: UNC path",
)
SECRETS = (
    "SYNTH-HOTFIX-CPASSWORD-ONLY",
    "SYNTH-HOTFIX-UNC-PASSWORD-ONLY",
    "SYNTH-HOTFIX-URI-PASSWORD-ONLY",
)


def build_preference_estate(tmp_path, credentials):
    source = tmp_path / "lab-estate"
    source.mkdir()
    report = ET.fromstring(
        """<AllGPOs><GPO>
        <Identifier><Identifier>{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}</Identifier>
        <Domain>lab.example.com</Domain></Identifier><Name>Lab preferences</Name>
        <Computer><Enabled>true</Enabled></Computer>
        <User><Enabled>true</Enabled></User>
        </GPO></AllGPOs>"""
    )
    for cse, tag, share in (("Drives", "Drive", "share"), ("Printers", "SharedPrinter", "printer")):
        root = ET.Element(cse)
        properties = {"path": rf"\\files.lab.example.com\{share}", "userName": "LABDOMAIN\\reader"}
        if credentials:
            properties.update(
                path=rf"\\lab-user:{SECRETS[1]}@files.lab.example.com\{share}",
                cpassword=SECRETS[0],
                userName=f"https://lab-user:{SECRETS[2]}@files.lab.example.com/identity",
            )
        ET.SubElement(ET.SubElement(root, tag, name="Lab preference"), "Properties", properties)
        directory = source / "SYSVOL-Policies" / "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
        directory = directory / "User" / "Preferences" / cse
        directory.mkdir(parents=True)
        ET.ElementTree(root).write(directory / f"{cse}.xml", encoding="utf-8")
        # The collector report carries the same preference subtree as SYSVOL.
        extension_data = ET.SubElement(report.find("GPO/User"), "ExtensionData")
        ET.SubElement(extension_data, "Name").text = cse
        ET.SubElement(extension_data, "Extension").append(root)
    ET.ElementTree(report).write(source / "AllGPOs.xml", encoding="utf-8")
    estate = load_estate(source)
    assert bool(secret_values(estate)) == credentials
    refs = broken_refs(estate)
    assert len(refs) == 2
    assert {r.detail for r in refs} == set(DETAILS)
    assert {r.ref_type for r in refs} == {"drive_mapping_unc"}
    db = tmp_path / "lab.sqlite3"
    with sqlite3.connect(db) as conn:
        init_db(conn)
        snapshot = save_estate(conn, estate)
        evaluate_finding_lifecycle_v2(conn, snapshot, estate)
    conn.close()
    return source, db, credentials


@pytest.fixture(params=[False, True], ids=["ordinary", "credentials"])
def preference_estate(tmp_path, request):
    return build_preference_estate(tmp_path, request.param)


def assert_safe_output(output, credentials):
    decoded = html.unescape(output).replace(r"\[", "[").replace(r"\]", "]")
    for secret in SECRETS:
        assert secret not in decoded
    if credentials:
        assert REDACTED in decoded


@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize("command", ["broken-refs", "doctor"])
@pytest.mark.parametrize("input_mode", ["source", "database"])
def test_cli_preference_details(preference_estate, capsys, command, as_json, input_mode):
    source, db, credentials = preference_estate
    argv = ["--db", str(db)] + (["--json"] if as_json else []) + [command]
    if input_mode == "source":
        argv.append(str(source))
    assert main(argv) == 0
    output = capsys.readouterr().out
    assert_safe_output(output, credentials)
    if as_json:
        rows = json.loads(output)["data"]
        if command == "doctor":
            rows = rows["findings"]
        field = "detail" if command == "broken-refs" else "summary"
        assert set(DETAILS) <= {r[field] for r in rows}
    else:
        for detail in DETAILS:
            assert detail in output
    if not credentials:
        assert REDACTED not in output


@pytest.mark.parametrize(
    "route",
    [
        "/api/v1/query/broken_refs",
        "/api/v1/query/estate_doctor",
        "/gpo/" + GID,
        "/gpo/" + GID + "?view=ledger",
        "/findings?lifecycle=all&triage=all",
        "/export/findings?format=json",
        *[f"/export/gpo/{GID}?format={fmt}" for fmt in ("json", "md", "csv")],
        *[f"/export/findings?format={fmt}&lifecycle=all&triage=all" for fmt in ("md", "csv")],
    ],
)
def test_web_preference_redaction(preference_estate, monkeypatch, route):
    _, db, credentials = preference_estate
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "synthetic-hotfix-token")
    with TestClient(
        create_app(str(db)), headers={"Authorization": "Bearer synthetic-hotfix-token"}
    ) as client:
        response = client.get(route)
    assert response.status_code == 200
    assert_safe_output(response.text, credentials)
    if route.startswith(("/findings?", "/export/findings?")):
        for detail in DETAILS:
            assert detail in html.unescape(response.text)
    if "query/" in route or "export/findings?format=json" in route:
        rows = response.json()
        if "query/" in route:
            rows = rows["data"]
        field = "detail" if "broken_refs" in route else "summary"
        assert set(DETAILS) <= {r[field] for r in rows}


@pytest.mark.parametrize("format", ["md", "csv"])
@pytest.mark.parametrize("view", ["dossier", "ledger", "findings"])
def test_cli_preference_exports(preference_estate, capsys, view, format):
    _, db, credentials = preference_estate
    extra = ["--gpo-id", GID] if view in {"dossier", "ledger"} else ["--lifecycle", "all"]
    assert main(["--db", str(db), "export", view, "--format", format, *extra]) == 0
    output = capsys.readouterr().out
    assert_safe_output(output, credentials)
    if view == "findings":
        for detail in DETAILS:
            assert detail in html.unescape(output)


@pytest.mark.parametrize(
    "fragment",
    [
        '<Properties cpassword="SYNTH-HOTFIX-CPASSWORD-ONLY" />',
        '<Drive><Properties path="\\\\files.lab.example.com\\share" /></Drive>',
        '<gpp:Properties userName="lab-user"/>',
        '<svg/onload="lab-value">',
        DETAILS[0] + ' <Properties password="SYNTH-HOTFIX-CPASSWORD-ONLY"/>',
        "O:SYG:SYD:(A;;GA;;;SY)",
    ],
)
def test_raw_fragments_still_omitted(fragment):
    assert safe_data({"detail": fragment})["detail"] == REDACTED


@pytest.mark.parametrize("as_json", [False, True])
def test_no_secret_cli_read_commands_do_not_redact(tmp_path, capsys, monkeypatch, as_json):
    from gpo_lens.cli._core import _COMMANDS
    from gpo_lens.model import ResolvedPrincipal
    from gpo_lens.store import load_estate as load_snapshot

    source, db, _ = build_preference_estate(tmp_path, False)
    sid = "s-1-5-21-100-200-300-1001"
    with sqlite3.connect(db) as conn:
        estate = load_snapshot(conn)
        estate.principals[sid] = ResolvedPrincipal(
            sid, "LABDOMAIN\\reader", "reader", "User", "LABDOMAIN", True
        )
        save_estate(conn, estate)
    conn.close()
    dump = tmp_path / "settings.json"
    dump.write_text("[]", encoding="utf-8")
    monkeypatch.delenv("GPO_LENS_API_KEY", raising=False)
    # Exercise ask's read projection without a model call.
    monkeypatch.setattr(
        "gpo_lens.narration.route_question", lambda _: {"query": "broken_refs", "params": {}}
    )
    commands = {
        c.name: [c.name]
        for c in _COMMANDS
        if c.src_arg and not c.positional_args and c.name not in {"ingest", "repl"}
    }
    commands.update(
        {
            "who-sets": ["who-sets", "Lab"],
            "search": ["search", "Lab"],
            "show": ["show", GID],
            "scope": ["scope", GID],
            "som": ["som", "dc=lab,dc=example,dc=com"],
            "settings-at": ["settings-at", "dc=lab,dc=example,dc=com"],
            "som-conflicts": ["som-conflicts", "dc=lab,dc=example,dc=com"],
            "diff": ["diff", "1", "2"],
            "diff-settings": ["diff-settings", "1", "2"],
            "changelog": ["changelog", "1", "2"],
            "settings-diff": ["settings-diff", str(dump), str(dump)],
            "baseline-diff": ["baseline-diff", str(source)],
            "golden-diff": ["golden-diff", str(source)],
            "snapshots": ["snapshots"],
            "events": ["events"],
            "trends": ["trends"],
            "resultant": ["resultant", sid, "--dn", "cn=reader,dc=lab,dc=example,dc=com"],
            "ask": ["ask", "broken refs", "--no-narrate"],
            "explain-setting": ["explain-setting", "Lab"],
        }
    )
    # Exports intentionally mark omitted raw/audit fields even without secrets;
    # their credential behavior is covered by the export tests above.
    excluded = {"ingest", "events-export", "export", "serve", "repl"}
    assert set(commands) == {c.name for c in _COMMANDS} - excluded
    failures = []
    for name, argv in commands.items():
        json_args = ["--json"] if as_json and name != "report" else []
        status = main(["--db", str(db), *json_args, *argv])
        captured = capsys.readouterr()
        assert status == 0, (name, captured.err)
        if REDACTED in captured.out or REDACTED in captured.err:
            failures.append(name)
    assert not failures, failures
