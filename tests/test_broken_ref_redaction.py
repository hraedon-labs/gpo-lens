"""v1.3.1: GPP diagnostic locators are descriptive text, not raw XML."""

from __future__ import annotations

import html
import json
import re
import sqlite3
import xml.etree.ElementTree as ET
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from gpo_lens.cli import main
from gpo_lens.dependencies import external_dependencies
from gpo_lens.detection import broken_refs
from gpo_lens.findings import evaluate_finding_lifecycle_v2
from gpo_lens.ingest import load_estate
from gpo_lens.safe_output import REDACTED, safe_data, secret_values
from gpo_lens.store import init_db, save_estate
from gpo_lens.web.app import create_app

GID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DETAILS = (
    "GPP User/Preferences/Drives/Drives.xml <Drive/Properties @path>: path reference",
    "GPP User/Preferences/Printers/Printers.xml <SharedPrinter/Properties @path>: path reference",
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
    assert broken_refs(estate) == []
    refs = [r for group in external_dependencies(estate) for r in group.dependencies]
    assert len(refs) == 2
    assert {r.detail for r in refs} == set(DETAILS)
    assert {r.dependency_type for r in refs} == {"drive_mapping", "printer_connection"}
    db = tmp_path / "lab.sqlite3"
    with closing(sqlite3.connect(db)) as conn, conn:
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


@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize("command", ["broken-refs", "doctor", "dependencies"])
@pytest.mark.parametrize("input_mode", ["source", "database"])
def test_cli_preference_details(preference_estate, capsys, command, as_json, input_mode):
    source, db, credentials = preference_estate
    argv = ["--db", str(db)] + (["--json"] if as_json else []) + [command]
    if input_mode == "source":
        argv.append(str(source))
    assert main(argv) == 0
    output = capsys.readouterr().out
    assert_safe_output(output, credentials)
    if command == "dependencies":
        if as_json:
            rows = [r for group in json.loads(output)["data"] for r in group["dependencies"]]
            assert set(DETAILS) <= {r["detail"] for r in rows}
        if credentials:
            assert REDACTED in output
    elif command == "broken-refs" and as_json:
        assert json.loads(output)["data"] == []
    if not credentials:
        assert REDACTED not in output


@pytest.mark.parametrize(
    "route",
    [
        "/api/v1/query/broken_refs",
        "/dependencies",
        "/dependencies?format=md",
        "/dependencies?format=csv",
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
            assert detail not in html.unescape(response.text)
    if "broken_refs" in route:
        assert response.json()["data"] == []
    if route.startswith("/dependencies") and credentials:
        assert REDACTED in response.text.replace(r"\[", "[").replace(r"\]", "]")


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
            assert detail not in html.unescape(output)


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
    from gpo_lens.cli._export import EXPORT_VIEWS
    from gpo_lens.events import append_event
    from gpo_lens.model import ResolvedPrincipal
    from gpo_lens.store import load_estate as load_snapshot

    source, db, _ = build_preference_estate(tmp_path, False)
    sid = "s-1-5-21-100-200-300-1001"
    with closing(sqlite3.connect(db)) as conn, conn:
        estate = load_snapshot(conn)
        estate.principals[sid] = ResolvedPrincipal(
            sid, "LABDOMAIN\\reader", "reader", "User", "LABDOMAIN", True
        )
        save_estate(conn, estate)
        append_event(conn, "lab.read_guard", {"description": "Ordinary lab evidence", "count": 7})
        occurrence = conn.execute("SELECT id FROM finding ORDER BY id LIMIT 1").fetchone()[0]
    assert secret_values(estate) == ()
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
    events_file = tmp_path / "events.ndjson"
    commands["events-export"] = ["events-export", "--ndjson", str(events_file)]
    exports = {
        "dossier": ["--gpo-id", GID],
        "ledger": ["--gpo-id", GID],
        "findings": ["--lifecycle", "all", "--triage", "all"],
        "occurrence": ["--occurrence-id", str(occurrence)],
        "accepted-risks": [],
        "briefing": [],
        "setting": ["--identity", "Lab"],
        "diff": ["--snapshot-a", "1", "--snapshot-b", "2"],
        "diff-settings": ["--snapshot-a", "1", "--snapshot-b", "2"],
        "changelog": ["--snapshot-a", "1", "--snapshot-b", "2"],
        "baseline-diff": ["--comparator", str(source)],
        "golden-diff": ["--comparator", str(source)],
        "settings-dump": [],
        "settings-diff": ["--file-a", str(dump), "--file-b", str(dump)],
        "who-sets": ["--q", "Lab"],
    }
    assert set(exports) == set(EXPORT_VIEWS)
    for view, extra in exports.items():
        for format in ("md", "csv"):
            commands[f"export:{view}:{format}"] = [
                "export",
                view,
                "--format",
                format,
                "--as-of",
                "2026-10-06T12:00:00Z",
                *extra,
            ]
    # Every read command is covered, including every export view. Only actions
    # that import data, start a server or open an interactive REPL are outside
    # the inventory. Omitted raw fields must stay identical in both passes.
    assert {argv[0] for argv in commands.values()} == {
        c.name for c in _COMMANDS if c.name not in {"ingest", "serve", "repl"}
    }

    def stable(text):
        # CLI envelopes/report prose carry informational generation clocks.
        return re.sub(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|\+00:00)", "<clock>", text)

    def run(argv):
        if argv[0] == "events-export":
            # NDJSON sinks append by contract; compare independent artifacts.
            events_file.unlink(missing_ok=True)
        json_args = ["--json"] if as_json and argv[0] not in {"report", "export"} else []
        status = main(["--db", str(db), *json_args, *argv])
        captured = capsys.readouterr()
        assert status == 0, (argv, captured.err)
        artifact = events_file.read_text() if argv[0] == "events-export" else ""
        return stable(captured.out), stable(captured.err), artifact

    failures = []
    for name, argv in commands.items():
        projected = run(argv)
        if not name.startswith("export:") and any(REDACTED in part for part in projected):
            failures.append(name)
        from gpo_lens import safe_output

        with monkeypatch.context() as control:
            control.setattr(safe_output, "secret_values", lambda _: ())
            control.setattr(safe_output, "_credential_material", lambda _: False)
            control.setattr(safe_output, "_sensitive", lambda _: False)
            control.setattr(safe_output, "_mask_text", lambda value, _: value)
            assert projected == run(argv), name
    assert not failures, failures
