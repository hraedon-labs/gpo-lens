"""Synthetic F2 calibration: offline certainty, inventory, and upgrade history."""

import json
import os
import sqlite3
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from gpo_lens import admx_parser, queries, store
from gpo_lens.briefing import build_briefing
from gpo_lens.cli import main
from gpo_lens.finding_model import FindingCandidate, compute_fingerprint
from gpo_lens.findings import (
    append_triage_event,
    candidates_from_estate,
    complete_evaluation_run,
    create_evaluation_run,
    evaluate_finding_lifecycle_v2,
    finding_history,
    finding_inbox,
    run_evaluation,
)
from gpo_lens.ingest import parse_report_xml
from gpo_lens.model import CoverageGap, Estate, Gpo, Setting
from gpo_lens.web.app import create_app

GID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def gpo(settings=(), sysvol=None, gid=GID):
    return Gpo(
        id=gid,
        name="Lab dependencies",
        domain="lab.example.com",
        created=None,
        modified=None,
        read=None,
        computer_enabled=True,
        user_enabled=True,
        computer_ver_ds=None,
        computer_ver_sysvol=None,
        user_ver_ds=None,
        user_ver_sysvol=None,
        sddl=None,
        owner=None,
        filter_data_available=False,
        wmi_filter=None,
        sysvol_path=str(sysvol) if sysvol else None,
        settings=list(settings),
    )


def setting(cse, target, identity="path"):
    return Setting(GID, "User", cse, identity, identity, target, {}, False)


def test_external_paths_are_inventory_not_findings():
    estate = Estate(
        gpos=[
            gpo(
                [
                    setting("Drives", r"\\old-fs01\Share\team"),
                    setting("Printers", r"\\OLD-FS01\PrintQueue"),
                    setting("Scheduled Tasks", r"C:\Windows\System32\cmd.exe"),
                ]
            )
        ]
    )
    assert queries.broken_refs(estate) == []
    groups = queries.external_dependencies(estate)
    assert len(groups) == 1
    assert groups[0].server == "old-fs01"
    assert groups[0].dependency_count == 2
    assert groups[0].gpo_ids == (GID,)
    assert {r.dependency_type for r in groups[0].dependencies} == {
        "drive_mapping",
        "printer_connection",
    }
    assert not any(f.category.startswith("broken_ref:") for f in queries.estate_doctor(estate))


def test_own_sysvol_is_verifiable_but_remote_and_local_machine_paths_are_not(tmp_path):
    startup = tmp_path / "MACHINE" / "Scripts" / "Startup"
    startup.mkdir(parents=True)
    (startup / "Exists.cmd").write_text("echo lab")
    prefix = rf"\\lab.example.com\SYSVOL\lab.example.com\Policies\{{{GID}}}\Machine\Scripts\Startup"
    estate = Estate(
        gpos=[
            gpo(
                [
                    setting("Scripts", prefix + r"\exists.CMD"),
                    setting("Scripts", prefix + r"\missing.cmd"),
                    setting(
                        "Scripts",
                        r"\\other-domain\SYSVOL\lab.example.com\Policies\{"
                        + GID
                        + r"}\missing.cmd",
                    ),
                    setting("Scheduled Tasks", r"C:\lab\task.exe"),
                    setting("Files", r"\\old-fs01"),
                ],
                tmp_path,
            )
        ]
    )
    refs = queries.broken_refs(estate)
    assert {r.ref_value for r in refs} == {prefix + r"\missing.cmd", r"\\old-fs01"}
    assert {r.ref_type for r in refs} == {"missing_script", "malformed_path"}


def test_gpp_types_all_task_actions_and_deduplication(tmp_path):
    prefs = tmp_path / "User" / "Preferences"
    prefs.mkdir(parents=True)
    (prefs / "Shortcuts.xml").write_text(
        '<Shortcuts><Shortcut><Properties targetPath="\\\\old-fs01\\tools\\app.exe"/>'
        "</Shortcut></Shortcuts>"
    )
    (prefs / "ScheduledTasks.xml").write_text(
        "<ScheduledTasks><TaskV2><Properties><Task><Actions>"
        "<Exec><Command>\\\\old-fs01\\tools\\one.exe</Command></Exec>"
        "<Exec><Command>\\\\old-fs01\\tools\\two.exe</Command></Exec>"
        "</Actions></Task></Properties></TaskV2></ScheduledTasks>"
    )
    estate = Estate(gpos=[gpo([setting("Shortcuts", r"\\old-fs01\tools\app.exe")], tmp_path)])
    rows = queries.external_dependencies(estate)[0].dependencies
    assert len(rows) == 3
    assert {r.dependency_type for r in rows} == {"shortcut_target", "scheduled_task_action"}
    assert queries.broken_refs(estate) == []
    assert queries.external_dependencies(estate) == queries.external_dependencies(estate)


def test_admx_one_finding_per_gpo_and_stable_as_gap_list_changes():
    settings = [setting("Registry", "1", rf"SYSTEM\Lab:Value{i}") for i in range(80)]
    estate = Estate(gpos=[gpo(settings)])
    candidates = [c for c in candidates_from_estate(estate) if c.category == "admx_gap"]
    assert len(candidates) == 1
    assert "80" in candidates[0].summary
    assert all(s.identity in candidates[0].detail for s in settings)
    estate.gpos[0].settings.pop()
    later = next(c for c in candidates_from_estate(estate) if c.category == "admx_gap")
    assert compute_fingerprint(later) == compute_fingerprint(candidates[0])


def test_upgrade_resolves_old_noise_and_preserves_triage_history(tmp_path):
    estate = Estate(gpos=[gpo([setting("Registry", "1", r"SYSTEM\Lab:Value")])])
    with closing(sqlite3.connect(tmp_path / "history.db")) as conn, conn:
        store.init_db(conn)
        sid = store.save_estate(conn, estate)
        old = [
            FindingCandidate(
                detector_id=category,
                detector_version="1",
                category=category,
                severity="low",
                subject_type="gpo",
                subject_key=(GID,),
                summary="Old calibration noise",
                dimensions=dims,
            )
            for category, dims in [
                ("broken_ref:drive_mapping_unc", (("ref_value", r"\\old-fs01\share"),)),
                ("admx_gap", ()),
            ]
        ]
        run = create_evaluation_run(conn, sid)
        run_evaluation(conn, run, old)
        complete_evaluation_run(conn, run)
        ids = [r.occurrence_id for r in finding_inbox(conn)]
        for oid in ids:
            append_triage_event(conn, oid, "acknowledged", "lab-reviewer", note="Lab history")
        new_sid = store.save_estate(conn, estate)
        result = evaluate_finding_lifecycle_v2(conn, new_sid, estate)
        assert result.resolved_count == 2
        for oid in ids:
            history = finding_history(conn, oid)
            assert history.occurrence.resolved_run_id is not None
            assert history.triage_events[0].note == "Lab history"
        gaps = [r for r in finding_inbox(conn) if r.category == "admx_gap"]
        assert len(gaps) == 1
        assert gaps[0].triage_status == "open"


def test_multi_admx_dirs_cli_env_web_and_doctor(tmp_path, monkeypatch, capsys):
    dirs = [tmp_path / "central", tmp_path / "toolkit"]
    for i, directory in enumerate(dirs):
        directory.mkdir()
        (directory / "Lab.admx").write_text(
            '<policyDefinitions xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions">'
            '<policies><policy name="Lab" class="Machine" key="SYSTEM\\Lab" '
            f'valueName="Value{i}" displayName="Lab policy {i}"/></policies></policyDefinitions>'
        )
    pd = admx_parser.parse_admx_dirs(dirs)
    estate = Estate(
        gpos=[gpo([setting("Registry", "1", rf"SYSTEM\Lab:Value{i}") for i in range(2)])]
    )
    assert not [f for f in queries.estate_doctor(estate, admx=pd) if f.category == "admx_gap"]
    db = tmp_path / "lab.db"
    with closing(sqlite3.connect(db)) as conn, conn:
        store.init_db(conn)
        store.save_estate(conn, estate)
    monkeypatch.setenv("GPO_LENS_ADMX_DIR", os.pathsep.join(map(str, dirs)))
    assert len(create_app(str(db)).state.admx.policies) == 2
    assert main(["--db", str(db), "--json", "admx-gaps"]) == 0
    assert json.loads(capsys.readouterr().out)["data"] == []
    assert (
        main(
            [
                "--db",
                str(db),
                "--json",
                "admx-gaps",
                "--admx-dir",
                str(dirs[0]),
                "--admx-dir",
                str(dirs[1]),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["data"] == []


def test_inventory_cli_web_exports_navigation_and_host_boundary(tmp_path, capsys):
    estate = Estate(gpos=[gpo([setting("Drives", r"\\old-fs01\share")])])
    db = tmp_path / "lab.db"
    with closing(sqlite3.connect(db)) as conn, conn:
        store.init_db(conn)
        store.save_estate(conn, estate)
    assert main(["--db", str(db), "dependencies", "--json"]) == 0
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["schema_version"] == 2
    assert envelope["data"][0]["server"] == "old-fs01"
    client = TestClient(create_app(str(db)), client=("127.0.0.1", 50000))
    assert "/dependencies" in client.get("/explore").text
    page = client.get("/dependencies")
    assert page.status_code == 200
    assert "old-fs01" in page.text and f"/gpo/{GID}" in page.text
    for format in ("md", "csv"):
        url = f"/dependencies?server=OLD-FS01&format={format}"
        response = client.get(url)
        assert response.status_code == 200
        assert response.content == client.get(url).content
        assert "old-fs01" in response.text
    assert client.get("/dependencies?format=json").status_code == 400
    assert client.get("/dependencies", headers={"Host": "untrusted.lab"}).status_code == 400


def test_noisy_estate_keeps_high_dangers_first_in_inbox_and_briefing(tmp_path):
    estate = Estate(
        gpos=[
            gpo(
                [setting("Registry", "1", rf"SYSTEM\Lab:Value{i}") for i in range(80)]
                + [setting("Drives", rf"\\old-fs01\share{i}") for i in range(80)]
            )
        ]
    )
    estate.gpos[0].sddl = "O:S-1-5-21-100-200-300-1001D:(A;;GA;;;S-1-5-21-100-200-300-1001)"
    with closing(sqlite3.connect(tmp_path / "noise.db")) as conn, conn:
        store.init_db(conn)
        sid = store.save_estate(conn, estate)
        evaluate_finding_lifecycle_v2(conn, sid, estate)
        inbox = finding_inbox(conn)
        assert inbox[0].severity == "high"
        assert inbox[0].category.startswith("danger:")
        assert len([r for r in inbox if r.category == "admx_gap"]) == 1
        briefing = build_briefing(conn)
        assert briefing is not None
        assert briefing.problems and "high" in briefing.problems[0]
        assert inbox[0].summary in briefing.problems[0]


def test_coverage_gap_does_not_resolve_old_noise(tmp_path):
    estate = Estate(gpos=[gpo()])
    with closing(sqlite3.connect(tmp_path / "partial.db")) as conn, conn:
        store.init_db(conn)
        sid = store.save_estate(conn, estate)
        run = create_evaluation_run(conn, sid)
        run_evaluation(
            conn,
            run,
            [
                FindingCandidate(
                    detector_id="admx_gap",
                    detector_version="1",
                    category="admx_gap",
                    severity="low",
                    subject_type="gpo",
                    subject_key=(GID,),
                )
            ],
        )
        complete_evaluation_run(conn, run)
        oid = finding_inbox(conn)[0].occurrence_id
        absent = Estate(gpos=[], coverage_gaps=[CoverageGap(GID, "Lab", "inaccessible", "Denied")])
        next_sid = store.save_estate(conn, absent)
        evaluate_finding_lifecycle_v2(conn, next_sid, absent)
        assert finding_history(conn, oid).occurrence.resolved_run_id is None


def test_structured_unc_targets_keep_spaces_and_existing_files(tmp_path):
    startup = tmp_path / "Machine" / "Scripts" / "Startup"
    startup.mkdir(parents=True)
    (startup / "setup script.cmd").write_text("echo lab")
    own = (
        rf"\\lab.example.com\sysvol\lab.example.com\Policies\{{{GID}}}"
        r"\Machine\Scripts\Startup\setup script.cmd"
    )
    remote = r"\\old-fs01\share\Team Files\setup script.cmd"
    estate = Estate(gpos=[gpo([setting("Scripts", own), setting("Files", remote)], tmp_path)])
    assert queries.broken_refs(estate) == []
    assert queries.external_dependencies(estate)[0].dependencies[0].target == remote


def test_relative_dot_paths_are_valid_and_do_not_escape_collected_copy(tmp_path):
    scripts = tmp_path / "User" / "Scripts" / "Logon"
    scripts.mkdir(parents=True)
    (scripts / "login.cmd").write_text("echo lab")
    estate = Estate(
        gpos=[
            gpo(
                [
                    setting("Scripts", r".\login.cmd"),
                    setting("Scheduled Tasks", r"C:\Tools\..\app.exe"),
                    setting("Scripts", r"..\..\..\outside.cmd"),
                ],
                tmp_path,
            )
        ]
    )
    assert queries.broken_refs(estate) == []


def test_parser_script_command_is_used_instead_of_logon_label(tmp_path):
    xml = f"""<AllGPOs><GPO><Identifier><Identifier>{{{GID}}}</Identifier>
      <Domain>lab.example.com</Domain></Identifier><Name>Lab scripts</Name>
      <User><Enabled>true</Enabled><ExtensionData><Name>Scripts</Name><Extension>
      <Script><Command>login.cmd</Command><Type>Logon</Type></Script>
      </Extension></ExtensionData></User></GPO></AllGPOs>"""
    gpos = parse_report_xml(xml.encode())
    scripts = tmp_path / "User" / "Scripts" / "Logon"
    scripts.mkdir(parents=True)
    (scripts / "login.cmd").write_text("echo lab")
    gpos[0].sysvol_path = str(tmp_path)
    estate = Estate(gpos=gpos)
    assert queries.broken_refs(estate) == []
    (scripts / "login.cmd").unlink()
    assert [r.ref_value for r in queries.broken_refs(estate)] == ["login.cmd"]


def test_inventory_empty_estate_and_exports(tmp_path):
    db = tmp_path / "empty.db"
    with closing(sqlite3.connect(db)) as conn, conn:
        store.init_db(conn)
    client = TestClient(create_app(str(db)), client=("127.0.0.1", 50000))
    for suffix in ("", "?format=md", "?format=csv"):
        response = client.get("/dependencies" + suffix)
        assert response.status_code == 200


def test_admx_evidence_keeps_setting_lists_per_observation(tmp_path):
    settings = [setting("Registry", "1", rf"SYSTEM\Lab:Value{i}") for i in range(3)]
    estate = Estate(gpos=[gpo(settings)])
    with closing(sqlite3.connect(tmp_path / "evidence.db")) as conn, conn:
        store.init_db(conn)
        sid = store.save_estate(conn, estate)
        evaluate_finding_lifecycle_v2(conn, sid, estate)
        oid = next(r.occurrence_id for r in finding_inbox(conn) if r.category == "admx_gap")
        estate.gpos[0].settings.pop()
        sid = store.save_estate(conn, estate)
        evaluate_finding_lifecycle_v2(conn, sid, estate)
        history = finding_history(conn, oid)
        assert len(history.observations) == 2
        projections = [
            [
                e["safe_projection"]
                for e in json.loads(o.evidence_json)
                if e["field_path"].startswith("admx_gap.settings.")
            ]
            for o in history.observations
        ]
        assert projections[0] == [rf"User/SYSTEM\Lab:Value{i}" for i in range(3)]
        assert projections[1] == [rf"User/SYSTEM\Lab:Value{i}" for i in range(2)]


@pytest.mark.parametrize("suffix", ["", "?format=md", "?format=csv"])
def test_dependency_view_and_exports_require_authentication(tmp_path, monkeypatch, suffix):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "lab-only-token")
    db = tmp_path / "auth.db"
    with closing(sqlite3.connect(db)) as conn, conn:
        store.init_db(conn)
    client = TestClient(create_app(str(db)))
    assert client.get("/dependencies" + suffix).status_code == 401


@pytest.mark.parametrize(
    "cse,expected",
    [
        ("Software Installation", "software_installation_package"),
        ("Folder Redirection", "folder_redirection_target"),
        ("Files", "file_copy"),
        ("Scripts", "script"),
    ],
)
def test_report_only_dependency_types_and_raw_nested_paths(cse, expected):
    s = setting(cse, "Lab configured path")
    s.raw = {"children": [{"tag": "Path", "text": r"\\old-fs01\share\Team Files\app.msi"}]}
    estate = Estate(gpos=[gpo([s])])
    groups = queries.external_dependencies(estate, server=r"\\OLD-FS01")
    assert len(groups) == 1
    assert groups[0].dependencies[0].dependency_type == expected
    assert groups[0].dependencies[0].target.endswith(r"Team Files\app.msi")
    assert queries.external_dependencies(estate, server="other-server") == []


def test_parser_gpp_action_prefix_does_not_truncate_or_double_count(tmp_path):
    scripts = tmp_path / "User" / "Scripts"
    scripts.mkdir(parents=True)
    (scripts / "setup script.cmd").write_text("echo lab")
    own = (
        rf"\\lab.example.com\sysvol\lab.example.com\Policies\{{{GID}}}"
        r"\User\Scripts\setup script.cmd"
    )
    remote = r"\\old-fs01\share\Team Files\file.cmd"
    xml = f'''<AllGPOs><GPO><Identifier><Identifier>{{{GID}}}</Identifier>
      <Domain>lab.example.com</Domain></Identifier><Name>Lab files</Name>
      <User><Enabled>true</Enabled><ExtensionData><Name>Files</Name><Extension>
      <Files clsid="lab"><File uid="one" name="Lab source"><Properties
       action="U" fromPath="{remote}"/></File><File uid="two" name="Lab script">
       <Properties action="U" fromPath="{own}"/></File></Files>
      </Extension></ExtensionData></User></GPO></AllGPOs>'''
    gpos = parse_report_xml(xml.encode())
    gpos[0].sysvol_path = str(tmp_path)
    estate = Estate(gpos=gpos)
    assert queries.broken_refs(estate) == []
    groups = queries.external_dependencies(estate)
    assert groups[0].dependency_count == 1
    assert groups[0].dependencies[0].target == remote


def test_mixed_quoted_and_unquoted_task_arguments_keep_every_server(tmp_path):
    import xml.etree.ElementTree as ET

    prefs = tmp_path / "User" / "Preferences"
    prefs.mkdir(parents=True)
    root = ET.Element("ScheduledTasks")
    props = ET.SubElement(ET.SubElement(root, "Task"), "Properties")
    props.set("appName", "cmd.exe")
    props.set("arguments", r'"\\first-fs\share\Team Files\one.cmd" \\second-fs\tools\two.cmd')
    ET.ElementTree(root).write(prefs / "ScheduledTasks.xml")
    groups = queries.external_dependencies(Estate(gpos=[gpo([], tmp_path)]))
    assert [g.server for g in groups] == ["first-fs", "second-fs"]
    assert groups[0].dependencies[0].target.endswith(r"Team Files\one.cmd")


def test_own_sysvol_expansions_and_file_patterns_are_unverifiable(tmp_path):
    prefix = rf"\\lab.example.com\SYSVOL\lab.example.com\Policies\{{{GID}}}\User\Scripts"
    estate = Estate(
        gpos=[
            gpo(
                [
                    setting("Files", prefix + r"\*.xml"),
                    setting("Scripts", prefix + r"\%USERNAME%.cmd"),
                ],
                tmp_path,
            )
        ]
    )
    assert queries.broken_refs(estate) == []
