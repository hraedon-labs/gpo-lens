"""Regression: GPP scanning must survive an unreadable SYSVOL subtree.

A copied SYSVOL can contain policy folders the analysis account cannot enter:
a security-filtered GPO copied with its ACLs intact, or — observed on a real
run-through — a Windows-produced zip extracted on Linux where a directory lost
its traversal (``x``) bit. ``_walk_gpp_xml`` must skip such subtrees, not crash
the whole ``doctor`` run. Coverage gaps are reported via collection-errors.json.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from gpo_lens import ingest
from gpo_lens.admx_parser import parse_admx_dir
from gpo_lens.detection import (
    _scan_gpo_for_cpassword,
    _walk_gpp_xml,
    scan_ilt,
    scan_local_groups,
    scan_scheduled_tasks,
)
from gpo_lens.ingest import augment_blocked_registry_from_pol
from gpo_lens.model import Estate, Gpo, Setting

_SCHED_XML = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<ScheduledTasks><ImmediateTaskV2 name="t">'
    '<Properties action="C" runAs="SYSTEM"><Task><Actions>'
    "<Exec><Command>cmd.exe</Command></Exec>"
    "</Actions></Task></Properties></ImmediateTaskV2></ScheduledTasks>"
)


def _make_gpo(sysvol_path: str) -> Gpo:
    return Gpo(
        id="gpo-1",
        name="Partial GPO",
        domain="test.local",
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
        sysvol_path=sysvol_path,
        settings=[],
    )


def _build_tree(base: Path) -> None:
    machine = base / "Machine" / "Preferences" / "ScheduledTasks"
    machine.mkdir(parents=True)
    (machine / "ScheduledTasks.xml").write_text(_SCHED_XML, encoding="utf-8")
    (base / "User" / "Preferences").mkdir(parents=True)


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0,
    reason="chmod-based unreadable-dir test requires a non-root POSIX host",
)
def test_walk_skips_unreadable_side(tmp_path):
    base = tmp_path / "{GUID}"
    _build_tree(base)
    unreadable = base / "User"
    unreadable.chmod(0o000)  # drop traversal bit, as a broken extraction does
    try:
        gpo = _make_gpo(str(base))
        # Must not raise PermissionError, and must still find the readable side.
        found = [w.rel_file.as_posix() for w in _walk_gpp_xml(gpo)]
        assert any("Machine/Preferences" in p for p in found)
        assert _scan_gpo_for_cpassword(gpo) == []
    finally:
        unreadable.chmod(0o755)  # restore so tmp cleanup can recurse


_GROUPS_XML = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<Groups><Group name="Administrators (built-in)">'
    '<Properties action="U" groupSid="S-1-5-32-544" groupName="Administrators">'
    '<Members><Member name="HRAENET\\helpdesk" action="ADD" '
    'sid="S-1-5-21-1-2-3-1106"/></Members>'
    "</Properties></Group></Groups>"
)


def test_real_nested_cse_layout_is_parsed(tmp_path):
    """Real SYSVOL nests each CSE in its own subfolder: Preferences/<CSE>/<CSE>.xml.

    The flat fixtures used elsewhere hid this; a real export only works if the
    walker descends one level into the CSE subfolders.
    """
    base = tmp_path / "{GUID}"
    sched = base / "Machine" / "Preferences" / "ScheduledTasks"
    sched.mkdir(parents=True)
    (sched / "ScheduledTasks.xml").write_text(_SCHED_XML, encoding="utf-8")
    groups = base / "Machine" / "Preferences" / "Groups"
    groups.mkdir(parents=True)
    (groups / "Groups.xml").write_text(_GROUPS_XML, encoding="utf-8")

    gpo = _make_gpo(str(base))
    tasks = scan_scheduled_tasks(gpo)
    assert len(tasks) == 1
    mods = scan_local_groups(gpo)
    assert len(mods) == 1
    assert mods[0].side == "Computer"


def test_walk_dedupes_mixed_flat_and_nested_layout(tmp_path):
    """When BOTH flat (Preferences/Groups.xml) and nested
    (Preferences/Groups/Groups.xml) exist, the walker must yield only ONE —
    not double-count findings."""
    base = tmp_path / "{GUID}"
    prefs = base / "Machine" / "Preferences"
    nested_dir = prefs / "Groups"
    nested_dir.mkdir(parents=True)
    # Write the SAME file in both locations
    (prefs / "Groups.xml").write_text(_GROUPS_XML, encoding="utf-8")
    (nested_dir / "Groups.xml").write_text(_GROUPS_XML, encoding="utf-8")

    gpo = _make_gpo(str(base))
    mods = scan_local_groups(gpo)
    assert len(mods) == 1, f"Expected 1 (deduped), got {len(mods)}"


def test_scheduled_task_v2_extracts_nested_exec(tmp_path):
    """V2 tasks store command/arguments in <Task><Actions><Exec>."""
    base = tmp_path / "{GUID}"
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<ScheduledTasks><ImmediateTaskV2 name="Set Timezone">'
        '<Properties action="UPDATE">'
        "<Task><Actions><Exec>"
        "<Command>tzutil.exe</Command>"
        '<Arguments>/s "UTC"</Arguments>'
        "</Exec></Actions>"
        '<Principals><Principal id="Author">'
        "<UserId>NT AUTHORITY\\SYSTEM</UserId>"
        "</Principal></Principals>"
        "</Task></Properties></ImmediateTaskV2></ScheduledTasks>"
    )
    sched = base / "Machine" / "Preferences" / "ScheduledTasks"
    sched.mkdir(parents=True)
    (sched / "ScheduledTasks.xml").write_text(xml, encoding="utf-8")

    gpo = _make_gpo(str(base))
    tasks = scan_scheduled_tasks(gpo)
    assert len(tasks) == 1
    t = tasks[0]
    assert t.kind == "ImmediateTaskV2"
    assert t.command == "tzutil.exe"
    assert t.arguments == '/s "UTC"'
    assert t.run_as == "NT AUTHORITY\\SYSTEM"
    assert t.side == "Computer"


def test_scheduled_task_v2_nested_falls_back_to_v1_attrs(tmp_path):
    """V1 attribute extraction is still used for legacy Task elements."""
    base = tmp_path / "{GUID}"
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<ScheduledTasks><Task name="Legacy" runAs="HRAENET\\svc">'
        '<Properties action="C" appName="legacy.exe" arguments="-q"/>'
        "</Task></ScheduledTasks>"
    )
    sched = base / "Machine" / "Preferences" / "ScheduledTasks"
    sched.mkdir(parents=True)
    (sched / "ScheduledTasks.xml").write_text(xml, encoding="utf-8")

    gpo = _make_gpo(str(base))
    tasks = scan_scheduled_tasks(gpo)
    assert len(tasks) == 1
    t = tasks[0]
    assert t.kind == "Task"
    assert t.command == "legacy.exe"
    assert t.arguments == "-q"
    assert t.run_as == "HRAENET\\svc"


def test_scheduled_task_v1_and_v2_mixed(tmp_path):
    """A single ScheduledTasks.xml can contain both V1 and V2 tasks."""
    base = tmp_path / "{GUID}"
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        "<ScheduledTasks>"
        '<Task name="Legacy"><Properties action="C" appName="a.exe"/></Task>'
        '<ImmediateTaskV2 name="Modern"><Properties action="C">'
        "<Task><Actions><Exec><Command>b.exe</Command></Exec></Actions></Task>"
        "</Properties></ImmediateTaskV2>"
        "</ScheduledTasks>"
    )
    sched = base / "Machine" / "Preferences" / "ScheduledTasks"
    sched.mkdir(parents=True)
    (sched / "ScheduledTasks.xml").write_text(xml, encoding="utf-8")

    gpo = _make_gpo(str(base))
    tasks = scan_scheduled_tasks(gpo)
    assert len(tasks) == 2
    by_name = {t.name: t for t in tasks}
    assert by_name["Legacy"].command == "a.exe"
    assert by_name["Modern"].command == "b.exe"


def test_uppercase_side_dir_is_parsed(tmp_path):
    """Default GPOs ship as MACHINE/USER (upper-case). On a case-sensitive host
    the walker must still find them and assign the correct side."""
    base = tmp_path / "{GUID}"
    sched = base / "MACHINE" / "Preferences" / "ScheduledTasks"
    sched.mkdir(parents=True)
    (sched / "ScheduledTasks.xml").write_text(_SCHED_XML, encoding="utf-8")

    gpo = _make_gpo(str(base))
    tasks = scan_scheduled_tasks(gpo)
    assert len(tasks) == 1
    assert tasks[0].side == "Computer"


def test_walk_skips_side_raising_oserror(tmp_path, monkeypatch):
    """Deterministic (root-safe) variant: iterdir raises on the User side."""
    base = tmp_path / "{GUID}"
    _build_tree(base)
    gpo = _make_gpo(str(base))

    real_iterdir = Path.iterdir

    def fake_iterdir(self):
        if self.parent.name == "User":
            raise PermissionError(13, "Permission denied")
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", fake_iterdir)
    found = [w.rel_file.as_posix() for w in _walk_gpp_xml(gpo)]
    assert any("Machine/Preferences" in p for p in found)


def _sched_gpo(tmp_path: Path, xml: str) -> Gpo:
    base = tmp_path / "{GUID}"
    sched = base / "Machine" / "Preferences" / "ScheduledTasks"
    sched.mkdir(parents=True)
    (sched / "ScheduledTasks.xml").write_text(xml, encoding="utf-8")
    return _make_gpo(str(base))


def test_malformed_xml_in_preferences_is_skipped(tmp_path):
    gpo = _sched_gpo(tmp_path, "<<not xml")
    assert scan_scheduled_tasks(gpo) == []


def test_empty_xml_in_preferences_is_skipped(tmp_path):
    gpo = _sched_gpo(tmp_path, "")
    assert scan_scheduled_tasks(gpo) == []


def test_load_estate_malformed_allgpos_fails_loud(tmp_path):
    """A corrupt primary input must fail loud, not silently degrade.

    Coverage honesty: silently producing an empty Estate from an unparseable
    AllGPOs.xml would render the estate as "complete, just empty" — a worse
    failure mode than crashing, because the operator might not notice.
    """
    (tmp_path / "AllGPOs.xml").write_text("<<not xml", encoding="utf-8")
    with pytest.raises((ValueError, ET.ParseError)):
        ingest.load_estate(tmp_path)


def test_load_estate_malformed_optional_json_degrades(tmp_path):
    (tmp_path / "AllGPOs.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>'
        '<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">'
        "  <GPO><Identifier><Identifier>"
        "{11111111-1111-1111-1111-111111111111}"
        "</Identifier></Identifier><Name>Test</Name>"
        "<Computer><Enabled>true</Enabled></Computer>"
        "<User><Enabled>true</Enabled></User>"
        "<FilterDataAvailable>false</FilterDataAvailable></GPO>"
        "</GPO>",
        encoding="utf-8",
    )
    (tmp_path / "gp-inheritance.json").write_text("not json", encoding="utf-8")
    with pytest.warns(UserWarning, match="Skipping gp-inheritance.json"):
        estate = ingest.load_estate(tmp_path)
    assert len(estate.gpos) == 1
    assert estate.soms == []


def _make_blocked_gpo(sysvol_path: str) -> Gpo:
    return Gpo(
        id="gpo-1",
        name="Blocked GPO",
        domain="test.local",
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
        sysvol_path=sysvol_path,
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="Registry:blocked",
                display_name="(blocked extension)",
                display_value="",
                raw={"blocked": True},
                from_disabled_side=False,
                source_state="blocked",
            )
        ],
    )


def test_augment_ignores_truncated_registry_pol(tmp_path):
    """A truncated Registry.pol does not crash augmentation or remove the placeholder."""
    base = tmp_path / "gpo-1"
    machine = base / "Machine"
    machine.mkdir(parents=True)
    # Valid header followed by an incomplete record.
    (machine / "Registry.pol").write_bytes(b"PReg\x01\x00\x00\x00" + b"\x5b\x00" + b"\x00" * 3)
    gpo = _make_blocked_gpo(str(base))
    augment_blocked_registry_from_pol([gpo])
    assert any(s.source_state == "blocked" for s in gpo.settings)
    assert not any(s.source_state == "registry_pol" for s in gpo.settings)


def test_ilt_reports_specific_gpp_file(tmp_path):
    """Item-level-targeting findings name the file, not just 'SYSVOL'."""
    base = tmp_path / "{GUID}"
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<ScheduledTasks><Task name="t">'
        "<Filters><Filter1/></Filters>"
        "</Task></ScheduledTasks>"
    )
    sched = base / "Machine" / "Preferences" / "ScheduledTasks"
    sched.mkdir(parents=True)
    (sched / "ScheduledTasks.xml").write_text(xml, encoding="utf-8")

    gpo = _make_gpo(str(base))
    estate = Estate(domain="test.local", gpos=[gpo])
    hits = scan_ilt(estate)
    assert len(hits) == 1
    assert "Machine/Preferences/ScheduledTasks/ScheduledTasks.xml" in hits[0].files


def test_parse_admx_dir_missing_directory_returns_empty():
    pd = parse_admx_dir(Path("/does/not/exist"))
    assert pd.policies == []


def test_parse_admx_dir_corrupted_adml_is_skipped(tmp_path):
    """A corrupted ADML file must not prevent parsing valid ADMX policies."""
    base = tmp_path / "PolicyDefinitions"
    en_us = base / "en-US"
    en_us.mkdir(parents=True)
    ns = "http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"
    (en_us / "good.adml").write_text(
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<policyDefinitionResources xmlns="{ns}">'
        f'<stringTable><string id="Foo">Foo Policy</string></stringTable>'
        f"</policyDefinitionResources>",
        encoding="utf-8",
    )
    (en_us / "bad.adml").write_text("not xml", encoding="utf-8")
    (base / "test.admx").write_text(
        '<?xml version="1.0" encoding="utf-8"?>'
        '<policyDefinitions xmlns="'
        "http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"
        '">'
        '<policy name="TestPolicy" class="Both" key="Software\\Test" '
        'valueName="Val" displayName="$(string.Foo)"/>'
        "</policyDefinitions>",
        encoding="utf-8",
    )
    pd = parse_admx_dir(base)
    assert len(pd.policies) == 1
    assert pd.policies[0].display_name == "Foo Policy"


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0,
    reason="chmod-based unreadable-dir test requires a non-root POSIX host",
)
def test_parse_admx_dir_unreadable_directory_returns_empty(tmp_path):
    base = tmp_path / "PolicyDefinitions"
    base.mkdir()
    base.chmod(0o000)
    try:
        pd = parse_admx_dir(base)
        assert pd.policies == []
    finally:
        base.chmod(0o755)


# ---------------------------------------------------------------------------
# Coverage honesty: unreadable SYSVOL Preferences dirs must be surfaced
# ---------------------------------------------------------------------------


def test_unreadable_sysvol_produces_coverage_gap(tmp_path):
    """A Windows zip extracted on Linux often drops the traversal bit on
    Preferences subdirs. The walker must skip them (not crash), and
    _scan_sysvol_gaps must surface them as coverage_gaps."""
    from gpo_lens.ingest import _scan_sysvol_gaps

    base = tmp_path / "{GUID}"
    prefs = base / "Machine" / "Preferences" / "Groups"
    prefs.mkdir(parents=True)
    (prefs / "Groups.xml").write_text(_GROUPS_XML, encoding="utf-8")
    # Drop traversal bit on the CSE subdir
    prefs.chmod(0o000)
    try:
        gpo = _make_gpo(str(base))
        gaps = [g for g in _scan_sysvol_gaps([gpo]) if g.kind == "unreadable_sysvol"]
        assert len(gaps) == 1
        assert gaps[0].kind == "unreadable_sysvol"
        assert gaps[0].gpo_id == gpo.id
        assert "chmod" in (gaps[0].detail or "")
    finally:
        prefs.chmod(0o755)


def test_readable_sysvol_produces_no_coverage_gap(tmp_path):
    """A healthy SYSVOL with readable Preferences dirs produces no gaps."""
    from gpo_lens.ingest import _scan_sysvol_gaps

    base = tmp_path / "{GUID}"
    sched = base / "Machine" / "Preferences" / "ScheduledTasks"
    sched.mkdir(parents=True)
    (sched / "ScheduledTasks.xml").write_text(_SCHED_XML, encoding="utf-8")
    gpo = _make_gpo(str(base))
    gaps = [g for g in _scan_sysvol_gaps([gpo]) if g.kind == "unreadable_sysvol"]
    assert gaps == []


# ---------------------------------------------------------------------------
# Broken-ref scanner: Properties-child UNC paths
# ---------------------------------------------------------------------------

_DRIVE_XML = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<Drives><Drive clsid="{...}" name="Public" changed="2025-01-01">'
    '<Properties action="C" driveLetter="P:" path="\\\\oldserver\\share"/>'
    "</Drive></Drives>"
)


def test_drive_unc_in_properties_child_is_detected(tmp_path):
    """Real GPP XML puts UNC paths on <Properties>, not on the outer element.
    The ref scanner must descend into Properties children."""
    from gpo_lens.dependencies import external_dependencies
    from gpo_lens.detection import _scan_gpp_xml_for_refs

    base = tmp_path / "{GUID}"
    drives = base / "User" / "Preferences" / "Drives"
    drives.mkdir(parents=True)
    (drives / "Drives.xml").write_text(_DRIVE_XML, encoding="utf-8")
    gpo = _make_gpo(str(base))
    assert _scan_gpp_xml_for_refs(gpo) == []
    refs = [r for group in external_dependencies(Estate(gpos=[gpo])) for r in group.dependencies]
    unc_refs = [r for r in refs if "oldserver" in r.target]
    assert len(unc_refs) == 1
    assert all(r.dependency_type == "drive_mapping" for r in unc_refs)
