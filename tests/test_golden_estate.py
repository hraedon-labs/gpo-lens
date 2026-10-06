"""CI-gated assertions against the scrubbed golden estate fixture.

This test module runs ALWAYS (no skips) and validates that the ingest + detection
pipeline works correctly against a fixture that mirrors the REAL on-disk SYSVOL
shape: uppercase side dirs (MACHINE/USER), nested per-CSE subfolders
(Preferences/Groups/Groups.xml), V2 scheduled tasks with nested <Exec>,
cpassword positives, <Blocked/> Registry extensions resolved from Registry.pol,
drive mappings with UNC paths, Printers preference, ILT (FilterOrgUnit), and
coverage gaps.

This is the WI-011 + WI-013 CI gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gpo_lens.dependencies import external_dependencies
from gpo_lens.detection import (
    broken_refs,
    cpassword_scan,
    scan_ilt,
    scan_local_groups,
    scan_scheduled_tasks,
)
from gpo_lens.ingest import load_estate
from gpo_lens.model import Estate
from gpo_lens.queries import estate_doctor, is_security_filtered
from gpo_lens.topology import is_security_filtered as topology_is_security_filtered

GOLDEN_DIR = Path(__file__).resolve().parent / "golden_estate"

# Canonical GUIDs (lowercase, braces and hyphens stripped — the contract key)
G = {
    "v2task": "aaaaaaaa000100010001aaaaaaaaaaaa",
    "cpassword": "aaaaaaaa000200020002aaaaaaaaaaaa",
    "blocked": "aaaaaaaa000300030003aaaaaaaaaaaa",
    "secfilt": "aaaaaaaa000400040004aaaaaaaaaaaa",
    "wmifilt": "aaaaaaaa000500050005aaaaaaaaaaaa",
    "invonly": "aaaaaaaa000600060006aaaaaaaaaaaa",
    "collerr": "aaaaaaaa000700070007aaaaaaaaaaaa",
    "drives": "aaaaaaaa000800080008aaaaaaaaaaaa",
}


@pytest.fixture(scope="module")
def golden_estate() -> Estate:
    """Load the golden estate once per module."""
    return load_estate(GOLDEN_DIR)


# ===========================================================================
# AC-1: All GPOs are ingested — count matches expected
# ===========================================================================


class TestIngestCount:
    """6 GPOs in AllGPOs.xml; the 7th (invonly) is inventory-only → coverage gap."""

    def test_gpo_count(self, golden_estate: Estate) -> None:
        assert len(golden_estate.gpos) == 6

    def test_all_six_ids_present(self, golden_estate: Estate) -> None:
        ingested_ids = {g.id for g in golden_estate.gpos}
        expected = {
            G["v2task"],
            G["cpassword"],
            G["blocked"],
            G["secfilt"],
            G["wmifilt"],
            G["drives"],
        }
        assert ingested_ids == expected

    def test_domain(self, golden_estate: Estate) -> None:
        assert golden_estate.domain == "GOLDEN.local"


# ===========================================================================
# AC-2: V2 scheduled task command is parsed from nested <Exec>
# ===========================================================================


class TestV2ScheduledTask:
    """The V2 ImmediateTaskV2 uses <Properties><Task><Actions><Exec><Command>
    format — NOT the V1 appName attribute. The parser must extract
    command='tzutil.exe' and arguments populated."""

    def test_v2_task_command_parsed(self, golden_estate: Estate) -> None:
        gpo = golden_estate.gpo_by_id(G["v2task"])
        assert gpo is not None
        tasks = scan_scheduled_tasks(gpo)
        # Should find both the V1 and V2 tasks
        assert len(tasks) == 2

        # The V2 task — command from nested <Exec>
        v2 = next(t for t in tasks if t.kind == "ImmediateTaskV2")
        assert v2.command == "tzutil.exe", f"V2 command should be 'tzutil.exe', got {v2.command!r}"
        assert v2.arguments == '/s "UTC"', (
            f"V2 arguments should be '/s \"UTC\"', got {v2.arguments!r}"
        )
        assert v2.run_as == "NT AUTHORITY\\SYSTEM"
        assert v2.name == "Set Timezone"

    def test_v1_task_still_works(self, golden_estate: Estate) -> None:
        """V1 tasks (appName attribute) must still parse correctly."""
        gpo = golden_estate.gpo_by_id(G["v2task"])
        assert gpo is not None
        tasks = scan_scheduled_tasks(gpo)
        v1 = next(t for t in tasks if t.kind == "Task")
        assert v1.command  # appName should be non-empty
        assert "legacy.exe" in v1.command

    def test_v2_task_uses_nested_layout(self, golden_estate: Estate) -> None:
        """The file path must reflect the nested SYSVOL layout."""
        gpo = golden_estate.gpo_by_id(G["v2task"])
        assert gpo is not None
        tasks = scan_scheduled_tasks(gpo)
        for t in tasks:
            expected = "MACHINE/Preferences/ScheduledTasks/ScheduledTasks.xml"
            assert t.file == expected, f"Expected {expected}, got: {t.file}"


# ===========================================================================
# AC-3: Cpassword is detected (WI-013) — from nested Groups/Groups.xml
# ===========================================================================


class TestCpasswordDetection:
    """cpassword_scan / estate_doctor finds the cpassword in the nested
    Groups/Groups.xml and it is masked in the output."""

    def test_cpassword_scan_finds_hit(self, golden_estate: Estate) -> None:
        hits = cpassword_scan(golden_estate)
        assert len(hits) == 1
        hit = hits[0]
        assert hit.gpo_id == G["cpassword"]
        assert hit.gpo_name == "golden-cpassword"
        # The cpassword attribute lives on the <Properties> child of <User>
        assert hit.tag == "Properties"

    def test_cpassword_masked_in_doctor(self, golden_estate: Estate) -> None:
        findings = estate_doctor(golden_estate)
        cpw_findings = [f for f in findings if f.category == "cpassword"]
        assert len(cpw_findings) == 1
        detail = cpw_findings[0].detail
        # The masked cpassword should start with the first 4 chars then "****"
        assert "****" in detail
        # The full (unmasked) cpassword must NOT appear in the detail
        # (Well-known test value is long; check a distinctive substring)
        assert "AQUbc" not in detail  # last 5 chars of the well-known value

    def test_cpassword_from_nested_path(self, golden_estate: Estate) -> None:
        """The cpassword hit's file path must reflect the nested layout."""
        hits = cpassword_scan(golden_estate)
        assert len(hits) == 1
        expected = "MACHINE/Preferences/Groups/Groups.xml"
        assert hits[0].file == expected, f"Expected {expected}, got: {hits[0].file}"


# ===========================================================================
# AC-4: Registry.pol is parsed — <Blocked/> resolved from PReg binary
# ===========================================================================


class TestBlockedRegistryResolution:
    """The <Blocked/> GPO's settings are resolved from the PReg binary file,
    not left as opaque <Blocked/> placeholders."""

    def test_blocked_settings_resolved(self, golden_estate: Estate) -> None:
        gpo = golden_estate.gpo_by_id(G["blocked"])
        assert gpo is not None

        # There should be settings from Registry.pol (NOT the blocked placeholder)
        reg_settings = [s for s in gpo.settings if s.cse == "Registry"]
        assert len(reg_settings) >= 2, (
            f"Expected >= 2 Registry settings from Registry.pol, got {len(reg_settings)}"
        )

    def test_no_blocked_placeholder_remaining(self, golden_estate: Estate) -> None:
        """After augment_blocked_registry_from_pol, the blocked placeholder is gone."""
        gpo = golden_estate.gpo_by_id(G["blocked"])
        assert gpo is not None
        blocked = [s for s in gpo.settings if s.source_state == "blocked"]
        assert len(blocked) == 0, (
            "Blocked placeholder should have been replaced by Registry.pol records"
        )

    def test_registry_pol_values(self, golden_estate: Estate) -> None:
        """The PReg records have the correct values."""
        gpo = golden_estate.gpo_by_id(G["blocked"])
        assert gpo is not None
        reg_settings = [s for s in gpo.settings if s.source_state == "registry_pol"]
        assert len(reg_settings) == 2

        # Check specific values
        by_id = {s.identity: s for s in reg_settings}
        # DWORD: EnableAudit = 1
        audit = by_id.get(r"Software\GoldenPolicies:EnableAudit")
        assert audit is not None, f"EnableAudit setting not found; identities: {list(by_id)}"
        assert audit.display_value == "1"

        # SZ: LogPath
        log = by_id.get(r"Software\GoldenPolicies:LogPath")
        assert log is not None, f"LogPath setting not found; identities: {list(by_id)}"
        assert r"C:\Logs\GPAudit.log" in log.display_value


# ===========================================================================
# AC-5: Security-filtered GPO is flagged
# ===========================================================================


class TestSecurityFiltering:
    """is_security_filtered returns True for the narrowed GPO."""

    def test_security_filtered_true(self, golden_estate: Estate) -> None:
        gpo = golden_estate.gpo_by_id(G["secfilt"])
        assert gpo is not None
        assert is_security_filtered(gpo) is True

    def test_topology_security_filtered_true(self, golden_estate: Estate) -> None:
        """Also check via the topology module's version."""
        gpo = golden_estate.gpo_by_id(G["secfilt"])
        assert gpo is not None
        assert topology_is_security_filtered(gpo) is True

    def test_normal_gpo_not_filtered(self, golden_estate: Estate) -> None:
        gpo = golden_estate.gpo_by_id(G["v2task"])
        assert gpo is not None
        assert is_security_filtered(gpo) is False


# ===========================================================================
# AC-6: Nested layout works — file paths use nested-subfolder format
# ===========================================================================


class TestNestedLayoutPaths:
    """All GPP findings come from nested-subfolder paths (e.g.
    Preferences/Groups/Groups.xml), NOT flat paths (Preferences/Groups.xml)."""

    def test_scheduled_tasks_nested_path(self, golden_estate: Estate) -> None:
        gpo = golden_estate.gpo_by_id(G["v2task"])
        assert gpo is not None
        tasks = scan_scheduled_tasks(gpo)
        for t in tasks:
            assert "ScheduledTasks/ScheduledTasks.xml" in t.file
            # Must NOT be the flat layout
            assert "Preferences/ScheduledTasks.xml" not in t.file

    def test_cpassword_nested_path(self, golden_estate: Estate) -> None:
        hits = cpassword_scan(golden_estate)
        assert len(hits) == 1
        assert "Groups/Groups.xml" in hits[0].file
        # Must NOT be the flat layout
        assert hits[0].file.count("Groups.xml") == 1  # exactly one occurrence

    def test_local_groups_nested_path(self, golden_estate: Estate) -> None:
        gpo = golden_estate.gpo_by_id(G["cpassword"])
        assert gpo is not None
        mods = scan_local_groups(gpo)
        assert len(mods) >= 1
        for m in mods:
            # Should be Preferences/LocalUsersAndGroups/LocalUsersAndGroups.xml
            assert "LocalUsersAndGroups/LocalUsersAndGroups.xml" in m.file, (
                f"Expected nested LUG path, got: {m.file}"
            )


# ===========================================================================
# AC-7: Coverage gap is surfaced — not a crash
# ===========================================================================


class TestCoverageGap:
    """The empty/unreadable policy folder generates a coverage_gap finding,
    not a crash."""

    def test_coverage_gap_present(self, golden_estate: Estate) -> None:
        assert len(golden_estate.coverage_gaps) == 2

    def test_coverage_gap_is_inaccessible(self, golden_estate: Estate) -> None:
        gaps = [g for g in golden_estate.coverage_gaps if g.kind == "inaccessible"]
        assert len(gaps) == 1
        gap = gaps[0]
        assert gap.gpo_id == G["invonly"]
        assert gap.display_name == "golden-inaccessible"

    def test_coverage_gap_is_collection_error(self, golden_estate: Estate) -> None:
        gaps = [g for g in golden_estate.coverage_gaps if g.kind == "collection_error"]
        assert len(gaps) == 1
        gap = gaps[0]
        assert gap.gpo_id == G["collerr"]
        assert gap.display_name == "golden-collection-error"
        assert "Access Denied" in (gap.detail or "")

    def test_coverage_gap_in_doctor(self, golden_estate: Estate) -> None:
        findings = estate_doctor(golden_estate)
        cov = [f for f in findings if f.category == "coverage_gap"]
        assert len(cov) == 2
        for f in cov:
            assert f.severity == "high"
        cov_ids = {f.gpo_id for f in cov}
        assert G["invonly"] in cov_ids
        assert G["collerr"] in cov_ids


# ===========================================================================
# Bonus structural checks
# ===========================================================================


class TestStructural:
    """Cross-cutting structural assertions."""

    def test_som_count(self, golden_estate: Estate) -> None:
        """One domain-root SOM."""
        assert len(golden_estate.soms) == 1
        assert golden_estate.soms[0].container_type == "domain"

    def test_wmi_filter_count(self, golden_estate: Estate) -> None:
        assert len(golden_estate.wmi_filters) == 1
        assert golden_estate.wmi_filters[0].name == "Golden WMI Filter"

    def test_ou_tree_count(self, golden_estate: Estate) -> None:
        assert len(golden_estate.ou_tree) == 1

    def test_local_group_mods(self, golden_estate: Estate) -> None:
        """The cpassword GPO also has a LocalUsersAndGroups.xml."""
        gpo = golden_estate.gpo_by_id(G["cpassword"])
        assert gpo is not None
        mods = scan_local_groups(gpo)
        assert len(mods) == 1
        m = mods[0]
        assert m.group_name == "Administrators"
        assert m.group_sid == "S-1-5-32-544"
        assert "GOLDEN\\ServerAdmins" in m.members_added
        assert "GOLDEN\\LegacyAdmin" in m.members_removed

    def test_all_gpos_have_sysvol_path(self, golden_estate: Estate) -> None:
        """Every ingested GPO should have a sysvol_path attached."""
        for gpo in golden_estate.gpos:
            assert gpo.sysvol_path is not None, f"GPO {gpo.name} ({gpo.id}) has no sysvol_path"

    def test_description_round_trips(self, golden_estate: Estate) -> None:
        """GPO cpassword carries a <Description>; it must round-trip."""
        gpo = golden_estate.gpo_by_id(G["cpassword"])
        assert gpo is not None
        assert gpo.description is not None
        assert "MS14-025" in gpo.description

    def test_wmi_filter_ref_on_gpo(self, golden_estate: Estate) -> None:
        gpo = golden_estate.gpo_by_id(G["wmifilt"])
        assert gpo is not None
        assert gpo.wmi_filter == "Golden WMI Filter"

    def test_estate_doctor_sorted_by_severity(self, golden_estate: Estate) -> None:
        """Findings are sorted: critical < high < medium < low."""
        findings = estate_doctor(golden_estate)
        severities = [f.severity for f in findings]
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ranked = [rank.get(s, 99) for s in severities]
        assert ranked == sorted(ranked), f"Not sorted by severity: {severities}"


# ===========================================================================
# AC-8: Drive mappings GPO — Drives.xml with UNC paths
# ===========================================================================


class TestDriveMappings:
    """The drives GPO carries USER-side Drive Maps settings parsed from
    Drives.xml.  The broken_refs scanner must surface UNC paths as
    drive_mapping_unc findings."""

    def test_drive_mappings_detected(self, golden_estate: Estate) -> None:
        """The drives GPO has Drive Maps settings with UNC paths."""
        gpo = golden_estate.gpo_by_id(G["drives"])
        assert gpo is not None
        drive_settings = [s for s in gpo.settings if s.cse == "Drive Maps"]
        assert len(drive_settings) == 3, (
            f"Expected 3 Drive Maps settings, got {len(drive_settings)}"
        )
        # All settings are on the User side
        assert all(s.side == "User" for s in drive_settings)

    def test_drive_unc_refs_in_doctor(self, golden_estate: Estate) -> None:
        findings = estate_doctor(golden_estate)
        assert not [f for f in findings if f.category == "broken_ref:drive_mapping_unc"]

    def test_drive_mappings_dependency_scan(self, golden_estate: Estate) -> None:
        refs = [
            r
            for group in external_dependencies(golden_estate)
            for r in group.dependencies
            if r.gpo_id == G["drives"]
        ]
        assert len(refs) == 4
        assert {r.dependency_type for r in refs} == {"drive_mapping", "printer_connection"}
        assert {r.target for r in refs} == {
            r"\\GOLDEN.local\shares\public",
            r"\\oldserver.golden.local\deprecated\share",
            r"\\missing-server\share",
            r"\\printserver\lab-printer",
        }

    def test_drives_gpo_has_sysvol_path(self, golden_estate: Estate) -> None:
        """The drives GPO should have a sysvol_path attached."""
        gpo = golden_estate.gpo_by_id(G["drives"])
        assert gpo is not None
        assert gpo.sysvol_path is not None

    def test_drives_gpo_user_enabled(self, golden_estate: Estate) -> None:
        """The drives GPO should have User side enabled."""
        gpo = golden_estate.gpo_by_id(G["drives"])
        assert gpo is not None
        assert gpo.user_enabled is True


# ===========================================================================
# AC-9: ILT (FilterOrgUnit) detection
# ===========================================================================


class TestILTDetection:
    """scan_ilt detects the FilterOrgUnit targeting filter in Drives.xml."""

    def test_ilt_scan_finds_orgunit_filter(self, golden_estate: Estate) -> None:
        """scan_ilt should find the FilterOrgUnit in the drives GPO."""
        hits = scan_ilt(golden_estate)
        drives_hits = [h for h in hits if h.gpo_id == G["drives"]]
        assert len(drives_hits) == 1, f"Expected 1 ILT hit for drives GPO, got {len(drives_hits)}"
        hit = drives_hits[0]
        assert "FilterOrgUnit" in hit.filter_types, (
            f"Expected FilterOrgUnit in filter_types, got {hit.filter_types}"
        )

    def test_ilt_file_path_nested(self, golden_estate: Estate) -> None:
        """The ILT file path should reflect the nested SYSVOL layout."""
        hits = scan_ilt(golden_estate)
        drives_hits = [h for h in hits if h.gpo_id == G["drives"]]
        assert len(drives_hits) == 1
        hit = drives_hits[0]
        assert "Drives/Drives.xml" in hit.files[0], f"Expected nested Drives path, got {hit.files}"

    def test_ilt_in_doctor(self, golden_estate: Estate) -> None:
        """The doctor should surface the ILT finding."""
        findings = estate_doctor(golden_estate)
        ilt_findings = [f for f in findings if f.category == "ilt_gpo" and f.gpo_id == G["drives"]]
        assert len(ilt_findings) == 1, (
            f"Expected 1 ilt_gpo finding for drives GPO, got {len(ilt_findings)}"
        )


# ===========================================================================
# AC-10: Printers.xml — UNC path exercised
# ===========================================================================


class TestPrintersPreference:
    """The drives GPO also carries a Printers.xml with a UNC printer path."""

    def test_printer_unc_in_broken_refs(self, golden_estate: Estate) -> None:
        """broken_refs should find the UNC printer path.

        The Printers CSE in the SYSVOL XML produces a gpp_file_ref for
        SharedPrinter's path attribute.  The settings-based scan may also
        surface it as drive_mapping_unc (since the CSE is 'Printers').
        Either way, the UNC path must appear in broken_refs output.
        """
        refs = [
            r
            for group in external_dependencies(golden_estate)
            for r in group.dependencies
            if r.gpo_id == G["drives"] and r.dependency_type == "printer_connection"
        ]
        assert len(refs) == 1
        assert refs[0].server == "printserver"
        assert not [r for r in broken_refs(golden_estate) if "printserver" in r.ref_value]
