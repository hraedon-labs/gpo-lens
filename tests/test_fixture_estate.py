"""Structural assertions against the synthetic fixture estate.

These run without the real (gitignored) samples/ directory, so they can gate CI.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from gpo_lens.ingest import load_estate
from gpo_lens.queries import (
    admx_gaps,
    blocked_extensions,
    broken_refs,
    broken_wmi_refs,
    conflicts,
    cpassword_scan,
    dangling_links,
    disabled_but_populated,
    effective_scope,
    empty_gpos,
    enforced_links,
    estate_doctor,
    external_dependencies,
    is_security_filtered,
    loopback_awareness,
    loopback_gpos,
    ms16_072_vulnerable,
    orphaned_wmi_filters,
    scope_caveats,
    settings_at_som,
    som_conflicts,
    stale_gpos,
    topology_crosscheck,
    unlinked_gpos,
    version_skew,
    wmi_filtered_gpos,
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

GPO_IDS = {
    "cpassword": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "ms16_072": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version_skew": "cccccccccccccccccccccccccccccccc",
    "broken_unc": "dddddddddddddddddddddddddddddddd",
    "loopback": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "blocked_ext": "ffffffffffffffffffffffffffffffff",
    "user_disabled": "11111111111111111111111111111111",
    "conflict": "22222222222222222222222222222222",
    "loopback_merge": "33333333333333333333333333333333",
    "loopback_unknown": "44444444444444444444444444444444",
    "security_filtered": "55555555555555555555555555555555",
    "wmi_broken_ref": "66666666666666666666666666666666",
    "gpp_ilt": "77777777777777777777777777777777",
    "stale": "88888888888888888888888888888888",
}
GPO_NAMES = {
    "cpassword": "gpo-cpassword",
    "ms16_072": "gpo-ms16-072-vuln",
    "version_skew": "gpo-version-skew",
    "broken_unc": "gpo-broken-unc",
    "loopback": "gpo-loopback",
    "blocked_ext": "gpo-blocked-ext",
    "user_disabled": "gpo-user-disabled",
    "conflict": "gpo-conflict",
    "loopback_merge": "gpo-loopback-merge",
    "loopback_unknown": "gpo-loopback-unknown",
    "security_filtered": "gpo-security-filtered",
    "wmi_broken_ref": "gpo-wmi-broken-ref",
    "gpp_ilt": "gpo-gpp-ilt",
    "stale": "gpo-stale",
}
ROOT_DN = "dc=fakefixture,dc=local"
CHILD_DN = "ou=child,dc=fakefixture,dc=local"


@pytest.fixture(scope="session")
def fixture_estate():
    return load_estate(FIXTURE_DIR)


# AC-1: fixture loads via load_estate


def test_fixture_gpo_count(fixture_estate):
    assert len(fixture_estate.gpos) == 14


def test_fixture_som_counts(fixture_estate):
    ou_soms = [s for s in fixture_estate.soms if s.container_type != "site"]
    assert len(ou_soms) == 2
    assert sum(1 for s in ou_soms if s.inheritance_blocked) == 1
    # Two AD sites: one unlinked, one with an enforced GPO link.
    site_soms = [s for s in fixture_estate.soms if s.container_type == "site"]
    assert len(site_soms) == 2


# AC-2: calibration assertions ported to fixture


def test_fixture_disabled_but_populated(fixture_estate):
    hits = disabled_but_populated(fixture_estate)
    assert len(hits) == 2
    # GPO C has Computer side disabled but with settings
    assert any(g.id == GPO_IDS["version_skew"] and side == "Computer" for g, side in hits)
    # GPO G has User side disabled but with settings
    assert any(g.id == GPO_IDS["user_disabled"] and side == "User" for g, side in hits)


def test_fixture_enforced_flag_is_boolean(fixture_estate):
    links = [link for g in fixture_estate.gpos for link in g.links]
    assert links
    assert all(isinstance(link.enforced, bool) for link in links)
    # Also assert at least one enforced link exists (GPO C)
    assert any(link.enforced for link in links)


def test_fixture_enforced_links(fixture_estate):
    links = enforced_links(fixture_estate)
    assert len(links) >= 1
    # At least one enforced link at domain root
    root_links = [lnk for s, lnk in links if s.path == ROOT_DN]
    assert any(lnk.gpo_id == GPO_IDS["version_skew"] for lnk in root_links)


def test_fixture_loopback_detected(fixture_estate):
    hits = loopback_gpos(fixture_estate)
    assert len(hits) == 3
    gpo_ids = {g.id for g, _ in hits}
    assert GPO_IDS["loopback"] in gpo_ids
    assert GPO_IDS["loopback_merge"] in gpo_ids
    assert GPO_IDS["loopback_unknown"] in gpo_ids
    for g, setting in hits:
        assert setting.side == "Computer"
        assert "loopback" in setting.identity.lower()


def test_fixture_loopback_awareness(fixture_estate):
    awareness = loopback_awareness(fixture_estate)
    assert len(awareness) == 3
    assert awareness[GPO_IDS["loopback"]] == "replace"
    assert awareness[GPO_IDS["loopback_merge"]] == "merge"
    assert awareness[GPO_IDS["loopback_unknown"]] == "unknown"


def test_fixture_version_skew(fixture_estate):
    hits = version_skew(fixture_estate)
    assert len(hits) == 1
    gpo, side = hits[0]
    assert gpo.name == "gpo-version-skew"
    assert side == "Computer"


def test_fixture_ms16_072(fixture_estate):
    vuln = ms16_072_vulnerable(fixture_estate)
    assert len(vuln) == 2
    vuln_names = {g.name for g in vuln}
    assert "gpo-ms16-072-vuln" in vuln_names
    assert "gpo-security-filtered" in vuln_names


def test_fixture_cpassword_hit(fixture_estate):
    hits = cpassword_scan(fixture_estate)
    assert len(hits) == 1
    assert hits[0].gpo_name == "gpo-cpassword"


def test_fixture_broken_unc(fixture_estate):
    assert broken_refs(fixture_estate) == []
    hits = [r for group in external_dependencies(fixture_estate) for r in group.dependencies]
    unc_hits = [h for h in hits if h.dependency_type == "unc_path"]
    assert len(unc_hits) == 1
    assert unc_hits[0].gpo_id == GPO_IDS["broken_unc"]
    assert "\\oldserver\\share" in unc_hits[0].target


def test_fixture_no_dangling_links(fixture_estate):
    assert len(dangling_links(fixture_estate)) == 0


def test_fixture_settings_at_som(fixture_estate):
    # Domain root should have effective settings from the chain
    result = settings_at_som(fixture_estate, ROOT_DN)
    assert len(result) > 0
    for es in result:
        assert es.winner_gpo_id
        assert es.winner_gpo_name
        assert es.identity
    # GPO C (version_skew) is the only enforced-link GPO at root, but its
    # Computer side is DISABLED — its settings are disabled-side ghosts and
    # must NOT appear as effective (charter: flag, don't simulate). They are
    # surfaced separately by disabled_but_populated().
    enforced_ids = {es.winner_gpo_id for es in result if es.enforced}
    assert GPO_IDS["version_skew"] not in enforced_ids
    assert not any(es.winner_gpo_id == GPO_IDS["version_skew"] for es in result)
    # At least one overridden_by populated (the D/H BadValue conflict at child)
    assert any(es.overridden_by for es in result)


# AC-1 additional sanity checks


def test_fixture_domain(fixture_estate):
    assert fixture_estate.domain == "fakefixture.local"


def test_fixture_description_parsed(fixture_estate):
    """GPO A carries a <Description>; it must round-trip into Gpo.description."""
    gpo_a = fixture_estate.gpo_by_id(GPO_IDS["cpassword"])
    assert gpo_a is not None
    assert gpo_a.description == ("Baseline domain security; do not modify without change review.")
    # GPOs without <Description> parse to None.
    gpo_b = fixture_estate.gpo_by_id(GPO_IDS["ms16_072"])
    assert gpo_b is not None
    assert gpo_b.description is None


def test_fixture_gpp_scanners_find_tasks_and_groups(fixture_estate):
    """The fixture's GPO A carries ScheduledTasks.xml + LocalUsersAndGroups.xml;
    the structured scanners must surface them."""
    from gpo_lens.detection import local_group_mods, scheduled_tasks

    tasks = scheduled_tasks(fixture_estate)
    assert len(tasks) == 2
    names = {t.name for t in tasks}
    assert {"Update App Catalog", "OneShot Bootstrap"} <= names
    # The SYSTEM-run task is the higher-signal finding for an audit.
    sys_task = next(t for t in tasks if t.run_as == "NT AUTHORITY\\SYSTEM")
    assert sys_task.command.endswith("app.exe")

    mods = local_group_mods(fixture_estate)
    assert len(mods) == 1
    m = mods[0]
    assert m.group_name == "Administrators"
    assert m.group_sid == "S-1-5-32-544"
    assert "FAKEFIXTURE\\Tier1Admins" in m.members_added
    assert "FAKEFIXTURE\\LegacyAdmin" in m.members_removed


def test_fixture_wmi_filter_count(fixture_estate):
    assert len(fixture_estate.wmi_filters) == 2


def test_fixture_ou_tree(fixture_estate):
    assert len(fixture_estate.ou_tree) == 2
    child = next(ou for ou in fixture_estate.ou_tree if ou.dn == CHILD_DN)
    assert child.gp_options == 1


def test_fixture_estate_doctor(fixture_estate):
    from gpo_lens.queries import estate_summary

    summary = estate_summary(fixture_estate)
    assert summary.gpo_count == 14
    assert summary.som_count == 2
    assert summary.ms16_072_vulnerable_count == 2
    assert summary.cpassword_hit_count == 1
    assert summary.version_skew_count == 1
    assert summary.loopback_gpo_count == 3
    assert summary.broken_ref_count == 0
    # 2 OU/domain enforced links + 1 enforced site link.
    assert summary.enforced_link_count == 3
    assert summary.linked_site_count == 1
    assert summary.dangling_link_count == 0


def test_fixture_estate_doctor_findings(fixture_estate):
    findings = estate_doctor(fixture_estate)
    # Find specific findings by category
    cpassword_finds = [f for f in findings if f.category == "cpassword"]
    assert len(cpassword_finds) == 1
    assert cpassword_finds[0].severity == "critical"
    assert cpassword_finds[0].gpo_id == GPO_IDS["cpassword"]

    ms16_finds = [f for f in findings if f.category == "ms16_072"]
    assert len(ms16_finds) == 2
    assert all(f.severity == "high" for f in ms16_finds)
    ms16_gpo_ids = {f.gpo_id for f in ms16_finds}
    assert GPO_IDS["ms16_072"] in ms16_gpo_ids
    assert GPO_IDS["security_filtered"] in ms16_gpo_ids

    skew_finds = [f for f in findings if f.category == "version_skew"]
    assert len(skew_finds) == 1
    assert skew_finds[0].severity == "medium"
    assert skew_finds[0].gpo_id == GPO_IDS["version_skew"]

    disabled_finds = [f for f in findings if f.category == "disabled_but_populated"]
    assert len(disabled_finds) == 2  # Computer (GPO C) + User (GPO G)
    assert all(f.severity == "low" for f in disabled_finds)

    # Verify sort order: critical before high before medium before low
    severities = [f.severity for f in findings]
    assert severities.index("critical") < severities.index("high")
    assert severities.index("high") < severities.index("medium")
    assert severities.index("medium") < severities.index("low")


def test_fixture_topology_crosscheck(fixture_estate):
    discrepancies = topology_crosscheck(fixture_estate)
    assert discrepancies == [], f"Unexpected topology discrepancies: {discrepancies}"


def test_fixture_wmi_filtered_gpos(fixture_estate):
    hits = wmi_filtered_gpos(fixture_estate)
    assert len(hits) == 2
    hit_ids = {g.id for g in hits}
    assert GPO_IDS["loopback"] in hit_ids
    assert GPO_IDS["wmi_broken_ref"] in hit_ids


def test_fixture_admx_gaps_detected(fixture_estate):
    hits = admx_gaps(fixture_estate)
    # GPO D and GPO H both have HKLM\Software\Fake:BadValue
    gap_gpos = {h.gpo_id for h in hits}
    assert GPO_IDS["broken_unc"] in gap_gpos
    assert GPO_IDS["conflict"] in gap_gpos


def test_fixture_blocked_extensions(fixture_estate):
    hits = blocked_extensions(fixture_estate)
    assert len(hits) == 1
    gpo, side, cse = hits[0]
    assert gpo.id == GPO_IDS["blocked_ext"]
    assert side == "Computer"
    assert cse == "Registry"


def test_fixture_som_conflicts(fixture_estate):
    hits = som_conflicts(fixture_estate, ROOT_DN)
    # GPO D and GPO H both set HKLM\Software\Fake:BadValue with different values
    assert len(hits) >= 1
    conflict = next(h for h in hits if h.identity == r"HKLM\Software\Fake:BadValue")
    assert conflict is not None
    gpo_names_in_conflict = {e[0] for e in conflict.entries}
    assert GPO_NAMES["broken_unc"] in gpo_names_in_conflict
    assert GPO_NAMES["conflict"] in gpo_names_in_conflict


def test_fixture_empty_gpos(fixture_estate):
    hits = empty_gpos(fixture_estate)
    # MS16-072 GPO should be empty (no settings)
    assert any(g.id == GPO_IDS["ms16_072"] for g in hits)


def test_fixture_unlinked_gpos(fixture_estate):
    # All 14 GPOs have links in the fixture
    hits = unlinked_gpos(fixture_estate)
    assert len(hits) == 0


def test_fixture_conflicts(fixture_estate):
    hits = conflicts(fixture_estate)
    # GPO D and GPO H both set the same registry key with different values
    conflict = next((c for c in hits if c.identity == r"HKLM\Software\Fake:BadValue"), None)
    assert conflict is not None
    gpo_ids_in_conflict = {e[0] for e in conflict.entries}
    assert GPO_IDS["broken_unc"] in gpo_ids_in_conflict
    assert GPO_IDS["conflict"] in gpo_ids_in_conflict


# ---------------------------------------------------------------------------
# Scope honesty tests (Plan 013 Workstream S)
# ---------------------------------------------------------------------------


def test_fixture_security_filtered(fixture_estate):
    sec_gpo = fixture_estate.gpo_by_id(GPO_IDS["security_filtered"])
    assert sec_gpo is not None
    assert is_security_filtered(sec_gpo)
    # Normal GPOs should NOT be filtered
    normal_gpo = fixture_estate.gpo_by_id(GPO_IDS["cpassword"])
    assert normal_gpo is not None
    assert not is_security_filtered(normal_gpo)


def test_fixture_effective_scope(fixture_estate):
    scope = effective_scope(fixture_estate, GPO_IDS["security_filtered"])
    assert scope is not None
    assert scope.security_filtering.is_filtered
    assert any("security-filtered" in c.lower() for c in scope.caveats)

    scope_normal = effective_scope(fixture_estate, GPO_IDS["cpassword"])
    assert scope_normal is not None
    assert not scope_normal.security_filtering.is_filtered


def test_fixture_effective_scope_by_name(fixture_estate):
    scope = effective_scope(fixture_estate, "gpo-security-filtered")
    assert scope is not None
    assert scope.gpo_id == GPO_IDS["security_filtered"]


def test_fixture_effective_scope_not_found(fixture_estate):
    assert effective_scope(fixture_estate, "nonexistent-gpo") is None


def test_fixture_effective_scope_wmi(fixture_estate):
    scope = effective_scope(fixture_estate, GPO_IDS["wmi_broken_ref"])
    assert scope is not None
    assert scope.wmi_filter is not None
    assert scope.wmi_filter.is_broken


def test_fixture_orphaned_wmi_filters(fixture_estate):
    orphans = orphaned_wmi_filters(fixture_estate)
    orphan_names = {f.name for f in orphans}
    assert "Orphaned WMI Filter" in orphan_names


def test_fixture_broken_wmi_refs(fixture_estate):
    refs = broken_wmi_refs(fixture_estate)
    assert len(refs) == 1
    assert refs[0].gpo_id == GPO_IDS["wmi_broken_ref"]
    assert refs[0].filter_name == "Nonexistent WMI Filter"


def test_fixture_scope_caveats(fixture_estate):
    caveats = scope_caveats(fixture_estate, ROOT_DN)
    # Root has security-filtered GPO + WMI-filtered GPO + loopback GPOs in scope
    assert len(caveats) > 0
    assert any("security-filtered" in c.lower() for c in caveats)


# Pinned reference clock so staleness assertions stay deterministic as real
# time advances past the fixture's fixed timestamps (stale GPO: 2022-01-01,
# recent GPO: 2025-06-01). See stale_gpos(now=...).
_STALE_REF_NOW = datetime(2026, 6, 13, tzinfo=UTC)


def test_fixture_stale_gpos(fixture_estate):
    stale = stale_gpos(fixture_estate, threshold_years=2, now=_STALE_REF_NOW)
    stale_ids = {g.id for g, _ in stale}
    assert GPO_IDS["stale"] in stale_ids
    # Recent GPOs should not be flagged
    assert GPO_IDS["cpassword"] not in stale_ids


def test_fixture_stale_gpos_threshold(fixture_estate):
    stale = stale_gpos(fixture_estate, threshold_years=10, now=_STALE_REF_NOW)
    assert len(stale) == 0


def test_fixture_ilt_detection(fixture_estate):
    from gpo_lens.detection import scan_ilt

    hits = scan_ilt(fixture_estate)
    ilt_ids = {h.gpo_id for h in hits}
    assert GPO_IDS["gpp_ilt"] in ilt_ids


def test_fixture_doctor_new_categories(fixture_estate):
    findings = estate_doctor(fixture_estate, now=_STALE_REF_NOW)
    categories = {f.category for f in findings}

    assert "broken_wmi_ref" in categories
    assert "orphaned_wmi_filter" in categories
    assert "ilt_gpo" in categories
    assert "stale_gpo" in categories

    broken = [f for f in findings if f.category == "broken_wmi_ref"]
    assert broken[0].gpo_id == GPO_IDS["wmi_broken_ref"]

    stale = [f for f in findings if f.category == "stale_gpo"]
    assert stale[0].gpo_id == GPO_IDS["stale"]

    orphan = [f for f in findings if f.category == "orphaned_wmi_filter"]
    assert "Orphaned WMI Filter" in orphan[0].summary
