"""Unit tests for Tier-1 queries (no samples required)."""

from __future__ import annotations

import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path

from gpo_lens import queries
from gpo_lens.admx_parser import AdmxPolicy, PolicyDefinitions
from gpo_lens.model import DelegationEntry, Estate, Gpo, OuRecord, ResolvedPrincipal, Setting


def _make_gpo(**kwargs) -> Gpo:
    defaults = {
        "id": "31b2f340016d11d2945f00c04fb984f9",
        "name": "Test GPO",
        "domain": "test.local",
        "created": None,
        "modified": None,
        "read": None,
        "computer_enabled": True,
        "user_enabled": True,
        "computer_ver_ds": None,
        "computer_ver_sysvol": None,
        "user_ver_ds": None,
        "user_ver_sysvol": None,
        "sddl": None,
        "owner": None,
        "filter_data_available": False,
        "wmi_filter": None,
        "sysvol_path": None,
    }
    defaults.update(kwargs)
    return Gpo(**defaults)


# ---- version_skew ----------------------------------------------------------


def test_version_skew_none():
    estate = Estate(gpos=[_make_gpo()])
    assert queries.version_skew(estate) == []


def test_version_skew_computer():
    gpo = _make_gpo(computer_ver_ds=1, computer_ver_sysvol=2)
    estate = Estate(gpos=[gpo])
    assert queries.version_skew(estate) == [(gpo, "Computer")]


def test_version_skew_user():
    gpo = _make_gpo(user_ver_ds=1, user_ver_sysvol=2)
    estate = Estate(gpos=[gpo])
    assert queries.version_skew(estate) == [(gpo, "User")]


def test_version_skew_both_sides():
    gpo = _make_gpo(computer_ver_ds=1, computer_ver_sysvol=2, user_ver_ds=3, user_ver_sysvol=4)
    estate = Estate(gpos=[gpo])
    results = queries.version_skew(estate)
    assert len(results) == 2
    assert (gpo, "Computer") in results
    assert (gpo, "User") in results


def test_version_skew_equal_versions():
    gpo = _make_gpo(computer_ver_ds=5, computer_ver_sysvol=5)
    estate = Estate(gpos=[gpo])
    assert queries.version_skew(estate) == []


def test_version_skew_one_none():
    """If one version is None (not collected) and the other is known,
    that is not skew — unknown vs known is not a mismatch."""
    gpo = _make_gpo(computer_ver_ds=5, computer_ver_sysvol=None)
    estate = Estate(gpos=[gpo])
    assert queries.version_skew(estate) == []


# ---- ms16_072 --------------------------------------------------------------


def test_ms16_072_empty_delegation():
    gpo = _make_gpo(delegation=[])
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == [gpo]


def test_ms16_072_has_au_read():
    """AU with Read is sufficient."""
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x",
                trustee="Authenticated Users",
                trustee_sid=None,
                permission="Read",
                allowed=True,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == []


def test_ms16_072_has_dc_read():
    """DC with Read is sufficient."""
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x",
                trustee="Domain Computers",
                trustee_sid="S-1-5-21-123-515",
                permission="Read",
                allowed=True,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == []


def test_ms16_072_custom_permission_is_vulnerable():
    """A broad trustee with only "Custom" grouped access does not imply Read.

    "Custom" is the one standard GPMC grouping that does not necessarily
    include the READ access right, so it cannot satisfy MS16-072.
    """
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x",
                trustee="Authenticated Users",
                trustee_sid=None,
                permission="Custom",
                allowed=True,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == [gpo]


def test_ms16_072_denied_read():
    """Denied Read counts as missing."""
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x",
                trustee="Authenticated Users",
                trustee_sid=None,
                permission="Read",
                allowed=False,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == [gpo]


def test_ms16_072_case_insensitive():
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x",
                trustee="authenticated users",
                trustee_sid=None,
                permission="read",
                allowed=True,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == []


def test_ms16_072_dc_read_via_sid():
    """DC matched by SID ending in -515."""
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x",
                trustee="SomeGroup",
                trustee_sid="S-1-5-21-123-515",
                permission="Read",
                allowed=True,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == []


def test_ms16_072_dc_sid_requires_domain_prefix():
    """A SID ending in -515 but outside S-1-5-21-* must NOT match Domain Computers.

    Previously `endswith("-515")` matched any such SID (e.g. a builtin-domain
    group), producing a false MS16-072 pass. The check now requires the
    domain-SID prefix.
    """
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x",
                trustee="Backup-thing",
                trustee_sid="S-1-5-32-515",
                permission="Read",
                allowed=True,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    # The bogus -515 SID is not Domain Computers → no broad read → vulnerable.
    assert gpo in queries.ms16_072_vulnerable(estate)


# ---- ms16_072 golden / behavior-preservation cases -------------------------


def test_ms16_072_apply_group_policy_is_not_vulnerable():
    """ "Apply Group Policy" IS Read+Apply (GpoApply) — it satisfies MS16-072.

    Per Microsoft (gpmgmt.h GPMPermissionType / KB MS16-072), permGPOApply
    "corresponds to the READ and APPLY Group Policy access rights"; GPMC shows
    it on the Delegation tab as "Read (from Security Filtering)". Treating it as
    non-Read flagged every default-filtered GPO as MS16-072 vulnerable.
    """
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x",
                trustee="Authenticated Users",
                trustee_sid=None,
                permission="Apply Group Policy",
                allowed=True,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == []


def test_ms16_072_edit_settings_is_not_vulnerable():
    """Edit settings is treated as Read-implying by the MS16-072 check."""
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x",
                trustee="Authenticated Users",
                trustee_sid=None,
                permission="Edit settings",
                allowed=True,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == []


def test_ms16_072_edit_delete_modify_security_variant_is_not_vulnerable():
    """Real GPMC emits "Edit, delete, modify security" (no "settings") — Read-implying."""
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x",
                trustee="Authenticated Users",
                trustee_sid=None,
                permission="Edit, delete, modify security",
                allowed=True,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == []


def test_ms16_072_narrow_trustee_with_read_is_vulnerable():
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x",
                trustee="Helpdesk Operators",
                trustee_sid="S-1-5-21-999-1000",
                permission="Read",
                allowed=True,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == [gpo]


def test_ms16_072_allow_plus_deny_same_trustee_not_vulnerable():
    """MS16-072 only examines allowed entries; a paired deny is ignored."""
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x",
                trustee="Authenticated Users",
                trustee_sid=None,
                permission="Read",
                allowed=True,
            ),
            DelegationEntry(
                gpo_id="x",
                trustee="Authenticated Users",
                trustee_sid=None,
                permission="Read",
                allowed=False,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    # The allow entry is sufficient; the deny entry is not subtracted.
    assert queries.ms16_072_vulnerable(estate) == []


def test_ms16_072_bogus_515_sid_is_vulnerable():
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x",
                trustee="Builtin-515",
                trustee_sid="S-1-5-32-515",
                permission="Read",
                allowed=True,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == [gpo]


# ---- delegation_deep_dive --------------------------------------------------


def test_delegation_deep_dive_privilege_rollup():
    gpo_a = _make_gpo(
        id="gpo-a",
        name="Alpha",
        delegation=[
            DelegationEntry(
                gpo_id="gpo-a",
                trustee="Rogue Admin",
                trustee_sid=None,
                permission="Edit settings, delete, modify security",
                allowed=True,
            ),
        ],
    )
    gpo_b = _make_gpo(
        id="gpo-b",
        name="Beta",
        delegation=[
            DelegationEntry(
                gpo_id="gpo-b",
                trustee="Rogue Admin",
                trustee_sid=None,
                permission="Edit settings, delete, modify security",
                allowed=True,
            ),
        ],
    )
    estate = Estate(gpos=[gpo_a, gpo_b])
    audit = queries.delegation_deep_dive(estate)
    assert "Rogue Admin" in audit.privilege_rollup
    assert sorted(audit.privilege_rollup["Rogue Admin"]) == ["Alpha", "Beta"]


def test_delegation_deep_dive_orphaned_sid():
    gpo = _make_gpo(
        id="gpo-1",
        name="Test",
        delegation=[
            DelegationEntry(
                gpo_id="gpo-1",
                trustee="",
                trustee_sid="S-1-5-21-999999",
                permission="Read",
                allowed=True,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    audit = queries.delegation_deep_dive(estate)
    assert len(audit.orphaned_sids) == 1
    assert audit.orphaned_sids[0][0].id == "gpo-1"
    assert audit.orphaned_sids[0][1] == "S-1-5-21-999999"


def test_delegation_deep_dive_broad_writers():
    gpo = _make_gpo(
        id="gpo-1",
        name="Test",
        delegation=[
            DelegationEntry(
                gpo_id="gpo-1",
                trustee="Domain Admins",
                trustee_sid=None,
                permission="Edit settings",
                allowed=True,
            ),
            DelegationEntry(
                gpo_id="gpo-1",
                trustee="Rogue Editor",
                trustee_sid=None,
                permission="Edit settings",
                allowed=True,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    audit = queries.delegation_deep_dive(estate)
    broad_names = {d.trustee for _, d in audit.broad_writers}
    assert "Rogue Editor" in broad_names
    assert "Domain Admins" not in broad_names


def test_delegation_deep_dive_no_issues():
    gpo = _make_gpo(
        id="gpo-1",
        name="Test",
        delegation=[
            DelegationEntry(
                gpo_id="gpo-1",
                trustee="Domain Admins",
                trustee_sid=None,
                permission="Read",
                allowed=True,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    audit = queries.delegation_deep_dive(estate)
    assert audit.orphaned_sids == []
    assert audit.broad_writers == []
    assert audit.privilege_rollup == {}
    assert audit.deny_aces == []
    assert audit.excessive_writers == []


# ---- cpassword_scan --------------------------------------------------------


def test_cpassword_scan_no_sysvol_path(tmp_path):
    gpo = _make_gpo(sysvol_path=None)
    estate = Estate(gpos=[gpo])
    assert queries.cpassword_scan(estate) == []


def test_cpassword_scan_clean(tmp_path):
    gpo_dir = tmp_path / "gpo"
    gpo_dir.mkdir()
    prefs = gpo_dir / "Machine" / "Preferences"
    prefs.mkdir(parents=True)
    (prefs / "Groups.xml").write_text("<Groups/>")
    gpo = _make_gpo(sysvol_path=str(gpo_dir))
    estate = Estate(gpos=[gpo])
    assert queries.cpassword_scan(estate) == []


def test_cpassword_scan_finds_hit(tmp_path):
    gpo_dir = tmp_path / "gpo"
    gpo_dir.mkdir()
    prefs = gpo_dir / "Machine" / "Preferences"
    prefs.mkdir(parents=True)
    root = ET.Element("Groups")
    user = ET.SubElement(root, "User")
    user.set("cpassword", "ABCD1234")
    tree = ET.ElementTree(root)
    tree.write(prefs / "Groups.xml")
    gpo = _make_gpo(id="abc", name="GPO", sysvol_path=str(gpo_dir))
    estate = Estate(gpos=[gpo])
    hits = queries.cpassword_scan(estate)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.gpo_id == "abc"
    assert hit.gpo_name == "GPO"
    assert Path(hit.file) == Path("Machine/Preferences/Groups.xml")
    assert hit.tag == "User"
    assert hit.cpassword == "ABCD1234"


def test_cpassword_scan_skips_broken_xml(tmp_path):
    gpo_dir = tmp_path / "gpo"
    gpo_dir.mkdir()
    prefs = gpo_dir / "Machine" / "Preferences"
    prefs.mkdir(parents=True)
    (prefs / "Groups.xml").write_text("not xml")
    gpo = _make_gpo(sysvol_path=str(gpo_dir))
    estate = Estate(gpos=[gpo])
    assert queries.cpassword_scan(estate) == []


# ---- topology queries ------------------------------------------------------


def test_som_effective_gpos():
    from gpo_lens.model import Som, SomLink

    gpo = _make_gpo(id="gpo-1", name="Test GPO")
    som = Som(
        path="ou=workstations,dc=test,dc=local",
        name="Workstations",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(
                gpo_id="gpo-1",
                order=1,
                enabled=True,
                enforced=False,
                target="ou=workstations,dc=test,dc=local",
            ),
        ],
    )
    estate = Estate(gpos=[gpo], soms=[som])
    result = queries.som_effective_gpos(estate, "ou=workstations,dc=test,dc=local")
    assert len(result) == 1
    assert result[0].gpo_id == "gpo-1"
    assert result[0].gpo_name == "Test GPO"


def test_som_effective_gpos_case_insensitive():
    from gpo_lens.model import Som, SomLink

    gpo = _make_gpo(id="gpo-1", name="Test GPO")
    som = Som(
        path="OU=Workstations,DC=test,DC=local",
        name="Workstations",
        container_type="ou",
        inheritance_blocked=False,
        links=[SomLink(gpo_id="gpo-1", order=1, enabled=True, enforced=False, target="")],
    )
    estate = Estate(gpos=[gpo], soms=[som])
    result = queries.som_effective_gpos(estate, "ou=workstations,dc=test,dc=local")
    assert len(result) == 1


def test_som_effective_gpos_parent_ou_walk():
    """When the target SOM is not in the estate, walk up the DN to find a parent SOM."""
    from gpo_lens.model import Som, SomLink

    gpo = _make_gpo(id="gpo-1", name="Parent GPO")
    parent_som = Som(
        path="ou=parent,dc=test,dc=local",
        name="Parent",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(
                gpo_id="gpo-1",
                order=1,
                enabled=True,
                enforced=False,
                target="ou=parent,dc=test,dc=local",
            ),
        ],
    )
    estate = Estate(gpos=[gpo], soms=[parent_som])

    # Query for a child OU that is NOT in the estate — should fall back to parent.
    result = queries.som_effective_gpos(
        estate,
        "ou=child,ou=parent,dc=test,dc=local",
    )
    assert len(result) == 1
    assert result[0].gpo_id == "gpo-1"
    assert result[0].gpo_name == "Parent GPO"


def test_som_effective_gpos_no_parent_found():
    """When no parent SOM exists, return empty list."""
    from gpo_lens.model import Som

    estate = Estate(
        gpos=[],
        soms=[
            Som(
                path="ou=other,dc=test,dc=local",
                name="Other",
                container_type="ou",
                inheritance_blocked=False,
                links=[],
            )
        ],
    )
    result = queries.som_effective_gpos(
        estate,
        "ou=nonexistent,dc=test,dc=local",
    )
    assert result == []


def test_som_effective_gpos_multi_level_parent_walk():
    """Multi-level walk: skip multiple absent intermediate OUs to find grandparent."""
    from gpo_lens.model import Som, SomLink

    gpo = _make_gpo(id="gpo-1", name="Grandparent GPO")
    grandparent_som = Som(
        path="ou=grandparent,dc=test,dc=local",
        name="Grandparent",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(
                gpo_id="gpo-1",
                order=1,
                enabled=True,
                enforced=False,
                target="ou=grandparent,dc=test,dc=local",
            ),
        ],
    )
    estate = Estate(gpos=[gpo], soms=[grandparent_som])

    result = queries.som_effective_gpos(
        estate,
        "ou=grandchild,ou=child,ou=grandparent,dc=test,dc=local",
    )
    assert len(result) == 1
    assert result[0].gpo_id == "gpo-1"


def test_som_effective_gpos_skips_site_som_in_parent_walk():
    """Site SOMs should not be matched during parent-OU walk."""
    from gpo_lens.model import Som, SomLink

    gpo = _make_gpo(id="gpo-1", name="Site GPO")
    # The site SOM's path IS a parent candidate of the target DN.
    site_som = Som(
        path="dc=test,dc=local",
        name="Default-First-Site",
        container_type="site",
        inheritance_blocked=False,
        links=[SomLink(gpo_id="gpo-1", order=1, enabled=True, enforced=False, target="")],
    )
    estate = Estate(gpos=[gpo], soms=[site_som])

    result = queries.som_effective_gpos(
        estate,
        "ou=child,dc=test,dc=local",
    )
    assert result == []


def test_split_dn_escaped_backslash_before_separator():
    """_split_dn must treat a comma after an even backslash run as a separator.

    ``CN=test\\\\`` is a literal backslash at the end of the value; the following
    comma is a real DN separator. The old regex ``(?<!\\\\),`` saw one backslash
    before the comma and wrongly treated it as escaped.
    """
    from gpo_lens.topology import _split_dn

    parts = _split_dn(r"CN=test\\,OU=Servers,DC=test")
    assert parts == [r"CN=test\\", "OU=Servers", "DC=test"]


def test_split_dn_escaped_comma_in_rdn():
    """A backslash-escaped comma stays inside the RDN value."""
    from gpo_lens.topology import _split_dn

    parts = _split_dn(r"CN=Last\,First,OU=Users,DC=test")
    assert parts == [r"CN=Last\,First", "OU=Users", "DC=test"]


def test_split_dn_plain_dn():
    from gpo_lens.topology import _split_dn

    assert _split_dn("OU=Users,DC=test,DC=local") == [
        "OU=Users",
        "DC=test",
        "DC=local",
    ]


def test_split_dn_three_backslashes():
    """Three backslashes = escaped-backslash + escaped-comma (odd run)."""
    from gpo_lens.topology import _split_dn

    parts = _split_dn(r"CN=test\\\,x,OU=Users,DC=test")
    assert parts == [r"CN=test\\\,x", "OU=Users", "DC=test"]


def test_split_dn_empty_string():
    from gpo_lens.topology import _split_dn

    assert _split_dn("") == [""]


def test_som_effective_gpos_target_present_empty_links_no_walk():
    """When the target SOM exists but has no links, return its empty chain —
    do NOT walk up to a parent."""
    from gpo_lens.model import Som, SomLink

    gpo = _make_gpo(id="gpo-1", name="Parent GPO")
    parent_som = Som(
        path="ou=parent,dc=test,dc=local",
        name="Parent",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(
                gpo_id="gpo-1",
                order=1,
                enabled=True,
                enforced=False,
                target="ou=parent,dc=test,dc=local",
            ),
        ],
    )
    child_som = Som(
        path="ou=child,ou=parent,dc=test,dc=local",
        name="Child",
        container_type="ou",
        inheritance_blocked=False,
        links=[],
    )
    estate = Estate(gpos=[gpo], soms=[parent_som, child_som])
    result = queries.som_effective_gpos(
        estate,
        "ou=child,ou=parent,dc=test,dc=local",
    )
    assert result == []


def test_som_effective_gpos_parent_walk_case_insensitive():
    """Parent-OU matching is case-insensitive."""
    from gpo_lens.model import Som, SomLink

    gpo = _make_gpo(id="gpo-1", name="Parent GPO")
    parent_som = Som(
        path="OU=Parent,DC=Test,DC=Local",
        name="Parent",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(
                gpo_id="gpo-1",
                order=1,
                enabled=True,
                enforced=False,
                target="OU=Parent,DC=Test,DC=Local",
            ),
        ],
    )
    estate = Estate(gpos=[gpo], soms=[parent_som])
    result = queries.som_effective_gpos(
        estate,
        "ou=child,ou=parent,dc=test,dc=local",
    )
    assert len(result) == 1
    assert result[0].gpo_id == "gpo-1"


def test_dangling_links():
    from gpo_lens.model import Som, SomLink

    som = Som(
        path="ou=workstations,dc=test,dc=local",
        name="Workstations",
        container_type="ou",
        inheritance_blocked=False,
        links=[SomLink(gpo_id="missing-gpo", order=1, enabled=True, enforced=False, target="")],
    )
    estate = Estate(gpos=[], soms=[som])
    result = queries.dangling_links(estate)
    assert len(result) == 1
    assert result[0][1].gpo_id == "missing-gpo"


def test_enforced_links():
    from gpo_lens.model import Som, SomLink

    gpo = _make_gpo(id="gpo-1")
    som = Som(
        path="ou=workstations,dc=test,dc=local",
        name="Workstations",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id="gpo-1", order=1, enabled=True, enforced=True, target=""),
        ],
    )
    estate = Estate(gpos=[gpo], soms=[som])
    result = queries.enforced_links(estate)
    assert len(result) == 1
    assert result[0][1].enforced is True


def test_loopback_gpos_detects_loopback_setting():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="Configure user Group Policy loopback processing mode",
                display_name="Loopback",
                display_value="Enabled",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.loopback_gpos(estate)
    assert len(result) == 1
    assert result[0][0].id == "gpo-1"


def test_loopback_awareness_extracts_mode():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Configure user Group Policy loopback processing mode",
                display_name="Loopback",
                display_value="Replace",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    awareness = queries.loopback_awareness(estate)
    assert awareness == {"gpo-1": "replace"}


def test_loopback_awareness_merge_mode():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Configure Group Policy loopback processing mode",
                display_name="Loopback",
                display_value="Merge",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    awareness = queries.loopback_awareness(estate)
    assert awareness == {"gpo-1": "merge"}


def test_loopback_awareness_unknown_mode():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Configure Group Policy loopback processing mode",
                display_name="Loopback",
                display_value="Enabled",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    awareness = queries.loopback_awareness(estate)
    assert awareness == {"gpo-1": "unknown"}


def test_loopback_awareness_empty():
    estate = Estate(gpos=[_make_gpo()])
    assert queries.loopback_awareness(estate) == {}


def test_loopback_awareness_raw_replace():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Configure user Group Policy loopback processing mode",
                display_name="Loopback",
                display_value="Some display text",
                raw={
                    "tag": "Security",
                    "@attr": {
                        "Name": "Configure user Group Policy loopback processing mode",
                        "Type": "Policy",
                    },
                    "children": [{"tag": "SettingString", "text": "Replace"}],
                },
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    awareness = queries.loopback_awareness(estate)
    assert awareness == {"gpo-1": "replace"}


def test_loopback_awareness_raw_merge():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Configure Group Policy loopback processing mode",
                display_name="Loopback",
                display_value="Configured",
                raw={
                    "tag": "Security",
                    "@attr": {
                        "Name": "Configure Group Policy loopback processing mode",
                        "Type": "Policy",
                    },
                    "children": [{"tag": "SettingString", "text": "Merge"}],
                },
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    awareness = queries.loopback_awareness(estate)
    assert awareness == {"gpo-1": "merge"}


def test_loopback_awareness_raw_numeric_replace():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Configure user Group Policy loopback processing mode",
                display_name="Loopback",
                display_value="Enabled",
                raw={
                    "tag": "Security",
                    "@attr": {
                        "Name": "Configure user Group Policy loopback processing mode",
                        "Type": "Policy",
                    },
                    "children": [{"tag": "SettingBoolean", "text": "1"}],
                },
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    awareness = queries.loopback_awareness(estate)
    assert awareness == {"gpo-1": "replace"}


def test_loopback_awareness_raw_numeric_merge():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Configure user Group Policy loopback processing mode",
                display_name="Loopback",
                display_value="Enabled",
                raw={
                    "tag": "Security",
                    "@attr": {
                        "Name": "Configure user Group Policy loopback processing mode",
                        "Type": "Policy",
                    },
                    "children": [{"tag": "SettingBoolean", "text": "2"}],
                },
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    awareness = queries.loopback_awareness(estate)
    assert awareness == {"gpo-1": "merge"}


def test_loopback_awareness_policy_dropdown_replace():
    from gpo_lens.model import Setting

    _name = "Configure user Group Policy loopback processing mode"
    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="Registry:Policy:abc123",
                display_name=_name,
                display_value=_name,
                raw={
                    "tag": "Policy",
                    "children": [
                        {"tag": "Name", "text": _name},
                        {"tag": "State", "text": "Enabled"},
                        {"tag": "Explain", "text": "..."},
                        {
                            "tag": "DropDownList",
                            "children": [
                                {"tag": "Name", "text": "Mode:"},
                                {"tag": "State", "text": "Enabled"},
                                {
                                    "tag": "Value",
                                    "children": [
                                        {"tag": "Name", "text": "Replace"},
                                    ],
                                },
                            ],
                        },
                    ],
                },
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    awareness = queries.loopback_awareness(estate)
    assert awareness == {"gpo-1": "replace"}


def test_loopback_awareness_policy_dropdown_merge():
    from gpo_lens.model import Setting

    _name = "Configure user Group Policy loopback processing mode"
    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="Registry:Policy:abc123",
                display_name=_name,
                display_value=_name,
                raw={
                    "tag": "Policy",
                    "children": [
                        {"tag": "Name", "text": _name},
                        {"tag": "State", "text": "Enabled"},
                        {
                            "tag": "DropDownList",
                            "children": [
                                {"tag": "Name", "text": "Mode:"},
                                {
                                    "tag": "Value",
                                    "children": [
                                        {"tag": "Name", "text": "Merge"},
                                    ],
                                },
                            ],
                        },
                    ],
                },
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    awareness = queries.loopback_awareness(estate)
    assert awareness == {"gpo-1": "merge"}


def test_loopback_awareness_policy_disabled_returns_none():
    from gpo_lens.model import Setting

    _name = "Configure user Group Policy loopback processing mode"
    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="Registry:Policy:abc123",
                display_name=_name,
                display_value=_name,
                raw={
                    "tag": "Policy",
                    "children": [
                        {"tag": "Name", "text": _name},
                        {"tag": "State", "text": "Disabled"},
                        {
                            "tag": "DropDownList",
                            "children": [
                                {"tag": "Value", "children": [{"tag": "Name", "text": "Merge"}]},
                            ],
                        },
                    ],
                },
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    awareness = queries.loopback_awareness(estate)
    assert awareness == {}


def test_loopback_awareness_policy_enabled_no_dropdown_unknown():
    from gpo_lens.model import Setting

    _name = "Configure user Group Policy loopback processing mode"
    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="Registry:Policy:abc123",
                display_name=_name,
                display_value=_name,
                raw={
                    "tag": "Policy",
                    "children": [
                        {"tag": "Name", "text": _name},
                        {"tag": "State", "text": "Enabled"},
                    ],
                },
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    awareness = queries.loopback_awareness(estate)
    assert awareness == {"gpo-1": "unknown"}
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Configure user Group Policy loopback processing mode",
                display_name="Loopback",
                display_value="Loopback: Replace",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    awareness = queries.loopback_awareness(estate)
    assert awareness == {"gpo-1": "replace"}


def test_loopback_awareness_unrecognized_text_is_unknown():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Configure user Group Policy loopback processing mode",
                display_name="Loopback",
                display_value="Custom Loopback Mode",
                raw={
                    "tag": "Security",
                    "@attr": {
                        "Name": "Configure user Group Policy loopback processing mode",
                        "Type": "Policy",
                    },
                    "children": [{"tag": "SettingString", "text": "CustomValue"}],
                },
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    awareness = queries.loopback_awareness(estate)
    assert awareness == {"gpo-1": "unknown"}


def test_loopback_awareness_none_display_value():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Configure user Group Policy loopback processing mode",
                display_name="Loopback",
                display_value="",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    awareness = queries.loopback_awareness(estate)
    assert awareness == {}


def test_loopback_awareness_all_variants_bannered():
    from gpo_lens.model import Setting

    gpo_replace = _make_gpo(
        id="gpo-replace",
        settings=[
            Setting(
                gpo_id="gpo-replace",
                side="Computer",
                cse="Security",
                identity="Configure user Group Policy loopback processing mode",
                display_name="Loopback",
                display_value="Replace",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    gpo_merge = _make_gpo(
        id="gpo-merge",
        settings=[
            Setting(
                gpo_id="gpo-merge",
                side="Computer",
                cse="Security",
                identity="Configure user Group Policy loopback processing mode",
                display_name="Loopback",
                display_value="Merge",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    gpo_unknown = _make_gpo(
        id="gpo-unknown",
        settings=[
            Setting(
                gpo_id="gpo-unknown",
                side="Computer",
                cse="Security",
                identity="Configure user Group Policy loopback processing mode",
                display_name="Loopback",
                display_value="OddValue",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo_replace, gpo_merge, gpo_unknown])
    awareness = queries.loopback_awareness(estate)
    assert len(awareness) == 3
    assert awareness["gpo-replace"] == "replace"
    assert awareness["gpo-merge"] == "merge"
    assert awareness["gpo-unknown"] == "unknown"


def test_wmi_filtered_gpos():
    gpo = _make_gpo(id="gpo-1", wmi_filter="MyFilter")
    estate = Estate(gpos=[gpo])
    result = queries.wmi_filtered_gpos(estate)
    assert len(result) == 1
    assert result[0].wmi_filter == "MyFilter"


# ---- Tier 2.5 chain-aware queries -----------------------------------------


def test_som_conflicts_empty_when_no_som():
    estate = Estate(gpos=[], soms=[])
    assert queries.som_conflicts(estate, "dc=test,dc=local") == []


def test_som_conflicts_empty_when_single_gpo():
    from gpo_lens.model import Setting, Som, SomLink

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Account:Foo",
                display_name="Foo",
                display_value="bar",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[SomLink(gpo_id="gpo-1", order=1, enabled=True, enforced=False, target="")],
    )
    estate = Estate(gpos=[gpo], soms=[som])
    result = queries.som_conflicts(estate, "ou=ws,dc=test,dc=local")
    assert result == []


def test_som_conflicts_detects_value_mismatch():
    from gpo_lens.model import Setting, Som, SomLink

    gpo_a = _make_gpo(
        id="gpo-a",
        name="GPO A",
        settings=[
            Setting(
                gpo_id="gpo-a",
                side="Computer",
                cse="Security",
                identity="Account:LockoutBadCount",
                display_name="LockoutBadCount",
                display_value="5",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    gpo_b = _make_gpo(
        id="gpo-b",
        name="GPO B",
        settings=[
            Setting(
                gpo_id="gpo-b",
                side="Computer",
                cse="Security",
                identity="Account:LockoutBadCount",
                display_name="LockoutBadCount",
                display_value="10",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id="gpo-a", order=1, enabled=True, enforced=False, target=""),
            SomLink(gpo_id="gpo-b", order=2, enabled=True, enforced=False, target=""),
        ],
    )
    estate = Estate(gpos=[gpo_a, gpo_b], soms=[som])
    result = queries.som_conflicts(estate, "ou=ws,dc=test,dc=local")
    assert len(result) == 1
    c = result[0]
    assert c.identity == "Account:LockoutBadCount"
    assert c.winner == "GPO B"
    assert len(c.entries) == 2


def test_som_conflicts_ignores_disabled_links():
    from gpo_lens.model import Setting, Som, SomLink

    gpo_a = _make_gpo(
        id="gpo-a",
        settings=[
            Setting(
                gpo_id="gpo-a",
                side="Computer",
                cse="Security",
                identity="Account:Foo",
                display_name="Foo",
                display_value="5",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    gpo_b = _make_gpo(
        id="gpo-b",
        settings=[
            Setting(
                gpo_id="gpo-b",
                side="Computer",
                cse="Security",
                identity="Account:Foo",
                display_name="Foo",
                display_value="10",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id="gpo-a", order=1, enabled=True, enforced=False, target=""),
            SomLink(
                gpo_id="gpo-b",
                order=2,
                enabled=False,
                enforced=False,
                target="",
            ),
        ],
    )
    estate = Estate(gpos=[gpo_a, gpo_b], soms=[som])
    result = queries.som_conflicts(estate, "ou=ws,dc=test,dc=local")
    assert result == []


def test_precedence_conflicts_empty_when_clean():
    estate = Estate(gpos=[], soms=[])
    assert queries.precedence_conflicts(estate) == []


def test_broken_refs_detects_unc_in_display_value():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="InstallDir",
                display_name="Install Dir",
                display_value=r"\\server\share\app",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    assert queries.broken_refs(estate) == []
    result = [r for group in queries.external_dependencies(estate) for r in group.dependencies]
    assert len(result) == 1
    assert result[0].dependency_type == "unc_path"
    assert result[0].target == r"\\server\share\app"


def test_broken_refs_empty_when_clean():
    gpo = _make_gpo(id="gpo-1", settings=[])
    estate = Estate(gpos=[gpo])
    assert queries.broken_refs(estate) == []


def test_broken_refs_detects_unc_in_raw_dict():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="InstallDir",
                display_name="Install Dir",
                display_value="local",
                raw={"children": [{"text": r"\\server\share\path"}]},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    assert queries.broken_refs(estate) == []
    result = [r for group in queries.external_dependencies(estate) for r in group.dependencies]
    unc_refs = [r for r in result if r.dependency_type == "unc_path"]
    assert len(unc_refs) >= 1
    assert r"\\server\share\path" in unc_refs[0].target


def test_broken_refs_detects_missing_script(tmp_path):
    from gpo_lens.model import Setting

    gpo_dir = tmp_path / "gpo"
    gpo_dir.mkdir()
    gpo = _make_gpo(
        id="gpo-1",
        sysvol_path=str(gpo_dir),
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Scripts",
                identity="StartupScript",
                display_name="StartupScript",
                display_value="missing.bat",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.broken_refs(estate)
    missing = [r for r in result if r.ref_type == "missing_script"]
    assert len(missing) == 1
    assert "missing.bat" in missing[0].ref_value


def test_broken_refs_script_found_in_sysvol(tmp_path):
    from gpo_lens.model import Setting

    gpo_dir = tmp_path / "gpo"
    scripts_dir = gpo_dir / "Machine" / "Scripts" / "Startup"
    scripts_dir.mkdir(parents=True)
    (scripts_dir / "exists.bat").write_text("@echo off", encoding="utf-8")

    gpo = _make_gpo(
        id="gpo-1",
        sysvol_path=str(gpo_dir),
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Scripts",
                identity="StartupScript",
                display_name="StartupScript",
                display_value="exists.bat",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.broken_refs(estate)
    missing = [r for r in result if r.ref_type == "missing_script"]
    assert missing == []


def test_broken_refs_deduplicates():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="X",
                display_name="X",
                display_value=r"\\server\share\path",
                raw={"text": r"\\server\share\path"},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    assert queries.broken_refs(estate) == []
    result = [r for group in queries.external_dependencies(estate) for r in group.dependencies]
    unc_refs = [
        r for r in result if r.dependency_type == "unc_path" and r.target == r"\\server\share\path"
    ]
    assert len(unc_refs) == 1


# ---- estate_summary ---------------------------------------------------------


def test_estate_summary():
    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="X",
                display_name="X",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(domain="test.local", gpos=[gpo])
    s = queries.estate_summary(estate)
    assert s.domain == "test.local"
    assert s.gpo_count == 1
    assert s.total_settings == 1
    assert s.unlinked_count == 1  # no links
    assert s.empty_count == 0
    assert s.conflict_count == 0
    assert s.ms16_072_vulnerable_count == 1  # no delegation entries
    # WI-007: the four newer doctor categories are surfaced on the summary.
    assert s.broken_wmi_ref_count == 0
    assert s.orphaned_wmi_filter_count == 0
    assert s.ilt_gpo_count == 0
    assert s.stale_gpo_count == 0


# ---- existing queries still pass smoke --------------------------------------


def test_empty_gpos():
    gpo = _make_gpo(settings=[])
    estate = Estate(gpos=[gpo])
    assert queries.empty_gpos(estate) == [gpo]


def test_empty_gpos_counts_only_blocked_as_empty():
    from gpo_lens.model import Setting

    truly_empty = _make_gpo(id="gpo-empty", name="Truly Empty", settings=[])
    blocked_only = _make_gpo(
        id="gpo-blocked",
        name="Blocked Only",
        settings=[
            Setting(
                gpo_id="gpo-blocked",
                side="Computer",
                cse="Registry",
                identity="Registry:blocked",
                display_name="(blocked extension)",
                display_value="",
                raw={"blocked": True},
                from_disabled_side=False,
                source_state="blocked",
            ),
        ],
    )
    normal = _make_gpo(
        id="gpo-normal",
        name="Normal",
        settings=[
            Setting(
                gpo_id="gpo-normal",
                side="Computer",
                cse="Security",
                identity="X",
                display_name="X",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[truly_empty, blocked_only, normal])
    result = queries.empty_gpos(estate)
    assert truly_empty in result
    assert blocked_only in result
    assert normal not in result


def test_unlinked_gpos():
    gpo = _make_gpo(links=[])
    estate = Estate(gpos=[gpo])
    assert queries.unlinked_gpos(estate) == [gpo]


# ---- disabled_but_populated --------------------------------------------------


def test_disabled_but_populated_computer_side():
    gpo = _make_gpo(
        computer_enabled=False,
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="X",
                display_name="X",
                display_value="1",
                raw={},
                from_disabled_side=True,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.disabled_but_populated(estate)
    assert result == [(gpo, "Computer")]


def test_disabled_but_populated_user_side():
    gpo = _make_gpo(
        user_enabled=False,
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="User",
                cse="Registry",
                identity="Y",
                display_name="Y",
                display_value="2",
                raw={},
                from_disabled_side=True,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.disabled_but_populated(estate)
    assert result == [(gpo, "User")]


def test_disabled_but_populated_both_sides():
    gpo = _make_gpo(
        computer_enabled=False,
        user_enabled=False,
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="X",
                display_name="X",
                display_value="1",
                raw={},
                from_disabled_side=True,
            ),
            Setting(
                gpo_id="gpo-1",
                side="User",
                cse="Registry",
                identity="Y",
                display_name="Y",
                display_value="2",
                raw={},
                from_disabled_side=True,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.disabled_but_populated(estate)
    assert len(result) == 2
    assert (gpo, "Computer") in result
    assert (gpo, "User") in result


def test_disabled_but_populated_enabled_side_ignored():
    gpo = _make_gpo(
        computer_enabled=True,
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="X",
                display_name="X",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    assert queries.disabled_but_populated(estate) == []


# ---- settings_at_som --------------------------------------------------------


def test_settings_at_som_empty_when_no_som():
    estate = Estate(gpos=[], soms=[])
    assert queries.settings_at_som(estate, "dc=test,dc=local") == []


def test_settings_at_som_empty_when_single_gpo():
    from gpo_lens.model import Setting, Som, SomLink

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Account:Foo",
                display_name="Foo",
                display_value="bar",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[SomLink(gpo_id="gpo-1", order=1, enabled=True, enforced=False, target="")],
    )
    estate = Estate(gpos=[gpo], soms=[som])
    result = queries.settings_at_som(estate, "ou=ws,dc=test,dc=local")
    assert len(result) == 1
    assert result[0].identity == "Account:Foo"
    assert result[0].display_value == "bar"
    assert result[0].winner_gpo_id == "gpo-1"
    assert result[0].overridden_by == []
    assert result[0].enforced is False


def test_settings_at_som_last_gpo_wins():
    from gpo_lens.model import Setting, Som, SomLink

    gpo_a = _make_gpo(
        id="gpo-a",
        name="GPO A",
        settings=[
            Setting(
                gpo_id="gpo-a",
                side="Computer",
                cse="Security",
                identity="Account:LockoutBadCount",
                display_name="LockoutBadCount",
                display_value="5",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    gpo_b = _make_gpo(
        id="gpo-b",
        name="GPO B",
        settings=[
            Setting(
                gpo_id="gpo-b",
                side="Computer",
                cse="Security",
                identity="Account:LockoutBadCount",
                display_name="LockoutBadCount",
                display_value="10",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id="gpo-a", order=1, enabled=True, enforced=False, target=""),
            SomLink(gpo_id="gpo-b", order=2, enabled=True, enforced=False, target=""),
        ],
    )
    estate = Estate(gpos=[gpo_a, gpo_b], soms=[som])
    result = queries.settings_at_som(estate, "ou=ws,dc=test,dc=local")
    assert len(result) == 1
    es = result[0]
    assert es.identity == "Account:LockoutBadCount"
    assert es.display_value == "10"
    assert es.winner_gpo_name == "GPO B"
    assert es.overridden_by == [("GPO A", "5")]


def test_settings_at_som_ignores_disabled_links():
    from gpo_lens.model import Setting, Som, SomLink

    gpo_a = _make_gpo(
        id="gpo-a",
        name="GPO A",
        settings=[
            Setting(
                gpo_id="gpo-a",
                side="Computer",
                cse="Security",
                identity="Account:Foo",
                display_name="Foo",
                display_value="5",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    gpo_b = _make_gpo(
        id="gpo-b",
        name="GPO B",
        settings=[
            Setting(
                gpo_id="gpo-b",
                side="Computer",
                cse="Security",
                identity="Account:Foo",
                display_name="Foo",
                display_value="10",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id="gpo-a", order=1, enabled=True, enforced=False, target=""),
            SomLink(
                gpo_id="gpo-b",
                order=2,
                enabled=False,
                enforced=False,
                target="",
            ),
        ],
    )
    estate = Estate(gpos=[gpo_a, gpo_b], soms=[som])
    result = queries.settings_at_som(estate, "ou=ws,dc=test,dc=local")
    assert len(result) == 1
    assert result[0].display_value == "5"
    assert result[0].overridden_by == []


def test_settings_at_som_enforced_flag():
    from gpo_lens.model import Setting, Som, SomLink

    gpo = _make_gpo(
        id="gpo-1",
        name="GPO One",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Account:Foo",
                display_name="Foo",
                display_value="5",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id="gpo-1", order=1, enabled=True, enforced=True, target=""),
        ],
    )
    estate = Estate(gpos=[gpo], soms=[som])
    result = queries.settings_at_som(estate, "ou=ws,dc=test,dc=local")
    assert len(result) == 1
    assert result[0].enforced is True


def test_settings_at_som_excludes_disabled_side_settings():
    """A setting on a disabled side does NOT apply — it must not appear as
    effective (charter: flag, don't simulate). Disabled-side ghosts are
    surfaced separately by disabled_but_populated()."""
    from gpo_lens.model import Setting, Som, SomLink

    gpo = _make_gpo(
        id="gpo-1",
        name="Disabled Side GPO",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Account:Foo",
                display_name="Foo",
                display_value="5",
                raw={},
                from_disabled_side=True,
            ),
            Setting(
                gpo_id="gpo-1",
                side="User",
                cse="Registry",
                identity="Bar",
                display_name="Bar",
                display_value="B",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[SomLink(gpo_id="gpo-1", order=1, enabled=True, enforced=True, target="")],
    )
    estate = Estate(gpos=[gpo], soms=[som])
    result = queries.settings_at_som(estate, "ou=ws,dc=test,dc=local")
    # The disabled-side Computer setting is excluded; only the live User setting appears.
    assert len(result) == 1
    assert result[0].identity == "Bar"
    assert result[0].side == "User"


def test_som_conflicts_excludes_disabled_side_settings():
    """A disabled-side setting must not fabricate a conflict."""
    from gpo_lens.model import Setting, Som, SomLink

    gpo_live = _make_gpo(
        id="gpo-live",
        name="Live",
        settings=[
            Setting(
                gpo_id="gpo-live",
                side="Computer",
                cse="Security",
                identity="X",
                display_name="X",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    gpo_ghost = _make_gpo(
        id="gpo-ghost",
        name="Ghost",
        settings=[
            Setting(
                gpo_id="gpo-ghost",
                side="Computer",
                cse="Security",
                identity="X",
                display_name="X",
                display_value="2",
                raw={},
                from_disabled_side=True,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id="gpo-live", order=1, enabled=True, enforced=False, target=""),
            SomLink(gpo_id="gpo-ghost", order=2, enabled=True, enforced=False, target=""),
        ],
    )
    estate = Estate(gpos=[gpo_live, gpo_ghost], soms=[som])
    # Only the live setting applies → no differing-value conflict.
    assert queries.som_conflicts(estate, "ou=ws,dc=test,dc=local") == []


def test_settings_at_som_multiple_identities():
    from gpo_lens.model import Setting, Som, SomLink

    gpo = _make_gpo(
        id="gpo-1",
        name="GPO One",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Account:Foo",
                display_name="Foo",
                display_value="A",
                raw={},
                from_disabled_side=False,
            ),
            Setting(
                gpo_id="gpo-1",
                side="User",
                cse="Registry",
                identity="Bar",
                display_name="Bar",
                display_value="B",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id="gpo-1", order=1, enabled=True, enforced=False, target=""),
        ],
    )
    estate = Estate(gpos=[gpo], soms=[som])
    result = queries.settings_at_som(estate, "ou=ws,dc=test,dc=local")
    # Should be stable sorted: by (cse, side, identity)
    # Registry (User) sorts before Security (Computer)
    assert len(result) == 2
    assert result[0].cse == "Registry"
    assert result[0].side == "User"
    assert result[0].identity == "Bar"
    assert result[1].cse == "Security"
    assert result[1].side == "Computer"
    assert result[1].identity == "Account:Foo"


# ---- topology_crosscheck ----------------------------------------------------


def test_topology_crosscheck_no_tree():
    estate = Estate(gpos=[], soms=[], ou_tree=[])
    assert queries.topology_crosscheck(estate) == []


def test_topology_crosscheck_block_mismatch():
    from gpo_lens.model import Som

    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[],
    )
    ou = OuRecord(
        dn="OU=WS,DC=test,DC=local",
        name="WS",
        gp_link=None,
        gp_options=1,
    )
    estate = Estate(soms=[som], ou_tree=[ou])
    result = queries.topology_crosscheck(estate)
    assert len(result) == 1
    assert result[0].kind == "block_mismatch"


def test_topology_crosscheck_block_match():
    from gpo_lens.model import Som

    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=True,
        links=[],
    )
    ou = OuRecord(
        dn="OU=WS,DC=test,DC=local",
        name="WS",
        gp_link=None,
        gp_options=1,
    )
    estate = Estate(soms=[som], ou_tree=[ou])
    result = queries.topology_crosscheck(estate)
    assert result == []


def test_topology_crosscheck_ou_missing_from_soms():
    ou = OuRecord(
        dn="OU=Missing,DC=test,DC=local",
        name="Missing",
        gp_link="[LDAP://cn={AAA};0]",
        gp_options=0,
    )
    estate = Estate(soms=[], ou_tree=[ou])
    result = queries.topology_crosscheck(estate)
    assert len(result) == 1
    assert result[0].kind == "ou_missing_from_soms"


def test_topology_crosscheck_ou_no_gplink_not_flagged():
    ou = OuRecord(
        dn="OU=Empty,DC=test,DC=local",
        name="Empty",
        gp_link=None,
        gp_options=0,
    )
    estate = Estate(soms=[], ou_tree=[ou])
    result = queries.topology_crosscheck(estate)
    assert result == []


# ---- admx_gaps --------------------------------------------------------------


def test_admx_gaps_no_registry_settings():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Account:Foo",
                display_name="Foo",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    assert queries.admx_gaps(estate) == []


def test_admx_gaps_detects_raw_registry_path():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity=r"Software\MyApp:Setting1",
                display_name=r"Software\MyApp",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.admx_gaps(estate)
    assert len(result) == 1
    assert result[0].key_path == r"Software\MyApp"
    assert result[0].value_name == "Setting1"
    assert result[0].side == "Computer"


def test_admx_gaps_resolved_by_admx_crosswalk():
    """When ADMX resolves the registry path, it's not a gap."""
    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity=r"Software\Policies\Foo:Bar",
                display_name="Bar",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    # No ADMX — should be a gap
    assert len(queries.admx_gaps(estate)) == 1

    # With ADMX that resolves the exact identity — gap disappears
    admx = PolicyDefinitions(
        policies=[
            AdmxPolicy(
                name="TestPolicy",
                class_scope="Machine",
                key=r"Software\Policies\Foo",
                value_name="Bar",
                display_name_ref="$(string.Test)",
                display_name="Test Display",
                explain_text="",
            ),
        ]
    )
    assert queries.admx_gaps(estate, admx) == []


def test_admx_gaps_detects_hklm_prefix():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="User",
                cse="Registry",
                identity=r"HKLM\Software\Foo:Bar",
                display_name=r"HKLM\Software\Foo",
                display_value="2",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.admx_gaps(estate)
    assert len(result) == 1
    assert result[0].gpo_id == "gpo-1"


def test_admx_gaps_skips_blocked_extensions():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity=r"Software\MyApp:Set",
                display_name=r"Software\MyApp",
                display_value="1",
                raw={},
                from_disabled_side=False,
                source_state="blocked",
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    assert queries.admx_gaps(estate) == []


def test_admx_gaps_included_in_summary():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity=r"Software\MyApp:Set",
                display_name=r"Software\MyApp",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(domain="test.local", gpos=[gpo])
    s = queries.estate_summary(estate)
    assert s.admx_gap_count == 1


# ---- deeper broken_refs: drive mapping, scheduled tasks, GPP XML ----------


def test_broken_refs_drive_mapping_unc():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="User",
                cse="Drives",
                identity="DriveMap:H:",
                display_name="H Drive",
                display_value=r"\\server\share\home",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    assert queries.broken_refs(estate) == []
    result = [r for group in queries.external_dependencies(estate) for r in group.dependencies]
    drive_refs = [r for r in result if r.dependency_type == "drive_mapping"]
    assert len(drive_refs) == 1
    assert r"\\server\share\home" in drive_refs[0].target


def test_broken_refs_scheduled_task_path():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Scheduled Tasks",
                identity="Task:Cleanup",
                display_name="Cleanup Task",
                display_value=r"C:\Scripts\cleanup.bat",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.broken_refs(estate)
    assert result == []


def test_broken_refs_gpp_xml_unc(tmp_path):
    gpo_dir = tmp_path / "gpo"
    prefs = gpo_dir / "Machine" / "Preferences"
    prefs.mkdir(parents=True)
    root = ET.Element("ScheduledTasks")
    task = ET.SubElement(root, "Task")
    task.set("appPath", r"\\fileserver\tasks\cleanup.bat")
    tree = ET.ElementTree(root)
    tree.write(prefs / "ScheduledTasks.xml")

    gpo = _make_gpo(id="gpo-1", sysvol_path=str(gpo_dir))
    estate = Estate(gpos=[gpo])
    assert queries.broken_refs(estate) == []
    result = [r for group in queries.external_dependencies(estate) for r in group.dependencies]
    gpp_refs = [r for r in result if r.dependency_type == "scheduled_task_action"]
    assert len(gpp_refs) >= 1
    assert r"\\fileserver\tasks\cleanup.bat" in gpp_refs[0].target


def test_broken_refs_gpp_xml_scheduled_task_exe(tmp_path):
    gpo_dir = tmp_path / "gpo"
    prefs = gpo_dir / "Machine" / "Preferences"
    prefs.mkdir(parents=True)
    root = ET.Element("ScheduledTasks")
    task = ET.SubElement(root, "ImmediateTask")
    task.set("appPath", r"C:\Tools\run.exe")
    tree = ET.ElementTree(root)
    tree.write(prefs / "ScheduledTasks.xml")

    gpo = _make_gpo(id="gpo-1", sysvol_path=str(gpo_dir))
    estate = Estate(gpos=[gpo])
    result = queries.broken_refs(estate)
    assert result == []


def test_broken_refs_gpp_xml_drive_unc(tmp_path):
    gpo_dir = tmp_path / "gpo"
    prefs = gpo_dir / "User" / "Preferences"
    prefs.mkdir(parents=True)
    root = ET.Element("Drives")
    drive = ET.SubElement(root, "Drive")
    drive.set("Path", r"\\fileserver\shares\home")
    tree = ET.ElementTree(root)
    tree.write(prefs / "Drives.xml")

    gpo = _make_gpo(id="gpo-1", sysvol_path=str(gpo_dir))
    estate = Estate(gpos=[gpo])
    assert queries.broken_refs(estate) == []
    result = [r for group in queries.external_dependencies(estate) for r in group.dependencies]
    drive_refs = [r for r in result if r.dependency_type == "drive_mapping"]
    assert len(drive_refs) >= 1
    assert r"\\fileserver\shares\home" in drive_refs[0].target
    assert "Drive" in drive_refs[0].detail


def test_broken_refs_gpp_xml_file_unc(tmp_path):
    gpo_dir = tmp_path / "gpo"
    prefs = gpo_dir / "Machine" / "Preferences"
    prefs.mkdir(parents=True)
    root = ET.Element("Files")
    file_elem = ET.SubElement(root, "File")
    file_elem.set("fromPath", r"\\source\dist\app.msi")
    file_elem.set("toPath", r"C:\Program Files\app.msi")
    tree = ET.ElementTree(root)
    tree.write(prefs / "Files.xml")

    gpo = _make_gpo(id="gpo-1", sysvol_path=str(gpo_dir))
    estate = Estate(gpos=[gpo])
    assert queries.broken_refs(estate) == []
    result = [r for group in queries.external_dependencies(estate) for r in group.dependencies]
    gpp_refs = [r for r in result if r.dependency_type == "file_copy"]
    assert len(gpp_refs) >= 1
    unc_values = {r.target for r in gpp_refs}
    assert r"\\source\dist\app.msi" in unc_values
    detail_texts = " ".join(r.detail for r in gpp_refs)
    assert "File" in detail_texts


def test_broken_refs_gpp_xml_service_unc(tmp_path):
    gpo_dir = tmp_path / "gpo"
    prefs = gpo_dir / "Machine" / "Preferences"
    prefs.mkdir(parents=True)
    root = ET.Element("Services")
    svc = ET.SubElement(root, "Service")
    svc.set("serviceName", r"\\malicious\service_path")
    tree = ET.ElementTree(root)
    tree.write(prefs / "Services.xml")

    gpo = _make_gpo(id="gpo-1", sysvol_path=str(gpo_dir))
    estate = Estate(gpos=[gpo])
    assert queries.broken_refs(estate) == []
    result = [r for group in queries.external_dependencies(estate) for r in group.dependencies]
    gpp_refs = [r for r in result if r.dependency_type == "service_path"]
    assert len(gpp_refs) >= 1
    assert r"\\malicious\service_path" in gpp_refs[0].target
    assert "Service" in gpp_refs[0].detail


def test_broken_refs_gpp_xml_datasource_unc(tmp_path):
    gpo_dir = tmp_path / "gpo"
    prefs = gpo_dir / "User" / "Preferences"
    prefs.mkdir(parents=True)
    root = ET.Element("DataSources")
    ds = ET.SubElement(root, "DataSource")
    ds.set("dsn", r"\\dbserver\data\inventory.mdb")
    ds.set("dsnTarget", r"C:\local\copy.mdb")
    tree = ET.ElementTree(root)
    tree.write(prefs / "DataSources.xml")

    gpo = _make_gpo(id="gpo-1", sysvol_path=str(gpo_dir))
    estate = Estate(gpos=[gpo])
    assert queries.broken_refs(estate) == []
    result = [r for group in queries.external_dependencies(estate) for r in group.dependencies]
    gpp_refs = [r for r in result if r.dependency_type == "data_source"]
    assert len(gpp_refs) >= 1
    unc_values = {r.target for r in gpp_refs}
    assert r"\\dbserver\data\inventory.mdb" in unc_values
    detail_texts = " ".join(r.detail for r in gpp_refs)
    assert "DataSource" in detail_texts


def test_broken_refs_gpp_xml_no_unc_skipped(tmp_path):
    gpo_dir = tmp_path / "gpo"
    prefs = gpo_dir / "Machine" / "Preferences"
    prefs.mkdir(parents=True)
    root = ET.Element("Drives")
    drive = ET.SubElement(root, "Drive")
    drive.set("Path", "C:\\local\\path")
    tree = ET.ElementTree(root)
    tree.write(prefs / "Drives.xml")

    gpo = _make_gpo(id="gpo-1", sysvol_path=str(gpo_dir))
    estate = Estate(gpos=[gpo])
    result = queries.broken_refs(estate)
    assert result == []


def test_broken_refs_gpp_xml_unknown_tag_skipped(tmp_path):
    gpo_dir = tmp_path / "gpo"
    prefs = gpo_dir / "Machine" / "Preferences"
    prefs.mkdir(parents=True)
    root = ET.Element("Foo")
    child = ET.SubElement(root, "Bar")
    child.set("Path", r"\\server\share")
    tree = ET.ElementTree(root)
    tree.write(prefs / "Foo.xml")

    gpo = _make_gpo(id="gpo-1", sysvol_path=str(gpo_dir))
    estate = Estate(gpos=[gpo])
    result = queries.broken_refs(estate)
    assert result == []


# ---- richer snapshot_diff ---------------------------------------------------


def test_snapshot_diff_metadata_changes(tmp_path):
    from gpo_lens import store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-1", name="Old Name", owner="OldOwner")
    estate_a = Estate(domain="test.local", gpos=[gpo_a])
    sid_a = store.save_estate(conn, estate_a)

    gpo_b = _make_gpo(id="gpo-1", name="New Name", owner="NewOwner")
    estate_b = Estate(domain="test.local", gpos=[gpo_b])
    sid_b = store.save_estate(conn, estate_b)

    diff = queries.snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    meta = {(m.field, m.old_value, m.new_value) for m in diff.metadata_changes}
    assert ("name", "Old Name", "New Name") in meta
    assert ("owner", "OldOwner", "NewOwner") in meta


def test_snapshot_diff_enabled_flips(tmp_path):
    from gpo_lens import store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-1", computer_enabled=True, user_enabled=True)
    estate_a = Estate(domain="test.local", gpos=[gpo_a])
    sid_a = store.save_estate(conn, estate_a)

    gpo_b = _make_gpo(id="gpo-1", computer_enabled=False, user_enabled=True)
    estate_b = Estate(domain="test.local", gpos=[gpo_b])
    sid_b = store.save_estate(conn, estate_b)

    diff = queries.snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    flips = {(m.field, m.old_value, m.new_value) for m in diff.enabled_flips}
    assert ("computer_enabled", "True", "False") in flips


def test_snapshot_diff_wmi_filter_changes(tmp_path):
    from gpo_lens import store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-1", wmi_filter="OldFilter")
    estate_a = Estate(domain="test.local", gpos=[gpo_a])
    sid_a = store.save_estate(conn, estate_a)

    gpo_b = _make_gpo(id="gpo-1", wmi_filter="NewFilter")
    estate_b = Estate(domain="test.local", gpos=[gpo_b])
    sid_b = store.save_estate(conn, estate_b)

    diff = queries.snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    wmi = {(m.field, m.old_value, m.new_value) for m in diff.wmi_filter_changes}
    assert ("wmi_filter", "OldFilter", "NewFilter") in wmi


def test_snapshot_diff_settings_changed(tmp_path):
    from gpo_lens import store
    from gpo_lens.model import Setting

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="HKLM\\Software\\Foo",
                display_name="Foo",
                display_value="old",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="HKLM\\Software\\Foo",
                display_name="Foo",
                display_value="new",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = queries.snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    assert "gpo-1" in diff.settings_changed


def test_snapshot_diff_links_changed(tmp_path):
    from gpo_lens import store
    from gpo_lens.model import GpoLink

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(
        id="gpo-1",
        links=[
            GpoLink(
                gpo_id="gpo-1",
                som_name="OU=Foo",
                som_path="OU=Foo,DC=test,DC=local",
                link_enabled=True,
                enforced=False,
            ),
        ],
    )
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(
        id="gpo-1",
        links=[
            GpoLink(
                gpo_id="gpo-1",
                som_name="OU=Bar",
                som_path="OU=Bar,DC=test,DC=local",
                link_enabled=True,
                enforced=False,
            ),
        ],
    )
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = queries.snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    assert "gpo-1" in diff.links_changed


def test_snapshot_diff_delegation_changed(tmp_path):
    from gpo_lens import store
    from gpo_lens.model import DelegationEntry

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(
        id="gpo-1",
        delegation=[
            DelegationEntry(
                gpo_id="gpo-1", trustee="User1", trustee_sid=None, permission="READ", allowed=True
            ),
        ],
    )
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(
        id="gpo-1",
        delegation=[
            DelegationEntry(
                gpo_id="gpo-1", trustee="User2", trustee_sid=None, permission="READ", allowed=True
            ),
        ],
    )
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = queries.snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    assert "gpo-1" in diff.delegation_changed


def test_snapshot_diff_version_skew_changed(tmp_path):
    from gpo_lens import store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(
        id="gpo-1",
        computer_ver_ds=1,
        computer_ver_sysvol=1,
        user_ver_ds=1,
        user_ver_sysvol=1,
    )
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(
        id="gpo-1",
        computer_ver_ds=2,
        computer_ver_sysvol=1,
        user_ver_ds=1,
        user_ver_sysvol=1,
    )
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = queries.snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    assert "gpo-1" in diff.version_skew_changed


def test_snapshot_diff_no_common_gpos(tmp_path):
    from gpo_lens import store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-1")
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(id="gpo-2")
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = queries.snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    assert diff.gpos_added == ["gpo-2"]
    assert diff.gpos_removed == ["gpo-1"]
    assert diff.settings_changed == []
    assert diff.links_changed == []
    assert diff.delegation_changed == []


def test_snapshot_diff_settings_appeared(tmp_path):
    """GPO has no settings in snapshot A, has settings in snapshot B."""
    from gpo_lens import store
    from gpo_lens.model import Setting

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-1")
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="HKLM\\Software\\New",
                display_name="New",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = queries.snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    assert "gpo-1" in diff.settings_changed


# ---- snapshot_settings_diff (per-setting delta) -----------------------------


def test_snapshot_settings_diff_modified(tmp_path):
    from gpo_lens import store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="HKLM\\Software\\Foo",
                display_name="Foo",
                display_value="old_val",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate_a = Estate(domain="test.local", gpos=[gpo_a])
    sid_a = store.save_estate(conn, estate_a)

    gpo_b = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="HKLM\\Software\\Foo",
                display_name="Foo",
                display_value="new_val",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate_b = Estate(domain="test.local", gpos=[gpo_b])
    sid_b = store.save_estate(conn, estate_b)

    changes = queries.snapshot_settings_diff(conn, sid_a, sid_b)
    conn.close()

    assert len(changes) == 1
    c = changes[0]
    assert c.gpo_id == "gpo-1"
    assert c.change_type == "modified"
    assert c.old_value == "old_val"
    assert c.new_value == "new_val"
    assert c.cse == "Registry"
    assert c.identity == "HKLM\\Software\\Foo"


def test_snapshot_settings_diff_added(tmp_path):
    from gpo_lens import store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-1", settings=[])
    estate_a = Estate(domain="test.local", gpos=[gpo_a])
    sid_a = store.save_estate(conn, estate_a)

    gpo_b = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="HKLM\\Software\\New",
                display_name="New",
                display_value="enabled",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate_b = Estate(domain="test.local", gpos=[gpo_b])
    sid_b = store.save_estate(conn, estate_b)

    changes = queries.snapshot_settings_diff(conn, sid_a, sid_b)
    conn.close()

    assert len(changes) == 1
    assert changes[0].change_type == "added"
    assert changes[0].old_value is None
    assert changes[0].new_value == "enabled"


def test_snapshot_settings_diff_removed(tmp_path):
    from gpo_lens import store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="User",
                cse="Folders",
                identity="Folder:Desktop",
                display_name="Desktop",
                display_value=r"\\server\desktop",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate_a = Estate(domain="test.local", gpos=[gpo_a])
    sid_a = store.save_estate(conn, estate_a)

    gpo_b = _make_gpo(id="gpo-1", settings=[])
    estate_b = Estate(domain="test.local", gpos=[gpo_b])
    sid_b = store.save_estate(conn, estate_b)

    changes = queries.snapshot_settings_diff(conn, sid_a, sid_b)
    conn.close()

    assert len(changes) == 1
    assert changes[0].change_type == "removed"
    assert changes[0].old_value == r"\\server\desktop"
    assert changes[0].new_value is None


def test_snapshot_settings_diff_no_changes(tmp_path):
    from gpo_lens import store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    s = Setting(
        gpo_id="gpo-1",
        side="Computer",
        cse="Registry",
        identity="HKLM\\Software\\Foo",
        display_name="Foo",
        display_value="same",
        raw={},
        from_disabled_side=False,
    )
    gpo_a = _make_gpo(id="gpo-1", settings=[s])
    gpo_b = _make_gpo(id="gpo-1", settings=[s])
    estate_a = Estate(domain="test.local", gpos=[gpo_a])
    estate_b = Estate(domain="test.local", gpos=[gpo_b])
    sid_a = store.save_estate(conn, estate_a)
    sid_b = store.save_estate(conn, estate_b)

    changes = queries.snapshot_settings_diff(conn, sid_a, sid_b)
    conn.close()

    assert changes == []


def test_snapshot_settings_diff_filter_by_gpo_id(tmp_path):
    from gpo_lens import store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="Key1",
                display_name="K1",
                display_value="v1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    gpo_b_gpo = _make_gpo(
        id="gpo-2",
        settings=[
            Setting(
                gpo_id="gpo-2",
                side="Computer",
                cse="Registry",
                identity="Key2",
                display_name="K2",
                display_value="v2",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate_a = Estate(domain="test.local", gpos=[gpo_a, gpo_b_gpo])
    sid_a = store.save_estate(conn, estate_a)

    estate_b = Estate(domain="test.local", gpos=[gpo_a, gpo_b_gpo])
    sid_b = store.save_estate(conn, estate_b)

    changes_all = queries.snapshot_settings_diff(conn, sid_a, sid_b)
    assert changes_all == []

    gpo_a_changed = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="Key1",
                display_name="K1",
                display_value="changed",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate_c = Estate(domain="test.local", gpos=[gpo_a_changed, gpo_b_gpo])
    sid_c = store.save_estate(conn, estate_c)

    changes_filtered = queries.snapshot_settings_diff(
        conn,
        sid_a,
        sid_c,
        gpo_id="gpo-1",
    )
    assert len(changes_filtered) == 1
    assert changes_filtered[0].gpo_id == "gpo-1"

    changes_other = queries.snapshot_settings_diff(
        conn,
        sid_a,
        sid_c,
        gpo_id="gpo-2",
    )
    assert changes_other == []

    conn.close()


def test_snapshot_settings_diff_filter_by_side(tmp_path):
    from gpo_lens import store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    s_comp = Setting(
        gpo_id="gpo-1",
        side="Computer",
        cse="Registry",
        identity="Key1",
        display_name="K1",
        display_value="v1",
        raw={},
        from_disabled_side=False,
    )
    s_user = Setting(
        gpo_id="gpo-1",
        side="User",
        cse="Registry",
        identity="Key2",
        display_name="K2",
        display_value="v2",
        raw={},
        from_disabled_side=False,
    )
    gpo_a = _make_gpo(id="gpo-1", settings=[s_comp, s_user])
    estate_a = Estate(domain="test.local", gpos=[gpo_a])
    sid_a = store.save_estate(conn, estate_a)

    s_comp_mod = Setting(
        gpo_id="gpo-1",
        side="Computer",
        cse="Registry",
        identity="Key1",
        display_name="K1",
        display_value="changed",
        raw={},
        from_disabled_side=False,
    )
    s_user_mod = Setting(
        gpo_id="gpo-1",
        side="User",
        cse="Registry",
        identity="Key2",
        display_name="K2",
        display_value="changed_user",
        raw={},
        from_disabled_side=False,
    )
    gpo_b = _make_gpo(id="gpo-1", settings=[s_comp_mod, s_user_mod])
    estate_b = Estate(domain="test.local", gpos=[gpo_b])
    sid_b = store.save_estate(conn, estate_b)

    comp_only = queries.snapshot_settings_diff(
        conn,
        sid_a,
        sid_b,
        side="Computer",
    )
    assert len(comp_only) == 1
    assert comp_only[0].side == "Computer"

    user_only = queries.snapshot_settings_diff(
        conn,
        sid_a,
        sid_b,
        side="User",
    )
    assert len(user_only) == 1
    assert user_only[0].side == "User"

    conn.close()


def test_snapshot_settings_diff_gpo_name_resolved(tmp_path):
    from gpo_lens import store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(
        id="gpo-1",
        name="My Policy",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="Key1",
                display_name="K1",
                display_value="v1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate_a = Estate(domain="test.local", gpos=[gpo_a])
    sid_a = store.save_estate(conn, estate_a)

    gpo_b = _make_gpo(
        id="gpo-1",
        name="My Policy",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="Key1",
                display_name="K1",
                display_value="v2",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate_b = Estate(domain="test.local", gpos=[gpo_b])
    sid_b = store.save_estate(conn, estate_b)

    changes = queries.snapshot_settings_diff(conn, sid_a, sid_b)
    conn.close()

    assert changes[0].gpo_name == "My Policy"


# ---- ou_tree persistence ---------------------------------------------------


def test_ou_tree_persisted_and_loaded(tmp_path):
    from gpo_lens import store
    from gpo_lens.model import OuRecord

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo = _make_gpo(id="gpo-1")
    ou = OuRecord(
        dn="OU=WS,DC=test,DC=local", name="WS", gp_link="[LDAP://cn={AAA};0]", gp_options=1
    )
    estate = Estate(
        domain="test.local",
        gpos=[gpo],
        ou_tree=[ou],
    )
    sid = store.save_estate(conn, estate)

    loaded = store.load_estate(conn, sid)
    conn.close()

    assert len(loaded.ou_tree) == 1
    assert loaded.ou_tree[0].dn == "OU=WS,DC=test,DC=local"
    assert loaded.ou_tree[0].gp_options == 1
    assert loaded.ou_tree[0].gp_link == "[LDAP://cn={AAA};0]"


# ---- broader ADMX gap heuristic -------------------------------------------


def test_admx_gaps_detects_hkcr_prefix():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="User",
                cse="Windows Registry",
                identity=r"HKCR\.ext:Content Type",
                display_name=r"HKCR\.ext",
                display_value="application/x-foo",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.admx_gaps(estate)
    assert len(result) == 1
    assert result[0].key_path == r"HKCR\.ext"


def test_admx_gaps_detects_mid_path_match():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity=r"System\CurrentControlSet\Services\MySvc:Start",
                display_name="MySvc Start",
                display_value="3",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.admx_gaps(estate)
    assert len(result) == 1


def test_admx_gaps_windows_registry_cse():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="User",
                cse="Windows Registry",
                identity=r"Software\MyApp:Setting",
                display_name=r"Software\MyApp",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.admx_gaps(estate)
    assert len(result) == 1


# ---- estate_doctor ----------------------------------------------------------


def test_estate_doctor_empty_estate():
    estate = Estate(gpos=[], soms=[])
    findings = queries.estate_doctor(estate)
    assert findings == []


def test_estate_doctor_cpassword_is_critical(tmp_path):
    import xml.etree.ElementTree as ET

    gpo_dir = tmp_path / "gpo"
    prefs = gpo_dir / "Machine" / "Preferences"
    prefs.mkdir(parents=True)
    root = ET.Element("Groups")
    user = ET.SubElement(root, "User")
    user.set("cpassword", "ABCD1234")
    tree = ET.ElementTree(root)
    tree.write(prefs / "Groups.xml")
    gpo = _make_gpo(id="abc", name="GPO", sysvol_path=str(gpo_dir))
    estate = Estate(gpos=[gpo])
    findings = queries.estate_doctor(estate)
    critical = [f for f in findings if f.severity == "critical"]
    assert len(critical) == 1
    assert critical[0].category == "cpassword"


def test_estate_doctor_ms16_072_is_high():
    gpo = _make_gpo(id="gpo-1", delegation=[])
    estate = Estate(gpos=[gpo])
    findings = queries.estate_doctor(estate)
    high = [f for f in findings if f.severity == "high"]
    assert len(high) == 1
    assert high[0].category == "ms16_072"


def test_estate_doctor_version_skew_is_medium():
    gpo = _make_gpo(computer_ver_ds=1, computer_ver_sysvol=2)
    estate = Estate(gpos=[gpo])
    findings = queries.estate_doctor(estate)
    medium = [f for f in findings if f.severity == "medium"]
    assert any(f.category == "version_skew" for f in medium)


def test_estate_doctor_unlinked_is_info():
    gpo = _make_gpo(links=[])
    estate = Estate(gpos=[gpo])
    findings = queries.estate_doctor(estate)
    info = [f for f in findings if f.severity == "info"]
    assert any(f.category == "unlinked" for f in info)


def test_estate_doctor_sorted_by_severity():
    """Critical findings should come before high, medium, low, info."""
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        computer_ver_ds=1,
        computer_ver_sysvol=2,
        delegation=[],
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity=r"Software\X:Y",
                display_name=r"Software\X",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    findings = queries.estate_doctor(estate)
    severities = [f.severity for f in findings]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    numeric = [order[s] for s in severities]
    assert numeric == sorted(numeric)


# ---- settings_dump ----------------------------------------------------------


def test_settings_dump_all():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        name="Test",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="X",
                display_name="X",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
            Setting(
                gpo_id="gpo-1",
                side="User",
                cse="Registry",
                identity="Y",
                display_name="Y",
                display_value="2",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.settings_dump(estate)
    assert len(result) == 2


def test_settings_dump_filter_side():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        name="Test",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="X",
                display_name="X",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
            Setting(
                gpo_id="gpo-1",
                side="User",
                cse="Registry",
                identity="Y",
                display_name="Y",
                display_value="2",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.settings_dump(estate, side="User")
    assert len(result) == 1
    assert result[0].side == "User"


def test_settings_dump_filter_cse():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        name="Test",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="X",
                display_name="X",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="Y",
                display_name="Y",
                display_value="2",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.settings_dump(estate, cse="Sec")
    assert len(result) == 1
    assert result[0].cse == "Security"


def test_settings_dump_filter_gpo_name():
    from gpo_lens.model import Setting

    gpo_a = _make_gpo(
        id="gpo-a",
        name="Alpha GPO",
        settings=[
            Setting(
                gpo_id="gpo-a",
                side="Computer",
                cse="Security",
                identity="X",
                display_name="X",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    gpo_b = _make_gpo(
        id="gpo-b",
        name="Beta GPO",
        settings=[
            Setting(
                gpo_id="gpo-b",
                side="Computer",
                cse="Security",
                identity="Y",
                display_name="Y",
                display_value="2",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo_a, gpo_b])
    result = queries.settings_dump(estate, gpo_name="Alpha")
    assert len(result) == 1
    assert result[0].gpo_name == "Alpha GPO"


def test_settings_dump_filter_combined():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        name="Test",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="X",
                display_name="X",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
            Setting(
                gpo_id="gpo-1",
                side="User",
                cse="Registry",
                identity="Y",
                display_name="Y",
                display_value="2",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.settings_dump(estate, side="Computer", cse="Security")
    assert len(result) == 1
    assert result[0].identity == "X"


def test_settings_dump_empty():
    estate = Estate(gpos=[])
    assert queries.settings_dump(estate) == []


def test_settings_dump_output_is_sorted():
    """settings_dump output must be deterministic regardless of GPO/setting
    insertion order — it feeds --json consumers and snapshot diffs."""
    from gpo_lens.model import Setting

    gpo_b = _make_gpo(
        id="gpo-b",
        name="Beta",
        settings=[
            Setting(
                gpo_id="gpo-b",
                side="User",
                cse="Registry",
                identity="Z",
                display_name="Z",
                display_value="z",
                raw={},
                from_disabled_side=False,
            ),
            Setting(
                gpo_id="gpo-b",
                side="Computer",
                cse="Security",
                identity="A",
                display_name="A",
                display_value="a",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    gpo_a = _make_gpo(
        id="gpo-a",
        name="Alpha",
        settings=[
            Setting(
                gpo_id="gpo-a",
                side="Computer",
                cse="Security",
                identity="B",
                display_name="B",
                display_value="b",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    forward = queries.settings_dump(Estate(gpos=[gpo_a, gpo_b]))
    reverse = queries.settings_dump(Estate(gpos=[gpo_b, gpo_a]))
    assert forward == reverse
    keys = [(r.gpo_id, r.side, r.cse, r.identity.lower()) for r in forward]
    assert keys == sorted(keys)


def test_conflicts_output_is_sorted_and_deterministic():
    """conflicts() output and its entries must be order-independent of input."""
    from gpo_lens.model import Setting

    def _make_conflicting(name: str, ident: str, value: str) -> Gpo:
        return _make_gpo(
            id=f"gpo-{name}",
            name=name,
            settings=[
                Setting(
                    gpo_id=f"gpo-{name}",
                    side="Computer",
                    cse="Security",
                    identity=ident,
                    display_name=ident,
                    display_value=value,
                    raw={},
                    from_disabled_side=False,
                ),
            ],
        )

    a1, a2 = _make_conflicting("a1", "SharedID", "1"), _make_conflicting("a2", "SharedID", "2")
    b1, b2 = _make_conflicting("b1", "Other", "x"), _make_conflicting("b2", "Other", "y")
    forward = queries.conflicts(Estate(gpos=[a1, a2, b1, b2]))
    reverse = queries.conflicts(Estate(gpos=[b2, b1, a2, a1]))
    assert forward == reverse
    for c in forward:
        assert c.entries == sorted(c.entries)


def test_broken_refs_prefers_gpp_detail_over_settings(tmp_path):
    """When a UNC appears in both GPP XML and settings, GPP detail wins."""
    gpo_dir = tmp_path / "gpo"
    prefs = gpo_dir / "Machine" / "Preferences"
    prefs.mkdir(parents=True)
    root = ET.Element("Drives")
    drive = ET.SubElement(root, "Drive")
    drive.set("Path", r"\\fileserver\share\home")
    tree = ET.ElementTree(root)
    tree.write(prefs / "Drives.xml")

    gpo = _make_gpo(
        id="gpo-1",
        sysvol_path=str(gpo_dir),
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Drives",
                identity="DriveMap:H:",
                display_name="H Drive",
                display_value=r"\\fileserver\share\home",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    assert queries.broken_refs(estate) == []
    result = [r for group in queries.external_dependencies(estate) for r in group.dependencies]
    matching = [r for r in result if r.target == r"\\fileserver\share\home"]
    assert len(matching) == 1
    # Both sources produce drive_mapping_unc; SYSVOL detail should win
    assert matching[0].dependency_type == "drive_mapping"
    assert "GPP" in matching[0].detail or "Drive" in matching[0].detail


def test_broken_refs_settings_detail_kept_when_no_gpp(tmp_path):
    """When only settings-level scan catches a UNC, settings detail is used."""
    gpo = _make_gpo(
        id="gpo-1",
        sysvol_path=None,
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="User",
                cse="Drives",
                identity="DriveMap:H:",
                display_name="H Drive",
                display_value=r"\\server\share",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    assert queries.broken_refs(estate) == []
    result = [r for group in queries.external_dependencies(estate) for r in group.dependencies]
    matching = [r for r in result if r.target == r"\\server\share"]
    assert len(matching) == 1
    assert matching[0].dependency_type == "drive_mapping"


# ---- baseline_diff ----------------------------------------------------------


def test_baseline_diff_compliant():
    from gpo_lens.model import Setting

    baseline = [
        queries.BaselineSetting(
            side="Computer",
            cse="Security",
            identity="Account:LockoutBadCount",
            display_name="LockoutBadCount",
            expected_value="5",
        ),
    ]
    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Account:LockoutBadCount",
                display_name="LockoutBadCount",
                display_value="5",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.baseline_diff(estate, baseline)
    assert len(result) == 1
    assert result[0].status == "compliant"


def test_baseline_diff_drift():
    from gpo_lens.model import Setting

    baseline = [
        queries.BaselineSetting(
            side="Computer",
            cse="Security",
            identity="Account:LockoutBadCount",
            display_name="LockoutBadCount",
            expected_value="5",
        ),
    ]
    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Account:LockoutBadCount",
                display_name="LockoutBadCount",
                display_value="10",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.baseline_diff(estate, baseline)
    assert len(result) == 1
    assert result[0].status == "drift"
    assert result[0].expected_value == "5"
    assert result[0].actual_value == "10"


def test_baseline_diff_missing():
    baseline = [
        queries.BaselineSetting(
            side="Computer",
            cse="Security",
            identity="Account:LockoutBadCount",
            display_name="LockoutBadCount",
            expected_value="5",
        ),
    ]
    estate = Estate(gpos=[_make_gpo(settings=[])])
    result = queries.baseline_diff(estate, baseline)
    assert len(result) == 1
    assert result[0].status == "missing"


def test_baseline_diff_extra():
    from gpo_lens.model import Setting

    baseline: list[queries.BaselineSetting] = []
    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Account:LockoutBadCount",
                display_name="LockoutBadCount",
                display_value="5",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.baseline_diff(estate, baseline)
    assert len(result) == 1
    assert result[0].status == "extra"


def test_baseline_diff_sorted_by_status():
    from gpo_lens.model import Setting

    baseline = [
        queries.BaselineSetting(
            side="Computer",
            cse="Security",
            identity="A",
            display_name="A",
            expected_value="1",
        ),
        queries.BaselineSetting(
            side="Computer",
            cse="Security",
            identity="B",
            display_name="B",
            expected_value="2",
        ),
    ]
    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="B",
                display_name="B",
                display_value="99",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.baseline_diff(estate, baseline)
    statuses = [r.status for r in result]
    assert statuses == ["drift", "missing"]  # drift before missing


def test_baseline_diff_uses_admx_crosswalk():
    from gpo_lens.admx_parser import AdmxPolicy, PolicyDefinitions
    from gpo_lens.model import Setting

    admx = PolicyDefinitions(
        policies=[
            AdmxPolicy(
                name="LockoutPolicy",
                class_scope="Machine",
                key="Software\\Policies\\Microsoft\\System",
                value_name="LockoutBadCount",
                display_name_ref="$(string.LockoutPolicy)",
                display_name="Account Lockout Threshold",
                explain_text="",
            ),
        ]
    )
    baseline = [
        queries.BaselineSetting(
            side="Computer",
            cse="Security",
            identity="Account:LockoutBadCount",
            display_name="LockoutBadCount",
            expected_value="5",
        ),
    ]
    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="Account:LockoutBadCount",
                display_name="LockoutBadCount",
                display_value="10",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.baseline_diff(estate, baseline, admx)
    # The ADMX crosswalk won't match "Account:LockoutBadCount" because
    # it's a Security CSE identity, not a registry path — admx_name stays empty
    assert result[0].admx_name == ""


def test_baseline_diff_admx_resolves_registry_identity():
    from gpo_lens.admx_parser import AdmxPolicy, PolicyDefinitions
    from gpo_lens.model import Setting

    admx = PolicyDefinitions(
        policies=[
            AdmxPolicy(
                name="NoControlPanel",
                class_scope="User",
                key="Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                value_name="NoControlPanel",
                display_name_ref="$(string.NoControlPanel)",
                display_name="Prohibit Control Panel",
                explain_text="",
            ),
        ]
    )
    baseline = [
        queries.BaselineSetting(
            side="User",
            cse="Registry",
            identity=r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoControlPanel",
            display_name="NoControlPanel",
            expected_value="1",
        ),
    ]
    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="User",
                cse="Registry",
                identity=r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoControlPanel",
                display_name="NoControlPanel",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.baseline_diff(estate, baseline, admx)
    assert len(result) == 1
    assert result[0].status == "compliant"
    assert result[0].admx_name == "Prohibit Control Panel"


def test_load_baseline_from_estate():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="X",
                display_name="X",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    baseline = queries.load_baseline_from_estate(estate)
    assert len(baseline) == 1
    assert baseline[0].expected_value == "1"


# ---- snapshot_changelog (version-aware change log) --------------------------


def test_snapshot_changelog_metadata_only(tmp_path):
    from gpo_lens import store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    # Snapshot A: GPO with Computer ver 1/1, User ver 1/1
    gpo_a = _make_gpo(
        id="gpo-1",
        name="Test",
        computer_ver_ds=1,
        computer_ver_sysvol=1,
        user_ver_ds=1,
        user_ver_sysvol=1,
    )
    estate_a = Estate(domain="test.local", gpos=[gpo_a])
    sid_a = store.save_estate(conn, estate_a)

    # Snapshot B: same GPO, only Computer sysvol bumped to 3 (2 edits)
    gpo_b = _make_gpo(
        id="gpo-1",
        name="Test",
        computer_ver_ds=1,
        computer_ver_sysvol=3,
        user_ver_ds=1,
        user_ver_sysvol=1,
    )
    estate_b = Estate(domain="test.local", gpos=[gpo_b])
    sid_b = store.save_estate(conn, estate_b)

    entries = queries.snapshot_changelog(conn, sid_a, sid_b)
    conn.close()

    assert len(entries) == 1
    e = entries[0]
    assert e.gpo_id == "gpo-1"
    assert e.kind == "metadata_only"
    assert e.side == "Computer"
    assert e.version_change is not None
    assert e.version_change.old_sysvol == 1
    assert e.version_change.new_sysvol == 3
    assert e.version_change.edit_count == 2
    assert e.setting_changes == []
    assert "metadata changed" in e.summary.lower()


def test_snapshot_changelog_settings_detail(tmp_path):
    from gpo_lens import store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(
        id="gpo-1",
        name="Test",
        computer_ver_ds=1,
        computer_ver_sysvol=1,
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="HKLM\\Software\\Foo",
                display_name="Foo",
                display_value="old",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate_a = Estate(domain="test.local", gpos=[gpo_a])
    sid_a = store.save_estate(conn, estate_a)

    gpo_b = _make_gpo(
        id="gpo-1",
        name="Test",
        computer_ver_ds=1,
        computer_ver_sysvol=3,
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="HKLM\\Software\\Foo",
                display_name="Foo",
                display_value="new",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate_b = Estate(domain="test.local", gpos=[gpo_b])
    sid_b = store.save_estate(conn, estate_b)

    entries = queries.snapshot_changelog(conn, sid_a, sid_b)
    conn.close()

    assert len(entries) == 1
    e = entries[0]
    assert e.kind == "settings_detail"
    assert e.side == "Computer"
    assert e.version_change is not None
    assert e.version_change.edit_count == 2
    assert len(e.setting_changes) == 1
    sc = e.setting_changes[0]
    assert sc.change_type == "modified"
    assert sc.old_value == "old"
    assert sc.new_value == "new"
    assert "edited" in e.summary.lower()
    assert "1 setting" in e.summary.lower()


def test_snapshot_changelog_user_and_computer(tmp_path):
    from gpo_lens import store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(
        id="gpo-1",
        name="Test",
        computer_ver_ds=1,
        computer_ver_sysvol=1,
        user_ver_ds=2,
        user_ver_sysvol=2,
    )
    estate_a = Estate(domain="test.local", gpos=[gpo_a])
    sid_a = store.save_estate(conn, estate_a)

    gpo_b = _make_gpo(
        id="gpo-1",
        name="Test",
        computer_ver_ds=2,
        computer_ver_sysvol=2,
        user_ver_ds=3,
        user_ver_sysvol=3,
    )
    estate_b = Estate(domain="test.local", gpos=[gpo_b])
    sid_b = store.save_estate(conn, estate_b)

    entries = queries.snapshot_changelog(conn, sid_a, sid_b)
    conn.close()

    assert len(entries) == 2
    sides = {e.side for e in entries}
    assert sides == {"Computer", "User"}
    for e in entries:
        assert e.kind == "metadata_only"
        assert e.version_change.edit_count == 1


def test_snapshot_changelog_no_changes(tmp_path):
    from gpo_lens import store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo = _make_gpo(id="gpo-1", name="Test")
    estate_a = Estate(domain="test.local", gpos=[gpo])
    sid_a = store.save_estate(conn, estate_a)
    estate_b = Estate(domain="test.local", gpos=[gpo])
    sid_b = store.save_estate(conn, estate_b)

    entries = queries.snapshot_changelog(conn, sid_a, sid_b)
    conn.close()
    assert entries == []


# ---- settings_diff -----------------------------------------------------------


def test_settings_diff_no_diff(tmp_path):
    import json

    data = [
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Security",
            "identity": "Account:Foo",
            "display_name": "Foo",
            "display_value": "1",
            "from_disabled_side": False,
        },
    ]
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    fa.write_text(json.dumps(data))
    fb.write_text(json.dumps(data))
    result = queries.settings_diff(str(fa), str(fb))
    assert result == []


def test_settings_diff_added(tmp_path):
    import json

    data_a = [
        {
            "gpo_id": "{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Security",
            "identity": "X",
            "display_name": "X",
            "display_value": "1",
            "from_disabled_side": False,
        },
    ]
    data_b = [
        {
            "gpo_id": "{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Security",
            "identity": "X",
            "display_name": "X",
            "display_value": "1",
            "from_disabled_side": False,
        },
        {
            "gpo_id": "{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Registry",
            "identity": "Y",
            "display_name": "Y",
            "display_value": "2",
            "from_disabled_side": False,
        },
    ]
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    fa.write_text(json.dumps(data_a))
    fb.write_text(json.dumps(data_b))
    result = queries.settings_diff(str(fa), str(fb))
    assert len(result) == 1
    assert result[0].change_type == "added"
    assert result[0].identity == "Y"
    assert result[0].old_value is None
    assert result[0].new_value == "2"


def test_settings_diff_removed(tmp_path):
    import json

    data_a = [
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Test",
            "side": "User",
            "cse": "Registry",
            "identity": "Z",
            "display_name": "Z",
            "display_value": "3",
            "from_disabled_side": False,
        },
    ]
    data_b: list[dict[str, object]] = []
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    fa.write_text(json.dumps(data_a))
    fb.write_text(json.dumps(data_b))
    result = queries.settings_diff(str(fa), str(fb))
    assert len(result) == 1
    assert result[0].change_type == "removed"
    assert result[0].old_value == "3"
    assert result[0].new_value is None


def test_settings_diff_modified(tmp_path):
    import json

    data_a = [
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Security",
            "identity": "LockoutBadCount",
            "display_name": "LockoutBadCount",
            "display_value": "5",
            "from_disabled_side": False,
        },
    ]
    data_b = [
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Security",
            "identity": "LockoutBadCount",
            "display_name": "LockoutBadCount",
            "display_value": "10",
            "from_disabled_side": False,
        },
    ]
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    fa.write_text(json.dumps(data_a))
    fb.write_text(json.dumps(data_b))
    result = queries.settings_diff(str(fa), str(fb))
    assert len(result) == 1
    assert result[0].change_type == "modified"
    assert result[0].old_value == "5"
    assert result[0].new_value == "10"


def test_settings_diff_canonical_guid(tmp_path):
    import json

    data_a = [
        {
            "gpo_id": "{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Security",
            "identity": "X",
            "display_name": "X",
            "display_value": "1",
            "from_disabled_side": False,
        },
    ]
    data_b = [
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Security",
            "identity": "X",
            "display_name": "X",
            "display_value": "2",
            "from_disabled_side": False,
        },
    ]
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    fa.write_text(json.dumps(data_a))
    fb.write_text(json.dumps(data_b))
    result = queries.settings_diff(str(fa), str(fb))
    assert len(result) == 1
    assert result[0].change_type == "modified"


def test_settings_diff_filter_side(tmp_path):
    import json

    data_a = [
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Security",
            "identity": "X",
            "display_name": "X",
            "display_value": "1",
            "from_disabled_side": False,
        },
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Test",
            "side": "User",
            "cse": "Registry",
            "identity": "Y",
            "display_name": "Y",
            "display_value": "2",
            "from_disabled_side": False,
        },
    ]
    data_b = [
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Security",
            "identity": "X",
            "display_name": "X",
            "display_value": "10",
            "from_disabled_side": False,
        },
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Test",
            "side": "User",
            "cse": "Registry",
            "identity": "Y",
            "display_name": "Y",
            "display_value": "20",
            "from_disabled_side": False,
        },
    ]
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    fa.write_text(json.dumps(data_a))
    fb.write_text(json.dumps(data_b))
    result = queries.settings_diff(str(fa), str(fb), side="User")
    assert len(result) == 1
    assert result[0].side == "User"
    assert result[0].new_value == "20"


def test_settings_diff_filter_cse(tmp_path):
    import json

    data_a = [
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Security",
            "identity": "X",
            "display_name": "X",
            "display_value": "1",
            "from_disabled_side": False,
        },
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Registry",
            "identity": "Y",
            "display_name": "Y",
            "display_value": "2",
            "from_disabled_side": False,
        },
    ]
    data_b = [
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Security",
            "identity": "X",
            "display_name": "X",
            "display_value": "10",
            "from_disabled_side": False,
        },
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Registry",
            "identity": "Y",
            "display_name": "Y",
            "display_value": "20",
            "from_disabled_side": False,
        },
    ]
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    fa.write_text(json.dumps(data_a))
    fb.write_text(json.dumps(data_b))
    result = queries.settings_diff(str(fa), str(fb), cse="Sec")
    assert len(result) == 1
    assert result[0].cse == "Security"


def test_settings_diff_filter_gpo_id(tmp_path):
    import json

    data_a = [
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Alpha",
            "side": "Computer",
            "cse": "Security",
            "identity": "X",
            "display_name": "X",
            "display_value": "1",
            "from_disabled_side": False,
        },
        {
            "gpo_id": "a2a2a2a2016d11d2945f00c04fb984f9",
            "gpo_name": "Beta",
            "side": "Computer",
            "cse": "Security",
            "identity": "Y",
            "display_name": "Y",
            "display_value": "2",
            "from_disabled_side": False,
        },
    ]
    data_b = [
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Alpha",
            "side": "Computer",
            "cse": "Security",
            "identity": "X",
            "display_name": "X",
            "display_value": "10",
            "from_disabled_side": False,
        },
        {
            "gpo_id": "a2a2a2a2016d11d2945f00c04fb984f9",
            "gpo_name": "Beta",
            "side": "Computer",
            "cse": "Security",
            "identity": "Y",
            "display_name": "Y",
            "display_value": "20",
            "from_disabled_side": False,
        },
    ]
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    fa.write_text(json.dumps(data_a))
    fb.write_text(json.dumps(data_b))
    result = queries.settings_diff(str(fa), str(fb), gpo_id="31b2f340")
    assert len(result) == 1
    assert result[0].gpo_id == "31b2f340016d11d2945f00c04fb984f9"


def test_settings_diff_bom_json(tmp_path):
    import json

    data_a: list[dict[str, object]] = []
    data_b = [
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Security",
            "identity": "X",
            "display_name": "X",
            "display_value": "1",
            "from_disabled_side": False,
        },
    ]
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    fa.write_text(json.dumps(data_a))
    fb.write_bytes(b"\xef\xbb\xbf" + json.dumps(data_b).encode("utf-8"))
    result = queries.settings_diff(str(fa), str(fb))
    assert len(result) == 1
    assert result[0].change_type == "added"


# ---- SDDL parsing ----------------------------------------------------------


def test_parse_sddl_simple():
    sddl = "O:S-1-5-21-123-512D:(A;;GA;;;S-1-5-21-123-512)(A;;GR;;;S-1-5-11)"
    acl = queries.parse_sddl(sddl)
    assert acl.owner_sid == "S-1-5-21-123-512"
    assert acl.group_sid is None
    assert len(acl.dacl) == 2
    assert acl.dacl[0].ace_type == "allow"
    assert acl.dacl[0].rights == "GA"
    assert acl.dacl[0].trustee_sid == "S-1-5-21-123-512"
    assert acl.dacl[1].ace_type == "allow"
    assert acl.dacl[1].rights == "GR"
    assert acl.dacl[1].trustee_sid == "S-1-5-11"
    assert len(acl.sacl) == 0


def test_parse_sddl_with_deny():
    sddl = "O:S-1-5-21-123-512D:(D;;GA;;;S-1-5-32-545)(A;;GR;;;S-1-5-11)"
    acl = queries.parse_sddl(sddl)
    assert len(acl.dacl) == 2
    assert acl.dacl[0].ace_type == "deny"
    assert acl.dacl[0].trustee_sid == "S-1-5-32-545"
    assert acl.dacl[0].rights == "GA"
    assert acl.dacl[1].ace_type == "allow"


def test_parse_sddl_with_group():
    sddl = "O:S-1-5-21-123-512G:S-1-5-21-123-513D:(A;;GA;;;S-1-5-21-123-512)"
    acl = queries.parse_sddl(sddl)
    assert acl.owner_sid == "S-1-5-21-123-512"
    assert acl.group_sid == "S-1-5-21-123-513"
    assert len(acl.dacl) == 1


def test_parse_sddl_with_flags():
    sddl = "O:S-1-5-21-123-512D:(A;CI;GA;;;S-1-5-21-123-512)(A;OI;GR;;;S-1-5-11)"
    acl = queries.parse_sddl(sddl)
    assert len(acl.dacl) == 2
    assert acl.dacl[0].flags == "CI"
    assert acl.dacl[1].flags == "OI"


def test_parse_sddl_empty():
    acl = queries.parse_sddl("")
    assert acl.owner_sid is None
    assert acl.group_sid is None
    assert acl.dacl == ()
    assert acl.sacl == ()


def test_parse_sddl_with_sacl():
    sddl = "O:S-1-5-18D:(A;;GA;;;S-1-5-18)S:(AU;SA;FA;;;WD)"
    acl = queries.parse_sddl(sddl)
    assert len(acl.dacl) == 1
    assert len(acl.sacl) == 1
    assert acl.sacl[0].ace_type == "audit_success"
    assert acl.sacl[0].trustee_sid == "WD"


def test_parse_sddl_with_dacl_flags_prefix():
    sddl = "O:S-1-5-18D:PAI(A;;GA;;;S-1-5-18)(A;;GR;;;S-1-5-11)"
    acl = queries.parse_sddl(sddl)
    assert len(acl.dacl) == 2
    assert acl.dacl[0].trustee_sid == "S-1-5-18"


def test_parse_sddl_malformed_ace():
    sddl = "O:S-1-5-18D:(A;;GA;;;S-1-5-18)(bad_ace)(A;;GR;;;S-1-5-11)"
    acl = queries.parse_sddl(sddl)
    assert len(acl.dacl) == 2


# ---- deny_aces -------------------------------------------------------------


def test_deny_aces_none():
    estate = Estate(gpos=[_make_gpo(sddl=None)])
    assert queries.deny_aces(estate) == []


def test_deny_aces_with_deny():
    sddl = "O:S-1-5-18D:(D;;GA;;;S-1-5-32-545)(A;;GR;;;S-1-5-11)"
    gpo = _make_gpo(id="gpo-1", name="Test", sddl=sddl)
    estate = Estate(gpos=[gpo])
    result = queries.deny_aces(estate)
    assert len(result) == 1
    assert result[0].gpo_id == "gpo-1"
    assert result[0].trustee_sid == "s-1-5-32-545"
    assert result[0].rights == "GA"
    assert result[0].gpo_name == "Test"
    assert result[0].acl_section == "dacl"


def test_deny_aces_no_deny():
    sddl = "O:S-1-5-18D:(A;;GA;;;S-1-5-18)(A;;GR;;;S-1-5-11)"
    gpo = _make_gpo(id="gpo-1", sddl=sddl)
    estate = Estate(gpos=[gpo])
    assert queries.deny_aces(estate) == []


def test_deny_aces_multiple_gpos():
    sddl_a = "O:S-1-5-18D:(D;;GA;;;S-1-5-32-545)(A;;GR;;;S-1-5-11)"
    sddl_b = "O:S-1-5-18D:(A;;GA;;;S-1-5-18)(D;;WD;;;S-1-5-32-545)"
    gpo_a = _make_gpo(id="gpo-a", name="A", sddl=sddl_a)
    gpo_b = _make_gpo(id="gpo-b", name="B", sddl=sddl_b)
    estate = Estate(gpos=[gpo_a, gpo_b])
    result = queries.deny_aces(estate)
    assert len(result) == 2
    sids = {d.trustee_sid for d in result}
    assert "s-1-5-32-545" in sids


# ---- excessive_writers -----------------------------------------------------


def test_excessive_writers_none():
    estate = Estate(gpos=[_make_gpo(sddl=None)])
    assert queries.excessive_writers(estate) == []


def test_excessive_writers_below_threshold():
    sddl = "O:S-1-5-21-999-512D:(A;;GA;;;S-1-5-21-999-1111)"
    gpos = [_make_gpo(id=f"gpo-{i}", name=f"GPO {i}", sddl=sddl) for i in range(3)]
    estate = Estate(gpos=gpos)
    result = queries.excessive_writers(estate, threshold=5)
    assert result == []


def test_excessive_writers_above_threshold():
    sddl = "O:S-1-5-21-999-512D:(A;;GA;;;S-1-5-21-999-1111)"
    gpos = [_make_gpo(id=f"gpo-{i}", name=f"GPO {i}", sddl=sddl) for i in range(6)]
    estate = Estate(gpos=gpos)
    result = queries.excessive_writers(estate, threshold=5)
    assert len(result) == 1
    assert result[0].trustee_sid == "s-1-5-21-999-1111"
    assert result[0].gpo_count == 6
    assert "GA" in result[0].rights


def test_excessive_writers_excludes_domain_admins():
    sddl = "O:S-1-5-21-999-512D:(A;;GA;;;S-1-5-21-999-512)"
    gpos = [_make_gpo(id=f"gpo-{i}", name=f"GPO {i}", sddl=sddl) for i in range(10)]
    estate = Estate(gpos=gpos)
    result = queries.excessive_writers(estate, threshold=5)
    assert result == []


def test_excessive_writers_excludes_local_system():
    sddl = "O:S-1-5-18D:(A;;GA;;;S-1-5-18)"
    gpos = [_make_gpo(id=f"gpo-{i}", name=f"GPO {i}", sddl=sddl) for i in range(10)]
    estate = Estate(gpos=gpos)
    result = queries.excessive_writers(estate, threshold=5)
    assert result == []


def test_excessive_writers_excludes_builtin_admins():
    sddl = "O:S-1-5-18D:(A;;GA;;;S-1-5-32-544)"
    gpos = [_make_gpo(id=f"gpo-{i}", name=f"GPO {i}", sddl=sddl) for i in range(10)]
    estate = Estate(gpos=gpos)
    result = queries.excessive_writers(estate, threshold=5)
    assert result == []


def test_excessive_writers_mixed_rights():
    sddl_a = "O:S-1-5-21-999-512D:(A;;GW;;;S-1-5-21-999-1111)"
    sddl_b = "O:S-1-5-21-999-512D:(A;;WD;;;S-1-5-21-999-1111)"
    gpos = [
        _make_gpo(id=f"gpo-{i}", name=f"GPO {i}", sddl=sddl_a if i % 2 == 0 else sddl_b)
        for i in range(6)
    ]
    estate = Estate(gpos=gpos)
    result = queries.excessive_writers(estate, threshold=5)
    assert len(result) == 1
    assert result[0].gpo_count == 6
    rights_set = set(result[0].rights)
    assert "GW" in rights_set or "WD" in rights_set


def test_excessive_writers_sorted_by_count():
    sddl_svc = "O:S-1-5-18D:(A;;GA;;;S-1-5-21-999-1111)"
    sddl_other = "O:S-1-5-18D:(A;;GA;;;S-1-5-21-999-2222)"
    gpos = [_make_gpo(id=f"svc-{i}", name=f"SvcGPO {i}", sddl=sddl_svc) for i in range(8)] + [
        _make_gpo(id=f"other-{i}", name=f"OtherGPO {i}", sddl=sddl_other) for i in range(6)
    ]
    estate = Estate(gpos=gpos)
    result = queries.excessive_writers(estate, threshold=5)
    assert len(result) == 2
    assert result[0].gpo_count >= result[1].gpo_count


# ---- delegation_deep_dive with SDDL ----------------------------------------


def test_delegation_deep_dive_with_deny_aces():
    sddl = "O:S-1-5-18D:(D;;GA;;;S-1-5-32-545)(A;;GR;;;S-1-5-11)"
    gpo = _make_gpo(id="gpo-1", name="Test", sddl=sddl)
    estate = Estate(gpos=[gpo])
    audit = queries.delegation_deep_dive(estate)
    assert len(audit.deny_aces) == 1
    assert audit.deny_aces[0].trustee_sid == "s-1-5-32-545"


def test_delegation_deep_dive_with_excessive_writers():
    sddl = "O:S-1-5-21-999-512D:(A;;GA;;;S-1-5-21-999-1111)"
    gpos = [_make_gpo(id=f"gpo-{i}", name=f"GPO {i}", sddl=sddl) for i in range(6)]
    estate = Estate(gpos=gpos)
    audit = queries.delegation_deep_dive(estate)
    assert len(audit.excessive_writers) == 1
    assert audit.excessive_writers[0].trustee_sid == "s-1-5-21-999-1111"


# ---- principal resolution on deny_aces / excessive_writers (Plan 020 A.4) ---


_COLLATED_SID = "s-1-5-21-100-200-300-1131"
_WELL_KNOWN_SID = "S-1-5-32-545"  # BUILTIN\Users


def _estate_with_principals(gpos, principals=None):
    return Estate(gpos=gpos, principals=principals or {})


def test_deny_aces_trustee_name_resolved_from_collected_map():
    """AC-1: a deny ACE on a domain group renders the group name with SID retained."""
    sddl = f"O:S-1-5-18D:(D;;GA;;;{_COLLATED_SID.upper()})"
    gpo = _make_gpo(id="gpo-1", name="Test", sddl=sddl)
    principals = {
        _COLLATED_SID: ResolvedPrincipal(
            sid=_COLLATED_SID,
            name="TEST\\GPO-Admins",
            sam="GPO-Admins",
            principal_type="Group",
            domain="TEST",
            resolved=True,
        ),
    }
    estate = _estate_with_principals([gpo], principals)
    result = queries.deny_aces(estate)
    assert len(result) == 1
    row = result[0]
    assert row.trustee_name == "TEST\\GPO-Admins"
    # AC-4: SID is always present alongside the resolved name
    assert row.trustee_sid == _COLLATED_SID


def test_deny_aces_trustee_name_well_known_without_principals_json():
    """AC-2: well-known SID resolves with no principals.json."""
    sddl = f"O:S-1-5-18D:(D;;GA;;;{_WELL_KNOWN_SID})"
    gpo = _make_gpo(id="gpo-1", sddl=sddl)
    estate = _estate_with_principals([gpo])
    result = queries.deny_aces(estate)
    assert len(result) == 1
    assert result[0].trustee_name == "BUILTIN\\Users"
    assert result[0].trustee_sid == _WELL_KNOWN_SID.lower()


def test_deny_aces_trustee_name_falls_back_to_sid_when_unresolved():
    """AC-3: unknown SID → trustee_name is the SID (never blank)."""
    sid = "S-1-5-21-999-999-999-99999"
    sddl = f"O:S-1-5-18D:(D;;GA;;;{sid})"
    gpo = _make_gpo(id="gpo-1", sddl=sddl)
    estate = _estate_with_principals([gpo])
    result = queries.deny_aces(estate)
    assert len(result) == 1
    assert result[0].trustee_name == sid.lower()
    assert result[0].trustee_sid == sid.lower()


def test_deny_aces_verdict_invariant_with_and_without_principals():
    """AC-5: detector verdicts are byte-identical with/without resolution.

    Only the trustee_name display field changes; the set/count of findings
    and every other field is unchanged.
    """
    sid = "S-1-5-21-100-200-300-1131"
    sddl = f"O:S-1-5-18D:(D;;GA;;;{sid})"
    gpo = _make_gpo(id="gpo-1", name="Test", sddl=sddl)
    estate_bare = _estate_with_principals([gpo])
    estate_resolved = _estate_with_principals(
        [gpo],
        {
            sid.lower(): ResolvedPrincipal(
                sid=sid.lower(),
                name="X\\Admins",
                sam="Admins",
                principal_type="Group",
                domain="X",
                resolved=True,
            ),
        },
    )
    bare = queries.deny_aces(estate_bare)
    resolved = queries.deny_aces(estate_resolved)
    assert len(bare) == len(resolved) == 1
    # Everything except trustee_name is identical
    assert bare[0].gpo_id == resolved[0].gpo_id
    assert bare[0].gpo_name == resolved[0].gpo_name
    assert bare[0].trustee_sid == resolved[0].trustee_sid
    assert bare[0].rights == resolved[0].rights
    assert bare[0].flags == resolved[0].flags
    assert bare[0].acl_section == resolved[0].acl_section
    # Only the name differs
    assert bare[0].trustee_name != resolved[0].trustee_name
    assert resolved[0].trustee_name == "X\\Admins"


def test_excessive_writers_trustee_name_resolved_from_collected_map():
    """AC-1: an excessive writer on a domain group renders the group name."""
    sid = "S-1-5-21-100-200-300-1131"
    sddl = f"O:S-1-5-21-999-512D:(A;;GA;;;{sid})"
    gpos = [_make_gpo(id=f"gpo-{i}", name=f"GPO {i}", sddl=sddl) for i in range(6)]
    principals = {
        sid.lower(): ResolvedPrincipal(
            sid=sid.lower(),
            name="TEST\\GPO-Admins",
            sam="GPO-Admins",
            principal_type="Group",
            domain="TEST",
            resolved=True,
        ),
    }
    estate = _estate_with_principals(gpos, principals)
    result = queries.excessive_writers(estate, threshold=5)
    assert len(result) == 1
    row = result[0]
    assert row.trustee_name == "TEST\\GPO-Admins"
    # AC-4: SID retained
    assert row.trustee_sid == sid.lower()


def test_excessive_writers_trustee_name_unresolved_falls_back_to_sid():
    """AC-3: unknown SID → trustee_name is the SID."""
    sid = "S-1-5-21-999-999-999-99999"
    sddl = f"O:S-1-5-18D:(A;;GA;;;{sid})"
    gpos = [_make_gpo(id=f"gpo-{i}", name=f"GPO {i}", sddl=sddl) for i in range(6)]
    estate = _estate_with_principals(gpos)
    result = queries.excessive_writers(estate, threshold=5)
    assert len(result) == 1
    assert result[0].trustee_name == sid.lower()
    assert result[0].trustee_sid == sid.lower()


def test_excessive_writers_verdict_invariant_with_and_without_principals():
    """AC-5: the set of excessive-writer findings is unchanged by resolution."""
    sid = "S-1-5-21-100-200-300-1131"
    sddl = f"O:S-1-5-21-999-512D:(A;;GA;;;{sid})"
    gpos = [_make_gpo(id=f"gpo-{i}", name=f"GPO {i}", sddl=sddl) for i in range(6)]
    estate_bare = _estate_with_principals(gpos)
    estate_resolved = _estate_with_principals(
        gpos,
        {
            sid.lower(): ResolvedPrincipal(
                sid=sid.lower(),
                name="X\\Admins",
                sam="Admins",
                principal_type="Group",
                domain="X",
                resolved=True,
            ),
        },
    )
    bare = queries.excessive_writers(estate_bare, threshold=5)
    resolved = queries.excessive_writers(estate_resolved, threshold=5)
    assert len(bare) == len(resolved) == 1
    assert bare[0].trustee_sid == resolved[0].trustee_sid
    assert bare[0].gpo_count == resolved[0].gpo_count
    assert bare[0].gpo_names == resolved[0].gpo_names
    assert bare[0].rights == resolved[0].rights
    assert bare[0].trustee_name != resolved[0].trustee_name
    assert resolved[0].trustee_name == "X\\Admins"


def test_deny_aces_sid_always_present_with_resolved_name():
    """AC-4: every row that shows a resolved name also carries the SID."""
    sid = "S-1-5-32-545"  # well-known BUILTIN\Users
    sddl = f"O:S-1-5-18D:(D;;GA;;;{sid})"
    gpo = _make_gpo(id="gpo-1", sddl=sddl)
    estate = _estate_with_principals([gpo])
    result = queries.deny_aces(estate)
    assert len(result) == 1
    row = result[0]
    assert row.trustee_name  # non-empty (resolved)
    assert row.trustee_sid == sid.lower()  # SID always present


def test_settings_diff_side_in_join_key(tmp_path):
    import json

    gid = "31b2f340016d11d2945f00c04fb984f9"
    data_a = [
        {
            "gpo_id": gid,
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Security",
            "identity": "SharedId",
            "display_name": "CompSetting",
            "display_value": "1",
            "from_disabled_side": False,
        },
        {
            "gpo_id": gid,
            "gpo_name": "Test",
            "side": "User",
            "cse": "Security",
            "identity": "SharedId",
            "display_name": "UserSetting",
            "display_value": "2",
            "from_disabled_side": False,
        },
    ]
    data_b = [
        {
            "gpo_id": gid,
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Security",
            "identity": "SharedId",
            "display_name": "CompSetting",
            "display_value": "10",
            "from_disabled_side": False,
        },
        {
            "gpo_id": gid,
            "gpo_name": "Test",
            "side": "User",
            "cse": "Security",
            "identity": "SharedId",
            "display_name": "UserSetting",
            "display_value": "2",
            "from_disabled_side": False,
        },
    ]
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    fa.write_text(json.dumps(data_a))
    fb.write_text(json.dumps(data_b))
    result = queries.settings_diff(str(fa), str(fb))
    assert len(result) == 1
    assert result[0].side == "Computer"
    assert result[0].change_type == "modified"
    assert result[0].old_value == "1"
    assert result[0].new_value == "10"


def test_settings_diff_invalid_guid_skipped(tmp_path):
    import json

    data_a = [
        {
            "gpo_id": "not-a-valid-guid",
            "gpo_name": "Bad",
            "side": "Computer",
            "cse": "Security",
            "identity": "X",
            "display_name": "X",
            "display_value": "1",
            "from_disabled_side": False,
        },
    ]
    data_b: list[dict[str, object]] = []
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    fa.write_text(json.dumps(data_a))
    fb.write_text(json.dumps(data_b))
    result = queries.settings_diff(str(fa), str(fb))
    assert result == []


def test_settings_diff_missing_required_key_skipped(tmp_path):
    import json

    data_a = [
        {
            "gpo_id": "31b2f340016d11d2945f00c04fb984f9",
            "gpo_name": "Test",
            "cse": "Security",
            "identity": "X",
            "display_name": "X",
            "display_value": "1",
        },
    ]
    data_b: list[dict[str, object]] = []
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    fa.write_text(json.dumps(data_a))
    fb.write_text(json.dumps(data_b))
    result = queries.settings_diff(str(fa), str(fb))
    assert result == []


def test_settings_diff_side_exact_match(tmp_path):
    import json

    gid = "31b2f340016d11d2945f00c04fb984f9"
    data_a = [
        {
            "gpo_id": gid,
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Security",
            "identity": "X",
            "display_name": "X",
            "display_value": "1",
            "from_disabled_side": False,
        },
        {
            "gpo_id": gid,
            "gpo_name": "Test",
            "side": "ComputerExtension",
            "cse": "Security",
            "identity": "Y",
            "display_name": "Y",
            "display_value": "2",
            "from_disabled_side": False,
        },
    ]
    data_b = [
        {
            "gpo_id": gid,
            "gpo_name": "Test",
            "side": "Computer",
            "cse": "Security",
            "identity": "X",
            "display_name": "X",
            "display_value": "10",
            "from_disabled_side": False,
        },
        {
            "gpo_id": gid,
            "gpo_name": "Test",
            "side": "ComputerExtension",
            "cse": "Security",
            "identity": "Y",
            "display_name": "Y",
            "display_value": "20",
            "from_disabled_side": False,
        },
    ]
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    fa.write_text(json.dumps(data_a))
    fb.write_text(json.dumps(data_b))
    result = queries.settings_diff(str(fa), str(fb), side="Computer")
    assert len(result) == 1
    assert result[0].side == "Computer"


# ---- GPP structured scanners (scheduled tasks, local groups) ---------------


def _write_gpp(tmp_path, gpo_id: str, side: str, filename: str, xml: str) -> Gpo:
    """Build a GPO whose sysvol_path contains a GPP file under Machine/Preferences."""
    base = tmp_path / "sysvol" / gpo_id
    prefs = base / side / "Preferences"
    prefs.mkdir(parents=True)
    (prefs / filename).write_text(xml)
    return _make_gpo(id=gpo_id, name=f"GPO {gpo_id}", sysvol_path=str(base))


def test_scan_scheduled_tasks_extracts_structured_fields(tmp_path):
    from gpo_lens.detection import scan_scheduled_tasks

    xml = (
        '<?xml version="1.0"?>\n'
        '<ScheduledTasks clsid="{x}">\n'
        '  <Task clsid="{y}" name="Backup Job">\n'
        '    <Properties action="REPLACE" appName="C:\\Tools\\bkup.exe"\n'
        '      arguments="--full" runAs="DOMAIN\\BackupSvc"/>\n'
        "  </Task>\n"
        "</ScheduledTasks>\n"
    )
    gpo = _write_gpp(tmp_path, "gpo-1", "Machine", "ScheduledTasks.xml", xml)
    hits = scan_scheduled_tasks(gpo)
    assert len(hits) == 1
    h = hits[0]
    assert h.kind == "Task"
    assert h.name == "Backup Job"
    assert h.action == "REPLACE"
    assert h.command == r"C:\Tools\bkup.exe"
    assert h.arguments == "--full"
    assert h.run_as == r"DOMAIN\BackupSvc"
    assert h.side == "Computer"
    assert "ScheduledTasks.xml" in h.file


def test_scan_scheduled_tasks_picks_up_immediate_tasks(tmp_path):
    from gpo_lens.detection import scan_scheduled_tasks

    xml = (
        '<?xml version="1.0"?>\n'
        "<ScheduledTasks>\n"
        '  <ImmediateTaskV2 name="OneShot">\n'
        '    <Properties action="CREATE" appName="boot.cmd"/>\n'
        "  </ImmediateTaskV2>\n"
        "</ScheduledTasks>\n"
    )
    gpo = _write_gpp(tmp_path, "gpo-u", "User", "ScheduledTasks.xml", xml)
    hits = scan_scheduled_tasks(gpo)
    assert len(hits) == 1
    assert hits[0].kind == "ImmediateTaskV2"
    assert hits[0].side == "User"


def test_scan_scheduled_tasks_empty_when_no_file(tmp_path):
    from gpo_lens.detection import scan_scheduled_tasks

    gpo = _make_gpo(id="gpo-1", sysvol_path=str(tmp_path / "nope"))
    assert scan_scheduled_tasks(gpo) == []


def test_scan_local_groups_extracts_member_deltas(tmp_path):
    from gpo_lens.detection import scan_local_groups

    xml = (
        '<?xml version="1.0"?>\n'
        "<Groups>\n"
        '  <Group name="Administrators (local)">\n'
        '    <Properties action="UPDATE" groupName="Administrators" groupSid="S-1-5-32-544">\n'
        "      <Members>\n"
        '        <Member name="DOMAIN\\Tier1" action="ADD" sid="S-1-5-21-1-1101"/>\n'
        '        <Member name="DOMAIN\\Old" action="REMOVE" sid="S-1-5-21-1-1102"/>\n'
        "      </Members>\n"
        "    </Properties>\n"
        "  </Group>\n"
        "</Groups>\n"
    )
    # Real GPP stores this in Groups.xml, not a separate file.
    gpo = _write_gpp(tmp_path, "gpo-2", "Machine", "Groups.xml", xml)
    mods = scan_local_groups(gpo)
    assert len(mods) == 1
    m = mods[0]
    assert m.group_name == "Administrators"
    assert m.group_sid == "S-1-5-32-544"
    assert m.members_added == (r"DOMAIN\Tier1",)
    assert m.members_removed == (r"DOMAIN\Old",)
    assert m.side == "Computer"


def test_scan_local_groups_ignores_user_elements(tmp_path):
    """A <User> account definition in Groups.xml is not a group membership mod."""
    from gpo_lens.detection import scan_local_groups

    xml = (
        '<?xml version="1.0"?>\n'
        "<Groups>\n"
        '  <User name="svc">\n'
        '    <Properties action="UPDATE" userName="svc"/>\n'
        "  </User>\n"
        "</Groups>\n"
    )
    gpo = _write_gpp(tmp_path, "gpo-3", "Machine", "Groups.xml", xml)
    assert scan_local_groups(gpo) == []


def test_scheduled_tasks_and_local_group_mods_are_deterministic(tmp_path):
    """Estate-wide roll-up order must not depend on GPO iteration order."""
    from gpo_lens.detection import local_group_mods, scheduled_tasks

    xml_t = (
        '<ScheduledTasks><Task name="T1"><Properties action="CREATE"'
        ' appName="a.exe"/></Task></ScheduledTasks>'
    )
    g1 = _write_gpp(tmp_path, "gpo-b", "Machine", "ScheduledTasks.xml", xml_t)
    g2 = _write_gpp(tmp_path, "gpo-a", "Machine", "ScheduledTasks.xml", xml_t)
    fwd = scheduled_tasks(Estate(gpos=[g1, g2]))
    rev = scheduled_tasks(Estate(gpos=[g2, g1]))
    assert fwd == rev
    assert [(t.gpo_id, t.name) for t in fwd] == sorted((t.gpo_id, t.name) for t in fwd)
    # local_group_mods with the same property
    xml_g = (
        '<Groups><Group name="x"><Properties groupName="Administrators">'
        '<Members><Member name="D\\A" action="ADD"/></Members></Properties>'
        "</Group></Groups>"
    )
    h1 = _write_gpp(tmp_path, "gpo-d", "Machine", "Groups.xml", xml_g)
    h2 = _write_gpp(tmp_path, "gpo-c", "Machine", "Groups.xml", xml_g)
    assert local_group_mods(Estate(gpos=[h1, h2])) == local_group_mods(Estate(gpos=[h2, h1]))
