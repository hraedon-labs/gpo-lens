"""Tests for the dangerous-configuration detectors (Plan 018 Phase B)."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from gpo_lens.danger import (
    ComplianceMapping,
    DangerRule,
    danger_findings,
    evaluate_danger_rules,
    gpo_writable_by_nonadmin,
    load_danger_rules,
    local_admin_push,
    overbroad_apply_group_policy,
)
from gpo_lens.model import DelegationEntry, Estate, Gpo, Setting

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
DEFAULT_GID = "11111111222233334444555555555555"
_WDIGEST_ID = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseLogonCredential"
_LMCOMP_ID = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:LmCompatibilityLevel"


def _make_gpo(**kwargs) -> Gpo:
    defaults = {
        "id": DEFAULT_GID,
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


def _reg_setting(
    gpo_id: str,
    identity: str,
    value: str,
    side: str = "Computer",
) -> Setting:
    return Setting(
        gpo_id=gpo_id,
        side=side,
        cse="Registry",
        identity=identity,
        display_name=identity.split(":")[-1] if ":" in identity else identity,
        display_value=value,
        raw={},
        from_disabled_side=False,
    )


# ---------------------------------------------------------------------------
# Bucket 2 — structural / attack-path
# ---------------------------------------------------------------------------


class TestGpoWritableByNonadmin:
    def test_detects_writable_gpo(self) -> None:
        # GA (Generic All) includes write rights; S-1-5-21-...-1000 is a
        # non-default-writer trustee (not Domain Admins/System/Administrators).
        sddl = "D:(A;;GA;;;S-1-5-21-1-2-3-1000)"
        gpo = _make_gpo(sddl=sddl, name="writable-gpo")
        estate = Estate(gpos=[gpo])
        findings = gpo_writable_by_nonadmin(estate)
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "gpo_writable_nonadmin"
        assert f.severity == "high"
        assert f.gpo_id == gpo.id
        assert "S-1-5-21-1-2-3-1000" in f.detail
        assert f.reference

    def test_ignores_domain_admins(self) -> None:
        sddl = "D:(A;;GA;;;S-1-5-21-1234567890-1234567890-1234567890-512)"
        gpo = _make_gpo(sddl=sddl)
        estate = Estate(gpos=[gpo])
        assert gpo_writable_by_nonadmin(estate) == []

    def test_ignores_system(self) -> None:
        sddl = "D:(A;;GA;;;S-1-5-18)"
        gpo = _make_gpo(sddl=sddl)
        estate = Estate(gpos=[gpo])
        assert gpo_writable_by_nonadmin(estate) == []

    def test_ignores_read_only_ace(self) -> None:
        # GR (Generic Read) is not a write right.
        sddl = "D:(A;;GR;;;S-1-5-21-1-2-3-1000)"
        gpo = _make_gpo(sddl=sddl)
        estate = Estate(gpos=[gpo])
        assert gpo_writable_by_nonadmin(estate) == []

    def test_no_sddl_no_finding(self) -> None:
        gpo = _make_gpo(sddl=None)
        estate = Estate(gpos=[gpo])
        assert gpo_writable_by_nonadmin(estate) == []

    def test_detects_nonadmin_owner(self) -> None:
        sddl = "O:S-1-5-21-1-2-3-1000D:(A;;GA;;;BA)"
        gpo = _make_gpo(sddl=sddl, name="owned-gpo")
        estate = Estate(gpos=[gpo])
        findings = gpo_writable_by_nonadmin(estate)
        owner_findings = [f for f in findings if f.check_id == "gpo_owner_nonadmin"]
        assert len(owner_findings) == 1
        assert "S-1-5-21-1-2-3-1000" in owner_findings[0].detail

    def test_ignores_admin_owner(self) -> None:
        sddl = "O:S-1-5-21-1234567890-1234567890-1234567890-512D:(A;;GA;;;BA)"
        gpo = _make_gpo(sddl=sddl)
        estate = Estate(gpos=[gpo])
        findings = gpo_writable_by_nonadmin(estate)
        owner_findings = [f for f in findings if f.check_id == "gpo_owner_nonadmin"]
        assert owner_findings == []

    def test_detects_object_allow_ace(self) -> None:
        sddl = "D:(OA;;GA;;;S-1-5-21-1-2-3-1000)"
        gpo = _make_gpo(sddl=sddl)
        estate = Estate(gpos=[gpo])
        findings = gpo_writable_by_nonadmin(estate)
        writable = [f for f in findings if f.check_id == "gpo_writable_nonadmin"]
        assert len(writable) == 1

    def test_ignores_real_default_gpo_dacl(self) -> None:
        """Regression: real GPO SDDL uses the ``O:DA`` alias and a Creator Owner
        (CO) full-control ACE. Neither is a hijack primitive — flagging them
        produced a finding on *every* GPO and buried the real signal."""
        sddl = (
            "O:DAG:DAD:PAI"
            "(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;DA)"  # Domain Admins full control
            "(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;EA)"  # Enterprise Admins full control
            "(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;CO)"  # Creator Owner full control
            "(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;SY)"  # SYSTEM full control
            "(A;CI;RPLCRC;;;AU)"  # Authenticated Users read+apply
        )
        gpo = _make_gpo(sddl=sddl)
        findings = gpo_writable_by_nonadmin(Estate(gpos=[gpo]))
        assert findings == []

    def test_detail_shows_resolved_name_with_sid(self) -> None:
        """AC-1/AC-4: detail shows 'name (sid)' when principals.json is present."""
        from gpo_lens.model import ResolvedPrincipal

        sid = "S-1-5-21-1-2-3-1000"
        sddl = f"D:(A;;GA;;;{sid})"
        gpo = _make_gpo(sddl=sddl, name="writable-gpo")
        estate = Estate(
            gpos=[gpo],
            principals={
                sid.lower(): ResolvedPrincipal(
                    sid=sid.lower(),
                    name="TEST\\GPO-Admins",
                    sam="GPO-Admins",
                    principal_type="Group",
                    domain="TEST",
                    resolved=True,
                ),
            },
        )
        findings = gpo_writable_by_nonadmin(estate)
        assert len(findings) == 1
        assert "TEST\\GPO-Admins" in findings[0].detail
        # AC-4: SID always present alongside the resolved name
        assert sid in findings[0].detail

    def test_detail_unresolved_shows_sid_only(self) -> None:
        """AC-3: unresolved SID → detail shows the raw SID, no blank."""
        sid = "S-1-5-21-1-2-3-1000"
        sddl = f"D:(A;;GA;;;{sid})"
        gpo = _make_gpo(sddl=sddl)
        estate = Estate(gpos=[gpo])
        findings = gpo_writable_by_nonadmin(estate)
        assert len(findings) == 1
        assert sid in findings[0].detail

    def test_owner_detail_shows_resolved_name(self) -> None:
        from gpo_lens.model import ResolvedPrincipal

        sid = "S-1-5-21-1-2-3-1000"
        sddl = f"O:{sid}D:(A;;GA;;;BA)"
        gpo = _make_gpo(sddl=sddl, name="owned-gpo")
        estate = Estate(
            gpos=[gpo],
            principals={
                sid.lower(): ResolvedPrincipal(
                    sid=sid.lower(),
                    name="TEST\\Owner",
                    sam="Owner",
                    principal_type="User",
                    domain="TEST",
                    resolved=True,
                ),
            },
        )
        findings = gpo_writable_by_nonadmin(estate)
        owner = [f for f in findings if f.check_id == "gpo_owner_nonadmin"]
        assert len(owner) == 1
        assert "TEST\\Owner" in owner[0].detail
        assert sid in owner[0].detail


class TestLocalAdminPush:
    @staticmethod
    def _make_sysvol(tmp_path: Path) -> str:
        sysvol = tmp_path / "Sysvol"
        prefs = sysvol / "Machine" / "Preferences"
        prefs.mkdir(parents=True)
        (prefs / "LocalUsersAndGroups.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D66F83}">\n'
            '  <Group name="Administrators (local)" changed="2025-06-01">\n'
            '    <Properties action="UPDATE" groupName="Administrators"\n'
            '      groupSid="S-1-5-32-544" removePolicy="0">\n'
            "      <Members>\n"
            '        <Member name="HELPDESK\\Tier1Admins" action="ADD"\n'
            '          sid="S-1-5-21-1-2-3-1101"/>\n'
            "      </Members>\n"
            "    </Properties>\n"
            "  </Group>\n"
            "</Groups>\n",
            encoding="utf-8",
        )
        return str(sysvol)

    def test_detects_admin_group_mod(self, tmp_path: Path) -> None:
        gpo = _make_gpo(
            id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            name="admin-push-gpo",
            sysvol_path=self._make_sysvol(tmp_path),
        )
        estate = Estate(gpos=[gpo])
        findings = local_admin_push(estate)
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "local_admin_push"
        assert f.severity == "high"
        assert f.gpo_id == gpo.id
        assert "Tier1Admins" in f.detail
        assert f.reference

    def test_ignores_non_admin_group(self, tmp_path: Path) -> None:
        sysvol = tmp_path / "Sysvol"
        prefs = sysvol / "Machine" / "Preferences"
        prefs.mkdir(parents=True)
        (prefs / "LocalUsersAndGroups.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D66F83}">\n'
            '  <Group name="Remote Desktop Users" changed="2025-06-01">\n'
            '    <Properties action="UPDATE" groupName="Remote Desktop Users"\n'
            '      groupSid="S-1-5-32-555" removePolicy="0">\n'
            "      <Members>\n"
            '        <Member name="HELPDESK\\Users" action="ADD" sid="S-1-5-21-1-2-3-9"/>\n'
            "      </Members>\n"
            "    </Properties>\n"
            "  </Group>\n"
            "</Groups>\n",
            encoding="utf-8",
        )
        gpo = _make_gpo(sysvol_path=str(sysvol))
        estate = Estate(gpos=[gpo])
        assert local_admin_push(estate) == []

    def test_ignores_admin_group_with_no_adds(self, tmp_path: Path) -> None:
        sysvol = tmp_path / "Sysvol"
        prefs = sysvol / "Machine" / "Preferences"
        prefs.mkdir(parents=True)
        (prefs / "LocalUsersAndGroups.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D66F83}">\n'
            '  <Group name="Administrators (local)" changed="2025-06-01">\n'
            '    <Properties action="UPDATE" groupName="Administrators"\n'
            '      groupSid="S-1-5-32-544" removePolicy="0">\n'
            "      <Members>\n"
            '        <Member name="HELPDESK\\OldAdmin" action="REMOVE"\n'
            '         sid="S-1-5-21-1-2-3-1102"/>\n'
            "      </Members>\n"
            "    </Properties>\n"
            "  </Group>\n"
            "</Groups>\n",
            encoding="utf-8",
        )
        gpo = _make_gpo(sysvol_path=str(sysvol))
        estate = Estate(gpos=[gpo])
        assert local_admin_push(estate) == []


class TestOverbroadApplyGroupPolicy:
    def test_detects_everyone(self) -> None:
        gpo = _make_gpo(
            delegation=[
                DelegationEntry(
                    gpo_id="g1",
                    trustee="Everyone",
                    trustee_sid="S-1-1-0",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        findings = overbroad_apply_group_policy(estate)
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "overbroad_apply_gp"
        assert f.severity == "medium"
        assert "s-1-1-0" in f.detail.lower()
        assert f.reference

    def test_detects_anonymous(self) -> None:
        gpo = _make_gpo(
            delegation=[
                DelegationEntry(
                    gpo_id="g1",
                    trustee="Anonymous",
                    trustee_sid="S-1-5-7",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        assert len(overbroad_apply_group_policy(estate)) == 1

    def test_ignores_helpdesk_apply(self) -> None:
        gpo = _make_gpo(
            delegation=[
                DelegationEntry(
                    gpo_id="g1",
                    trustee="Helpdesk",
                    trustee_sid="S-1-5-21-1-2-3-1000",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        assert overbroad_apply_group_policy(estate) == []

    def test_ignores_denied(self) -> None:
        gpo = _make_gpo(
            delegation=[
                DelegationEntry(
                    gpo_id="g1",
                    trustee="Everyone",
                    trustee_sid="S-1-1-0",
                    permission="Apply Group Policy",
                    allowed=False,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        assert overbroad_apply_group_policy(estate) == []

    def test_sddl_fallback_when_delegation_empty(self) -> None:
        gpo = _make_gpo(
            sddl="D:(A;;GA;;;WD)",
            delegation=[],
        )
        estate = Estate(gpos=[gpo])
        findings = overbroad_apply_group_policy(estate)
        assert len(findings) == 1
        assert findings[0].check_id == "overbroad_apply_gp"

    def test_no_sddl_fallback_when_delegation_populated(self) -> None:
        gpo = _make_gpo(
            sddl="D:(A;;GA;;;WD)",
            delegation=[
                DelegationEntry(
                    gpo_id="g1",
                    trustee="Helpdesk",
                    trustee_sid="S-1-5-21-1-2-3-1000",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        assert overbroad_apply_group_policy(estate) == []

    def test_overbroad_detail_shows_resolved_name(self) -> None:
        """AC-1: delegation path already carries the trustee name + SID."""
        gpo = _make_gpo(
            delegation=[
                DelegationEntry(
                    gpo_id="g1",
                    trustee="Everyone",
                    trustee_sid="S-1-1-0",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        findings = overbroad_apply_group_policy(estate)
        assert len(findings) == 1
        assert "Everyone" in findings[0].detail
        assert "s-1-1-0" in findings[0].detail.lower()

    def test_overbroad_sddl_fallback_detail_shows_resolved_name(self) -> None:
        """SDDL fallback path resolves the bare SID to a name via resolve_principal."""
        gpo = _make_gpo(
            sddl="D:(A;;GA;;;S-1-1-0)",
            delegation=[],
        )
        estate = Estate(gpos=[gpo])
        findings = overbroad_apply_group_policy(estate)
        assert len(findings) == 1
        assert "Everyone" in findings[0].detail
        assert "S-1-1-0" in findings[0].detail

    def test_overbroad_verdict_invariant_with_principals(self) -> None:
        """AC-5: the set of findings is unchanged by principal resolution."""
        from gpo_lens.model import ResolvedPrincipal

        sid = "S-1-1-0"
        gpo = _make_gpo(
            delegation=[
                DelegationEntry(
                    gpo_id="g1",
                    trustee="Everyone",
                    trustee_sid=sid,
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        estate_bare = Estate(gpos=[gpo])
        estate_resolved = Estate(
            gpos=[gpo],
            principals={
                sid.lower(): ResolvedPrincipal(
                    sid=sid.lower(),
                    name="Everyone",
                    sam="Everyone",
                    principal_type="WellKnown",
                    domain="",
                    resolved=True,
                ),
            },
        )
        bare = overbroad_apply_group_policy(estate_bare)
        resolved = overbroad_apply_group_policy(estate_resolved)
        assert len(bare) == len(resolved) == 1
        assert bare[0].check_id == resolved[0].check_id
        assert bare[0].gpo_id == resolved[0].gpo_id

    def test_deny_cancels_allow_for_everyone(self) -> None:
        """M-4: when Everyone has both allow and deny for Apply Group Policy,
        the deny must cancel the allow (Windows deny-first evaluation)."""
        gpo = _make_gpo(
            delegation=[
                DelegationEntry(
                    gpo_id="g1",
                    trustee="Everyone",
                    trustee_sid="S-1-1-0",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
                DelegationEntry(
                    gpo_id="g1",
                    trustee="Everyone",
                    trustee_sid="S-1-1-0",
                    permission="Apply Group Policy",
                    allowed=False,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        assert overbroad_apply_group_policy(estate) == []

    def test_sddl_deny_cancels_allow_for_everyone(self) -> None:
        """M-4: SDDL fallback path — deny ACE for Everyone cancels allow ACE."""
        gpo = _make_gpo(
            sddl="D:(A;;GA;;;S-1-1-0)(D;;GA;;;S-1-1-0)",
            delegation=[],
        )
        estate = Estate(gpos=[gpo])
        assert overbroad_apply_group_policy(estate) == []


# ---------------------------------------------------------------------------
# Bucket 1 — setting-value dangers
# ---------------------------------------------------------------------------


class TestDangerRules:
    def test_load_danger_rules_ships_cited_set(self) -> None:
        rules = load_danger_rules()
        ids = {r.id for r in rules}
        assert {
            "wdigest_creds",
            "smb_signing_disabled",
            "lm_hash_enabled",
            "autoadmin_logon",
            "ntlmv1_allowed",
        } <= ids
        for r in rules:
            assert r.reference, f"rule {r.id} has no citation"
            assert r.severity in ("critical", "high", "medium", "low")

    def test_wdigest_creds(self) -> None:
        rule = DangerRule(
            id="wdigest_creds",
            title="WDigest",
            severity="critical",
            applies="Machine",
            identity=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseLogonCredential",
            predicate="equals",
            value="1",
            reference="https://attack.mitre.org/techniques/T1003/001/",
        )
        gpo = _make_gpo(
            settings=[
                _reg_setting(DEFAULT_GID, _WDIGEST_ID, "1"),
            ]
        )
        findings = evaluate_danger_rules(Estate(gpos=[gpo]), [rule])
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert findings[0].reference == rule.reference

    def test_smb_signing_disabled(self) -> None:
        rule = DangerRule(
            id="smb_signing_disabled",
            title="SMB signing",
            severity="high",
            applies="Machine",
            identity=r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters:RequireSecuritySignature",
            predicate="equals",
            value="0",
            reference="https://attack.mitre.org/techniques/T1557/001/",
        )
        gpo = _make_gpo(
            settings=[
                _reg_setting(
                    DEFAULT_GID,
                    r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters:RequireSecuritySignature",
                    "0",
                ),
            ]
        )
        findings = evaluate_danger_rules(Estate(gpos=[gpo]), [rule])
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_no_match_when_value_safe(self) -> None:
        rule = DangerRule(
            id="wdigest_creds",
            title="WDigest",
            severity="critical",
            applies="Machine",
            identity=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseLogonCredential",
            predicate="equals",
            value="1",
            reference="ref",
        )
        gpo = _make_gpo(
            settings=[
                _reg_setting(DEFAULT_GID, _WDIGEST_ID, "0"),
            ]
        )
        assert evaluate_danger_rules(Estate(gpos=[gpo]), [rule]) == []

    def test_case_insensitive_identity(self) -> None:
        rule = DangerRule(
            id="x",
            title="x",
            severity="high",
            applies="Machine",
            identity=r"hklm\system\currentcontrolset\control\lsa:uselogoncredential",
            predicate="equals",
            value="1",
            reference="ref",
        )
        gpo = _make_gpo(
            settings=[
                _reg_setting(DEFAULT_GID, _WDIGEST_ID, "1"),
            ]
        )
        assert len(evaluate_danger_rules(Estate(gpos=[gpo]), [rule])) == 1

    def test_side_filter_machine_excludes_user(self) -> None:
        rule = DangerRule(
            id="x",
            title="x",
            severity="high",
            applies="Machine",
            identity=r"HKLM\Key:Val",
            predicate="equals",
            value="1",
            reference="ref",
        )
        gpo = _make_gpo(
            settings=[
                _reg_setting(DEFAULT_GID, r"HKLM\Key:Val", "1", side="User"),
            ]
        )
        assert evaluate_danger_rules(Estate(gpos=[gpo]), [rule]) == []

    def test_in_predicate(self) -> None:
        rule = DangerRule(
            id="ntlmv1",
            title="NTLMv1",
            severity="high",
            applies="Machine",
            identity=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:LmCompatibilityLevel",
            predicate="in",
            value="0,1",
            reference="ref",
        )
        for bad in ("0", "1"):
            gpo = _make_gpo(
                settings=[
                    _reg_setting(DEFAULT_GID, _LMCOMP_ID, bad),
                ]
            )
            assert len(evaluate_danger_rules(Estate(gpos=[gpo]), [rule])) == 1, bad
        gpo_safe = _make_gpo(
            settings=[
                _reg_setting(DEFAULT_GID, _LMCOMP_ID, "3"),
            ]
        )
        assert evaluate_danger_rules(Estate(gpos=[gpo_safe]), [rule]) == []

    def test_admx_name_keyed_resolves(self) -> None:
        from gpo_lens.admx_parser import AdmxPolicy, PolicyDefinitions

        admx = PolicyDefinitions(
            policies=[
                AdmxPolicy(
                    name="WDigestCreds",
                    class_scope="Machine",
                    key=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                    value_name="UseLogonCredential",
                    display_name_ref="$(string.WDigestCreds)",
                    display_name="WDigest plaintext credential caching",
                    explain_text="",
                )
            ]
        )
        rule = DangerRule(
            id="wdigest",
            title="WDigest",
            severity="critical",
            applies="Machine",
            identity="WDigest plaintext credential caching",
            predicate="equals",
            value="1",
            reference="https://attack.mitre.org/techniques/T1003/001/",
        )
        gpo = _make_gpo(
            settings=[
                _reg_setting(DEFAULT_GID, _WDIGEST_ID, "1"),
            ]
        )
        findings = evaluate_danger_rules(Estate(gpos=[gpo]), [rule], admx=admx)
        assert len(findings) == 1
        assert findings[0].check_id == "wdigest"

    def test_admx_none_degrades_gracefully(self) -> None:
        name_keyed = DangerRule(
            id="name_keyed",
            title="x",
            severity="high",
            applies="Machine",
            identity="Some Policy Display Name",
            predicate="equals",
            value="1",
            reference="ref",
        )
        identity_keyed = DangerRule(
            id="identity_keyed",
            title="y",
            severity="high",
            applies="Machine",
            identity=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseLogonCredential",
            predicate="equals",
            value="1",
            reference="ref2",
        )
        gpo = _make_gpo(
            settings=[
                _reg_setting(DEFAULT_GID, _WDIGEST_ID, "1"),
            ]
        )
        estate = Estate(gpos=[gpo])
        # No crash; name-keyed produces nothing, identity-keyed still fires.
        findings = evaluate_danger_rules(estate, [name_keyed, identity_keyed], admx=None)
        ids = {f.check_id for f in findings}
        assert ids == {"identity_keyed"}

    def test_blocked_settings_skipped(self) -> None:
        rule = DangerRule(
            id="x",
            title="x",
            severity="critical",
            applies="Machine",
            identity=r"HKLM\Key:Val",
            predicate="equals",
            value="1",
            reference="ref",
        )
        gpo = _make_gpo(
            settings=[
                Setting(
                    gpo_id=DEFAULT_GID,
                    side="Computer",
                    cse="Registry",
                    identity=r"HKLM\Key:Val",
                    display_name="Val",
                    display_value="1",
                    raw={},
                    from_disabled_side=False,
                    source_state="blocked",
                ),
            ]
        )
        estate = Estate(gpos=[gpo])
        assert evaluate_danger_rules(estate, [rule]) == []

    def test_lowercase_cse_name_matches(self) -> None:
        """M-2: CSE name comparison must be case-insensitive so a lowercase
        ``"registry"`` is still recognized."""
        rule = DangerRule(
            id="x",
            title="x",
            severity="high",
            applies="Machine",
            identity=r"HKLM\Key:Val",
            predicate="equals",
            value="1",
            reference="ref",
        )
        gpo = _make_gpo(
            settings=[
                Setting(
                    gpo_id=DEFAULT_GID,
                    side="Computer",
                    cse="registry",
                    identity=r"HKLM\Key:Val",
                    display_name="Val",
                    display_value="1",
                    raw={},
                    from_disabled_side=False,
                ),
            ]
        )
        estate = Estate(gpos=[gpo])
        assert len(evaluate_danger_rules(estate, [rule])) == 1

    def test_malformed_toml_warns_and_returns_empty(self, tmp_path: Path) -> None:
        """Malformed TOML warns loudly; orchestrator escalates shipped-file failure."""
        import warnings as _warnings

        bad = tmp_path / "bad.toml"
        bad.write_text("not valid toml {{{{", encoding="utf-8")
        from gpo_lens.danger import _load_rules_file

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            assert _load_rules_file(bad) == []
        assert any("Failed to load danger rules" in str(w.message) for w in caught), (
            "malformed TOML must warn loudly, not silently"
        )

    def test_load_danger_rules_raises_when_shipped_file_yields_zero_rules(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """If the shipped danger_rules.toml yields zero rules, fail loud.

        A security tool that silently returns an empty rule set when its own
        packaged rules file is corrupt/missing would report a clean estate
        while having no rules to evaluate. The orchestrator must refuse.
        """
        from gpo_lens import danger as danger_mod

        # Force the shipped-path lookup to return [].
        monkeypatch.setattr(danger_mod, "_load_rules_file", lambda _path: [])
        monkeypatch.delenv("GPO_LENS_DANGER_RULES_DIR", raising=False)
        with pytest.raises(RuntimeError, match="failed to load or contains no rules"):
            danger_mod.load_danger_rules()

    def test_load_danger_rules_override_dir_warns_on_bad_file(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """A malformed override file warns but does not abort the load."""
        import warnings as _warnings

        from gpo_lens import danger as danger_mod

        override_dir = tmp_path / "overrides"
        override_dir.mkdir()
        (override_dir / "broken.toml").write_text("not valid toml {{{{", encoding="utf-8")
        monkeypatch.setenv("GPO_LENS_DANGER_RULES_DIR", str(override_dir))
        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            rules = danger_mod.load_danger_rules()
        assert rules, "shipped rules must still load despite bad override"
        assert any("broken.toml" in str(w.message) for w in caught), "malformed override must warn"

    def test_invalid_predicate_skipped_at_load(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "rules.toml"
        toml_file.write_text(
            "[[rules]]\n"
            'id = "bad"\n'
            'title = "Bad"\n'
            'severity = "high"\n'
            'applies = "Machine"\n'
            'identity = "HKLM\\\\Key:Val"\n'
            'predicate = "exquls"\n'
            'value = "1"\n'
            'reference = "ref"\n',
            encoding="utf-8",
        )
        from gpo_lens.danger import _load_rules_file

        rules = _load_rules_file(toml_file)
        assert rules == []

    def test_missing_required_fields_skipped_with_warning(self, tmp_path: Path) -> None:
        import warnings as _warnings

        toml_file = tmp_path / "rules.toml"
        toml_file.write_text(
            "[[rules]]\n"
            'id = "missing_fields"\n'
            'title = "Has most fields"\n'
            'predicate = "equals"\n'
            'value = "1"\n'
            "[[rules]]\n"
            'id = "complete"\n'
            'title = "Complete"\n'
            'severity = "high"\n'
            'applies = "Machine"\n'
            'identity = "HKLM\\\\Key:Val"\n'
            'predicate = "equals"\n'
            'value = "1"\n'
            'reference = "ref"\n',
            encoding="utf-8",
        )
        from gpo_lens.danger import _load_rules_file

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            rules = _load_rules_file(toml_file)
        assert len(rules) == 1
        assert rules[0].id == "complete"
        skips = [str(w.message) for w in caught if "missing" in str(w.message).lower()]
        assert len(skips) == 1
        assert "severity" in skips[0] and "applies" in skips[0]
        assert "identity" in skips[0] and "reference" in skips[0]

    def test_missing_field_only_severity(self, tmp_path: Path) -> None:
        """A rule missing exactly one required field still loads others in the file."""
        import warnings as _warnings

        toml_file = tmp_path / "rules.toml"
        toml_file.write_text(
            "[[rules]]\n"
            'id = "no_severity"\n'
            'title = "No severity"\n'
            'applies = "Machine"\n'
            'identity = "HKLM\\\\Key:Val"\n'
            'predicate = "equals"\n'
            'value = "1"\n'
            'reference = "ref"\n',
            encoding="utf-8",
        )
        from gpo_lens.danger import _load_rules_file

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            rules = _load_rules_file(toml_file)
        assert rules == []
        assert any("severity" in str(w.message) for w in caught)

    def test_extra_fields_ignored(self, tmp_path: Path) -> None:
        """Unknown fields must not break the loader (forward-compatible)."""
        toml_file = tmp_path / "rules.toml"
        toml_file.write_text(
            "[[rules]]\n"
            'id = "with_extra"\n'
            'title = "Extra fields"\n'
            'severity = "high"\n'
            'applies = "Machine"\n'
            'identity = "HKLM\\\\Key:Val"\n'
            'predicate = "equals"\n'
            'value = "1"\n'
            'reference = "ref"\n'
            'future_field = "ignored"\n',
            encoding="utf-8",
        )
        from gpo_lens.danger import _load_rules_file

        rules = _load_rules_file(toml_file)
        assert len(rules) == 1
        assert rules[0].id == "with_extra"

    def test_rules_not_a_list_returns_empty(self, tmp_path: Path) -> None:
        """A scalar 'rules' must not crash the loader."""
        import warnings as _warnings

        toml_file = tmp_path / "rules.toml"
        toml_file.write_text("rules = 42\n", encoding="utf-8")
        from gpo_lens.danger import _load_rules_file

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            rules = _load_rules_file(toml_file)
        assert rules == []
        assert any("must be an array" in str(w.message) for w in caught)

    def test_non_dict_entry_skipped(self, tmp_path: Path) -> None:
        """An entry that is not a table (int/str) must not crash the loader."""
        import warnings as _warnings

        toml_file = tmp_path / "rules.toml"
        toml_file.write_text(
            "rules = ["
            '{id = "ok", title = "Ok", severity = "high", '
            'applies = "Machine", identity = "HKLM\\\\K:V", '
            'predicate = "equals", value = "1", reference = "ref"}, 42'
            "]\n",
            encoding="utf-8",
        )
        from gpo_lens.danger import _load_rules_file

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            rules = _load_rules_file(toml_file)
        assert len(rules) == 1
        assert rules[0].id == "ok"
        assert any("non-table" in str(w.message) for w in caught)


# ---------------------------------------------------------------------------
# Compliance framework mapping
# ---------------------------------------------------------------------------


class TestComplianceMapping:
    def test_compliance_parsed_from_toml(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "rules.toml"
        toml_file.write_text(
            "[[rules]]\n"
            'id = "with_compliance"\n'
            'title = "Test"\n'
            'severity = "high"\n'
            'applies = "Machine"\n'
            'identity = "HKLM\\\\Key:Val"\n'
            'predicate = "equals"\n'
            'value = "1"\n'
            'reference = "ref"\n'
            "[[rules.compliance]]\n"
            'framework = "CIS"\n'
            'control_id = "2.3.11.1"\n'
            "[[rules.compliance]]\n"
            'framework = "STIG"\n'
            'control_id = "WN10-CC-000001"\n',
            encoding="utf-8",
        )
        from gpo_lens.danger import _load_rules_file

        rules = _load_rules_file(toml_file)
        assert len(rules) == 1
        rule = rules[0]
        assert len(rule.compliance) == 2
        assert rule.compliance[0] == ComplianceMapping(framework="CIS", control_id="2.3.11.1")
        assert rule.compliance[1] == ComplianceMapping(
            framework="STIG", control_id="WN10-CC-000001"
        )

    def test_rules_without_compliance_default_empty(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "rules.toml"
        toml_file.write_text(
            "[[rules]]\n"
            'id = "no_compliance"\n'
            'title = "Test"\n'
            'severity = "high"\n'
            'applies = "Machine"\n'
            'identity = "HKLM\\\\Key:Val"\n'
            'predicate = "equals"\n'
            'value = "1"\n'
            'reference = "ref"\n',
            encoding="utf-8",
        )
        from gpo_lens.danger import _load_rules_file

        rules = _load_rules_file(toml_file)
        assert len(rules) == 1
        assert rules[0].compliance == ()

    def test_compliance_propagated_to_finding(self) -> None:
        rule = DangerRule(
            id="wdigest_creds",
            title="WDigest",
            severity="critical",
            applies="Machine",
            identity=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseLogonCredential",
            predicate="equals",
            value="1",
            reference="https://attack.mitre.org/techniques/T1003/001/",
            compliance=(
                ComplianceMapping(framework="CIS", control_id="2.3.11.1"),
                ComplianceMapping(framework="STIG", control_id="WN10-CC-000001"),
            ),
        )
        gpo = _make_gpo(
            settings=[
                _reg_setting(DEFAULT_GID, _WDIGEST_ID, "1"),
            ]
        )
        findings = evaluate_danger_rules(Estate(gpos=[gpo]), [rule])
        assert len(findings) == 1
        assert findings[0].compliance == rule.compliance

    def test_compliance_empty_when_not_set_on_rule(self) -> None:
        rule = DangerRule(
            id="x",
            title="x",
            severity="high",
            applies="Machine",
            identity=r"HKLM\Key:Val",
            predicate="equals",
            value="1",
            reference="ref",
        )
        gpo = _make_gpo(
            settings=[
                _reg_setting(DEFAULT_GID, r"HKLM\Key:Val", "1"),
            ]
        )
        findings = evaluate_danger_rules(Estate(gpos=[gpo]), [rule])
        assert len(findings) == 1
        assert findings[0].compliance == ()

    def test_invalid_compliance_entry_skipped(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "rules.toml"
        toml_file.write_text(
            "[[rules]]\n"
            'id = "mixed_compliance"\n'
            'title = "Test"\n'
            'severity = "high"\n'
            'applies = "Machine"\n'
            'identity = "HKLM\\\\Key:Val"\n'
            'predicate = "equals"\n'
            'value = "1"\n'
            'reference = "ref"\n'
            "[[rules.compliance]]\n"
            'framework = "CIS"\n'
            'control_id = "2.3.11.1"\n'
            "[[rules.compliance]]\n"
            'framework = "STIG"\n',
            encoding="utf-8",
        )
        import warnings as _warnings

        from gpo_lens.danger import _load_rules_file

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            rules = _load_rules_file(toml_file)
        assert len(rules) == 1
        assert len(rules[0].compliance) == 1
        assert rules[0].compliance[0].framework == "CIS"
        assert any("framework/control_id" in str(w.message) for w in caught)

    def test_compliance_not_a_list_defaults_empty(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "rules.toml"
        toml_file.write_text(
            "[[rules]]\n"
            'id = "scalar_compliance"\n'
            'title = "Test"\n'
            'severity = "high"\n'
            'applies = "Machine"\n'
            'identity = "HKLM\\\\Key:Val"\n'
            'predicate = "equals"\n'
            'value = "1"\n'
            'reference = "ref"\n'
            'compliance = "not-a-list"\n',
            encoding="utf-8",
        )
        from gpo_lens.danger import _load_rules_file

        rules = _load_rules_file(toml_file)
        assert len(rules) == 1
        assert rules[0].compliance == ()

    def test_compliance_empty_framework_skipped(self, tmp_path: Path) -> None:
        """Empty/whitespace-only framework must be skipped with a warning."""
        import warnings as _warnings

        toml_file = tmp_path / "rules.toml"
        toml_file.write_text(
            "[[rules]]\n"
            'id = "empty_fw"\n'
            'title = "Test"\n'
            'severity = "high"\n'
            'applies = "Machine"\n'
            'identity = "HKLM\\\\Key:Val"\n'
            'predicate = "equals"\n'
            'value = "1"\n'
            'reference = "ref"\n'
            "[[rules.compliance]]\n"
            'framework = ""\n'
            'control_id = "WN10-CC-000038"\n'
            "[[rules.compliance]]\n"
            'framework = "CIS"\n'
            'control_id = "18.6.2"\n',
            encoding="utf-8",
        )
        from gpo_lens.danger import _load_rules_file

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            rules = _load_rules_file(toml_file)
        assert len(rules) == 1
        # Only the well-formed entry survives.
        assert len(rules[0].compliance) == 1
        assert rules[0].compliance[0].framework == "CIS"
        assert any("framework/control_id" in str(w.message) for w in caught)

    def test_compliance_whitespace_control_id_skipped(self, tmp_path: Path) -> None:
        """Whitespace-only control_id must be skipped with a warning."""
        import warnings as _warnings

        toml_file = tmp_path / "rules.toml"
        toml_file.write_text(
            "[[rules]]\n"
            'id = "ws_cid"\n'
            'title = "Test"\n'
            'severity = "high"\n'
            'applies = "Machine"\n'
            'identity = "HKLM\\\\Key:Val"\n'
            'predicate = "equals"\n'
            'value = "1"\n'
            'reference = "ref"\n'
            "[[rules.compliance]]\n"
            'framework = "STIG"\n'
            'control_id = "   "\n',
            encoding="utf-8",
        )
        from gpo_lens.danger import _load_rules_file

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            rules = _load_rules_file(toml_file)
        assert len(rules) == 1
        assert rules[0].compliance == ()
        assert any("framework/control_id" in str(w.message) for w in caught)

    def test_absent_rule_finding_carries_compliance(self) -> None:
        """An ``absent`` predicate rule that fires (setting not found estate-wide)
        must propagate its compliance mappings to the finding."""
        rule = DangerRule(
            id="missing_setting",
            title="Required setting is absent",
            severity="high",
            applies="Machine",
            identity=r"HKLM\SYSTEM\SomeKey:MissingValue",
            predicate="absent",
            value="",
            reference="https://example.com/ref",
            compliance=(
                ComplianceMapping(framework="CIS", control_id="18.6.2"),
                ComplianceMapping(framework="STIG", control_id="WN10-CC-000038"),
            ),
        )
        # Empty estate → the absent rule fires (no setting matches).
        estate = Estate(gpos=[])
        findings = evaluate_danger_rules(estate, [rule])
        assert len(findings) == 1
        assert findings[0].check_id == "missing_setting"
        assert findings[0].gpo_id == ""  # estate-wide
        assert findings[0].compliance == rule.compliance


class TestBucket2Compliance:
    def test_writable_finding_has_compliance(self) -> None:
        sddl = "D:(A;;GA;;;S-1-5-21-1-2-3-1000)"
        gpo = _make_gpo(sddl=sddl, name="writable-gpo")
        estate = Estate(gpos=[gpo])
        findings = gpo_writable_by_nonadmin(estate)
        writable = [f for f in findings if f.check_id == "gpo_writable_nonadmin"]
        assert len(writable) == 1
        assert len(writable[0].compliance) >= 2
        frameworks = {c.framework for c in writable[0].compliance}
        assert "CIS" in frameworks
        assert "NIST-800-171" in frameworks
        assert "STIG" not in frameworks

    def test_owner_finding_has_compliance(self) -> None:
        sddl = "O:S-1-5-21-1-2-3-1000D:(A;;GA;;;BA)"
        gpo = _make_gpo(sddl=sddl, name="owned-gpo")
        estate = Estate(gpos=[gpo])
        findings = gpo_writable_by_nonadmin(estate)
        owner = [f for f in findings if f.check_id == "gpo_owner_nonadmin"]
        assert len(owner) == 1
        assert len(owner[0].compliance) >= 2
        frameworks = {c.framework for c in owner[0].compliance}
        assert "CIS" in frameworks

    def test_local_admin_push_has_compliance(self, tmp_path: Path) -> None:
        from gpo_lens.danger import _BUCKET2_COMPLIANCE

        sysvol = tmp_path / "Sysvol"
        prefs = sysvol / "Machine" / "Preferences"
        prefs.mkdir(parents=True)
        (prefs / "LocalUsersAndGroups.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D66F83}">\n'
            '  <Group name="Administrators (local)" changed="2025-06-01">\n'
            '    <Properties action="UPDATE" groupName="Administrators"\n'
            '      groupSid="S-1-5-32-544" removePolicy="0">\n'
            "      <Members>\n"
            '        <Member name="HELPDESK\\Tier1Admins" action="ADD"\n'
            '          sid="S-1-5-21-1-2-3-1101"/>\n'
            "      </Members>\n"
            "    </Properties>\n"
            "  </Group>\n"
            "</Groups>\n",
            encoding="utf-8",
        )
        gpo = _make_gpo(
            id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            name="admin-push-gpo",
            sysvol_path=str(sysvol),
        )
        estate = Estate(gpos=[gpo])
        findings = local_admin_push(estate)
        assert len(findings) == 1
        expected = _BUCKET2_COMPLIANCE["local_admin_push"]
        assert findings[0].compliance == expected
        frameworks = {c.framework for c in findings[0].compliance}
        assert "NIST-800-171" in frameworks
        assert "CIS" in frameworks
        assert "STIG" not in frameworks

    def test_overbroad_apply_gp_has_compliance(self) -> None:
        gpo = _make_gpo(
            delegation=[
                DelegationEntry(
                    gpo_id="g1",
                    trustee="Everyone",
                    trustee_sid="S-1-1-0",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        findings = overbroad_apply_group_policy(estate)
        assert len(findings) == 1
        assert len(findings[0].compliance) >= 2
        frameworks = {c.framework for c in findings[0].compliance}
        assert "NIST-800-171" in frameworks
        assert "CIS" in frameworks

    def test_overbroad_sddl_fallback_has_compliance(self) -> None:
        gpo = _make_gpo(
            sddl="D:(A;;GA;;;WD)",
            delegation=[],
        )
        estate = Estate(gpos=[gpo])
        findings = overbroad_apply_group_policy(estate)
        assert len(findings) == 1
        assert len(findings[0].compliance) >= 2


class TestShippedRulesCompliance:
    def test_shipped_rules_have_compliance(self) -> None:
        rules = load_danger_rules()
        rule_map = {r.id: r for r in rules}
        for rid in (
            "wdigest_creds",
            "smb_signing_disabled",
            "lm_hash_enabled",
            "autoadmin_logon",
            "ntlmv1_allowed",
        ):
            assert rid in rule_map, f"Missing shipped rule: {rid}"
            assert len(rule_map[rid].compliance) >= 1, f"Rule {rid} has no compliance mappings"

    def test_shipped_compliance_entries_well_formed(self) -> None:
        rules = load_danger_rules()
        for r in rules:
            for c in r.compliance:
                assert c.framework, f"Rule {r.id}: empty framework"
                assert c.control_id, f"Rule {r.id}: empty control_id"

    def test_shipped_stig_control_ids_verified(self) -> None:
        """The shipped STIG control IDs must match the verified values."""
        rules = load_danger_rules()
        rule_map = {r.id: r for r in rules}
        expected_stig = {
            "wdigest_creds": "WN10-CC-000038",
            "smb_signing_disabled": "WN10-SO-000100",
            "lm_hash_enabled": "WN10-SO-000195",
            "autoadmin_logon": "WN10-CC-000325",
            "ntlmv1_allowed": "WN10-SO-000205",
        }
        for rid, expected_stig_id in expected_stig.items():
            assert rid in rule_map, f"Missing shipped rule: {rid}"
            stig_mappings = [c for c in rule_map[rid].compliance if c.framework == "STIG"]
            assert len(stig_mappings) == 1, (
                f"Rule {rid}: expected exactly one STIG mapping, got {len(stig_mappings)}"
            )
            assert stig_mappings[0].control_id == expected_stig_id, (
                f"Rule {rid}: STIG control_id should be {expected_stig_id}, "
                f"got {stig_mappings[0].control_id}"
            )

    def test_wdigest_cis_control_id_verified(self) -> None:
        """wdigest_creds CIS control must be 18.6.2 (WDigest Authentication)."""
        rules = load_danger_rules()
        rule_map = {r.id: r for r in rules}
        assert "wdigest_creds" in rule_map
        cis_mappings = [c for c in rule_map["wdigest_creds"].compliance if c.framework == "CIS"]
        assert len(cis_mappings) == 1
        assert cis_mappings[0].control_id == "18.6.2"


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------


class TestDangerFindings:
    def test_aggregate_sorted_by_severity(self) -> None:
        critical_rule = DangerRule(
            id="wdigest_creds",
            title="WDigest",
            severity="critical",
            applies="Machine",
            identity=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseLogonCredential",
            predicate="equals",
            value="1",
            reference="ref",
        )
        writable_gpo = _make_gpo(
            id="11111111111111111111111111111111",
            name="writable",
            sddl="D:(A;;GA;;;S-1-5-21-1-2-3-1000)",
        )
        dangerous_gpo = _make_gpo(
            id="22222222222222222222222222222222",
            name="wdigest-gpo",
            settings=[
                _reg_setting(
                    "22222222222222222222222222222222",
                    r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseLogonCredential",
                    "1",
                ),
            ],
        )
        estate = Estate(gpos=[writable_gpo, dangerous_gpo])
        findings = danger_findings(estate, rules=[critical_rule])
        severities = [f.severity for f in findings]
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        assert severities == sorted(severities, key=lambda s: rank.get(s, 99))
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# Integration: estate_doctor + estate_summary
# ---------------------------------------------------------------------------


class TestIntegration:
    def test_danger_findings_in_estate_doctor(self) -> None:
        from gpo_lens.queries import estate_doctor

        gpo = _make_gpo(
            sddl="D:(A;;GA;;;S-1-5-21-1-2-3-1000)",
            name="writable-gpo",
        )
        estate = Estate(gpos=[gpo])
        findings = estate_doctor(estate)
        danger_cats = {f.category for f in findings if f.category.startswith("danger:")}
        assert "danger:gpo_writable_nonadmin" in danger_cats
        assert all("[ref:" in f.detail for f in findings if f.category.startswith("danger:"))

    def test_doctor_finding_carries_compliance(self) -> None:
        """Danger findings propagated through estate_doctor must carry their
        compliance mappings on the DoctorFinding."""
        from gpo_lens.queries import estate_doctor

        gpo = _make_gpo(
            sddl="D:(A;;GA;;;S-1-5-21-1-2-3-1000)",
            name="writable-gpo",
        )
        estate = Estate(gpos=[gpo])
        findings = estate_doctor(estate)
        danger = [f for f in findings if f.category == "danger:gpo_writable_nonadmin"]
        assert len(danger) == 1
        assert len(danger[0].compliance) >= 2
        frameworks = {c.framework for c in danger[0].compliance}
        assert "CIS" in frameworks
        assert "NIST-800-171" in frameworks
        # STIG was removed from Bucket 2 structural checks (AD-level, not
        # endpoint STIG).
        assert "STIG" not in frameworks

    def test_doctor_finding_compliance_empty_for_non_danger(self) -> None:
        """Non-danger DoctorFindings (e.g. cpassword, version_skew) must have
        an empty compliance tuple (the default)."""
        from gpo_lens.queries import estate_doctor

        gpo = _make_gpo(
            id="11111111111111111111111111111111",
            name="stale-gpo",
            computer_ver_ds=2,
            computer_ver_sysvol=1,
        )
        estate = Estate(gpos=[gpo])
        findings = estate_doctor(estate)
        non_danger = [f for f in findings if not f.category.startswith("danger:")]
        assert len(non_danger) >= 1
        for f in non_danger:
            assert f.compliance == ()

    def test_danger_findings_in_estate_summary(self) -> None:
        from gpo_lens.queries import estate_summary

        gpo = _make_gpo(
            sddl="D:(A;;GA;;;S-1-5-21-1-2-3-1000)",
            name="writable-gpo",
        )
        estate = Estate(gpos=[gpo])
        summary = estate_summary(estate)
        assert summary.danger_finding_count == 1

        clean = Estate(gpos=[_make_gpo()])
        assert estate_summary(clean).danger_finding_count == 0


# ---------------------------------------------------------------------------
# Web route
# ---------------------------------------------------------------------------

try:
    import fastapi  # noqa: F401

    _HAS_WEB = True
except ImportError:
    _HAS_WEB = False

pytestmark_web = pytest.mark.skipif(not _HAS_WEB, reason="web extra not installed")


@pytest.fixture()
def _fixture_db():
    from gpo_lens.ingest import load_estate as ingest_load_estate
    from gpo_lens.store import init_db, save_estate

    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
        path = f.name
    conn = sqlite3.connect(path)
    init_db(conn)
    estate = ingest_load_estate(FIXTURE_DIR)
    save_estate(conn, estate)
    conn.close()
    try:
        yield path
    finally:
        os.unlink(path)


@pytest.fixture()
def _client(_fixture_db, monkeypatch):
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    app = create_app(_fixture_db)
    return TestClient(
        app,
        headers={
            "origin": "http://localhost",
            "Authorization": "Bearer test-secret-token",
        },
    )


@pytest.mark.skipif(not _HAS_WEB, reason="web extra not installed")
class TestDangerWebRoute:
    def test_danger_route_returns_200(self, _client) -> None:
        resp = _client.get("/danger")
        assert resp.status_code == 200
        assert "Dangerous configurations" in resp.text

    def test_danger_route_shows_finding(self, _client) -> None:
        resp = _client.get("/danger")
        assert resp.status_code == 200
        # The fixture GPO AAAAAAAA pushes local Administrators membership.
        assert "local_admin_push" in resp.text
        assert "citation" in resp.text

    def test_danger_route_severity_filter(self, _client) -> None:
        resp = _client.get("/danger", params={"severity": "high"})
        assert resp.status_code == 200
        assert "gp-pill high" in resp.text

    def test_danger_route_shows_compliance_badges(self, _client) -> None:
        import re

        resp = _client.get("/danger")
        assert resp.status_code == 200
        assert "gp-badge" in resp.text
        # The card layout shows compliance badges inline in the group header,
        # not in a "Compliance" table column.
        assert "gp-danger-group" in resp.text
        # Strengthened: actual framework names and control_ids must appear inside
        # <span class="gp-badge"> elements.
        badges = re.findall(r'<span class="gp-badge">(.*?)</span>', resp.text)
        assert len(badges) >= 1, "Expected at least one compliance badge in HTML"
        framework_names = {"CIS", "STIG", "NIST-800-171"}
        # At least one badge contains a known framework name.
        assert any(fw in b for b in badges for fw in framework_names)
        # At least one badge carries a control_id (non-empty token after the
        # framework name).
        assert any(len(b.split()) >= 2 and b.split()[-1] for b in badges)


# ---------------------------------------------------------------------------
# CLI parity
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _HAS_WEB, reason="needs fixture estate + web stack")
class TestDangerCli:
    def test_danger_cli_json(self, _fixture_db, capsys) -> None:
        from gpo_lens.cli import main

        rc = main(["--db", _fixture_db, "danger", "--json"])
        out = capsys.readouterr().out
        assert rc == 0
        env = json.loads(out)
        assert env["schema_version"] == 2
        assert env["kind"] == "danger"
        data = env["data"]
        assert isinstance(data, list)
        assert len(data) >= 1
        expected = {
            "check_id",
            "severity",
            "title",
            "gpo_id",
            "gpo_name",
            "detail",
            "reference",
        }
        assert expected <= set(data[0])

    def test_danger_cli_json_includes_compliance(self, _fixture_db, capsys) -> None:
        from gpo_lens.cli import main

        rc = main(["--db", _fixture_db, "danger", "--json"])
        out = capsys.readouterr().out
        assert rc == 0
        env = json.loads(out)
        data = env["data"]
        assert isinstance(data, list)
        assert len(data) >= 1
        for entry in data:
            assert "compliance" in entry, "Missing compliance key in JSON output"
            assert isinstance(entry["compliance"], list)
        local_admin = [e for e in data if e["check_id"] == "local_admin_push"]
        if local_admin:
            assert len(local_admin[0]["compliance"]) >= 1
            for c in local_admin[0]["compliance"]:
                assert "framework" in c
                assert "control_id" in c

    def test_danger_cli_json_includes_remediation(self, _fixture_db, capsys) -> None:
        from gpo_lens.cli import main

        rc = main(["--db", _fixture_db, "danger", "--json"])
        out = capsys.readouterr().out
        assert rc == 0
        env = json.loads(out)
        data = env["data"]
        assert isinstance(data, list)
        assert len(data) >= 1
        for entry in data:
            assert "remediation" in entry, "Missing remediation key in JSON output"
            assert isinstance(entry["remediation"], str)
        local_admin = [e for e in data if e["check_id"] == "local_admin_push"]
        if local_admin:
            assert local_admin[0]["remediation"], (
                "local_admin_push finding should carry non-empty remediation"
            )


# ---------------------------------------------------------------------------
# Remediation guidance (WI-055)
# ---------------------------------------------------------------------------


class TestRemediationBucket1:
    def test_shipped_toml_has_remediation_for_all_rules(self) -> None:
        rules = load_danger_rules()
        rule_map = {r.id: r for r in rules}
        for rid in (
            "wdigest_creds",
            "smb_signing_disabled",
            "lm_hash_enabled",
            "autoadmin_logon",
            "ntlmv1_allowed",
        ):
            assert rid in rule_map, f"Missing shipped rule: {rid}"
            assert rule_map[rid].remediation, f"Rule {rid} has no remediation text"

    def test_shipped_remediation_mentions_key_setting(self) -> None:
        rules = load_danger_rules()
        rule_map = {r.id: r for r in rules}
        assert "UseLogonCredential" in rule_map["wdigest_creds"].remediation
        assert "RequireSecuritySignature" in rule_map["smb_signing_disabled"].remediation
        assert "NoLMHash" in rule_map["lm_hash_enabled"].remediation
        assert "AutoAdminLogon" in rule_map["autoadmin_logon"].remediation
        assert "LmCompatibilityLevel" in rule_map["ntlmv1_allowed"].remediation

    def test_remediation_propagated_to_present_finding(self) -> None:
        rule = DangerRule(
            id="wdigest_creds",
            title="WDigest",
            severity="critical",
            applies="Machine",
            identity=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseLogonCredential",
            predicate="equals",
            value="1",
            reference="https://attack.mitre.org/techniques/T1003/001/",
            remediation="Set UseLogonCredential to 0.",
        )
        gpo = _make_gpo(
            settings=[
                _reg_setting(DEFAULT_GID, _WDIGEST_ID, "1"),
            ]
        )
        findings = evaluate_danger_rules(Estate(gpos=[gpo]), [rule])
        assert len(findings) == 1
        assert findings[0].remediation == "Set UseLogonCredential to 0."

    def test_remediation_propagated_to_absent_finding(self) -> None:
        rule = DangerRule(
            id="missing_setting",
            title="Required setting is absent",
            severity="high",
            applies="Machine",
            identity=r"HKLM\SYSTEM\SomeKey:MissingValue",
            predicate="absent",
            value="",
            reference="https://example.com/ref",
            remediation="Configure the missing setting.",
        )
        estate = Estate(gpos=[])
        findings = evaluate_danger_rules(estate, [rule])
        assert len(findings) == 1
        assert findings[0].remediation == "Configure the missing setting."

    def test_remediation_defaults_empty_when_not_set(self) -> None:
        rule = DangerRule(
            id="x",
            title="x",
            severity="high",
            applies="Machine",
            identity=r"HKLM\Key:Val",
            predicate="equals",
            value="1",
            reference="ref",
        )
        gpo = _make_gpo(
            settings=[
                _reg_setting(DEFAULT_GID, r"HKLM\Key:Val", "1"),
            ]
        )
        findings = evaluate_danger_rules(Estate(gpos=[gpo]), [rule])
        assert len(findings) == 1
        assert findings[0].remediation == ""

    def test_remediation_loaded_from_toml(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "rules.toml"
        toml_file.write_text(
            "[[rules]]\n"
            'id = "with_remediation"\n'
            'title = "Test"\n'
            'severity = "high"\n'
            'applies = "Machine"\n'
            'identity = "HKLM\\\\Key:Val"\n'
            'predicate = "equals"\n'
            'value = "1"\n'
            'reference = "ref"\n'
            'remediation = "Fix it like this."\n',
            encoding="utf-8",
        )
        from gpo_lens.danger import _load_rules_file

        rules = _load_rules_file(toml_file)
        assert len(rules) == 1
        assert rules[0].remediation == "Fix it like this."

    def test_remediation_defaults_empty_in_toml_when_absent(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "rules.toml"
        toml_file.write_text(
            "[[rules]]\n"
            'id = "no_remediation"\n'
            'title = "Test"\n'
            'severity = "high"\n'
            'applies = "Machine"\n'
            'identity = "HKLM\\\\Key:Val"\n'
            'predicate = "equals"\n'
            'value = "1"\n'
            'reference = "ref"\n',
            encoding="utf-8",
        )
        from gpo_lens.danger import _load_rules_file

        rules = _load_rules_file(toml_file)
        assert len(rules) == 1
        assert rules[0].remediation == ""

    def test_remediation_loaded_via_drop_in_override(self, tmp_path: Path, monkeypatch) -> None:
        """A drop-in TOML in GPO_LENS_DANGER_RULES_DIR that overrides a shipped
        rule must propagate its remediation text through load_danger_rules()."""
        override_dir = tmp_path / "overrides"
        override_dir.mkdir()
        (override_dir / "custom.toml").write_text(
            "[[rules]]\n"
            'id = "wdigest_creds"\n'
            'title = "WDigest override"\n'
            'severity = "critical"\n'
            'applies = "Machine"\n'
            'identity = "HKLM\\\\Key:Val"\n'
            'predicate = "equals"\n'
            'value = "1"\n'
            'reference = "https://example.com/override"\n'
            'remediation = "Custom override remediation text."\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("GPO_LENS_DANGER_RULES_DIR", str(override_dir))
        rules = load_danger_rules()
        rule_map = {r.id: r for r in rules}
        assert "wdigest_creds" in rule_map
        assert rule_map["wdigest_creds"].remediation == "Custom override remediation text."
        assert rule_map["wdigest_creds"].title == "WDigest override"


class TestRemediationBucket2:
    def test_writable_finding_has_remediation(self) -> None:
        sddl = "D:(A;;GA;;;S-1-5-21-1-2-3-1000)"
        gpo = _make_gpo(sddl=sddl, name="writable-gpo")
        estate = Estate(gpos=[gpo])
        findings = gpo_writable_by_nonadmin(estate)
        writable = [f for f in findings if f.check_id == "gpo_writable_nonadmin"]
        assert len(writable) == 1
        assert writable[0].remediation
        assert "write permissions" in writable[0].remediation.lower()

    def test_owner_finding_has_remediation(self) -> None:
        sddl = "O:S-1-5-21-1-2-3-1000D:(A;;GA;;;BA)"
        gpo = _make_gpo(sddl=sddl, name="owned-gpo")
        estate = Estate(gpos=[gpo])
        findings = gpo_writable_by_nonadmin(estate)
        owner = [f for f in findings if f.check_id == "gpo_owner_nonadmin"]
        assert len(owner) == 1
        assert owner[0].remediation
        assert "owner" in owner[0].remediation.lower()

    def test_local_admin_push_has_remediation(self, tmp_path: Path) -> None:
        from gpo_lens.danger import _BUCKET2_REMEDIATION

        sysvol = tmp_path / "Sysvol"
        prefs = sysvol / "Machine" / "Preferences"
        prefs.mkdir(parents=True)
        (prefs / "LocalUsersAndGroups.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D66F83}">\n'
            '  <Group name="Administrators (local)" changed="2025-06-01">\n'
            '    <Properties action="UPDATE" groupName="Administrators"\n'
            '      groupSid="S-1-5-32-544" removePolicy="0">\n'
            "      <Members>\n"
            '        <Member name="HELPDESK\\Tier1Admins" action="ADD"\n'
            '          sid="S-1-5-21-1-2-3-1101"/>\n'
            "      </Members>\n"
            "    </Properties>\n"
            "  </Group>\n"
            "</Groups>\n",
            encoding="utf-8",
        )
        gpo = _make_gpo(
            id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            name="admin-push-gpo",
            sysvol_path=str(sysvol),
        )
        estate = Estate(gpos=[gpo])
        findings = local_admin_push(estate)
        assert len(findings) == 1
        assert findings[0].remediation == _BUCKET2_REMEDIATION["local_admin_push"]
        assert "Administrators" in findings[0].remediation

    def test_overbroad_apply_gp_has_remediation(self) -> None:
        gpo = _make_gpo(
            delegation=[
                DelegationEntry(
                    gpo_id="g1",
                    trustee="Everyone",
                    trustee_sid="S-1-1-0",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        findings = overbroad_apply_group_policy(estate)
        assert len(findings) == 1
        assert findings[0].remediation
        assert "Apply Group Policy" in findings[0].remediation

    def test_overbroad_sddl_fallback_has_remediation(self) -> None:
        gpo = _make_gpo(
            sddl="D:(A;;GA;;;WD)",
            delegation=[],
        )
        estate = Estate(gpos=[gpo])
        findings = overbroad_apply_group_policy(estate)
        assert len(findings) == 1
        assert findings[0].remediation
        assert "Everyone" in findings[0].remediation

    def test_all_bucket2_check_ids_have_remediation(self) -> None:
        from gpo_lens.danger import _BUCKET2_REMEDIATION

        expected = {
            "gpo_writable_nonadmin",
            "gpo_owner_nonadmin",
            "local_admin_push",
            "overbroad_apply_gp",
        }
        assert set(_BUCKET2_REMEDIATION.keys()) == expected
        for check_id, text in _BUCKET2_REMEDIATION.items():
            assert text, f"Empty remediation for {check_id}"
            assert len(text) <= 300, f"Remediation for {check_id} exceeds 300 chars: {len(text)}"


class TestRemediationDangerFindingDefault:
    def test_danger_finding_defaults_empty_remediation(self) -> None:
        from gpo_lens.danger import DangerFinding

        f = DangerFinding(
            check_id="x",
            severity="high",
            title="t",
            gpo_id="",
            gpo_name="",
            detail="d",
            reference="ref",
        )
        assert f.remediation == ""

    def test_danger_rule_defaults_empty_remediation(self) -> None:
        from gpo_lens.danger import DangerRule

        r = DangerRule(
            id="x",
            title="t",
            severity="high",
            applies="Machine",
            identity="HKLM\\K:V",
            predicate="equals",
            value="1",
            reference="ref",
        )
        assert r.remediation == ""


class TestRemediationDoctorFinding:
    def test_doctor_finding_carries_remediation(self) -> None:
        from gpo_lens.queries import estate_doctor

        gpo = _make_gpo(
            sddl="D:(A;;GA;;;S-1-5-21-1-2-3-1000)",
            name="writable-gpo",
        )
        estate = Estate(gpos=[gpo])
        findings = estate_doctor(estate)
        danger = [f for f in findings if f.category == "danger:gpo_writable_nonadmin"]
        assert len(danger) == 1
        assert danger[0].remediation
        assert "write permissions" in danger[0].remediation.lower()

    def test_doctor_finding_remediation_empty_for_non_danger(self) -> None:
        from gpo_lens.queries import estate_doctor

        gpo = _make_gpo(
            id="11111111111111111111111111111111",
            name="stale-gpo",
            computer_ver_ds=2,
            computer_ver_sysvol=1,
        )
        estate = Estate(gpos=[gpo])
        findings = estate_doctor(estate)
        non_danger = [f for f in findings if not f.category.startswith("danger:")]
        assert len(non_danger) >= 1
        for f in non_danger:
            assert f.remediation == ""


class TestRemediationWebRoute:
    def test_danger_route_shows_remediation_text(self, _client) -> None:
        resp = _client.get("/danger")
        assert resp.status_code == 200
        assert "Remediation" in resp.text
        # The fixture GPO AAAAAAAA pushes local Administrators membership,
        # which carries remediation text mentioning "Administrators".
        assert "Administrators" in resp.text
        # Strengthened: assert a phrase unique to the remediation text that
        # would never appear in the finding detail (which only lists added
        # members and the group name).
        assert "tiered administration" in resp.text.lower()


# ---------------------------------------------------------------------------
# Shipped TOML validation
# ---------------------------------------------------------------------------


class TestDangerRulesToml:
    def test_shipped_rules_parse(self) -> None:
        """The shipped danger_rules.toml must parse to a non-empty, valid rule set."""
        rules = load_danger_rules()
        assert len(rules) >= 5, f"Expected >= 5 rules, got {len(rules)}"
        for r in rules:
            assert r.id, f"Rule missing id: {r}"
            assert r.severity in ("critical", "high", "medium", "low", "info"), (
                f"Rule {r.id}: invalid severity {r.severity!r}"
            )
            assert r.applies in ("Machine", "User", "Both"), (
                f"Rule {r.id}: invalid applies {r.applies!r}"
            )
            assert r.predicate in (
                "equals",
                "in",
                "min",
                "max",
                "present",
                "absent",
            ), f"Rule {r.id}: invalid predicate {r.predicate!r}"
            assert r.reference.startswith("http"), (
                f"Rule {r.id}: reference must be a URL, got {r.reference!r}"
            )

    def test_shipped_rule_ids_unique(self) -> None:
        rules = load_danger_rules()
        ids = [r.id for r in rules]
        assert len(ids) == len(set(ids)), (
            f"Duplicate rule ids: {[x for x in ids if ids.count(x) > 1]}"
        )


# ---------------------------------------------------------------------------
# AdmxResolver Protocol conformance
# ---------------------------------------------------------------------------


class TestAdmxResolverProtocol:
    def test_policy_definitions_satisfies_protocol(self) -> None:
        from gpo_lens.admx_parser import PolicyDefinitions
        from gpo_lens.model import AdmxResolver

        assert isinstance(PolicyDefinitions(), AdmxResolver)

    def test_duck_typed_resolver_satisfies_protocol(self) -> None:
        from gpo_lens.model import AdmxResolver

        class Duck:
            def resolve_display_name(self, identity: str) -> str | None:
                return None

        assert isinstance(Duck(), AdmxResolver)


# ---------------------------------------------------------------------------
# Bucket 1 — predicate evaluator coverage (non-``equals`` predicates)
# The shipped ``danger_rules.toml`` uses only ``equals``, so the ``in``,
# ``present``, ``min``, and ``max`` branches are never exercised by the
# calibration tests.  These unit-test the extensible predicate engine.
# ---------------------------------------------------------------------------


def _rule(predicate: str, value: str, **kwargs: object) -> DangerRule:
    """Build a minimal DangerRule with the given predicate/value."""
    fields: dict[str, object] = {
        "id": "test_rule",
        "title": "Test Rule",
        "severity": "high",
        "applies": "Machine",
        "identity": r"HKLM\Software\Test:Setting",
        "predicate": predicate,
        "value": value,
        "reference": "https://example.com/ref",
    }
    fields.update(kwargs)
    return DangerRule(**fields)  # type: ignore[arg-type]


class TestPredicateMatches:
    def test_in_predicate_matches(self) -> None:
        from gpo_lens.danger import _predicate_matches

        rule = _rule("in", "1, 2, 3")
        assert _predicate_matches(rule, "2") is True

    def test_in_predicate_no_match(self) -> None:
        from gpo_lens.danger import _predicate_matches

        rule = _rule("in", "1, 2, 3")
        assert _predicate_matches(rule, "4") is False

    def test_present_predicate_always_true(self) -> None:
        from gpo_lens.danger import _predicate_matches

        rule = _rule("present", "")
        assert _predicate_matches(rule, "anything") is True
        assert _predicate_matches(rule, "") is True

    def test_min_predicate_above(self) -> None:
        from gpo_lens.danger import _predicate_matches

        rule = _rule("min", "5")
        assert _predicate_matches(rule, "10") is True

    def test_min_predicate_below(self) -> None:
        from gpo_lens.danger import _predicate_matches

        rule = _rule("min", "5")
        assert _predicate_matches(rule, "3") is False

    def test_min_predicate_non_numeric(self) -> None:
        from gpo_lens.danger import _predicate_matches

        rule = _rule("min", "5")
        assert _predicate_matches(rule, "abc") is False

    def test_max_predicate_below(self) -> None:
        from gpo_lens.danger import _predicate_matches

        rule = _rule("max", "5")
        assert _predicate_matches(rule, "3") is True

    def test_max_predicate_above(self) -> None:
        from gpo_lens.danger import _predicate_matches

        rule = _rule("max", "5")
        assert _predicate_matches(rule, "10") is False

    def test_max_predicate_non_numeric(self) -> None:
        from gpo_lens.danger import _predicate_matches

        rule = _rule("max", "5")
        assert _predicate_matches(rule, "abc") is False

    def test_unknown_predicate_returns_false(self) -> None:
        from gpo_lens.danger import _predicate_matches

        rule = _rule("bogus", "x")
        assert _predicate_matches(rule, "x") is False


class TestAbsentPredicate:
    """The ``absent`` predicate fires a finding when *no* GPO in the estate
    carries a setting matching the rule's identity."""

    def test_absent_fires_when_setting_missing(self) -> None:
        estate = Estate(gpos=[_make_gpo()])  # no settings
        rule = _rule("absent", "", identity=r"HKLM\Software\Missing:Key")
        findings = evaluate_danger_rules(estate, [rule])
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "test_rule"
        assert f.gpo_id == ""  # estate-wide, not per-GPO
        assert "not found estate-wide" in f.detail

    def test_absent_no_finding_when_setting_present(self) -> None:
        gpo = _make_gpo()
        gpo.settings.append(_reg_setting(gpo.id, r"HKLM\Software\Present:Key", "1"))
        estate = Estate(gpos=[gpo])
        rule = _rule("absent", "", identity=r"HKLM\Software\Present:Key")
        findings = evaluate_danger_rules(estate, [rule])
        assert findings == []

    def test_absent_mixed_with_present_rule(self) -> None:
        """An absent rule and a present (equals) rule in the same batch."""
        gpo = _make_gpo()
        gpo.settings.append(_reg_setting(gpo.id, r"HKLM\Software\Present:Key", "1"))
        estate = Estate(gpos=[gpo])
        rules = [
            _rule("absent", "", identity=r"HKLM\Software\Missing:Key"),
            _rule("equals", "1", identity=r"HKLM\Software\Present:Key"),
        ]
        findings = evaluate_danger_rules(estate, rules)
        ids = {f.check_id for f in findings}
        assert ids == {"test_rule"}
        # One absent finding + one present finding
        assert len(findings) == 2

    def test_absent_machine_side_ignores_user_side_setting(self) -> None:
        """C-1: A Machine-scoped absent rule must NOT be suppressed by a
        matching setting on the User side only.  The absent loop must call
        _side_matches(), just like the present path does."""
        gpo = _make_gpo()
        gpo.settings.append(_reg_setting(gpo.id, r"HKLM\Software\Target:Key", "1", side="User"))
        estate = Estate(gpos=[gpo])
        rule = _rule("absent", "", identity=r"HKLM\Software\Target:Key")
        findings = evaluate_danger_rules(estate, [rule])
        # The setting is on the User side; rule applies to Machine → finding fires.
        assert len(findings) == 1
        assert findings[0].check_id == "test_rule"

    def test_absent_machine_side_no_finding_when_computer_side_present(self) -> None:
        """C-1: A Machine-scoped absent rule is suppressed when a matching
        setting exists on the Computer side."""
        gpo = _make_gpo()
        gpo.settings.append(_reg_setting(gpo.id, r"HKLM\Software\Target:Key", "1", side="Computer"))
        estate = Estate(gpos=[gpo])
        rule = _rule("absent", "", identity=r"HKLM\Software\Target:Key")
        findings = evaluate_danger_rules(estate, [rule])
        assert findings == []


# ---------------------------------------------------------------------------
# Malformed compliance entry handling (_parse_compliance warning path)
# ---------------------------------------------------------------------------


class TestParseComplianceMalformed:
    def test_non_table_entry_warns_and_skipped(self) -> None:
        import warnings

        from gpo_lens.danger import _parse_compliance

        raw = [
            {"framework": "CIS", "control_id": "1.1"},
            "not-a-table",  # should warn + skip
            123,  # should warn + skip
            {"framework": "STIG", "control_id": "SV-1"},
        ]
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = _parse_compliance(raw, Path("test.toml"))
        assert len(result) == 2
        assert result[0].framework == "CIS"
        assert result[1].framework == "STIG"
        assert len(caught) == 2  # two warnings for the two bad entries

    def test_non_list_returns_empty(self) -> None:
        from gpo_lens.danger import _parse_compliance

        assert _parse_compliance("not-a-list", Path("test.toml")) == ()
        assert _parse_compliance(None, Path("test.toml")) == ()

    def test_empty_framework_or_control_id_warns_and_skipped(self) -> None:
        import warnings

        from gpo_lens.danger import _parse_compliance

        raw = [
            {"framework": "", "control_id": "1.1"},  # empty framework
            {"framework": "CIS", "control_id": ""},  # empty control_id
            {"framework": "CIS"},  # missing control_id
            {"control_id": "SV-1"},  # missing framework
            {"framework": 123, "control_id": "SV-1"},  # non-string framework
        ]
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = _parse_compliance(raw, Path("test.toml"))
        assert result == ()  # all entries skipped
        assert len(caught) == 5


# ---------------------------------------------------------------------------
# ADMX display-name identity resolution through evaluate_danger_rules
# ---------------------------------------------------------------------------


class TestAdmxIdentityResolution:
    """When a rule's ``identity`` is a policy display name (not a raw registry
    path), the evaluator resolves the setting's registry identity via the ADMX
    crosswalk.  This exercises the second branch of ``_identity_matches``."""

    def test_admx_resolves_policy_name_to_identity(self) -> None:
        gpo = _make_gpo()
        gpo.settings.append(_reg_setting(gpo.id, r"HKLM\Software\Real:Key", "1"))
        estate = Estate(gpos=[gpo])

        # Rule targets a policy display name, not the raw registry path.
        rule = _rule("equals", "1", identity="Disable WDigest")

        # Duck-typed AdmxResolver: maps the registry path to the policy name.
        class FakeAdmx:
            def resolve_display_name(self, identity: str) -> str | None:
                if identity == r"HKLM\Software\Real:Key":
                    return "Disable WDigest"
                return None

        findings = evaluate_danger_rules(estate, [rule], admx=FakeAdmx())  # type: ignore[arg-type]
        assert len(findings) == 1
        assert findings[0].detail.startswith(r"HKLM\Software\Real:Key")

    def test_admx_returns_none_no_match(self) -> None:
        """When the ADMX resolver returns None, no match via display name."""
        gpo = _make_gpo()
        gpo.settings.append(_reg_setting(gpo.id, r"HKLM\Software\Other:Key", "1"))
        estate = Estate(gpos=[gpo])
        rule = _rule("equals", "1", identity="Nonexistent Policy")

        class FakeAdmx:
            def resolve_display_name(self, identity: str) -> str | None:
                return None

        findings = evaluate_danger_rules(estate, [rule], admx=FakeAdmx())  # type: ignore[arg-type]
        assert findings == []


def test_overbroad_apply_gp_detects_full_control():
    """overbroad_apply_group_policy must flag GPOs where 'Full Control'
    (which implies Apply) is granted to Everyone, not just literal
    'Apply Group Policy' permissions.
    """
    gpo = _make_gpo(id="fc-gpo", name="FC GPO")
    gpo.delegation = [
        DelegationEntry(
            gpo_id="fc-gpo",
            trustee="Everyone",
            trustee_sid="S-1-1-0",
            permission="Full control",
            allowed=True,
        ),
    ]
    estate = Estate(gpos=[gpo])
    findings = overbroad_apply_group_policy(estate)
    assert len(findings) == 1
    assert findings[0].check_id == "overbroad_apply_gp"
