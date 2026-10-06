"""Dangerous-configuration detectors — curated, cited, AI-free (Plan 018 Phase B).

Two buckets, matched to their mechanics (B.1):

* **Bucket 2 — structural / attack-path** (typed detectors reusing the
  existing SDDL/delegation/GPP parse): :func:`gpo_writable_by_nonadmin`,
  :func:`local_admin_push`, :func:`overbroad_apply_group_policy`.
* **Bucket 1 — setting-value dangers** (a small cited data table + one pure
  evaluator): :func:`evaluate_danger_rules` over :class:`DangerRule` instances
  loaded from ``danger_rules.toml``.

Both emit one typed :class:`DangerFinding` carrying a required ``reference``.
Findings are *facts about the GPO* (B.3 "Flag, don't simulate"), not claims
about per-principal effective state. The module is a core module: it never
imports ``narration`` or ``web`` and makes zero model calls (AC-8).
"""

from __future__ import annotations

import os
import tomllib
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from gpo_lens.authz import (
    APPLY_RIGHTS,
    applies_broadly,
    broad_trustee_key,
    canonical_sddl_sid,
    has_write_right,
    is_allow_ace_type,
    is_default_writer_sid,
    is_deny_ace_type,
    parse_sddl,
    parse_sddl_rights,
    permission_implies_apply,
    resolve_principal,
)
from gpo_lens.detection import (
    scan_local_groups,
)
from gpo_lens.model import SEVERITY_ORDER
from gpo_lens.normalize import is_registry_cse

if TYPE_CHECKING:
    from gpo_lens.model import AdmxResolver, Estate, Side

__all__ = [
    "ComplianceMapping",
    "DangerFinding",
    "DangerRule",
    "audit_subcategory_override",
    "danger_findings",
    "evaluate_danger_rules",
    "gpo_writable_by_nonadmin",
    "load_danger_rules",
    "local_admin_push",
    "overbroad_apply_group_policy",
]


_SEVERITY_ORDER = SEVERITY_ORDER


@dataclass(frozen=True)
class ComplianceMapping:
    """One compliance framework control mapping for a danger finding."""

    framework: str
    control_id: str


@dataclass(frozen=True)
class DangerFinding:
    """One dangerous-configuration finding from a curated, cited check."""

    check_id: str
    severity: str
    title: str
    gpo_id: str
    gpo_name: str
    detail: str
    reference: str
    compliance: tuple[ComplianceMapping, ...] = ()
    remediation: str = ""
    # Identity-bearing dimensions for lifecycle fingerprinting (WI-1.1,
    # Plan 024 §4). Typed key/value pairs the adapter reads directly, so a
    # finding's identity never depends on parsing its prose title/detail.
    # Distinguishes multiple findings that share one subject (e.g. several
    # non-admin writers on the same GPO, keyed by trustee SID).
    dimensions: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class DangerRule:
    """One cited danger rule from the shipped TOML data table."""

    id: str
    title: str
    severity: str
    applies: str
    identity: str
    predicate: str
    value: str
    reference: str
    compliance: tuple[ComplianceMapping, ...] = ()
    remediation: str = ""


# ---------------------------------------------------------------------------
# Bucket 2 — structural / attack-path detectors
# ---------------------------------------------------------------------------

_GPO_MODIFY_REF = "https://attack.mitre.org/techniques/T1484/001/"
_LOCAL_ADMIN_REF = "https://attack.mitre.org/techniques/T1078/003/"
_APPLY_GP_REF = (
    "https://learn.microsoft.com/en-us/troubleshoot/"
    "windows-server/group-policy/security-filtering-group-policy"
)

# "Apply Group Policy" granted to these SIDs means any authenticated or
# anonymous user receives the GPO — an over-broad apply scope.
_BROAD_APPLY_SIDS = {"s-1-1-0", "s-1-5-7", "wd", "an"}

_BUCKET2_COMPLIANCE: dict[str, tuple[ComplianceMapping, ...]] = {
    "gpo_writable_nonadmin": (
        ComplianceMapping(framework="CIS", control_id="5.1"),
        ComplianceMapping(framework="NIST-800-171", control_id="3.1.2"),
    ),
    "gpo_owner_nonadmin": (
        ComplianceMapping(framework="CIS", control_id="5.1"),
        ComplianceMapping(framework="NIST-800-171", control_id="3.1.2"),
    ),
    "local_admin_push": (
        ComplianceMapping(framework="NIST-800-171", control_id="3.1.6"),
        ComplianceMapping(framework="CIS", control_id="2.3.1.1"),
    ),
    "overbroad_apply_gp": (
        ComplianceMapping(framework="NIST-800-171", control_id="3.1.5"),
        ComplianceMapping(framework="CIS", control_id="2.3.11.2"),
    ),
}

_BUCKET2_REMEDIATION: dict[str, str] = {
    "gpo_writable_nonadmin": (
        "Remove write permissions from the GPO's ACL for non-admin trustees "
        "(look for rights including GenericAll, WriteDacl, WriteOwner, "
        "WriteProperty). GPO modification should be restricted to Domain "
        "Admins, Enterprise Admins, and SYSTEM only. Edit via GPMC > GPO > "
        "Delegation tab."
    ),
    "gpo_owner_nonadmin": (
        "Change the GPO owner to a Domain Admin or Enterprise Admin. The Owner "
        "implicitly holds WRITE_DAC and can escalate to full control. Use GPMC "
        "to change ownership (right-click GPO > Properties > Security tab > "
        "Advanced > Owner), or use Set-Acl / dsmod from the command line."
    ),
    "local_admin_push": (
        "Review and remove GPP Local Users and Groups entries that add members "
        "to the local Administrators group (SID S-1-5-32-544). If tiered "
        "administration is required, use a separate GPO with security filtering "
        "targeting specific admin groups, not broad membership pushes."
    ),
    "overbroad_apply_gp": (
        "Remove 'Apply Group Policy' permission from Everyone (S-1-1-0) and "
        "Anonymous (S-1-5-7). Use security filtering to target specific groups. "
        "Edit via GPMC > GPO > Security Filtering, removing 'Everyone' and "
        "adding the intended target group."
    ),
}


def _format_trustee(estate: Estate, sid: str) -> str:
    """Resolve *sid* to ``"name (sid)"`` when resolved, else the raw SID.

    The SID is always present (Plan 020, decision 2); the name is omitted when
    unresolved to avoid the redundant ``sid (sid)`` form.
    """
    rp = resolve_principal(estate, sid)
    if rp.resolved:
        return f"{rp.name} ({sid})"
    return sid


def gpo_writable_by_nonadmin(estate: Estate) -> list[DangerFinding]:
    """Flag GPOs whose DACL grants write rights to a non-default-writer trustee,
    or whose Owner is a non-default-writer SID.

    Reuses the existing SDDL parse and the ``is_default_writer_sid`` /
    ``has_write_right`` helpers — no new ACL evaluator (AC-7). Emits one
    finding per (GPO, trustee) pair for DACL write ACEs, plus one finding
    per GPO with a non-admin Owner (the Owner implicitly holds WRITE_DAC
    and can escalate to full control — a GPO-hijack primitive).
    """
    findings: list[DangerFinding] = []
    for g in estate.gpos:
        if not g.sddl:
            continue
        acl = parse_sddl(g.sddl)

        if acl.owner_sid and not is_default_writer_sid(acl.owner_sid):
            owner_display = _format_trustee(estate, acl.owner_sid)
            findings.append(
                DangerFinding(
                    check_id="gpo_owner_nonadmin",
                    severity="high",
                    title="GPO owned by a non-admin trustee",
                    gpo_id=g.id,
                    gpo_name=g.name,
                    detail=(
                        f"GPO Owner is {owner_display} — the Owner implicitly "
                        f"holds WRITE_DAC and can escalate to full control"
                    ),
                    reference=_GPO_MODIFY_REF,
                    compliance=_BUCKET2_COMPLIANCE.get("gpo_owner_nonadmin", ()),
                    remediation=_BUCKET2_REMEDIATION.get("gpo_owner_nonadmin", ""),
                    dimensions=(("owner_sid", acl.owner_sid),),
                )
            )

        for ace in acl.dacl:
            if not is_allow_ace_type(ace.ace_type):
                continue
            if not has_write_right(ace.rights):
                continue
            sid = ace.trustee_sid
            if not sid or is_default_writer_sid(sid):
                continue
            trustee_display = _format_trustee(estate, sid)
            findings.append(
                DangerFinding(
                    check_id="gpo_writable_nonadmin",
                    severity="high",
                    title="GPO writable by a non-admin trustee",
                    gpo_id=g.id,
                    gpo_name=g.name,
                    detail=(
                        f"Trustee {trustee_display} has write access ({ace.rights}) "
                        f"to this GPO — a GPO-hijack primitive"
                    ),
                    reference=_GPO_MODIFY_REF,
                    compliance=_BUCKET2_COMPLIANCE.get("gpo_writable_nonadmin", ()),
                    remediation=_BUCKET2_REMEDIATION.get("gpo_writable_nonadmin", ""),
                    dimensions=(("trustee_sid", sid),),
                )
            )
    return findings


def local_admin_push(estate: Estate) -> list[DangerFinding]:
    """Flag GPOs that push members into the local Administrators group.

    Reuses :func:`detection.scan_local_groups` (no new GPP parse). Emits one
    finding per GPO (deduplicated across groups). Adds via Restricted Groups
    or GPP LocalUsersAndGroups to the local Administrators (SID S-1-5-32-544
    or a name containing "admin") are flagged as a privilege-escalation path.
    """
    findings: list[DangerFinding] = []
    for g in estate.gpos:
        pushes: list[str] = []
        for mod in scan_local_groups(g):
            is_admin = (mod.group_sid and mod.group_sid.upper() == "S-1-5-32-544") or "ADMIN" in (
                mod.group_name or ""
            ).upper()
            if not is_admin or not mod.members_added:
                continue
            pushes.append(f"adds {', '.join(mod.members_added)} to '{mod.group_name}'")
        if pushes:
            findings.append(
                DangerFinding(
                    check_id="local_admin_push",
                    severity="high",
                    title="GPO pushes local Administrators membership",
                    gpo_id=g.id,
                    gpo_name=g.name,
                    detail="; ".join(pushes),
                    reference=_LOCAL_ADMIN_REF,
                    compliance=_BUCKET2_COMPLIANCE.get("local_admin_push", ()),
                    remediation=_BUCKET2_REMEDIATION.get("local_admin_push", ""),
                )
            )
    return findings


def overbroad_apply_group_policy(estate: Estate) -> list[DangerFinding]:
    """Flag GPOs whose 'Apply Group Policy' is granted to Everyone/Anonymous.

    Checks ``gpo.delegation`` entries first. When delegation is empty (common
    when the collector only has SDDL), falls back to parsing ``gpo.sddl`` for
    allow ACEs granting apply/read rights to Everyone (S-1-1-0) or Anonymous
    (S-1-5-7). Everyone or Anonymous receiving Apply Group Policy means any
    authenticated/anonymous user gets the GPO applied — an over-broad scope.
    """
    findings: list[DangerFinding] = []
    for g in estate.gpos:
        if g.delegation:
            # Collect grants (allow and deny) for broad trustees, then use
            # applies_broadly() so a deny ACE cancels an allow for the same
            # trustee (Windows deny-first evaluation).
            grants: list[tuple[str | None, bool]] = []
            for d in g.delegation:
                if not permission_implies_apply(d.permission or ""):
                    continue
                sid = (d.trustee_sid or "").lower()
                key = broad_trustee_key(d.trustee, d.trustee_sid)
                if key is None and sid not in _BROAD_APPLY_SIDS:
                    continue
                if key is None:
                    key = canonical_sddl_sid(sid)
                grants.append((key, d.allowed))
            if not applies_broadly(grants):
                continue
            # Find the specific broad trustee for the detail message.
            for d in g.delegation:
                if not d.allowed:
                    continue
                if not permission_implies_apply(d.permission or ""):
                    continue
                sid = (d.trustee_sid or "").lower()
                if sid not in _BROAD_APPLY_SIDS:
                    continue
                findings.append(
                    DangerFinding(
                        check_id="overbroad_apply_gp",
                        severity="medium",
                        title="GPO apply scope is over-broad (Everyone/Anonymous)",
                        gpo_id=g.id,
                        gpo_name=g.name,
                        detail=(f"'Apply Group Policy' granted to {d.trustee or sid} ({sid})"),
                        reference=_APPLY_GP_REF,
                        compliance=_BUCKET2_COMPLIANCE.get("overbroad_apply_gp", ()),
                        remediation=_BUCKET2_REMEDIATION.get("overbroad_apply_gp", ""),
                    )
                )
                break
        elif g.sddl:
            # SDDL fallback: collect allow and deny ACEs for broad trustees,
            # then use applies_broadly() for deny-first net-access evaluation.
            acl = parse_sddl(g.sddl)
            grants = []
            for ace in acl.dacl:
                if not (is_allow_ace_type(ace.ace_type) or is_deny_ace_type(ace.ace_type)):
                    continue
                rights = frozenset(parse_sddl_rights(ace.rights))
                if not (rights & APPLY_RIGHTS):
                    continue
                sid = (ace.trustee_sid or "").lower()
                key = broad_trustee_key("", ace.trustee_sid)
                if key is None and sid not in _BROAD_APPLY_SIDS:
                    continue
                if key is None:
                    key = canonical_sddl_sid(sid)
                grants.append((key, is_allow_ace_type(ace.ace_type)))
            if not applies_broadly(grants):
                continue
            for ace in acl.dacl:
                if not is_allow_ace_type(ace.ace_type):
                    continue
                rights = frozenset(parse_sddl_rights(ace.rights))
                if not (rights & APPLY_RIGHTS):
                    continue
                sid = (ace.trustee_sid or "").lower()
                if sid not in _BROAD_APPLY_SIDS:
                    continue
                trustee_display = _format_trustee(estate, ace.trustee_sid)
                findings.append(
                    DangerFinding(
                        check_id="overbroad_apply_gp",
                        severity="medium",
                        title="GPO apply scope is over-broad (Everyone/Anonymous)",
                        gpo_id=g.id,
                        gpo_name=g.name,
                        detail=(f"SDDL grants apply rights to {trustee_display} ({ace.rights})"),
                        reference=_APPLY_GP_REF,
                        compliance=_BUCKET2_COMPLIANCE.get("overbroad_apply_gp", ()),
                        remediation=_BUCKET2_REMEDIATION.get("overbroad_apply_gp", ""),
                    )
                )
                break
    return findings


# ---------------------------------------------------------------------------
# Bucket 1 — setting-value dangers (data table + pure evaluator)
# ---------------------------------------------------------------------------


def _resolve_display_name(admx: AdmxResolver, identity: str, side: Side) -> str | None:
    """Resolve a setting identity to an ADMX policy display name.

    Returns ``None`` when the resolver has no match, so name-keyed
    rules degrade to identity-keyed only (AC-9 — no crash, no silent all-match).
    """
    result = admx.resolve_display_name(identity, side=side)
    return result if isinstance(result, str) else None


def _predicate_matches(rule: DangerRule, value: str) -> bool:
    v = (value or "").strip()
    if rule.predicate == "equals":
        return v.lower() == rule.value.strip().lower()
    if rule.predicate == "in":
        wanted = {x.strip().lower() for x in rule.value.split(",") if x.strip()}
        return v.lower() in wanted
    if rule.predicate == "present":
        return True
    if rule.predicate == "min":
        try:
            return float(v) >= float(rule.value)
        except ValueError:
            return False
    if rule.predicate == "max":
        try:
            return float(v) <= float(rule.value)
        except ValueError:
            return False
    return False


def _side_matches(rule_applies: str, setting_side: str) -> bool:
    if rule_applies == "Both":
        return True
    want = "Computer" if rule_applies == "Machine" else "User"
    return setting_side == want


def _identity_matches(
    rule: DangerRule,
    setting_identity: str,
    setting_side: Side,
    admx: AdmxResolver | None,
) -> bool:
    if setting_identity.lower() == rule.identity.lower():
        return True
    if admx is None:
        return False
    resolved = _resolve_display_name(admx, setting_identity, setting_side)
    return resolved is not None and resolved.lower() == rule.identity.lower()


def evaluate_danger_rules(
    estate: Estate, rules: list[DangerRule], admx: AdmxResolver | None = None
) -> list[DangerFinding]:
    """Evaluate setting-value danger rules against estate Registry settings.

    For each rule, scan all GPO Registry CSE settings where the side matches
    ``rule.applies`` and the identity matches ``rule.identity`` (raw registry
    path, case-insensitive) *or* the ADMX-resolved display name matches
    ``rule.identity`` (policy-name-keyed). When *admx* is ``None``, name-keyed
    rules produce no matches (graceful degradation, AC-9).

    The ``absent`` predicate is estate-wide: a finding is emitted when *no*
    GPO carries a setting matching the rule's identity.
    """
    present_findings: list[DangerFinding] = []
    absent_rules = [r for r in rules if r.predicate == "absent"]
    active_rules = [r for r in rules if r.predicate != "absent"]

    for rule in active_rules:
        for g in estate.gpos:
            for s in g.settings:
                if s.source_state == "blocked" or s.from_disabled_side:
                    continue
                if not is_registry_cse(s.cse):
                    continue
                if not _side_matches(rule.applies, s.side):
                    continue
                if not _identity_matches(rule, s.identity, s.side, admx):
                    continue
                if _predicate_matches(rule, s.display_value):
                    present_findings.append(
                        DangerFinding(
                            check_id=rule.id,
                            severity=rule.severity,
                            title=rule.title,
                            gpo_id=g.id,
                            gpo_name=g.name,
                            detail=f"{s.identity} = {s.display_value}",
                            reference=rule.reference,
                            compliance=rule.compliance,
                            remediation=rule.remediation,
                        )
                    )

    absent_findings: list[DangerFinding] = []
    for rule in absent_rules:
        found_any = False
        for g in estate.gpos:
            for s in g.settings:
                if s.source_state == "blocked" or s.from_disabled_side:
                    continue
                if not is_registry_cse(s.cse):
                    continue
                if not _side_matches(rule.applies, s.side):
                    continue
                if _identity_matches(rule, s.identity, s.side, admx):
                    found_any = True
                    break
            if found_any:
                break
        if not found_any:
            absent_findings.append(
                DangerFinding(
                    check_id=rule.id,
                    severity=rule.severity,
                    title=rule.title,
                    gpo_id="",
                    gpo_name="",
                    detail=f"Expected setting not found estate-wide: {rule.identity}",
                    reference=rule.reference,
                    compliance=rule.compliance,
                    remediation=rule.remediation,
                )
            )

    return present_findings + absent_findings


_VALID_PREDICATES = frozenset(
    {
        "equals",
        "in",
        "min",
        "max",
        "present",
        "absent",
    }
)

_REQUIRED_RULE_FIELDS = frozenset(
    {
        "id",
        "title",
        "severity",
        "applies",
        "identity",
        "reference",
    }
)


def _parse_compliance(raw: object, path: Path) -> tuple[ComplianceMapping, ...]:
    if not isinstance(raw, list):
        return ()
    out: list[ComplianceMapping] = []
    for item in raw:
        if not isinstance(item, dict):
            warnings.warn(
                f"Skipping non-table compliance entry in {path.name}",
                stacklevel=1,
            )
            continue
        framework = item.get("framework")
        control_id = item.get("control_id")
        if (
            not isinstance(framework, str)
            or not isinstance(control_id, str)
            or not framework.strip()
            or not control_id.strip()
        ):
            warnings.warn(
                f"Skipping compliance entry with missing or empty framework/control_id "
                f"in {path.name}",
                stacklevel=1,
            )
            continue
        out.append(ComplianceMapping(framework=framework, control_id=control_id))
    return tuple(out)


def _load_rules_file(path: Path) -> list[DangerRule]:
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        # Warn loudly and return empty. The orchestrator ``load_danger_rules``
        # escalates a *shipped*-file failure to a hard error; per-file
        # tolerance here keeps one bad override from disabling every override.
        warnings.warn(
            f"Failed to load danger rules from {path.name}: {exc}",
            stacklevel=2,
        )
        return []
    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        warnings.warn(
            f"Skipping danger rules in {path.name} ('rules' must be an array)",
            stacklevel=1,
        )
        return []
    rules: list[DangerRule] = []
    for entry in raw_rules:
        if not isinstance(entry, dict):
            warnings.warn(
                f"Skipping non-table entry in {path.name} (got {type(entry).__name__})",
                stacklevel=1,
            )
            continue
        predicate = entry.get("predicate", "")
        if predicate not in _VALID_PREDICATES:
            continue
        missing = _REQUIRED_RULE_FIELDS - entry.keys()
        if missing:
            warnings.warn(
                f"Skipping danger rule in {path.name} (missing: {sorted(missing)})",
                stacklevel=1,
            )
            continue
        remediation_raw = entry.get("remediation", "")
        rules.append(
            DangerRule(
                id=entry["id"],
                title=entry["title"],
                severity=entry["severity"],
                applies=entry["applies"],
                identity=entry["identity"],
                predicate=predicate,
                value=str(entry.get("value", "")),
                reference=entry["reference"],
                compliance=_parse_compliance(entry.get("compliance"), path),
                remediation=remediation_raw if isinstance(remediation_raw, str) else "",
            )
        )
    return rules


def load_danger_rules(rules_path: Path | None = None) -> list[DangerRule]:
    """Load danger rules from a TOML file.

    Falls back to the shipped ``danger_rules.toml``. When
    ``GPO_LENS_DANGER_RULES_DIR`` is set, additional ``.toml`` files in that
    directory are loaded and merged by ``id`` (drop-in overrides — B.2).

    Fail-fast policy: the shipped file is part of the package and must always
    load. If it does not (corruption, packaging bug, accidental deletion) we
    raise ``RuntimeError`` rather than silently disabling every curated danger
    check — a security tool that swallows its own rule-set failure would
    report a clean estate while having no rules to evaluate.
    """
    if rules_path is not None:
        return _load_rules_file(rules_path)

    shipped_path = Path(__file__).resolve().parent / "danger_rules.toml"
    shipped = _load_rules_file(shipped_path)
    if not shipped:
        raise RuntimeError(
            f"Shipped danger_rules.toml ({shipped_path}) failed to load or "
            f"contains no rules. The dangerous-configuration detector cannot "
            f"run safely — refusing to return an empty rule set."
        )

    env_dir = os.environ.get("GPO_LENS_DANGER_RULES_DIR")
    if not env_dir:
        return shipped

    env_path = Path(env_dir)
    if not env_path.is_dir():
        return shipped

    merged: dict[str, DangerRule] = {}
    for r in shipped:
        merged[r.id] = r
    for toml_file in sorted(env_path.glob("*.toml")):
        for r in _load_rules_file(toml_file):
            merged[r.id] = r
    return list(merged.values())


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------


def audit_subcategory_override(estate: Estate) -> list[DangerFinding]:
    """Flag a GPO authoring system subcategories without its force option.

    Absence in one GPO cannot establish the device's resultant security option:
    defaults and other GPOs may supply it. This is an authoring caveat only.
    """
    findings: list[DangerFinding] = []
    registry_key = r"system\currentcontrolset\control\lsa\scenoapplylegacyauditpolicy"
    for gpo in estate.gpos:
        active = [
            s
            for s in gpo.settings
            if s.side == "Computer" and not s.from_disabled_side and s.source_state != "blocked"
        ]
        audit = [
            s
            for s in active
            if s.cse == "Advanced Audit Configuration"
            and s.raw.get("cse_parser") in {"advanced_audit", "advanced_audit_csv"}
            and ":" not in s.identity
        ]
        if not audit:
            continue
        force_values: list[bool] = []
        for setting in active:
            if setting.cse != "Security" and not is_registry_cse(setting.cse):
                continue
            key = setting.identity.lower()
            if key.startswith("securityoptions:"):
                key = key.removeprefix("securityoptions:")
            key = key.replace(":scenoapplylegacyauditpolicy", r"\scenoapplylegacyauditpolicy")
            for hive in ("machine\\", "hklm\\", "hkey_local_machine\\"):
                if key.startswith(hive):
                    key = key.removeprefix(hive)
                    break
            if key != registry_key:
                continue
            attrs = setting.raw.get("@attr")
            if isinstance(attrs, dict) and str(attrs.get("action", "")).upper() == "D":
                continue
            value = setting.display_value.strip().lower().removeprefix("[reg_dword] ")
            force_values.append(value in {"1", "true", "enabled", "0x00000001"})
        if force_values and all(force_values):
            continue
        findings.append(
            DangerFinding(
                check_id="audit_subcategory_override",
                severity="low",
                title="Advanced audit configured without the force-subcategory option in this GPO",
                gpo_id=gpo.id,
                gpo_name=gpo.name,
                detail=(
                    "System advanced audit subcategories are configured, but this GPO does not "
                    "enable "
                    "SCENoApplyLegacyAuditPolicy. Legacy audit categories may override "
                    "subcategories. "
                    "Microsoft documents this security option as preventing category-level policy "
                    "application. This is a GPO authoring caveat; other GPOs or device defaults "
                    "may "
                    "enable it. No effective device state is inferred."
                ),
                reference=(
                    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/"
                    "windows-10/security/threat-protection/security-policy-settings/"
                    "audit-force-audit-policy-subcategory-settings-to-override"
                ),
            )
        )
    return findings


def danger_findings(
    estate: Estate, *, admx: AdmxResolver | None = None, rules: list[DangerRule] | None = None
) -> list[DangerFinding]:
    """Run all danger detectors (Bucket 1 + Bucket 2) and return sorted findings."""
    if rules is None:
        rules = load_danger_rules()
    findings: list[DangerFinding] = []
    findings.extend(gpo_writable_by_nonadmin(estate))
    findings.extend(local_admin_push(estate))
    findings.extend(overbroad_apply_group_policy(estate))
    findings.extend(evaluate_danger_rules(estate, rules, admx))
    findings.extend(audit_subcategory_override(estate))
    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.check_id, f.gpo_id))
    return findings
