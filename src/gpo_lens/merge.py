"""Per-CSE merge-resolution model and principal resultant (Plan 021).

This module encodes the merge-resolution table (Phase B) that makes the
resultant correct rather than last-writer-approximate, plus the principal
token + security-gate evaluation (Phase A). It is a core module — no
``narration`` or ``web`` imports, no model calls.

The merge model is a small per-CSE table, most of it deterministic from the
snapshot. Unknown CSEs default to last-writer-wins **and are flagged
approximate**, never silently assumed (B.1). WMI/ILT-gated contributors are
excluded from the deterministic resultant and listed as conditional (decision 2)
— never silently dropped. Output is labeled "resultant given collected inputs,"
never unqualified "effective" (decision 4).
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from gpo_lens.authz import (
    APPLY_RIGHTS,
    AU_SID,
    DOMAIN_SID_PREFIX,
    EVERYONE_SID,
    READ_OR_APPLY_RIGHTS,
    SID_RE,
    canonical_sddl_sid,
    is_allow_ace_type,
    is_deny_ace_type,
    parse_sddl,
    parse_sddl_rights,
    permission_implies_apply,
    permission_implies_read,
    resolve_principal,
    resolve_well_known,
)
from gpo_lens.detection import scan_ilt
from gpo_lens.model import Side
from gpo_lens.normalize import is_registry_cse
from gpo_lens.topology import (
    EffectiveGpo,
    _split_dn,
    loopback_awareness,
    som_effective_gpos,
)

ANONYMOUS_SID = "s-1-5-7"

if TYPE_CHECKING:
    from gpo_lens.danger import DangerFinding
    from gpo_lens.model import Estate, Gpo, Setting

__all__ = [
    "ChainEntry",
    "ConditionalDanger",
    "CseMergeMode",
    "ExcludedGpo",
    "ExcludedSetting",
    "MergeResult",
    "MergedSetting",
    "PrincipalResultant",
    "PrincipalToken",
    "build_token",
    "cse_merge_mode",
    "merge_settings",
    "merge_settings_with_exclusions",
    "principal_resultant",
    "resolve_principal_input",
]


# ---------------------------------------------------------------------------
# B.1 — Per-CSE resolution mode
# ---------------------------------------------------------------------------


class CseMergeMode(Enum):
    LAST_WRITER_WINS = "last_writer_wins"
    UNION = "union"
    AUTHORITATIVE_REPLACE = "authoritative_replace"
    ADDITIVE = "additive"
    ACCUMULATE = "accumulate"
    SINGLE_WINNER = "single_winner"
    MERGE_REPLACE_FLAG = "merge_replace_flag"
    APPROXIMATE = "approximate"


_SCRIPTS_CSES = frozenset({"scripts", "group policy scripts"})
_SEC_RESTRICTED_GROUPS_TYPES = frozenset(
    {
        "restrictedgroups",
        "restricted groups",
    }
)
_GPP_CSES = frozenset(
    {
        "group policy preferences",
        "gpp",
        "gpp drive maps",
        "gpp registry",
        "gpp files",
        "gpp local users and groups",
        "gpp scheduled tasks",
        "drives",
        "files",
        "groups",
        "scheduledtasks",
        "localusersandgroups",
        "datasources",
        "printers",
        "folders",
        "services",
        "environment",
        "shortcuts",
        "internetsettings",
        "regional",
        "poweroptions",
        "networkshares",
        "eventlogs",
    }
)
_IPSEC_WIRELESS_CSES = frozenset(
    {
        "ipsec",
        "ip security",
        "wireless",
        "wired",
        "wireless network (ieee 802.11) policy",
        "wired network policy",
    }
)
_FOLDER_REDIRECTION_CSES = frozenset(
    {
        "folder redirection",
        "folders redirection",
    }
)

_DOMAIN_RID_DOMAIN_USERS = "-513"
_DOMAIN_RID_DOMAIN_COMPUTERS = "-515"

_NAME_TO_WELLKNOWN_SID: dict[str, str] = {
    "authenticated users": AU_SID,
    "everyone": EVERYONE_SID,
    "system": "s-1-5-18",
    "anonymous": "s-1-5-7",
    "domain users": _DOMAIN_RID_DOMAIN_USERS,
    "domain computers": _DOMAIN_RID_DOMAIN_COMPUTERS,
}


def _restricted_groups_mode(setting: Setting) -> CseMergeMode:
    """Members → AUTHORITATIVE_REPLACE, Member Of → ADDITIVE.

    A Restricted Groups setting may carry both sections; Members dominates
    (the authoritative membership list is the stronger semantic).
    """
    raw = setting.raw
    if not isinstance(raw, dict):
        return CseMergeMode.AUTHORITATIVE_REPLACE
    children = raw.get("children")
    if isinstance(children, list):
        tags = {str(child.get("tag", "")).lower() for child in children if isinstance(child, dict)}
        if "members" in tags:
            return CseMergeMode.AUTHORITATIVE_REPLACE
        if "memberof" in tags:
            return CseMergeMode.ADDITIVE
    return CseMergeMode.AUTHORITATIVE_REPLACE


def _folder_redirection_mode(setting: Setting) -> CseMergeMode:
    """Folder Redirection: 'Replace' → AUTHORITATIVE_REPLACE, 'Merge' → ACCUMULATE."""
    val = setting.display_value.strip().lower()
    if "replace" in val:
        return CseMergeMode.AUTHORITATIVE_REPLACE
    if "merge" in val:
        return CseMergeMode.ACCUMULATE
    return CseMergeMode.MERGE_REPLACE_FLAG


def cse_merge_mode(cse: str, setting: Setting | None = None) -> CseMergeMode:
    """Map a CSE name to its merge-resolution mode (Plan 021 B.1).

    Where the mode depends on a setting flag (Restricted Groups Members-vs-
    MemberOf, Folder Redirection merge/replace), the *setting* is consulted.
    Unknown CSEs default to APPROXIMATE — flagged, never silently assumed.
    """
    cse_lower = cse.strip().lower()
    if is_registry_cse(cse):
        return CseMergeMode.LAST_WRITER_WINS
    if cse_lower in _SCRIPTS_CSES:
        return CseMergeMode.UNION
    if cse_lower == "security":
        if setting is not None:
            id_lower = setting.identity.lower()
            for rg_type in _SEC_RESTRICTED_GROUPS_TYPES:
                if id_lower.startswith(rg_type + ":"):
                    return _restricted_groups_mode(setting)
        return CseMergeMode.LAST_WRITER_WINS
    if cse_lower == "software installation":
        return CseMergeMode.ACCUMULATE
    if cse_lower in _GPP_CSES:
        return CseMergeMode.ACCUMULATE
    if cse_lower in _IPSEC_WIRELESS_CSES:
        return CseMergeMode.SINGLE_WINNER
    if cse_lower in _FOLDER_REDIRECTION_CSES:
        if setting is not None:
            return _folder_redirection_mode(setting)
        return CseMergeMode.MERGE_REPLACE_FLAG
    return CseMergeMode.APPROXIMATE


def _is_gpp_cse(cse: str) -> bool:
    return cse.strip().lower() in _GPP_CSES


# ---------------------------------------------------------------------------
# B.2 — GPP item action state machine
# ---------------------------------------------------------------------------


def _extract_gpp_action(setting: Setting) -> str:
    """Extract the GPP action (C/R/U/D or CREATE/REPLACE/UPDATE/DELETE)."""
    raw = setting.raw
    if not isinstance(raw, dict):
        return ""
    attrs = raw.get("@attr")
    if isinstance(attrs, dict):
        action = attrs.get("action")
        if isinstance(action, str) and action:
            return action.strip().upper()
    children = raw.get("children")
    if isinstance(children, list):
        for child in children:
            if isinstance(child, dict) and str(child.get("tag", "")).lower() == "properties":
                child_attrs = child.get("@attr")
                if isinstance(child_attrs, dict):
                    action = child_attrs.get("action")
                    if isinstance(action, str) and action:
                        return action.strip().upper()
    return ""


_ACTION_CREATE = frozenset({"C", "CREATE"})
_ACTION_REPLACE = frozenset({"R", "REPLACE"})
_ACTION_UPDATE = frozenset({"U", "UPDATE"})
_ACTION_DELETE = frozenset({"D", "DELETE"})


# ---------------------------------------------------------------------------
# Chain entry + merged setting
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChainEntry:
    """One GPO's contribution at a SOM, carrying its settings for merge."""

    gpo_id: str
    gpo_name: str
    order: int
    enforced: bool
    settings: list[Setting]


@dataclass(frozen=True)
class MergedSetting:
    """One setting after merge-resolution across the precedence chain."""

    cse: str
    side: Side
    identity: str
    display_name: str
    winning_value: str
    winning_gpo_id: str
    winning_gpo_name: str
    merge_mode: CseMergeMode
    overridden_by: list[tuple[str, str]]
    approximate: bool
    conditional: bool


@dataclass(frozen=True)
class ExcludedSetting:
    """A setting excluded from the deterministic resultant (e.g. ILT-gated GPP).

    Per Plan 021 decision 2 / B.3, an ILT-gated GPP item is excluded from the
    resultant and *listed* — never silently dropped. ``kind`` identifies the
    exclusion reason; ``"ilt"`` is the only kind today (ILT-gated GPP item).
    """

    cse: str
    side: Side
    identity: str
    display_name: str
    value: str
    gpo_id: str
    gpo_name: str
    kind: str


@dataclass(frozen=True)
class MergeResult:
    """Outcome of merge-resolution: surviving settings + excluded (ILT) settings."""

    settings: list[MergedSetting]
    excluded_settings: list[ExcludedSetting]


@dataclass(frozen=True)
class _BucketItem:
    """One setting occurrence in a merge bucket."""

    gpo_id: str
    gpo_name: str
    value: str
    display_name: str
    order: int
    enforced: bool
    action: str
    setting: Setting


def _merge_bucket(
    cse: str,
    side: Side,
    identity: str,
    items: list[_BucketItem],
) -> MergedSetting | None:
    """Resolve one (cse, side, identity) bucket per its CSE merge mode.

    ILT-gated GPP buckets never reach this function — they are excluded
    upstream in :func:`merge_settings_with_exclusions` (decision 2 / B.3) so
    the deterministic resultant never carries a conditional GPP item.
    """
    mode = cse_merge_mode(cse, items[0].setting)
    approximate = mode is CseMergeMode.APPROXIMATE

    if mode is CseMergeMode.ACCUMULATE:
        survivor = _resolve_gpp_actions(items)
        if survivor is None:
            return None
        winner = survivor
    else:
        winner = max(items, key=lambda it: it.order)

    overridden: list[tuple[str, str]] = []
    if mode in (
        CseMergeMode.LAST_WRITER_WINS,
        CseMergeMode.AUTHORITATIVE_REPLACE,
        CseMergeMode.SINGLE_WINNER,
        CseMergeMode.APPROXIMATE,
    ):
        overridden = [(it.gpo_name, it.value) for it in items if it.order < winner.order]
    else:
        overridden = [(it.gpo_name, it.value) for it in items if it.order != winner.order]

    return MergedSetting(
        cse=cse,
        side=side,
        identity=identity,
        display_name=winner.display_name,
        winning_value=winner.value,
        winning_gpo_id=winner.gpo_id,
        winning_gpo_name=winner.gpo_name,
        merge_mode=mode,
        overridden_by=overridden,
        approximate=approximate,
        conditional=False,
    )


def _resolve_gpp_actions(items: list[_BucketItem]) -> _BucketItem | None:
    """Resolve GPP items through Create/Replace/Update/Delete (B.2).

    Processed in precedence→order (lowest order first). A later Delete removes
    the item; Replace supersedes; Update merges fields (the update's value is
    the latest modification, so the winning entry is the updater); Create only
    sets the item if none exists. Returns the surviving item, or None if a
    later Delete removed it.
    """
    ordered = sorted(items, key=lambda it: it.order)
    current: _BucketItem | None = None
    deleted = False
    for it in ordered:
        action = it.action or "UPDATE"
        if action in _ACTION_DELETE:
            deleted = True
            current = None
        elif action in _ACTION_REPLACE:
            deleted = False
            current = it
        elif action in _ACTION_UPDATE:
            if not deleted:
                current = it
        elif action in _ACTION_CREATE:
            if current is None:
                deleted = False
                current = it
    if deleted or current is None:
        return None
    return current


def merge_settings(
    chain_entries: list[ChainEntry],
    *,
    ilt_gpo_ids: frozenset[str] | None = None,
) -> list[MergedSetting]:
    """Resolve a precedence chain into merged settings per the CSE merge model.

    Backward-compatible wrapper around :func:`merge_settings_with_exclusions`
    that returns only the surviving settings. ILT-gated GPP items are excluded
    (decision 2 / B.3) — use :func:`merge_settings_with_exclusions` to also
    retrieve the excluded items.
    """
    return merge_settings_with_exclusions(
        chain_entries,
        ilt_gpo_ids=ilt_gpo_ids,
    ).settings


def merge_settings_with_exclusions(
    chain_entries: list[ChainEntry],
    *,
    ilt_gpo_ids: frozenset[str] | None = None,
) -> MergeResult:
    """Resolve a precedence chain, returning merged + ILT-excluded settings.

    Buckets settings by ``(cse, side, identity)`` and resolves each bucket per
    its CSE merge mode (B.1). GPP items resolve through the action state
    machine (B.2). Per decision 2 / B.3, an ILT-gated GPP item is **excluded**
    from the deterministic resultant and listed in ``excluded_settings`` —
    never silently dropped, and never carried as a conditional survivor.
    """
    ilt = ilt_gpo_ids or frozenset()
    buckets: dict[tuple[str, Side, str], list[_BucketItem]] = defaultdict(list)
    for entry in chain_entries:
        for s in entry.settings:
            if s.from_disabled_side:
                continue
            key = (s.cse, s.side, s.identity)
            action = _extract_gpp_action(s) if _is_gpp_cse(s.cse) else ""
            buckets[key].append(
                _BucketItem(
                    gpo_id=entry.gpo_id,
                    gpo_name=entry.gpo_name,
                    value=s.display_value,
                    display_name=s.display_name,
                    order=entry.order,
                    enforced=entry.enforced,
                    action=action,
                    setting=s,
                )
            )

    results: list[MergedSetting] = []
    excluded: list[ExcludedSetting] = []
    for (cse, side, identity), items in buckets.items():
        # ILT-gated GPP buckets are excluded entirely (decision 2 / B.3):
        # the gate is unevaluated by design, so a conditional survivor would
        # be an over-claim. The gated items are listed for visibility.
        if _is_gpp_cse(cse) and any(it.gpo_id in ilt for it in items):
            for it in items:
                if it.gpo_id in ilt:
                    excluded.append(
                        ExcludedSetting(
                            cse=cse,
                            side=side,
                            identity=identity,
                            display_name=it.display_name,
                            value=it.value,
                            gpo_id=it.gpo_id,
                            gpo_name=it.gpo_name,
                            kind="ilt",
                        )
                    )
            continue
        merged = _merge_bucket(cse, side, identity, items)
        if merged is not None:
            results.append(merged)

    results.sort(key=lambda m: (m.cse, m.side, m.identity.lower()))
    excluded.sort(key=lambda e: (e.cse, e.side, e.identity.lower(), e.gpo_id))
    return MergeResult(settings=results, excluded_settings=excluded)


# ---------------------------------------------------------------------------
# Phase A — Principal token
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PrincipalToken:
    """A principal's security token (set of SIDs)."""

    principal_sid: str
    principal_name: str
    token_sids: frozenset[str]
    token_caveats: list[str]


def _domain_sid_from(sid: str) -> str | None:
    """Extract the domain SID (S-1-5-21-...) from a domain principal SID."""
    s = sid.strip().lower()
    if not s.startswith(DOMAIN_SID_PREFIX):
        return None
    parts = s.split("-")
    if len(parts) < 7:
        return None
    return "-".join(parts[:-1])


def _estate_domain_sid(estate: Estate) -> str | None:
    """Derive the domain SID (s-1-5-21-...) from any collected domain principal.

    Used to expand domain-relative RID suffixes (e.g. ``-513`` for Domain
    Users) into the full SIDs that appear in a principal's token. Falls back
    across ``estate.principals`` then ``estate.group_members``; returns
    ``None`` if no domain principal was collected (empty/unresolved estate).
    """
    for sid in estate.principals:
        ds = _domain_sid_from(sid)
        if ds is not None:
            return ds
    for sid in estate.group_members:
        ds = _domain_sid_from(sid)
        if ds is not None:
            return ds
    return None


def build_token(estate: Estate, principal_sid: str) -> PrincipalToken:
    """Expand a principal's transitive group membership into a token SID set.

    Adds well-known groups (Authenticated Users, Everyone; Domain Users or
    Domain Computers based on principal type). Expands nested groups
    upward-only (member → parent groups via ``estate.group_members``,
    Plan 020 B). Records what could not be expanded (foreign SIDs,
    unresolved groups) as caveats.
    """
    sid = principal_sid.strip().lower()
    rp = resolve_principal(estate, sid)
    token: set[str] = {sid}
    caveats: list[str] = []

    if sid != ANONYMOUS_SID:
        token.add(AU_SID)
    token.add(EVERYONE_SID)

    domain_sid = _domain_sid_from(sid)
    if domain_sid is not None:
        is_computer = rp.principal_type.lower() == "computer"
        if is_computer:
            token.add(f"{domain_sid}{_DOMAIN_RID_DOMAIN_COMPUTERS}")
        else:
            token.add(f"{domain_sid}{_DOMAIN_RID_DOMAIN_USERS}")

    member_to_groups: dict[str, list[str]] = defaultdict(list)
    for g_sid, g_mem in estate.group_members.items():
        for member in g_mem.members:
            member_to_groups[member].append(g_sid)

    queue: deque[str] = deque(token)
    visited: set[str] = set()
    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        gm = estate.group_members.get(current)
        for group_sid in member_to_groups.get(current, ()):
            if group_sid not in token:
                token.add(group_sid)
                queue.append(group_sid)
        if (
            current.startswith(DOMAIN_SID_PREFIX)
            and not resolve_well_known(current)
            and current != sid
            and gm is None
            and current not in estate.principals
        ):
            caveats.append(f"unresolved group SID: {current}")

    return PrincipalToken(
        principal_sid=sid,
        principal_name=rp.name,
        token_sids=frozenset(token),
        token_caveats=caveats,
    )


# ---------------------------------------------------------------------------
# Phase A — Security-filter gate evaluation
# ---------------------------------------------------------------------------


def _build_name_to_sid_map(estate: Estate) -> dict[str, str]:
    """Reverse name→SID map from collected principals and group memberships."""
    out: dict[str, str] = dict(_NAME_TO_WELLKNOWN_SID)
    for sid, rp in estate.principals.items():
        if rp.name:
            out.setdefault(rp.name.lower(), sid)
        if rp.sam:
            out.setdefault(rp.sam.lower(), sid)
    for sid, gm in estate.group_members.items():
        if gm.name:
            out.setdefault(gm.name.lower(), sid)
    return out


def resolve_principal_input(estate: Estate, principal_input: str) -> str | None:
    """Resolve a principal name or SID to a canonical SID string.

    If the input looks like a SID (starts with ``S-1-``, case-insensitive),
    it is returned lowercased. Otherwise the input is matched against
    collected principal names, SAM account names, and well-known group
    names (Authenticated Users, Domain Users, etc.) to find the
    corresponding SID.

    Domain-relative RID suffixes (e.g. ``-513`` for Domain Users) are
    expanded to full SIDs using the estate's domain SID. If the domain SID
    cannot be determined, the suffix cannot be expanded and the function
    returns ``None``.

    Returns ``None`` when the input cannot be resolved — the caller should
    surface a user-facing error in that case.
    """
    s = principal_input.strip()
    if not s:
        return None
    if s.lower().startswith("s-1-"):
        if not SID_RE.match(s):
            return None
        return s.lower()
    name_to_sid = _build_name_to_sid_map(estate)
    result = name_to_sid.get(s.lower())
    if result is not None and result.startswith("-"):
        domain_sid = _estate_domain_sid(estate)
        if domain_sid is None:
            return None
        return f"{domain_sid}{result}"
    return result


def _gpo_apply_trustee_sids(
    gpo: Gpo,
    name_to_sid: dict[str, str],
    domain_sid: str | None = None,
) -> tuple[set[str], set[str]]:
    """Collect (allow_sids, deny_sids) holding Apply/Read rights on the GPO.

    Returns two independent sets:

    - **allow_sids** — trustees with a net allow for Read/Apply (after
      same-trustee deny cancellation).
    - **deny_sids** — trustees with a deny for Read/Apply, including
      deny-only ACEs that have no corresponding allow. This is critical for
      cross-trustee deny: a principal whose token independently intersects
      the deny set must be blocked even if the denied trustee is not in the
      allow set.

    Domain-relative RID suffixes (e.g. ``-513`` for Domain Users) are
    expanded to full SIDs using ``domain_sid`` so they match the full SIDs
    in a principal's token.
    """
    allow_sids: set[str] = set()
    deny_sids: set[str] = set()
    has_data = False

    def _expand(sid: str) -> str:
        if sid.startswith("-"):
            if domain_sid is None:
                return ""
            return f"{domain_sid}{sid}"
        return sid

    for entry in gpo.delegation:
        has_data = True
        if entry.allowed:
            if not permission_implies_apply(entry.permission):
                continue
        elif not permission_implies_read(entry.permission):
            continue
        sid = (entry.trustee_sid or "").strip().lower()
        if not sid and entry.trustee:
            sid = name_to_sid.get(entry.trustee.lower(), "")
        sid = _expand(sid)
        if not sid:
            continue
        if entry.allowed:
            allow_sids.add(sid)
        else:
            deny_sids.add(sid)

    if not gpo.delegation and gpo.sddl:
        has_data = True
        acl = parse_sddl(gpo.sddl)
        allow_rights: dict[str, set[str]] = defaultdict(set)
        deny_rights: dict[str, set[str]] = defaultdict(set)
        for ace in acl.dacl:
            # Canonicalize alias forms (AU/WD/DA…) to the raw SID so an
            # alias-form deny cancels a raw-SID allow for the same trustee and
            # matches the canonical SIDs in a principal's token (WI-084).
            sid = canonical_sddl_sid(ace.trustee_sid or "", domain_sid)
            if not sid:
                continue
            rights = set(parse_sddl_rights(ace.rights))
            if is_allow_ace_type(ace.ace_type):
                allow_rights[sid] |= rights
            elif is_deny_ace_type(ace.ace_type):
                deny_rights[sid] |= rights
        for sid, allowed in allow_rights.items():
            net = allowed - deny_rights.get(sid, set())
            if net & APPLY_RIGHTS:
                allow_sids.add(sid)
        for sid, denied in deny_rights.items():
            if denied & READ_OR_APPLY_RIGHTS:
                deny_sids.add(sid)

    if not has_data:
        return set(), set()
    return allow_sids, deny_sids


# ---------------------------------------------------------------------------
# Phase A — Principal resultant
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExcludedGpo:
    """A GPO excluded from the deterministic resultant, with reason."""

    gpo_id: str
    gpo_name: str
    reason: str
    kind: str
    side: str = ""


@dataclass(frozen=True)
class ConditionalDanger:
    """A dangerous config in a GPO that is gated (not silently dropped)."""

    gpo_id: str
    gpo_name: str
    reason: str
    finding_count: int


@dataclass(frozen=True)
class PrincipalResultant:
    """The effective policy for a principal, given collected inputs."""

    principal_sid: str
    principal_name: str
    computer_sid: str | None
    settings: list[MergedSetting]
    excluded: list[ExcludedGpo]
    excluded_settings: list[ExcludedSetting]
    conditional_dangers: list[ConditionalDanger]
    token_caveats: list[str]
    caveat_summary: str
    caveat_mechanisms: list[str] | None = None

    def __post_init__(self) -> None:
        if self.caveat_mechanisms is None:
            object.__setattr__(self, "caveat_mechanisms", [])


def _resolve_som_path_for_principal(estate: Estate, dn: str | None) -> str:
    """Find the most specific SOM path for a principal's DN, or the domain root."""
    if dn:
        parts = [p.strip() for p in _split_dn(dn)]
        for i in range(len(parts)):
            candidate = ",".join(parts[i:])
            for som in estate.soms:
                if som.container_type == "site":
                    continue
                if som.path.lower() == candidate.lower():
                    return som.path
    for som in estate.soms:
        if som.container_type == "domain":
            return som.path
    for som in estate.soms:
        if som.container_type != "site":
            return som.path
    return ""


def _evaluate_security_gate(
    gpo: Gpo,
    token_sids: frozenset[str],
    name_to_sid: dict[str, str],
    domain_sid: str | None = None,
) -> tuple[bool, str]:
    """Return (passes, reason). passes=True if the token can Read+Apply the GPO.

    Deny-first evaluation: if the principal's token intersects any deny ACE
    trustee, the GPO is blocked — even if the token also intersects an allow
    trustee. This catches cross-trustee deny (e.g. GPO allows
    Authenticated Users but denies a group the principal is a member of).
    """
    allow_sids, deny_sids = _gpo_apply_trustee_sids(gpo, name_to_sid, domain_sid)
    if deny_sids & token_sids:
        return False, "security filter: token intersects deny ACE"
    if not allow_sids:
        if gpo.delegation or gpo.sddl:
            return False, "security filter: no resolvable Apply trustee SIDs in token"
        return True, "no delegation/SDDL data — security filtering state unknown"
    if allow_sids & token_sids:
        return True, ""
    return False, "security filter: token does not intersect Apply trustees"


def _side_for_principal(principal_type: str) -> Side:
    if principal_type.lower() == "computer":
        return "Computer"
    return "User"


def _build_conditional_dangers(
    excluded: list[ExcludedGpo],
    excluded_settings: list[ExcludedSetting],
    danger_findings: list[DangerFinding],
) -> list[ConditionalDanger]:
    """Cross gated GPOs with danger findings (decision 3: never hide a danger).

    A GPO is "gated" if it was excluded at the GPO level (security filter /
    WMI) or had settings excluded at the item level (ILT-gated GPP). Any danger
    in such a GPO surfaces here rather than being silently dropped.
    """
    gated: dict[str, str] = {}  # gpo_id -> reason
    gpo_names: dict[str, str] = {}  # gpo_id -> gpo_name
    for exc in excluded:
        gated[exc.gpo_id] = exc.reason
        gpo_names[exc.gpo_id] = exc.gpo_name
    for es in excluded_settings:
        gpo_names.setdefault(es.gpo_id, es.gpo_name)
        if es.kind == "ilt" and es.gpo_id not in gated:
            gated[es.gpo_id] = "ILT-gated GPP item excluded from resultant"

    by_gpo: dict[str, list[DangerFinding]] = defaultdict(list)
    for f in danger_findings:
        if f.gpo_id in gated:
            by_gpo[f.gpo_id].append(f)

    out: list[ConditionalDanger] = []
    for gpo_id, reason in gated.items():
        findings = by_gpo.get(gpo_id, [])
        if findings:
            out.append(
                ConditionalDanger(
                    gpo_id=gpo_id,
                    gpo_name=gpo_names.get(gpo_id, gpo_id),
                    reason=reason,
                    finding_count=len(findings),
                )
            )
    out.sort(key=lambda c: (c.gpo_name.lower(), c.gpo_id))
    return out


def _build_caveat_mechanisms(
    excluded: list[ExcludedGpo],
    excluded_settings: list[ExcludedSetting],
    token_caveats: list[str],
    is_user_side: bool,
    has_site_soms: bool,
) -> list[str]:
    """Build the list of non-simulated mechanisms applicable to this resultant.

    Per the per-user RSoP design (docs/design/per-user-rsop.md), these
    mechanisms are surfaced explicitly — never silently assumed. Only
    mechanisms that are *relevant* to this resultant are listed (e.g., WMI
    is only listed when a WMI-filtered GPO was actually excluded).
    """
    mechanisms: list[str] = []
    if is_user_side:
        mechanisms.append("Loopback processing")
    if any(e.kind == "wmi_filter" for e in excluded):
        mechanisms.append("WMI filter evaluation")
    if any(e.kind == "ilt" for e in excluded_settings):
        mechanisms.append("Item-level targeting (ILT)")
    if has_site_soms:
        mechanisms.append("AD-site membership")
    mechanisms.append("Deny-ACE interaction")
    if token_caveats:
        mechanisms.append("Primary-group / foreign-SID edge cases")
    return mechanisms


def _build_caveat_summary(
    settings: list[MergedSetting],
    excluded: list[ExcludedGpo],
    excluded_settings: list[ExcludedSetting],
    conditional_dangers: list[ConditionalDanger],
    token_caveats: list[str],
    has_computer: bool,
    label: str,
) -> str:
    parts: list[str] = ["Resultant given collected inputs"]
    if label:
        parts.append(f"({label})")
    approx = sum(1 for s in settings if s.approximate)
    cond = sum(1 for s in settings if s.conditional)
    parts.append(f"{len(settings)} setting(s)")
    if approx:
        parts.append(f"{approx} approximate")
    if cond:
        parts.append(f"{cond} conditional")
    if excluded:
        parts.append(f"{len(excluded)} excluded")
    if excluded_settings:
        ilt = sum(1 for e in excluded_settings if e.kind == "ilt")
        if ilt:
            parts.append(f"{ilt} ILT-excluded setting(s)")
    if conditional_dangers:
        parts.append(f"{len(conditional_dangers)} conditional danger(s)")
    if token_caveats:
        parts.append(f"{len(token_caveats)} token caveat(s)")
    if has_computer:
        parts.append("computer pair")
    return ". ".join(parts) + "."


def _collect_chain_entries(
    chain: list[EffectiveGpo],
    target_side: Side,
    gpo_by_id: dict[str, Gpo],
    token_sids: frozenset[str],
    name_to_sid: dict[str, str],
    domain_sid: str | None,
    excluded: list[ExcludedGpo],
    *,
    _already_excluded: set[str] | None = None,
) -> list[ChainEntry]:
    """Walk a precedence chain, evaluate gates, and collect one side's settings.

    GPOs that fail the security gate or carry a WMI filter are appended to
    ``excluded`` (never silently dropped — decision 2). Used for both the
    user chain (User-side settings) and the computer chain (Computer-side
    settings) so the two paths share one exclusion-recording code path.

    ``_already_excluded`` is a shared set of GPO IDs already excluded from
    a prior chain (e.g. the user chain when computing a user+computer pair).
    When provided, GPOs in this set are skipped without re-recording the
    exclusion, preventing duplicate entries (WI-051).
    """
    entries: list[ChainEntry] = []
    for eg in chain:
        gpo = gpo_by_id.get(eg.gpo_id)
        if gpo is None or not eg.enabled:
            continue
        if _already_excluded is not None and gpo.id in _already_excluded:
            continue
        passes, reason = _evaluate_security_gate(
            gpo,
            token_sids,
            name_to_sid,
            domain_sid,
        )
        if not passes:
            if _already_excluded is not None:
                _already_excluded.add(gpo.id)
            excluded.append(
                ExcludedGpo(
                    gpo_id=gpo.id,
                    gpo_name=gpo.name,
                    reason=reason,
                    kind="security_filter",
                    side=target_side,
                )
            )
            continue
        if gpo.wmi_filter:
            if _already_excluded is not None:
                _already_excluded.add(gpo.id)
            excluded.append(
                ExcludedGpo(
                    gpo_id=gpo.id,
                    gpo_name=gpo.name,
                    reason=f"WMI filter attached: {gpo.wmi_filter}",
                    kind="wmi_filter",
                    side=target_side,
                )
            )
            continue
        side_settings = [
            s for s in gpo.settings if s.side == target_side and not s.from_disabled_side
        ]
        if not side_settings:
            continue
        entries.append(
            ChainEntry(
                gpo_id=gpo.id,
                gpo_name=gpo.name,
                order=eg.order,
                enforced=eg.enforced,
                settings=side_settings,
            )
        )
    return entries


def principal_resultant(
    estate: Estate,
    principal_sid: str,
    computer_sid: str | None = None,
    *,
    dn: str | None = None,
    computer_dn: str | None = None,
    danger: list[DangerFinding] | None = None,
) -> PrincipalResultant:
    """Compute the resultant policy for a principal given collected inputs.

    Builds the principal's token (A.1), resolves the precedence chain (A.2),
    evaluates the security-filter gate (A.3), applies the merge model (A.4),
    and produces the resultant with explicit caveat lists (A.5).

    Output is labeled "resultant given collected inputs," never unqualified
    "effective" (decision 4). WMI/ILT-gated contributors are excluded and
    listed, never silently dropped (decision 2). Dangerous configs in gated
    GPOs surface in the conditional-dangers bucket (decision 3).

    For a user+computer pair (decision 5), the user's chain (from ``dn``)
    contributes User-side settings and the computer's chain (from
    ``computer_dn``) contributes Computer-side settings; both are evaluated
    against the combined user+computer token (post-MS16-072).

    Best-effort loopback (WI-028): when a GPO in the computer chain
    configures loopback processing, user-side settings from the computer's
    chain are merged into the resultant. In **replace** mode, the user's own
    chain is ignored for User-side settings (the computer chain is the sole
    source). In **merge** mode, both chains contribute, with the computer
    chain winning conflicts (offset orders). Security filtering on loopback
    user-side GPOs uses the computer's token only (MS16-072). WMI/ILT on
    computer-chain user-side GPOs and ``mixed``/``unknown`` modes are still
    not simulated — they fall back to the non-loopback path with a caveat.

    *danger* lets a caller that already computed ``danger_findings()`` pass
    the list in, avoiding a redundant re-evaluation (WI-031).
    """
    sid = principal_sid.strip().lower()
    rp = resolve_principal(estate, sid)
    token = build_token(estate, sid)
    token_sids = token.token_sids

    if computer_sid:
        comp_sid = computer_sid.strip().lower()
        comp_token = build_token(estate, comp_sid)
        token_sids = token_sids | comp_token.token_sids

    name_to_sid = _build_name_to_sid_map(estate)
    # Domain SID expands domain-relative RID suffixes (Domain Users/Computers)
    # in the security-gate trustee resolution. Prefer collected principals;
    # fall back to the principal's own SID (e.g. an unresolved/empty estate).
    domain_sid = _estate_domain_sid(estate) or _domain_sid_from(sid)
    ilt_hits = scan_ilt(estate)
    ilt_gpo_ids = frozenset(h.gpo_id for h in ilt_hits)

    som_path = _resolve_som_path_for_principal(estate, dn)
    chain = som_effective_gpos(estate, som_path) if som_path else []
    gpo_by_id = estate.gpo_index

    side = _side_for_principal(rp.principal_type)
    is_user_computer_pair = computer_sid is not None and side == "User"

    excluded: list[ExcludedGpo] = []
    active_loopback: str | None = None

    approx_msgs: list[str] = []
    if dn and som_path and chain:
        dn_norm = ",".join(p.strip() for p in _split_dn(dn)).lower()
        if dn_norm != som_path.lower():
            approx_msgs.append(
                "Principal target DN did not match a collected scope; the chain "
                "uses a collected ancestor or fallback scope. Inheritance blocking on "
                "uncollected intermediate OUs could not be checked."
            )
    if is_user_computer_pair:
        comp_token_sids = comp_token.token_sids
        comp_som = _resolve_som_path_for_principal(
            estate,
            computer_dn if computer_dn is not None else dn,
        )
        comp_chain = som_effective_gpos(estate, comp_som) if comp_som else []
        comp_dn_resolved = computer_dn if computer_dn is not None else dn
        if comp_dn_resolved and comp_som and comp_chain:
            comp_dn_norm = ",".join(p.strip() for p in _split_dn(comp_dn_resolved)).lower()
            if comp_dn_norm != comp_som.lower():
                approx_msgs.append(
                    "Computer target DN did not match a collected scope; its chain "
                    "uses a collected ancestor or fallback scope."
                )

        loopback_map = loopback_awareness(estate)
        comp_chain_ids = {eg.gpo_id for eg in comp_chain if eg.enabled}
        loopback_modes = {loopback_map[gid] for gid in comp_chain_ids if gid in loopback_map}
        if not loopback_modes:
            active_loopback = None
        elif len(loopback_modes) == 1:
            active_loopback = loopback_modes.pop()
        else:
            active_loopback = "mixed"

        excluded_ids: set[str] = set()
        if active_loopback == "replace":
            chain_entries = _collect_chain_entries(
                comp_chain,
                "User",
                gpo_by_id,
                comp_token_sids,
                name_to_sid,
                domain_sid,
                excluded,
            )
            chain_entries += _collect_chain_entries(
                comp_chain,
                "Computer",
                gpo_by_id,
                token_sids,
                name_to_sid,
                domain_sid,
                excluded,
                _already_excluded=excluded_ids,
            )
        elif active_loopback == "merge":
            user_entries = _collect_chain_entries(
                chain,
                "User",
                gpo_by_id,
                token_sids,
                name_to_sid,
                domain_sid,
                excluded,
                _already_excluded=excluded_ids,
            )
            comp_user_entries = _collect_chain_entries(
                comp_chain,
                "User",
                gpo_by_id,
                comp_token_sids,
                name_to_sid,
                domain_sid,
                excluded,
            )
            max_user_order = max((e.order for e in user_entries), default=0)
            offset = max_user_order + 1 if user_entries else 0
            offset_comp_user = [
                ChainEntry(
                    gpo_id=e.gpo_id,
                    gpo_name=e.gpo_name,
                    order=e.order + offset,
                    enforced=e.enforced,
                    settings=e.settings,
                )
                for e in comp_user_entries
            ]
            chain_entries = user_entries + offset_comp_user
            chain_entries += _collect_chain_entries(
                comp_chain,
                "Computer",
                gpo_by_id,
                token_sids,
                name_to_sid,
                domain_sid,
                excluded,
                _already_excluded=excluded_ids,
            )
        else:
            chain_entries = _collect_chain_entries(
                chain,
                "User",
                gpo_by_id,
                token_sids,
                name_to_sid,
                domain_sid,
                excluded,
                _already_excluded=excluded_ids,
            )
            chain_entries += _collect_chain_entries(
                comp_chain,
                "Computer",
                gpo_by_id,
                token_sids,
                name_to_sid,
                domain_sid,
                excluded,
                _already_excluded=excluded_ids,
            )
    else:
        chain_entries = _collect_chain_entries(
            chain,
            side,
            gpo_by_id,
            token_sids,
            name_to_sid,
            domain_sid,
            excluded,
        )

    if is_user_computer_pair:
        seen_exc: set[tuple[str, str, str]] = set()
        deduped: list[ExcludedGpo] = []
        for exc in excluded:
            key = (exc.gpo_id, exc.kind, exc.side)
            if key not in seen_exc:
                seen_exc.add(key)
                deduped.append(exc)
        excluded = deduped

    merge = merge_settings_with_exclusions(
        chain_entries,
        ilt_gpo_ids=ilt_gpo_ids,
    )
    settings = merge.settings
    excluded_settings = merge.excluded_settings

    if danger is not None:
        dangers = danger
    else:
        # Lazy import: merge is a core module and shouldn't eagerly couple to
        # the danger rules loader (which reads ``danger_rules.toml`` at call
        # time). Importing at module top made every principal_resultant call
        # depend on a parseable shipped rules file even when the caller
        # passed pre-computed findings.
        from gpo_lens.danger import danger_findings as _danger_findings

        dangers = _danger_findings(estate)
    conditional_dangers = _build_conditional_dangers(
        excluded,
        excluded_settings,
        dangers,
    )

    if is_user_computer_pair:
        if active_loopback == "replace":
            label = "user resultant with computer pair (loopback=replace)"
        elif active_loopback == "merge":
            label = "user resultant with computer pair (loopback=merge)"
        elif active_loopback in ("mixed", "unknown"):
            label = (
                "user resultant with computer pair "
                f"(loopback={active_loopback}; best-effort, no simulation)"
            )
        else:
            label = "user resultant with computer pair (no loopback)"
    elif side == "User":
        label = "user in own OU, no loopback, no computer"
    else:
        label = "computer resultant"

    caveat_summary = _build_caveat_summary(
        settings,
        excluded,
        excluded_settings,
        conditional_dangers,
        token.token_caveats,
        has_computer=computer_sid is not None,
        label=label,
    )

    has_site_soms = any(som.container_type == "site" and som.links for som in estate.soms)
    caveat_mechanisms = _build_caveat_mechanisms(
        excluded,
        excluded_settings,
        token.token_caveats,
        is_user_side=side == "User",
        has_site_soms=has_site_soms,
    )
    caveat_mechanisms = approx_msgs + caveat_mechanisms

    return PrincipalResultant(
        principal_sid=sid,
        principal_name=rp.name,
        computer_sid=computer_sid.strip().lower() if computer_sid else None,
        settings=settings,
        excluded=excluded,
        excluded_settings=excluded_settings,
        conditional_dangers=conditional_dangers,
        token_caveats=token.token_caveats,
        caveat_summary=caveat_summary,
        caveat_mechanisms=caveat_mechanisms,
    )
