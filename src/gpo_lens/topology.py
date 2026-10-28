"""Topology and scope-aware queries over an Estate.

These functions resolve SOM chains, security filtering, WMI loops, and loopback
state.  They live in a separate module so queries.py can stay focused on
composition, diffing, and estate-wide scans.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from gpo_lens.authz import (
    READ_OR_APPLY_RIGHTS,
    SCOPE_BROAD_TRUSTEES,
    applies_broadly,
    broad_trustee_key,
    is_allow_ace_type,
    is_deny_ace_type,
    iter_sddl_apply_aces,
    parse_sddl,
    parse_sddl_rights,
    permission_implies_apply,
    permission_implies_read,
    resolve_principal,
)
from gpo_lens.detection import scan_ilt
from gpo_lens.model import SddlAce, Side

if TYPE_CHECKING:
    from gpo_lens.model import Estate, Gpo, GpoLink, Setting, Som, SomLink

__all__ = [
    "EffectiveGpo",
    "EffectiveScope",
    "EffectiveSetting",
    "GateSummary",
    "SecurityFiltering",
    "SomConflict",
    "WmiFilterScope",
    "effective_scope",
    "gate_summaries",
    "is_security_filtered",
    "loopback_awareness",
    "loopback_gpos",
    "precedence_conflicts",
    "scope_caveats",
    "security_filtering_detail",
    "settings_at_som",
    "som_conflicts",
    "som_effective_gpos",
    "wmi_filtered_gpos",
]


# ---------------------------------------------------------------------------
# Topology / SOM-aware queries (Tier 2.5)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EffectiveGpo:
    """One GPO in the resolved chain at a SOM."""

    gpo_id: str
    gpo_name: str
    order: int
    enabled: bool
    enforced: bool
    target: str  # DN the link originates from


def _split_dn(dn: str) -> list[str]:
    """Split a DN on commas, respecting backslash escaping.

    ``CN=Last\\,First,OU=Users,DC=test`` → ``['CN=Last\\,First', 'OU=Users', 'DC=test']``

    A comma is a separator only when preceded by an *even* number of
    backslashes (zero or a complete escaped-backslash run). An odd run
    means the comma itself is escaped (``\\,``) and is part of the RDN
    value. This also keeps ``\\\\,`` (literal backslash + separator) correct.
    """
    parts: list[str] = []
    start = 0
    i = 0
    while i < len(dn):
        if dn[i] == ",":
            bs = 0
            j = i - 1
            while j >= 0 and dn[j] == "\\":
                bs += 1
                j -= 1
            if bs % 2 == 0:
                parts.append(dn[start:i])
                start = i + 1
        i += 1
    parts.append(dn[start:])
    return parts


def _dn_parts_without_padding(dn: str) -> list[str]:
    """Split a DN and trim formatting without removing escaped value spaces."""
    parts: list[str] = []
    for part in _split_dn(dn):
        part = part.lstrip()
        end = len(part)
        while end and part[end - 1].isspace():
            backslashes = 0
            cursor = end - 2
            while cursor >= 0 and part[cursor] == "\\":
                backslashes += 1
                cursor -= 1
            if backslashes % 2:
                # An escaped trailing space belongs to the RDN's value.
                break
            end -= 1
        parts.append(part[:end])
    return parts


def _find_parent_som(estate: Estate, dn: str) -> Som | None:
    """Walk up a DN to find the closest non-site SOM in the estate.

    Strips the leftmost RDN component repeatedly until a matching SOM is
    found.  Sites are skipped — they are a parallel scoping axis, not
    part of the OU-precedence chain.

    **Limitation:** ``inheritance_blocked`` on intermediate OUs that are
    *not* in the estate cannot be checked.  The returned chain is the
    parent SOM's ``InheritedGpoLinks`` — which the collector already
    resolved for the parent, but which may not reflect block-inheritance
    on uncollected intermediate OUs.  Callers should surface this as an
    approximation when the target SOM was absent (WI-076).
    """
    if not dn:
        return None
    som_by_path = {som.path.lower(): som for som in estate.soms if som.container_type != "site"}
    parts = _dn_parts_without_padding(dn)
    for i in range(1, len(parts)):
        candidate = ",".join(parts[i:]).lower()
        if candidate in som_by_path:
            return som_by_path[candidate]
    return None


def som_effective_gpos(
    estate: Estate,
    som_path: str,
    *,
    _som: Som | None = None,
) -> list[EffectiveGpo]:
    """Return the resolved, ordered GPO chain at a given SOM path.

    When the SOM is found, its ``InheritedGpoLinks`` (captured by the
    collector via ``Get-GPInheritance``) already include both direct and
    parent-inherited links — the platform resolves inheritance upstream.

    When the SOM is **not** found in the estate (e.g. a principal DN
    whose OU was not captured by the collector), the function walks up
    the DN to find the closest parent SOM that *is* in the estate and
    returns its chain. This ensures GPOs linked at ancestor OUs are
    surfaced even when the exact target is absent (WI-076).
    """
    names = estate.gpo_names
    target_som = _som
    if target_som is None:
        for som in estate.soms:
            if som.path.lower() == som_path.lower():
                target_som = som
                break
        if target_som is None:
            target_som = _find_parent_som(estate, som_path)
    if target_som is None:
        return []
    return [
        EffectiveGpo(
            gpo_id=link.gpo_id,
            gpo_name=names.get(link.gpo_id, "<unknown>"),
            order=link.order,
            enabled=link.enabled,
            enforced=link.enforced,
            target=link.target,
        )
        for link in target_som.links
    ]


# ---------------------------------------------------------------------------
# Feature-flag queries
# ---------------------------------------------------------------------------

_LOOPBACK_IDENTITIES = {
    "configure user group policy loopback processing mode",
    "configure group policy loopback processing mode",
}


def loopback_gpos(estate: Estate) -> list[tuple[Gpo, Setting]]:
    """GPOs that configure loopback processing mode."""
    results: list[tuple[Gpo, Setting]] = []
    for g in estate.gpos:
        for s in g.settings:
            ident_lower = s.identity.lower()
            val_lower = s.display_value.lower()
            if any(lb in ident_lower for lb in _LOOPBACK_IDENTITIES):
                results.append((g, s))
            elif any(lb in val_lower for lb in _LOOPBACK_IDENTITIES):
                results.append((g, s))
    return results


def _extract_loopback_mode(setting: Setting) -> str | None:
    """Return 'merge', 'replace', 'unknown', or None from a loopback setting.

    Returns None when the setting does not actually configure loopback
    (Disabled/Not Configured/empty).  Returns 'unknown' when loopback IS
    configured but the specific mode cannot be determined.

    Handles three raw-dict shapes:

    1. **Security CSE** (test fixtures): ``Security > SettingString/SettingBoolean``
       with text "Replace"/"Merge"/"1"/"2".
    2. **Registry CSE / Policy** (real-world exports): ``Policy > State`` ("Enabled"
       or "Disabled") + ``Policy > DropDownList > Value > Name`` with text
       "Merge"/"Replace".
    3. **Fallback**: ``display_value`` containing "replace"/"merge"/"not configured".
    """
    raw = setting.raw
    if isinstance(raw, dict):
        children_raw = raw.get("children", [])
        if isinstance(children_raw, list):
            # Check for Policy > State = "Disabled" first (not actually configured)
            for child in children_raw:
                if not isinstance(child, dict):
                    continue
                if str(child.get("tag", "")).lower() == "state":
                    state_text = str(child.get("text") or "").strip().lower()
                    if state_text == "disabled":
                        return None
                    break

            # Security CSE: SettingBoolean/SettingString/SettingNumber children
            for child in children_raw:
                if not isinstance(child, dict):
                    continue
                tag = str(child.get("tag", "")).lower()
                if tag in ("settingboolean", "settingstring", "settingnumber"):
                    text = str(child.get("text") or "").strip().lower()
                    if text in ("replace", "1"):
                        return "replace"
                    if text in ("merge", "2"):
                        return "merge"
                    if text == "0":
                        return None

            # Registry CSE / Policy: DropDownList > Value > Name
            for child in children_raw:
                if not isinstance(child, dict):
                    continue
                if str(child.get("tag", "")).lower() == "dropdownlist":
                    dd_children = child.get("children")
                    if not isinstance(dd_children, list):
                        continue
                    for vc in dd_children:
                        if not isinstance(vc, dict):
                            continue
                        if str(vc.get("tag", "")).lower() == "value":
                            v_children = vc.get("children")
                            if not isinstance(v_children, list):
                                continue
                            for nc in v_children:
                                if not isinstance(nc, dict):
                                    continue
                                if str(nc.get("tag", "")).lower() == "name":
                                    text = str(nc.get("text") or "").strip().lower()
                                    if text == "replace":
                                        return "replace"
                                    if text == "merge":
                                        return "merge"
    val = setting.display_value.strip().lower()
    if "replace" in val:
        return "replace"
    if "merge" in val:
        return "merge"
    if not val or val in ("not configured", "disabled"):
        return None
    return "unknown"


def loopback_awareness(estate: Estate) -> dict[str, str]:
    """Map GPO id -> loopback mode for GPOs that configure loopback.

    Every GPO that sets loopback will appear in the result.  Mode will be
    'merge', 'replace', 'mixed', or 'unknown' (never None / never absent).
    GPOs where loopback is not actually configured (Disabled/Not Configured)
    are excluded.
    """
    results: dict[str, str] = {}
    for g, s in loopback_gpos(estate):
        mode = _extract_loopback_mode(s)
        if mode is None:
            continue
        existing = results.get(g.id)
        if existing is None:
            results[g.id] = mode
        elif existing != mode:
            results[g.id] = "mixed"
    return results


def wmi_filtered_gpos(estate: Estate) -> list[Gpo]:
    """GPOs that have a WMI filter attached."""
    return [g for g in estate.gpos if g.wmi_filter is not None]


# ---------------------------------------------------------------------------
# Tier 2.5 — Chain-aware conflict detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SomConflict:
    """One setting identity that fights in the resolved SOM chain."""

    som_path: str
    cse: str
    side: Side
    identity: str
    display_name: str
    entries: list[tuple[str, str, str]]  # (gpo_name, display_value, status)
    winner: str  # gpo_name of the last in chain


def _find_som(estate: Estate, som_path: str) -> Som | None:
    """Case-insensitive SOM lookup by path, or None if absent."""
    for som in estate.soms:
        if som.path.lower() == som_path.lower():
            return som
    return None


def _resolve_som_chain(
    estate: Estate, som_path: str
) -> tuple[list[SomLink], dict[str, Gpo], dict[str, str]] | None:
    """Find a SOM and return (enabled_chain, gpo_by_id, names) or None.

    Returns None both when the SOM does not exist and when it exists but has
    no enabled links. Callers that need to tell those apart should use
    ``_find_som`` directly (see ``scope_caveats``).
    """
    target_som = _find_som(estate, som_path)
    if target_som is None:
        return None
    chain = [link for link in target_som.links if link.enabled]
    if not chain:
        return None
    return chain, estate.gpo_index, estate.gpo_names


@dataclass(frozen=True)
class _BucketEntry:
    """One setting occurrence folded into a SOM-chain bucket."""

    gpo_id: str
    gpo_name: str
    value: str
    display_name: str
    link_order: int
    enforced: bool


def _fold_chain_to_buckets(
    estate: Estate,
    som_path: str,
) -> dict[tuple[str, Side, str], list[_BucketEntry]] | None:
    """Resolve the SOM chain and build per-setting-identity buckets.

    Returns ``None`` when the SOM does not exist or has no enabled links.
    """
    resolved = _resolve_som_chain(estate, som_path)
    if resolved is None:
        return None
    chain, gpo_by_id, names = resolved

    buckets: dict[tuple[str, Side, str], list[_BucketEntry]] = defaultdict(list)
    for link in chain:
        gpo = gpo_by_id.get(link.gpo_id)
        if gpo is None:
            continue
        gpo_name = names.get(link.gpo_id, "<unknown>")
        for s in gpo.settings:
            # A setting on a disabled side does not apply — skip it. These
            # ghosts are surfaced separately by disabled_but_populated().
            if s.from_disabled_side:
                continue
            key = (s.cse, s.side, s.identity)
            buckets[key].append(
                _BucketEntry(
                    gpo_id=link.gpo_id,
                    gpo_name=gpo_name,
                    value=s.display_value,
                    display_name=s.display_name,
                    link_order=link.order,
                    enforced=link.enforced,
                )
            )
    return dict(buckets)


def som_conflicts(estate: Estate, som_path: str) -> list[SomConflict]:
    """Settings that appear in the SOM chain with differing values."""
    buckets = _fold_chain_to_buckets(estate, som_path)
    if buckets is None:
        return []

    results: list[SomConflict] = []
    for (cse, side, identity), entries in buckets.items():
        gpo_names = {e.gpo_name for e in entries}
        values = {e.value for e in entries}
        if len(gpo_names) < 2 or len(values) < 2:
            continue
        winner_entry = max(entries, key=lambda e: e.link_order)
        winner = winner_entry.gpo_name
        conflict_entries: list[tuple[str, str, str]] = []
        for e in entries:
            status = "winner" if e.gpo_name == winner else "overridden"
            conflict_entries.append((e.gpo_name, e.value, status))
        conflict_entries.sort()
        display_name = next((e.display_name for e in entries if e.display_name), "")

        results.append(
            SomConflict(
                som_path=som_path,
                cse=cse,
                side=side,
                identity=identity,
                display_name=display_name,
                entries=conflict_entries,
                winner=winner,
            )
        )

    results.sort(key=lambda sc: (sc.cse, sc.side, sc.identity.lower()))
    return results


def precedence_conflicts(estate: Estate) -> list[tuple[Som, list[SomConflict]]]:
    """Estate-wide precedence conflict summary (OU/domain SOMs only).

    Site SOMs are a parallel scoping axis whose per-machine application is not
    resolved here, so they are excluded from the OU-precedence view.
    """
    results: list[tuple[Som, list[SomConflict]]] = []
    for som in estate.soms:
        if som.links and som.container_type != "site":
            conflicts_ = som_conflicts(estate, som.path)
            if conflicts_:
                results.append((som, conflicts_))
    results.sort(key=lambda pair: pair[0].path)
    return results


@dataclass(frozen=True)
class ConflictRollup:
    """One precedence conflict de-duplicated across every scope it resolves at.

    The same two GPOs fighting over the same setting recurs identically at every
    OU that inherits the same link chain — a flat per-OU list re-counts one root
    cause hundreds of times. This collapses those into a single row keyed by the
    competing settings + winner, with ``scopes`` recording the blast radius.
    """

    cse: str
    side: Side
    identity: str
    display_name: str
    winner: str
    entries: tuple[tuple[str, str, str], ...]  # (gpo_name, value, status)
    scopes: tuple[str, ...]  # som_paths resolving identically


def _enabled_chain_signature(som: Som) -> tuple[tuple[str, int, bool], ...]:
    """Order-independent signature of a SOM's enabled link chain.

    Two SOMs with the same enabled ``(gpo_id, order, enforced)`` set resolve to
    the *identical* conflict set, because ``som_conflicts`` derives everything
    (buckets, winner, entries) from the chain alone — the only path-dependent
    field is ``SomConflict.som_path``, which the rollup does not key on. Sorting
    makes the signature independent of link iteration order.
    """
    return tuple(
        sorted((link.gpo_id, link.order, link.enforced) for link in som.links if link.enabled)
    )


def precedence_conflict_rollup(estate: Estate) -> list[ConflictRollup]:
    """Collapse :func:`precedence_conflicts` to distinct root causes.

    Two per-OU conflicts are "the same" when the setting, the competing
    (GPO, value, status) entries, and the winner all match. Sorted by blast
    radius (most scopes first) so the worst-spread conflicts lead.

    Performance (WI-081): conflicts are resolved once per *distinct* enabled
    link chain, not once per SOM. On a real estate hundreds of leaf OUs share
    one chain, so this collapses ~900 chain resolutions down to the handful of
    distinct chains — an order-of-magnitude win — while producing byte-identical
    output to the naive per-SOM walk.
    """
    # 1. Bucket every OU/domain SOM by its resolved-chain signature. Site SOMs
    #    are a parallel axis (see precedence_conflicts) and are excluded.
    sig_to_scopes: dict[tuple[tuple[str, int, bool], ...], list[str]] = defaultdict(list)
    sig_repr: dict[tuple[tuple[str, int, bool], ...], str] = {}
    for som in estate.soms:
        if not som.links or som.container_type == "site":
            continue
        sig = _enabled_chain_signature(som)
        if not sig:  # no enabled links — som_conflicts would return []
            continue
        sig_to_scopes[sig].append(som.path)
        sig_repr.setdefault(sig, som.path)

    # 2. Resolve conflicts once per distinct chain, fanning the blast radius
    #    out to every SOM that shares the chain.
    groups: dict[tuple[Any, ...], list[str]] = defaultdict(list)
    meta: dict[tuple[Any, ...], SomConflict] = {}
    for sig, scopes in sig_to_scopes.items():
        for sc in som_conflicts(estate, sig_repr[sig]):
            key = (sc.cse, sc.side, sc.identity, sc.winner, tuple(sc.entries))
            groups[key].extend(scopes)
            meta[key] = sc
    out: list[ConflictRollup] = []
    for key, scopes in groups.items():
        sc = meta[key]
        out.append(
            ConflictRollup(
                cse=sc.cse,
                side=sc.side,
                identity=sc.identity,
                display_name=sc.display_name,
                winner=sc.winner,
                entries=tuple(sc.entries),
                scopes=tuple(sorted(scopes)),
            )
        )
    out.sort(key=lambda r: (-len(r.scopes), r.cse, r.identity.lower()))
    return out


# ---------------------------------------------------------------------------
# AD site links (parallel scoping axis — flagged, not resolved per-machine)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SiteGpoLink:
    """One GPO linked at an AD site."""

    gpo_id: str
    gpo_name: str
    enabled: bool
    enforced: bool
    order: int


@dataclass(frozen=True)
class SiteScope:
    """An AD site and its direct GPO links."""

    name: str
    dn: str
    links: list[SiteGpoLink]


def site_scopes(estate: Estate) -> list[SiteScope]:
    """All AD sites with their direct GPO links, resolved to GPO names."""
    names = estate.gpo_names
    out: list[SiteScope] = []
    for som in estate.soms:
        if som.container_type != "site":
            continue
        links = [
            SiteGpoLink(
                gpo_id=link.gpo_id,
                gpo_name=names.get(link.gpo_id, link.gpo_id),
                enabled=link.enabled,
                enforced=link.enforced,
                order=link.order,
            )
            for link in sorted(som.links, key=lambda link: link.order)
        ]
        out.append(SiteScope(name=som.name, dn=som.path, links=links))
    return out


def has_site_links(estate: Estate) -> bool:
    """True if any AD site carries at least one *enabled* GPO link."""
    return any(
        link.enabled for som in estate.soms if som.container_type == "site" for link in som.links
    )


# ---------------------------------------------------------------------------
# SOM Resolution Deep View
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EffectiveSetting:
    """One setting that applies at a SOM after chain folding."""

    cse: str
    side: Side
    identity: str
    display_name: str
    display_value: str
    winner_gpo_id: str
    winner_gpo_name: str
    overridden_by: list[tuple[str, str]]  # (gpo_name, display_value)
    enforced: bool


def settings_at_som(estate: Estate, som_path: str) -> list[EffectiveSetting]:
    """Return the effective settings that apply at a given SOM path."""
    buckets = _fold_chain_to_buckets(estate, som_path)
    if buckets is None:
        return []

    results: list[EffectiveSetting] = []
    for (cse, side, identity), entries in buckets.items():
        winner_entry = max(entries, key=lambda e: e.link_order)

        overridden: list[tuple[str, str]] = []
        for e in entries:
            if e.link_order < winner_entry.link_order:
                overridden.append((e.gpo_name, e.value))

        results.append(
            EffectiveSetting(
                cse=cse,
                side=side,
                identity=identity,
                display_name=winner_entry.display_name,
                display_value=winner_entry.value,
                winner_gpo_id=winner_entry.gpo_id,
                winner_gpo_name=winner_entry.gpo_name,
                overridden_by=overridden,
                enforced=winner_entry.enforced,
            )
        )

    results.sort(key=lambda es: (es.cse, es.side, es.identity.lower()))
    return results


# ---------------------------------------------------------------------------
# Scope honesty — effective scope, security filtering, WMI analysis, ILT
# ---------------------------------------------------------------------------

# Domain Computers = S-1-5-21-{domain}-515. Require the domain-SID prefix so
# we don't match arbitrary SIDs whose RID happens to end in "515".


def _sddl_read_or_apply_grants(
    dacl: tuple[SddlAce, ...],
) -> list[tuple[str | None, bool]]:
    """Extract broad-trustee grants with read/apply rights from a DACL."""
    grants: list[tuple[str | None, bool]] = []
    for ace in dacl:
        key = broad_trustee_key("", ace.trustee_sid, SCOPE_BROAD_TRUSTEES)
        if key is None:
            continue
        rights = set(parse_sddl_rights(ace.rights))
        if not (rights & READ_OR_APPLY_RIGHTS):
            continue
        if is_allow_ace_type(ace.ace_type):
            grants.append((key, True))
        elif is_deny_ace_type(ace.ace_type):
            grants.append((key, False))
    return grants


@dataclass(frozen=True)
class SecurityFiltering:
    """Security-filtering state for a GPO."""

    is_filtered: bool
    apply_trustees: list[str]
    has_au_read: bool
    has_dc_read: bool


@dataclass(frozen=True)
class WmiFilterScope:
    """WMI filter attached to a GPO (or broken reference)."""

    name: str
    query: str
    is_broken: bool


@dataclass(frozen=True)
class EffectiveScope:
    """The composed scoping view for a single GPO."""

    gpo_id: str
    gpo_name: str
    domain: str
    computer_enabled: bool
    user_enabled: bool
    links: list[GpoLink]
    security_filtering: SecurityFiltering
    wmi_filter: WmiFilterScope | None
    loopback_mode: str | None
    caveats: list[str]


def is_security_filtered(gpo: Gpo) -> bool:
    """True if the GPO's audience appears narrowed away from broad application.

    A broad trustee is Authenticated Users, Domain Computers, or Everyone
    (matched by name or SID). The GPO is considered *not* filtered when at
    least one broad trustee holds an *allow* Read / Apply Group Policy ACE
    that is not overridden by a *deny* on that same trustee.

    Honest-by-charter semantics (this flags; it does not simulate AD ACL
    evaluation):

    - **Deny precedence.** Windows evaluates deny ACEs before allow. A broad
      trustee whose allow is countered by a deny Read/Apply on the same
      trustee does not count as broad application.
    - **No delegation data → not filtered.** With an empty delegation list we
      return ``False``: absence of data is not evidence of filtering, and
      real AD inherits a default DACL granting Authenticated Users Read+Apply.
      Returning ``True`` here would be a confident false positive.

    Not modeled (deliberately): nested group membership, default/inherited
    ACEs not present on the GPO, and cross-trustee set relationships (e.g.
    that a deny on Everyone also blocks Authenticated Users).

    SDDL fallback: when delegation entries are absent but an SDDL string is
    present, the DACL is parsed to check for broad trustees with read/apply
    rights. This catches GPOs whose report carries SDDL but no Permissions
    sub-element.
    """
    if gpo.delegation:
        grants: list[tuple[str | None, bool]] = []
        for entry in gpo.delegation:
            key = broad_trustee_key(entry.trustee, entry.trustee_sid, SCOPE_BROAD_TRUSTEES)
            if key is None or not permission_implies_read(entry.permission):
                continue
            grants.append((key, entry.allowed))
        return not applies_broadly(grants)

    if gpo.sddl:
        acl = parse_sddl(gpo.sddl)
        if not acl.dacl:
            return False
        return not applies_broadly(_sddl_read_or_apply_grants(acl.dacl))

    return False


def security_filtering_detail(
    gpo: Gpo,
    estate: Estate | None = None,
) -> SecurityFiltering:
    """Detailed security-filtering breakdown for a GPO.

    When *estate* is provided, bare-SID trustees in the SDDL fallback path are
    resolved to names via :func:`gpo_lens.authz.resolve_principal` (Plan 020).
    When *estate* is ``None`` (e.g. a GPO-only call), the SDDL fallback
    degrades to well-known-SID resolution only — no collected principals.
    """
    apply_trustees: list[str] = []
    has_au_read = False
    has_dc_read = False
    for entry in gpo.delegation:
        if not entry.allowed:
            continue
        key = broad_trustee_key(entry.trustee, entry.trustee_sid, SCOPE_BROAD_TRUSTEES)
        if permission_implies_read(entry.permission):
            if key == "authenticated_users":
                has_au_read = True
            if key == "domain_computers":
                has_dc_read = True
        if permission_implies_apply(entry.permission):
            if entry.trustee not in apply_trustees:
                apply_trustees.append(entry.trustee)
    if not gpo.delegation and gpo.sddl:
        for sddl_entry in iter_sddl_apply_aces(gpo.sddl, rights_filter=READ_OR_APPLY_RIGHTS):
            if sddl_entry.broad_key == "authenticated_users":
                has_au_read = True
            if sddl_entry.broad_key == "domain_computers":
                has_dc_read = True
        for sddl_entry in iter_sddl_apply_aces(gpo.sddl):
            if estate is not None:
                rp = resolve_principal(estate, sddl_entry.ace.trustee_sid)
                if rp.name not in apply_trustees:
                    apply_trustees.append(rp.name)
    return SecurityFiltering(
        is_filtered=is_security_filtered(gpo),
        apply_trustees=apply_trustees,
        has_au_read=has_au_read,
        has_dc_read=has_dc_read,
    )


def _wmi_filter_scope(gpo: Gpo, estate: Estate) -> WmiFilterScope | None:
    if not gpo.wmi_filter:
        return None
    known = {f.name: f for f in estate.wmi_filters}
    wf = known.get(gpo.wmi_filter)
    if wf:
        return WmiFilterScope(name=wf.name, query=wf.query, is_broken=False)
    return WmiFilterScope(name=gpo.wmi_filter, query="", is_broken=True)


def scope_caveats(estate: Estate, som_path: str) -> list[str]:
    """Scoping caveats for all GPOs in scope at a SOM path.

    Composes security-filtering, WMI, ILT, and loopback caveats.
    """
    resolved = _resolve_som_chain(estate, som_path)
    if resolved is None:
        # A missing SOM yields no caveats, but a SOM that exists with every
        # link disabled is a real (and easily-missed) state worth flagging —
        # not silence.
        som = _find_som(estate, som_path)
        if som is not None and som.links and not any(link.enabled for link in som.links):
            return [
                f"  {som_path}: all {len(som.links)} GPO link(s) at this SOM are "
                f"disabled — no GPO settings apply here"
            ]
        return []
    chain, gpo_by_id, _names = resolved
    gpo_ids = {link.gpo_id for link in chain if link.enabled}

    caveats: list[str] = []
    loopback_map = loopback_awareness(estate)
    ilt_gpos = {hit.gpo_id for hit in scan_ilt(estate)}

    for gid in sorted(gpo_ids):
        gpo = gpo_by_id.get(gid)
        if gpo is None:
            continue
        if is_security_filtered(gpo):
            caveats.append(
                f"  {gpo.name}: appears security-filtered (no broad allow for "
                f"Authenticated Users / Domain Computers / Everyone; "
                f"nested membership and inherited ACEs not evaluated)"
            )
        if gpo.wmi_filter:
            caveats.append(f"  {gpo.name}: WMI filter attached ({gpo.wmi_filter})")
        if gid in ilt_gpos:
            caveats.append(
                f"  {gpo.name}: item-level targeting (per-object delivery not evaluated)"
            )
        mode = loopback_map.get(gid)
        if mode:
            caveats.append(f"  {gpo.name}: loopback={mode} (user settings may be replaced/merged)")

    if has_site_links(estate):
        n_links = sum(
            1
            for som in estate.soms
            if som.container_type == "site"
            for link in som.links
            if link.enabled
        )
        caveats.append(
            f"  AD site links: {n_links} site-linked GPO link(s) apply before this "
            f"domain/OU chain based on the client's AD site (not resolved here; "
            f"see `gpo-lens sites`)"
        )

    return caveats


def effective_scope(estate: Estate, gpo_id_or_name: str) -> EffectiveScope | None:
    """Compose the full scoping view for a single GPO.

    Accepts a canonical GPO id (lowercase, braces stripped) or a GPO name
    (case-insensitive).  Returns ``None`` when not found.
    """
    target: Gpo | None = estate.gpo_by_id(gpo_id_or_name.lower().strip("{}"))
    if target is None:
        needle = gpo_id_or_name.lower().strip()
        for g in estate.gpos:
            if g.name.lower() == needle:
                target = g
                break
    if target is None:
        return None

    caveats: list[str] = []
    sec = security_filtering_detail(target, estate)
    if not target.delegation:
        caveats.append("No delegation entries — security filtering state unknown")
    elif sec.is_filtered:
        trustees = ", ".join(sec.apply_trustees) if sec.apply_trustees else "(none found)"
        caveats.append(
            f"Security-filtered — explicit Apply Group Policy trustees: {trustees}"
            f" (exclusivity not evaluated; default ACEs and group membership not modeled)"
        )
    elif not sec.has_au_read and not sec.has_dc_read:
        caveats.append("MS16-072: missing Authenticated Users / Domain Computers Read")

    wmi = _wmi_filter_scope(target, estate)
    if wmi:
        if wmi.is_broken:
            caveats.append(f"WMI filter '{wmi.name}' is broken (not found in estate)")
        else:
            caveats.append(f"WMI filter attached: {wmi.name}")

    loopback_map = loopback_awareness(estate)
    mode = loopback_map.get(target.id)
    if mode:
        caveats.append(f"Loopback mode: {mode}")

    ilt_gpos = {hit.gpo_id for hit in scan_ilt(estate)}
    if target.id in ilt_gpos:
        caveats.append("Item-level targeting present (per-object delivery not evaluated)")

    if not target.links:
        caveats.append("GPO has no links (applies nowhere)")

    return EffectiveScope(
        gpo_id=target.id,
        gpo_name=target.name,
        domain=target.domain,
        computer_enabled=target.computer_enabled,
        user_enabled=target.user_enabled,
        links=target.links,
        security_filtering=sec,
        wmi_filter=wmi,
        loopback_mode=mode,
        caveats=caveats,
    )


# ---------------------------------------------------------------------------
# Per-candidate gate attribution (Plan 019 Phase A)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GateSummary:
    """Per-GPO scoping gate facts, shown (never evaluated) on a chain row.

    Mirrors the *components* of :func:`effective_scope` so the per-row gate
    strip and the GPO-detail scope view describe the same facts. Gates are
    *shown, not simulated* (charter: "Flag, don't simulate") — a populated
    field is a reason a GPO *might* not reach an object, never a verdict that
    it does or does not.
    """

    is_security_filtered: bool
    apply_trustees: tuple[str, ...]  # explicit Apply-Group-Policy trustee names
    wmi_filter_name: str | None  # None = no WMI filter attached
    wmi_filter_broken: bool  # True if filter name not found in estate
    loopback_mode: str | None  # 'merge'|'replace'|'mixed'|'unknown'|None
    has_ilt: bool  # item-level targeting present
    side_disabled: str | None  # 'computer'|'user'|'both'|None
    link_enabled: bool  # whether this chain row's link is enabled


def gate_summaries(
    estate: Estate,
    som_path: str,
    *,
    _som: Som | None = None,
) -> list[tuple[EffectiveGpo, GateSummary]]:
    """Ordered chain with a per-GPO :class:`GateSummary`.

    Reuses the same components as :func:`effective_scope`
    (``security_filtering_detail``, ``_wmi_filter_scope``,
    ``loopback_awareness``, ``scan_ilt``) so the per-row gates cannot drift
    from the GPO-detail scope view (WI-029 lesson). The estate-wide
    ``loopback_awareness`` and ``scan_ilt`` passes are computed once and
    shared across all rows.
    """
    chain = som_effective_gpos(estate, som_path, _som=_som)
    if not chain:
        return []
    gpo_by_id = estate.gpo_index
    loopback_map = loopback_awareness(estate)
    ilt_gpos = {hit.gpo_id for hit in scan_ilt(estate)}

    out: list[tuple[EffectiveGpo, GateSummary]] = []
    for eg in chain:
        gpo = gpo_by_id.get(eg.gpo_id)
        if gpo is None:
            out.append(
                (
                    eg,
                    GateSummary(
                        is_security_filtered=False,
                        apply_trustees=(),
                        wmi_filter_name=None,
                        wmi_filter_broken=False,
                        loopback_mode=None,
                        has_ilt=False,
                        side_disabled=None,
                        link_enabled=eg.enabled,
                    ),
                )
            )
            continue
        sec = security_filtering_detail(gpo, estate)
        wmi = _wmi_filter_scope(gpo, estate)
        if not gpo.computer_enabled and not gpo.user_enabled:
            side_disabled: str | None = "both"
        elif not gpo.computer_enabled:
            side_disabled = "computer"
        elif not gpo.user_enabled:
            side_disabled = "user"
        else:
            side_disabled = None
        out.append(
            (
                eg,
                GateSummary(
                    is_security_filtered=sec.is_filtered,
                    apply_trustees=tuple(sec.apply_trustees),
                    wmi_filter_name=wmi.name if wmi else None,
                    wmi_filter_broken=wmi.is_broken if wmi else False,
                    loopback_mode=loopback_map.get(gpo.id),
                    has_ilt=gpo.id in ilt_gpos,
                    side_disabled=side_disabled,
                    link_enabled=eg.enabled,
                ),
            )
        )
    return out
