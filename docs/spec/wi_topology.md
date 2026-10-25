# Work Item: Topology (SOM chains and scope honesty)

## Dependencies

- `interface_ref`: `model` (`Estate`, `Gpo`, `Som`, `SomLink`, `GpoLink`,
  `Setting`, `SddlAce`, `Side`)
- `interface_ref`: `authz` (`parse_sddl`, `parse_sddl_rights`,
  `is_allow_ace_type`, `is_deny_ace_type`, `resolve_principal`,
  `applies_broadly`, `broad_trustee_key`, `SCOPE_BROAD_TRUSTEES`)
- `interface_ref`: `detection` (`scan_ilt` — ILT-gated GPO detection)
- Consumer: `queries.py` re-exports the entire public surface (the
  CLI/web/JSON contract goes through `queries.*`). `merge.py` consumes
  `EffectiveGpo` and `som_effective_gpos` for chain construction.
  `report.py` consumes `som_effective_gpos`, `settings_at_som`,
  `scope_caveats`, `precedence_conflicts`.
- Reference: `plans/009-som-resolution-deep-view.md` (SOM-resolution deep
  view — `settings_at_som`), `plans/007-tier25-topology-and-hygiene.md`
  (Tier 2.5 base — `som_effective_gpos`, `som_conflicts`), `plans/014-
  site-linked-gpos.md` (AD sites as parallel axis), `plans/019-scope-
  resultant-and-gate-attribution.md` (`gate_summaries`, `effective_scope`).

## Notes

This module hosts every SOM/scope-aware query. It is a **core module**
(`tests/_arch.py::CORE_MODULES`); no `narration`/`web` imports. All
functions are pure (zero I/O, zero model calls) over an explicit
`Estate` argument.

The module's stance is **"flag, don't simulate"** (AGENTS.md hard rule):
scoping mechanisms (security filtering, WMI filters, loopback, ILT, AD
sites) are reported as caveats and per-row gate facts, never resolved
into a per-object verdict. Every gate field on `GateSummary` is a
*reason a GPO might not reach an object*, never a verdict that it does
or does not.

### Charter boundary — what topology does *not* do

- **No object-level RSoP.** Per-user security-group expansion, WMI
  evaluation, and loopback merge/replace resolution are out of scope.
  `merge.principal_resultant` is the closest in-tree approximator, and
  even it labels its output `"Resultant given collected inputs"`.
- **Sites are a parallel axis.** `precedence_conflicts` and the SOM
  counts exclude `container_type="site"` SOMs; sites surface via
  `site_scopes`, `has_site_links`, and the `scope_caveats` site-link
  warning. Per-machine site membership is **never** resolved.
- **Loopback effect on the chain is deferred.** `loopback_awareness`
  reports the *mode* a GPO configures (`merge`/`replace`/`mixed`/
  `unknown`); it does not fold user-side settings into the computer
  chain.

### Drift / known simplifications vs the plans

- **Plan 009 R2 (block/enforced annotation) is implemented by relying
  on the collector's pre-resolved chain.** The plan called for explicit
  "inheritance blocked" annotation. The implementation reads the
  platform-resolved `InheritedGpoLinks` order from the GPInheritance
  dump and trusts it — block-inheritance and enforced-link resolution
  have already happened upstream. `EffectiveSetting.enforced` carries
  whether the *winning link* was enforced; it is not an inheritance
  simulation.
- **`som_effective_gpos` returns ALL links, including disabled ones.**
  The function does not filter `link.enabled`. Callers that want only
  enabled links must filter on `EffectiveGpo.enabled` themselves, or use
  `som_conflicts` / `settings_at_som` (which filter via
  `_resolve_som_chain`). `gate_summaries` likewise returns all rows but
  exposes `link_enabled` so the UI can dim disabled rows
  (`test_gate_summaries_link_enabled_reflects_chain_row`).
- **`scope_caveats` does NOT include security-filtering caveats for
  every GPO — only the chain GPOs.** It iterates `gpo_ids` from the
  resolved chain, not the whole estate. A GPO not linked at the SOM
  produces no caveat here even if it would be security-filtered.
- **`scope_caveats` site-link caveat always emits when *any* site has
  *any* enabled link — it is estate-wide, not chained to this SOM's
  AD-site membership** (which is unresolved). The count is the estate
  total of enabled site links. Document this when the operator asks
  "why is the site caveat on a non-site OU."
- **`is_security_filtered` returns `False` for the no-data case** (no
  delegation and no SDDL, or empty DACL). The docstring spells out why:
  absence of data is not evidence of filtering, and real AD inherits a
  default DACL granting Authenticated Users Read+Apply. Returning
  `True` would be a confident false positive (WI-029 lesson).
- **`_sddl_read_or_apply_grants` is identical to the merge security-gate
  SDDL evaluation.** Both use `READ_OR_APPLY_RIGHTS = {"GA", "GR",
  "CC", "CR", "RP"}` (imported from `authz`). Keep them in lockstep;
  this is the WI-029
  anti-drift invariant (`test_gate_summaries_match_effective_scope` is
  the regression test for the `gate_summaries` ↔ `effective_scope`
  direction).
- **`EffectiveSetting.overridden_by` excludes same-order ties.** An
  entry is "overridden" only when `e.link_order < winner_entry.link_order`
  — strictly less than. Two GPOs at the same `link.order` (rare but
  possible from a malformed collector dump) both report the higher one
  as winner; the lower-or-equal one is not listed as overridden.
- **`som_conflicts` sorts `entries` alphabetically, not by precedence.**
  `conflict_entries.sort()` runs after `winner`/`overridden` assignment,
  so the rendered order is `(gpo_name, value, status)` ascending —
  *not* chain order. This is a presentation choice; if a caller needs
  precedence order, re-sort at the call site.
- **`loopback_gpos` uses substring match, not exact identity.**
  `_LOOPBACK_IDENTITIES` are matched as `any(lb in ident_lower ...)`,
  so any setting whose identity *or value* contains the configured
  phrases is flagged. This is intentionally broad (catches both
  "Configure user Group Policy loopback processing mode" and
  "Configure Group Policy loopback processing mode").

## Module map

`src/gpo_lens/topology.py` — pure functions over `Estate`. Core module
(`tests/_arch.py`).

| Public surface | Role |
|----------------|------|
| `EffectiveGpo` (frozen dataclass) | One GPO row in a resolved SOM chain. |
| `som_effective_gpos(estate, som_path, *, _som=None) -> list[EffectiveGpo]` | Resolve chain at a SOM. |
| `loopback_gpos(estate) -> list[tuple[Gpo, Setting]]` | GPOs configuring loopback (substring). |
| `loopback_awareness(estate) -> dict[str, str]` | `{gpo_id: mode}` for loopback GPOs. |
| `wmi_filtered_gpos(estate) -> list[Gpo]` | GPOs with a WMI filter attached. |
| `SomConflict` (frozen dataclass) | One identity that fights in the chain. |
| `som_conflicts(estate, som_path) -> list[SomConflict]` | Cross-GPO value conflicts at a SOM. |
| `precedence_conflicts(estate) -> list[tuple[Som, list[SomConflict]]]` | Estate-wide rollup (OU/domain only). |
| `SiteGpoLink`, `SiteScope` | AD-site parallel-axis view. |
| `site_scopes(estate) -> list[SiteScope]` | All AD sites + their direct links. |
| `has_site_links(estate) -> bool` | True iff any site has ≥1 enabled link. |
| `EffectiveSetting` (frozen dataclass) | One folded setting at a SOM. |
| `settings_at_som(estate, som_path) -> list[EffectiveSetting]` | Folded effective state at a SOM. |
| `SecurityFiltering`, `WmiFilterScope`, `EffectiveScope` | Scope-honesty dataclasses. |
| `is_security_filtered(gpo) -> bool` | Coarse security-filtering verdict. |
| `security_filtering_detail(gpo, estate=None) -> SecurityFiltering` | Detailed breakdown (AU/DC read flags). |
| `scope_caveats(estate, som_path) -> list[str]` | Composed caveat strings for a SOM. |
| `effective_scope(estate, gpo_id_or_name) -> EffectiveScope \| None` | Full scope view for one GPO. |
| `GateSummary` (frozen dataclass) | Per-row gate facts shown on chain rows. |
| `gate_summaries(estate, som_path, *, _som=None) -> list[tuple[EffectiveGpo, GateSummary]]` | Chain + per-row gates. |

`__all__` exports every public name above. Private load-bearing helpers:
`_find_som`, `_resolve_som_chain`, `_fold_chain_to_buckets`,
`_BucketEntry`, `_LOOPBACK_IDENTITIES`, `_extract_loopback_mode`,
`_sddl_read_or_apply_grants`, `_wmi_filter_scope`.

---

## AC-01: `som_effective_gpos` chain resolution

```python
def som_effective_gpos(
    estate: Estate,
    som_path: str,
    *,
    _som: Som | None = None,
) -> list[EffectiveGpo]: ...
```

- SOM lookup is case-insensitive on `som.path.lower() ==
  som_path.lower()` (`test_som_effective_gpos_case_insensitive`).
  First match wins.
- If the `_som` kwarg is provided, it is used directly (no lookup) —
  internal optimization for callers that already hold the `Som`.
- No SOM found → **parent-OU walk** (WI-076): the function walks up
  the DN (stripping RDN components, respecting backslash escaping) to
  find the closest non-site SOM that *is* in the estate. If a parent
  SOM is found, its `InheritedGpoLinks` are returned. If no parent is
  found either, return `[]` (not an exception).
  - Whitespace trimming around RDN separators must preserve escaped trailing
    spaces in a value, including odd/even backslash runs. The same rule applies
    to principal-chain lookup in `merge.py`; it does not decode or equate
    different DN spellings.
  - **Limitation:** `inheritance_blocked` on intermediate OUs that are
    *not* in the estate cannot be checked. The returned chain is an
    approximation — the parent's resolved links, which may not reflect
    block-inheritance on uncollected intermediate OUs.
- For each `SomLink` in `target_som.links` (in `links` list order),
  emit one `EffectiveGpo`:
  - `gpo_id=link.gpo_id`.
  - `gpo_name=estate.gpo_by_id(link.gpo_id).name`, or `"<unknown>"`
    when the GPO is not in the estate (dangling link).
  - `order=link.order`, `enabled=link.enabled`, `enforced=link.enforced`,
    `target=link.target`.

**Disabled links are included.** The function does not filter on
`link.enabled` (see Notes). `link.order` is preserved as-is from the
collector; the platform's `InheritedGpoLinks` order is the precedence
order, with higher `order` = later (winner) in the chain.

## AC-02: `EffectiveGpo` dataclass shape

`@dataclass(frozen=True)`. Fields:

| Field | Type | Source |
|-------|------|--------|
| `gpo_id` | `str` | Canonical GPO id. |
| `gpo_name` | `str` | GPO display name, or `"<unknown>"`. |
| `order` | `int` | Link precedence order from the collector. |
| `enabled` | `bool` | Whether this link is enabled. |
| `enforced` | `bool` | Whether this link is enforced (NoOverride). |
| `target` | `str` | DN the link originates from. |

## AC-03: Chain folding — `_fold_chain_to_buckets`

The shared builder used by `som_conflicts` and `settings_at_som`:

- Calls `_resolve_som_chain`, which returns `(chain, gpo_by_id, names)`
  or `None`. `chain` filters `som.links` to `link.enabled is True`
  (unlike AC-01 — disabled links **are** dropped here).
- Returns `None` if the SOM is absent or has no enabled links.
- For each enabled link in chain order, for each `Setting` on the
  resolved GPO:
  - **Skip `from_disabled_side=True` settings.** These are ghosts from
    a disabled CSE side; they are surfaced separately by
    `queries.disabled_but_populated` (AC-03 of `wi_queries`).
  - Bucket key is `(s.cse, s.side, s.identity)` — same identity on
    different sides or in different CSEs is a different bucket.
  - Append a `_BucketEntry(gpo_id, gpo_name, value, display_name,
    link_order, enforced)` to the bucket.

A GPO referenced by a link but absent from `estate.gpos` contributes
nothing (the `gpo_by_id.get(link.gpo_id) is None` guard).

## AC-04: `settings_at_som` — folded effective state

```python
def settings_at_som(estate: Estate, som_path: str) -> list[EffectiveSetting]: ...
```

- Returns `[]` if `_fold_chain_to_buckets` returns `None` (no SOM or
  no enabled links).
- For each bucket:
  - Winner is `max(entries, key=lambda e: e.link_order)` — the
    highest-order entry (latest in precedence chain). Ties resolve to
    the first `max` encountered (Python's stable max).
  - `overridden_by` is built from entries with
    `e.link_order < winner_entry.link_order` (strictly less — see Notes).
    Each entry contributes `(gpo_name, value)`, in chain order.
- Build `EffectiveSetting(cse, side, identity,
  display_name=winner.display_name, display_value=winner.value,
  winner_gpo_id=winner.gpo_id, winner_gpo_name=winner.gpo_name,
  overridden_by=overridden, enforced=winner.enforced)`.
- Sort the result by `(cse, side, identity.lower())` — stable, alphabetical.

Disabled links excluded (AC-03); disabled-side settings excluded (AC-03).
`test_settings_at_som_last_gpo_wins`,
`test_settings_at_som_ignores_disabled_links`,
`test_settings_at_som_excludes_disabled_side_settings`,
`test_settings_at_som_enforced_flag` are the canonical tests.

## AC-05: `EffectiveSetting` dataclass shape

`@dataclass(frozen=True)`. Fields:

| Field | Type |
|-------|------|
| `cse` | `str` |
| `side` | `Side` (`"Computer"` or `"User"`) |
| `identity` | `str` |
| `display_name` | `str` (from the winning GPO) |
| `display_value` | `str` (from the winning GPO) |
| `winner_gpo_id` | `str` |
| `winner_gpo_name` | `str` |
| `overridden_by` | `list[tuple[str, str]]` — `(gpo_name, display_value)` |
| `enforced` | `bool` (whether the *winning link* was enforced) |

## AC-06: `som_conflicts` — value-conflict detection

```python
def som_conflicts(estate: Estate, som_path: str) -> list[SomConflict]: ...
```

- Returns `[]` if the SOM is missing or has no enabled links.
- For each bucket from `_fold_chain_to_buckets`:
  - A bucket is a conflict iff **both**: `len({e.gpo_name}) >= 2` (≥2
    distinct GPOs) **and** `len({e.value}) >= 2` (≥2 distinct values).
    Two GPOs setting the same value are not a conflict.
  - Winner is `max(entries, key=lambda e: e.link_order)` — same rule as
    AC-04.
  - `conflict_entries` is built by appending `(gpo_name, value, status)`
    for every entry, where `status` is `"winner"` if
    `e.gpo_name == winner` else `"overridden"`. The list is then
    `.sort()`-ed alphabetically (see Notes — not precedence order).
  - `display_name` is the first non-empty `display_name` among entries
    (iteration order), else `""`.

- Build `SomConflict(som_path, cse, side, identity, display_name,
  entries=conflict_entries, winner=winner.gpo_name)`.
- Sort the result list by `(cse, side, identity.lower())`.

Disabled links and `from_disabled_side=True` settings are excluded by
the shared `_fold_chain_to_buckets` (AC-03).

## AC-07: `SomConflict` dataclass shape

`@dataclass(frozen=True)`. Fields:

| Field | Type |
|-------|------|
| `som_path` | `str` |
| `cse` | `str` |
| `side` | `Side` |
| `identity` | `str` |
| `display_name` | `str` |
| `entries` | `list[tuple[str, str, str]]` — `(gpo_name, value, status)` |
| `winner` | `str` — `gpo_name` of the highest-order contributor |

Note: `entries` is a `list` (not `tuple`), so `SomConflict` is "frozen
but the entries list is mutable." Treat it as read-only.

## AC-08: `precedence_conflicts` — estate-wide rollup, sites excluded

```python
def precedence_conflicts(estate: Estate) -> list[tuple[Som, list[SomConflict]]]: ...
```

- Iterate `estate.soms` in estate order. For each SOM with non-empty
  `links` **and** `container_type != "site"`, call `som_conflicts`.
- Include the SOM in the result iff `som_conflicts` returns a non-empty
  list.
- Sort the result by `pair[0].path` (the SOM DN, lexicographic).
- Site SOMs are excluded (charter: parallel scoping axis,
  `test_sites_excluded_from_precedence_conflicts`).

## AC-09: AD-site parallel axis — `site_scopes` and `has_site_links`

`site_scopes` iterates `estate.soms` and emits a `SiteScope` for each
`container_type == "site"` SOM. Each `SiteGpoLink` carries
`(gpo_id, gpo_name=names.get(gpo_id, gpo_id), enabled, enforced, order)`.
Links within a site are sorted by `link.order` ascending. `gpo_name`
falls back to the raw `gpo_id` when the GPO is not in the estate.

`has_site_links` returns True iff **any** site SOM has **any**
`link.enabled` (`test_has_site_links`). An estate with only disabled
site links returns False.

Sites are excluded from `precedence_conflicts` (AC-08) and from the
SOM count in `queries.estate_summary` (`test_sites_excluded_from_som_count_and_counted_separately`).

## AC-10: Loopback detection — `loopback_gpos` and `loopback_awareness`

`_LOOPBACK_IDENTITIES = {"configure user group policy loopback processing
mode", "configure group policy loopback processing mode"}`.

`loopback_gpos(estate)` returns `(Gpo, Setting)` for every setting where
**either** the lowercased identity **or** the lowercased display_value
contains one of the loopback phrases (substring match — see Notes). No
deduplication: the same GPO appears once per matching setting.

`loopback_awareness(estate)` builds `{gpo_id: mode}`:

1. For each `(g, s)` from `loopback_gpos`, call `_extract_loopback_mode(s)`.
2. If mode is `None` (Disabled/Not Configured), skip the GPO entirely.
3. If the GPO is new: `results[g.id] = mode`.
4. If the GPO already has a different mode: `results[g.id] = "mixed"`.

Modes returned by `_extract_loopback_mode`: `"merge"`, `"replace"`,
`"unknown"` (configured but mode unparseable), or `None`. Never absent
in the result for a configured GPO. The dispatch handles three raw-dict
shapes (Security CSE SettingBoolean/String, Registry/Policy
DropDownList, and a `display_value` substring fallback) — see the
docstring for the precedence order.

## AC-11: `wmi_filtered_gpos`

```python
def wmi_filtered_gpos(estate: Estate) -> list[Gpo]: ...
```

Returns `[g for g in estate.gpos if g.wmi_filter is not None]` — every
GPO whose `wmi_filter` field is non-empty. Estate iteration order; no
deduplication. Whether the filter name resolves to a known
`estate.wmi_filters` entry is checked separately by `_wmi_filter_scope`
(used in `effective_scope`).

## AC-12: `is_security_filtered` — coarse verdict

```python
def is_security_filtered(gpo: Gpo) -> bool: ...
```

A GPO is "not filtered" (returns `False`) when at least one broad
trustee holds an allow Read/Apply ACE that is not canceled by a deny on
the same trustee. Broad trustees are `Authenticated Users`, `Domain
Computers`, `Everyone` (matched by name or SID via `broad_trustee_key`
+ `SCOPE_BROAD_TRUSTEES`).

Two evaluation paths:

1. **Delegation path** (when `gpo.delegation` is non-empty): collect
   grants as `(broad_key, allowed)` for each delegation entry whose
   trustee is broad and whose `permission` lowercased contains `"read"`
   or `"apply"`. Then `return not applies_broadly(grants)`.
2. **SDDL fallback** (when delegation is empty AND `gpo.sddl` is set):
   parse the SDDL, and if `acl.dacl` is non-empty, run the same
   `applies_broadly` check over `_sddl_read_or_apply_grants(acl.dacl)`.
   An empty DACL returns `False` (not filtered — see Notes).

3. **No data** (no delegation, no SDDL): return `False`. Absence of
   evidence is not evidence of filtering.

`applies_broadly(grants)` returns True iff any allowed trustee is not
in the denied set. Deny ACEs override allows on the *same* trustee;
grants for different trustees are independent (cross-trustee
relationships like "deny Everyone blocks Authenticated Users" are
deliberately not modeled — see docstring).

`Domain Computers` is matched by SID only when the SID matches
`S-1-5-21-*-515` (the domain-SID prefix is required so an arbitrary SID
ending in `-515` is not falsely matched).

## AC-13: `security_filtering_detail` — detailed breakdown

```python
def security_filtering_detail(
    gpo: Gpo,
    estate: Estate | None = None,
) -> SecurityFiltering: ...
```

Returns `SecurityFiltering(is_filtered, apply_trustees, has_au_read,
has_dc_read)`:

- `is_filtered` is delegated to `is_security_filtered(gpo)` (AC-12).
- `apply_trustees`: ordered list (deduped, insertion order) of trustee
  **names** whose allowed permission lowercased contains `"apply"` or
  `"grouppolicy"` (after stripping spaces). For the SDDL fallback path,
  when `estate` is provided, bare SIDs are resolved via
  `resolve_principal` and the resolved name is appended.
- `has_au_read`: True iff any allowed broad-*Authenticated Users*
  delegation/ACE has Read/Apply/GroupPolicy permission.
- `has_dc_read`: same for *Domain Computers*.

The SDDL fallback (when `gpo.delegation` is empty and `gpo.sddl` is
set) follows the same broad-trustee matching as AC-12 but only inspects
allow ACEs (deny ACEs are skipped here — they're accounted for only in
`is_filtered` via `applies_broadly`). With `estate=None`, the SDDL
fallback degrades to well-known-SID matching only (no collected
principals).

## AC-14: `SecurityFiltering`, `WmiFilterScope`, `EffectiveScope` dataclasses

All `@dataclass(frozen=True)`.

`SecurityFiltering`: `is_filtered: bool`, `apply_trustees: list[str]`,
`has_au_read: bool`, `has_dc_read: bool`.

`WmiFilterScope`: `name: str`, `query: str`, `is_broken: bool`. Built
by `_wmi_filter_scope`: if the filter name is in `estate.wmi_filters`,
return with the real query and `is_broken=False`. Otherwise return
`query=""` and `is_broken=True` (broken reference).

`EffectiveScope`: `gpo_id, gpo_name, domain, computer_enabled,
user_enabled, links: list[GpoLink], security_filtering:
SecurityFiltering, wmi_filter: WmiFilterScope | None, loopback_mode:
str | None, caveats: list[str]`.

## AC-15: `effective_scope` — single-GPO composition

```python
def effective_scope(estate: Estate, gpo_id_or_name: str) -> EffectiveScope | None: ...
```

- Lookup: first try `estate.gpo_by_id(gpo_id_or_name.lower().strip("{}"))
  ` (canonical id form). If None, fall back to a case-insensitive name
  match over `estate.gpos`. Returns `None` if neither matches.
- Compose caveats in this order:
  1. If `not target.delegation`: `"No delegation entries — security
     filtering state unknown"`.
  2. Else if `sec.is_filtered`: `"Security-filtered — explicit Apply
     Group Policy trustees: {trustees} (exclusivity not evaluated;
     default ACEs and group membership not modeled)"`.
  3. Else if `not sec.has_au_read and not sec.has_dc_read`:
     `"MS16-072: missing Authenticated Users / Domain Computers Read"`.
  4. WMI: broken vs. attached caveat from `_wmi_filter_scope`.
  5. Loopback: `f"Loopback mode: {mode}"` if loopback_awareness has it.
  6. ILT: `"Item-level targeting present (per-object delivery not
     evaluated)"` if `target.id` is in `scan_ilt(estate)` hits.
  7. Links: `"GPO has no links (applies nowhere)"` if `not target.links`.

Return `EffectiveScope(gpo_id=target.id, gpo_name=target.name,
domain=target.domain, computer_enabled=target.computer_enabled,
user_enabled=target.user_enabled, links=target.links,
security_filtering=sec, wmi_filter=wmi, loopback_mode=mode,
caveats=caveats)`.

`test_fixture_effective_scope_by_name` covers name lookup;
`test_fixture_effective_scope_not_found` covers the None path.

## AC-16: `scope_caveats` — per-SOM composed caveats

```python
def scope_caveats(estate: Estate, som_path: str) -> list[str]: ...
```

- Resolve chain via `_resolve_som_chain`. If None:
  - Look up the SOM via `_find_som`. If it exists, has links, but none
    are enabled: emit one caveat
    `f"  {som_path}: all {len(som.links)} GPO link(s) at this SOM are
    disabled — no GPO settings apply here"`.
  - Otherwise (missing SOM) return `[]`.
- For the resolved chain, build `gpo_ids = {link.gpo_id for enabled links}`,
  then iterate `sorted(gpo_ids)` and for each GPO append (in this order):
  1. If `is_security_filtered(gpo)`: a `"appears security-filtered…"`
     caveat.
  2. If `gpo.wmi_filter`: `f"  {gpo.name}: WMI filter attached
     ({gpo.wmi_filter})"`.
  3. If `gid in ilt_gpos` (from `scan_ilt(estate)`): an ILT caveat.
  4. If `loopback_map.get(gid)`: a loopback caveat with the mode.
- After per-GPO caveats, if `has_site_links(estate)`: append an
  estate-wide site-link caveat with the total count of enabled site
  links. The count is estate-wide (see Notes).

Each caveat string begins with two spaces and the GPO/SOM name. The
2-space indent is part of the contract — `report.py` and the web
templates render the list as-is inside a `<pre>` block.

## AC-17: `gate_summaries` — per-row gate facts

```python
def gate_summaries(
    estate: Estate,
    som_path: str,
    *,
    _som: Som | None = None,
) -> list[tuple[EffectiveGpo, GateSummary]]: ...
```

- Build the chain via `som_effective_gpos(estate, som_path, _som=_som)`.
  Returns `[]` if the chain is empty.
- Compute `loopback_map = loopback_awareness(estate)` and
  `ilt_gpos = {hit.gpo_id for hit in scan_ilt(estate)}` **once**,
  outside the per-row loop.
- For each `EffectiveGpo` in the chain, build a `GateSummary`:
  - `is_security_filtered = sec.is_filtered` (via
    `security_filtering_detail`).
  - `apply_trustees = tuple(sec.apply_trustees)`.
  - `wmi_filter_name = wmi.name if wmi else None` (via `_wmi_filter_scope`).
  - `wmi_filter_broken = wmi.is_broken if wmi else False`.
  - `loopback_mode = loopback_map.get(gpo.id)` (may be `None`).
  - `has_ilt = gpo.id in ilt_gpos`.
  - `side_disabled`: `"both"` if neither side enabled; `"computer"` if
    only computer disabled; `"user"` if only user disabled; else `None`.
  - `link_enabled = eg.enabled` (mirrors the underlying `EffectiveGpo`).
- If the GPO is missing from the estate (dangling link), emit a
  default-`GateSummary` with everything False/empty except `link_enabled`.

**Anti-drift invariant:** `test_gate_summaries_match_effective_scope`
asserts that for the same GPO, every field on `GateSummary` matches the
corresponding field on `effective_scope(estate, gpo_id)`. This is the
WI-029 lesson materialized — if you change one path, the test fails on
the other.

## AC-18: `GateSummary` dataclass shape

`@dataclass(frozen=True)`. Fields:

| Field | Type |
|-------|------|
| `is_security_filtered` | `bool` |
| `apply_trustees` | `tuple[str, ...]` (note: tuple, not list — hashable) |
| `wmi_filter_name` | `str \| None` |
| `wmi_filter_broken` | `bool` |
| `loopback_mode` | `str \| None` |
| `has_ilt` | `bool` |
| `side_disabled` | `str \| None` (`"computer"`, `"user"`, `"both"`, or `None`) |
| `link_enabled` | `bool` |

The fields are all *facts*, not verdicts. A populated
`is_security_filtered` is "this GPO appears filtered," not "this GPO
will not reach any object." Rendering decisions (dim the row, hide it)
belong to the UI layer, not to `GateSummary`.

## AC-19: Determinism and purity

- All functions are pure over their explicit arguments. No I/O, no
  network, no model calls, no `narration`/`web` imports
  (`tests/_arch.py::forbidden_imports_in("topology")`).
- Estate iteration is stable: `estate.gpos`, `estate.soms` order drives
  every iteration. Within a SOM, `som.links` order drives the chain.
- All output sorts are explicit and stable: `(cse, side,
  identity.lower())` for `settings_at_som` and `som_conflicts`;
  `pair[0].path` for `precedence_conflicts`; `link.order` for
  `site_scopes` site links; `sorted(gpo_ids)` for the per-GPO caveat
  loop in `scope_caveats`.
- The only "shared computation cached across rows" is in
  `gate_summaries` (`loopback_map`, `ilt_gpos`), computed once before
  the per-row loop. `scope_caveats` does the same (`loopback_map`,
  `ilt_gpos`). These caches are local to a single function call.
