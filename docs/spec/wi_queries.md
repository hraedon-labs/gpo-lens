# Work Item: Queries (Tier-1 deterministic analysis)

## Dependencies

- `interface_ref`: `model`

## Notes

Pure functions over an `Estate` (or equivalently a loaded snapshot). No I/O, no
AI. Each returns plain dataclasses/tuples suitable for CLI rendering and, later,
JSON/web. Module: `src/gpo_lens/queries/` (package — `__init__.py` is the
backward-compatible re-export facade; composition logic lives in `_search`,
`_delegation`, `_topology`, `_wmi`, `_settings`, `_baseline`, `_summary`,
`_doctor`).

The calibration numbers in `tests/` (measured from the real exports) are the
acceptance bar — e.g. the work export has 8 disabled-but-populated sides.

---

## AC-01: Unlinked GPOs
`unlinked_gpos(estate) -> list[Gpo]` — GPOs with no `links`. These apply nowhere.

## AC-02: Empty GPOs
`empty_gpos(estate) -> list[Gpo]` — GPOs with no `settings` on either side.
(Define "empty" as zero parsed settings; a GPO with only `<Blocked/>` extensions
and no readable settings counts as empty but is also reported by AC-05.)

## AC-03: Disabled-but-populated
`disabled_but_populated(estate) -> list[tuple[Gpo, Side]]` — each (GPO, side)
where that side's `*_enabled` is False but it has ≥1 setting with
`from_disabled_side=True`. Work export must yield 8 such (GPO, side) pairs.

## AC-04: Who sets X
`who_sets(estate, term: str) -> list[Setting]` — settings whose `display_name`,
`identity`, or `display_value` contains `term` (case-insensitive substring).
Results carry their `gpo_id` so the caller can name the GPO.

## AC-05: Conflict surface
`conflicts(estate) -> list[Conflict]` where `Conflict` groups settings sharing
`(cse, side, identity)` across **two or more distinct GPOs** with **two or more
distinct `display_value`s**. Each `Conflict` lists the contributing
`(gpo_id, display_value)` pairs. This is the cross-estate conflict surface; it
makes no precedence/winner claim (that needs the topology layer, Tier 2.5).
Strongest for structured CSEs (`Security`); best-effort elsewhere, consistent
with the identity rules in `wi_ingest` AC-06.

## AC-06: Blocked extensions (hygiene)
`blocked_extensions(estate) -> list[tuple[Gpo, Side, str]]` — (GPO, side, cse)
where an extension was `<Blocked/>` / unreadable. Surfaces report-generation gaps
rather than asserting the GPO is empty.

## AC-07: Version skew
`version_skew(estate) -> list[tuple[Gpo, Side]]` — GPOs where the GPC (AD) and
GPT (SYSVOL) version numbers differ for at least one side. Comparison uses the
`computer_version_skew` / `user_version_skew` properties on `Gpo`.

## AC-08: MS16-072 vulnerable
`ms16_072_vulnerable(estate) -> list[Gpo]` — GPOs missing `Read` permission for
Authenticated Users or Domain Computers in their delegation entries. Checked by
trustee name (case-insensitive) or SID (`S-1-5-11` for AU, `*-515` for DC).
Only `allowed=True` entries count.

## AC-09: Permissions audit
`permissions_audit(estate) -> list[tuple[Gpo, str]]` — audit delegation for
common security issues: no AU/DC read (MS16-072), too many write principals
(threshold: 3), or orphan GPOs with no delegation entries.

## AC-10: cpassword scan (MS14-025)
`cpassword_scan(estate) -> list[CpasswordHit]` — scans SYSVOL GPP Preference XML
for lingering `cpassword` attributes (attribute name matched in any casing and
namespace; a `<cpassword>` element's text also counts). Each `CpasswordHit`
records the GPO, file, tag, and cpassword value, read from the SYSVOL file at
scan time; the value is never persisted. The persisted finding's detail is the
fixed `redaction.CPASSWORD_FINDING_DETAIL`, and `mask_cpassword` returns `****`
with no characters of the value. Uses the unified GPP XML walker
(`_walk_gpp_xml`) with `only_known=True` to scan only well-known GPP file names.

## AC-11: Full-text search
`search(estate, term: str, scope: str = "all") -> list[SearchResult]` — search
across GPO names, settings, and delegation entries. `scope` filters to
`"names"`, `"settings"`, `"delegation"`, or `"all"`. Case-insensitive substring.

## AC-12: Estate summary
`estate_summary(estate) -> EstateSummary` — one-command health overview combining
counts from all other queries: unlinked, empty, disabled-but-populated, conflicts,
blocked extensions, version skew, MS16-072, cpassword, loopback, WMI-filtered,
enforced links, dangling links, broken refs, ADMX gaps, plus totals.

## AC-13: Snapshot diff
`snapshot_diff(conn, snap_a: int, snap_b: int) -> SnapshotDiff` — compute the
structured diff between two stored snapshots. Reports GPOs added/removed,
settings/links/delegation/version-skew changes, metadata field changes,
WMI filter changes, and enabled-state flips.

---

## Tier 2.5 — Topology / SOM-aware queries

### AC-20: SOM effective GPOs
`som_effective_gpos(estate, som_path: str) -> list[EffectiveGpo]` — the resolved,
ordered GPO chain at a given SOM path (case-insensitive match). Reads the
platform-computed chain from the GPInheritance dump; no object-level simulation.

### AC-21: Dangling links
`dangling_links(estate) -> list[tuple[Som, SomLink]]` — SOM links that point to
GPO ids not present in the estate.

### AC-22: Enforced links
`enforced_links(estate) -> list[tuple[Som, SomLink]]` — all enforced
(NoOverride) links across the estate.

### AC-23: SOM conflicts
`som_conflicts(estate, som_path: str) -> list[SomConflict]` — settings that
appear in the resolved SOM chain with differing values across two or more enabled
GPOs. The later (higher `order`) GPO wins platform precedence, annotated as
`winner`. Disabled links are excluded.

### AC-24: Estate-wide precedence conflicts
`precedence_conflicts(estate) -> list[tuple[Som, list[SomConflict]]]` — runs
`som_conflicts` for every SOM that has links, returning those with hits.

### AC-25: Settings at SOM (deep view)
`settings_at_som(estate, som_path: str) -> list[EffectiveSetting]` — the folded
state of all settings that apply at a SOM path. One `EffectiveSetting` per unique
identity, annotated with the winner GPO, its value, and any overridden values.
Sorted by (cse, side, identity).

---

## Feature-flag queries

### AC-30: Loopback GPOs
`loopback_gpos(estate) -> list[tuple[Gpo, Setting]]` — GPOs that configure
Group Policy loopback processing mode, detected by identity or value containing
"loopback".

### AC-31: WMI-filtered GPOs
`wmi_filtered_gpos(estate) -> list[Gpo]` — GPOs that have a WMI filter attached
(`wmi_filter is not None`).

---

## Security / hygiene (GPP XML scanning)

### AC-40: Broken references
`broken_refs(estate) -> list[BrokenRef]` — scan settings and SYSVOL GPP XML for
broken-reference patterns. Detection-only (no reachability probe). Flags:
- UNC paths in setting display values and raw dicts
- Script files referenced in settings that don't exist in SYSVOL
- Drive mapping UNC patterns
- Scheduled task executable paths (local, non-env-var)
- GPP XML file/path/service references (Drive, File, Service, DataSource, etc.)

Uses the unified GPP XML walker (`_walk_gpp_xml`) with `only_known=False` to scan
all XML files under Preferences. Deduplicates by (gpo_id, ref_value).

### AC-41: ADMX gap detection
`admx_gaps(estate) -> list[AdmxGap]` — Registry CSE settings where no ADMX
policy name was resolved (identity is a raw registry key path). Heuristic: checks
for common hive abbreviations and well-known subkey stems. Skips blocked extensions.

---

## OU-tree / inheritance cross-check

### AC-50: Topology crosscheck
`topology_crosscheck(estate) -> list[TopologyDiscrepancy]` — cross-check
`ou_tree` against the platform-resolved `soms`. Detects:
- `block_mismatch` — OU has `gPOptions=1` but SOM doesn't show inheritance blocked
  (or vice versa).
- `ou_missing_from_soms` — OU in `ou_tree` not found in `soms` (collector gap).
