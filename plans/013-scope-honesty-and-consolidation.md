# Plan 013 — Scope Honesty, Consolidation, and Decomposition

**Status:** Shipped in v0.3.0; verified 2026-10-06. Evidence: [src/gpo_lens/topology.py](../src/gpo_lens/topology.py), [tests/test_scope_honesty.py](../tests/test_scope_honesty.py).

Scope, WMI, ILT and stale-GPO caveats shipped; `topology.py` and the `queries/` package supply the decomposition. The historical site-collection ceiling below was superseded by Plan 014 (v0.4.0); the original module-size targets are not current architecture requirements.

The design below is the historical specification; this status records the verified release scope.
**Author:** GLM 5.2 (session consolidation of user-selected improvements)
**Strategic role:** This plan implements the user's selected improvements from the
portfolio review: scope honesty (Plan 011 Workstream S), queries.py decomposition,
and documents the architectural ceilings. It consolidates work already landed this
session (narration gaps, security hardening, fixture extensions) and sequences the
remaining scope-honesty implementation.

## Ground truth at time of writing

- 619 tests pass, ruff clean, mypy --strict clean.
- **Already landed this session (Wave 1 + fixes):**
  - Narration gaps (N.1 dispatch-driven prompt, N.2 explain-setting, injection
    hardening, baseline_diff in dispatch). Reviewed + fixed.
  - Security hardening (WI-005 CSRF tests, WI-006 streaming decompression).
    Reviewed + fixed.
  - Fixture generator extended with 4 new GPOs (security-filtered, WMI broken-ref,
    GPP ILT, stale) + orphaned WMI filter + ILT SYSVOL XML. Round-trip verified.
- **Deferred (user decision):** Distribution/PyPI (item 2) — wait until closer to v1.
- **Moved to complements:** Real-time 5136 bridge (item 7) → complement #1
  (AD change-monitor daemon).

## Architectural ceilings (safe subset of item 6)

### Documented as non-goals
1. **Single-domain Estate model.** `Estate` holds one domain's GPOs, SOMs, WMI
   filters. Multi-domain/forest estates are not supported and extending the model
   would compromise the single-snapshot ingestion contract. Documented in README
   "Limits" section.
2. **Site-level GPO links.** The collector (`Export-GpoEstate.ps1`) exports
   OU/domain inheritance only. Sites are a real GPO scoping mechanism but
   extending the collector is additive (not charter-breaking) and deferred until
   a real estate needs it.

### Moved to complement project
3. **Cross-estate diffing** → complement #6 (`/projects/maybe-projects/cross-estate-diff.md`).
   Comparing two different estates requires identity matching across domains — a
   different problem space that doesn't belong in gpo-lens's single-estate model.

---

## Workstream S — Scope honesty (v0.3.0)

The charter's "flag, don't simulate" already governs loopback. Four more scoping
mechanisms can silently make `settings-at` / conflict views wrong. This workstream
makes the tool honest about **who actually receives a GPO** — the question every
other view implicitly assumes away.

### Design principle: caveat banners

All scope-honesty features use the same pattern as the existing loopback banner:
1. A pure detection function identifies the scoping mechanism.
2. Topology views (`settings_at_som`, `som_conflicts`, `precedence_conflicts`)
   check whether any GPO in scope triggers a caveat.
3. If so, the view returns a `caveats: list[str]` field (or the CLI prints a banner).
4. The caveat says what mechanism is active and that per-object delivery was not
   evaluated. **Flag, don't simulate.**

### WI-S.1 — Effective-scope view (`gpo-lens scope <gpo>`)

One answer composing what the model already holds.

```python
@dataclass(frozen=True)
class EffectiveScope:
    gpo_id: str
    gpo_name: str
    domain: str
    computer_enabled: bool
    user_enabled: bool
    links: list[GpoLink]  # where linked + enabled/enforced
    security_filtering: SecurityFiltering
    wmi_filter: WmiFilterScope | None  # name + query text if attached
    loopback_mode: str | None  # "merge"/"replace"/"unknown"/None
    caveats: list[str]  # "security-filtered", "wmi-filtered", etc.


@dataclass(frozen=True)
class SecurityFiltering:
    is_filtered: bool  # True if NOT applied to AU/DC
    apply_trustees: list[str]  # who has "Apply Group Policy"
    has_au_read: bool  # Authenticated Users Read (MS16-072)
    has_dc_read: bool  # Domain Computers Read
```

- `effective_scope(estate, gpo_id) -> EffectiveScope | None`
- CLI: `gpo-lens scope <gpo-name-or-id>` — one screen
- `--json` shape documented in `wi_queries.md`
- **AC:** fixture security-filtered GPO (GUID_K) renders `is_filtered=True`;
  normal GPOs render `is_filtered=False`.

### WI-S.2 — Security-filtering caveat in topology views

When a GPO in `settings_at_som` / `som_conflicts` scope is security-filtered
(NOT applied to Authenticated Users / Domain Computers), add a caveat banner.
Without this, the conflict surface claims a winner that filtered-out principals
never receive.

- Add `_security_filtering_caveats(estate, gpo_ids_in_scope) -> list[str]`
- Modify `settings_at_som` and `som_conflicts` to check and append caveats.
- **AC:** fixture with security-filtered GPO in root scope produces the caveat;
  unfiltered estates render unchanged (empty caveats list).

### WI-S.3 — WMI filter analysis

Filters are ingested but only displayed. Add:
- `orphaned_wmi_filters(estate) -> list[WmiFilter]` — defined, referenced by zero GPOs.
- `broken_wmi_refs(estate) -> list[BrokenWmiRef]` — GPOs referencing a filter absent
  from `wmi-filters.json`.
- WMI caveat in topology views (same pattern as S.2).
- New `doctor` categories for orphaned + broken-ref.
- **AC:** fixture covers orphaned (Orphaned WMI Filter) + broken-ref (GUID_L);
  doctor flags both.

### WI-S.4 — GPP item-level targeting flag

GPP settings can carry `<Filters>` (item-level targeting) that gates them
per-object — invisible in every current view.

- Detection in `detection.py`: scan SYSVOL GPP XML for `<Filters>` child elements
  via `_walk_gpp_xml`. Return `IltHit(gpo_id, file, filter_type)`.
- `has_ilt(estate) -> list[IltHit]` query function.
- ILT caveat in topology views.
- `doctor` category for GPOs with ILT.
- **AC:** fixture GUID_M (with ILT SYSVOL XML) is flagged; non-ILT GPOs unchanged.

### WI-S.5 — Stale-GPO doctor check

Modified-over-N-years (default 2, configurable) **and** still linked.

- `stale_gpos(estate, threshold_years: int = 2) -> list[tuple[Gpo, int]]` —
  returns (GPO, years_since_modification) for linked GPOs older than threshold.
- New `doctor` category (`stale_gpo`, severity `info`).
- **AC:** fixture GUID_N (modified 2022-01-01, linked) is flagged; recent GPOs
  are not.

### WI-S.6 — Document limits

README "Limits" section + AGENTS.md update:
- Single-domain Estate model (non-goal).
- Site-level GPO links (collector limit, extendable).
- Per-user/object RSoP simulation (charter-declined; complement #2).

---

## Workstream Q — queries.py decomposition

`queries.py` is 1,569 lines and growing. Extract topology queries into
`topology.py`. Do this after S items land (reduces merge risk).

### Extraction plan
- **`topology.py`** — `som_effective_gpos`, `dangling_links`, `enforced_links`,
  `som_conflicts`, `precedence_conflicts`, `settings_at_som`, `loopback_gpos`,
  `loopback_awareness`, and all helper functions they depend on.
- **`queries.py`** — keeps estate summary, simple hygiene queries, doctor, diff,
  baseline, delegation.
- Import `topology` from `queries` (or have CLI import both directly).
- Update `query_dispatch.py` imports.
- Update architecture test module list.
- **AC:** all existing tests pass unchanged; `queries.py` < 800 lines;
  `topology.py` < 800 lines.

---

## Sequencing

| Step | What | Who |
|------|------|-----|
| 1 | Plan 013 + ceilings docs (S.6) | done |
| 2 | Fixtures for S workstream | done |
| 3 | S.1 effective_scope + CLI | this session |
| 4 | S.2-S.5 implementation | this session |
| 5 | queries.py decomposition (Q) | this session, after S |
| 6 | Adversarial review of S + Q | reviewer agents |

## Release framing

| Release | Headline | Contents |
|---------|----------|----------|
| v0.3.0 | Honest about scope | Workstream S + Q decomposition |
