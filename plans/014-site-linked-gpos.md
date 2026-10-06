# Plan 014 — Site-linked GPO support

**Status:** Shipped in v0.4.0; verified 2026-10-06. Evidence: [src/gpo_lens/ingest.py](../src/gpo_lens/ingest.py), [tests/test_sites.py](../tests/test_sites.py).

Site SOM ingest, links, persistence and OU caveats are implemented. `scripts/Export-GpoEstate.ps1` exports `sites.json`; per-machine site membership remains unresolved.

The design below is the historical specification; this status records the verified release scope.
**Author:** Opus 4.8 (post-v0.3.0 feature-completeness review)
**Strategic role:** Close the one remaining *in-charter* feature gap. gpo-lens
models Domain and OU scopes-of-management but is entirely blind to AD **site**
links — the third GPO scoping axis. This makes `settings-at`, `som-conflicts`,
and `precedence-conflicts` silently incomplete for any estate that links GPOs
at the site level (multi-subnet / branch-office / DR shops). This plan adds
site **visibility** while staying true to "flag, don't simulate": we capture
site→GPO links and warn that site scoping is machine-dependent, without
pretending to resolve which computers land in which site.

## Ground truth at time of writing

- v0.3.0 released (tagged, merged to `main`). 675 tests pass, ruff + mypy
  --strict clean. JSON output contract frozen at `schema_version: 1`.
- `grep -ri site src/` returns **nothing** — sites are absent from the model,
  ingest, collector, and every query.
- README "Limits" documents this explicitly as additive/deferred:
  *"The collector exports OU/domain inheritance only. Sites are a real GPO
  scoping mechanism but are not captured."*

## Background — why sites are different

GPO processing order is **Site → Domain → OU**. Site-linked GPOs are applied
*first*, which means they have the **lowest precedence** (later-applied
domain/OU GPOs win on conflict, unless the site link is **enforced**).

Two facts make sites a distinct problem, not a fourth column on the OU tree:

1. **Sites are not in the OU hierarchy.** A site object lives in the
   Configuration partition (`CN=Sites,CN=Configuration,…`), not under the
   domain DN. It is a *parallel* scoping container, not an ancestor of any OU.
2. **Site membership is machine-dependent.** A computer's site is decided at
   runtime by its IP → subnet → site association. gpo-lens is OU-level and
   machine-agnostic, so it **cannot** know which site a given OU's computers
   are in. Resolving that is RSoP-simulator territory (a parked complement).

The charter answer is therefore: **collect and surface site links; flag that
per-machine site application is unresolved.** This mirrors the existing
loopback / WMI / security-filtering caveat pattern exactly.

## Modeling decision

Model each site as a `Som` with `container_type="site"`, carrying its **direct**
gPLink GPOs as `SomLink`s. This reuses the existing SOM storage, link parsing,
and `sites`-style listing with no new top-level model type.

**Why this is safe (verified against the code):** OU views resolve a single SOM
by *exact path* (`_find_som` / `_resolve_som_chain`, `topology.py:192`) and use
that SOM's pre-resolved inheritance chain (from `Get-GPInheritance`, which never
includes site GPOs). A site SOM has its own Configuration-partition path and is
only ever matched by the dedicated `sites` query — it cannot leak into an OU's
chain. The OU-view impact is limited to an additive **caveat**, by design.

Scope boundary (v1, explicit non-goals — flag, don't simulate):
- No subnet → site mapping, no computer → site resolution.
- `settings-at <ou>` does **not** merge site GPOs into the OU chain (we can't
  know the site); it raises a caveat instead.

## Work items

### WI-1 — Collector: export `sites.json` (read-only)
- Extend `scripts/Export-GpoEstate.ps1` to query the Configuration partition for
  site objects and their links: `Get-ADObject -SearchBase
  "CN=Sites,$configNC" -LDAPFilter "(objectClass=site)" -Properties
  gPLink,gPOptions` (config NC from RootDSE `configurationNamingContext`).
  ADSI fallback if the AD module is unavailable, consistent with the existing
  collector style.
- Emit `sites.json`: `[{name, dn, gpLink (raw), gpOptions}]` — same raw shape
  the OU exporter already produces (`ou-tree.json`), so ingest reuses the
  gPLink parser. Optionally also emit the site→subnet list as informational
  context (deferred if it complicates the read).
- Read-only; least-privilege (authenticated read of Configuration NC).
- **AC:** collector produces `sites.json`; absence of sites yields `[]`, not an
  error. (Manual/VM verification — not unit-testable here.)

### WI-2 — Synthetic fixture: add sites
- Add `tests/fixtures/sites.json` with two sites: one with no links, one with an
  **enforced** GPO link to an existing fixture GPO (to exercise the precedence
  note). Keep `build_fixture.py` as the source of truth if it generates the dir.
- **AC:** fixture round-trips through ingest; no real-domain identifiers.

### WI-3 — Model + ingest + store
- Parse `sites.json` into `Som(container_type="site", …)` records with their
  direct `SomLink`s, reusing the existing gPLink parser. **Backward compatible:**
  a missing `sites.json` (older exports) yields zero site SOMs and changes
  nothing.
- Persist + reload via `store.py` (site SOMs are ordinary `som`/`som_link`
  rows distinguished by `container_type`).
- **AC:** ingesting the fixture yields the expected site SOMs; an export without
  `sites.json` ingests unchanged.

### WI-4 — Queries: `site_links(estate)`
- `site_links(estate) -> list[...]` returning sites with their resolved GPO
  links (name, enabled, enforced, order). Pure, in `topology.py`.
- **AC:** returns the fixture's linked site; empty when no site SOMs.

### WI-5 — CLI: `gpo-lens sites`
- New subcommand listing sites and their GPO links (text + `--json`). The
  `--json` envelope `kind: "sites"` is **additive** to the frozen contract —
  no `schema_version` bump (new command, new shape).
- **AC:** `sites` renders the fixture; `--json` emits a valid envelope;
  golden contract test extended with the `sites` shape.

### WI-6 — Caveat in OU views
- When the estate has any site SOM with an enabled link, `scope_caveats` /
  `settings_at_som` append:
  *"N AD site(s) carry GPO links, applied before domain/OU based on the
  client's site (not resolved here); see `gpo-lens sites`."*
- Optional info-severity `doctor` visibility line (low priority).
- **AC:** fixture-with-site produces the caveat in `settings-at`; estates with
  no site links render unchanged (empty caveat list).

### WI-7 — Docs
- README: soften the "Limits" entry (sites are now *captured and flagged*, with
  per-machine resolution still a non-goal); add `sites` to the command table.
- `docs/spec/json-contract.md`: document the `sites` payload shape.
- AGENTS.md module map; CHANGELOG entry.
- **AC:** docs match behavior; json-contract lists `sites`.

## Sequencing

| Step | What | Testable here |
|------|------|---------------|
| 1 | WI-2 fixture + WI-3 model/ingest/store | yes |
| 2 | WI-4 query + WI-5 `sites` CLI + contract test | yes |
| 3 | WI-6 caveat + tests | yes |
| 4 | WI-7 docs | yes |
| 5 | WI-1 collector | VM/manual only |

Lead with the testable core (steps 1–4) against the fixture; the PowerShell
collector (WI-1) is written but verified separately on the Windows test VM,
since it needs live AD.

## Release framing

| Release | Headline | Contents |
|---------|----------|----------|
| v0.4.0 | Sees site scope | This plan (site visibility + caveat) |
