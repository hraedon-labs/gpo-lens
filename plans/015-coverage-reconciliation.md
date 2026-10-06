# Plan 015 — Coverage reconciliation (accept + name the access limitation)

**Status:** Shipped in v0.4.0; verified 2026-10-06. Evidence: [src/gpo_lens/ingest.py](../src/gpo_lens/ingest.py), [tests/test_coverage.py](../tests/test_coverage.py).

Inventory/error reconciliation populates `Estate.coverage_gaps`, persistence, doctor findings and summary counts. Both sidecars remain optional for older exports; absence is not proof of full collection.

The design below is the historical specification; this status records the verified release scope.
**Author:** Opus 4.8 (from live testing against WORK-DOMAIN.local)
**Strategic role:** Make gpo-lens honest about a limit it cannot engineer away.

## The accepted limitation

A GPO with **Authenticated Users Read fully stripped** (security filtering done
the dangerous/MS16-072 way) is *invisible* to a least-privilege collector
account — not merely unreadable. Verified on a real domain: `LAB-SVC-1`'s own
`Get-ADObject` enumeration of `groupPolicyContainer` returned only the GPOs it
could read; the stripped ones were absent even from the raw GPC enumeration
(removing the ACE removes List, not just Read). If such a GPO is also unlinked,
nothing the collector runs *as that account* can know it exists.

We are **not** going to chase full coverage by iterating and granting explicit
permissions per GPO — that is operationally fragile and silently drifts. We
accept that collection coverage is bounded by the run account's access, document
it, and instead **reconcile** against an authoritative inventory so the gap is
*named*, never silent.

## Detection, layered (honest about each tier)

| Case | Detected by | Status |
|------|-------------|--------|
| GPO visible but report fails | per-GPO `collection-errors.json` | shipped (Plan 014 collector) |
| GPO **linked** but unreadable | gpo-lens `dangling`/`broken-refs` (the gPLink names the GUID) | already works |
| GPO fully stripped **+ unlinked** | **reconciliation** (this plan) | new |

## Design — inventory vs. export reconciliation

Decouple "what exists" (needs privilege, but only a cheap GUID+name list) from
"what we could collect" (least-privilege, frequent):

- **Inventory** (`gpo-inventory.json`): `[{Id, DisplayName}]` of every GPO,
  produced by a privileged enumeration. The collector already enumerates the
  GPC objects for its cross-check — it now **persists** that list. Run the
  collector (or just its enumeration) once as a Domain Admin / read-all account
  to get an *authoritative* inventory; run it routinely as the least-privilege
  account for the actual export.
- **Export**: the normal least-privilege collector output.
- **Reconciliation** (gpo-lens, on ingest): any inventory `Id` absent from the
  ingested GPOs is a **coverage gap** — an inaccessible GPO, named by GUID.
  Combined with the collector's `collection-errors.json` (GPOs that were visible
  but failed to pull), these become first-class `coverage_gap` findings.

The "user account vs domain admin reconciliation" is therefore an operational
workflow, not a privilege the collector demands at every run: produce the
inventory with privilege occasionally; collect with least privilege always;
gpo-lens flags the delta.

## Work items

- **WI-1 — Collector emits `gpo-inventory.json`.** Persist the GPC enumeration
  (`Id` + `DisplayName`) it already performs. Documented: run as a privileged
  account for an authoritative inventory. Backward compatible.
- **WI-2 — gpo-lens model + ingest.** `CoverageGap(gpo_id, display_name, kind,
  detail)` on `Estate.coverage_gaps`. Ingest reads `gpo-inventory.json`
  (reconcile: inventory − ingested → `kind="inaccessible"`) and
  `collection-errors.json` (`kind="collection_error"`). Both optional.
- **WI-3 — Persist via store** (`coverage_gap` table) so DB-backed `doctor`/
  `summary` surface gaps.
- **WI-4 — Surface.** `summary.coverage_gap_count`; `doctor` `coverage_gap`
  category (severity warning) naming each inaccessible/failed GPO.
- **WI-5 — Docs + contract.** README "Limits" (accepted limitation + the
  reconciliation workflow), AGENTS, `docs/spec/json-contract.md` (additive
  `coverage_gap_count` + doctor category — no `schema_version` bump), CHANGELOG.
- **WI-6 — Tests + fixture.** Fixture `gpo-inventory.json` listing one GUID not
  in the estate + a `collection-errors.json` entry; assert both surface as
  coverage gaps; absent files → no gaps (backward compatible).

## Non-goals

- Granting/iterating permissions to force full read (explicitly rejected).
- Resolving *why* a GPO is inaccessible beyond "in inventory, not collected" /
  "collector reported a failure."
