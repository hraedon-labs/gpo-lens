# Plan 007 — Tier 2.5 Topology & Hygiene Queries

**Status:** Shipped in v0.1.0; verified 2026-10-06. Evidence: [src/gpo_lens/topology.py](../src/gpo_lens/topology.py), [tests/test_topology.py](../tests/test_topology.py).

SOM conflicts, precedence conflicts and offline broken-reference scans are implemented; the current topology model preserves the collector-resolved chain, including blocked inheritance.

The design below is the historical specification; this status records the verified release scope.

## Context

Tier 1 is complete (ingest, store, core queries, CLI). Prior session landing added:
- `som_effective_gpos` — resolved chain at an OU
- `dangling_links` — SOM links to missing GPOs
- `enforced_links` — all NoOverride links
- `loopback_gpos` — loopback processing detection
- `wmi_filtered_gpos` — WMI-filtered GPOs

These are single-property lookups. The next natural step is **chain-aware** queries: given the platform-resolved precedence order already in `gp-inheritance.json`, find settings that appear more than once in the same chain with different values. This is the core value prop gpo-lens was built for — the thing GPMC won't show in one view.

## Requirements

### R1. Precedence-conflict at an SOM

`queries.som_conflicts(estate, som_path) -> list[SomConflict]`

For a given SOM, walk its `links[]` in `order`. For each `(cse, side, identity)` that appears in **two or more distinct GPOs** in that chain with **two or more distinct `display_value`s**, emit a `SomConflict`:
- SOM path, GPO names in order, setting identity, values per GPO
- The later (higher `order`) GPO wins precedence — annotate that
- Filter out disabled links
- If `inheritance_blocked` is true at that SOM, the chain is empty (nothing applies)

AC:
- Zero SOMs with conflicts in the lab domain (clean).
- Non-empty result on the work domain if any real precedence conflict exists.

### R2. Estate-wide precedence-conflict summary

`queries.precedence_conflicts(estate) -> list[tuple[Som, list[SomConflict]]]`

Run `som_conflicts` for every SOM that has links, return those with hits.
This is the "where are settings fighting in the inheritance chain" view.

### R3. Broken-reference inventory (SYSVOL scan)

Scan `Setting.raw` for common broken-reference patterns:
- UNC paths (`\\server\share`) in GPP files/settings
- Dead registry references (HKLM keys that refer to `%%SYSTEMROOT%%` — normal, but
  flagged if the path doesn't exist in SYSVOL)
- Scripts referencing non-existent files in the GPO's `sysvol_path`

`queries.broken_refs(estate) -> list[BrokenRef]`

Dataclass: `gpo_id`, `gpo_name`, `ref_type` ("unc_path", "missing_file"),
`ref_value`, `detail`.

This stops at **detection** — no reachability probe (avops will want to run this
air-gapped). Flag only; don't HTTP/DFS to verify.

### R4. CLI wiring + `--json`

Each new query gets:
- `gpo-lens som-conflicts <som_path> [src]`
- `gpo-lens precedence-conflicts [src]`
- `gpo-lens broken-refs [src]`

All accept `[src]` (sample dir) or read `--db`. All respect `--json`.

### R5. Calibration tests

Work domain has loopback (31 raw hits) and enforced links. Add calibrations:
- `test_work_loopback_count` — 30+ GPOs flagged by `loopback_gpo` (already passing)
- `test_work_enforced_count` — number of enforced links across SOMs
- `test_work_no_dangling` — no links to missing GPOs (clean domain)

## Why now

- The data model already carries everything needed (`Som.links[]`, `Gpo.settings[]`)
- No new ingest paths or collector changes
- `gp-inheritance.json` is already resolved by the platform — we only read, never simulate
- The user specifically asked for "what would make this system more useful"; this is the unique defensible feature none of the existing tools provide in one deterministic view

## Out of scope (later plans)

- Object-level RSoP simulation (per user, per security group)
- Reaching out to verify UNC paths are alive
- Baseline diff (Tier 2) — needs a baseline mapping file as an input artifact

## Files to touch

- `src/gpo_lens/queries.py` (new functions)
- `src/gpo_lens/cli.py` (subcommands)
- `tests/test_queries.py` (unit tests)
- `tests/test_cli.py` (integration tests)
- `tests/test_calibration.py` (calibration numbers)

## Acceptance

All tests pass. Sample calibration tests pass against real exports. `ruff` and `mypy` clean.
