# Plan 009 — SOM Resolution Deep View (Topology Tier 2.5 Complete)

**Status:** Shipped in v0.1.0; verified 2026-10-06. Evidence: [src/gpo_lens/topology.py](../src/gpo_lens/topology.py), [tests/test_topology.py](../tests/test_topology.py).

OU-level settings and precedence annotations are implemented by `settings_at_som`; later scope caveats and the Plan 021 merge model qualify the original last-writer description.

The design below is the historical specification; this status records the verified release scope.

## Context

Plan 007 adds `som_conflicts` — same setting identity across the chain with
different values. That is the first half of Tier 2.5. This plan completes
the topology layer with:
- A full OU-scoped settings catalog
- Inheritance-block and enforced annotation
- The "what applies here" summary for an arbitrary OU path

## Requirements

### R1. `settings_at_som(estate, som_path) -> list[EffectiveSetting]`

Walk the SOM's resolved chain, fold settings in precedence order, and emit the
effective state. For each `(cse, side, identity)`, the **last** GPO in the
chain wins.

`EffectiveSetting` dataclass:
- `cse`, `side`, `identity`, `display_name`, `display_value`
- `winner_gpo_id`, `winner_gpo_name` — the GPO whose value applies
- `overridden_by` — list of `(gpo_name, value)` for earlier GPOs that set
  the same identity
- `enforced` — bool, true if the link that brought this GPO in was enforced

### R2. Annotation for block/enforced

When folding the chain:
- If a SOM has `inheritance_blocked=True`, its `links[]` is the *entire* chain
  (platform already resolved this). The tool just confirms the chain is
  non-empty and notes the block.
- If any link in the ancestor chain is `enforced=True`, later block-inheritance
  does not drop it. Again — the platform already resolved this in the
  `InheritedGpoLinks[]` order.

### R3. CLI wiring

`gpo-lens settings-at <som_path> [src]`

Respects `--json`. Text output is a grouped view by GPO, ordered by precedence.

### R4. Calibration

- Lab domain `dc=lab,dc=example,dc=com` chain: 5 GPOs, all enabled, none enforced.
  Verify with `settings_at_som(...)` that settings fold correctly.
- Work domain: 1,000+ SOMs. Verify performance: must fold the largest
  chain (domain root) without pathological slowdown.

## Why now

This is the core promise of gpo-lens that no other tool provides cleanly:
"Show me, in one view, every setting that applies at OU X and which GPO won."
GPMC has the inheritance tab but won't roll up settings. Policy Analyzer does
value-diffing but has no topology view.

## Technical notes

- Runtime must stay in memory; no index needed (the estate is at most a few
  hundred GPOs, each with a few hundred settings).
- For the lab domain root: 5 GPOs × ~200 settings each = ~1000 settings max.
  Folding is `O(chain_length × settings_per_gpo)` — trivial.
- For the work domain root: 100+ GPOs. Still well within sub-second folding.

## Out of scope

- Loopback simulation (merge/replace modes). We **flag** loopback GPOs but
  do not simulate their effect on the chain. Per charter: "flag, don't simulate."
- Security group filtering (object-level RSoP).
- WMI filter evaluation (we report which GPOs have filters, but don't evaluate).

## Files to touch

- `src/gpo_lens/queries.py`
- `src/gpo_lens/cli.py`
- `tests/test_queries.py`
- `tests/test_calibration.py` (performance + correctness against work domain)

## Acceptance

All tests pass. `ruff` and `mypy` clean. `settings_at_som` runs on the work
domain root chain in < 1 second on a laptop.
