# Plan 019 — Scope-resultant view: per-candidate gate attribution

**Status:** Partially shipped in v0.6.3; verified 2026-10-06. Evidence: [src/gpo_lens/topology.py](../src/gpo_lens/topology.py), [tests/test_topology.py](../tests/test_topology.py).

Phase A per-candidate `GateSummary` and OU gate chips shipped. Phase B user-entered group de-emphasis did not ship; snapshot principal narrowing is instead covered by Plan 021. The live-AD-bind proposal below is outside the product charter.

The design below is the historical specification; this status records the verified release scope.
**Author:** Claude (Opus 4.8), from an RSoP feasibility review
**Strategic role:** People keep asking for "an RSoP view." The honest answer is
that *most* of what they want already exists, the genuinely-hard part (true
per-principal Resultant Set of Policy) is out of charter, and the remaining gap
is small and well-defined. This plan closes that gap **without** crossing into
simulation: it attributes the per-GPO scope *gates* (security filtering, WMI,
loopback, item-level targeting, disabled side) onto each row of the OU's
effective-precedence chain, so a human can reason about *why a given candidate
GPO might not reach a given object* — gates **shown, not evaluated**. It is a
web-layer + light-composition change over analysis the core already computes; no
new collection, no AD bind, no RSoP engine.

## Ground truth at time of writing

The OU-centric resultant view is **already built and shipping**. Plan 019 is a
refinement, not a new surface. Specifically:

- **Precedence is DC-computed, not reverse-engineered.** `gp-inheritance.json`
  is `Get-GPInheritance` per SOM (1552 entries in the work estate), each with
  `InheritedGpoLinks` already ordered and resolved for block-inheritance and
  enforced. `queries.som_effective_gpos` exposes this chain.
- **`ou_detail` (`web/app.py:839`) already renders:** the effective precedence
  chain (`som_effective_gpos`), winning settings (`settings_at_som`,
  `topology.py:397` — each `EffectiveSetting` carries `winner_gpo_*`,
  `overridden_by`, `enforced`), conflicts (`som_conflicts`), and a flat
  caveats block (`scope_caveats`). The template already frames it honestly:
  *"Scope caveats — flagged, not simulated"* (`ou_detail.html:45`).
- **The per-GPO gate analysis already exists** — `topology.effective_scope`
  (`topology.py:674`) composes, for a single GPO: `security_filtering_detail`
  (apply trustees, `has_au_read`/`has_dc_read`, `is_filtered`), `_wmi_filter_scope`
  (attached/broken WMI filter), `loopback_awareness`, and `scan_ilt` (item-level
  targeting), and already emits the right honesty caveats — e.g. *"exclusivity
  not evaluated; default ACEs and group membership not modeled"* and *"per-object
  delivery not evaluated"* for ILT.
- **The gap:** the precedence chain (`ou_detail.html:58-83`) shows each candidate
  GPO with only name / target / enforced / link-off / order. The *gates* live in
  a separate, **OU-aggregated** caveat list. So a reader cannot tell *which*
  inbound GPO is security-filtered to which group, or WMI-gated, or loopback'd.
  To reason "does this GPO reach object O?", the gates must be attributed
  **per candidate row**.
- **Loopback correctness is a hard dependency.** Loopback mode currently parses
  as `'unknown'` for every real-world setting (**WI-028**), so the loopback gate
  cannot state Merge vs Replace — which changes the *user-side* resultant on the
  affected computers. WI-028 must land first or the gate will be misleading.

## Charter addendum (decisions this plan records)

1. **Gates are shown, never evaluated.** We surface that a GPO is filtered to
   group `G` / gated by WMI `W` / user-side disabled / loopback Replace. We do
   **not** decide whether it applies to a principal — that needs group
   membership and WMI truth we do not have (see "True RSoP" below). This is the
   existing "Flag, don't simulate" line, made per-row.
2. **No new data, no AD bind.** Phase A composes analysis already in the core
   over data already ingested. The only new code is attribution + presentation.
3. **Rename away from "RSoP" in the UI.** Call it *scope* / *effective
   precedence* / *gates*. "RSoP" implies per-principal effective truth, which
   this is not; using the term would over-claim (the exact over-claim discipline
   from the sf2 governance work).

## Phase A — Per-candidate gate attribution (MVP)

Turn the existing OU precedence chain into a scope *explainer* by hanging each
GPO's own gates off its row.

### A.1 Core: attribute gates per chain entry

`som_effective_gpos` returns the ordered candidates. For each, compute its gate
summary by reusing the *components* of `effective_scope` (not the whole
function — we want the per-GPO gate facts, not the per-GPO caveat strings):
`security_filtering_detail`, `_wmi_filter_scope`, `loopback_awareness`,
`scan_ilt`, plus the link's `enabled` / the GPO's `computer_enabled`/
`user_enabled`. Expose this as a small typed structure per candidate (e.g.
`GateSummary` with `security_filter_trustees`, `is_filtered`, `wmi_filter`
(name/broken), `loopback_mode`, `has_ilt`, `side_disabled`) attached to each
effective-GPO row — a pure derivation in `topology`/`queries`, no web imports.

### A.2 Web: render gates inline on each chain row

`ou_detail.html` precedence chain (`:58-83`): each `<li>` gains a compact gate
strip beside the existing enforced/link-off chips — e.g. chips for
`filtered → Finance-Admins`, `WMI: Servers-Only`, `loopback: Replace`,
`ILT`, `user side off`. A GPO with no gates shows a quiet "applies to all in
scope" affordance. Keep the aggregated caveats block as the summary; the per-row
strip is the detail. Zero JS, consistent with the existing chip styling.

### A.3 Honesty affordance

Each gate chip links to or tooltips the same non-evaluation caveat the core
already emits (membership/default-ACEs/WMI-truth not modeled). The "flagged, not
simulated" header stays and applies to the per-row gates too.

### A.4 Acceptance criteria

- `AC-1` A security-filtered GPO in the chain shows its explicit Apply-Group-Policy
  trustees on its own row (not only in the aggregate list).
- `AC-2` A WMI-gated GPO shows the filter name on its row; a broken WMI ref is
  marked broken.
- `AC-3` A loopback GPO shows its mode (depends on WI-028; until then the chip
  reads `loopback (mode unknown)` and links to WI-028's caveat — no fabricated
  Merge/Replace).
- `AC-4` A GPO with a disabled user/computer side, or a disabled link, shows that
  on its row.
- `AC-5` A GPO with no gates renders cleanly as unconditional-in-scope.
- `AC-6` No gate is presented as a verdict on whether the GPO applies to a
  principal; every gate carries (or links) the "not evaluated" caveat.
- `AC-7` With no gates anywhere, the chain is visually unchanged from today
  (strict superset).

### A.5 Tests

`tests/test_web.py` + `tests/test_topology.py`: per-gate attribution
(filtered/WMI/loopback/ILT/disabled), the no-gate clean case, and an assertion
that the per-row gate data matches `effective_scope`'s components for the same
GPO (so the two surfaces can't drift — the lesson from the MS16-072 calibration
gap, WI-029). Add a calibration check (`test_calibration.py`) for the count of
gated GPOs in the work estate, cross-checked against GPMC, not the tool.

## Phase B — Declared-input scope narrowing (gated / exploratory)

The closest *honest* approach to "why doesn't this apply to **me**" without an
AD bind: let the user paste the group names a principal belongs to; the view
then **visually de-emphasizes** chain GPOs whose Apply-trustees don't intersect
those names (pure string set-intersection over data already shown). Strictly:

- It operates only on **user-declared** group names, never an AD lookup.
- It is labeled loudly as "based on the groups you entered — not observed
  membership, nested groups, WMI, or loopback."
- It **de-emphasizes**, never hides — the full chain stays, because the input is
  an assumption.

This is the boundary of what's defensible statically. It is gated because it
edges toward simulation in *feel* even though it does no evaluation; pursue only
if Phase A's per-row gates prove insufficient in real use.

## Out of scope — true per-principal RSoP (#3) needs a live-AD-bind refactor

Genuine RSoP ("what does user U on computer C effectively get") is **explicitly
not** this plan, and cannot be bolted onto the current static-export model. It
would be a separate, larger initiative — a **refactor introducing an explicit AD
bind so data can be ingested live** — plus a charter amendment, because it
crosses from reading structure into simulating the Windows client. It requires
inputs the export does not and cannot contain:

- **AD group membership** with transitive/nested expansion, primary group, and
  well-known SIDs, to build a principal's token and evaluate security filtering
  (the Read+Apply predicate fixed for MS16-072 is the *core* of this, but needs
  the principal's full SID set).
- **WMI evaluation** against the target machine's real state (OS build, RAM,
  make/model) — observable only live, or supplied as a declared planning profile.
- **Loopback** resolution against the target computer's OU and a correct mode
  parser (WI-028).
- **Per-CSE merge semantics** (scripts append, GPP merges) — resultant is not
  pure last-writer-wins; faithfully modeling each CSE is the simulation surface
  the charter forbids in the static tool.

If ever pursued, the only honest form is a **planning mode over a live AD bind
(or fully declared inputs)**, labeled a what-if, never a claim about a real
machine. That is a bigger scope than this plan aims at and is recorded here only
to mark the boundary.

## Non-goals

- **Per-principal effective state / true RSoP.** See above — separate initiative,
  needs a live AD bind.
- **Evaluating filters, membership, WMI, or CSE merge.** Phase A shows gates;
  it never decides applicability.
- **Hiding GPOs.** Even Phase B de-emphasizes rather than removes — the chain is
  the audit artifact.
- **New collection.** Everything here is derivation over the current export.

## Sequencing & risk

- **WI-028 (loopback mode) is a prerequisite** for the loopback gate to be
  truthful. It is also a standing correctness hole independent of this plan —
  fix it first. Until then, Phase A ships the loopback gate as an explicit
  "mode unknown" pointer to WI-028, never a fabricated mode.
- **Phase A is small and additive** — a per-candidate derivation reusing
  `effective_scope`'s components, plus a chip strip on an existing template. It
  is a strict superset of today's OU view.
- **Phase B is gated** on Phase A real-use feedback and carries a presentation
  risk (a "narrowed" chain can read as a verdict); the de-emphasize-don't-hide
  rule and loud labeling are what keep it honest.
- **Anti-drift:** the per-row gates and the GPO-detail `effective_scope` view now
  describe the same facts in two places — a test must assert they agree, or they
  will diverge (WI-029 lesson).
