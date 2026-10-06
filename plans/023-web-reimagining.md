# Plan 023 — Web frontend reimagining: question-oriented IA, GPO dossier, finding lifecycle

**Status:** Superseded by Plans 024 and 025; foundations shipped in v1.1.0 and completion scope in v1.3.0; verified 2026-10-06. Evidence: [src/gpo_lens/queries/_settings.py](../src/gpo_lens/queries/_settings.py), [tests/test_ledger.py](../tests/test_ledger.py).

Ledger, dossier/GPO comparison, setting page and snapshot-aware dossier shipped. Plan 024 replaces the original identity/triage model; Plan 025 supplies briefing, inbox, navigation, bounded narration and exports. Broad entity omnisearch, a global snapshot axis (including historical OU selection), attributed events and persisted comparison-to-workbench deep links remain unshipped; the header search is configured-settings search. No mandatory 301 retirement was needed: original handlers remain.

The design below is the historical specification; this status records the verified release scope.
**Author:** Claude (Fable 5), from the 2026-07-11 design conversation
**Strategic role:** gpo-lens is deployed and load-bearing at work, and the web UI
grew page-by-page: today it is ~17 noun-organized templates (inventory, conflicts,
delegation, admx-coverage, baseline, golden, trends, …) grouped under
Estate/Posture/Change/Tools. That shape answers "what artifacts do we have?" — but an
operator in front of a 129-GPO estate has three questions: **what changed?**, **is
anything wrong?**, and **why is this setting what it is, here?** This plan pivots the
presentation from artifact-per-page to question-per-page, adds the two genuinely new
pieces of state that daily use needs (finding identity/lifecycle and local triage
annotations), and builds the single-GPO reading experience GPMC never had. Almost all
the hard computation (normalization, merge, precedence, SDDL, diffs) already exists in
the deterministic core; this is dominantly a presentation-layer program with two small,
additive schema changes.

**Relation to Plan 022:** WI-1–WI-7 there are structural/defect consolidation and stand
alone. Plan 022's style-review leftovers — WI-8 (danger table→cards) and WI-9 (OU
caveat-wall summarization) — are **superseded by this plan** (WI-4/WI-5 replace the
danger list wholesale; WI-2's scope panel subsumes the OU caveat wall). If 022's WI-8/9
haven't started when this plan is approved, mark them absorbed.

## Design constraints (unchanged, restated for the reviewer)

- **Charter:** read-only against AD; flag-don't-simulate; deterministic truth path, LLM
  narrates only. Nothing here touches collectors or ingest semantics.
- **Triage annotations are charter-compatible:** acknowledging a finding records a fact
  about *operator attention* in the local SQLite store, not a change to the estate. The
  tool remains incapable of modifying AD. Annotations must be clearly rendered as local
  workflow state, never as estate facts.
- **Stack:** server-rendered Jinja2 + the shared family design system (`gp-` classes,
  verdigris accent, IBM Plex Mono, dark default). No JS framework; the type-to-filter
  and progressive-disclosure interactions are small dependency-free vanilla JS with
  no-JS fallbacks (full list renders without filter; `<details>` for disclosure).
- **DB:** additive SQLite migrations only (established pattern).
- **Auth/attribution:** ack/annotation writes ride the existing permission model;
  attribute the actor from `GPO_LENS_FORWARDED_USER_HEADER` when configured (names-only,
  as in the audit-attribution work), else the authenticated principal label.
- **Plan 022 WI-1 interaction:** any new route follows whatever sync/threadpool rule
  Plan 022 WI-1 lands; if 022 hasn't landed, new routes are plain `def` (sync) from the
  start.

## Non-goals

- No object-level RSoP, no live AD queries, no write access of any kind to the estate.
- No SPA rewrite; no client-side routing; no new runtime dependencies.
- No changes to CLI/query core semantics (new read queries are fine; changed meanings
  are not).
- Narration (Tier 3) gains no new authority — it moves *down* the hierarchy, not up.

---

## The target information architecture

Nav collapses from four groups / ~13 destinations to four destinations plus search:

| New nav | Answers | Absorbs (current pages) |
|---|---|---|
| **Briefing** (home) | "Do I need to care today?" | dashboard, trends |
| **Findings** | "Is anything wrong?" | danger list, conflicts, delegation, admx-coverage, baseline diff, golden diff |
| **Explore** | "Why is this setting what it is, here?" | inventory, gpo detail, ou list/detail, resultant, search |
| **History** | "What changed?" | changelog, snapshot diffs |
| (Tools menu) | ingest, ask/narration, export | ingest, ask |

Old URLs keep working: every absorbed page's route either renders the new view directly
or 301s to its new home with filters applied (bookmarks at work must not break).

---

## WI-1 — Normalized settings ledger (component + query)

The single highest value-to-effort item. Every setting from every CSE flattened into
uniform rows — side, area/CSE, path/key, name, state/value, targeting summary — rendered
as one instantly-filterable list. The normalization layer that powers merge/conflict
queries already computes this; it has never been rendered as one artifact.

- New query: `settings_ledger(gpo_id, snapshot_id) -> list[LedgerRow]` in the core
  (typed, deterministic, tested against the existing normalized model). Rows carry a
  **stable setting identity** (the same `(cse, identity)` key the merge model uses) so
  the ledger can anchor diffs, cross-links, and the setting page (WI-3).
- Template component (`_ledger.html`) + vanilla-JS type-to-filter (substring across
  path/name/value, `hidden` toggling, row count feedback). No-JS fallback: full list.
- Rows with no ADMX mapping are first-class, marked "no ADMX coverage" — not exiled to
  an "Extra Registry Settings" appendix.
- Per-row progressive disclosure (`<details>`): ADMX explain text / supported-on /
  possible values where the admx catalogue knows them; the **registry truth** (key,
  value name, type, data) always shown alongside the friendly name; GPP item-level
  targeting rendered as an indented boolean expression tree (parser exists in the GPP
  model — rendering is new); the raw evidence fragment (XML snippet / decoded PReg
  record) behind a second disclosure level.
- **AC:** ledger for the largest lab-estate GPO renders in one request and filters
  client-side with no visible lag; a GPO mixing AdminTemplates + Security + GPP shows
  all three in uniform rows; a no-ADMX registry row displays key/value prominently;
  golden-file test pins ledger output for a fixture GPO; works without JS.

## WI-2 — GPO dossier page

Rebuild `gpo_detail.html` as the dossier: one page, four layers.

1. **Verdict strip** (header): sides enabled vs. populated (dead weight flagged),
   linked where / orphaned, security filtering summary, WMI filter, AD↔SYSVOL version
   skew, owner, last-changed snapshot + attributed event when known, open findings
   count (links into WI-4's filtered view).
2. **Settings ledger** (WI-1 component).
3. **Scope & control panel**: "who receives this" — links in precedence order with
   enforced/disabled state, security filtering, WMI — with flag-don't-simulate caveats
   inline; beside it "who can change this" from delegation data.
4. **History tab**: this GPO across snapshots; diff any two of its versions (aligned by
   setting identity from WI-1); event attribution where the changelog has it.

Plus **GPO-vs-GPO diff**: from any dossier, "compare with…" → two ledgers aligned by
setting identity (only-in-A / only-in-B / differing-value). This is the consolidation
workflow for near-duplicate GPOs; it reuses the snapshot-diff alignment machinery.

- **AC:** every fact in the verdict strip is clickable through to its evidence; the
  dossier for a real-estate GPO (via lab export) answers "what does it set, who gets
  it, who can change it, when did it last change" with zero navigation away; version
  diff and GPO-vs-GPO diff each have a fixture-pinned test; existing `/gpo/<id>` URLs
  unchanged.

## WI-3 — Setting-centric page

The cross-cutting query no Microsoft tool answers: `/setting/<identity>` — "who sets
this setting, anywhere?"

- Every GPO configuring the setting, its value there, where each is linked, and —
  reusing the merge model — where they collide and who wins at each collision point
  (OU-level, with the standard caveats).
- Reached from ledger rows ("N other GPOs set this"), from conflicts data, and from
  omnisearch (WI-8) by name or registry path.
- **AC:** for a lab fixture with a deliberate three-GPO collision, the page names all
  three, the winner per linked OU, and the losers with reasons; identity round-trips
  through URLs safely (registry paths contain slashes — use an opaque encoded id, not
  raw path segments).

## WI-4 — Finding identity and lifecycle

Findings (danger rules, conflicts, broken refs, delegation issues, ADMX gaps, version
skew) become durable objects with identity across snapshots, so the tool can say **new
/ persisting / resolved** instead of re-reporting the world every scan.

- Stable finding key: `(rule_id, subject_identity)` where subject identity reuses the
  normalized identities (GPO GUID, setting identity, trustee SID, …). Keys must be
  deterministic and stable across snapshot re-ingest of identical data.
- New additive tables: `finding` (key, first_seen_snapshot, last_seen_snapshot,
  resolved_in_snapshot nullable) maintained at ingest time by diffing the current
  scan against the prior snapshot's findings. Backfill migration derives history for
  existing snapshots where feasible; otherwise findings start their lifecycle at the
  first post-migration ingest (state this honestly in the changelog).
- A finding that reappears after resolution is a **new occurrence linked to its
  predecessor** (regression signal), not a resurrected row.
- **AC:** ingest of two fixture snapshots (one fixes a cpassword, one introduces a
  delegation issue) yields exactly one resolved, one new, N persisting; re-ingesting
  the same export twice creates no duplicate findings; property test: finding keys are
  invariant under export ordering.

## WI-5 — Triage annotations + findings inbox

- New additive table: `finding_triage` (finding key → status
  `open|acknowledged|accepted_risk`, note, actor, timestamp; append-only history, not
  update-in-place — the provenance instinct applies to local state too).
- **Findings page** (replaces danger list/conflicts/delegation/admx-coverage/baseline/
  golden as destinations): one inbox, default filter **new + unacknowledged**, facets
  by category, severity, GPO, lifecycle state, triage state. Accepted-risk items one
  click away, never deleted. Baseline/golden diffs become categories/filters here
  (their computation is untouched).
- Every finding row: evidence disclosure (rule id, source fragment, snapshot observed,
  scope caveat) — receipts inline, in the regulated-workplace spirit.
- Triage writes require the existing ingest-level permission (not view-level);
  loopback principal retains it per the current model.
- **AC:** acknowledging a finding removes it from the default view and records actor +
  note; the accepted-risk register renders as its own filter; a resolved-then-regressed
  finding surfaces as new with a visible link to its accepted predecessor; annotations
  survive re-ingest.

## WI-6 — Briefing home page

Replace the dashboard with a prose-first delta briefing: "Since snapshot N−1 (date):
2 GPOs modified, 1 new finding (cpassword in X), 3 resolved, 1 new orphan" — every noun
a link (respecting the existing `resolvable_gpo_ids` gate). Sections: what changed
(from changelog/snapshot diff), findings delta (from WI-4), estate vitals (the few
numbers that matter; trends absorbed as a small section, page retired). Attributed
actors shown when event attribution has them.

- **AC:** briefing between two fixture snapshots reads correctly as sentences (golden
  test on rendered text); with a single snapshot it degrades gracefully to a "first
  snapshot" summary; no stat tile without a link to its evidence.

## WI-7 — Global snapshot axis

- Every entity page gains an explicit "as of snapshot N" indicator + selector;
  selecting renders the same page at that snapshot (query param, server-rendered).
- Entity history tabs (GPO from WI-2; OU precedence chain across snapshots) hang off
  the same mechanism.
- **AC:** flipping the selector on a GPO dossier and an OU page shows the older state
  with a visible "viewing historical snapshot" banner; links within a historical view
  stay within that snapshot; current-snapshot remains the default everywhere.

## WI-8 — Omnisearch

One search box in the header accepting: GPO name/GUID, OU name/DN fragment, setting
name/registry path, trustee name/SID. Classify (GUID/SID/DN are cheap to detect
syntactically), search the normalized tables, land directly on the entity when
unambiguous, else a grouped results page. Extends the existing `/search` (which
becomes the results renderer).

- **AC:** pasting a GPO GUID lands on its dossier; a registry value name lands on (or
  lists) setting pages; a SID lands on trustee-scoped results; junk input degrades to
  the grouped results page, never a 500.

## WI-9 — IA collapse, redirects, narration demotion

- `base.html` nav → Briefing / Findings / Explore / History + Tools + omnisearch.
- Absorbed routes 301 to their new homes with equivalent filters; a route-inventory
  test asserts every pre-023 URL returns 200-after-redirect.
- `/ask` leaves the nav; narration becomes an "explain this" action on dossier/OU/
  finding views that narrates *the facts already rendered on that page* (same guarded
  prompt path, page context as input). The page is the truth; the LLM is a caption
  writer. `/ask` itself remains reachable under Tools for the exploratory case.
- **AC:** route-inventory test green; nav has exactly the five affordances; "explain
  this" on a dossier produces narration referencing only entities present on the page
  (assert via the existing narration fact-check harness).

## WI-10 — Export everywhere

Every major view (dossier, findings inbox + accepted-risk register, briefing, setting
page, diffs) gets deterministic **Markdown** and **CSV** exports of exactly what the
view shows (current filters applied) — the consumer is a change ticket or an audit
email. Reuses the report/sinks machinery where it fits.

- **AC:** exports are byte-deterministic for a fixed snapshot + filter (golden tests);
  a findings export includes triage state and evidence references; no export path
  invokes narration.

---

## Sequencing and review gates

Order: **WI-1 → WI-2 → WI-4 → WI-5 → WI-6 → WI-7 → WI-3 → WI-8 → WI-9 → WI-10.**
Rationale: the ledger is pure presentation over existing data (lowest risk, immediately
usable at work, and everything else renders through it); the dossier makes the ledger
navigable; the lifecycle pair is the biggest daily-value change and needs the most
review (only schema changes in the plan); the briefing then has deltas to narrate; IA
collapse goes late so old pages keep working until their replacements exist.

Natural checkpoints for the deployed-at-work instance: after WI-2 (dossier usable,
nothing removed), after WI-6 (new home page), after WI-9 (old nav retired). Each
checkpoint ships behind the existing deploy flow to the lab IIS host first, then work —
real-estate exposure has caught what fixtures missed three times in this repo; treat
that as a gate, not a formality.

## Risks

- **Ledger performance on the messy estate** (129 GPOs, some very large): mitigate with
  per-GPO scoping (the ledger is per-dossier, never estate-wide) and the WI-1 AC;
  estate-wide setting queries live only on the setting page, which is per-identity.
- **Finding-key instability** would corrupt lifecycle history: the property test in
  WI-4 is load-bearing; any rule whose subject can't be stably identified stays
  lifecycle-less (rendered "snapshot-scoped") rather than guessing.
- **Backfill honesty:** if lifecycle backfill over old snapshots proves unreliable,
  ship without it and say so; never synthesize first-seen dates.
- **Scope creep toward a SPA:** the interactions are deliberately two vanilla-JS
  behaviors (filter, disclosure). Anything needing more state than that is out of
  scope for this plan.
