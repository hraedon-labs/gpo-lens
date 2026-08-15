<!-- VENDORED FROM patina 0.5.0 (e7024c1) -- patina-owned. Do not edit, reformat or lint this file; edit patina and re-run sync.sh. -->
# patina page archetypes (structure tier 2)

`patterns.md` covers component shapes. This document covers whole pages — how
a tool's screens are laid out — in two tiers with different rules. **Where the
two meet:** when a page-level rule constrains a component's shape, the normative
statement lives *here* and `patterns.md` carries the implementation with a
pointer back. The live case is the topbar — "One persistent page grid" below
says its contents sit on the page's centered container; `patterns.md` §2 shows
the markup that does it.

**The criterion (revised 2026-08-14 after blind review):** a page's structure
arises from the domain's operational questions, not from a generic archetype —
**and not from avoiding one.** Common is not wrong; *unconsidered* is wrong.
The first draft of this file banned the four-stat dashboard hero because it is
the dominant AI-training-data dashboard shape; a blind review (an evaluator
judging rendered mockups without the rationale) preferred it, and the review
identified the reasoning error: "common → LLM prior → AI fingerprint →
credibility problem → avoid" only establishes the first two links. The
recognizable-skeleton worry has a real kernel — a generic skeleton filled with
generic content reads as machine output and gets discounted — but the fix is
**semantic specificity** (thresholds from the domain, counts that are scopes,
urgency-ordered lists), not skeleton avoidance.

**The rule-test (from the same review):** every archetype rule below must name
the actual failure it prevents or the operator decision it improves. A rule
that can't is design-system gardening and doesn't belong here.

## Deriving a page (do this before picking an archetype)

The method (ratified 2026-08-14; it derives pages instead of imitating or
avoiding them):

1. **Write the operator questions first** — the questions this page must
   answer, in decision order. For a monitoring landing page they are
   usually: are any *known* objects bad now? which *known* objects need
   attention soon? **is my coverage complete enough to trust those two
   answers?** is a concentration of future work coming? what do I deal with
   first? is the data current? The coverage question is easy to omit and
   omitting it is an *epistemic* failure: the page confidently reports the
   state of what it knows without making the boundary of that knowledge
   visible. Keep the question list honest about scope, too — "is the estate's
   security quality good?" is usually a *different page's* question; answer
   it with a quiet cross-reference, not a duplicated metric.
2. **Identify the minimum decision-complete information** that answers them.
   Not "minimal" — a page can contain very little and still be bad because it
   forces the operator elsewhere for the obvious next question. The target is
   the smallest set that lets someone correctly understand the state and
   decide whether to act.
3. **Design the interaction model before the representation.** There are
   three layers, not two (added 2026-08-14 after WI-3, where skipping the
   middle one produced a wrong critique): *information* ("Expired = 3") →
   *interaction* ("select all expired certificates") → *representation* (a
   large segmented cell reading EXPIRED / 3). What looks like a decorative
   stat card at the representation layer may be a well-designed control at
   the interaction layer — judge the middle layer first. Corollary rule:
   **summary values may receive prominent, persistent treatment when the
   summary itself is an interaction with the primary object set; prefer
   integrated scopes over decorative metric cards.**
4. **Choose the simplest representation for each piece.** "12 expiring
   within 30 days" is first-order; whether it renders as a segmented cell, a
   compact status band, a chip, a sentence, or a histogram annotation is
   second-order. Provenance ("last scan 06:00") is decision-relevant but
   rarely a decision variable — present and quiet. For *persistent
   visibility* the test is not "does this change slowly?" (slow-moving
   information can deserve permanent visibility) but: **what bad decision
   becomes materially more likely when this information is one click away?**
   "I may conclude everything is healthy when I simply don't know" (a
   coverage gap) is a strong answer; "I may notice a busy month one click
   later" is a weak one.
5. **Reach for an archetype below as a pattern, not a starting assumption.**
   If the derivation converges on a conventional layout, ship the convention —
   convention is often many people independently finding the good solution.
   On another family tool the decision-complete minimum might genuinely be
   just a table; on cert-watch it isn't, because aggregate state has
   operational meaning independent of any single certificate.

**One persistent page grid (added 2026-08-14, from the WI-3 prototype
review):** a page keeps a stable set of horizontal edges from top to bottom;
subdivisions happen *inside* components, not by changing the page's columns.
A column that exists for one row only (e.g. a side rail beside a single
band) makes a mathematically centered page *feel* off-center — the eye never
gets a stable vertical axis, and full-width elements above/below read as
shoved aside. Facts that would create a one-row column belong in an existing
region instead (the page-header baseline is usually free real estate).

**The chrome is part of that grid.** The topbar's surface and border run
full-width, but its *contents* — wordmark, nav, actions — sit on the same
centered max-width container as the page body. Chrome pinned to the viewport
edge while content is centered creates two competing left edges, and the whole
page reads as indented even though it is mathematically centered. Implementation
in `patterns.md` §2 (which also carries the topbar's own density rule: ~46–48px,
quiet selected tab).

**The element-rejection test:** for any proposed addition (issuer pie chart,
scan success %, average lifetime, added-this-month…) the question is never
"is this interesting" or "do dashboards traditionally have it" — it is *what
operator question does this answer on this page?* No good answer, no
placement.

## Tier 1 — the frame and the invisible shapes: standardize aggressively

Two groups, one rule. Between them they account for every `patterns.md` section
except §6, which is Tier 2. (Before 2026-08-15 this taxonomy silently skipped
§§1, 2, 3 and 5 — including §2, which carries a normative rule.)

**The frame — `patterns.md` §1 (app shell), §2 (topbar + navigation).** Every
family tool wears the same chrome. There is no per-tool differentiation to
protect here beyond the accent, and a shell that varies per tool is the fastest
way for the family to stop reading as one product line. Standardize verbatim.
The topbar's *page-level* constraint is stated above ("One persistent page
grid"), not in the catalog.

**The invisible shapes — `patterns.md` §3 (buttons), §4 (inputs), §5 (panel),
§§7–14 (pill, chip, table, empty state, callout, drop zone, breadcrumb,
chain).** These carry no authorship signal — nobody clocks a table or a submit
button as machine-made. Use the canonical shapes everywhere, without variation
for variation's sake. Coherence here is pure win.

## Tier 2 — page archetypes: deliberate grammar, named failure modes

Every page names its archetype (in its surface brief — see
`content-model.md`). Each archetype below states the family layout and its
**banned failure mode**, with the *why* in-file — an unexplained rule gets
optimized away by the next agent session that finds the failure mode more
natural. If a page genuinely needs a different structure, amend this file in
the same PR; never override locally.

### Banned failure modes that apply to every archetype

Carried in 2026-08-15 from Plan 007's "banned defaults to name in v1". They were
proposed there, never written into this file, and never explicitly dropped —
so until now they were neither in force nor withdrawn. Each is stated here with
the rule-test answer it has to pass. (The fourth item on that list, the
4-stat-card hero, was **retracted** by Plan 007's own blind review and is *not*
banned — see the Dashboard entry, where a segmented version of that shape is the
ratified grammar.)

- **Hero → three feature cards, on any page.** *Why:* it is marketing grammar —
  a landing page persuading a visitor to adopt a product — applied to a tool the
  operator has already chosen and opened. The three cards are always equal
  weight and usually non-actionable, so the first viewport, the page's strongest
  position, spends itself on navigation-as-decoration. The failure it prevents:
  an operator who opened the tool to answer "what is wrong right now" gets a
  pitch instead, and scrolls past it every visit. If three destinations genuinely
  need equal billing, that is the nav's job.

- **Card-in-card nesting.** *Why:* the surface ramp (`--panel` → `--panel-2` →
  `--panel-3`) is a small, finite vocabulary for saying "this is different".
  Spending a level on mere containment leaves nothing to distinguish a selected,
  interactive, or alerting element from the box it happens to sit in, and the
  operator loses the ability to read elevation as meaning. It also costs a
  border plus padding of horizontal rhythm per level, which is how a page starts
  breaking "One persistent page grid" from the inside. Group with spacing, a
  hairline, or a mono section label instead; a second surface needs a reason
  beyond "these things are related."

- **Centered-everything on data pages.** *Why:* comparing identifiers,
  timestamps, and counts down a column depends on a fixed left scan edge.
  Centering text of varying length destroys it — the eye re-finds the start of
  every line, and near-identical values (two fingerprints, two dates) stop being
  visually diffable, which is the operator decision these pages exist to
  support. **This bans centered *content alignment*, not the centered page
  column:** the max-width container is the family grid (`patterns.md` §§1–2) and
  stays. Centering remains correct for genuinely single-object, low-density
  states — the empty state (`patterns.md` §10) is centered by design.

### Dashboard (posture at a glance)

**Family grammar (ratified 2026-08-14, Plan 007 WI-2 — mockup A chosen by
owner + blind review):** summary → trend → urgent objects.

- **A summary answers the operator's standing questions in order** —
  how many / how many need attention / how many are already bad / overall
  posture. Each stat is semantically loaded: zero renders neutral, thresholds
  come from the product's alerting semantics, and a stat that merely restates
  the table below it gets cut. The *representation* is second-order: four
  cards is one option; a single compact status band is an equally legitimate
  rendering of the same hierarchy (see "Deriving a page", step 3).
- **A trend block gives the page its center of gravity** and answers "is
  there a wall of work coming?" — domain-bucketed (expiry months, not generic
  time series), with the operational threshold drawn on it (the `+30d`
  marker). This is what makes the page *this product's* dashboard instead of
  anyone's.
- **An urgency-ordered object list follows** — abbreviated, actionable, not
  the full inventory.

**Banned failure mode:** the *decorative summary* — stat cards without
operational meaning (counts with no threshold, no neutral-zero, no consequence)
and generic analytics without domain semantics. *Why:* it spends the page's
strongest position saying nothing the operator can act on; it is also,
executed generically, what makes a dashboard read as machine output.

### Inventory (the complete object list)

**Family grammar:** scopes → objects. **Counts live on the filter bar as
clickable scope chips** (`expiring-30d (12)`) — on this page a count's job is
to filter, so it is a control, not a stat. The full table with search and
sorting leads; environment-level posture is compressed or absent (it has a
dashboard to live on). *Why the split:* dashboard and inventory answer
different questions ("how bad is it?" vs "show me everything matching X");
2026-08 mockups that tried to make one page do both duplicated the same
numbers in two shapes and were rejected for exactly that.

### Record detail (one certificate, one GPO, one host)

**Family grammar:** identity header (`page_head`: name, status pill, scope
chip), then panels in *task order* — what the operator checks first goes
first. Every concept appears **once**; the single editing control for each
concept lives with its display (see `content-model.md` rule 1). Related
records are links, not embedded editors.

**Banned default:** the "everything panel" — a detail page that grows one
panel per feature shipped, each with its own free-text field and save button.
*Why:* this is accretion's natural shape (cert-watch's detail page reached
seven free-text fields via four endpoints before Plan 055); panels-per-feature
mirrors git history, not operator tasks.

### Settings

**Family grammar:** sectioned single column, one route per section
(`/settings/{section}`), persistent section nav. Each setting states its
effect in one sentence next to the control. Dangerous actions are separated
and labeled by consequence ("Delete 47 records"), not by severity theater.

**Banned default:** the card grid of settings tiles, and toggles whose labels
name the mechanism ("Enable feature flag X") instead of the outcome. *Why:*
tile grids force equal visual weight onto unequal decisions; mechanism labels
outsource the thinking to the reader.

### Activity / log

**Family grammar:** a dense, filterable, reverse-chronological table —
timestamp (mono, `tnum`), actor, action, object-as-link. Filters follow the
dashboard's counts-on-filters rule. Zero decoration: the log IS the content.

**Banned default:** the social-media "activity feed" of avatar cards with
relative timestamps ("3 hours ago") and icon badges. *Why:* card feeds cut
row density 3–5× and relative time is useless in an audit context; both are
consumer-app grammar leaking into an operations tool.

## Applying this file

- An agent building or reshaping a page states the archetype out loud before
  writing markup, and records it in the page's surface brief.
- A page that matches an archetype's banned failure mode is a review finding
  even if every token and component on it is conformant.
- New archetypes (wizard, report, diff view …) get added here — with a failure
  mode, a why, and a rule-test answer — before the first page ships in that
  shape.
