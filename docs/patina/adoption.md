<!-- VENDORED FROM patina 0.6.0 (1dffec1) -- patina-owned. Do not edit, reformat or lint this file; edit patina and re-run sync.sh. -->
# Adopting patina — the conformance declaration

A consumer commits a `patina.toml` at its repo root saying which parts of
patina it claims, and by what mechanism. `check_patina.py --declaration
patina.toml` validates the claims and reports them.

Pair `--no-theme` with the checker whenever you synced `--no-theme`: without it
the gate fails on a `theme.js` the consumer deliberately does not have.

**This file is consumer-owned.** `sync.sh` never writes or rewrites it. The
standard is upstream-owned; the adoption declaration is downstream-owned. That
boundary is the point: patina says what conformance *means*, each tool says
what it *claims*, and no sync can quietly change a tool's answer.

```toml
[patina]
version = "0.5.0"        # the patina release this tool tracks
accent  = "gpo-lens"
prefix  = "gp"           # tool-local tokens must carry --gp-
static  = "src/gpo_lens/web/static"

[conformance.vendor]
state = "enforced"

[conformance.contract]
state = "enforced"

[conformance.content_model]
state    = "attested"
evidence = """snapshot: create /ingest, delete /ingest/delete. finding triage \
(status + 2000-char note): one inline form per row, /findings/{id}/triage. \
No second control for either concept; /baseline /golden /resultant /ask \
persist nothing."""
note     = "no UI-INVENTORY.md yet"

[conformance.structure]
state = "deferred"
why   = "no surface briefs written; these page shapes have no vocabulary yet"
until = "the first page rewrite, or a second tool reaching for the diff view"
```

> **"Read-only tool" is a claim about the wrong thing.** This example first
> declared gpo-lens's content model `not-applicable` on the grounds that it is a
> read-only analysis tool. Adopting patina in gpo-lens on 2026-08-15 showed that
> was false: gpo-lens is read-only towards *Active Directory*, not towards *its
> own store*. It persists finding triage state — including a 2000-character
> operator note, which is the precise concept class that motivated this facet —
> and snapshot lifecycle. The facet turns on whether the tool persists mutable
> domain state a user can edit, not on where its input comes from. Enumerate the
> write paths before claiming `not-applicable`; "it's a reporting tool" is an
> intuition, not evidence.

## Why facets and not levels

The first draft of Plan 009 proposed a ladder — L0 vendored, L1 contract-clean,
L2 content-modelled, L3 structured. It was wrong, and the plan contained the
evidence against it. Only one of those dependencies is real: the contract check
cannot evaluate anything until a stamped block defines what the contract *is*.
Nothing about a `UI-INVENTORY.md` requires contract-clean CSS, and nothing about
a surface brief requires an inventory.

Two things settle it:

- **A scalar cannot say "not applicable."** "This tool stopped at L1" and "this
  tier does not apply to this tool" are completely different facts, and a ladder
  can only record the second as a shortfall. gpo-lens is the case in point, and
  not in the way expected: its *structure* facet is genuinely `deferred` because
  six of its pages match none of the five archetypes — they are a diff view, a
  coverage reconciliation, a per-principal evaluation trace. Those are shapes
  patina has no vocabulary for, not failures. Under a ladder gpo-lens could only
  express that as having failed a tier it was never sensibly subject to.
- **A number implies a direction.** If L3 exists, L3 is better, whatever the
  prose says; people and agents optimise toward it. The plan had to spend a
  paragraph disclaiming the semantics of its own data structure, which is how
  you know the structure was wrong.

For the same reason there is **no rollup score**. A summary column would be read
as 3/4-is-worse-than-4/4 and we would have reinvented levels with more syntax.
The matrix is the answer; the facets mean different things and collapsing them
destroys the information that justified separating them.

## States, and what each one costs

| state | meaning | required |
|---|---|---|
| `enforced` | a script decides it, and it blocks | — |
| `advisory` | a script checks it, and it does not block | — |
| `attested` | the author claims it per change (see below) | `evidence` |
| `reviewed` | a human decided it | `reviewed_through` |
| `deferred` | deliberately not done yet | `why`, `until` |
| `not-applicable` | this facet does not apply to this tool | `why` |

**patina fixes which states are legal per facet.** A tool cannot declare
`structure = "enforced"`, because no script decides whether a page expresses an
operator's mental model. Allowing that claim would make machine proof, human
review and author attestation interchangeable in the output — and the point of
typing them separately is that they are not.

It *can* declare `structure = "attested"`. That was added on 2026-08-15, after
dossier completed a full archetype audit, came out clean, and had nowhere to
record it: `reviewed` means a human decided, and the facet offered no state an
agent-written audit could honestly claim. The same argument that put `attested`
on `content_model` applies here, and omitting it from the facet where an agent
audit is most often the *only* available evidence was simply inconsistent.

Machine-decidability is not importance. "Every `var()` resolves" is trivial to
automate and comparatively unimportant; "this screen matches how the operator
thinks about the job" is the opposite. patina does not weaken a requirement
because a script cannot judge it. It states honestly that some guarantees mean
*mechanically proven* and others mean *reviewed*.

**`deferred` needs a trigger, not an excuse.** `until = "pending a second
editing surface"` is a decision with a condition attached. `why = "not worth
doing"` alone is a standards graveyard, and the gate refuses it.

**`not-applicable` needs a reason** for the same cause the colour ratchet's
`patina-allow` needs one: an unexplained exemption is a disabled check with
better manners. Without this, a tool declares everything `not-applicable` and
shows all green.

**`attested` must carry its `evidence`, and needs it more than the others do.**
Every repo in this family is agent-written, which makes `reviewed` — "a human
decided it" — structurally unreachable for the agent doing the work. So
`attested` is the honest state for most real work here, and the first version
of this schema required nothing of it: gpo-lens's adoption produced a concrete
enumeration of every concept, control and write endpoint, and the only place to
put it was a TOML comment. The state that fits agent authorship must not also
be the one that records the least. `evidence` is where the enumeration goes.

**`reviewed` names a commit, not a date.** A date tells you when somebody
looked; a revision lets the tool work out whether anything relevant happened
afterwards. `patina status` can then distinguish *reviewed*, *reviewed but N
commits have landed since*, and *never reviewed*. Scoping staleness to
UI-relevant paths — templates, styles, the routes that render them — is the
obvious refinement and is deliberately not built yet; storing the revision is
the part that matters.

## Rendering contexts patina does not define

**Contract tokens may have context-specific mappings in explicitly declared
rendering contexts.** One reason covers the block:

```css
/* patina-allow-context:
   print needs paper-specific surface and contrast values; patina has no
   canonical print context. */
@media print {
  :root { --bg: #fff; --text: #000; /* … */ }
}
```

The marker is deliberately its own — `patina-allow-context:`, not the colour
ratchet's `patina-allow:`. They assert different things: "this literal is fine
here" versus "this whole block is a context the contract was never written
for". And the reason is block-scoped, because a context re-map is naturally a
dozen declarations and thirteen copies of one justification is compliance
theatre.

The no-shadowing rule exists to stop **drift** — one tool's `--panel` quietly
differing from another's. A print re-map creates no drift on any surface patina
defines, because patina defines exactly two rendering contexts and both are
screen (`:root[data-theme="dark"|"light"]`). Paper is a third, and `tokens.css`
ships no values for it.

Before this exemption there was **no legal way to print legibly and conform**.
dossier is a provenance instrument whose printed record is a deliverable, and a
dark-theme record printed with the screen tokens is pale text on unprinted
white; the only conforming alternatives were to stop printing, or to re-plumb
~120 rules onto `--ds-*` aliases so its components stopped referencing contract
tokens at all — which destroys the thing the contract actually cares about, and
is precisely the "cheapest path to green points away from the goal" failure this
family keeps legislating against.

**What patina owes here, precisely.** Not a canonical print palette — *a model
able to express additional rendering contexts without calling them contract
violations*. Those are different debts, and taking the first one now would
repeat in a new layer the exact mistake the archetype tier already made:
cert-watch established light and dark, dossier establishes print, so patina
rushes to define *the* family print theme before knowing whether a provenance
tool's audit-handoff requirements are representative of anything.

dossier has established that **print is a legitimate context**. It has not
established that every consumer should share one print treatment. So the
mapping stays local until a second consumer independently demonstrates enough
commonality to extract — the same evidence-flow rule as archetype promotion.
Recurrence across consumers triggers review, not extraction.

One consequence worth stating: **when a gate systematically rewards
circumvention, the gate is wrong.** Before this exemption the mechanically
cheapest way to conform was to re-plumb dossier's components onto `--ds-*`
aliases so they stopped referencing contract tokens at all — greener checker,
weaker design system. A rule with that incentive is not a strict rule; it is a
broken one.

## Attestation

Some semantic gates have a correct answer of "nothing changed." The content
model is one: plenty of template edits do not touch it. A gate that demands a
`UI-INVENTORY.md` diff on every template change teaches exactly one behaviour —
edit the file until CI goes green — and converts a review artifact into
ceremonial churn.

So the claim is made as a commit trailer:

```
Content-Model: reviewed-unchanged
```

You cannot make attestation expensive; an agent can produce any ceremony we
invent. You *can* make it legible. A trailer is better than touching a file
precisely because nobody can mistake it for substantive work — it gives a
reviewer a discrete claim to accept or challenge.

The general rule, which cost us a real bug to learn: **never make meaningless
file modification the cheapest way to satisfy a semantic gate.** The colour
ratchet was a single integer, so swapping one violation for another passed while
removing one turned CI red — the cheap path pointed away from the goal. Agents
find that immediately.

Attested facets are reported as `attested`, never as `enforced`.

## Versions

`version` is the patina release the tool tracks; the stamp inside the vendored
`tokens.css` records the revision actually vendored. With `--upstream` the gate
checks they agree, so a declaration cannot drift from reality.

A newer patina is **not** a conformance failure — it is an available upgrade,
reported as a note. Otherwise every commit to patina turns the whole estate red
and vendoring has bought nothing. See `CHANGELOG.md` for what a version bump
means and for the per-release impact metadata (`visual-change`,
`baseline-review`, `consumer-code-change`) that tells you what adopting one
actually costs.

## Vendoring the rules

```
./sync.sh --docs <consumer>/docs/patina <accent> <static-dir> <checks-dir>
```

This copies patina's docs into the consumer, each with a one-line provenance
banner, plus `patina-docs.json` (a manifest of source hashes) and
`OWNERSHIP.md`. `check_patina.py --docs <dir>` verifies them against the
manifest, and with `--upstream` against patina at the revision they claim.
Same version semantics as the token block: **mismatched-with-its-own-rev is
drift and fails; a newer upstream is an upgrade and does not.**

The rules have to be local because the estate's UIs are written by agents. Up
to 0.5.0, `sync.sh` shipped tokens, fonts, a theme toggle and a checker — and
not one line of the standard those things enforce. An agent working in a
consumer had no copy of the rules it was meant to follow, and adopting gpo-lens
made the cost concrete rather than theoretical.

### The ownership boundary

More useful than a generic "do not edit generated files" warning, and written
into `OWNERSHIP.md` at sync time:

- **patina-owned** — the vendored docs, `patina-check.py`, the block inside
  `css/tokens.css`, `theme.js`, `fonts/`. Upstream decides; a sync overwrites
  local changes. Do not edit, reformat, or lint them.
- **consumer-owned** — `patina.toml` and its evidence, `UI-INVENTORY.md`,
  surface briefs and deviation records, the ratchet baseline, and all of your
  own CSS including anything below `/* patina:end */`. A sync never touches
  these.

The standard is upstream-owned. What you claim about your adoption of it is
yours.

## Open family-pattern reviews (triggered by recurrence, not yet promoted)

Independent recurrence across consumers triggers **review**. These are the live
candidates as of 2026-08-15. None is promoted; each is recorded so the next
instance is cheap to spot.

**1. The paper substrate — strongest evidence, and the scope is the finding.**
dossier and openbia independently re-map the same surface/text ramp under
`@media print`, in the same order, for the same stated reason, having never
seen each other's CSS. Different domains, different reasons for printing.

What is shared is *the substrate only*. What is emphatically not:

| | dossier | openbia |
|---|---|---|
| what is printed | one provenance record | a whole multi-section report |
| why | audit handoff, once | recurrence — legible when the system that made it is down |
| type | no size rule at all | physical units (10.5/16/13/11**pt**) |
| status colour | preserved — coloured pills | degraded to outline + literal enum text |

Both divergences follow from what the paper is *for*, not from taste: physical
units because the artifact is measured in sheets, colour degradation because
openbia's output goes into a binder and is read off a mono laser during a
disaster, where a filled amber badge is an indistinguishable grey block.
**Shipping type sizing or status treatment as family defaults would force
dossier to print worse in order to serve openbia's binder.** Extract the
substrate; leave the rest local. Note also that openbia renders a second paper
path through reportlab, so a family print theme cannot assume CSS is the only
one.

**2. `local/worklist` — a genuine independent match.** dossier's and openbia's
`review_queue.html` ask the same operator questions in the same order (what is
queued on me, what do I take first, how long has it waited, who is accountable,
where do I act), both derive the set rather than store it, both order by
urgency and say so in the lead, and **neither carries a single control**. The
discriminator is the empty state: both authors independently wrote emptiness as
*success*. An Inventory is never "done"; a worklist's goal state is empty.

It is **not** Inventory — Inventory's grammar is scopes → objects with
counts-as-clickable-chips, and neither queue has a scope, filter or search,
because the set is handed to you rather than scoped by you. dossier's own
declaration currently force-fits it to Inventory; that mapping is wrong and is
corrected there. Against promotion: openbia's has zero interaction, so the
shared *interaction* grammar is thin. Review, not promotion.

**3. `local/derivation` — weaker signal, flagged.** openbia's
`downtime_coverage.html` (per-group total / covered / uncovered / percentage
against a stated target of zero) looks like the "coverage reconciliation" shape
gpo-lens's `admx_coverage.html` was recorded under. Not yet compared
side-by-side.

**No recurrence yet: `local/report-document`.** openbia's `report.html` is the
estate's only document surface so far — numbered sections each answering a
stated question, provenance in the header because the document outlives the
query, every table naming its evidence tier because the reader cannot re-run
it. Its banned failure mode is already obvious if it is ever promoted: **the
dashboard-in-a-report**, which spends the reader's attention on posture they
cannot act on or verify, and quietly substitutes a number for the stated
question.

## Recording an audit that found something

`attested` claims the property holds. An audit that was genuinely performed and
**found a violation** is `deferred` — with the finding in `why`, the fix
condition in `until`, and the completed audit in `evidence`, which is displayed
for every state. Deferring does not erase the work; it says the claim does not
hold *yet* and names what was found. openbia's `structure` facet is the worked
example: the audit covered all 16 templates and turned up a live banned failure
mode, so the facet cannot be `attested`, and the audit is still recorded.

## Two things that bite on first sync

**Your linter will want to edit the vendored files, and editing them breaks
their stamps.** `patina-check.py` and the vendored docs are byte-verified, so
any repo that lints its *whole* tree hits a standoff on day one, and every fix
invalidates the stamp on the files the standard most insists you do not touch.
Two individually correct invariants — "vendored code stays byte-identical" and
"all repository files satisfy our formatter" — that collide wherever the
formatter reaches the vendor tree.

**patina cannot fix this upstream for everyone.** Trivially portable complaints
were fixed at the source (an ambiguous `l`, one long line), and two of the four
consumers — cert-watch (`E,F,I,B,UP,SIM` at 100) and openbia (`E,F,I,UP,B,SIM`
at 100) — now report nothing on the vendored files. gpo-lens additionally
enables `FURB`, `ISC`, `PLW` and `EXE` and reports **30** findings on the same
bytes: `re.M` versus `re.MULTILINE`, implicit string concatenation inside a
tuple, `subprocess.run` without an explicit `check=`, a shebang on a file the
vendor step made non-executable. Style preferences, not defects — and no single
source satisfies every consumer's rule set at once.

So the collision is **not universal**; it depends on how strict your config is.
Exclusion is still the right answer, because the reason is byte-identity rather
than style: a formatter that rewrites a vendored file breaks its stamp whether
or not the rewrite was an improvement.

Exclude the vendored paths from your linter and formatter — they are not your
code, and their style is patina's problem:

```toml
# pyproject.toml
[tool.ruff]
extend-exclude = ["scripts/patina-check.py", "docs/patina"]
```

Every consumer that lints its whole tree hits this. cert-watch's CI runs
`ruff check .`, so it will too — it simply had not yet, because its adoption
branch has never been pushed. That is worth noting on its own: a collision this
mechanical went unseen for a day purely because CI had not run.

**Put the checker and the ratchet outside the web root.** `sync.sh`'s third
argument chooses where `patina-check.py` lands; pass your `scripts/` or
`tests/` directory. Likewise pass `--ratchet-file` explicitly. The defaults are
convenient for a first run and would otherwise publish both files.

## Deviation

A page whose shape patina has no vocabulary for records that in its own surface
brief and carries on:

```
archetype: local/diff-view — deviation; patina-proposal: <link or none>
```

The deviation is legal immediately; nothing blocks the consumer.

**The promotion rule:** *recurrence within a consumer establishes a local
pattern; independent recurrence across consumers triggers family-pattern
review.* Not automatic promotion — review. Two tools can reach for the same
wrong shape, and a third page in the same product is almost no new evidence,
because it shares the product's assumptions. A second *product* independently
arriving at the same operator questions and the same structure is a great deal
of evidence.

Record the local name now, in the page's brief (`local/comparison`,
`local/derivation`, whatever honestly describes it). Naming it locally costs
nothing and is what makes the recurrence visible later.

The first live candidate is gpo-lens's comparison surfaces — `baseline_diff`,
`golden_diff`, `admx_coverage`, `resultant` — which revealed that patina's
archetype vocabulary is **object-centric** while those pages are
**relationship-centric**: their subject is a relationship between two objects,
not a set of objects. That is a genuine discovery about the vocabulary. It is
*not* yet a Comparison archetype: those four may share a conceptual family
without sharing enough interaction grammar to justify one archetype, and they
are all observations from a single product.

The rule this replaces ("if a page needs a different structure, amend
`archetypes.md` in the same PR") described a monorepo we do not have. patina is
a separate repository consumed by copy; a gpo-lens PR cannot touch a patina
file, so as written every legitimate deviation was a process violation.
