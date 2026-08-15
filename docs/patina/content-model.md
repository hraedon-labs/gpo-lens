<!-- VENDORED FROM patina 0.5.0 (e7024c1) -- patina-owned. Do not edit, reformat or lint this file; edit patina and re-run sync.sh. -->
# patina content-model contract (the concept layer)

Tokens keep the family's colours coherent; patterns and archetypes keep its
shapes coherent. This layer keeps its **meaning** coherent: which concepts a
record exposes, and where each one lives. It exists because nothing else —
not visual regression, not token gates, not lint — can see the defect class
that motivated it: two duplicate controls are perfectly pixel-consistent.

## The worked example (why these rules exist)

cert-watch's certificate page, as shipped through a *dedicated redesign*
(Plan 055), surfaced seven free-text fields from two tables via three editing
surfaces and four write endpoints. Two were near-identical 10,000-character
"notes" textareas — one on the host row, one on the certificate row — whose
placeholder text invited each other's content, plus that of the structured
owner and runbook fields eight lines up. Cause: two features landed two
months apart and nobody reconciled, because no rule existed at the concept
level. The redesign unified *controls* ("one toggle, one chip") and couldn't
touch this, because its rules never named *concepts*. These rules do.

## The rules

1. **One concept, one control.** Each concept a record exposes (ownership,
   procedure notes, tags, …) has exactly one editing control across the whole
   UI. A proposed second free-text field on a record must either merge into
   the existing one or carry a visibly distinct scope — in its label AND
   wherever list views show it. "Distinct in the maintainer's head" does not
   count; if the two labels need a parenthetical to tell apart, they are one
   concept.

2. **Same noun, same verb, everywhere.** One term per concept across pages,
   labels, buttons, docs. Pick one of Delete/Remove, one of Note/Comment, one
   of Host/Server — and use it product-wide. If the save action looks
   different in two places, one of them is wrong.

3. **Say each idea once per surface.** A status or label rendered in several
   slots of the same panel is template wiring, not information. If the
   heading already states it, the body adds something or disappears.

4. **The inventory is part of the PR.** Every UI-bearing repo keeps
   `UI-INVENTORY.md`: record type → concepts → the one control that edits
   each → write endpoints. Adding a field, control, or editing surface
   without diffing the inventory in the same PR fails review. The inventory
   is a table of ownership, not documentation — if it takes more than a page
   per record type, it is doing the wrong job.

5. **Surface briefs.** Each page keeps `ui/surfaces/<route>.md` — a few lines
   (*normative for new and reshaped pages; no repo has written one yet, see
   Enforcement*): **the operator questions this page answers** (in decision
   order — this line IS the page's derivation, see `archetypes.md` "Deriving a
   page"), archetype, concepts owned, concepts deliberately NOT shown. An agent editing a page reads its brief first. A
   feature that contradicts the brief amends the brief in the same PR, never
   silently. The "NOT shown" line is load-bearing: it is how the next
   feature learns that an omission was a decision.

## Review questions (apply to any accreted page)

- Is this concept already editable somewhere else?
- Do two controls on this page compete for the same operator intent?
- Does any placeholder or help text invite content that another field owns?
- Would a new operator know, without asking, which field a renewal procedure
  goes in?

## Enforcement

Rule 4 has a script. The rest is review-time prose, which is worth stating
plainly in a document whose own premise is that prose enforcement fails.

- **Built, advisory — `scripts/check_content_model.py` (rule 4).** Given a diff
  range, it finds UI-affecting files and asks for one of two answers: an
  updated `UI-INVENTORY.md`, or a commit trailer `Content-Model:
  reviewed-unchanged`. It reports which one it got, and exits 0 unless
  `--blocking` is passed.

  **Both answers are real.** A blocking "templates changed ⇒ inventory must
  change" rule is mechanical and only approximately correlated with the thing
  we care about: most template edits do not touch the content model, so the
  cheapest route to green becomes *edit `UI-INVENTORY.md` somehow*, and a
  review artifact turns into ceremonial churn. The correct inventory diff is
  frequently zero bytes. Attestation cannot be made expensive — an agent can
  produce any ceremony we invent — but it can be made **legible**: a trailer
  is better than a file touch precisely because nobody can mistake it for
  substantive work, and it hands a reviewer a discrete claim to challenge.

  Family rule, learned the hard way from patina's own colour ratchet (which
  made *swapping* a violation cheaper than *removing* one): **never make
  meaningless file modification the cheapest way to satisfy a semantic gate.**

  It stays advisory until there is either a detector precise enough not to
  reward fake edits, or enough data from advisory runs to justify blocking.
  Consumers declaring `content_model = "attested"` (see `adoption.md`) are
  using the trailer path deliberately.
- **Not built — the duplicate-control detector.** Plan 008 WI-4 also specifies
  a heuristic that flags ≥2 same-type free-text controls bound to one record
  container in a rendered page, and duplicate visible labels within a
  container. **That part does not exist.** It is the half that would have
  caught the notes defect directly.
- **Applicability.** Content-model conformance applies to a tool that
  **persists operator-editable domain state**. It may be `not-applicable` when
  the UI is genuinely read-only with respect to domain state, or persists only
  incidental presentation/session preferences (theme choice, column widths, a
  saved filter).

  That is the whole test. It is deliberately broader than the earlier
  formulation, which required *more than one reachable editing surface* before
  the facet applied. gpo-lens is the counterexample that retired it: even if its
  triage note had exactly one editing surface and perfectly obvious ownership,
  it is still persisted operator-authored domain state, and a system storing
  that should be able to say what it stores and where it can be changed. A tiny
  tool with one mutable record type needs a ten-line inventory, not a
  theological argument about whether it qualifies.

  The following are **risk multipliers, not applicability triggers** — they say
  how much attention the inventory deserves, not whether you need one:

  - the same concept is editable from more than one reachable surface;
  - mutable state crosses entity or record ownership boundaries;
  - multiple controls appear to represent similar concepts;
  - persisted state has no obvious editing or viewing surface at all.

  "Reachable surface" still matters here, just one level down: an API endpoint
  no UI calls belongs in the inventory as part of the state model, but it is not
  by itself a second *control*.

  The defect class is **ambiguous ownership of mutable domain state** — not
  "several free-text fields". You get the same pathology with dropdowns,
  toggles, dates, tags or ownership fields; `hosts.notes` reaching five write
  paths across two control types is the shape of the bug, and text was
  incidental to it.

  One more trap, from the same adoption: **"read-only tool" is a claim about the
  wrong thing.** gpo-lens is read-only towards Active Directory and fully
  mutable towards its own store. Ask what the tool *persists*, not where its
  input comes from.
- **Normative for new work, with no artifacts yet — surface briefs (rule 5).**
  No `ui/surfaces/<route>.md` exists in any family repo. The rule binds pages
  written from here on; it does not describe an existing corpus, so "read the
  page's brief first" currently resolves to "there isn't one — write it."
  Plan 008 WI-6 produces the first set (cert-watch's four domains) as the
  worked example other repos copy.
