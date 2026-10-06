# Plan 011 — Remediation & Scope Honesty (post-Plan-010)

**Status:** Partially shipped across v0.2.2–v0.6.1; verified 2026-10-06. Evidence: [src/gpo_lens/topology.py](../src/gpo_lens/topology.py), [tests/test_fixtures.py](../tests/test_fixtures.py).

Publication review, version checks, generated BOM fixtures, scope honesty and narration dispatch/explain-setting shipped; Plans 013/014 and the v0.6.1 loopback fix refine the implementation. PyPI distribution is not pursued for v1.3.0. The requested sample ADMX resolution-rate threshold and manual print-to-PDF acceptance have no evidence in the branch tests; they are not claimed complete.

The design below is the historical specification; this status records the verified release scope.
**Author:** Fable 5 (full repo evaluation: code, tests, gates, plans 007–010,
reflections, breadcrumbs, public-repo state)
**Strategic role:** Plan 010 shipped in its entirety — Phase 0, Workstreams
A–D, and Tier 3 narration are all on main, v0.2.1 content is committed, and
the gates are green (423 tests, ruff clean, mypy --strict clean, zero active
breadcrumbs). What remains is (a) one governance deficiency created by the
speed of that shipping, (b) accumulated small drift and known fragilities the
reflections flagged but no session closed, and (c) the capability gaps that
keep the tool's answers honest about GPO scoping — the same honesty principle
the charter already applies to loopback.

## Ground truth at time of writing

- HEAD `a8b15f3` pushed to public `github.com/hraedon/gpo-lens`; tags v0.1.0,
  v0.2.0. CHANGELOG documents **v0.2.1 but no tag exists and both
  `pyproject.toml` and `__init__.__version__` still say 0.2.0**.
- Plan 010 WI-0.4 (publication & sanitization review) required a written
  decision note in `docs/` **before** any public flip. The repo is public and
  **no such note exists**. The real work-domain name appears in 8 committed
  files (`AGENTS.md`, `docs/tier1-normalized-model.md`, `plans/010`, three
  reflections, `tests/conftest.py`, `tests/test_calibration.py`), and 24
  reflection/breadcrumb files are committed and public.
- AGENTS.md has drifted: lists four resolved breadcrumbs as active, maps
  `cli.py` as a single module (it is a 13-module package), and describes the
  LLM layer as "future" (it shipped).
- Open fragilities carried in reflections but never filed as breadcrumbs:
  loopback mode string-matching, ADMX identity exact-match, the architecture
  test's `endswith("cli._narration")` exemption, hand-maintained fixture XML,
  no BOM-bearing fixture despite the hard rule, no negative
  `topology_crosscheck` test, unverified `@media print` CSS.
- Narration contract (WI-C.1) named three targets; two shipped (`doctor
  --explain`, `ask`). The third — single-setting "what does this do" — did
  not, though `admx_parser` already carries deterministic `explain_text`.

---

## Phase R — Remediation (do first, one session, → v0.2.2)

### WI-R.1 — Execute the skipped WI-0.4 sanitization review
The repo went public without the decision the plan gated publication on.
This is the only item in this plan with external exposure; do it first.
- Grep the committed tree (not just the working tree — `git log -p` too) for
  work-domain identifiers: domain name, OU names, GPO display names,
  hostnames, usernames. The domain name is already known-present in 8 files;
  reflections and breadcrumbs are the likely carriers of anything richer.
- Decide explicitly, in writing (`docs/publication-review.md`): what is
  acceptable to leave (e.g. aggregate counts, a bare domain name), what must
  be scrubbed, and whether scrubbing requires history rewrite (disruptive on
  a public repo — if needed, decide between rewrite-while-nobody-watches and
  accept-and-stop-adding).
- Add the decision's rules to AGENTS.md so future sessions don't re-leak
  (e.g. "reflections must not name work-domain objects").
- **AC:** decision note exists with the grep results; AGENTS.md carries the
  rule; any agreed scrub is done.

### WI-R.2 — Reconcile the v0.2.1 release
- Bump `pyproject.toml` + `__init__.__version__` to 0.2.1, tag `v0.2.1` on
  the release commit (or fold into v0.2.2 and say so in CHANGELOG — pick one,
  the current state is neither).
- Add `--version` to the CLI (it has 37 subcommands and no way to ask which
  build you're holding — support conversations need this).
- **AC:** `git tag` and CHANGELOG agree; `gpo-lens --version` prints the
  version that pyproject declares; a test asserts the three stay in sync.

### WI-R.3 — De-drift AGENTS.md and README
- AGENTS.md: replace the stale "Active breadcrumbs" section with a pointer to
  `breadcrumbs/active/` (a list goes stale by construction); fix the module
  map (`cli/` package, `report.py`, `narration.py` with the import-boundary
  rule stated); update "future LLM layer" to present tense.
- README: command table is missing `changelog`, `delegation`, `repl`,
  `settings-at`; quick-start should mention `GPO_LENS_API_KEY` is optional
  and what happens without it (degrades to facts, exits 0).
- **AC:** a new agent following AGENTS.md alone finds no contradictions with
  the tree.

---

## Workstream H — Hardening the known-fragile (v0.2.x, gated like
cert-watch Workstream E: do items when a feature touches the file, except
H.1/H.2 which are standalone-worthy)

### WI-H.1 — Fixture generator (`tests/fixtures/build_fixture.py`)
Two reflections called the hand-written XML "a time bomb": any new field in
`_parse_single_gpo` silently misses the fixtures. Generate the estate from
declarative Python instead; regeneration becomes part of adding a field.
While here: emit at least one JSON file with a UTF-8 BOM, because the
"BOM-tolerant JSON" hard rule currently has zero fixture coverage.
- **AC:** committed fixtures are generator output (checked by a test that
  regenerates and diffs); one BOM'd input exercised end-to-end.

### WI-H.2 — Loopback extraction robustness
`loopback_awareness` substring-matches "merge"/"replace" in `display_value`
and returns `None` silently on any wording/casing change — the exact silent
failure mode the feature exists to prevent. Match case-insensitively against
the setting's `raw` state value where available, fall back to display text,
and return an explicit `mode="unknown"` (still bannered) instead of `None`
when the GPO sets loopback but the mode can't be read.
- **AC:** fixture variants ("Merge", "Loopback: Replace", unrecognized text)
  all produce a banner; only the unrecognized one says mode unknown.

### WI-H.3 — ADMX crosswalk calibration
The registry-path→policy-name join is exact-string; casing and trailing
slashes in real Central Stores will miss. Normalize the join key (casefold,
strip trailing separators) and calibrate against the real estate's
PolicyDefinitions in a `samples`-marked test that reports the resolution
rate, so regressions in match quality are measurable.
- **AC:** normalized join; samples test asserts resolution rate ≥ current
  baseline (record the number when first measured).

### WI-H.4 — Test-debt sweep (small, batchable)
- Negative `topology_crosscheck` test (inject a `gPOptions` vs
  `GpoInheritanceBlocked` mismatch).
- End-to-end `estate_doctor` severity-order test against the fixture.
- Replace the architecture test's `endswith("cli._narration")` exemption
  with an explicit allowlist of module names.
- Render the HTML report once in CI-checkable form: assert the `@media
  print` block exists and the document passes an HTML parser; do one manual
  print-to-PDF and note the result in the report spec.
- **AC:** all four landed; no new fixture spelunking required (H.1 makes
  these cheap).

---

## Workstream S — Scoping honesty (v0.3.0, the capability story)

The charter's "flag, don't simulate" already governs loopback. Three more
scoping mechanisms can silently make `settings-at` / conflict views wrong,
and the data for all three is already ingested or trivially ingestible. This
workstream makes the tool honest about *who actually receives a GPO* — the
question every other view implicitly assumes away.

### WI-S.1 — Effective-scope view (`gpo-lens scope <gpo>`)
One answer composing what the model already holds: links (+enabled/enforced),
security filtering (which trustees hold Apply Group Policy — `DelegationEntry`
already powers MS16-072), WMI filter (+its WQL from `wmi_filters`), and
side-enabled flags. This is the single most-asked GPO question and currently
requires four commands.
- **AC:** one command, one screen; fixture GPO with non-default security
  filtering renders correctly; `--json` shape documented in `wi_queries.md`.

### WI-S.2 — Security-filtering caveat in topology views
When a GPO in a `settings-at` / `som-conflicts` scope is *not* applied to
Authenticated Users / Domain Computers (i.e. security-filtered), banner it the
same way loopback is bannered today. Without this, the conflict surface
claims a winner that filtered-out principals never receive.
- **AC:** fixture with a security-filtered GPO in an OU chain produces the
  caveat; unfiltered estates render unchanged.

### WI-S.3 — WMI filter analysis
Filters are ingested but only displayed. Add: orphaned filters (defined,
referenced by zero GPOs), GPOs referencing a filter absent from
`wmi-filters.json` (broken ref), and a WMI caveat in topology views matching
S.2's pattern. New `doctor` categories for the first two.
- **AC:** fixture covers orphaned + broken-ref cases; doctor flags both.

### WI-S.4 — GPP item-level targeting flag
GPP settings can carry `<Filters>` (item-level targeting) that gates them
per-object — invisible in every current view. The walker already preserves
`raw`; detect the Filters subtree, set a `has_ilt` flag on the Setting, and
banner it in settings/conflict views ("N settings carry item-level targeting;
per-object delivery not evaluated"). Flag, don't simulate.
- **AC:** fixture GPP item with ILT is flagged; conflict view banners it.

### WI-S.5 — Stale-GPO doctor check
Modified-over-N-years (default 2, configurable) **and** still linked — the
classic estate-rot signal. Timestamps are already in the model; this is a
detection function + doctor category + report row.
- **AC:** fixture with an old-but-linked GPO is flagged `info`/`low`;
  threshold flag works.

### WI-S.6 — Document the scoping limits that stay out of scope
Site-level GPO links (the collector exports OU/domain inheritance only) and
multi-domain/forest estates (the `Estate` model is single-domain) are real
limits a user will eventually hit. Decide: extend the collector for site
links (cheap: `Get-GPInheritance` on site DNs) or document both as
non-goals in README + AGENTS.md. Recommend documenting now, site links as a
v0.4 candidate only if a real estate needs it.
- **AC:** README "Limits" section exists; charter backlog updated.

---

## Workstream N — Narration completion & distribution (v0.3.x)

### WI-N.1 — Single source of truth for query routing
`_VALID_QUERIES`, `_QUERY_DISPATCH`, and `_ROUTING_SYSTEM_PROMPT` are
cross-validated but maintained by hand in two files (flagged in the last
reflection). Generate the prompt's query catalog from the dispatch table +
per-query descriptions; the cross-validation tests become construction-time
guarantees.
- **AC:** adding a query to the dispatch table is the *only* edit needed for
  `ask` to route to it.

### WI-N.2 — Third narration target: `explain-setting`
The WI-C.1 contract named three targets; "what does this setting do" never
shipped. Cheapest honest version: deterministic first — surface the ADMX
`explain_text` already parsed by `admx_parser` (no model call) — and only
layer narration on top for settings the ADMX can't resolve. This keeps the
truth path deterministic and gives the narration layer a fact to cite.
- **AC:** `explain-setting` (or `show --explain`) works offline via ADMX
  text; with a key, unresolved settings get narrated with the standard
  degrade-to-facts fallback.

### WI-N.3 — Distribution
Repo is public, which unblocks the Plan 010 distribution items — but gate
this on WI-R.1's decision sticking.
- PyPI publication (`uv build` + trusted publishing from CI on tag); confirm
  `pipx install gpo-lens` / `uv tool install` work from the sdist.
- CI matrix: add 3.13 (and 3.14 when GA on the runner) alongside 3.12 — the
  stdlib-only core makes this nearly free, and the cert-watch v0.6.5 release
  was bitten by exactly this local/CI version gap.
- **AC:** `pipx install gpo-lens` works from PyPI; CI green on ≥2 Python
  versions.

---

## Explicitly not in this plan

- **Per-user/object RSoP simulation** — charter-declined; S.2–S.4 are the
  honest alternative (flag the mechanisms, never simulate their outcome).
- **GPO↔Intune crosswalk** — stays declined (re-affirmed in Plan 010).
- **`queries.py` decomposition** (1,546 lines post-`detection.py` split) —
  keep the Plan 010 gate: split further only when a Workstream S item opens
  the file, not as a standalone session.
- **Report theming/dark mode** — cosmetic; revisit only if the report gets a
  real consumer asking for it.

## Sequencing & release framing

| Release | Headline | Contents |
|---------|----------|----------|
| v0.2.2 | Governance debt paid | Phase R (+ H.1/H.2 if the session has room) |
| v0.2.x | Hardened | Workstream H remainder, gated |
| v0.3.0 | Honest about scope | Workstream S |
| v0.3.x | Complete narration, installable | Workstream N |

Rationale: R first because it is the only externally-exposed item and
everything else compounds on a repo whose publication posture is settled.
H.1 (fixture generator) early because every Workstream S item needs new
fixtures and the generator pays for itself by the second one. S before N
because narration inherits whatever dishonesty the facts carry — same
argument that ordered B before C in Plan 010, and it was right.

## Decisions requested

1. **WI-R.1 scrub depth** — accept the domain name as published (it already
   is), or scrub + history-rewrite? Needs the user's read on workplace risk;
   the plan only insists the decision be written down.
2. **Site-link support (WI-S.6)** — document as a limit (recommended) or
   extend the collector now?
3. **PyPI name** — "gpo-lens" is presumably free but unverified; check before
   v0.3.x, since the README already treats the name as settled.
