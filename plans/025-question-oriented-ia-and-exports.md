# Plan 025 — Question-oriented information architecture, briefing, and exports

**Status:** Shipped in v1.3.0; verified 2026-10-06 on the release candidate (release date set by coordinator). Evidence: [src/gpo_lens/web/templates/base.html](../src/gpo_lens/web/templates/base.html), [tests/test_exports.py](../tests/test_exports.py).

WI-1/2/3 supply the inbox, briefing and directories; WI-4/5 landed as `5549855` and WI-6 as `20ecaa3`/`f5d30fb`, integrated by `d271cf7`. The shipped scope uses configured-settings search and retained handlers, rather than broad entity omnisearch or permanent redirects. Production rollout and tracker acceptance remain coordinator actions; see Plan 027.

The design below is the historical specification; this status records the verified release scope.

All six work items are implemented on the candidate. WI-1/2/3 introduced
persisted findings, deterministic briefing and Explore/Tools directories;
WI-4/5 changed navigation and added signed, bounded web explanations; WI-6
added Markdown/CSV exports. See the [route inventory](../docs/web-route-inventory.json)
and [release reconciliation](027-road-to-generous-1x.md).

The final implementation retains every old handler instead of retiring routes.
The primary search is configured-settings search. It does not provide the
broader Plan 023 entity omnisearch/global snapshot axis. Persisted contextual
comparison runs and exact category-to-workbench deep links remain follow-on
work; current baseline/golden upload workbenches are retained under Tools.

**Depends on:** Plan 023 reading primitives and Plan 024 durable finding queries

**Strategic role:** Complete the web reimagining once every existing destination
has an honest replacement or a deliberate specialist home.

## 1. Goal

Replace artifact-per-page navigation with a small question-oriented primary
information architecture while retaining deep analytical workbenches, stable
bookmarks, deterministic exports, and the project's distinction between facts
and narration.

## 2. Shipped information architecture

| Primary destination | Operator question | Principal views |
|---|---|---|
| **Briefing** | Do I need to care today? | Change delta, finding delta, estate vitals |
| **Findings** | Is anything wrong? | Inbox, occurrence history, accepted-risk register |
| **Explore** | Why is this setting what it is here? | Dossiers, OUs, settings, resultant, search |
| **History** | What changed? | Snapshot changelog/diffs; occurrence evaluation history is under Findings |
| **Tools** | What specialist operation do I need? | Ingest, baselines, golden comparisons, delegation, ADMX coverage, narration, export |

The top navigation becomes smaller; the product does not pretend every useful
analysis is a finding. Specialist workbenches remain available as secondary
views and may be linked from filtered primary views.

## 3. Non-goals

- No deletion of analytical capabilities merely to reduce navigation count.
- No conversion to a SPA or client-side routing.
- No new authority for narration.
- No exports of raw `Setting.raw`, credentials, or unredacted evidence.
- No implicit acceptance of risk from acknowledgment or navigation behavior.
- No rewrite of core finding, merge, topology, or snapshot semantics.

## 4. WI-1 — Findings inbox and occurrence view

The Findings page consumes Plan 024 core queries.

Default filter: new or regressed, open, and unacknowledged. Facets include:

- category and severity;
- GPO/subject;
- lifecycle and triage state;
- intrinsic/contextual evaluation series;
- comparator/policy pack;
- claim level and coverage state.

Each row shows bounded evidence, snapshot/evaluation provenance, local scope
caveats, and triage controls authorized separately from ingestion.

Resolved, acknowledged, indeterminate, and accepted-risk items remain one click
away and are never deleted. The occurrence view shows observations, predecessor
regressions, triage event history, and rule/comparator version changes.

Baseline, golden, delegation, conflict, and ADMX-derived findings may appear in
the inbox when backed by a persisted evaluation series. Their full comparison
or matrix workbench remains linked under Tools/Explore.

### Acceptance criteria

- Default inbox contains exactly actionable new/regressed unacknowledged items.
- Acknowledgment changes only local workflow state.
- Accepted-risk expiry returns an occurrence to the actionable view.
- Regression links to its predecessor without inheriting accepted risk by default.
- Failed/partial evaluations cannot make items appear resolved.
- Filters and pagination are stable, bounded, and URL-addressable.

## 5. WI-2 — Briefing home page

Replace the current dashboard with a prose-first deterministic briefing:

```text
Since snapshot N−1: 2 GPOs changed, 1 finding is new, 3 resolved,
and 1 accepted-risk decision expires soon.
```

Every noun links to its evidence or filtered view. Sections:

- what changed;
- findings delta;
- expiring accepted risks;
- coverage/provenance warnings;
- a small set of linked estate vitals;
- compact posture-over-time context.

Generated sentences come from deterministic formatters and typed deltas. They
are not Tier 3 narration. With one snapshot, the page honestly presents a first
snapshot summary. With a failed latest evaluation, it reports analysis
incomplete rather than a clean delta.

### Acceptance criteria

- Golden tests pin briefing text for first, ordinary, degraded, and no-change
  scenarios.
- No unlinked stat tile appears.
- Coverage and provenance gaps are at least as prominent as favorable counts.
- Historical snapshot selection produces a briefing as of that point.

## 6. WI-3 — Explore and specialist workbenches

Explore organizes:

- GPO dossiers and inventory;
- OU list/detail and supported resultant views;
- setting-centric pages;
- global search;
- conflict exploration;
- delegation and trustee exploration.

Tools organizes operations and contextual comparisons:

- ingest/snapshot administration;
- baseline and golden comparison workbenches;
- ADMX catalogue coverage;
- exports;
- exploratory narration.

If Plan 026 is implemented, Tools and eligible dossiers/findings may also expose
artifact export or configured “Open in GPO Studio” links. Those links remain
optional, non-mutating, and unavailable when no peer deployment is configured.

Primary pages link to a specialist workbench with filters applied. For example,
a baseline occurrence opens the exact persisted comparison run; a delegation
finding opens the affected trustee/GPO matrix.

## 7. WI-4 — Navigation migration and redirects

Update `base.html` to Briefing / Findings / Explore / History / Tools plus
omnisearch.

Before retiring a primary navigation link, maintain a route inventory mapping:

```text
old URL → replacement URL or retained specialist view → filter translation
```

Use redirects only when semantics and parameters can be preserved. Otherwise,
render the retained specialist view with a navigation cue. Prefer 302 during
the staged rollout; adopt permanent redirects only after work bookmarks and
filter translations are verified.

Plan 022 WI-8 and WI-9 are superseded only when the corresponding Findings and
scope/dossier replacements ship. Until then they remain independent work.

### Acceptance criteria

- Route inventory covers every pre-025 web URL and representative query strings.
- Old bookmarks reach equivalent information without losing snapshot/filter
  context.
- No specialist capability becomes undiscoverable.
- Keyboard navigation, visible focus, skip links, landmarks, and mobile layout
  pass the established accessibility review.

## 8. WI-5 — Narration demotion

Remove `/ask` from primary navigation. Keep it under Tools for exploration.

Add optional “explain these facts” actions to dossier, OU, finding, and
comparison views. The deterministic page payload is the only supplied factual
context. The page remains authoritative; the model output is visibly labeled a
narrative projection.

Requirements:

- Narration receives safe, bounded, redacted facts—not rendered HTML or raw
  evidence.
- Historical narration includes snapshot and analysis provenance.
- Existing fact-check harness rejects entities, findings, or claims absent from
  the supplied payload.
- Narration failure never hides or delays the deterministic page.

## 9. WI-6 — Deterministic export everywhere

Major views gain Markdown and CSV exports of their deterministic filtered
content:

- dossier and settings ledger;
- findings inbox, occurrence history, and accepted-risk register;
- briefing;
- setting-centric page;
- snapshot/GPO/comparison diffs.

Exports carry:

- snapshot and evaluation identifiers;
- application/rule/ADMX/comparator provenance where relevant;
- active filters;
- generated-at metadata only when the format explicitly permits it;
- scope and claim caveats;
- safe evidence references and redaction markers;
- triage state and event attribution where authorized.

“Exactly what the view shows” means the same typed query result and filters, not
a scrape of HTML. Byte-deterministic variants omit volatile timestamps or take
them as explicit inputs.

No export invokes narration or emits raw source fragments.

### Acceptance criteria

- Golden tests prove deterministic output for fixed inputs.
- HTML, CSV, Markdown, API, and narration redaction tests share the same secret
  fixture corpus.
- Authorization applies to export data and triage/audit fields.
- Large exports stream or remain within explicit memory bounds.

## 10. Sequencing and deployment gates

Order:

1. Findings inbox and occurrence view.
2. Briefing.
3. Explore/Tools organization without removing routes.
4. Staged primary-navigation switch.
5. Narration demotion.
6. Deterministic exports.
7. Permanent redirects only after observation.

Natural checkpoints:

- Findings available as an opt-in destination.
- Briefing becomes home while old navigation remains.
- New navigation enabled in lab with route telemetry/audit that records paths,
  never estate query contents.
- Work deployment with reversible navigation flag.
- Old navigation retired only after bookmark and workflow review.

## 11. Success measures

- Operators can answer the four primary questions with fewer page transitions.
- Daily entry lands on new/change deltas rather than an undifferentiated estate.
- Existing specialist tasks remain reachable and semantically intact.
- No increase in scope overclaim, secret exposure, or historical ambiguity.
- Narration use is optional and downstream of deterministic facts.
- Exports can be attached to change tickets without manual cleanup or secret
  inspection.

## 12. Final acceptance evidence (2026-10-06)

- [x] Primary IA is Briefing, Findings, Explore, History, Tools, plus configured-settings search — `tests/test_plan025_navigation.py`.
- [x] Findings and Briefing use persisted/provenance-aware queries — `tests/test_findings_inbox.py`, `tests/test_briefing.py`.
- [x] Specialist workbenches remain discoverable — `tests/test_explore_tools.py`, route-reference coverage in the navigation tests.
- [x] Old handlers retain snapshot/filter semantics; no route retirement or permanent redirect is required — `docs/web-route-inventory.json`, bookmark tests.
- [x] Web narration is demoted and consumes signed safe counts/caveats/provenance — `tests/test_page_narration.py`, `tests/test_ask_routes.py`.
- [x] Exports are deterministic, provenance-bearing, authorized and redacted — `tests/test_export_rendering.py`, `tests/test_exports.py`.
- [x] Rollout is reversible in code with `GPO_LENS_LEGACY_NAV` — `test_reversible_nav`.
- [ ] Coordinator: record the actual v1.3.0 lab/work rollout and bookmark smoke results; branch tests do not prove production deployment.
- [x] Automated accessibility/navigation checks and the local release gates are recorded in [verification evidence](../docs/release-v1.3.0-verification.md).
- [ ] Coordinator: final independent acceptance and any manual accessibility/browser review; no such review is invented by this docs pass.
