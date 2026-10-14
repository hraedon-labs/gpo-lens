# AGENTS.md

Conventions and quick reference for agents (and humans) working on gpo-lens.

## What this is

Local-first, **read-only** Group Policy analysis. The tool ingests *copies* of a
GPO estate (it never touches live AD) and answers questions about it. The
deterministic core has **no AI in the truth path** — the LLM layer only
narrates facts the core computed. See `README.md` for the full charter.

## Orient

1. **Read the model.** `docs/tier1-normalized-model.md` — the normalized data
   model, mapped against two real exports, with the join-key and parser gotchas.
   The dataclasses in `src/gpo_lens/model.py` are the concrete contract.
2. **Read the spec.** `docs/spec/wi_*.md` — one file per work item, with explicit
   acceptance criteria (`AC-NN`) and exact function signatures. **The spec is the
   contract.** Implement to the ACs.
3. **Validate against reality.** `tests/` encodes the *measured* numbers from the
    real exports (e.g. work domain = 100+ GPOs, several disabled-but-populated sides,
    1,000+ SOMs). Your implementation is correct when those pass. The sample exports
   live in `samples/` (gitignored — never commit them; WORK-DOMAIN.local is a real work
   domain's SYSVOL). Sample-dependent tests skip if `samples/` is absent.

## Hard rules

- **No work-domain identifiers in committed files.** Reflections and docs use
  placeholders (`WORK-DOMAIN.local`, `LABDOMAIN`). Exact counts are allowed
  only in test assertions against `samples/`; docs use ranges. **Reflections are
  the repeat offender** — when a reflection *describes* a leak, refer to "the
  work-domain FQDN", never paste the literal token (that re-leaks it).
  Enforced two ways: the CI `identifier-gate` job (hard gate) **and** a local
  pre-commit hook (early warning) — activate it once per clone with
  `git config core.hooksPath githooks` (or `scripts/install-git-hooks.sh`) and
  provide the denylist via `$GPO_LENS_FORBIDDEN_IDENTIFIERS` or a gitignored
  `.identifiers-denylist.local`. The hook scans staged content before the commit
  exists, closing the window where a token reaches history before CI flags it.
- **Fixture data is synthetic.** No real GPO names, OU paths, or domain names
  in committed test files.
- **`samples/` is gitignored and must never be committed.**
- **Read-only.** No code writes to or connects to Active Directory. Input is
  files only.
- **No AI in the deterministic core.** Tiers 1–2.5 must run with zero model calls.
- **Flag, don't simulate.** Topology resolution is OU-level; never claim
  object-level RSoP (no per-user security/WMI/loopback evaluation). Scoping
  mechanisms (loopback, security filtering, WMI filters, item-level targeting,
  AD-site links) are flagged with caveats in topology views, never simulated.
  Sites are modeled as `container_type="site"` SOMs (a parallel axis, excluded
  from OU-precedence views); per-machine site membership is not resolved.
- **Coverage honesty.** Collection is bounded by the collector account's AD
  access (a stripped-AU GPO is invisible to a least-privilege account). Don't
  paper over it — reconcile `gpo-inventory.json` (authoritative, privileged run)
  + `collection-errors.json` against the export and surface missing GPOs as
  `coverage_gap` findings. Never present a partial estate as complete.
- **Canonical GPO id everywhere:** lowercase, braces stripped. All cross-input
  joins use it (see `normalize.canonical_guid`).
- **BOM-tolerant JSON:** collector JSON may carry a UTF-8 BOM (PowerShell 5.1).
  Always load with `utf-8-sig`.
- **Import boundary:** Core modules (`model`, `normalize`, `ingest`, `store`, `queries`, `snapshot_diff`, `detection`, `admx_parser`, `display`, `report`, `events`, `sinks`, `query_dispatch`, `authz`, `topology`, `registry_pol`, `paths`, `danger`, `merge`, `trend`, `findings`, `finding_model`, `_legacy_findings`, `redaction`, `analyst_text`) must never import `narration` or `web`. An architecture test enforces this.
- **No cpassword value at rest.** `redaction.redact_element_tree` redacts
  labelled GPP `cpassword` values in the whole report tree before any field is
  read, and `redaction.sanitize_estate` chases the values discovered (report,
  SYSVOL, any input) through the estate — in `ingest.load_estate`, again in
  `save_estate`, and through finding text in `evaluate_finding_lifecycle_v2`.
  Copies are rewritten only in fields listed in `redaction.REWRITABLE_FIELDS`
  (and `store.REWRITABLE_COLUMNS` for the v11 migration); anywhere else they
  raise `CredentialInIdentityError`. When you add a model field or a column,
  classify it there (unlisted means structural). Never add a path that stores,
  hashes or prints a value; findings carry `CPASSWORD_FINDING_DETAIL` only.
  Multi-input loaders discover over all inputs before one sanitize
  (`_parse_report_root(..., sanitize=False)`). Results are verified
  independently (`residual_locations`, `store._verify_snapshot_rows`,
  `store.verify_committed_estate`); never gate discovery on a contiguous
  `cpassword` substring of serialized data without the mixed-content check.
  Schema v11 scrubs older databases, verifies by rediscovery (rolling back on
  a residual), and purges free pages (`store._scrub_cpassword_at_rest`,
  `_purge_free_pages`).
- **Operator-supplied text is refused, never rewritten, when it carries a
  cpassword.** Ingest redaction cannot know a value supplied after it, so every
  path that stores or sends such text (triage note, rationale and actor, the
  Ask question, event `principal`s, the `explain-setting` identity sent to the
  model, a forwarded user name) calls `analyst_text.check_analyst_text` (or
  `valid_principal_name`) first, on `checked_slice(...)` of what it keeps. The
  guard is total: it returns or raises `CpasswordInAnalystTextError`.
  `tests/test_analyst_text_guard.py` inventories write paths and request
  sources (SQL writes to `ANALYST_TEXT_COLUMNS` and `events`, `append_event`
  call sites and payload keys, web inputs including `Header`, raw
  header/cookie/query reads, LLM calls) and checks each guarded field: a new
  one fails it until it is guarded or classified there. It is a heuristic; read
  its blind-spot list. Refusals name the field, never the value;
  `gpo-lens analyst-text-check` lists ids of older rows (read-only).

## Build / test / lint

```bash
uv venv && uv pip install -e ".[dev]"   # local dev
.venv/bin/pytest -q            # unit + calibration tests (sample tests skip if samples/ absent)
.venv/bin/pytest -q -m samples # calibration tests against the real exports (needs samples/)
.venv/bin/pytest -m browser -n0 # real Chromium + axe-core tests (once: .venv/bin/playwright install chromium)
.venv/bin/ruff check .
.venv/bin/ruff format .          # formatter is authoritative — see below
.venv/bin/mypy src
```

Browser tests (`tests/browser/`) are deselected by default. They drive a live
`gpo-lens serve` with Playwright and gate axe-core serious/critical violations
against `tests/browser/axe-baseline.json`; a new violation **or** a baselined one
that disappears fails. After a deliberate a11y fix, regenerate with
`GPO_LENS_AXE_WRITE_BASELINE=1` and review the diff.

**Formatting is `ruff format`'s job, not yours.** CI runs
`ruff format --check`, so a hand-styled block fails the build; run
`ruff format .` rather than reflowing by hand or arguing with it in review.
Note it also formats Python code blocks inside Markdown, so `docs/spec/` and
`plans/` examples are governed too. Adopted 2026-08-07 in `4b7f2cd`, which is
listed in `.git-blame-ignore-revs` — run
`git config blame.ignoreRevsFile .git-blame-ignore-revs` once per clone so
`git blame` reports authors instead of the reformat.

CI installs from the lockfile (`uv sync --locked --extra dev --extra web`), so
**regenerate `uv.lock` (`uv lock`) and commit it whenever you touch
`[project] dependencies` or the `[project.optional-dependencies]` extras** —
stale-lock drift fails the build. A `supply-chain` CI job runs `pip-audit`
against the locked runtime + web set.

`docs/capability-matrix.md` is generated: after adding a detector, danger rule,
ingest parser, collector input or CSE handling, run
`python scripts/gen_capability_matrix.py` (curated descriptions live in that
script). `tests/test_capability_matrix.py` fails on a stale file or on a
detector/parser/input without a row.

**Releases** are tag-driven: pushing `vX.Y.Z` runs `.github/workflows/release.yml`,
which refuses unless the tag, `__version__`, `pyproject.toml`, `uv.lock` and the
top (released, dated) CHANGELOG heading agree (`scripts/check_release_version.py`)
and the commit is on `main`; it then re-runs all of `ci.yml`, builds the sdist and
wheel twice and requires identical bytes, smoke-installs the exact wheel against
the golden estate, and creates a **draft** GitHub release with a CycloneDX SBOM,
`SHA256SUMS` and build-provenance + SBOM attestations. Publishing the draft is a
human step.

Slice 1 is **stdlib-only** (`xml.etree.ElementTree`, `json`, `sqlite3`,
`argparse`) — keep it dependency-free so the core stays portable/air-gappable.

## Collectors

`scripts/Export-GpoEstate.ps1` produces the inputs (read-only PowerShell, run on
a DC/RSAT box). The tool consumes its output dir.

Read-only is enforced by `tests/test_collector_readonly.py`: it parses every
DC/RSAT-side script with the PowerShell AST (via `pwsh`) in two layers. The
**golden syntax tree** (`tests/powershell/collector-inventory.json`) is an
order-preserving serialization of each script's whole AST plus a source digest,
so *any* edit to a collector fails `test_inventory_matches_golden` until it is
regenerated with `python scripts/gen_collector_inventory.py` and the diff is
reviewed. The generator refuses to write unless the **semantic floor** passes:
strict per-script allowlists (commands, .NET calls, redirections, `using`/type
references, AST node types, local functions, exact scheduled-task argument
vectors), exact pinning of every binding of every write/receiver/exec variable
and its dependencies (`PINNED_VARS`), refusal of provider/global/automatic-
variable writes, the exact text plus control-flow context of every
command invocation, .NET method call and property access
(`GUARDED_OPS`), a type allowlist for every cast/`-as`/`-is`/
parameter-constraint/`[type]` construct (`check_cast_types`; computed types
refused), a digest of every local function body
(`LOCAL_FUNCTION_BODIES`) and of each script's param block
(`SCRIPT_HEADERS`), and the exact uses of secret-bearing variables
(`SECRET_USES`), every expression-valued pipeline input (`PIPELINE_INPUTS`),
and a digest of every statement of every block body (`STATEMENT_DIGESTS`).
These tables are hand-maintained; the generator never writes them (a test
enforces it). Because `STATEMENT_DIGESTS` covers every statement, **any**
collector edit fails the semantic layer until a human updates the tables:
print candidates with `python scripts/print_statement_digests.py`
(print-only, never wired into the generator), review them against the change,
and paste them in with a reason. The other checks remain the floor that still
refuses a harmful edit even when the digests are updated. Every reviewer bypass probe is a regression case in
`test_reviewer_probes_are_flagged` asserted to fail at its intended check and to
change the golden tree. Every PowerShell file under `scripts/` must be
classified. Locally the test skips when `pwsh` is absent; in CI it fails.

## Module map

| Module | Purpose |
|--------|---------|
| `model.py` | Dataclasses — the normalized contract |
| `normalize.py` | Pure helpers: `canonical_guid`, `load_json`, `parse_bool/int/dt` |
| `ingest.py` | Parse collector outputs → `Estate`. Also `parse_report_xml` for raw bytes (UTF-8/16), `load_baseline_from_zip` for Microsoft baseline zips, `augment_blocked_registry_from_pol` to resolve `<Blocked/>` Registry extensions from `Registry.pol` |
| `store.py` | SQLite persistence for snapshot history (additive schema migrations in `_migrate_schema`) |
| `queries/` (package) | Query composition, Tier 2/2.5 queries, estate_doctor, baseline diff, topology, conflicts. `__init__.py` is the re-export facade (backward-compatible `__all__`); composition logic lives in `_search`, `_delegation`, `_topology`, `_wmi`, `_settings`, `_baseline`, `_summary`, `_doctor` |
| `snapshot_diff.py` | SQLite-bound snapshot diffing — `snapshot_changelog`, `snapshot_settings_diff`, `snapshot_diff` |
| `detection/` (package) | Pure scanner functions — cpassword, MS16-072, version skew, broken refs, scheduled tasks, local-group mods, etc. Result types: `CpasswordHit`, `BrokenRef`, `AdmxGap`, `ScheduledTaskInfo`, `LocalGroupMod` |
| `registry_pol.py` | PReg binary parser — decodes `Registry.pol` files into `PregRecord`s (resolves `<Blocked/>` settings) |
| `danger.py` | Dangerous-configuration detectors — curated, cited Bucket 1 (setting-value rules) + Bucket 2 (structural attack-path) checks |
| `admx_parser.py` | ADMX/ADML template parser — builds registry-path → policy-name crosswalk for baseline diff |
| `display.py` | Table renderer |
| `report.py` | Markdown/HTML estate report generation |
| `events.py` | Append-only event store for tracking GPO estate changes |
| `sinks.py` | Event sinks for NDJSON file export and Splunk HEC |
| `query_dispatch.py` | Centralized query dispatch table (single source of truth for CLI and web) |
| `merge.py` | Per-CSE merge-resolution model + principal resultant (Plan 021). Token, security-gate eval, CSE merge modes |
| `redaction.py` | Ingest-time GPP `cpassword` redaction (element tree, stored JSON, inline text); `CPASSWORD_MARKER`, `CPASSWORD_FINDING_DETAIL` |
| `analyst_text.py` | Refuses analyst-typed text carrying GPP `cpassword` material (`check_analyst_text`); read-only `refusable_rows` scan for older rows |
| `trend.py` | Posture-over-time metrics from snapshot history — `compute_trend`, `changes_only`, `sparkline`, `TrendPoint` |
| `finding_model.py` | Plan 024 — durable finding identity protocol (`FindingCandidate`, `EvidenceRef`, `ClaimLevel`), fingerprint computation, occurrence/observation/triage data types, core query result types |
| `narration.py` | Tier 3 — LLM narration (`call_llm`, `explain_findings`, `route_question`). Optional; core never imports this |
| `web/` | FastAPI web UI — dashboard, GPO detail, ingest, ask, changelog, baseline diff, conflicts, estate-wide settings search (`/search`) |
| `cli/` | CLI package — argparse subcommands. Entry point: `cli._core:main` |

## Baseline diff

Microsoft ships Security Baselines as nested zips containing GPO backups.
`load_baseline_from_zip` handles the nesting.  Each GPO's `gpreport.xml`
is UTF-16 encoded — `parse_report_xml` detects the encoding.

Baseline settings are compared by `(side, cse, identity)` — the ADMX crosswalk
in `admx_parser.py` resolves registry paths back to policy names for display.

## Work tracking (issues)

Work-items for this project live in **regista** — the single source of truth. regista is the authoritative, signed, hash-chained event log; the local agent-notes store is a read projection of it. **Do not create physical breadcrumb files** (`breadcrumbs/`, `breadcrumbs/active/`, `*.breadcrumb.md`) — those are retired. This collapses the old two-surface split (markdown breadcrumb + DB `WI-NNN` with a `wi:` link field) that produced the WI-067 drift (breadcrumbs with no link to their work item). There is now one surface only.

**Agent face — the `agent-notes` CLI (and the `/file-breadcrumb` etc. skills).** Run from the project root so `--path .` resolves this project; the CLI routes to this project's regista schema automatically (you never set the schema).

```
# File an issue
agent-notes breadcrumb file --path . --title "<short title>" \
    --type <kind> [--severity low|medium|high|critical] [--body "<details>"]

# Find / show / update
agent-notes breadcrumb find  --path . [--status open] [--type bug] [--text "<q>"]
agent-notes breadcrumb get   --path . <WI-id>
agent-notes breadcrumb update --path . <WI-id> [--status <state>] [--title ...] [--body ...]
```

- **`--type` (kind):** todo, observation, decision, risk, task, bug, feature, improvement, question, experiment, spike, refactor, docs, ci, job.
- **`--severity`:** low, medium, high, critical.

**Lifecycle (canonical workflow):** `open → in_progress → (blocked | deferred) → in_review → in_human_review → done`. `done` is reachable only through the two-stage review gate (a cross-lineage adversarial-review pass, then accept), except a pre-work `close_from_open` dismissal (won't-fix / duplicate). "Who's working this" is a regista **claim** (a separate liveness axis), not a lifecycle state.

**Search before filing** — dedup is the store's main failure mode (the lesson of WI-067). Run `find` with `--text` before `file`. **Human face:** dossier — the web window onto these same items (when deployed).
