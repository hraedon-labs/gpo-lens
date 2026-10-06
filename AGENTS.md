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
- **Import boundary:** Core modules (`model`, `normalize`, `ingest`, `store`, `queries`, `snapshot_diff`, `detection`, `admx_parser`, `display`, `report`, `events`, `sinks`, `query_dispatch`, `authz`, `topology`, `registry_pol`, `paths`, `danger`, `merge`, `trend`, `findings`, `finding_model`, `_legacy_findings`) must never import `narration` or `web`. An architecture test enforces this.

## Build / test / lint

```bash
uv venv && uv pip install -e ".[dev]"   # local dev
.venv/bin/pytest -q            # unit + calibration tests (sample tests skip if samples/ absent)
.venv/bin/pytest -q -m samples # calibration tests against the real exports (needs samples/)
.venv/bin/ruff check .
.venv/bin/ruff format .          # formatter is authoritative — see below
.venv/bin/mypy src
```

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

Slice 1 is **stdlib-only** (`xml.etree.ElementTree`, `json`, `sqlite3`,
`argparse`) — keep it dependency-free so the core stays portable/air-gappable.

## Collectors

`scripts/Export-GpoEstate.ps1` produces the inputs (read-only PowerShell, run on
a DC/RSAT box). The tool consumes its output dir.

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
