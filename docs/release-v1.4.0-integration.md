# v1.4.0 candidate integration

The candidate starts at v1.3.1 commit `0a6b215` on
`release/v1.4.0-candidate`. Its release date and tag belong to the coordinator.
The five reviewed streams were merged with `--no-ff` and the repository hooks,
in the requested order. Both diffs against `origin/main` were read for every
shared file before resolving conflicts. No test or guard was removed.

| Stream | Candidate merge |
| --- | --- |
| F5 trends and calibration harness | `cb4b983` |
| F3 performance and connection hygiene | `e2dd92f` |
| F1 audit and Public Key parsing | `c692ad9` |
| F4 collection operations | `a0556dd` |
| F2 dependency inventory and noise reduction | `779e4bb` |

## Conflict decisions

| File | Conflicting merges | Resolution |
| --- | --- | --- |
| `CHANGELOG.md` | F3, F1, F4, F2 | Retain every stream's behavior and the v1.3.1 hotfix history. Consolidate into one v1.4 draft Unreleased section with Added, Changed, Fixed, Performance and Upgrade notes. |
| `tests/test_deployment.py` | F3, F1, F4 | Keep the stricter v1.3.0-section assertion from main, rather than allowing deployment terms anywhere in the changelog. |
| `tests/test_version.py` | F3, F1, F4, F2 | Retain F5's helper and all seven regression cases, require an explicit draft target and retain F3's latest-release ordering assertions. Reject F1/F4 fallbacks and F2's transitional current-package text as unnecessary for coordinated metadata. |
| `cli/_hygiene.py` | F2 | Import both `_add_secret_source` and `_get_admx`; retain SYSVOL-only credential registration and doctor template resolution. |
| `web/app.py` | F2 | Keep `Sequence` for multiple ADMX directories and F4's shared ZIP helper. Remove the obsolete `zipfile` import because extraction moved to `collection_zip.py`. Keep freshness configuration and dependency route registration. |

Other shared-file changes merged cleanly and were checked together:
F3's one-pass redaction preparation retains F5's numeric-material classification;
F1 audit/PKI/IEM findings coexist with F2's ADMX aggregation and evidence;
briefing keeps freshness/coverage warnings and severity-ordered dangers before
routine counts; CLI tables retain F5's header-independent projection. README and
handover retain collection instructions and distinguish 1.4 capabilities from
the published 1.3.1 behavior.

## Cross-feature regression coverage

- `tests/test_v14_integration.py`: audit/PKI ledger, search and findings exports
  retain configured values, provenance, byte determinism, credential redaction
  and equivalence to the original line transport. Findings export exactly one
  ADMX gap per GPO; audit/PKI-only settings produce no ADMX gaps. Stale briefing
  warnings coexist with critical-before-high ordering and immutable observation
  names, ahead of routine counts.
- `tests/performance_estate.py` and `tests/test_performance.py`: every seeded
  estate/comparator/upload includes audit, Public Key, drive and printer rows.
  SQL/time/determinism budgets include dependency Markdown/CSV exports at small
  and full scale. Existing provenance, redaction and findings budgets remain.
- `tests/test_exports.py`: the shared secret corpus occurs in dependency
  targets too; HTML and filtered/unfiltered Markdown/CSV matrices include the
  dependency view. CLI credential tests include dependencies and trends.
- `tests/test_broken_ref_redaction.py`: the no-secret differential guard covers
  every CLI read command, all fifteen export views in both formats, and NDJSON
  artifacts. Only ingest, server startup and interactive REPL are outside the
  read-command inventory. Omitted raw fields remain identical in the control
  pass; there are no read-command exemptions.
- `tests/test_plan025_navigation.py`: the exhaustive route equality check
  includes the dependency route, and its export contract is checked explicitly.
- `tests/test_calibrate.py`: the route/format inventory checks dependency HTML,
  Markdown and CSV, zero leaks, no auth/rate-limit responses, and initialization
  failure connection closure. Existing planted-leak/crash assertions remain.
- `tests/test_ingest.py`: dedicated Administrative Templates `EditTextBox`
  coverage asserts identity, policy name and the exact configured-value summary
  requested by WI-080.
- `tests/test_released_db_upgrades.py`: all older immutable fixtures remain;
  v1.3.1 adds preservation/idempotence and WAL backup/restore cases. Its manifest
  records tag commit `0a6b215bd3ddba7f857431e61e305b5bfa5275a0`, schema 9,
  two snapshots and three public-API triage events. The same generator created
  it in an isolated installed v1.3.1 checkout using CLI ingest, web ingest and
  released triage APIs; no schema was hand-built.

## Defects exposed by integration

1. F1's GPO loop variable collided with F2's optional lookup in doctor under
   mypy. Name the optional lookup `gap_gpo`; both behaviors remain.
2. F3's ResourceWarning and AST guards caught bare SQLite transaction contexts
   in F1/F2/F4/F5 tests and the F5 harness. Add explicit closing contexts while
   preserving transactions. Extend the harness's owning `try/finally` over
   initialization and scratch setup, so early failures close its connection.
3. F5 assigned an unused `max_requests` attribute. F2's added route formats
   exceeded the actual budget and late probes received 429 responses, hiding a
   planted leak. Set the harness's actual `_max_requests` budget; production
   defaults and guards stay intact.
4. F2 used the mutable occurrence GPO name for historical briefing dangers.
   Select `finding_observation.gpo_name` alongside observed severity/summary.

The package, lockfile and version-checked documents report 1.4.0. No runtime
dependency or schema migration was added by integration. CI push triggers are
unchanged. Tracker writes, PRs, tags and settings changes are outside this task;
only the candidate branch is authorized for push.

## Final validation protocol

Run the final gate set after the last source/document edit: Ruff lint/format,
mypy, the complete pytest coverage gate on Python 3.12/3.13/3.14, pip-audit of
the locked web/build closure, identifier gate, Pester 5.7.1, and Docker build
plus `deploy/container/smoke.py`. Also run the opt-in full-scale benchmark.
Preserve exact commands, exit codes and output in the final session transcript;
do not claim a gate passed from a partial or earlier run.
