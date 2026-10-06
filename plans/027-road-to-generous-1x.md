# Plan 027 — Road to the generous 1.x: final release reconciliation

**Status:** Shipped in v1.3.0; verified 2026-10-06 on the release candidate (release date set by coordinator). Evidence: [src/gpo_lens/web/templates/base.html](../src/gpo_lens/web/templates/base.html), [tests/test_released_db_upgrades.py](../tests/test_released_db_upgrades.py).

## Release scope and final state

Reconciled against `release/v1.3.0-candidate` on **2026-10-06**. “Shipped in
v1.3.0” below means implemented for this release; the coordinator still owns
version metadata, the release date/tag, tracker acceptance and deployment.
This docs pass does not create those artifacts or claim the release is already
running at work. Package metadata currently reports **1.2.0**; it must become
1.3.0 in the coordinator's release step.

| Phase / stream | Final state and evidence |
|----------------|--------------------------|
| Phase 0 — findings foundations | Shipped v1.1.0; `finding_model.py`, `findings.py`, `tests/test_plan024.py`; see CHANGELOG v1.1.0. |
| Phase 1 — identity, filtering and triage correctness | Shipped v1.1.0 and hardened for v1.3.0: typed identities, shared SQL predicates, batch triage, schema v8/v9; `tests/test_doctor_contract.py`, `tests/test_plan024.py`, `tests/test_findings_inbox.py`. The single-estate-per-store rule is now explicit in README. |
| Phase 2 / S2 — Plan 025 WI-1–5 | Inbox, briefing, directories, five-destination navigation, retained bookmarks and optional signed page explanations; `5549855`, integration `e1f4754`; `tests/test_plan025_navigation.py`, `tests/test_page_narration.py`. |
| Phase 2 / S1 — Plan 025 WI-6 | Deterministic Markdown/CSV exports in web/CLI; `20ecaa3`, `f5d30fb`, integration `d271cf7`; `tests/test_export_rendering.py`, `tests/test_exports.py`. |
| Phase 3 / S3 — WI-086 | Non-root container, Compose, optional TLS proxy and hardened systemd; `02bf7ea`, integration `fb9c99c`; `deploy/container/`, `deploy/systemd/`, `tests/test_deployment.py`, `deploy/container/smoke.py`. |
| S4 — upgrade evidence and WI-093 | Actual released-database migrations and WAL-safe restore tests (`2c86942`); targeted inbox ID query and output/benchmark evidence (`41721fe`); integration `a6cc995`. |
| WI-3.2 — docs describe the product | README, deployment index, v1.3.0 handover, grouped Unreleased changelog and every plan status reconciled in this pass; see status table below. |
| WI-3.3 — close the loop | Read-only tracker inventory and proposed dispositions below. Coordinator applies review/accept transitions, dates/tags the release and deploys it. |

## Definition of done

- [x] Findings foundations integrated and covered by core/inbox tests (Phase 0 above). Prior work rollout is recorded in CHANGELOG v1.1.0; a new v1.3.0 rollout is not assumed.
- [x] Plan 024 sharp correctness debt paid: typed fingerprint dimensions, SQL-before-LIMIT filtering, indexes, batch triage, legacy-row exclusion and unstable-subject honesty; `tests/test_plan024.py`, `tests/test_doctor_contract.py`.
- [x] Plan 025 release scope implemented: Briefing / Findings / Explore / History / Tools, retained URLs, supported historical views, configured-settings search, dossier/setting views, demoted web narration and deterministic exports. See its final acceptance checklist.
- [x] Non-IIS deployment exists and has smoke/static coverage — deployment guides, `tests/test_deployment.py`, container CI job and smoke script.
- [x] Documentation matches the branch and no shipped plan still claims proposed — WI-3.2 status table, README command verification and local-link checks.
- [x] Local lint, format, type, coverage, supply-chain and identifier checks recorded in [exact gate evidence](../docs/release-v1.3.0-verification.md).
- [x] All nonterminal tracker items have an evidence-backed proposed disposition below; no tracker writes were made.
- [ ] Coordinator: independent review and tracker transitions through `in_review → in_human_review → done`; deferred items remain deferred. The tracker is not yet “zero open non-deferred WIs”.
- [ ] Coordinator: bump package metadata, set the v1.3.0 date, run authoritative release CI, tag/release and deploy lab → work with backup/restore and legacy-navigation rollback exercised. This branch's docs status is not deployment evidence.

## Explicit dispositions and implementation limits

- **Plan 026 / WI-059:** not pursued for v1.3.0, per coordinator. Studio
  interop and multi-estate comparison remain out of scope.
- **Plan 028:** deferred; module decomposition carries risk before a
  production handover. `findings.py` and `ingest.py` remain modules.
- **WI-058:** deferred; gMSA scheduling needs live-AD validation, and the
  homelab has a known KDS/gMSA defect. A unit-tested scheduling helper would
  not discharge that prerequisite; this pass adds none.
- **Plan 016:** the old assertion that Splunk attribution was in `src/` was
  incorrect. `events.py` and `sinks.py` deliver outbound snapshot events,
  not actor-attributed Splunk imports. No change-event model/table, importer,
  correlation queries or Activity route is present. Attribution is not
  pursued for v1.3.0; the outbound sinks remain shipped Plan 012 features.
- **Plans 022/023:** the consolidation and reading primitives are present;
  their older workflow/navigation/identity designs are superseded by Plans
  024/025. Broad entity omnisearch and a global historical snapshot axis
  (notably OU selection) did not ship. Current search covers configured
  settings; historical selection is offered by specific views. The dedicated
  Plan 022 WI-1 async-store AST/concurrent-response tests are also absent.
- **Plan 024:** core contextual series/provenance exists, but baseline/golden
  workbenches do not yet persist contextual evaluations into the inbox.
  Exact comparison-run deep links remain follow-on work. The release does
  not claim otherwise or introduce a new analysis engine.

## WI-3.3 read-only tracker inventory

Read with `agent-notes work-item find` and **individual**
`agent-notes work-item get <id> --path /projects/gpo-lens --json` on 2026-10-06.
The requested `--path .` returned `PROJECT_NOT_RESOLVED` because this worktree
is not registered; the canonical project path resolves the same gpo-lens
projection. No init, reconcile/apply, claim, comment, file or update was run.
All nonterminal items from the complete find result are included, including
WI-085 (already deferred). “Done after review” is a recommendation, not an
acceptance or a tracker-state mutation.

| WI | Observed status | Proposed final disposition | Branch evidence / remaining prerequisite |
|----|-----------------|----------------------------|------------------------------------------|
| WI-058 | open | Deferred beyond v1.3.0 | Coordinator disposition: live-AD validation required; known homelab KDS/gMSA defect. No scheduling implementation in `scripts/`. |
| WI-059 | open | Deferred / out of v1.3.0 scope | Plan 027 scope decision; single-estate README limit; `docs/design/multi-domain-forest.md` is future design. |
| WI-080 | in_review | Done after independent review and accept | Configured AdminTemplates values are parsed; `src/gpo_lens/ingest.py`, `tests/test_ingest.py`, CHANGELOG v1.0.0 WI-080. |
| WI-082 | in_review | Done after independent review and accept | `web/routes/search.py`, `tests/test_web_search.py`, CHANGELOG v1.0.0 WI-082; settings-scoped search, not broad omnisearch. |
| WI-083 | in_review | Done after independent review and accept | `web/templates/ou_detail.html`, inline filtering in `web/templates/ou_detail.html`, `tests/test_ui_regression.py`, CHANGELOG v1.0.0 WI-083. |
| WI-085 | deferred | Done after review, if coordinator accepts the performance evidence | `pytest-xdist`, `addopts = "-q -n auto"` in `pyproject.toml`; CI has no 120-second test-job timeout. Fresh full-suite duration is in verification evidence; do not promise a fixed runtime on every host. |
| WI-086 | in_review | Done after independent review and accept | `02bf7ea` / `fb9c99c`; deployment guides, unit, image, smoke script and `tests/test_deployment.py`. |
| WI-087 | in_review | Done after independent review and accept | `PENDING-REGISTA-WI.md` absent; `tests/test_web.py::test_concurrent_upload_returns_409` explicitly acquires/releases the lock; CHANGELOG v1.0.0 records deterministic 409 coverage. |
| WI-093 | in_review | Done after independent review and accept | `41721fe`, `web/routes/findings.py::_latest_snapshot_gpo_ids`, `tests/test_findings_inbox.py::TestLatestSnapshotGpoIds`; synthetic inbox output and targeted-query benchmark pinned. |
| WI-096 | in_review | Done after independent review and accept | `5549855` / `e1f4754`, navigation inventory/bookmark/accessibility tests and bounded page-narration tests. Work rollout is a separate coordinator gate. |
| WI-097 | in_review | Done after independent review and accept | `20ecaa3`, `f5d30fb`, `tests/test_export_rendering.py`, `tests/test_exports.py`; deterministic redaction, authorization and filtered provenance tests. |
| WI-098 | in_review | Done after independent review and accept | `d271cf7` integrates S1 into the candidate; integrated full gates recorded in verification evidence. No release tag/production deployment implied. |

## WI-3.2 plan-status audit

Every file in `plans/` was checked against `src/`, tests, commit history and
CHANGELOG. Status dates are **2026-10-06 verification dates**, not invented
release dates. Earlier release versions follow CHANGELOG; the coordinator
will date v1.3.0. Links identify the present implementation or its replacement;
partial/not-pursued rows explicitly state missing scope in their own headers.

| File | Old status | New status | Evidence |
|------|------------|------------|----------|
| [007-tier25-topology-and-hygiene.md](007-tier25-topology-and-hygiene.md) | (absent) | Shipped in v0.1.0 | [src/gpo_lens/topology.py](../src/gpo_lens/topology.py), [tests/test_topology.py](../tests/test_topology.py) |
| [008-baseline-diff-framework.md](008-baseline-diff-framework.md) | (absent) | Superseded by GPO-backup baseline comparison (shipped by v0.1.0) | [src/gpo_lens/queries/_baseline.py](../src/gpo_lens/queries/_baseline.py), [tests/test_cli_diff.py](../tests/test_cli_diff.py) |
| [009-som-resolution-deep-view.md](009-som-resolution-deep-view.md) | (absent) | Shipped in v0.1.0 | [src/gpo_lens/topology.py](../src/gpo_lens/topology.py), [tests/test_topology.py](../tests/test_topology.py) |
| [010-capability-roadmap.md](010-capability-roadmap.md) | proposed 2026-06-09 | Partially shipped across v0.1.0–v0.3.0 | [src/gpo_lens/snapshot_diff.py](../src/gpo_lens/snapshot_diff.py), [tests/test_narration_integration.py](../tests/test_narration_integration.py) |
| [011-remediation-and-scope-honesty.md](011-remediation-and-scope-honesty.md) | proposed 2026-06-10 | Partially shipped across v0.2.2–v0.6.1 | [src/gpo_lens/topology.py](../src/gpo_lens/topology.py), [tests/test_fixtures.py](../tests/test_fixtures.py) |
| [012-local-web-ui.md](012-local-web-ui.md) | proposed 2026-06-10 | Partially shipped by v0.3.0, with hosting in v0.6.0 | [src/gpo_lens/events.py](../src/gpo_lens/events.py), [tests/test_web_auth.py](../tests/test_web_auth.py) |
| [013-scope-honesty-and-consolidation.md](013-scope-honesty-and-consolidation.md) | proposed 2026-06-13 | Shipped in v0.3.0 | [src/gpo_lens/topology.py](../src/gpo_lens/topology.py), [tests/test_scope_honesty.py](../tests/test_scope_honesty.py) |
| [014-site-linked-gpos.md](014-site-linked-gpos.md) | proposed 2026-06-14 | Shipped in v0.4.0 | [src/gpo_lens/ingest.py](../src/gpo_lens/ingest.py), [tests/test_sites.py](../tests/test_sites.py) |
| [015-coverage-reconciliation.md](015-coverage-reconciliation.md) | proposed 2026-06-14 | Shipped in v0.4.0 | [src/gpo_lens/ingest.py](../src/gpo_lens/ingest.py), [tests/test_coverage.py](../tests/test_coverage.py) |
| [016-splunk-change-attribution.md](016-splunk-change-attribution.md) | proposed 2026-06-17 | Not pursued for v1.3.0 | [src/gpo_lens/events.py](../src/gpo_lens/events.py), [tests/test_sinks.py](../tests/test_sinks.py) |
| [017-directory-search-and-scoping.md](017-directory-search-and-scoping.md) | shipped (v0.6.1) 2026-06-18 | Partially shipped in v0.6.1 | [src/gpo_lens/web/routes/ou.py](../src/gpo_lens/web/routes/ou.py), [tests/test_web.py](../tests/test_web.py) |
| [018-admx-policy-names-and-dangerous-config-detectors.md](018-admx-policy-names-and-dangerous-config-detectors.md) | shipped (v0.6.1) 2026-06-18 | Shipped in v0.6.1 | [src/gpo_lens/danger.py](../src/gpo_lens/danger.py), [tests/test_danger.py](../tests/test_danger.py) |
| [019-scope-resultant-and-gate-attribution.md](019-scope-resultant-and-gate-attribution.md) | shipped (v0.6.3) 2026-06-18 | Partially shipped in v0.6.3 | [src/gpo_lens/topology.py](../src/gpo_lens/topology.py), [tests/test_topology.py](../tests/test_topology.py) |
| [020-principal-resolution.md](020-principal-resolution.md) | shipped (v0.6.3) 2026-06-18 | Partially shipped in v0.6.3 | [src/gpo_lens/authz.py](../src/gpo_lens/authz.py), [tests/test_principal_resultant.py](../tests/test_principal_resultant.py) |
| [021-snapshot-rsop-and-merge-model.md](021-snapshot-rsop-and-merge-model.md) | shipped (v0.6.3) 2026-06-18 | Shipped in v0.6.3 | [src/gpo_lens/merge.py](../src/gpo_lens/merge.py), [tests/test_principal_resultant_boundary.py](../tests/test_principal_resultant_boundary.py) |
| [022-web-responsiveness-and-pattern-consolidation.md](022-web-responsiveness-and-pattern-consolidation.md) | Proposed 2026-07-01 | Superseded by Plans 024/025 for the web workflow; consolidation shipped in v1.0.0 | [src/gpo_lens/web/templates/ou_detail.html](../src/gpo_lens/web/templates/ou_detail.html), [tests/test_registry_cse_guard.py](../tests/test_registry_cse_guard.py) |
| [023-web-reimagining.md](023-web-reimagining.md) | Proposed 2026-07-11 (for external model review before work begins) | Superseded by Plans 024 and 025; foundations shipped in v1.1.0 and completion scope in v1.3.0 | [src/gpo_lens/queries/_settings.py](../src/gpo_lens/queries/_settings.py), [tests/test_ledger.py](../tests/test_ledger.py) |
| [024-finding-identity-lifecycle-and-triage.md](024-finding-identity-lifecycle-and-triage.md) | Proposed; requires dedicated model and adversarial review | Shipped in v1.1.0, hardened through v1.3.0 | [src/gpo_lens/finding_model.py](../src/gpo_lens/finding_model.py), [tests/test_plan024.py](../tests/test_plan024.py) |
| [025-question-oriented-ia-and-exports.md](025-question-oriented-ia-and-exports.md) | In Progress — WI-1/2/3 **merged to `main` 2026-08-07**; WI-4, WI-5, and WI-6 remain open and are the bulk of what is left. | Shipped in v1.3.0 | [src/gpo_lens/web/templates/base.html](../src/gpo_lens/web/templates/base.html), [tests/test_exports.py](../tests/test_exports.py) |
| [026-gpo-studio-interoperability-and-independent-verification.md](026-gpo-studio-interoperability-and-independent-verification.md) | Proposed integration charter and phased execution plan | Not pursued for v1.3.0 | [src/gpo_lens/exports.py](../src/gpo_lens/exports.py), [tests/test_exports.py](../tests/test_exports.py) |
| [027-road-to-generous-1x.md](027-road-to-generous-1x.md) | In progress. Proposed 2026-07-14; status reconciled with `main` 2026-08-07. | Shipped in v1.3.0 | [src/gpo_lens/web/templates/base.html](../src/gpo_lens/web/templates/base.html), [tests/test_released_db_upgrades.py](../tests/test_released_db_upgrades.py) |
| [028-module-decomposition.md](028-module-decomposition.md) | Proposed 2026-08-07 | Not pursued for v1.3.0 | [src/gpo_lens/findings.py](../src/gpo_lens/findings.py), [src/gpo_lens/ingest.py](../src/gpo_lens/ingest.py) |

## Release and rollback rules

Back up the database **and** separate `audit.log` before upgrade. Actual
released database fixtures cover v0.5.0, v0.7.0, v0.7.1, v1.0.0, v1.1.0 and
v1.2.0; online restore is tested with committed WAL changes. Rollback restores
the matching old backup and runs the matching old code, rather than reopening
a migrated database with older code. See the [handover](../docs/handover.md)
and [deployment index](../deploy/README.md).

Retain `GPO_LENS_LEGACY_NAV=1` as the navigation rollback during rollout;
bookmarks stay meaningful because existing handlers and query parameters are
retained. Production state and final tracker acceptance belong to the
coordinator, independently of this documentation commit.
