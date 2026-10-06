# Plan 024 — Durable finding identity, lifecycle, evaluation provenance, and triage

**Status:** Shipped in v1.1.0, hardened through v1.3.0; verified 2026-10-06. Evidence: [src/gpo_lens/finding_model.py](../src/gpo_lens/finding_model.py), [tests/test_plan024.py](../tests/test_plan024.py).

The durable identity/evaluation/occurrence/observation/triage protocol and core queries are implemented in `findings.py`, with typed identity fixes and SQL filtering. Schema v8 preserves legacy triage; v9 marks unstable subjects snapshot-scoped. Intrinsic evaluation is wired to ingest. Contextual series are supported by the core, but persisting baseline/golden workbench evaluations remains a gated follow-on, not a shipped UI workflow. Historical backfill is explicitly absent where exact provenance cannot be reproduced.

The design below is the historical specification; this status records the verified release scope.

**Depends on:** Plan 023 canonical identities and snapshot provenance vocabulary

**Strategic role:** Introduce durable analytical and operator-workflow state
without confusing local attention, current detector output, external comparison
runs, or estate facts.

## 1. Goal

Allow gpo-lens to say that a finding is new, persisting, resolved, regressed,
acknowledged, or accepted as risk—while preserving exactly which detector,
rules, catalogue, comparator, snapshot, and software version produced that
claim.

This is a new deterministic analytical subsystem, not a small UI migration.
Finding persistence and triage must be useful through core queries before the
Findings inbox in Plan 025 becomes the primary UI.

Plan 026 may export occurrence references as non-executable remediation handoffs
to GPO Studio. That integration does not grant Studio authority over Lens triage
and does not turn remediation prose into a proposed or publishable change.

## 2. Non-negotiable distinctions

Keep these entities separate:

- **Finding definition:** the typed rule/check and its version.
- **Evaluation run:** one execution against a snapshot and optional comparator.
- **Finding fingerprint:** detector-specific canonical identity of the issue.
- **Occurrence:** one continuous interval from first observed until resolved.
- **Observation:** presence or absence in one evaluation run.
- **Triage event:** append-only local operator action about an occurrence.
- **Estate fact:** immutable snapshot input from which an evaluation was derived.

An acknowledgment is a fact about operator attention, never evidence that the
estate changed. A resolved finding requires a comparable evaluation in which it
is absent; it is not inferred from deletion of a snapshot or failure to run a
detector.

## 3. Intrinsic versus contextual evaluations

### 3.1 Intrinsic findings

These are evaluated from one estate snapshot plus pinned analysis inputs:

- danger rules;
- cpassword and hygiene detectors;
- broken references;
- version skew;
- delegation and coverage checks;
- supported conflict/topology checks.

### 3.2 Contextual findings

These require an external comparison context:

- Microsoft or organizational baseline;
- golden GPO/estate;
- ADMX catalogue coverage;
- policy pack or future organizational rule set.

Contextual findings participate in lifecycle only when the comparator has a
stable type, canonical digest, and version. Uploading a different baseline is a
new evaluation series, not evidence that old findings resolved.

Delegation matrices, ADMX catalogue inventories, and comparison workbenches
remain useful analytical views even when selected rows also emit findings.

## 4. Canonical finding protocol

Every lifecycle-aware detector emits a typed record:

```python
@dataclass(frozen=True)
class FindingCandidate:
    detector_id: str
    detector_version: str
    category: str
    severity: str
    subject_type: str
    subject_key: tuple[str, ...]
    dimensions: tuple[tuple[str, str], ...]
    summary: str
    evidence_refs: tuple[EvidenceRef, ...]
    claim: ClaimLevel
```

The stable fingerprint is a versioned digest over canonical fields:

```text
fingerprint_version
detector_id
subject_type + complete subject_key
sorted identity-bearing dimensions
comparator series identity, when contextual
```

Severity, prose, remediation, and evidence location are not fingerprint fields.
Detector documentation must declare which dimensions distinguish multiple
findings on the same GPO, setting, trustee, SOM, or link.

Changing rule semantics requires a detector/rule version. Migration policy must
state whether the new version continues the old lifecycle series or starts a
new one; do not let a software update masquerade as remediation or regression.

Findings whose subjects cannot be stably identified remain explicitly
`snapshot_scoped` and cannot be acknowledged across snapshots.

## 5. Persistence model

Use additive migrations with foreign keys and indexed canonical digests.
Illustrative schema:

```text
analysis_input
  id, kind, canonical_digest, version, metadata_json

evaluation_run
  id, snapshot_id, evaluation_kind, detector_set_digest,
  comparator_input_id?, application_version, started_at, completed_at,
  status, error_summary

finding_definition
  detector_id, detector_version, category, title, reference

finding_occurrence
  id, fingerprint, fingerprint_version, series_key,
  first_seen_run_id, last_seen_run_id, resolved_run_id?, predecessor_id?

finding_observation
  run_id, occurrence_id, severity, summary, evidence_json, claim_level

finding_triage_event
  id, occurrence_id, action, actor, occurred_at, note,
  expires_at?, supersedes_event_id?
```

Requirements:

- One occurrence may have many observations.
- Resolution closes an occurrence; recurrence creates a new occurrence linked
  to its predecessor.
- Re-running an identical detector set against the same snapshot/comparator is
  idempotent or produces a separately identifiable run without duplicate
  occurrences.
- A failed or partial evaluation never resolves unseen findings.
- Deleting a snapshot follows explicit retention semantics and never rewrites
  audit history silently.
- Evidence stores bounded safe projections/references, never raw credentials.
- Schema migrations are failure-atomic and backup-tested.

## 6. Snapshot and analysis provenance

Record, when available:

- application build/version;
- collector/export version;
- detector and danger-rule digests;
- ADMX catalogue digest;
- comparator digest/version;
- evaluation start/end and completion state;
- input snapshot ID and source timestamp.

Old snapshots receive `unknown` provenance unless it can be derived exactly.
Backfill never synthesizes first-seen dates or rule versions.

The UI labels current reinterpretations of old snapshots separately from
recorded historical evaluations.

## 7. Lifecycle engine

For each completed comparable evaluation series:

1. Canonicalize and validate candidates.
2. Reject duplicate fingerprints within one detector result as a detector bug.
3. Match candidates to open occurrences in the same series.
4. Append observations and update `last_seen_run_id`.
5. Resolve unmatched open occurrences only if their detector completed
   successfully and coverage was sufficient for absence to be meaningful.
6. Create new occurrences for unmatched candidates, linking a resolved
   predecessor with the same fingerprint as a regression.
7. Commit evaluation, observations, occurrence transitions, and events in one
   transaction.

Coverage gaps may make absence indeterminate. Such occurrences remain open with
an `unobserved_due_to_coverage` state rather than being declared resolved.

## 8. Triage and authorization

Add permissions narrower than ingestion administration:

- `findings:comment` — append a note.
- `findings:acknowledge` — mark attention acknowledged.
- `findings:accept-risk` — record accepted risk.
- `findings:admin` — correct/supersede triage metadata under audit.

Do not grant snapshot upload or deletion merely because a user may acknowledge
a finding.

Triage actions are append-only events. Current status is a deterministic fold.
At minimum support:

- `commented`;
- `acknowledged`;
- `reopened`;
- `accepted_risk`;
- `risk_acceptance_expired`;
- `risk_acceptance_revoked`.

Accepted risk requires actor, rationale, timestamp, and optional/administratively
required expiry. It applies to one occurrence unless policy explicitly carries
it to a linked recurrence; the safe default is no automatic carry-forward.

Use forwarded-user attribution only through the existing trusted-proxy policy.
Never trust a caller-supplied identity header from an untrusted peer.

## 9. Core queries

Add deterministic queries independent of web templates:

- `finding_inbox(filters, as_of_run) -> list[FindingView]`;
- `finding_history(occurrence_id) -> FindingHistory`;
- `finding_delta(run_a, run_b) -> FindingDelta`;
- `accepted_risk_register(as_of) -> list[RiskAcceptance]`;
- `evaluation_runs(snapshot_id | series_key) -> list[EvaluationRun]`.

Filters include lifecycle, triage, category, severity, GPO, subject type,
evaluation series, comparator, and claim level. Pagination and stable ordering
are part of the query contract.

## 10. Migration and backfill

1. Add schema and candidate protocol without changing current views.
2. Adapt one narrow intrinsic detector family and qualify lifecycle behavior.
3. Expand detector adapters only after fingerprint review.
4. Backfill historical snapshots only for detectors whose exact inputs and
   versions are reproducible.
5. Mark all other lifecycle series as beginning at the first post-migration
   successful evaluation.
6. Add contextual evaluation series only after comparator persistence exists.

Each detector adapter documents its subject key, identity dimensions, rule
versioning, evidence projection, coverage requirements, and resolution logic.

## 11. Tests and adversarial review

- Same export ingested/evaluated repeatedly does not duplicate occurrences.
- One rule can emit multiple distinct findings for one GPO.
- Ordering changes do not affect fingerprints.
- Rule text/severity changes preserve identity when semantics do; semantic rule
  changes follow declared migration policy.
- Fixed, persisting, new, and regressed findings transition correctly.
- Partial/failed detector runs do not resolve findings.
- Coverage gaps produce indeterminate absence.
- Different baseline digests create separate contextual series.
- Triage events fold deterministically and survive re-evaluation.
- Expired risk acceptance re-enters the actionable inbox.
- Unauthorized identities cannot triage; trusted attribution is recorded.
- Evidence and audit payloads contain no known secret fixtures.
- Snapshot deletion, migration failure, backup, and restore preserve integrity.

Require an adversarial review of fingerprint collisions, rule-version drift,
coverage semantics, triage authorization, and migration rollback before the
Findings inbox becomes the default workflow.

## 12. Acceptance criteria

- [ ] Finding definition, evaluation, occurrence, observation, and triage are
      separate persisted concepts.
- [ ] Fingerprints include complete detector-specific canonical dimensions.
- [ ] Rule and comparator provenance prevents false lifecycle transitions.
- [ ] Failed or incomplete analysis never implies resolution.
- [ ] Triage uses dedicated least-privilege permissions and append-only events.
- [ ] Risk acceptance has rationale, actor, time, and expiry semantics.
- [ ] Intrinsic and contextual evaluations remain distinguishable.
- [ ] Historical backfill is exact or explicitly absent.
- [ ] Core queries are complete before Plan 025 makes the inbox primary.
- [ ] Tests, migration/restore evidence, security review, and identifier gate pass.
