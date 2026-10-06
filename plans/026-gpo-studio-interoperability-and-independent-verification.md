# Plan 026 — GPO Studio interoperability and independent verification

**Status:** Not pursued for v1.3.0; coordinator disposition recorded 2026-10-06. Evidence: [src/gpo_lens/exports.py](../src/gpo_lens/exports.py), [tests/test_exports.py](../tests/test_exports.py).

Out of release scope per Plan 027. Markdown/CSV view exports are shipped, but the Studio artifact contracts, peer links, proposed-state analysis and independent publication verification described here are not implemented. This two-product program remains deferred to the Studio roadmap.

The design below is the historical specification; this status records the verified release scope.

**Depends on:** Plan 023 canonical setting identity for setting-level links;
Plan 024 only for durable finding handoff. GPO Studio Bundle v1 and publication
contracts remain owned by gpo-studio.

**Strategic role:** Define the narrow, worthwhile seam between the read-only
estate analyzer and the separate authoring/publication product without weakening
either trust boundary.

## 1. Decision

Integrate gpo-lens and gpo-studio through portable, versioned artifacts, stable
identities, optional deep links, and independent post-publication verification.

Do not merge the products, share their databases, add Studio write behavior to
Lens, or make either application's availability a requirement for the other's
core workflows.

The integration should support this lifecycle:

```text
independent collection
  → Lens observed snapshot and findings
    → portable baseline / remediation handoff
      → Studio unprivileged draft and review
        → explicit external publication boundary
          → independent collection after convergence
            → Lens semantic verification against the approved artifact
```

Lens describes observed state and bounded analytical claims. Studio describes
desired state, revisions, approvals, and publication intent. Neither silently
converts one category into the other.

## 2. Why integration is worthwhile

The two products have complementary strengths:

- gpo-lens already normalizes collected GPOs, settings, links, delegation,
  topology, findings, and history.
- gpo-studio already owns drafts, immutable revisions, deterministic policy
  serialization, review artifacts, and the future publication trust boundary.
- Reimplementing Lens analysis in Studio would create two topology, danger,
  conflict, and merge engines.
- Adding draft/publication state to Lens would compromise its valuable
  read-only charter.

The useful seam is therefore “facts and evidence out; desired artifact and
verification assertions back,” not shared application internals.

## 3. Permanent trust boundaries

### 3.1 Lens remains read-only

- No AD, SYSVOL, LDAP, SMB, WinRM, GroupPolicy, or Studio publisher write client
  is added to gpo-lens.
- Lens never submits, approves, schedules, retries, rolls back, or publishes a
  Studio job.
- A finding remediation is guidance or a handoff request, never executable
  mutation intent.
- “Open in Studio” is a user navigation affordance, not an API command that
  changes a workspace.

### 3.2 Studio remains the authoring owner

- Draft IDs, revisions, validation, approvals, signatures, publication jobs,
  and desired-state artifacts remain Studio concepts.
- Lens does not edit or re-sign Studio artifacts.
- Studio decides whether and how an observed baseline can be forked into an
  editable draft.

### 3.3 Verification remains independent

- Lens verifies a fresh collector snapshot, not the publisher's own read-back
  claim.
- Publisher receipts are evidence inputs, not proof of resulting estate state.
- A successful Studio job does not cause Lens to declare convergence.
- Missing collection coverage, replication uncertainty, unsupported CSEs, and
  semantic ambiguity lower the verification result.

## 4. Integration non-goals

- No shared SQLite file or cross-product table access.
- No Python import dependency between application packages.
- No mandatory always-on REST connection.
- No Studio iframe or privileged embedded UI inside Lens.
- No arbitrary callback/webhook URLs supplied by imported artifacts.
- No execution of `apply.ps1`, scripts, binaries, or macros contained in a
  Studio bundle.
- No claim that Lens can round-trip every Studio-supported or opaque CSE.
- No automatic “fix this finding” transformation into a publishable draft.
- No object-level RSoP claim or endpoint-convergence claim from OU topology
  alone.

## 5. Shared contract strategy

Prefer language-neutral schemas and test vectors over a shared runtime library.
The products may share a small schema package only after contracts stabilize
and only if it imports neither application.

### 5.1 Canonical identities

Shared test vectors cover:

- canonical GPO GUID: lowercase, braces and hyphens stripped;
- domain/SOM identifiers with explicit normalization rules;
- Plan 023 `SettingKey(side, cse, identity)` encoding;
- trustee SID canonicalization;
- snapshot, artifact, revision, and publication IDs as namespaced types, never
  interchangeable bare strings.

Friendly GPO, OU, policy, or principal names are labels, not join keys.

### 5.2 Digests and canonical JSON

- Every exchange artifact has a schema ID/version, canonical serialization
  rules, content digest, producer identity/version, created time, and declared
  audience/purpose.
- Digest fields use one published algorithm and cross-language test vectors.
- Volatile display fields are either excluded from semantic identity or their
  inclusion is explicit.
- Signatures are optional for offline local exchange initially; managed
  workflows require signature and trust-policy verification owned by Studio.

### 5.3 Compatibility policy

- Readers reject unsupported major versions and unknown security-critical
  fields.
- Additive optional fields require fixtures proving old-reader behavior.
- Every release publishes minimum/maximum supported exchange schema versions.
- Schema evolution never reinterprets an old artifact without migration
  provenance.

## 6. Artifact A — Portable observed-estate baseline

Define a product-neutral `gpo-estate-snapshot-v1` bundle exported by Lens and
consumable by Studio or other offline tools.

Illustrative contents:

```text
manifest.json
estate.json
settings.ndjson
links.ndjson
delegation.ndjson
topology.ndjson
coverage.json
analysis-provenance.json
```

The manifest includes:

- snapshot ID and canonical snapshot digest;
- source domain identifier and collection time;
- Lens and collector versions;
- schema versions;
- included/omitted datasets;
- coverage gaps and known blind spots;
- ADMX/rule-set digests where relevant;
- per-entry content digests and size/count bounds.

Requirements:

- Export comes from an immutable named Lens snapshot, never an unqualified
  moving “latest” once generation begins.
- The normalized estate is deterministic for that snapshot.
- `Setting.raw` is excluded by default. Any future evidence section uses the
  Plan 023 safe projection and explicit purpose.
- Findings and triage are not part of the baseline identity; Plan 024 finding
  handoff is a separate optional artifact.
- Unknown/opaque settings are preserved as bounded opaque descriptors where
  possible, but never relabeled as Studio-editable.
- Coverage gaps travel with the artifact and are prominent on Studio import.
- Export is portable ZIP with safe names, fixed ordering/timestamps where
  byte determinism is claimed, and strict size/count limits.

Studio may import the snapshot as a read-only baseline and fork only supported
content into a draft. Unsupported content remains visible and loss warnings are
release-blocking for any purported full-GPO fork.

## 7. Artifact B — Finding/remediation handoff

After Plan 024, Lens may export a non-executable handoff describing one or more
finding occurrences.

```python
@dataclass(frozen=True)
class RemediationHandoff:
    schema_version: str
    source_snapshot_digest: str
    finding_occurrences: tuple[FindingReference, ...]
    affected_subjects: tuple[SubjectReference, ...]
    safe_evidence: tuple[EvidenceReference, ...]
    remediation_guidance: tuple[str, ...]
    claim_limits: tuple[str, ...]
```

Requirements:

- No proposed registry value, link mutation, ACL edit, script, or publisher
  operation is inferred unless a human authors it in Studio.
- Finding fingerprints, detector/rule versions, and evidence references are
  preserved.
- Acknowledgment or accepted-risk state is included only when authorized and
  is never treated as Studio approval.
- Studio records the handoff digest and source finding references when creating
  a draft, preserving traceability without making Lens the draft owner.
- A later Studio change may address, partially address, supersede, or reject the
  guidance; that disposition belongs to Studio workflow.

## 8. Artifact C — Proposed-state analysis request/result

Allow Studio to ask Lens's deterministic core to analyze a proposed artifact
offline before publication, without storing it as an observed snapshot.

### 8.1 Scenario model

Introduce a separate `ProposedEstateScenario` or equivalent:

- observed Lens snapshot digest;
- Studio artifact/revision digest;
- explicit overlay operations;
- target GPO/SOM bindings;
- representability and coverage warnings;
- scenario-local provenance.

Never insert a proposal into the ordinary snapshot table or history. Templates,
queries, APIs, and exports label it **proposed**, not observed/current.

### 8.2 Supported initial analysis

Start only with semantics both products can represent exactly:

- setting-level before/after diff;
- disabled-but-populated checks;
- duplicate/conflicting setting definitions;
- supported danger rules;
- link-intent/topology analysis when target bindings exist;
- supported OU-level precedence and conflict effects with standard caveats.

Unsupported CSEs, opaque content, security filters, WMI, ILT, sites, principal
tokens, or incomplete coverage yield `unknown/conditional`, not a clean result.

### 8.3 Execution forms

Preferred initial form:

```text
gpo-lens scenario analyze \
  --snapshot <id> \
  --studio-bundle <path> \
  --out analysis-result.json
```

An optional local API may follow the same schema later. File exchange remains
the reference path, keeping both tools independently usable and air-gappable.

## 9. Artifact D — Post-publication verification assertion

Studio's approved publication artifact should carry typed verification
assertions, not a request for Lens to trust “job succeeded.” Examples:

- expected semantic setting keys/values;
- expected Computer/User side state;
- expected GPO identity and version transition;
- expected link target/order/enforced/enabled state;
- allowed unchanged opaque-content digests;
- explicit verification deadline/convergence window;
- artifact, revision, proposal, publication job, and target identifiers.

After publication and the configured replication/convergence interval:

1. An independent collector produces a new estate export.
2. Lens ingests it through the normal read-only path with coverage checks.
3. Lens compares the fresh snapshot against verification assertions and the
   pre-publication observed snapshot.
4. Lens emits a deterministic verification result referencing all three
   digests: prior snapshot, approved artifact, and observed snapshot.

Result states include:

- `verified` — every supported assertion observed with sufficient coverage;
- `diverged` — supported observed state conflicts with the assertion;
- `partial` — some assertions verified, others not;
- `indeterminate` — collection, replication, unsupported semantics, or
  provenance prevents a claim;
- `not_yet_converged` — within the declared bounded convergence window.

Lens does not mark a Studio workflow complete. Studio or a provenance system
may consume the signed/digested result according to its own policy.

## 10. Stable deep links

Deep links improve operator flow but remain optional conveniences.

Lens may expose configured links such as:

- GPO dossier → Studio read-only imported baseline/draft selector;
- finding occurrence → Studio remediation-handoff import page;
- verification result → Studio artifact/publication record;
- Studio revision → Lens scenario analysis result or observed GPO dossier.

Rules:

- Base URLs are deployment configuration, never accepted from artifacts.
- Query strings contain opaque IDs/digests only, not domain names, DNs,
  evidence, credentials, or draft content.
- Links do not mutate state through GET.
- Missing/unconfigured peer applications degrade to copyable IDs or artifact
  download, not broken core functionality.
- Authentication/session credentials are never transferred between products.

## 11. Security and parser boundary

Treat every cross-product artifact as hostile input, even when signed.

- Streaming ZIP inspection with compressed/uncompressed size, file count,
  nesting, path, and compression-ratio limits.
- Reject traversal, symlinks, devices, duplicate names, case-colliding names,
  and unexpected executable content.
- Never execute or import `apply.ps1` or embedded scripts from a Studio bundle.
- Parse only allow-listed manifest and policy formats required for the analysis.
- Verify declared digests before semantic use.
- Bound JSON depth, strings, arrays, numeric ranges, and NDJSON records.
- Escape all displayed artifact content.
- Imported artifacts never select callback URLs, filesystem destinations,
  network endpoints, or authentication principals.
- Fuzz and maintain malicious-archive fixtures in both projects.

## 12. Ownership and companion work

This plan governs Lens contracts and behavior. Companion implementation plans
in gpo-studio own:

- baseline import/fork behavior;
- draft provenance fields;
- Studio-side scenario artifact emission;
- verification assertions in Studio artifacts;
- consumption of Lens verification results;
- Studio UI and approval-policy effects.

Cross-project schema fixtures live in one designated schema repository/package
or are mirrored with digest checks. Do not allow hand-copied schemas to drift.

## 13. Phased delivery

### Phase 0 — Contract and corpus

- Inventory overlapping models and deliberately incompatible concepts.
- Freeze canonical GUID/SettingKey/canonical-JSON test vectors.
- Decide schema ownership and compatibility policy.
- Build synthetic cross-product fixtures with no work-domain identifiers.
- Threat-model artifact parsing and deep links.

### Phase 1 — Observed baseline export/import

- Implement deterministic `gpo-estate-snapshot-v1` export in Lens.
- Add Studio read-only baseline import in its companion plan.
- Prove unsupported content and coverage gaps cannot disappear silently.
- No draft generation until loss accounting is explicit.

### Phase 2 — Finding handoff and deep links

- Requires Plan 024 stable finding occurrences.
- Export bounded remediation handoff.
- Add optional configured deep links and no-peer fallbacks.
- Prove no GET link mutates either product.

### Phase 3 — Proposed scenario analysis

- Add separate proposed-state scenario type and CLI.
- Support registry-setting diff/danger checks first.
- Expand only with per-CSE representability evidence.
- Never store proposals as observed snapshots.

### Phase 4 — Independent post-publication verification

- Agree typed verification assertions with Studio.
- Compare independently collected snapshots.
- Emit deterministic `verified/diverged/partial/indeterminate/not_yet_converged`
  results with digests and claim limits.
- Qualify replication delay, partial collection, and rollback scenarios in the
  Windows interoperability lab.

### Phase 5 — Managed evidence exchange, only if warranted

- Optional signed artifact/result transport through an external provenance or
  job system.
- No direct publisher authority in Lens.
- File/CLI exchange remains supported and independently testable.

## 14. Test and evidence program

- Cross-language canonical identity and digest vectors.
- Deterministic export bytes for fixed snapshot/provenance inputs.
- Round-trip normalized supported settings without changing identity or value.
- Explicit retained-opaque and lost/unrepresentable content reports.
- Coverage-gap propagation from Lens to Studio and back into verification.
- Malicious ZIP/JSON corpus and fuzzing.
- No secret/raw-evidence leakage across artifacts, logs, UI, or errors.
- Proposed scenario never appears in observed snapshot/history queries.
- Studio job receipt alone cannot produce `verified`.
- Independent snapshot detects expected success, divergence, partial
  application, delayed replication, rollback, and inaccessible GPOs.
- Old/new schema reader matrix and migration fixtures.
- Both products remain fully usable with the peer absent.

## 15. Success measures

- Studio can begin from a named observed Lens snapshot without re-parsing or
  silently dropping Lens-known content.
- A Lens finding can be handed to Studio with traceability but no executable
  authority.
- Supported proposed changes receive deterministic pre-publication analysis.
- Post-publication claims are based on independent collection and explicit
  assertions, not publisher self-report.
- Operators can navigate between related records without transferring secrets
  or coupling sessions.
- Neither product imports the other or shares its database.
- Lens remains credibly read-only and Studio remains the sole authoring owner.

## 16. Acceptance criteria

- [ ] Permanent trust boundaries and non-goals are preserved mechanically.
- [ ] Canonical identities, JSON, digests, and schema compatibility have shared
      test vectors.
- [ ] Observed baseline bundles carry coverage and provenance and exclude raw
      evidence by default.
- [ ] Finding handoff is non-executable and depends on stable Plan 024 occurrences.
- [ ] Proposed scenarios are never represented as observed snapshots.
- [ ] Verification requires an independently collected post-publication snapshot.
- [ ] Verification results express partial and indeterminate outcomes honestly.
- [ ] Deep links are optional, non-mutating, and contain no sensitive content.
- [ ] Artifact parsers pass hostile-input and resource-bound tests.
- [ ] Both products operate independently when the integration is absent.
