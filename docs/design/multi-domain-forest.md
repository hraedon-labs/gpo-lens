# Design — Multi-domain/forest support: the swimlane model (WI-059)

**Status:** design draft (post-1.0); not implemented (no `MultiEstate`, `CrossDomainLink` or `multi-estate` command exists in the code)  
**Author:** coding agent, from the enterprise-adoption boundary review  
**Scope:** data model, ingestion, queries, CLI/web presentation  
**Related work item:** WI-059 — Multi-estate comparison (post-1.0)  

## Strategic role

The `Estate` data model is deliberately single-domain. That was the right v1
decision: it gets honest, calibrated answers quickly without cross-domain trust
semantics, SID history or universal-group resolution. But enterprise AD is
almost always multi-domain. To be adopted at that scale, gpo-lens must reason
about more than one domain in a forest without giving up its local-first,
read-only posture.

This document proposes the **swimlane model**: keep each domain as an
independent `Estate`, add a thin `MultiEstate` coordination layer, and detect
and warn on cross-domain GPO links. It is cheaper than a true multi-forest
refactor because every existing single-domain analysis is reused. The price is
that cross-domain *policy flow* (a GPO in domain A applied through a link in
domain B) is flagged, not simulated, which keeps the charter's *flag, don't
simulate* discipline.

## Ground truth at time of writing

- **`model.Estate`** represents one domain snapshot. Its `domain` field is a
  string, and the code assumes every `Gpo.domain`, `Som.path`, `OuRecord.dn`
  and principal/group SID belongs to that one domain.
- **`Gpo.links`** carry `som_path` strings, which in a single-domain export are
  always DNs inside the same domain. A cross-domain link would appear as a
  `gpo_id` from domain A paired with a `som_path` from domain B, and today it
  would be handled inconsistently depending on which `Estate` ingested it.
- **`merge.principal_resultant`** builds tokens from `estate.group_members` and
  `estate.principals` and resolves the principal's OU chain from
  `estate.soms`. It cannot see group membership or SOMs in another domain.
- **`topology` and `queries`** all operate on one `Estate`. Conflict detection,
  baseline diff, estate doctor, hygiene and dangerous-config detection are
  intra-domain by construction.
- The collector, `scripts/Export-GpoEstate.ps1`, collects the current domain
  (`Get-ADDomain`) and has no domain parameter. Its parameters are
  `-OutputRoot`, `-SkipSysvol`, `-NoZip` and `-DryRun`. Multi-domain collection
  means running it once per domain, from a host in each, or adding a domain
  parameter.

## Charter addendum (decisions this design records)

1. **Swimlanes stay independent.** Each domain keeps its own `Estate`. Don't
   merge GPOs, SOMs, principals or settings into one graph; independence keeps
   the existing analysis correct.
2. **Cross-domain links are warnings, not resolved flows.** When a GPO from
   domain A is linked to a SOM in domain B, the tool emits a `cross_domain`
   finding. It does not compute domain B's resultant using domain A's GPO.
3. **Trust relationships are out of scope for v2.0.** Forest trusts, external
   trusts, selective authentication and UPN suffix mappings appear in caveats
   but are not modeled.
4. **Coverage honesty applies per swimlane.** Each `Estate` has its own
   `coverage_gaps`. A missing trust or an inaccessible domain is reported as a
   gap.
5. **Cross-domain comparison adds to single-domain comparison.** The existing
   `snapshot_diff` and baseline-diff views stay unchanged. Multi-domain compare
   is a new surface that aligns settings by `(cse, identity)` across `Estate`
   boundaries.

## The swimlane model

```text
+----------------------------------+
|          MultiEstate             |
|  { "corp.example"   -> Estate,   |
|    "child.example"  -> Estate,   |
|    "other.example"  -> Estate }  |
+----------------------------------+
        |          |          |
   [independent per-domain analysis]
        |          |          |
   hygiene doctor conflicts baseline
        |          |          |
        +-----+----+----------+
              |
   [coordination layer: cross-domain links, compare]
```

### Data-model changes

- Add a `MultiEstate` dataclass (in `model.py`) holding:
  - `estates: dict[str, Estate]` keyed by canonical domain name.
  - `cross_domain_links: list[CrossDomainLink]`.
  - `trust_caveats: list[str]`.
- Add `CrossDomainLink` dataclass:
  - `source_domain`, `gpo_id`, `gpo_name`, `target_domain`, `som_path`.
  - `link_enabled`, `enforced`, `caveat`.
- Existing `Estate` is unchanged except for stricter documentation that it
represents exactly one domain.

### Ingest changes

- `ingest.py` gains a `load_multi_estate(paths: dict[str, Path]) -> MultiEstate`
  entry point that runs the existing single-domain ingest on each export
  directory and assembles the results.
- Domain keys come from the export's metadata (`gpo-metadata.json` or
  `estate.json`), not directory names, so renaming a directory can't mislabel a
  domain.
- Each `Estate` is ingested independently; a failure in one domain does not
  affect the others.

### What works per-domain independently

All current queries run inside one `Estate` without change:

- Hygiene / estate doctor.
- Baseline diff (per-domain Microsoft Security Baseline comparison).
- Conflict and precedence-conflict detection.
- Topology within a domain (`settings_at_som`, `som_conflicts`).
- Dangerous-config detection (`danger.py`).
- `principal_resultant` for a principal in that domain.
- Snapshot diff and trend analysis.

### What needs cross-domain awareness

- **Cross-domain GPO links.** Detected during `MultiEstate` assembly and surfaced
as findings.
- **Cross-domain settings comparison.** A new query compares policy values for
the same `(cse, identity)` across selected domains, highlighting drift.
- **Universal group membership.** Groups that grant Apply rights may live in a
different domain than the GPO; flagged as a caveat unless membership was
collected from the trusted domain.
- **SID history / foreign-security principals.** A token may contain SIDs that
only make sense in another domain; flagged.
- **Trust state.** Whether a one-way or two-way trust existed at collection time
can only be noted; not simulated.

## Collector changes needed

The collector has no domain parameter today (see Ground truth), so this design
assumes one is added. Multi-domain collection is then an orchestration problem,
not a new collector script:

- Invoke `Export-GpoEstate.ps1` once per target domain with an explicit
  `-Domain` (the proposed new parameter) and a distinct output subdirectory
  (e.g. `export/corp.example/`, `export/child.example/`).
- A top-level `multi-estate.json` manifest lists the exported domains and each
  one's collection timestamp.
- Each per-domain export keeps today's format; no new file schemas inside a
  domain export.
- Trust and site metadata are optionally emitted at the multi-estate level as
  `trusts.json` and `sites.json` (optional; absence triggers a caveat).

## CLI and web surfaces

- **CLI:** `gpo-lens multi-estate /path/to/export` loads the manifest and runs
  per-domain summaries plus cross-domain link warnings. `gpo-lens multi-compare
  --domain=corp,child` reports settings drift.
- **Web:** a top-level domain switcher; each domain renders the existing
  single-domain dashboard. A cross-domain links page shows the warnings, and a
  settings-drift page compares a selected setting across domains.

## Acceptance criteria

- **AC-1** A `MultiEstate` can be constructed from two or more independent
single-domain exports without mutating any per-domain `Estate`.
- **AC-2** The existing single-domain tests continue to pass when a bare
`Estate` is used (no `MultiEstate` required for v1 behavior).
- **AC-3** A cross-domain GPO link is detected and surfaced in
`MultiEstate.cross_domain_links` with source domain, target domain, GPO id,
and a human-readable caveat string.
- **AC-4** A cross-domain link itself does not alter any per-domain topology,
resultant, or conflict query.
- **AC-5** A new cross-domain settings-drift query reports settings whose
`(cse, identity)` differs across selected domains, including the winning GPO
and value per domain.
- **AC-6** When a GPO in domain A is security-filtered to a group whose SID
belongs to domain B, the finding carries a cross-domain principal caveat.
- **AC-7** A missing per-domain export in a multi-estate manifest is reported as
a coverage gap, not a crash.
- **AC-8** The web UI domain switcher preserves all existing single-domain
views unchanged.
- **AC-9** No live AD trust evaluation is performed; trust state is either
collected or emitted as an unknown-trust caveat.
- **AC-10** All new dataclasses, functions, and CLI/web routes are documented
with the same "flag, don't simulate" caveat language used in single-domain
surfaces.

## Tests

- Unit tests using synthetic multi-domain fixtures (no real domain names or
SIDs). Each fixture has two `Estate` objects, one cross-domain link, and one
intra-domain link.
- Assertions that `settings_at_som`, `principal_resultant`, and
`danger_findings` produce identical results when run from a standalone
`Estate` vs. from the same `Estate` embedded in a `MultiEstate`.
- Cross-domain link detection test with enabled/disabled/link-off variants.
- Settings-drift test comparing registry policy across two domains.
- Coverage-gap test for a missing domain in the manifest.

## Non-goals

- **True cross-domain resultant policy.** A GPO from domain A linked to an OU
in domain B is flagged, not folded into domain B's effective settings.
- **Trust-path simulation.** The tool does not evaluate whether a trust exists,
whether it allows authentication, or whether a universal group from domain B is
in scope in domain A's resource check.
- **Global catalog / SID resolution across trusts.** Foreign-security-principal
SIDs that appear in a token are recorded as caveats; no cross-domain AD lookup is
attempted.
- **Removing the single-domain assumption entirely.** `Estate` stays
  single-domain; v2 work is additive around it.
- **Migration of existing single-domain deployments.** Existing exports and APIs
continue to work unchanged.

## Sequencing & risk

- **Effort:** medium. The data model and ingest assembly are small; the larger
  work is the cross-domain comparison query, the CLI/web surfaces and the test
  fixtures.
- **Risk:** medium-low for correctness, medium for scope creep. The biggest
  danger is simulating cross-domain policy flow once the data model makes it
  feel possible. The ACs prevent that by keeping cross-domain links as warnings
  and per-domain analyses independent.
- **Suggested sequencing:**
  1. Land `MultiEstate` + `CrossDomainLink` data model and `load_multi_estate`
     (no UI).
  2. Add cross-domain link detection and a CLI `multi-estate` command.
  3. Add settings-drift query and tests.
  4. Add web domain switcher and cross-domain pages (gated on UI bandwidth).
- **Post-1.0:** this design is tagged post-1.0 and must not delay v1.0. The
  single-domain path and API stay stable.
- **Dependencies:** if v1.x introduces a per-estate schema version or a
  normalized domain-name rule, that work helps this design and should come
  first.
