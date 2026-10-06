# Plan 020 — Principal resolution (SIDs → names, membership, population)

**Status:** Partially shipped in v0.6.3; verified 2026-10-06. Evidence: [src/gpo_lens/authz.py](../src/gpo_lens/authz.py), [tests/test_principal_resultant.py](../tests/test_principal_resultant.py).

SID/name resolution, optional `principals.json` and `group-members.json`, membership persistence and Plan 021 token use shipped. Collection is provided by `scripts/Export-Principals.ps1`. Phase C `ou-population.json`/blast-radius counts and the dedicated Phase B empty-filter-group finding did not ship and are not pursued for v1.3.0.

The design below is the historical specification; this status records the verified release scope.
**Author:** Claude (Opus 4.8), from a "what would live AD buy us" review
**Strategic role:** gpo-lens's differentiator is its SDDL/delegation analysis —
the attack-path view (who can write a GPO, who gets Apply, deny ACEs). But that
analysis currently speaks in **bare SIDs** wherever it reads from SDDL, because
`parse_sddl` yields SID-only ACEs. `S-1-5-21-1234567890-1234567890-1234567890-1131`
is not actionable to a human. This plan makes principals legible: resolve SIDs to
names, then (later) to membership and population. Crucially it does this through
**richer collection, not a live AD bind** — the new artifacts are point-in-time,
hashable, hand-me-an-export inputs, so the local-first / air-gapped / provenance-
clean posture that makes gpo-lens deployable in regulated environments is
preserved. (A live bind is reserved for continuous monitoring and interactive
planning-RSoP — out of scope; see Plan 019's boundary note.)

## Ground truth at time of writing

- **Where bare SIDs surface (the target):** SDDL-derived findings carry only a
  SID — `detection.deny_aces` (`detection.py:809`), `detection.excessive_writers`
  (`:839`), the SDDL checks in `danger.py`, and the SDDL fallback in
  `topology.security_filtering_detail` (`topology.py:554`). `parse_sddl`
  (`authz.py`) populates `SddlAce.trustee_sid` and no name — SDDL is SID-only by
  format.
- **Delegation is already name-paired.** `_parse_delegation` (`ingest.py:311`)
  reads both `<Name>` and `<SID>` from the GPMC report, so `DelegationEntry`
  already has a `trustee` name. So this plan is mostly about the **SDDL** surfaces,
  not delegation.
- **Some SIDs need no AD at all.** Well-known SIDs (`S-1-5-11` Authenticated
  Users, `S-1-1-0` Everyone, `S-1-5-7` Anonymous, `S-1-5-18` SYSTEM,
  `S-1-5-32-544` Administrators) and well-known RIDs (`-512` Domain Admins,
  `-519` Enterprise Admins, `-515` Domain Computers, `-513` Domain Users)
  resolve from a static table. Code already pattern-matches several of these by
  suffix (`authz.DOMAIN_COMPUTERS_RID_SUFFIX`, the default-writer exclusions at
  `detection.py:845`), but there is no general resolver and the names are not
  surfaced.
- **Collector:** `scripts/Export-GpoEstate.ps1` produces the export; format is
  documented in `docs/spec/export-format.md`. It is read-only and runs under a
  least-privilege account. Resolving SIDs and reading group membership are
  ordinary authenticated-user directory reads — no elevation, consistent with the
  current posture.
- **Design principle this plan must honor:** the **SID stays canonical**. A name
  is an *annotation* layered on top, never a replacement — an auditor must always
  be able to see the exact SID, and names are point-in-time (a SID can be renamed
  or deleted). Resolution is presentation/enrichment, not a rewrite of the truth.

## Charter addendum (decisions this plan records)

1. **Richer collection, not a live bind.** New artifacts are static, point-in-time,
   and hashable like the rest of the export. No standing credentials, no runtime
   directory connection.
2. **SID is the source of truth; name is an annotation.** Every view that shows a
   resolved name also retains the SID (tooltip / secondary line), same pattern as
   Plan 018-A's raw-identity affordance.
3. **Unresolved is a result, not an error.** A SID present in an ACL but absent
   from the resolution map (and not well-known) is an *orphaned/stale principal* —
   a finding in its own right (Phase B), not a collection failure.
4. **Resolution never changes a verdict.** Detectors continue to key on SID
   (the MS16-072 / danger logic stays SID-based); names are added for legibility
   only. This keeps the truth path independent of name-resolution drift.

## Phase A — Replace SIDs with names

Two sub-parts: a free static win, then a collected map.

### A.1 Static well-known SID/RID resolver (no collection change)

Add `authz.resolve_well_known(sid) -> str | None` backed by a table of absolute
well-known SIDs and domain-relative RIDs (`-512/-513/-515/-516/-519`, BUILTIN
`S-1-5-32-*`, `S-1-5-11/7/18/9`, etc.). Pure, offline, immediately useful — it
covers the SIDs that dominate GPO ACLs. Refactor the existing ad-hoc suffix
matches to consult this table so there is one source of truth.

### A.2 Collected SID → name map (`principals.json`)

Extend `Export-GpoEstate.ps1` to emit `principals.json`: a flat map of every SID
it encounters in any GPO SDDL or delegation entry, resolved once via the
directory at collection time:

```
{ "<sid>": { "name": "WORKDOMAIN\\GPO-Admins", "sam": "GPO-Admins",
             "type": "Group|User|Computer|WellKnown|Unresolved",
             "domain": "WORKDOMAIN" } }
```

Collector resolves via `[SecurityIdentifier].Translate()` / a directory lookup;
SIDs that fail translation are recorded with `type: "Unresolved"` (don't drop
them — see Phase B). Document the artifact in `docs/spec/export-format.md`. The
artifact is **optional**: ingest must work without it (older exports, or a
collector run that couldn't reach a DC).

### A.3 Ingest + resolver

- Ingest `principals.json` into `estate.principals: dict[str, Principal]`
  (empty dict when absent).
- One resolver: `resolve_principal(estate, sid) -> ResolvedPrincipal` that tries
  (1) the static well-known table, (2) the collected map, (3) falls back to the
  raw SID with `resolved=False`. Returns name + type + the original SID always.

### A.4 Wire into the SDDL-derived surfaces

Apply the resolver wherever a bare SID is shown: `deny_aces` / `excessive_writers`
output, the `danger.py` SDDL findings, the `security_filtering_detail` SDDL
fallback's `apply_trustees`, and their templates/CLI renderings. Name shown
primary, SID retained as secondary (per decision 2). CLI `--json` gains a
`resolved_name` field alongside the existing SID (additive, no breaking change).

### A.5 Acceptance criteria

- `AC-1` A deny ACE / excessive-writer on a domain group renders the group name
  with the SID retained, when `principals.json` is present.
- `AC-2` Well-known SIDs resolve with **no** `principals.json` (static table).
- `AC-3` Without `principals.json` and not well-known, the SID renders raw with
  `resolved=False` — no crash, no blank.
- `AC-4` The SID is present on every row that shows a resolved name (audit).
- `AC-5` Detector verdicts are byte-identical with and without resolution
  (names never change findings — decision 4).
- `AC-6` CLI `--json` is a strict superset (new `resolved_name`, SID unchanged).

### A.6 Tests

`tests/test_authz.py` (well-known table), `tests/test_ingest.py`
(`principals.json` present/absent/partial), `tests/test_topology.py` /
`tests/test_detection.py` (resolution applied, SID retained, verdict-invariant),
and a calibration check that resolved-name coverage on the work estate matches
an external count (GPMC / `Get-ADObject`), not the tool's own output (WI-029).

## Phase B — Membership & orphaned principals (gated)

Builds on A's map. Extend the collector with `group-members.json`
(group SID → member SIDs, transitively expanded, with a member count). Unlocks:

- **Empty-group filtering → dead GPO.** A GPO security-filtered to a group with
  zero members applies to nobody — a finding impossible from the static GPO
  export alone.
- **Orphaned/stale SIDs.** A SID in a GPO ACL that resolves to `Unresolved`
  (deleted principal) — surfaced as a hygiene finding (decision 3).
- **"Who's affected" counts.** A filter trustee renders as
  `Finance-Admins (12 members)` instead of a bare name.

Membership expansion has real subtlety (nesting, primary group, foreign-security-
principals); gated until Phase A proves the collection path and the value.

## Phase C — OU population & blast-radius (gated)

Extend the collector with per-OU object counts (`ou-population.json`: OU DN →
{computers, users}). Unlocks **blast-radius sizing** — annotate every existing
finding (dangerous config, MS16-072, …) with "reaches ~N objects," making
severity prioritizable. This is the highest-leverage population feature (it
multiplies the value of *all* findings), but it is independent of name
resolution, so it is sequenced last and gated on demand.

## Non-goals

- **Live AD bind / continuous monitoring / interactive RSoP.** Reserved for a
  separate initiative (Plan 019 boundary note). This plan is collection-only.
- **Per-principal effective RSoP.** Membership enables *counts and dead-group
  detection*, not per-user resultant policy (still "Flag, don't simulate").
- **Mutating the truth.** SIDs are never replaced in stored data; names are an
  annotation layer.
- **Treating unresolved SIDs as collection failures.** They are findings.

## Sequencing & risk

- **Phase A.1 (static table) is free and immediate** — ship it independent of any
  collector change; it covers the most common SIDs and removes the ad-hoc suffix
  matching scattered across `authz`/`detection`.
- **Phase A.2 needs a collector change** — additive, optional artifact; ingest
  degrades gracefully without it. Validate the new collection on the homelab
  (`LABDOMAIN`) before the work estate.
- **Posture risk:** keep the collector's directory reads least-privilege and
  read-only; `principals.json`/`group-members.json` contain directory data, so
  they fall under the same `samples/`-is-gitignored, never-commit-real-domain
  rule as the rest of the export.
- **Provenance:** names are point-in-time; record the collection timestamp on the
  artifact so a stale name is attributable. The SID-is-canonical rule means a
  drifted name can never silently corrupt a finding.
- **Phases B and C are gated** on A landing and on real-use demand; each is an
  additive collector artifact + a derivation, no rework of A.
