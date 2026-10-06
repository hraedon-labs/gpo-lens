# Changelog

## v1.3.0 — 2026-10-06

Draft **v1.3.0** — release date TBD by coordinator. This section remains
Unreleased until the release is dated and tagged.

### Fixed

- **Resilient ADMX/ADML loading.** Decode BOMs and nonstandard XML encoding
  declarations before protected parsing. Unreadable templates are isolated and
  reported in CLI warnings and ADMX coverage; template loading failures leave
  the web app available with a visible notice.
- **Upgrade triage ordering (F-01).** Merge legacy approvals and Plan 024 events
  chronologically, with immutable event IDs as the stable tie-breaker. A newer
  withdrawal stays open after upgrade; inbox and accepted-risk folds agree.
- **Finding identity and historical evidence (F-02–F-04).** Enforced links include
  SOM path, order and target; old blanket triage remains in occurrence history
  while new link findings require review. Duplicate fingerprints visibly degrade
  analysis and prevent resolution of unseen findings. Historical briefing totals
  and severity use the selected evaluation. Future-schema refusal precedes all
  journal, permission and schema changes.
- **Web authority boundary (WEB-01).** Validate Host before authentication, CSRF
  and URL generation. `GPO_LENS_ALLOWED_HOSTS` accepts comma-separated hosts
  (any valid port) or exact host:port entries, case-insensitively, including
  bracketed IPv6. Unset accepts only localhost, 127.0.0.1 and [::1]. Proxied
  deployments must configure this variable on installation and upgrade.
- **Shared credential redaction (WEB-02).** Mask concrete Windows credential
  registry values and URI/UNC userinfo, including copied values in finding
  evidence, triage notes and diffs. Preserve benign password-policy settings.
  HTML, API, comparison/export and ordinary CLI outputs share the projection;
  legacy report renderings and event export copies also mask credentials.
- **Evidence navigation (DB-005, DB-007).** The Briefing collection-coverage tile
  opens coverage-gap-filtered Findings. Explore describes configured-setting
  search accurately.

### Added

- **Deterministic Markdown/CSV exports (Plan 025 WI-6).** Download dossiers,
  ledgers, filtered findings, occurrence history, accepted risks, briefings,
  exact settings and snapshot/GPO/comparison differences. Upload comparisons
  have an output selector; `gpo-lens export` provides CLI equivalents.
  Exports carry filters, snapshot/evaluation provenance and scope caveats,
  omit volatile generation timestamps, and accept explicit as-of inputs for
  repeatable time-sensitive views. Output streams; existing `--json` contracts
  are unchanged.
- **Linux container and systemd deployment (WI-086).** Digest-pinned non-root
  image, locked web dependencies, loopback Compose default, optional Caddy
  TLS/basic-auth proxy and hardened systemd unit. Guides cover collector
  transfers, installation, upgrade, WAL-safe backup/restore and rollback.
  CI builds/smoke-tests the image, access control and synthetic upload.
- **Findings occurrence view and deterministic Briefing (Plan 025 WI-1/2).**
  Observations show evaluation provenance, severity/claim/rule changes,
  predecessor regressions and append-only triage history. Briefing provides
  linked vitals, snapshot/finding deltas and expiring risks, prominently
  reporting coverage/incomplete-analysis warnings. First-snapshot, historical,
  degraded and no-change scenarios have golden text tests.
- **Explore/Tools directories and route reference (Plan 025 WI-3/4).** Retained
  specialist workbenches are organized by operator question and resolved from
  a route registry; the migration inventory is test-enforced.
- **Operator handover.** `docs/handover.md` names v1.3.0 as the target, with a
  private site sheet, collection/coverage rules, provider-egress boundaries,
  deployment alternatives and backup/upgrade/rollback instructions.

### Changed

- IIS fresh network sites require Windows Authentication or an explicit
  anonymous-access opt-out; upgrades preserve access and warn if anonymous.
  New firewall rules default to LocalSubnet on Domain/Private profiles.
- IIS uses committed hash-pinned web dependencies and installs the project
  with `--no-deps`, preserving the shared-Python deployment design.
- Unstable finding subjects are snapshot-scoped (`snapshot_scoped`) and refuse
  triage (`485a5bd`).
- Store writes use batched persistence inserts via `executemany` (`b5133fb`).

- **Navigation (Plan 025 WI-4).** Primary links are Briefing / Findings /
  Explore / History / Tools, with configured-settings search. The wordmark
  opens Briefing. Existing handlers and query parameters remain valid,
  including the legacy dashboard at `/`; no permanent redirects are imposed.
  `GPO_LENS_LEGACY_NAV=1` restores earlier primary links after a restart;
  Ask stays under Tools.
- **Optional web narration (Plan 025 WI-5).** Separate Explain these facts
  actions use signed, bounded counts/caveats/provenance. Names, values, raw
  evidence and HTML are excluded. The model can select only supplied fact IDs;
  additional claims are rejected. Actions are absent without an API key and
  never delay deterministic pages. Web Ask keeps routing/deterministic results
  and uses the same checked explanation. CLI narration retains its separate
  provider data-egress boundary.
- **Findings inbox (Plan 025 WI-1).** Reads Plan 024 core queries with SQL
  filtering/counting/pagination and stable ordering. Default is new or
  regressed and open; all lifecycle/triage states remain accessible. Filter
  totals and rows share one predicate and triage fold. GPO links now use a
  targeted ID query instead of reconstructing the estate (WI-093), with
  output equivalence and synthetic benchmark coverage.
- **Plan bookkeeping.** Every plan's release status is reconciled with code
  and tests. Studio interop/multi-estate comparison remain outside v1.3.0;
  gMSA scheduling and module decomposition are deferred. Splunk HEC output is
  shipped, but Splunk-sourced actor attribution is not implemented.

### Fixed

- Danger findings avoid double-conversion and duplicate results (`c50549e`).
- Release metadata and lockfile identify the v1.3.0 candidate as 1.3.0;
  version checks bind to the draft target and the container API/package version.
- Every proxy deployment configures `GPO_LENS_ALLOWED_HOSTS`; IIS merges
  missing policy on fresh installs and upgrades without losing existing variables.
- IIS recovery uses WAL-safe online/whole-directory offline backups, audit-log
  copies, stale-sidecar removal and integrity/snapshot/GPO verification.
- Collector transfer instructions use the collector's portable forward-slash ZIP.

- **Triage convergence (WI-092).** UI triage writes the Plan 024 append-only
  `finding_triage_event` log; compatibility projections no longer read an
  isolated legacy store. Schema v8 migrates legacy triage idempotently,
  preserving actor/time/note; legacy tables remain for audit. Risk acceptance
  requires a non-empty rationale. Same-timestamp events remain distinct, and
  orphaned legacy rows do not prevent startup.
- Accepted-risk point-in-time queries retain expired/revoked history.
- Registry.pol ledger rows include value names, types and decoded data.
- Upload-backed `golden_diff` is no longer advertised through the GET query API.
- Successful CLI ingest warns if finding evaluation fails, matching web ingest
  behavior (WI-094).
- Older database GPO names resolve through both stored and canonical GUID forms.

### Security

- Caddy strips the Basic-auth Authorization header before forwarding to the
  no-token app; a mock upstream smoke assertion guards credential forwarding.

- **anyio 4.13.0 → 4.14.2** in the lockfile, addressing
  **PYSEC-2026-4024 / PYSEC-2026-4025** (`7d1c939`).
- Exports share secret/raw-source redaction with HTML/API safe output;
  spreadsheet formula cells are neutralized. Triage/audit attribution requires
  triage authorization. Web narration uses signed safe facts and checked output.
- Identifier hooks/gate fail closed when a public repository lacks a denylist;
  staged bytes, commit messages and publication-declaration history are checked,
  including UTF-16/symlink/type changes and shallow-history refusal.
- Linux examples preserve the loopback-XOR-token access model and scheme-only
  proxy forwarding. Remote browser access control belongs to the TLS proxy or
  network; the examples do not create per-user app authorization.

### Upgrade notes

- **Back up the database and separate `audit.log` before upgrading to v1.3.0.**
  Migrations on open are tested using actual databases from **v0.5.0, v0.7.0,
  v0.7.1, v1.0.0, v1.1.0 and v1.2.0**, covering released schema generations
  since v0.5.0 (not a fixture for every patch tag). Tests preserve entities,
  snapshots, events and supported finding/risk decisions; a second open is
  idempotent. Online SQLite backup/restore with committed WAL changes is tested.
- Schema v8 converges legacy triage and v9 records stable versus snapshot-scoped
  finding subjects. Review the v1.1.0 one-time re-key/triage note when upgrading
  from before that release. Exact historical lifecycle provenance is not invented.
- Restore an older backup into a newer install; rollback requires the matching
  old backup **and** old code. A newer migrated database with older code is not
  guaranteed. Use the deployment runbooks and test an isolated restore first.
- Use the reversible navigation flag during rollout and check bookmarked
  filters. Each database still represents one estate; cross-estate comparison
  is not included.

## v1.2.0 — 2026-07-16

### Adversarial review hardening

Four rounds of adversarial code review found and fixed:

**Critical:**
- `coverage_gap` table PK now includes `kind` (schema v7 migration) so
  multiple gap types per GPO (e.g. `unreadable_sysvol` +
  `corrupt_gpp_xml`) are not silently dropped by `INSERT OR IGNORE`.

**Major:**
- `parse_inheritance` no longer crashes on a malformed GUID — a single
  bad `GpoId` in `gp-inheritance.json` previously lost all topology data
  for the entire estate.
- `events.py` hash-chain `append_event` / `append_events` now use
  `BEGIN IMMEDIATE` so the SELECT + INSERT is atomic and two concurrent
  writers can't break the chain.
- SDDL alias vs raw-SID normalization in `overbroad_apply_group_policy`,
  `excessive_writers`, and `deny_aces`: aliases like `AN`, `AU`, `WD`
  are now canonicalized to raw SIDs (`s-1-5-7`, `s-1-5-11`, `s-1-1-0`)
  so an allow against one form and a deny against the other correctly
  cancel. Previously this caused false positive/negative security findings.
- Re-accepted risk revocation metadata: after accept → revoke → re-accept,
  the `revoked_at` / `revoked_by` fields are now cleared (previously
  stale from the prior revocation).
- `triage_finding` now rejects triage actions on already-resolved findings.

**Minor:**
- O(n²) GPO name lookup in `excessive_writers` → O(1) via
  `estate.gpo_names`.
- `set()` hoisted before comprehension in
  `augment_blocked_registry_from_pol`.
- `_parse_gplink` order counter only increments for valid links.
- `report.py` renders `?` instead of `None` for missing version numbers.
- Web ingest finding-lifecycle failures logged at ERROR (was WARNING)
  with snapshot_id for traceability.

**Schema migration v6 → v7** is automatic and additive on first open.
No finding re-key or triage state loss.

## v1.1.0 — 2026-07-14

### Phase 1 — finding-identity correctness and precision (Plan 027)

- **Detector identity comes from typed fields, not prose (WI-1.1).** Every
  detector that carries identity-bearing dimensions (version skew and
  disabled-side by side; broken refs by ref value; deny ACEs and non-admin
  writers/owners by trustee/owner SID; coverage gaps by kind) now declares
  them as typed `dimensions` on the finding. The lifecycle adapter reads those
  fields directly and no longer parses the summary/detail strings, so rewording
  a finding can never churn its identity. This also fixes two latent identity
  collisions: multiple non-admin writers on one GPO are now distinct findings
  (previously the trustee SID was parsed out of a display-name-bearing string
  and usually lost), and two different coverage-gap kinds on one GPO no longer
  fold into one fingerprint (the declared `kind` was being dropped whenever a
  GPO id was present).
- **Filtered inbox pages are complete (WI-1.2).** `finding_inbox` now applies
  the `claim_level` and `triage_status` filters in SQL *before* `LIMIT`
  (claim level via the latest observation; triage status via the folded
  event-log status). Previously both were applied in Python after the row cap,
  so a filtered page on a large estate could silently return fewer rows than
  matched. `limit` now bounds the matching set, not a pre-filter superset.
- **Query performance (WI-1.3).** Added indexes on the lifecycle run-id and
  series columns (`first_seen_run_id`, `last_seen_run_id`, `resolved_run_id`,
  `series_key`), and replaced the per-occurrence N+1 in `load_triage_status_map`
  with a single grouped scan of the triage event log.
- **Findings carry their real detail (WI-1.5).** The `finding.detail` column
  now stores the detector's detail text instead of duplicating the summary;
  documented the single-estate-per-store assumption; removed a redundant inline
  import.

**One-time re-key effect (batched, read this before upgrading a live store).**
The identity changes above (WI-1.1) plus the GPO-less identity change below
(WI-089) alter the fingerprint of findings in these categories: coverage gaps,
non-admin GPO writers, non-admin GPO owners, topology discrepancies, excessive
writers, and orphaned WMI filters. On the **first ingest after upgrading**, any
existing findings in those categories re-key: the old occurrences resolve and
the re-emitted findings appear as new. This is a single, expected event — not a
real posture change — and it is intentionally batched into one release so
operators see it once. Findings in all other categories keep their identity.

**Triage state does not carry over.** Triage events (risk-acceptances,
acknowledgements) are keyed to occurrence IDs, and a re-keyed finding gets a
new occurrence row — so any triage state an operator recorded on the re-keyed
categories will be orphaned on the resolved rows and the re-emitted findings
will resurface as untriaged "new." Snapshot the current risk-acceptances before
the first post-upgrade ingest and re-apply them as needed.

### Web reimagining (Plan 023/024, landed)

- **Findings inbox is lifecycle-backed and actionable (WI-090/WI-091).**
  Findings are materialized at ingest on both the CLI and web paths (shared
  core `evaluate_finding_lifecycle`), with bounded evidence persisted, so the
  inbox and GPO detail pages read from the `finding` table instead of
  re-running whole-estate detectors per request. Inbox gains filtering,
  triage, pagination, and accessibility improvements.
- **Finding triage is its own permission (WI-088).** The findings triage
  endpoint now requires the new `Permission.TRIAGE` instead of
  `Permission.INGEST`: acknowledging or accepting risk on a finding no longer
  implies (or requires) the right to upload estate snapshots (Plan 024 §8
  pulled forward). Loopback/forwarded principals and the operator/admin roles
  gain `TRIAGE`, so existing single-operator deployments behave unchanged; a
  new `triager` role shape (view + triage, no ingest) exists for least-
  privilege setups.
- **Stable identity for GPO-less findings (WI-089).** Topology discrepancies,
  excessive writers, orphaned WMI filters, and coverage gaps now fingerprint
  on declared identity dimensions (OU DN, trustee SID, filter name, gap kind)
  instead of their prose summary/detail (Plan 024 §4 pulled forward).
  Previously any wording or evidence-count change (e.g. a writer's GPO count
  going 12 → 13) re-keyed the finding, falsely resolving the old one and
  reporting a "new" one. (The one-time re-key this causes is covered by the
  batched note above.)

## v1.0.0 — 2026-07-06

First stable release. Local-first, read-only Group Policy analysis with a
deterministic core (no AI in the truth path) and an optional LLM narration
layer. Covers Tier 1 hygiene scans, Tier 2 baseline comparison, Tier 2.5
OU-level topology, and Tier 3 AI narration. See `README.md` for the full
feature set.

### SDDL parser — reference-validated fixes (from the 2026-07-01 differential review)

- **`SW` (validated write / `ADS_RIGHT_DS_SELF`) joins the valid rights set.**
  It appears in the canonical AD rights string on essentially every GPO DACL
  (386 of 767 ACEs in the real-estate corpus) and was silently dropped; worse,
  the 1-char resync could fabricate a phantom `WD` (Write DAC) from `SWDT`.
- **Hex rights mask decoding corrected:** `0x8` is `SW`, not `CR`; `0x100`
  (`ADS_RIGHT_DS_CONTROL_ACCESS` — the bit Apply Group Policy actually uses)
  was missing entirely. Hex masks never occur in GPMC XML output (corpus-
  confirmed), so no live verdicts change; the code path is now correct for
  other producers.
- **SDDL alias fixes per sddl.h:** `PS` is Principal Self (`S-1-5-10`), not
  Pre-Windows 2000 Compatible Access (that alias is `RU`, now added); BUILTIN
  RID 555 is Remote Desktop Users, not a duplicate of 554.
- **ACL control flags are preserved:** `SddlAcl` gains `dacl_flags` /
  `sacl_flags` (e.g. `PAI` — `P` = inheritance-protected, posture-relevant);
  previously discarded.
- **New differential regression corpus** (`tests/fixtures/sddl/` +
  `test_sddl_reference_corpus.py`): 27 SDDL strings (5 real lab GPMC strings +
  22 synthetic grammar-coverage strings) decoded by .NET
  `RawSecurityDescriptor` on a real Windows host; the tests assert field-level
  agreement (ACE count/order/type/flags, trustee SID, rights, read-or-apply
  and write verdicts, owner/group, protected flag). The `PS` and RID-555
  fixes above were caught by this corpus, not by review.

### Web UI — navigation, attribution, and readability

- **Nav grouped by workflow** (Estate / Posture / Change / Tools) with
  hairline dividers, and three previously orphaned pages — `/delegation`,
  `/admx-coverage`, `/golden-diff` — are now linked (they were reachable only
  by typing the URL).
- **Per-user audit attribution behind a reverse proxy** (opt-in): set
  `GPO_LENS_FORWARDED_USER_HEADER=X-Forwarded-User` and have the same-host
  proxy set that header from the authenticated user (IIS URL Rewrite wiring
  documented in `deploy/iis/README.md`). Audit-log entries then carry the real
  operator (role `forwarded`) instead of `local-analyst`. Loopback-gated;
  grants no permissions beyond the loopback set; ignored from remote peers.
- **GPO owner extraction fixed:** GPMC's `<Owner>` element holds `<SID>`/
  `<Name>` children, so reading its own text stored whitespace as the owner of
  every GPO — the GPO-detail Owner row has been blank on real estates. Owner
  now reads `Name` (fallback `SID`); the template also tolerates historical
  whitespace values.
- **Readability:** the Conflicts "Setting" and Danger "Finding"/"Remediation"
  columns get minimum widths so long registry paths and remediation prose stop
  wrapping into unreadable 15-character shards.

### WI-080 — configured values for Administrative-Templates settings

- Admin-Template policies (Registry CSE) now show the data they configure, not
  just `Enabled`/`Disabled`. The ingest parser summarizes each policy's option
  sub-elements (`DropDownList`, `EditText`, `Numeric`, `CheckBox`, `ListBox`,
  `MultiText`) into `display_value`, e.g.
  `Enabled — Maximum Log Size (KB): 2097120`. Policies with no options keep the
  bare state. On a real export, 395 of 1363 Registry settings now carry a value.

### WI-083 — CSE filter + in-table search on the OU effective-settings view

- The OU detail "Effective settings" table (up to ~1,000 rows on a real OU) gains
  a CSE facet dropdown (CSEs present, with counts) and a text search over
  identity / name / value, via a reusable `filter_settings` helper. The heading
  badge shows `filtered / total`; filters round-trip through pagination.

### WI-082 — estate-wide settings search (web)

- New `/search` route + nav entry: "which GPOs set X?" over the whole estate.
  Searches settings by policy name / registry identity / value (`queries.who_sets`),
  groups hits by GPO with deep-links, and offers CSE + side facets with counts.
  An empty query renders a prompt instead of dumping the estate; results
  paginate by GPO. Closes the cross-cutting-lookup gap the CLI already covered
  but the web UI did not.

### WI-081 — precedence-conflict rollup deduplicated by chain signature

- `precedence_conflict_rollup` now resolves conflicts once per *distinct*
  enabled link chain instead of once per SOM. On a real ~1,500-SOM estate this
  is a ~12× speedup (4.6s → 0.4s, 66 distinct chains) with byte-identical
  output. The `/conflicts` "Resolved (who wins)" tab and its pagination no
  longer pay the full per-OU walk on every visit.

### WI-084 — SDDL alias and raw-SID trustee forms now compare equal

- `broad_trustee_key` resolves the SID through `resolve_well_known`, so an SDDL
  alias (`AU`/`WD`) and the corresponding raw SID (`S-1-5-11`/`S-1-1-0`) yield
  the same key. A deny in alias form now cancels an allow in raw-SID form in
  `applies_broadly` (fixes a latent false positive in `overbroad_apply_gp`).
- New `authz.canonical_sddl_sid` canonicalizes ACE trustee tokens (absolute and
  domain-relative aliases) to comparable SIDs. The principal-resultant security
  gate (`_gpo_apply_trustee_sids`) applies it when grouping SDDL ACEs, so an
  alias-form deny correctly excludes a principal whose token holds the canonical
  SID — closing a gate over-grant on alias-form SDDL.

### Supply-chain hardening (CI)

- CI installs from the `uv.lock` (`uv sync --locked`) instead of resolving
  fresh from version floors, so builds are reproducible and lock drift fails
  the build.
- New `supply-chain` job runs `pip-audit` (`--strict`) against the locked
  runtime + web dependency set on every push and PR.

### Code-quality fixes for v1.0.0

- **SID validation regex centralized.** `SID_RE` in `authz.py` is now the
  single source of truth for SID format validation, replacing two independent
  copies in `merge.py` and `cli/_resultant.py`. The CLI copy used `\d`
  (matches Unicode digits — false positives) while `merge.py` used `[0-9]`
  (ASCII only, correct). A SID with Unicode digits previously passed CLI
  validation but failed in the merge engine, producing a confusing "Principal
  not found" error.
- **`_load_row_sets` extracted to module scope** in `snapshot_diff.py`,
  making the table/column allow-list guards directly testable. Previously a
  nested function that could not be exercised from outside the module.
- **Chunking path now tested.** The >500-GPO chunked query path in
  `snapshot_diff` is exercised by a test that monkeypatches the chunk size
  and verifies merge-across-chunks correctness via a call spy.
- **Shared `_make_gpo()` test helper** extracted to `tests/_helpers.py`,
  eliminating ~400 lines of boilerplate `Gpo(...)` construction in
  `test_topology.py` and ensuring new `Gpo` fields don't require updating
  every test.
- **Drained `PENDING-REGISTA-WI.md`.** The flaky
  `test_concurrent_upload_returns_409` test is now deterministic (explicitly
  acquires the ingest lock before the concurrent request). The transient
  holding file has been deleted.

### Earlier unreleased work (folded into v1.0.0)

#### Fix: CI coverage gate raised from 20% to 85% — synthetic estate already built (WI-074)

- The WI-070 entry described a `--cov-fail-under=20` CI floor as necessary
  because "sample-dependent calibration tests are skipped on a fresh
  checkout, yielding only ~20.7%." That framing was **stale**: two synthetic
  fixture estates (`tests/fixtures/` — 14 GPOs, and `tests/golden_estate/` —
  6 GPOs) had already landed with comprehensive structural test suites that
  drive CI coverage to **~92%** without samples. The 20% gate was a
  false-confidence hazard in the opposite direction — it would let a
  regression that deleted half the detection module pass green.
- The CI gate is now `--cov-fail-under=85`, leaving 7% headroom below the
  measured 92% for CLI/web presentation-layer evolution while catching any
  real regression. Stale comments in `pyproject.toml`, `ci.yml`, and
  `plans/010-capability-roadmap.md` corrected.
- Added targeted core-coverage tests for previously-untested branches in the
  deterministic core (not presentation wrappers):
  - `registry_pol.py` — all 8 malformed/truncated PReg record branches
    (missing separators, truncated DWORDs, truncated data, missing close
    bracket) and the `_read_utf16_null` no-null-terminator fallback. Coverage:
    90% → **100%**.
  - `danger.py` — the `in`/`present`/`min`/`max` predicate evaluators (shipped
    rules use only `equals`), the `absent` estate-wide rule path, the
    `_parse_compliance` malformed-entry warning branches, and ADMX
    display-name identity resolution through `evaluate_danger_rules`. Coverage:
    90% → **98%**.
  - `ingest.py` — the flat `<Permission>` delegation fallback (alternate SDDL
    parsing path used by older/third-party GPO reports). Coverage: 91% → 93%.
- Cross-model adversarial review (kimi) ran against all new tests; four
  SHOULD-FIX findings (missing line-175 test, unasserted `<Type>` fallback,
  uncovered `_parse_compliance` empty-field branch, untested ADMX resolution)
  were addressed before this entry.

#### Behavior change: load_danger_rules now raises RuntimeError on shipped-rules failure (WI-069)

- `load_danger_rules()` in `src/gpo_lens/danger.py` previously returned an
  empty list (`[]`) silently when the shipped `danger_rules.toml` failed to
  load or contained no rules. This meant every curated danger check was
  effectively disabled without any signal — a security tool that swallows
  its own rule-set failure would report a clean estate while having no rules
  to evaluate.
- It now raises `RuntimeError` with a descriptive message when the shipped
  rules file is missing, corrupt, or empty. This is a fail-fast policy: a
  packaging bug, accidental deletion, or file corruption must be loud, not
  silent.
- **User-supplied rules via `GPO_LENS_DANGER_RULES_DIR` are unaffected.**
  Malformed TOML in a drop-in directory produces a `warnings.warn` and is
  skipped; the load does not abort. Only the shipped `danger_rules.toml`
  (part of the package) is subject to the fail-fast contract.

#### Fix: `narration.call_llm` no longer leaks Anthropic headers to non-Anthropic endpoints (WI-064)

- `call_llm` previously sent `x-api-key` and `anthropic-version` headers
  unconditionally, regardless of `GPO_LENS_LLM_ENDPOINT`. This caused
  OpenAI-compatible proxies that reject unknown headers to fail, and meant the
  Anthropic API key was sent to whichever host the operator pointed at.
- Headers are now chosen by hostname detection: Anthropic hosts
  (`api.anthropic.com` and `*.anthropic.com`) get `x-api-key` + `anthropic-version`;
  all other hosts get `Authorization: Bearer <key>`. Lookalike and suffix-attack
  domains (`api.anthropic.com.evil.com`, `xanthropic.com`, etc.) are correctly
  treated as non-Anthropic — the leading dot in `.anthropic.com` defeats the
  suffix attack.
- A new `GPO_LENS_LLM_PROVIDER` env var (`anthropic` / `openai` / `auto`,
  default `auto`, case-insensitive) lets operators force the header style when
  a proxy or gateway hostname is ambiguous. Unrecognized values fall through
  to `auto` detection rather than failing — narration degrades gracefully.
- **The request body shape is unchanged** (still Anthropic-shaped
  `{"system":..., "messages":[...]}`). True OpenAI chat-completions endpoints
  will still not work end-to-end; that is filed as a separate work item.

#### Fix: SYSVOL never collected — clobbered `$dom` AD-domain object (the real root cause)

- **The principals/SID-resolution loop reused `$dom` as a local** for the
  `DOMAIN\user` part of a translated SID, overwriting the script-level
  `Get-ADDomain` object set at the top. By the time the SYSVOL copy ran,
  `$dom.DNSRoot` was empty, so the source path became `\\\SYSVOL\\Policies`
  (a path that does not exist) and the copy collected **nothing** — every
  SYSVOL/GPP/cPassword detector went blind. The same clobber also broke the
  Get-ADObject SID supplement (it calls `$dom.DNSRoot` after the clobber, into
  an empty `catch`) and nulled the `domain` field in principals/group exports.
- Renamed the loop-local to `$domPart`; `$dom` is now assigned exactly once.
  This is a **pre-existing regression** from the principal-resolution feature,
  not from the recent SYSVOL/identity work — but the earlier false-success bug
  hid it (it reported "SYSVOL copy" success despite 0 files); the false-success
  fix is what surfaced it.
- **Validated end-to-end on a live domain** (scheduled task as the machine
  account, no stored credential): SYSVOL-Policies went from 0 files to **5,328
  files / ~90 MB across 17 policy folders**, `principals.domain` resolved
  correctly, and one security-filtered folder was honestly flagged inaccessible
  rather than silently dropped.
- **New AST guard** (`scripts-parse.Tests.ps1`): asserts `$dom` is assigned
  exactly once in the collector, so this clobber cannot regress.

#### Fix: collector aborted with parser "formatting" errors (non-ASCII)

- **`Export-GpoEstate.ps1` had an em-dash (`—`) inside a string literal**, added
  with the SYSVOL-coverage work. PowerShell 5.1 reads a BOM-less `.ps1` as the
  ANSI code page, so the em-dash's bytes corrupted the string token and the
  parser aborted the whole script with a cascade of misleading syntax errors
  before it ran anything. Scrubbed the script to ASCII-only. Confirmed it now
  parses and executes on a real domain-joined Windows box (PS 5.1).
- **New pester guard** (`tests/powershell/scripts-parse.Tests.ps1`,
  windows-latest CI): AST-parses every `scripts/*.ps1` and asserts ASCII-only,
  covering the collector that the install/uninstall unit tests never load. This
  is the gap that let the break ship — the collector had no CI parse check.

#### Remove estate imports from the web UI

- **The Ingest page can now delete a snapshot.** Each row in the Snapshots table
  has a Delete action (with a confirm and the newest snapshot marked
  `current`); removal cascades away the whole estate via the existing
  `snapshot(id) ON DELETE CASCADE` foreign keys. Deleting the current snapshot
  falls back to the next newest; deleting all returns to the empty-estate state.
  Gated on the `INGEST` permission and the same-origin CSRF check, and audited
  (`audit.snapshot_delete`). New `store.delete_snapshot`.

#### New: Conflicts view (`/conflicts`)

- **Estate-wide conflict surfacing — two lenses, both previously CLI-only.**
  - **Resolved (who wins):** `topology.precedence_conflict_rollup` collapses the
    per-OU resolved conflicts into one row per *root cause* (competing settings +
    winner), ranked by blast radius. On a real estate this turned **10,935 per-OU
    conflict instances into 58 distinct conflicts** — the same handful of GPO
    pairs re-counted down the OU tree. Each row expands to the scopes it spreads
    to; winner and overridden GPOs deep-link to their detail pages.
  - **Defined inconsistently:** `queries.conflicts` lists settings assigned
    different values across the estate (89 on the same export — most newly
    visible now that GPP/Audit/Printers identities are readable and bucket).
  - The "Setting conflicts" posture card links here (it was previously a dead
    count), plus a primary-nav entry.
- *Perf note:* the resolved lens resolves every OU chain (~3s on a 900-OU
  estate), so it is computed only when its tab is the active view; the defined
  lens is cheap. Caching the rollup is a future optimization.

#### Readable identities everywhere — no hashed setting keys

- **Every CSE now resolves to a human-readable identity; the opaque
  `<cse>:<block>:<hash>` fallback is gone.** Validated against a real 3,900-setting
  export: zero hashed identities remain (was ~1,900). This fixes the unreadable
  `IDENTITY` column in the GPO detail view, the Effective/Resultant table, **and**
  OU browsing — they all render the same `identity`.
  - **GPP preferences** (Drive Maps, Printers, Services, Scheduled Tasks,
    Shortcuts, Files, Folders, Local Users & Groups, Power Options) expand into
    one readable row per item (`PortPrinter:floor1-printer`, `Drive:I:`).
  - **Security** keys on the real child element, not an attribute
    (`Account:ClearTextPassword`, `UserRightsAssignment:SeAssignPrimaryTokenPrivilege`,
    `RestrictedGroups:BUILTIN\Remote Desktop Users`), while the legacy
    `Type`-attribute form still maps to the same key for cross-export diffs.
  - **Advanced Audit** uses the subcategory (`AuditSetting:Audit Credential
    Validation`); **Folder Redirection** resolves the KnownFolder GUID to a name
    (`Folder Redirection:Documents` = destination path).
  - Anything else falls back to `<BlockType>:<natural key>` from the first naming
    child/attribute, degrading to the block type for a genuine singleton. A
    readable-but-duplicate key is disambiguated with an ordinal (`… #2`), never a
    hash.

#### New: Inventory tab

- **`/inventory` lists every GPO with drill-in to detail**, with search (name or
  GUID), a status filter (linked / unlinked / empty / both-sides-disabled), and
  sort by name / links / settings / modified. Added to the primary nav. This is
  the "show me all the GPOs" browser the severity-sorted dashboard findings list
  was never meant to be.

#### Dashboard findings: usable by default

- **Informational findings are hidden by default.** A large estate can carry
  thousands of `info`-level rows (e.g. ~4,000 enforced links) that buried the
  actionable findings across dozens of pages. The default view now shows
  critical/high/medium/low with a "Show all" escape hatch and an "All (incl.
  info)" filter option; a posture deep-link still shows its whole category.
- **Estate-wide findings no longer render a blank GPO cell** — they read
  `(estate-wide)` instead, so the GPO-name sort is no longer dominated by blanks.

#### Collector: SYSVOL-less exports no longer pass silently

- **`Export-GpoEstate.ps1` now verifies SYSVOL files actually landed before
  reporting "SYSVOL copy" success.** Previously the section reported success
  whenever no copy *exception* was thrown — which was also true when the source
  share enumerated zero policy folders (unreachable `\\domain\SYSVOL\…\Policies`,
  DFS/auth failure) and nothing was copied. That produced an export ~5% of normal
  size with **no SYSVOL data at all**, which silently blinds every SYSVOL-only
  detector (cPassword, GPP Scheduled Tasks, GPP Local Users & Groups,
  `Registry.pol` resolution). The copy now counts files on disk and surfaces the
  source enumeration error (no longer swallowed by `SilentlyContinue`), failing
  the section with a "GPP/cPassword detection will be BLIND" message instead.
- **Zip step reconciles archived-vs-on-disk file counts.** PowerShell 5.1's
  `Get-ChildItem -Recurse` silently skips paths over `MAX_PATH` (260 chars) —
  exactly the deep SYSVOL/GPP trees — so an archive could omit whole subtrees
  while still printing "Done". The collector now warns loudly when paths could
  not be enumerated and prints the zipped file count.

#### Ingest: a missing SYSVOL is a loud, critical finding

- **`load_estate` emits a `missing_sysvol` coverage gap** when no GPO matched a
  SYSVOL folder (directory absent or empty). It surfaces as a **critical** Doctor
  finding ("No SYSVOL collected — GPP/cPassword detectors are BLIND, not clean"),
  so a SYSVOL-blind run can no longer masquerade as a clean estate.

#### GPO detail: readable Registry identities

- **Group Policy Preferences Registry settings are now parsed into one readable
  row per value** (`HKLM\key:name = value`) instead of collapsing an entire
  `<RegistrySettings>`/`<Collection>`/`<Registry>`/`<Properties>` tree into a
  single opaque `Registry:Policy:<hash>` row. GPP `action` (C/R/U/D) is preserved
  in each row's `raw` for merge logic.
- **Administrative-Templates policies** (`<Policy>`) now use the
  category-qualified policy name as identity (e.g.
  `Windows Components/Internet Explorer/Site to Zone Assignment List = Enabled`),
  and classic `<RegistrySetting>` blocks resolve to `KeyPath:ValueName`. The
  unreadable hashed-identity rows in the Registry table are gone.

#### Dashboard: clickable Posture indicators

- **Posture cards deep-link into the Doctor-findings table, pre-filtered to that
  issue.** The findings list gained a `category` filter (exact or `cat:`-prefix,
  so "Broken references" catches every `broken_ref:<type>`); each fired card that
  has a backing finding category is now an anchor to `?category=…#findings` with
  an active-filter chip and clear (✕). Set conflicts, loopback, and WMI-filtered
  cards have no backing finding and stay non-clickable rather than dead-ending on
  empty results.

## v0.8.5 — 2026-06-26

### Per-user RSoP caveat banner (design doc)

- `PrincipalResultant` now carries a `caveat_mechanisms: list[str]` field that
  explicitly lists the non-simulated mechanisms applicable to each resultant
  (loopback, WMI, ILT, AD-site, deny-ACE, primary-group/foreign-SID).
- CLI `resultant` command renders a "Non-simulated mechanisms" banner after
  the caveat summary. JSON output includes the `caveat_mechanisms` array.
- Web `/resultant` template shows caveat chips for each non-simulated mechanism.
- Boundary tests (`tests/test_principal_resultant_boundary.py`) cover AC-1
  through AC-9 from `docs/design/per-user-rsop.md`.

### WI-073 — per-provider default model in call_llm

- `call_llm` now defaults to `gpt-4o` for OpenAI providers and
  `claude-sonnet-4-20250514` for Anthropic, instead of always defaulting to
  the Anthropic model (which 400s on true OpenAI endpoints).

### M4 — ADMX threaded through dispatch layer

- `golden_diff` and `admx_coverage` in `query_dispatch.py` now accept an
  optional `admx` parameter. The `/ask` NL routing path injects
  `app.state.admx` for these queries, so ADMX resolution is no longer
  silently absent when called via the web ask route.

### H1 — /delegation route crash on empty DB

- `create_app()` now always calls `init_db()` on the DB file, even when it
  already exists (idempotent — `CREATE TABLE IF NOT EXISTS`). Previously an
  empty/uninitialized DB file caused `sqlite3.OperationalError` in the
  delegation route, which only caught `ValueError`.
- Delegation route now catches `(ValueError, sqlite3.Error)`.

### Loopback awareness in precedence-conflicts

- `cmd_precedence_conflicts` CLI command now displays a loopback caveat banner
  when any GPO in the estate has loopback processing enabled (merge/replace).
  This makes the OU conflict view honest for estates using loopback (RDS/VDI).

### Web UI — golden-diff and admx-coverage routes

- New `/golden-diff` route with zip upload, mirroring the `/baseline` route.
- New `/admx-coverage` route showing estate-wide ADMX template inventory and
  gap detection (referenced, unreferenced, gaps).

### CLI/web tests for v0.8.0 features (L1, L2)

- `tests/test_cli_golden_diff.py` — CLI tests for `golden-diff` (text + JSON).
- `tests/test_cli_admx_coverage.py` — CLI tests for `admx-coverage` (text + JSON).
- `tests/test_web_delegation.py` — web tests for `/delegation` route on empty,
  uninitialized, and populated DBs.
- `tests/test_loopback_awareness.py` — loopback caveat in precedence-conflicts
  and settings-at-som CLI output.

### WI-075 — Web route tests for golden-diff and admx-coverage

- `tests/test_web_golden_diff.py` — GET form, POST valid zip, POST invalid
  zip, size-limit 413, empty DB.
- `tests/test_web_admx_coverage.py` — GET with data, empty DB, blank file DB,
  gap section rendering.
- Route coverage: `golden.py` 47%→100%, `admx_coverage.py` 57%→100%.

### ADMX threading through API dispatch layer

- `/api/v1/query/{query_name}` now injects `app.state.admx` for queries
  with an `admx` optional param (matching the `/ask` route pattern).
  Previously `admx_coverage` via the API silently ran without ADMX
  templates.

### WI-076 — som_effective_gpos parent-OU walk fallback

- When the target SOM is not in the estate (e.g. a principal DN whose
  OU was not captured by the collector), the function walks up the DN to
  find the closest parent SOM and returns its `InheritedGpoLinks`.
- `_split_dn` respects backslash-escaped commas in LDAP DNs.
- `_find_parent_som` uses O(n+m) dict lookup instead of O(n×m) scan.
- Site SOMs are skipped during the walk (parallel scoping axis).
- Spec AC-01 updated to document the fallback and its limitations
  (`inheritance_blocked` on uncollected intermediate OUs).

## v0.8.0 — 2026-06-26

### Golden-backup comparison (WI-061)

- New `golden-diff` CLI command compares the live estate against the org's own
  known-good GPO backup (a .zip or directory). GPOs are matched by name;
  settings within matched GPOs are compared by (side, cse, identity).
- Reports: `compliant`, `changed` (value drift), `added` (new since backup),
  `removed` (deleted since backup), `gpo_added`, `gpo_removed`.
- `golden_diff()` and `golden_diff_summary()` in `queries/_golden.py`,
  registered in `query_dispatch.py`, exported from `queries/__init__.py`.
- Blocked extensions are skipped. Original casing is preserved in output.
  Duplicate GPO names trigger a warning.

### ADMX Central Store auto-detection (Plan 010 WI-B.2)

- `find_admx_dir()` in `admx_parser.py` auto-detects the
  `PolicyDefinitions` (Central Store) directory in the export — checks
  `SYSVOL-Policies/PolicyDefinitions/` then `PolicyDefinitions/` directly.
- New `_get_admx(args)` helper in `cli/_helpers.py` consolidates the 5
  duplicated `--admx-dir` handling blocks across CLI commands into one
  function with priority: explicit `--admx-dir` → auto-detect from `src` →
  `None`.
- Updated `admx-gaps`, `baseline-diff`, `danger`, `report`, and
  `explain-setting` CLI commands and the web app to use auto-detection.
  This resolves the dominant noise source in baseline diff (1,605
  "missing" rows that were just unresolved registry paths).

### ADMX coverage view (WI-062)

- New `admx-coverage` CLI command shows estate-wide ADMX template inventory:
  which policies are referenced by GPOs, which are defined but unused, and
  which estate settings have no ADMX match (gaps).
- `admx_coverage()` in `queries/_admx_coverage.py` returns an
  `AdmxCoverageReport` with `summary`, `referenced`, `unreferenced`, and
  `gaps` sections. Gap scanning runs even when no ADMX policies are loaded.
- Registered in `query_dispatch.py`, exported from `queries/__init__.py`.

### Delegation estate-wide rollup (breadcrumb: estate-wide-delegation-view)

- New `delegation --rollup` CLI flag and `/delegation` web route provide a
  per-trustee → editable-GPO matrix, sorted by breadth (most GPOs first).
- `delegation_rollup()` in `queries/_delegation.py` inverts per-GPO
  delegation entries into a per-trustee view with:
  - Unknown-SID detection (not well-known, not in collected principals)
  - Default-writer vs non-default-writer flagging
  - Resolved name from `authz.resolve_principal`
- Deny entries and Read/Apply-only permissions are excluded.
- `DelegationRollupEntry` dataclass with trustee, SID, resolved name,
  flags, GPO names, and permissions.

### Design docs

- `docs/design/per-user-rsop.md` — design for principal-group effective
  policy: resolve security-filter SIDs against collected AD group membership
  to compute "what does this user actually get" for the common case, with
  a caveat banner for unsimulated mechanisms (loopback, WMI, ILT, sites).
  Acknowledges existing `merge.principal_resultant` (Plan 021).
- `docs/design/multi-domain-forest.md` — swimlane model for multi-domain
  AD: per-domain `Estate` objects with a thin coordination layer that
  detects cross-domain GPO links. Cheaper than a true multi-forest refactor.

### Tests

- 29 new tests in `tests/test_v080_features.py` covering golden_diff,
  admx_coverage, delegation_rollup, and find_admx_dir edge cases.
- 3 new routing corpus entries for `golden_diff`, `admx_coverage`,
  `delegation_rollup`.
- Adversarial review (glm) found 5 high-severity and 7 medium-severity
  issues; all were fixed before release (delegation route crash on empty
  DB, report auto-detection gating, fuzzy key matching false positives,
  golden_diff summary undercount, duplicate GPO name handling, original
  casing preservation, Protocol conformance, docstring accuracy).

## v0.7.2 — 2026-06-23

### SNI-safe, sibling-safe uninstaller

- **`uninstall-windows.ps1` no longer tears down a co-resident tool's TLS
  binding.** The SSL-binding cleanup now decides catch-all vs SNI from the
  site's `sslFlags` (bit 1), not from hostname presence — a catch-all binding
  can carry a host header (`*:PORT:host` with `sslFlags=0`), where the cert
  lives at `ipport=0.0.0.0:PORT`, not `hostnameport=host:PORT`. In SNI mode the
  script removes only the per-host `hostnameport` binding and leaves the
  catch-all alone (a sibling such as cert-watch on port 443 may own it). The
  numeric/string `sslFlags` dual-form is handled the same way as the installer
  (WI-041). Validated end-to-end on a real IIS host with disposable
  catch-all + SNI sibling sites.

- **Fixed a destructive bug: the uninstaller hard-coded the site directory.**
  The final cleanup step removed `C:\inetpub\gpo-lens` regardless of
  `-SiteName`, so running it for a different site could delete the real
  gpo-lens site directory. It now removes the site's OWN `physicalPath`
  (captured before the site is removed), falling back to a new `-SitePath`
  parameter only when the site is already gone.

- **New parameters:** `-HostName` (target an SNI binding when the site is
  already removed) and `-SitePath`. The catch-all/SNI decision is extracted
  into pure functions (`Get-IsSniFlag`, `Resolve-OwnedSslBinding`) behind a
  dot-source guard, covered by `tests/powershell/uninstall-windows.Tests.ps1`
  (11 Pester tests). Note: the installer already supported `-Port 443` and
  `-Sni`; this change brings the uninstaller to parity.

## v0.7.1 — 2026-06-23

### HEC plaintext token warning, store.py assert fix, CLI coverage round 2

- **sinks.py HEC plaintext token warning.** `HecSink.__init__` now emits
  a `UserWarning` when the HEC URL is `http://` (the Splunk token is sent
  in the `Authorization` header in plaintext). The warning includes the
  hostname:port so multi-sink setups can identify the offending URL.
  Hoisted `import warnings` to module top-level (was function-local in
  `from_env`); fixed `from_env` `stacklevel` from 1 to 2. Added 2 new
  tests verifying the warning fires for `http://` and not for `https://`.
  Existing tests that intentionally use `http://` mock servers are
  silenced via `pyproject.toml` `filterwarnings`.

- **store.py assert replaced with RuntimeError.** `save_estate` used
  `assert snapshot_id is not None` which is a no-op under `python -O`.
  Replaced with an explicit `if snapshot_id is None: raise RuntimeError`.

- **`.gitattributes` added.** Marks `.sqlite3`, `.db`, `.zip`, `.coverage`,
  and image files as binary to prevent merge conflicts and accidental
  text normalization.

- **CLI coverage gaps closed (round 2):**
  - `cli/_diff.py`: 41% → 98%. 27 direct-call tests covering diff,
    diff-settings, changelog, snapshots, and baseline-diff (text + JSON,
    with/without changes, filters, zip baseline path).
  - `cli/_delegation.py`: 30% → 100%. 15 direct-call tests covering
    perms, delegation (all 5 output sections), and sddl (text + JSON,
    with/without data).

- **WI-036, WI-042 closed in memory** (paperwork — code was already
  resolved in commit `3e6f06e`).

### Adversarial review
One round of adversarial review (GLM). Found and fixed: missing test for
HEC warning (C-1), existing test warning suppression (C-2), function-local
`import warnings` (M-1), incorrect `stacklevel` in `from_env` (M-2), warning
message missing URL (L-1), fixture return type annotations and decorator
style inconsistencies in test_cli_diff.py (M-4, M-5).

### Test coverage
- 1484 passed, 6 skipped. `ruff` and `mypy --strict` clean. Coverage
  90.36% (with samples), up from 88.31%.

## v0.7.0 — 2026-06-23

### sslFlags bitmask fix, test coverage gaps closed, WI-044 deduplicated

- **WI-041 (low, fix):** `install-windows.ps1:158` used string matching
  (`-match "Sni"`) to detect SNI from IIS `sslFlags`, which fails when
  `sslFlags` is a numeric bitmask (the common case on modern IIS). Fixed
  to use `[int]::TryParse` + `-band 1` for numeric values, with string
  fallback for older IIS provider versions that return `"Sni"`/`"None"`.
  The Pester test that codified the old behavior (`sslFlags = 1` →
  `Sni = $false`) is updated to assert the correct behavior (`Sni = $true`).
  Added a test for `sslFlags = 3` (SNI + Central Cert Store combined).

- **Test coverage gaps closed:**
  - `cli/_resultant.py`: 15% → 76% coverage. Added 40 tests (26
    subprocess + 14 direct-call) covering text/JSON output, invalid SID,
    unknown principal, computer SID, DN, and all error paths.
  - `cli/_report.py`: 20% → 87% coverage. Added direct-call tests for
    Markdown/HTML output, file output, `--json` refusal, baseline
    loading (valid/invalid/missing), changelog (`--since`), and
    `--admx-dir` warnings.
  - `web/routes/resultant.py`: 48% → 100% coverage. Added 11 tests
    covering GET form, POST with empty/valid/whitespace SID, computer
    SID, DN, viewer permission, and exception handling.

- **WI-044 (low, closed):** Closed as duplicate of WI-043. Both work
  items had identical descriptions ("Cross-process ingest lock has no
  multi-process test"). WI-043 was resolved in commit `3e6f06e`.

### Test coverage
- 1440 passed, 6 skipped. `ruff` and `mypy --strict` clean. Coverage
  88.31% (with samples), up from 87.03%.

## v0.6.4 — 2026-06-20

### Coverage CI gate, danger loader resilience, merge spec (WI-032, WI-034, WI-035)

- **WI-034 (medium, ci):** Coverage is now enforced in CI. `pyproject.toml`
  `addopts` carries `--cov=src --cov-report=term-missing --cov-fail-under=85`
  (single source of truth), and the CI workflow step is renamed to
  `Run tests with coverage`. Local and CI both pass the 85% floor (current:
  86.71% with samples, 86.55% without). The dual-flag drift the first
  review caught was fixed by removing the explicit flags from CI and
  relying on `addopts`.
- **Danger TOML loader hardening (active breadcrumb):** `_load_rules_file`
  no longer crashes on a malformed user-supplied TOML via
  `GPO_LENS_DANGER_RULES_DIR`. Three categories of malformed input are now
  handled with a `warnings.warn` and a `continue`:
  - `rules` is not an array (scalar/bool/table).
  - A `[[rules]]` entry is not a dict (e.g. int/str).
  - Required fields are missing (`id`, `title`, `severity`, `applies`,
    `identity`, `reference`).
  5 new tests in `tests/test_danger.py` pin the behavior
  (skips, warning content, valid peers still load).
- **WI-032 (medium):** Closed. The 5 calibrated TOML danger rules have
  known measurement against both sample estates (work + lab): 0 Bucket 1
  findings (estates use ADMX-managed `Registry:Policy:*` identities, not
  raw HKLM preferences), 35 Bucket 2 on the work estate, 0 on the lab
  estate. Calibration tests in `tests/test_calibration.py` document the
  observed behavior.
- **WI-035 (low, docs):** Added `docs/spec/wi_merge.md` — the formal
  work-item spec for `merge.py` (Plan 021). 20 ACs cover the CSE merge
  taxonomy, merge mode dispatch (UNION/ADDITIVE/ACCUMULATE/LAST_WRITER_WINS/
  AUTHORITATIVE_REPLACE/SINGLE_WINNER/MERGE_REPLACE_FLAG/APPROXIMATE),
  ILT exclusion (decision 2), token expansion, security-gate evaluation,
  principal resultant composition, and caveat summary format. Two rounds
  of adversarial review found and fixed 12 spec/code mismatches before
  the spec was committed.

### Test coverage
- 1352 passed, 6 skipped. `ruff` and `mypy --strict` clean. Coverage
  86.71% (with samples), 86.55% (CI scenario, no samples).

## v0.6.3 — 2026-06-19

### End-to-end validation of Plans 017–021 — four real-data-only bugs fixed

The Plans 017–021 feature work passed unit/sample tests but had bugs that only
surface against real collector output (the synthetic fixtures used canonical
string values the live data never emits). End-to-end runs against the lab and
work estates caught:

- **Danger owner false positive (Plan 018):** real GPO SDDL names the owner with
  the domain-relative alias `O:DA` (Domain Admins), not a raw `S-1-5-21-…-512`
  SID. `resolve_well_known` didn't know `DA`/`EA`, so **every** GPO was flagged
  "owned by a non-admin trustee." Added the domain-relative SDDL aliases to
  `authz._SDDL_SID_ALIASES`.
- **Danger Creator Owner false positive (Plan 018):** the `CO` (S-1-3-0)
  full-control ACE present in every default GPO DACL was flagged as a hijack
  primitive on every GPO. Creator Owner / Creator Group / Owner Rights are
  non-actionable placeholders (no principal authenticates as them) — added them
  to `detection._DEFAULT_WRITER_NAMES`. Clean lab now reports 0 findings; the
  messy work estate still surfaces 35 real custom-group writers.
- **Principals dropped on the `--db` path (Plans 020/021):** `store` persisted
  everything except `principals` / `group_members`, so `danger` and `resultant`
  run against a saved snapshot silently degraded to raw SIDs. Added schema v3
  (`principal` + `group_member` tables) with a defensive read path for pre-v3
  DBs.
- **`container_type` never normalized (Plans 017/019/021):** `Get-GPInheritance`
  serializes its `SomType` enum as an integer (Domain=1, OU=2), but the `/ou`
  type filter and `merge`/`topology` site/domain logic compare against the
  strings `"domain"`/`"ou"`/`"site"`. The type filter returned nothing on real
  data. Normalized at ingest (`_normalize_container_type`).

### Test coverage
- 1338 passed, 6 skipped. Added regression tests for each fix. `ruff` and
  `mypy` clean.

## v0.6.2 — 2026-06-19

### Work-item hygiene: close 4 resolved WIs

Four work items had their fixes committed in prior sessions but were never
transitioned in the tracking system:

- **WI-022** (high): CI gate for work-domain identifiers — `check_committed_identifiers.py`
  + `identifier-gate` job + secret configured. 14 tests. Caught real leak on first run.
- **WI-024** (low): OU-detail scope-caveats test assertion tightened from vacuous
  `"loopback"` to discriminating `"loopback="` (commit 46d9e46).
- **WI-031** (medium): `danger_findings()` reduced from 3x to 1x per dashboard render
  via parameter injection (`danger=` / `danger_count=`). ADMX propagation gap also closed.
- **WI-033** (low): Search `q` parameter capped at 200 chars (`_MAX_SEARCH_LEN`) in
  all three web endpoints to bound O(n*m) substring scan cost.

### Remaining open WIs

- **WI-032** (medium): Danger rules lack calibration tests against real estate (needs `samples/`).
- **WI-030** (medium): `install-windows.ps1` IIS binding/SNI/cert logic has no automated test harness.
- **WI-018** (low): Standing decision — re-evaluate web/snapshot/event-store cost vs value.

### Test coverage
- 1310 passed, 6 skipped. `ruff` and `mypy --strict` clean.

## v0.6.1 — 2026-06-18

### WI-028: Loopback mode parser now resolves real-world settings

The `_extract_loopback_mode` parser in `topology.py` only handled the
`Security` CSE shape (`SettingString`/`SettingBoolean` children). Real-world
GPO exports configure loopback via the `Registry` CSE, where the raw dict
has a `Policy > DropDownList > Value > Name` structure. Every real-world
loopback setting was classified as "unknown" (merge/replace never resolved).

Now handles three raw-dict shapes: Security CSE `SettingString`/`SettingBoolean`,
Registry CSE `Policy > DropDownList > Value > Name`, and a display_value
fallback. `Policy > State = "Disabled"` correctly returns None. Calibration
test against the real work estate confirms zero "unknown" modes across all
28 loopback GPOs.

### Plans 017 & 018: Directory search, ADMX policy names, danger detectors

- **Plan 017**: Directory page (`/ou`) gains search (`q`), type filter
  (`type`), and sort (`sort`), mirroring the dashboard's filter UX. 15 tests.
- **Plan 018 Phase A**: ADMX policy-name crosswalk wired into the web UI via
  `GPO_LENS_ADMX_DIR` env var / `--admx-dir` CLI flag. Registry settings show
  human policy names with raw identity as secondary detail. Strict superset
  when unconfigured. Also fixed MS16-072 Read detection (Apply Group Policy
  = Read+Apply per GPMC, was incorrectly treated as non-Read).
- **Plan 018 Phase B**: New `danger.py` core module with curated, cited
  dangerous-configuration detectors. Bucket 2 (structural): GPO writable by
  non-admin (DACL + Owner SID), local admin push, over-broad apply scope.
  Bucket 1 (setting-value): 5 cited TOML rules (WDigest, SMB signing, LM
  hash, AutoAdminLogon, NTLMv1) + pure evaluator. New `/danger` web view,
  `gpo-lens danger` CLI, dashboard posture indicator. 35+ tests.

### WI-025/026/027: Dashboard filtering, pagination, export (resolved)

Already implemented and resolved in v0.6.0. Breadcrumbs moved to resolved/.
46 tests cover all three features.

## v0.6.0 — 2026-06-18

### Production-readiness: IIS deployment, observability, access control

First **Windows smoke test** of `install-windows.ps1` on a real IIS host
(`LAB-HOST-1`), closing the "untested on Windows" gap flagged in prior
reflections. The installer ran end-to-end: Python 3.14.6 resolution, venv
creation, idempotent upgrade, IIS site/pool management, TLS binding, and
firewall — all clean. cert-watch (sharing the host on port 443) was not
disrupted.

- **`-Sni` switch (install-windows.ps1).** gpo-lens can now share port 443
  with cert-watch (or any HTTPS site) via SNI, instead of requiring its own
  port. Sets `sslFlags=1` on the IIS binding before the netsh
  `hostnameport` sslcert add — the ordering that the prior error-87 failure
  (cert-watch WI-047) got wrong. Non-SNI remains the default (dedicated port,
  catch-all cert). The catch-all `ipport` binding is never touched in SNI
  mode.
- **`-WindowsAuth` switch (install-windows.ps1).** Installs the
  `Web-Windows-Auth` role service if missing, enables Windows Authentication,
  and disables anonymous access — so only authenticated domain users reach
  the app. The smoke test found the role service was not installed by
  default, leaving the site open; this switch makes the fix a one-liner.
  Windows Auth is sticky: re-running without the flag does not re-enable
  anonymous access (security-positive default).
- **`GET /healthz`** (unauthenticated) — liveness probe for IIS/app-pool
  supervisors. Returns `{"status":"ok"}`.
- **`GET /api/version`** (unauthenticated) — version surface for ops.
  Returns `{"version":"…","name":"gpo-lens"}`.
- **Audit log (JSON-lines, best-effort).** Every ingest path (success,
  malformed zip, invalid estate, size limit, concurrent 409) is appended to
  `<db_dir>/audit.log` (or `GPO_LENS_AUDIT_LOG` override) with timestamp,
  principal, outcome, detail, and request-id. Thread-safe via
  double-checked locking. Never raises into the request path.
- **Backup/restore runbook** added to `deploy/iis/README.md`: online SQLite
  `.backup` (no downtime), offline copy, restore procedure, migration note.

### CI gate: no work-domain identifiers in committed files (WI-022)

Mechanically enforces the AGENTS.md hard rule. The checker reads forbidden
identifiers from `GPO_LENS_FORBIDDEN_IDENTIFIERS` (CI secret) so the real
identifiers never touch the repo. No-op locally when the env var is unset
(warns on stderr, exits 0). UTF-16 aware (BOM detection), streaming binary
sniff (no OOM), skips `samples/` and `.venv/`. 13 tests.

### Web UI: dashboard filtering, pagination, export (WI-025/026/027)

- **Dashboard findings table**: filter by severity, search by text, sort by
  severity/GPO/finding, paginated (default 50, max 200, "all" supported).
- **In-app CSV/JSON export** of findings and settings dump.
- **OU list and GPO detail paginated** for large estates.
- Shared `_pagination.html` partial with page/per_page controls.

### Test quality (WI-024)

OU-detail loopback caveat test tightened: was vacuously matching the word
"loopback" in fallback text; now asserts `"loopback="` which only appears in
rendered caveats.

### Plan 016 — Splunk change attribution (proposed, shelved)

Tracked but not started. Has a hard discovery dependency (confirm what
Splunk holds re: AD event 5136 / SYSVOL 4663) before any code. Ingest model
(not live query) keeps the deterministic core offline.

## v0.5.0 — 2026-06-15

### Windows deployment run-through fixes (first end-to-end run on real AD)
First full collector→ingest→doctor run against a live domain (read-only, via a
least-privilege service account) surfaced several defects that the flat,
hand-built test fixtures had hidden:
- **GPP scanners now work against a real SYSVOL.** `gpp-tasks`, `gpp-groups`,
  and cpassword detection silently returned nothing on real exports: a real
  SYSVOL nests each CSE in its own subfolder (`Preferences/Groups/Groups.xml`),
  but the walker only looked one level too shallow (`Preferences/Groups.xml`).
  It now handles both the nested and flat shapes.
- **Case-insensitive SYSVOL path resolution.** Default GPOs ship as
  `MACHINE`/`USER` (upper-case); on a case-sensitive (Linux) analysis host the
  literal `Machine`/`User` lookups missed them entirely — affecting GPP scans,
  `Registry.pol` resolution, and script-reference checks. New `paths.py`
  (`ci_child`/`ci_path`) resolves SYSVOL children case-insensitively.
- **`doctor` no longer crashes on an unreadable SYSVOL subtree.** A
  security-filtered GPO copied with its ACLs intact (or an extraction that
  dropped a directory's traversal bit) raised `PermissionError` and aborted the
  whole run; such subtrees are now skipped (coverage gaps are still surfaced via
  `collection-errors.json`).
- **Collector: resilient SYSVOL copy.** One inaccessible policy folder
  (Authenticated Users Read stripped) aborted the entire SYSVOL copy; it now
  skips and records each denied folder in `collection-errors.json`, mirroring
  the per-GPO `Get-GPOReport` resilience.
- **Collector: portable archive.** Replaced `Compress-Archive` (Windows
  PowerShell 5.1 writes backslash separators and directory entries that extract
  on Linux without the traversal bit) with a forward-slash, file-only zip — so
  the export ingests cleanly on a non-Windows analysis box.
- **Collector: create `OutputRoot` if missing** (the write-test failed when the
  output directory did not yet exist).
- **`gpp-tasks`: no spurious empty row** for the nested `<Task>` wrapper inside
  an `ImmediateTaskV2`'s `<Properties>` (iterate direct children, not all
  descendants).
- **README: `-OutputDir` → `-OutputRoot`** (the documented flag did not exist).

### Added — deeper coverage (GPP structured audits, Registry.pol, GPO descriptions)
- **GPP scheduled-task audit (`gpp-tasks`).** Structured inventory of every
  scheduled task / immediate task deployed by GPO (`ScheduledTasks.xml`),
  with name, action, command, arguments, and run-as account. Deterministic,
  read-only; surfaces what is configured without evaluating reachability.
  Text + `--json` (envelope `kind: "gpp-tasks"`).
- **GPP local-group audit (`gpp-groups`).** Structured inventory of local-group
  membership changes (`Groups.xml` / `LocalUsersAndGroups.xml`): target group
  + SID, members added, members removed. The single most common "who is a
  local admin where" audit question, now answerable from the estate.
- **`Registry.pol` binary parser — resolves `<Blocked/>` Registry settings.**
  When the GPO report renders the Registry CSE as `<Blocked/>`, the
  authoritative values live in `Machine`/`User` `Registry.pol` (PReg format).
  gpo-lens now parses it and replaces the opaque blocked placeholder with the
  real key/value/type triples (`source_state="registry_pol"`). New
  `registry_pol.py` module (pure stdlib). Where `Registry.pol` is absent the
  blocked placeholder is kept (we do not fabricate values).
- **`Gpo.description`.** The GPO `<Description>` field (the admin's note) is
  now captured, persisted, and surfaced in `show`, the web detail view, and
  the report — letting `stale_gpo` findings distinguish "forgotten" from
  "intentionally frozen."
- **SQLite additive migrations.** `init_db` now runs `_migrate_schema` so an
  existing DB from an older gpo-lens gains new columns (additive only) on
  open, rather than silently producing wrong results.

### Charter & correctness fixes (deep review)
- **`settings_at_som` / `som_conflicts` no longer present disabled-side
  settings as effective.** A setting on a side whose `Enabled=false` does not
  apply regardless of link enforcement — surfacing it as "effective" violated
  the "flag, don't simulate" charter. These settings are still reported by
  `disabled_but_populated` (the correct channel).
- **Tightened Domain Computers SID matching.** Both `is_security_filtered`
  (topology) and the MS16-072 check (detection) now require the `S-1-5-21-*`
  domain-SID prefix before matching the `-515` RID. Previously any SID ending
  in `-515` (e.g. a builtin-domain group) could false-match Domain Computers,
  masking real security-filtering / MS16-072 findings.
- **Determinism hardening.** `settings_dump`, `conflicts`, `som_conflicts`,
  and `precedence_conflicts` now sort their output; `load_estate` adds
  `ORDER BY` to every table read. Estate reconstruction from a DB snapshot is
  now order-independent of insertion order, which snapshot diffs and the
  `--json` contract depend on.

### Hardening
- **CSRF: `0.0.0.0` removed from the localhost Origin allow-list.** It is the
  bind-any wildcard, not a legitimate client Origin, and a cross-origin POST
  can spoof it. `localhost`/`127.0.0.1`/`::1`/`localhost.localdomain` remain.
- **SQLite DB files are created `0600`.** `init_db` now tightens the snapshot
  DB to owner-only regardless of the process umask — the DB holds the full
  estate (GPO names, delegation, settings) and must not be world/group
  readable on a shared host.

### Docs
- **README: "zero runtime dependencies" corrected** to "minimal runtime
  dependencies (defusedxml)" — the prior claim was inaccurate. Added a
  Requirements section (Python 3.12+, RSAT modules) and documented the
  `<Blocked/>` limit.

### Cleanup
- Removed dead `_QUERY_PARAMS` alias from `query_dispatch.py`.

## v0.4.0 — 2026-06-14

Headline: **sees site scope, and honest about collection coverage.** AD
site-linked GPOs are captured and flagged; GPOs the collector can't read are
named (reconciliation) instead of silently dropped.

### Honest about collection coverage (Plan 015)
- **Coverage reconciliation.** A GPO with Authenticated Users Read fully
  stripped is invisible to a least-privilege collector account (verified on a
  real domain). Rather than chase full read by granting per-GPO permissions, the
  collector emits `gpo-inventory.json` (every GPC GUID it could enumerate — run
  it once as a privileged account for an authoritative baseline), and gpo-lens
  reconciles inventory + `collection-errors.json` against the export: any GPO
  that exists but was not collected is surfaced as a **coverage gap** (new
  `doctor` `coverage_gap` finding + `summary.coverage_gap_count`) — named, never
  silently dropped. Backward compatible (absent manifests → no gaps).
- **Collector hardening.** Per-GPO report collection is resilient (one
  unreadable GPO no longer aborts the rest); inaccessible GPOs are detected via
  an AD enumeration cross-check and recorded in `collection-errors.json`.
- **Collector fix:** `Get-GPOReport` uses `-Path` (was the nonexistent
  `-LiteralPath`, which silently failed every report — surfaced by live testing).

### Sees site scope (Plan 014)
- **AD site-linked GPOs are now captured and surfaced.** The collector exports
  `sites.json` (Configuration-partition site `gPLink`/`gPOptions`); ingest models
  each site as a `container_type="site"` SOM with its direct links. New
  `gpo-lens sites` command (text + `--json`, contract `kind: "sites"`) lists
  sites and their GPO links.
- **OU views now flag site scope.** `settings-at` / `scope` caveats note that
  site-linked GPOs apply before the domain/OU chain based on the client's AD
  site, which is **not** resolved per-machine (flag, don't simulate).
- **Summary gains `linked_site_count`**; `som_count` now counts OU/domain SOMs
  only (sites counted separately). `enforced_links` / `dangling_links` correctly
  include enforced/broken site links.
- **Backward compatible:** an export without `sites.json` ingests unchanged.

## v0.3.0 — 2026-06-14

Headline: **honest about scope, and a frozen machine-readable contract.**
Scope-honesty across loopback/security-filtering/WMI/ILT, plus a versioned
JSON output contract that downstream tools can build against.

### JSON output contract (frozen, `schema_version: 1`)
- **Versioned envelope on every `--json` payload.** All machine-readable output
  is now wrapped as `{schema_version, kind, tool_version, generated_at, data}`,
  so downstream consumers can depend on a stable shape and detect contract
  evolution. Documented in `docs/spec/json-contract.md` and pinned by
  `tests/test_json_contract.py` (the freeze guard). Consumers read `data`.
- **`report --json` no longer silently emits Markdown.** It now refuses `--json`
  (exit 2, stderr) and points at the real machine-readable commands. `report`
  is a human document (`--format md|html`); the snapshot is `summary --json`,
  the per-setting body is `settings-dump --json`.
- **`settings-dump --json` now carries `source_state`** (`"normal"`/`"blocked"`)
  per row, exposing `<Blocked/>`-extension settings to consumers.
- **Errors under `--json` no longer leak to stdout.** `scope <gpo>` for a
  missing GPO now exits nonzero with the message on stderr (was exit 0 with a
  plain-text line on stdout), so "exit 0 ⟹ stdout is the envelope" holds.
- **Documented precondition:** the `events` stream is populated only by
  `ingest --diff-latest`.

### Scope honesty
- **`is_security_filtered` hardened (WI-009).** Now recognises `Everyone`
  (S-1-1-0) alongside Authenticated Users and Domain Computers, applies
  deny-ACE precedence (a deny Read/Apply on a broad trustee overrides its
  allow), and treats an *empty* delegation list as "not filtered" rather than
  a confident false positive — absence of delegation data is not evidence of
  filtering. Nested membership and inherited ACEs remain explicitly not
  modeled (charter: flag, don't simulate). Scope caveat reworded to "appears
  security-filtered (… nested membership and inherited ACEs not evaluated)".
- **All-disabled SOM is flagged, not silent.** `scope_caveats` now
  distinguishes "SOM not found" from "SOM exists but every GPO link is
  disabled," emitting a caveat for the latter instead of returning nothing
  (previously both cases were silent).

### Added
- **Four hygiene categories surfaced on the estate summary (WI-007).**
  `EstateSummary` now carries `broken_wmi_ref_count`,
  `orphaned_wmi_filter_count`, `ilt_gpo_count`, and `stale_gpo_count`,
  rendered in the Markdown/HTML report tables and the web dashboard.

### Bug fixes
- **`stale_gpos` leap-year drift.** Year math now divides elapsed days by
  365.25 so a GPO just under the threshold is not rounded up across a leap
  day. Added an injectable `now` parameter so staleness tests pin a reference
  clock and no longer rot as wall-clock time passes the fixed fixture
  timestamps (WI-010). `estate_doctor` accepts the same `now` so its
  stale-GPO finding is deterministic under test too.
- **Item-level-targeting findings name the file.** `IltHit` now reports the
  specific GPP XML file(s) (e.g. `Registry.xml`) that carry `<Filters>`
  instead of a hard-coded `SYSVOL`.
- **`settings-at` dead loopback branch removed.** The text view's estate-wide
  loopback block could surface GPOs not in scope at the queried SOM; loopback
  is already covered, correctly scoped, by `scope_caveats`.

### Tests
- New `tests/test_scope_honesty.py` and `tests/test_scope_cli.py` covering
  scope-caveat / effective-scope / ILT edge cases and the `scope` CLI command
  (WI-008). Suite: 665 passed, 25 skipped; ruff and mypy --strict clean.

## v0.2.2 — 2026-06-10

- **Note:** v0.2.1 was folded into this release.

### Bug fixes
- **`report --db` no longer shadows top-level `--db`**: Removed duplicate `--db` argument from the report subparser that silently overrode the parent parser's value (report-db-shadow).
- **`ask` validates required params before dispatch**: `settings_at_som` now errors clearly if `ou_path` is missing instead of silently returning empty results. Unexpected params from LLM routing produce a warning (dispatch-param-validation).
- **Consistent `--admx-dir` warnings**: `baseline-diff` and `admx-gaps` now warn on nonexistent/invalid `--admx-dir` paths, matching the existing `report` behavior (admx-dir-consistent-errors).

### Added
- `--version` flag to CLI (prints version and exits).
- Version-sync test asserting `pyproject.toml` version matches `__init__.__version__`.

## v0.2.0 — 2026-06-10

### Workstream D — Distribution & Polish
- **CLI decomposition**: Monolithic `cli.py` (1,749 lines) refactored into a 13-module `cli/` package. Entry points preserved; all 389 tests pass.
- **Collector hardening** (`Export-GpoEstate.ps1`): `-DryRun` flag, per-section `Write-Progress`, module validation, writability check, export summary, `-LiteralPath` for wildcard safety, least-privilege documentation.
- **Design debt fixes**: `_get_estate` raises `FileNotFoundError` instead of `sys.exit()`, DB connections wrapped in `try/finally`, architecture guard test scans all `cli/*.py` files, `settings-diff` reports `skipped_count`, dead `_PD()` import removed.
- **GitHub Actions CI**: ruff + mypy --strict + pytest, pinned action SHAs, uv caching, `permissions: contents: read`.
- **Public repo**: [github.com/hraedon/gpo-lens](https://github.com/hraedon/gpo-lens).

### Test coverage
- 389 tests. `ruff` and `mypy --strict` clean. CI green in 21s.

## v0.1.0 — 2026-06-10

### Infrastructure (Phase 0)
- **CI-ready fixture estate** (`tests/fixtures/`): 8 synthetic GPOs covering cpassword, MS16-072, version-skew, broken UNC, loopback, block-inheritance, enforced links, precedence conflicts, and blocked extensions. 25 fixture tests run without real `samples/`.

### Workstream A — AGPM-replacement story
- **`snapshot_changelog()` + `changelog` CLI**: Version-aware change log that pairs GPC/GPT version counter deltas with per-setting diffs. Distinguishes "metadata says N edits" from full setting detail.
- **`gpo-lens report` CLI**: Self-contained Markdown/HTML estate documentation export. Synthesizes estate summary, doctor findings by severity, topology overview, baseline compliance %, and change history. Print-to-PDF friendly.
- **`gpo-lens ingest --diff-latest`**: Auto-diff against the previous snapshot on ingest, appending to the changelog workflow.

### Workstream B — Security-analysis depth
- **`delegation` CLI + `delegation_deep_dive()`**: Privilege rollup (which trustees edit which GPOs), orphaned SID detection, and non-default-editor flagging.
- **`admx-gaps --admx-dir`**: Optional ADMX crosswalk integration — resolved registry paths are excluded from gap reports.
- **`loopback_awareness()` + `settings-at` banner**: Detects loopback mode (merge/replace) and prints a caveat banner when any GPO in scope configures loopback.

### Test coverage
- 280 tests (was 233), 237 non-samples tests (91.9% of total). `ruff` and `mypy --strict` clean.
