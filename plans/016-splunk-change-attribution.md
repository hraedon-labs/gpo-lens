# Plan 016 — Splunk-sourced GPO change attribution

**Status:** Not pursued for v1.3.0; verified 2026-10-06. Evidence: [src/gpo_lens/events.py](../src/gpo_lens/events.py), [tests/test_sinks.py](../tests/test_sinks.py).

The branch has outbound snapshot-change events and Splunk HEC delivery from Plan 012, not Splunk-sourced actor attribution. No `gpo_change_event` model/table, Splunk export ingestor, `gpo_change_history`/`changes_in_window` queries, Activity route or live connector exists in `src/` or tests. Plan 027's earlier claim that attribution was implemented was incorrect. Discovery and this attribution program remain deferred; no live-Splunk validation is claimed.

The design below is the historical specification; this status records the verified release scope.
**Author:** Opus 4.8
**Strategic role:** Add the *who/when/which-event* attribution layer the
Changelog has always implied — sourced from an external audit trail (Splunk),
without compromising the read-only, offline, deterministic core.

## The gap this closes

gpo-lens's **Changelog** (`snapshot_changelog`, `snapshot_settings_diff`) diffs
two ingested estate snapshots: it answers *what* differs between two photos
(version skew, per-setting deltas) but cannot attribute a change to an **actor,
a timestamp, or a specific directory/SYSVOL write** — a point-in-time export
carries no audit trail. Splunk (where AD/SYSVOL change auditing is collected)
holds exactly that. Overlaying Splunk events onto the existing snapshot diff
turns "GPO X's version changed between A and B" into "…changed by `DOMAIN\user`
at 14:02, attribute `versionNumber` / `gPCMachineExtensionNames`."

This is the project's own long-stated "snapshot -> version -> **event-attributed**"
changelog finally getting its event source. It is a strong fit for a regulated
shop: deterministic, verifiable, no AI in the truth path.

## Load-bearing decision — ingest an export, not a live query (default)

gpo-lens is "read-only, eats exports, never touches a live system." Splunk is a
live service. Reconcile by keeping the **core** on the ingest model and treating
a live connector as an optional, isolated extra:

| Mode | How | Posture |
|------|-----|---------|
| **Ingest (default, this plan)** | A Splunk saved search exports GPO-change events to JSON/CSV; gpo-lens ingests the file like any other artifact. | Core stays offline/deterministic; no credentials, no network in the truth path. |
| **Live connector (deferred, WI-6)** | Optional `[splunk]` extra queries the Splunk REST API at request time. | Bends read-only/offline; isolated exactly like the LLM narration extra — imports the core, never imported by it. |

The deterministic core must remain usable with **zero** external services (the
[[user-regulated-workplace]] constraint). The live connector is opt-in only.

## Discovery dependency (do this first — feasibility hinges on it)

Confirm what Splunk actually holds before building the ingestor:

- Is **AD object auditing — event 5136** ("directory service object modified")
  collected for the GPC container (`CN={GUID},CN=Policies,CN=System,…`)? This is
  the gold source: `SubjectUserName` (who), time, changed attribute
  (`versionNumber`, `gPCMachineExtensionNames`, `gPCUserExtensionNames`,
  `gPCFileSysPath`, `displayName`, `flags`).
- Optionally **SYSVOL file auditing (4663)** for writes under `Policies\{GUID}\`,
  and the Group Policy operational logs.
- Which index/sourcetype, what retention, and is object auditing actually
  enabled (if not, you get version bumps but no actor — still useful, but the UI
  must say so).

Output of discovery: a documented sourcetype/field map and a sample export
(`samples/splunk-changes.json`, gitignored) to develop the ingestor against
**real** event shapes — not a hand-built fixture (the recurring "flat fixtures
make green CI a lie" lesson; see [[project-gpo-lens]]).

## Work items

### WI-1 — Splunk discovery + saved search (no code)
Identify the sourcetype/index/fields per the discovery section; write the saved
search that emits GPO-change events as JSON with a stable field set
(`_time`, actor, gpo identifier [DN or GUID], attribute, old/new if available,
event id). Capture a real sample export. Document the field map in
`docs/splunk-change-feed.md` (new design doc — the contract for the ingestor).

### WI-2 — Change-event model + migration
Add a `gpo_change_event` table (additive migration, per house style): event
time, `gpo_id` (canonical GUID), actor, attribute/action, old/new value
(nullable), source event id, and feed provenance (search name, index, export
time range). Frozen dataclass in the model module.

### WI-3 — Deterministic ingestor with GUID correlation
Parse the export -> normalize -> map each event to a GPO **GUID** (the join
key; gpo-lens already canonicalizes via `canonical_guid`). Events that carry
only a DN resolve to a GUID via the estate's GPO/link DNs. No network. Drop /
flag events that resolve to no known GPO (coverage honesty — do not invent
attribution). Tests against the real sample from WI-1.

### WI-4 — Correlation queries
`gpo_change_history(estate, gpo_id)` (timeline for one GPO) and
`changes_in_window(conn, a, b)` that overlays events onto an existing snapshot
diff, so a settings delta between two captures shows the attributed events in
that window. Pure functions in the core; covered by tests.

### WI-5 — Web: Activity page + GPO-detail history section
An "Activity" page: a filterable timeline (who · when · what), linking to GPO
detail; and a "Change history" section on the GPO detail page. Built on the
family UI (patina tokens). **Provenance is non-negotiable:** show the source
(search/index + time window) and never render *absence of events* as *no
changes* (auditing may simply have been off) — the same "flag, don't overclaim"
discipline as the scope-caveats banner.

### WI-6 — (deferred) optional live Splunk connector
An opt-in `[splunk]` extra: query Splunk REST (`/services/search/jobs/export`)
with a token + time range, cache results, feed the same ingest pipeline.
Isolated from the core (import-boundary test must keep the core free of it).
Config via env (`GPO_LENS_SPLUNK_URL`, `GPO_LENS_SPLUNK_TOKEN`). Behind the
read-only-posture caveat; only pursue if export cadence proves annoying.

## Acceptance

- With a real Splunk export ingested, a GPO's detail page shows an attributed
  change history, and the Activity page shows a filterable timeline.
- A snapshot diff window can be overlaid with the events that occurred in it.
- The core still runs and passes tests with **no** Splunk data and **no**
  network (ingest absent => feature shows an honest empty/"no feed" state).
- The import-boundary (`tests/_arch.py`) keeps the core free of any live
  connector; provenance labelling is asserted by a test.

## Out of scope / non-goals

- Writing back to AD/Splunk (read-only, always).
- Real-time streaming/alerting (this is review/forensics, not monitoring).
- Inferring intent or correctness of a change — gpo-lens reports the recorded
  event, it does not judge it.
