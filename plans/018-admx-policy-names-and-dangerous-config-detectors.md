# Plan 018 — ADMX policy names in the UI + dangerous-configuration detectors

**Status:** Shipped in v0.6.1; verified 2026-10-06. Evidence: [src/gpo_lens/danger.py](../src/gpo_lens/danger.py), [tests/test_danger.py](../tests/test_danger.py).

ADMX naming and the bounded, cited Bucket 1/2 danger set shipped; see also `tests/test_calibration.py` and CHANGELOG v0.6.1/v0.6.4. The examples below are candidate designs, not a promise that every suggested rule ships.

The design below is the historical specification; this status records the verified release scope.
**Author:** GLM 5.2 (from live IIS-deployment feedback)
**Strategic role:** Two related gaps, one plan with a hard prerequisite.
Today the GPO detail "Registry" section shows a column called **Identity** whose
value is a raw registry path (`HKLM\Software\Policies\Microsoft\Windows…\
:NoControlPanel`) — unparsable to a human, and the adjacent **Name** column is
only the value name (`NoControlPanel`). gpo-lens *already* has the resolver for
this — `admx_parser.resolve_display_name(identity)` returns the human policy name
("Prohibit Control Panel") — but it is wired into every CLI surface and **none**
of the web surfaces, because the web app has no ADMX-dir configuration. This plan
(Phase A) wires the existing crosswalk into the web UI so registry settings read
as policy names. Phase B builds on that naming to add **dangerous-configuration
detectors**: a curated, cited set of *known-dangerous* GPO settings and
structural attack-paths surfaced as findings — the natural extension of the
existing cpassword / MS16-072 / excessive-writers detector family, not a
compliance catalogue. Deterministic, no AI in the truth path (AGENTS.md hard
rule).

**Why "dangerous" and not "best practices":** the engine mechanics are the same
(match a setting → compare → emit a typed finding); what collapses is the
content cost and the truth bar. A normative best-practices catalogue ("you
*should* set X") is a maintained content liability in a crowded space (MS SCT,
CIS-CAT, PingCastle), it forces arbitrary relative severities, and it trips the
precedence/RSoP false-positive trap on *every* rule (the same scope-honesty
failure mode as the MS16-072 "Apply Group Policy" bug — see WI-029). A
danger list is bounded, each item is intrinsically severe and citable to an
advisory/ATT&CK technique, and most danger findings can be framed as a fact
about the GPO rather than a claim about effective state. We can always grow a
broader catalogue later; we start with the high-signal, defensible core.

## Ground truth at time of writing

- **Identity is raw, by design.** For the Registry CSE, `ingest.py:195-199`
  sets `identity = f"{key}:{value_name}"` and
  `display_name = value_name or key or _localname(block.tag)` — i.e. the value
  name, not the ADMX policy name. So neither column tells you *which policy*.
- **The resolver already exists and is tested.** `admx_parser.PolicyDefinitions.
  resolve_display_name(identity)` (`admx_parser.py:76`) splits `key:value`,
  case-insensitive `lookup()`, and returns the ADML display name. Tests:
  `tests/test_admx_parser.py:140-155`.
- **The CLI uses it everywhere; the web app uses it nowhere.** `resolve_display_name`
  is called in `queries.py:794,837` (baseline diff), `detection.py:673` (admx
  gaps), and the CLI (`_narration.py:126`, `_diff.py:156`, `_report.py:30`,
  `_settings.py:323`) — all gated on a `--admx-dir` argument. The web app
  (`web/app.py`) has **no** `admx_dir` / `GPO_LENS_ADMX_DIR` config at all.
- **Where the raw Identity is shown in the UI:** `gpo_detail.html:126,131`
  (GPO settings table header `Identity / Name / Value`),
  `ou_detail.html:101` (effective settings), `ou_detail.html:127` (conflicts),
  `changelog.html:79` (setting-change rows), `baseline_diff.html:50-51`
  (already has a separate `display_name` column from the baseline-diff path).
- **Phase B extends an existing detector family, it is not a new surface.**
  `detection.py` already returns typed danger findings — `CpasswordHit`
  (MS14-025), `LocalGroupMod` (Restricted Groups), `ScheduledTaskInfo`,
  `deny_aces`, `excessive_writers` — plus `topology._sddl_read_or_apply_grants`
  and `queries.delegation_deep_dive` over parsed SDDL. `queries.estate_doctor`
  aggregates findings and `_POSTURE_SPEC` (`app.py:84`) enumerates dashboard
  posture indicators. New danger detectors plug into exactly this pipeline.
- **Baseline diff is the precedent, not the mechanism.** Plan 008 compares the
  estate against a Microsoft baseline *zip* (a whole-GPO reference). Danger
  detectors are a different shape: independent, intrinsically-severe checks
  (a known attack primitive or boundary weakening), not a deviation-from-ideal
  score. Phase B reuses the ADMX crosswalk for naming but not the baseline-diff
  comparator.
- **Charter constraint:** "No AI in the deterministic core" (AGENTS.md). Danger
  evaluation is pure comparison; every check is curated and cited. The narration
  layer (optional) may *explain* a finding later, never *produce* it.

## Phase A — Wire the ADMX crosswalk into the web UI

### A.1 Configuration

The web app needs an ADMX PolicyDefinitions source, resolved once at startup
(parsing the whole PolicyDefinitions dir is the expensive step; `lookup` is
cheap). Add a config knob, lowest-friction first:

- `GPO_LENS_ADMX_DIR` environment variable (path to a `PolicyDefinitions` dir).
  Read in `create_app` (`app.py:430`) and `cli/_serve.py`; parse once via
  `parse_admx_dir` and cache on `app.state.admx` (a `PolicyDefinitions` or
  `None`). This mirrors how `GPO_LENS_LLM_ENDPOINT` / `GPO_LENS_API_KEY` are
  already consumed for narration (and is settable in `web.config`
  `<environmentVariables>`, like those).
- Optional `serve --admx-dir` flag for parity with the CLI, falling back to
  the env var.

If unset or the dir is missing/empty, `app.state.admx is None` and the UI falls
back to today's behaviour (raw identity) — Phase A must be a strict superset
(no regression when unconfigured), exactly like the CLI's graceful
`--admx-dir not found → warn + skip` path (`_report.py:58-61`).

### A.2 Resolution at render time

Add a small helper (e.g. `_setting_label(s, admx)` in `app.py`) that returns
`(label, sub)` where:
- `label` = `admx.resolve_display_name(s.identity)` if an ADMX source is
  configured and matches, else `s.display_name` (today's value).
- `sub` = the raw `s.identity` (registry path), always available as the
  audit-grounding detail.

Apply in every view that shows a registry setting row:
`gpo_detail.html`, `ou_detail.html` (effective settings + conflicts),
`changelog.html`, and the baseline-diff view (which already has a display name
column — just route it through the same helper for consistency).

### A.3 Template change

The `<th>Identity</th><th>Name</th>` table becomes `<th>Setting</th><th>Value</th>`
with the raw registry identity demoted to a secondary detail — a
`<details>`/`title=` tooltip or a muted line under the label — so the audit
trail is preserved without dominating the column. Keep the `mono` styling on
the raw path. Non-Registry CSEs (Files, Scheduled Tasks, …) keep their existing
identity-as-label behaviour unchanged (the helper only enhances when an ADMX
match exists).

### A.4 Acceptance criteria

- `AC-1` With `GPO_LENS_ADMX_DIR` set to a PolicyDefinitions dir containing a
  policy for `NoControlPanel`, the GPO detail Registry row shows "Prohibit
  Control Panel" as the setting label.
- `AC-2` Without `GPO_LENS_ADMX_DIR` (or with an empty/missing dir), every
  view is byte-identical to today — Phase A is a strict superset.
- `AC-3` The raw registry identity remains visible (e.g. in a tooltip / expandable)
  on every row that has an ADMX name, so an operator can still cite the exact
  key:value.
- `AC-4` Resolution is cached once per process (no per-request `parse_admx_dir`);
  verified by a test that asserts the dir is parsed at most once.
- `AC-5` A setting with no ADMX match falls back to `display_name` (value name),
  not to blank — no row loses its label.

### A.5 Tests

`tests/test_web.py`: build a tiny PolicyDefinitions fixture (reuse the ADMX
fixture pattern from `tests/test_admx_parser.py`), set `GPO_LENS_ADMX_DIR`, and
assert `AC-1`/`AC-2`/`AC-3`/`AC-5`. Add an architecture assertion that
`app.state.admx` is parsed once.

## Phase B — Dangerous-configuration detectors (gated / incremental)

**Gated on Phase A** (danger findings keyed on a registry policy must show the
human policy name to be legible). Scoped as a small, cited, high-signal set —
not a CIS/STIG catalogue. We can expand later; we start with the defensible core.

### B.0 Inclusion bar (the thing that keeps it honest)

A check qualifies **only if** it is, with a citation:

- a **known attack primitive** (an attacker can directly exploit it), **or**
- a configuration that **materially weakens a security boundary**,

**and** citable to an advisory / CVE / ATT&CK technique / vendor hardening doc.

If a candidate is merely "suboptimal" or "recommended against" with no concrete
threat, it **does not qualify** — that is the best-practices catalogue we
explicitly deferred. This bar is the load-bearing decision: without it,
"dangerous" silently drifts back into "suboptimal" and we are back to an
unbounded, hard-to-maintain ruleset.

### B.1 Two buckets (different mechanics — be explicit which one a check is)

**Bucket 1 — setting-value dangers** (small data table; reuses Registry CSE
parsing). One identity/policy-name + a dangerous value predicate. Examples
(each must carry a cite at implementation time):

- WDigest `UseLogonCredential=1` (plaintext creds in LSASS — Mimikatz primitive).
- SMB signing **disabled** (not "not required" — disabled is unambiguous).
- LM hash storage enabled / NTLMv1 (`LmCompatibilityLevel` too low).
- `AutoAdminLogon=1` with plaintext `DefaultPassword` in the registry.
- LSA Protection (`RunAsPPL`) absent where expected; Credential Guard off.

These are *value* checks: dangerous because of the value, not the structure.

**Bucket 2 — structural / attack-path dangers** (reuses the SDDL + delegation
parsing already in `topology`/`detection` — this is the differentiator most
GPO tools lack). Examples:

- A GPO **writable by a non-admin** trustee while linked at/above a sensitive
  scope (GPO-hijack → privilege escalation / domain compromise). Builds directly
  on `excessive_writers` / `deny_aces` / `delegation_deep_dive`.
- Restricted Groups / GPP pushing **local admin** or a SYSTEM-context scheduled
  task to a broad scope (`LocalGroupMod` / `ScheduledTaskInfo` already parse the
  data — promote the dangerous shapes to findings).
- "Apply Group Policy" granted to **Everyone / Anonymous** (over-broad scope).

These reuse parsed structure; they are richer than a value-compare.

### B.2 Build the minimum that carries the danger set — do not over-build

For ~8–12 checks, **do not build a generic 200-rule engine.** Two mechanisms,
matched to the two buckets:

- **Bucket 2 (structural) → typed detectors in the `cpassword` mould**, in
  `detection.py` / `topology.py`. They need real logic (scope, ACL trustee
  resolution), not a value-compare, and they already share helpers.
- **Bucket 1 (setting-value) → one small data table + one pure evaluator.** A
  shipped data file (`src/gpo_lens/danger_rules/*.toml`) of
  `{id, title, severity, match (identity|policy-name), predicate
  (equals/in/min/max/present/absent), applies (Machine/User), reference}`,
  evaluated by a pure `evaluate_danger_rules(estate, rules, admx) ->
  list[DangerFinding]`. Optional `GPO_LENS_DANGER_RULES_DIR` drop-in for
  site-specific additions, user-overrides-shipped by `id`.

Both emit one typed `DangerFinding` (severity from the existing
critical/high/medium/low/info set + a required `reference`). Honor the import
boundary (core never imports `narration`/`web`; extend the existing
architecture test to any new module).

### B.3 Frame each finding honestly (precedence/RSoP)

Default framing is a **fact about the GPO** ("this GPO grants local admin to
*X*" / "this GPO ships WDigest plaintext-credential caching"), **not** a claim
about per-principal effective state — which gpo-lens does not compute
("Flag, don't simulate", AGENTS.md). cpassword-class dangers are
precedence-independent (the secret is recoverable from SYSVOL regardless of
which GPO wins). For value checks that *could* be overridden, carry the same
scope caveat the OU-detail effective-settings view already uses — an overridden
danger is still worth flagging because the override is fragile.

### B.4 Surfacing

- A new posture indicator row in `_POSTURE_SPEC` (`app.py:84`) —
  "Dangerous configurations" (alert tone) — surfacing the count.
- A dedicated view listing each finding with title, offending GPO(s), the
  dangerous value/ACL, severity, and the **cite link**. Reuse the findings-table
  filter/sort UX (Plan 017 / WI-025 — extract the shared macro first if 017
  lands, to avoid a third copy).
- CLI parity: `gpo-lens danger` (or `dangerous-config`) subcommand emitting
  `--json`, like every other query (Plan 012 invariant: web layer is
  `queries.py` → template).

### B.5 Validation discipline (the MS16-072 lesson, WI-029)

Each check's correctness depends on a Windows semantic; getting one wrong is the
exact class of bug that shipped in MS16-072. Therefore, non-negotiable:

- Every check carries an external citation in its definition (not a comment).
- Every check gets a **calibration test against a real estate** with a
  known-good expected count (the now-live `tests/test_calibration.py` harness),
  cross-checked against an external oracle (GPMC / `Get-GPPermission` /
  the cited advisory), **never** against the tool's own output.

### B.6 Acceptance criteria (Phase B)

- `AC-6` A GPO carrying a Bucket-1 dangerous value produces a `DangerFinding`
  with the check's severity and a non-empty `reference`.
- `AC-7` A GPO writable by a non-admin trustee (Bucket 2) produces a
  `DangerFinding` keyed to the offending trustee, reusing the existing SDDL/
  delegation parse — no new ACL evaluator.
- `AC-8` Evaluation is deterministic and AI-free: same estate + checks → same
  findings, no model calls (architecture test extended to any new module).
- `AC-9` A value check may match by policy name (via the ADMX crosswalk) *or*
  raw registry identity; a missing ADMX source degrades name-keyed checks to
  identity-keyed only (no crash, no silent all-match).
- `AC-10` Findings appear in `estate_doctor` output, the dashboard posture grid,
  and the dedicated view; CLI `--json` parity holds.
- `AC-11` Every shipped check has a citation and a calibration test (B.5).

## Non-goals

- **AI-generated or AI-scored checks.** Every danger check is curated and cited;
  the LLM layer may later narrate a finding (Tier 3), never author one (AGENTS.md).
- **A best-practices / compliance catalogue (CIS/STIG/"you should set X").**
  Explicitly deferred per the B.0 inclusion bar. Danger checks flag *known-bad*,
  not *not-ideal*. A broader catalogue is a separate, larger content effort we
  can take on later if the danger core proves useful.
- **Object-level RSoP.** Checks evaluate *configured* state estate-wide, not
  per-principal effective values (out of charter; AGENTS.md "Flag, don't
  simulate"). Findings are framed as facts about the GPO (B.3).
- **Re-implementing baseline diff.** Plan 008 compares estate vs a whole
  baseline GPO; Phase B flags independent dangerous configs. Different shapes,
  both kept.

## Sequencing & risk

- **Phase A is the near-term win and Phase B's prerequisite.** It is small
  (config knob + a render-time helper + template edits), reuses a tested
  resolver, and is a strict superset — safe to land first.
- **Phase B is incremental and explicitly gated** on Phase A. Land Bucket 2
  first — the structural attack-path checks are the differentiator and reuse the
  SDDL/delegation parse already in the tree, so they need no new data format.
  Then add Bucket 1 as a small cited data table. Each check ships with its
  citation and calibration test (B.5); validate against a real estate before
  expanding. The B.0 inclusion bar gates every addition.
- **ADMX source availability** is the operational dependency for both phases:
  the PolicyDefinitions dir must be present on the host. Document the source
  (RSAT `PolicyDefinitions`, or the MS Security Compliance Toolkit ship) in
  `deploy/iis/README.md` alongside the existing narration env-var notes.
