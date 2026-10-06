# Plan 012 — Local Web UI (and the server eventuality)

**Status:** Partially shipped by v0.3.0, with hosting in v0.6.0; verified 2026-10-06. Evidence: [src/gpo_lens/events.py](../src/gpo_lens/events.py), [tests/test_web_auth.py](../tests/test_web_auth.py).

The web views, uploads, permission seam, snapshot event store, NDJSON and HEC sinks shipped. The proposed unified web `audit.*` event-table stream did not: web audit uses the separate `audit.log`. Trusted-header group-to-role server mode did not ship; the actual loopback/token boundary is documented in `deploy/README.md`. Navigation is now governed by Plan 025.

The design below is the historical specification; this status records the verified release scope.
**Author:** Fable 5 (with cert-watch as the lessons-learned reference)
**Strategic role:** The target audience — Microsoft-environment administrators —
is often CLI-averse. This plan adds a browser surface over the existing query
layer without breaking the charter (deterministic core, read-only, stdlib-only
core, air-gappable), and makes the *architectural* down payment for the
probably-inevitable "put it on a server for the team" request, so that server
mode later is a provider swap plus config, not a rewrite. It also carries
Phase EV — a core-only event store and emission layer (ingest-diff events to
Splunk, audit events for the web UI) that ships before and independently of
the web extra, because the audit-log decision and the Splunk requirement
turned out to be the same mechanism.

## Ground truth at time of writing

- Every query already emits `--json`; the web layer is `queries.py` →
  template with no new computation. The API design problem was solved when
  `--json` became universal.
- The narration layer established the optional-subsystem pattern this plan
  reuses: optional extra in `pyproject.toml`, import boundary enforced by an
  architecture test (core never imports the subsystem).
- cert-watch lessons (measured, not vibes):
  - Its production frontend is **server-rendered Jinja + CSS with zero
    JavaScript files**, serving real users. SPA machinery is not needed for
    this audience.
  - Its auth pain was in **credential providers**, not RBAC: `auth/` is
    ~1,700 lines dominated by LDAP (three documented private-CA LDAPS
    production failures in HANDOFF.md), OAuth, and session management.
    `rbac.py` itself — admin/operator/viewer, IdP-group→role map, role→
    permission table — is small, clean, and worth copying.
  - cert-watch has **no trusted-header auth provider**; that gap is what made
    its auth expensive. This plan designates trusted-header as gpo-lens's
    *only* server-mode auth story (see Charter addendum).
  - Playwright E2E is a real recurring cost (selector drift, opt-in markers,
    CI-only feedback). The MVP tests with `httpx` TestClient instead.
  - IIS-fronting-uvicorn is proven (cert-watch `deploy/iis/`, validated on
    the Windows test VM) — the eventual server runbook adapts, not invents.
- Dependency on Plan 011: Phase R (publication posture) lands first;
  WI-S.1 (effective-scope query) is the natural core of the GPO detail page;
  Workstream S caveats (loopback, security filtering, WMI, ILT) become page
  banners here.

## Charter addendum (decisions this plan records)

1. **Web UI is an optional extra** (`pip install "gpo-lens[web]"`). The core
   stays stdlib-only; the README phrasing becomes "stdlib-only core; optional
   extras for narration and the web UI."
2. **Read-only by construction.** View routes open SQLite with `mode=ro`.
   Ingest/upload is the single write path, behind its own permission.
3. **Server mode authenticates at the proxy, authorizes coarsely in the app,
   and never stores a credential.** Identity arrives as trusted headers from
   a fronting proxy (IIS + Windows Integrated Auth is the designated path);
   the app maps AD groups → roles. No login forms, no password store, no
   LDAP binds, no session store.
4. **Pre-declined** (charter-style, with reasons):
   - *In-app credentials* — the entire category that hurt cert-watch;
     the proxy owns Kerberos/MFA/lockout. (cert-watch's OIDC provider exists
     to borrow if a non-IIS shop ever becomes a real requirement — that is a
     trigger-gated decision, not a plan.)
   - *Per-OU view scoping* ("delegated admins see only their subtree") —
     reimplements AD's delegation model as an application filter; subtly
     wrong forever; off-charter for the same reason RSoP simulation is.
     Coarse viewer/operator/admin serves the realistic team.
   - *Multi-tenancy* — one instance, one estate scope.

---

## Phase EV — Event store & emission (core; ships independently of `[web]`)

Two requirements turned out to be the same mechanism: the web UI's audit log
(WI-W.4) and programmatic export of ingest-diff events to Splunk. Both are
"append an immutable structured event; deliver it somewhere." Build the
mechanism once, in core (stdlib only), before the web work consumes it.

**Honest positioning (goes in the docs):** these are change events at
*snapshot grain*, not real-time GPO auditing — AD's 5136 events own that.
But 5136 logs raw attribute blobs; gpo-lens events say which policy setting
changed from what to what. Complementary, not competing.

### WI-EV.1 — Event store + change events at ingest
- Append-only `events` table in the existing SQLite store: id, timestamp,
  `event_type`, `schema_version`, JSON payload. Canonical record; sinks are
  derivatives, so delivery is replayable.
- Ingest's diff path (the `--diff-latest` / `snapshot_changelog` machinery)
  emits: one event per changed GPO — `gpo.created` / `gpo.deleted` /
  `gpo.modified` carrying per-setting deltas `{cse, identity, display_name,
  old, new}`, link/WMI changes, and version-counter deltas — plus one
  `ingest.summary` event per run (snapshot ids, counts). Per-GPO grain, not
  per-setting: at weekly-ingest volume the deltas array is small, and SPL
  reaches it via `spath`; cap the array defensively (`truncated: true` +
  count) so a pathological diff can't produce a megabyte event.
- `gpo-lens events [--since ts|--type t] [--json]` reads them back. This
  subsumes the audit-read AC from WI-W.4.
- **AC:** two fixture ingests produce per-GPO change events whose deltas
  match `snapshot_changelog` output exactly (same truth path); events table
  is append-only (no UPDATE/DELETE statements against it in the codebase).

### WI-EV.2 — Sinks: NDJSON file (default) and Splunk HEC (optional)
- **NDJSON file sink** — append one JSON object per line to a configured
  path; a Splunk Universal Forwarder (ubiquitous in Windows shops) monitors
  it. Zero network coupling, air-gap friendly, SIEM-agnostic — this is also
  the generic programmatic-export answer. Suggested sourcetype:
  `gpo_lens:change`.
- **HEC sink** — POST batches to the HTTP Event Collector via stdlib
  `urllib` (no new dependency; TLS verification on by default). Config via
  `GPO_LENS_HEC_URL` / `GPO_LENS_HEC_TOKEN`, mirroring the narration env
  convention.
- Emission is best-effort and never blocks or fails ingest: sink failure
  warns and continues; `gpo-lens events export --since <ts> [--sink hec]`
  re-emits from the canonical store after an outage.
- Note in docs: setting values (which may include security-relevant config)
  leave the box via these sinks — enabling a sink is the operator's explicit
  choice, consistent with the narration layer's posture.
- **AC:** file sink output is valid NDJSON consumed back by `events
  --json`; HEC sink tested against a stub server (success, 4xx, timeout —
  ingest succeeds in all three); replay after simulated outage delivers
  exactly the missed events.

---

## Phase W0 — Skeleton & seams (the down payment)

The seams are first-class work items because they are cheap now and a rewrite
later. Local-mode behavior is identical with or without them; they exist so
server mode touches zero routes.

### WI-W.1 — `gpo_lens/web/` package, extra, app factory, guard test
- `[web]` optional extra: `fastapi`, `uvicorn`, `jinja2` (+`python-multipart`
  for W.9). First real dependency block in the project — document the
  air-gap install path (wheel cache / `uv pip download`).
- `create_app(db_path) -> FastAPI` factory (cert-watch `app.py` pattern);
  `gpo-lens serve [--db] [--port] [--open]` CLI command in the existing
  `cli/` package.
- View routes acquire a **read-only** connection (`file:...?mode=ro`).
- Extend the architecture guard test: no core module (`queries`, `ingest`,
  `store`, `detection`, `model`, `normalize`, `admx_parser`, `report`) may
  import `gpo_lens.web`; `gpo_lens.web` may import core + narration.
- **AC:** `pip install -e .` (no extra) imports and tests green with web
  absent; `serve` errors helpfully when the extra is missing; guard test
  covers the new package.

### WI-W.2 — Principal & permission seam
- `Permission` enum sized to this app: `VIEW` (all read pages), `INGEST`
  (upload/ingest), `NARRATE` (ask/explain — it spends API money and sends
  estate facts to an external endpoint, so it is gateable independently),
  `ADMIN` (config). Roles `viewer`/`operator`/`admin` via a role→permission
  table (copy cert-watch `rbac.py` shape).
- Identity is a FastAPI dependency. Local mode resolves a static principal
  (`local-analyst`, all permissions). **Every route declares its required
  permission from day one** via `requires(Permission.X)`.
- **AC:** a test enumerates all routes and asserts each declares a
  permission; swapping the principal dependency for a `viewer`-only stub in
  tests yields 403 on ingest/narrate routes with no route changes.

### WI-W.3 — Bind guardrail & proxy hygiene
- `serve` refuses to bind a non-loopback address unless an auth mode is
  explicitly configured (none exist yet, so today that means: loopback
  only, mechanically). "Accidentally an open server" becomes impossible
  rather than documented-against.
- Relative URLs only; honor `root_path` (the IIS/ARR reverse-proxy lesson
  cert-watch learned in production).
- **AC:** `serve --host 0.0.0.0` exits non-zero with an explanation; the
  test suite renders pages under a non-empty `root_path` and all links
  resolve.

### WI-W.4 — Audit events (consumes Phase EV)
- Web requests emit `audit.*` events (principal, action, target, timestamp)
  through the WI-EV.1 event store — same table, same sinks, so a shared
  deployment's audit trail can flow to Splunk with zero additional
  machinery. In local mode the principal is the static analyst; the value is
  that the *mechanism* exists before the first shared deployment.
- **AC:** ingest-via-upload and an `ask` call each produce an `audit.*`
  event readable via `gpo-lens events --type audit`; events from the web
  layer carry the principal.

---

## Phase W1 — Views (the MVP an admin actually uses)

Server-rendered Jinja + a single hand-rolled CSS file. **No JavaScript
framework; target zero JS files** (cert-watch proves this works in
production for this audience) — plain HTML forms and links. Every view is
`render(template, query_fn(...))`; logic stays in `queries.py`.

### WI-W.5 — Dashboard
- `doctor` findings by severity (badges, linked to detail) + `summary`
  counts. This is the front door; an admin should see estate health in one
  screen with zero typing.
- **AC:** fixture estate renders all doctor categories; severity order
  matches the CLI; each finding links to its GPO/OU page.

### WI-W.6 — GPO detail page
- Composition of what the model holds per GPO: metadata, links
  (enabled/enforced), settings by side/CSE, delegation, WMI filter + WQL,
  version skew. Incorporates Plan 011 WI-S.1 (effective scope) when it
  lands — the page *is* that query, rendered.
- **AC:** fixture GPOs render; disabled-but-populated and version-skew
  states are visibly flagged.

### WI-W.7 — OU browser
- OU tree → `settings-at` / `som-conflicts` for the selected OU, with the
  Workstream S honesty banners (loopback today; security-filtering, WMI,
  ILT as Plan 011 S.2–S.4 land). The banners are the point: this is the
  page where a misleading answer does the most damage.
- **AC:** fixture OU chain renders precedence order; the loopback fixture
  produces the banner in the browser exactly where the CLI prints it.

### WI-W.8 — Changelog & baseline-diff views
- Snapshot picker → changelog between snapshots (metadata-only vs
  settings-detail entries visually distinct); baseline-diff table with
  ADMX-resolved names where available and the unresolved rate shown.
- **AC:** two fixture snapshots render a readable change history; baseline
  rows show policy names where the crosswalk resolves.

### WI-W.9 — Browser ingest (the CLI-aversion killer)
- Drag/upload the collector zip → existing ingest path → redirect to
  dashboard. Behind `Permission.INGEST`. Single-writer: serialize ingest
  behind a lock; reject a second concurrent upload cleanly. Size cap and
  zip-slip-safe extraction (ingest already consumes a directory tree — the
  upload handler must place it safely).
- The full target-user workflow becomes: run the PowerShell collector
  (admins are fine with PowerShell), `gpo-lens serve`, drag the zip, read
  the dashboard.
- **AC:** uploading a fixture-estate zip through TestClient ingests and
  renders; a malformed zip errors without partial DB writes; concurrent
  second upload is rejected with a clear message.

### WI-W.10 — Ask (narration in the browser)
- Text box rendered only when narration is configured; same
  degrade-to-facts contract as the CLI. Behind `Permission.NARRATE`.
- **AC:** without a key the page states narration is unconfigured and the
  rest of the UI is unaffected; with the mocked client, an answer renders
  with its underlying facts shown.

---

## Testing approach

- `httpx` TestClient against the fixture estate: response-content
  assertions (the data is present, banners appear, links resolve), not
  pixels. Template rendering is exercised end-to-end this way.
- **No Playwright in the MVP** — deliberate, from cert-watch's recorded
  cost. Revisit only if the UI grows real interaction (which the zero-JS
  rule resists structurally).
- One manual browser pass per release noted in the PR (the cert-watch
  Playwright-MCP ad-hoc check pattern is available if wanted, but is not a
  gate).

## Server mode — gated follow-on (not in this plan's deliverables)

**Trigger (explicit, maybe-projects style):** a second person needs regular
access, or hosting is requested. Until then, none of this is built.

When triggered, the work is bounded *because the W0 seams exist*:
1. Trusted-header auth provider (~150 lines): read principal + groups from
   proxy-injected headers; reject if the configured header secret/marker is
   absent. Stateless — no sessions.
2. Group→role config map (`GPO_LENS_ROLE_MAP`, JSON, cert-watch convention).
3. Flip the WI-W.3 guardrail: non-loopback bind allowed iff trusted-header
   mode is configured.
4. Deploy runbook adapted from cert-watch `deploy/iis/` (IIS + Windows
   Integrated Auth fronting uvicorn).
- **Estimate held honest by the seams:** zero route changes; the principal
  dependency and permission declarations are already load-bearing.

## Explicitly not in this plan

- In-app credentials, per-OU view scoping, multi-tenancy (Charter addendum
  §4 — declined with reasons, not deferred silently).
- A REST API for third-party consumers — the CLI `--json` *is* the
  programmatic interface; don't maintain two.
- Report theming/dark mode (carried from Plan 011's declines).

## Sequencing & release framing

| Release | Headline | Contents |
|---------|----------|----------|
| v0.3.x | Change events to Splunk | Phase EV (core-only; no web dependency) |
| v0.4.0 | Usable without a CLI | Phase W0 + W.5/W.6/W.9 (dashboard, GPO detail, upload) |
| v0.4.x | Full read surface | W.7/W.8/W.10 as Plan 011 Workstream S lands |
| gated | Server mode | Trigger-bound follow-on above |

Ordering rationale: after Plan 011 Phase R (publication posture settles
before new surface area). Phase EV first — it has no web dependency, is
immediately useful to the current CLI workflow (ingest → events → Splunk
UF), and W0's audit work consumes it. W0 before any view because the seams
are the plan's whole thesis. W.9 (upload) ships in the *first* web release
because it, not the dashboard, is what removes the CLI from the target
user's path. Interleave W.7's banners with Plan 011 S.2–S.4 rather than
rendering known-dishonest views first.

## Decisions recorded (2026-06-10)

1. **CSS approach** — hand-rolled single file. Zero JS, zero vendored
   assets.
2. **`ask` timing** — W.10 stays in v0.4.x; not needed for the first web
   release.
3. **Audit log location** — resolved by Phase EV: audit events live in the
   `events` table in the same SQLite DB (canonical), with delivery via the
   shared sinks. The "separate file" option became the NDJSON *sink*, which
   is a derivative, not the source of truth.
4. **Splunk export** (requested 2026-06-10) — per-changed-GPO diff events +
   ingest summary, NDJSON-file-for-Universal-Forwarder as the default
   transport, HEC push optional via stdlib. See Phase EV.
