# gpo-lens threat model (the tool's own attack surface)

This document covers threats **to and through gpo-lens itself**: the collector,
the transport of its output, ingest, the SQLite database, the web server, the
browser, and the optional egress paths. It does not catalogue Group Policy
attacks; those are what gpo-lens *detects* (see `docs/spec/wi_danger.md` and
the detectors in `src/gpo_lens/danger.py` and `src/gpo_lens/detection/`).

Citations are `path:line` at the commit that last edited this file; tests are
named so a reviewer can run them. Where a mitigation is not mechanically
enforced, this document says so. Report a gap through [SECURITY.md](../SECURITY.md).

## Assets

| Asset | Where it lives | Why it matters |
|-------|----------------|----------------|
| Collector exports (`AllGPOs.xml`, `gpo-metadata.json`, `principals.json`, `group-members.json`, `SYSVOL-Policies/` copy, the ZIP) | Collector output root on the DC/RSAT host; transfer medium; analysis host | The full GPO estate: names, OU paths, delegation, SIDs, settings and every GPP XML file — including any `cpassword` attribute (an AES key Microsoft published; MS14-025), which is a recoverable credential. |
| SQLite database (`--db`, plus `-wal`/`-shm`) | Analysis host | Persisted snapshots: GPOs, links, settings (`setting.raw` holds the parsed setting subtree), delegation, findings, triage notes and actors. |
| `cpassword` values | Discovered across every input of an import and replaced with `[redacted cpassword]` before anything is written (schema v11); the finding carries no characters of the value and no hash or fingerprint | A live credential if leaked. See residual risk R1 for where unredacted copies can still exist. |
| Narration payloads | In memory; sent to the configured LLM endpoint | Whatever the code path sends leaves the host. The web paths and CLI paths differ deliberately (see "Egress"). |
| Audit log (`audit.log` beside the DB or `GPO_LENS_AUDIT_LOG`) | Analysis host | Who ingested, deleted, triaged or narrated, and when. |
| Auth material | Environment: `GPO_LENS_AUTH_TOKEN`, `GPO_LENS_API_KEY`, `GPO_LENS_HEC_TOKEN`; a service-account password handed to Task Scheduler | Each grants access to the app, the LLM endpoint or Splunk. |
| Analysis integrity | Findings, coverage gaps, caveats | A **false all-clear** (a condition present in the export but not reported) is treated as a security bug ([SECURITY.md](../SECURITY.md)). |

## Trust boundaries and data flow

```text
 [B1] DC / RSAT host (domain account, read-only collection)
      scripts/Export-GpoEstate.ps1  (+ Run-/Register-GpoLensCollection.ps1)
        | writes only under -OutputRoot (and -CopyTo for delivery)
        v
 [B2] Transport: operator copies the ZIP or folder (SMB share, USB, ...)
        |   no signature or hash is produced or verified (residual R4)
        v
 [B3] Ingest on the analysis host
      CLI:  gpo-lens ingest <dir|zip>      Web: POST /ingest (ZIP upload)
        | bounded extraction (collection_zip.py), defusedxml parsing
        v
 [B4] SQLite database at rest (0600 on POSIX)
        |
        v
 [B5] Web server: uvicorn on 127.0.0.1 (default)  <-- optional same-host
      Host allow-list -> CSRF -> auth -> routes        reverse proxy (IIS,
        |                                              Caddy) for remote use
        v
 [B6] Browser: autoescaped HTML, strict CSP, no third-party assets

 Egress (opt-in, off by default):
   [E1] LLM endpoint  (GPO_LENS_API_KEY set): web /explain, web /ask routing,
        CLI ask / doctor --explain / explain-setting
   [E2] Splunk HEC    (GPO_LENS_HEC_URL + GPO_LENS_HEC_TOKEN): CLI events
```

## Adversaries considered

- **A hostile or corrupted export**: a crafted ZIP/XML from a compromised DC,
  a tampered transfer share, or a malformed collector run.
- **A remote web attacker** who can make the operator's browser visit a page
  (CSRF, DNS rebinding), or who can reach a misconfigured listener.
- **Another local user** on the analysis host.
- **A prompt-injecting string** inside the estate or a user question, aimed at
  the narration layer.
- **The collector itself** as a hazard: a bug that writes to AD/GPO/SYSVOL.

Out of scope: an attacker who already runs code as the account that owns the
database or the app process; a compromised LLM or Splunk endpoint beyond what
it receives; physical access.

## Threats and mitigations

### B1 — Collector on the DC/RSAT host

| Threat | Mitigation | Evidence |
|--------|------------|----------|
| Collector writes to AD, GPO or SYSVOL | **Two-layer gate.** A CI check parses (never executes) every DC/RSAT-side script with the PowerShell AST. (1) **Golden syntax tree:** a committed file holds, per script, an order-preserving serialization of the *whole* AST (every node with its operators, names, string values, flags, `#Requires`, attributes and arguments, in source order) plus a digest of the exact source bytes (LF pinned by `.gitattributes`; CR and non-ASCII bytes refused), so any edit — including a reorder, a changed argument, an index assignment, a `#Requires` line or a comment — fails the comparison until regenerated. A meta-test proves the serializer covers every AST node type and property of the running PowerShell and that sampled systematic mutations (single tokens, statement swaps, negated conditions, inserted statements) all change the tree. (2) **Semantic floor:** the generator refuses to regenerate unless the semantic checks pass, so what it can admit is bounded by them: commands (plus a never-allowed list: alias/variable/drive/location/module/job cmdlets), dynamic invocations, `using`, redirections (`$null` only), `New-Object`/`Add-Type` forms, static/instance .NET calls, a closed set of AST node types, no `#Requires`/background jobs/non-ASCII source, the exact set of local functions and a hand-maintained digest of each one's whole syntax tree (so a helper's return value or behaviour cannot change unreviewed), a hand-maintained digest of each script's attributes and param block (`SupportsShouldProcess`, validators), and the exact text *and control-flow context* (enclosing conditions, loops, try blocks and preceding guards) of **every command invocation** and every write/delete/exec/handle-lifetime .NET call. Every read or write of a secret-bearing variable (the service-account credential, the extracted password, and anything assigned from them) must be one of the committed uses; no command argument may carry a UNC/remote path, and no string literal anywhere in a script may look like a UNC, `//host`, device or URL path except the listed ones (the domain's own SYSVOL Policies share); every `TaskName` parameter must carry the shared validator that refuses wildcard/path/quote characters (so `-Unregister` can match only one task). Command, function, parameter, member, type, assembly and variable names are compared case-insensitively, and every parameter token is resolved to its full name the way PowerShell binds it (unambiguous prefixes such as `-Pi` for `-PipelineVariable`, and aliases such as `-ov`), using the cmdlet's real metadata; a token matching no real parameter of a known cmdlet is refused. AD/GroupPolicy cmdlets must be `Get-*`; only `Register-GpoLensCollection.ps1` may use the ScheduledTasks cmdlets, each with a pinned argument vector. `[ADSI]`/`System.DirectoryServices.*`/COM/WMI/CIM/runspace type references are rejected; inline C# for `Add-Type` is pinned by SHA-256. The golden comparison is the completeness guarantee; the semantic floor is what a regeneration cannot get past, and a human still reviews the golden diff. Every reviewer bypass probe (four rounds, two lineages) is a regression case asserted to fail at its intended check and to change the golden tree. | `tests/test_collector_readonly.py`; `tests/powershell/Get-ScriptCallInventory.ps1`; `tests/powershell/collector-inventory.json`; `scripts/gen_collector_inventory.py`; CI job `collector-readonly` |
| Collector writes local files outside its outputs | Dataflow confinement: every write root, every receiver of an instance-method call / property write / index write, every splatted variable, **every variable read by any command argument, .NET call argument or branch/loop condition**, and transitively every variable their bindings read (the gate computes this closure from the AST and requires the pin table to equal it), is pinned, per scope (the function that makes the binding; `ForEach-Object`/`Where-Object` scriptblocks count as their caller's scope), to the **exact set of its bindings** — assignments of any operator, parameter defaults, `foreach` variables, `[ref]` arguments, `++`/`--`, local-function call-site arguments and splats, variable-writing common parameters, and property/index writes on the object. A rebind of any kind is not in the set and fails. Provider/drive and `$global:` assignment targets (`${alias:…}`, `$env:…`, `${C:\file}`), multiple assignment, writes to automatic/preference variables (beyond `$ErrorActionPreference = 'Stop'` and `$matches`), any use of `$PSDefaultParameterValues`/`$PSModuleAutoLoadingPreference`/`$ExecutionContext`, unlisted index writes, computed `-OutVariable`-style names and `ForEach-Object <MethodName>` are refused. Each write target must be exactly one of a committed set of pinned path expressions per script; file redirections must target `$null`; `New-Item` may not create a symlink/junction/hardlink or name a provider. | `tests/test_collector_readonly.py` (`test_local_writes_stay_under_declared_roots`, `test_pinned_variables_are_not_rebound`, `test_no_unpinnable_or_engine_bindings`, `test_write_and_exec_operations_keep_their_guards`, `test_inventory_matches_golden`, `test_reviewer_probes_are_flagged`) |
| Retention or log rotation deletes outside the output root, or follows a link | Owner marker required before any write; reparse points refused before retention deletes; marker opened with link-count check. | `scripts/Run-GpoLensCollection.ps1:67-99,115-126,183-195`; `scripts/GpoLensCollectionMarker.ps1:3-68`; `tests/powershell/collection.Tests.ps1` |
| Service-account password exposure during task registration | Prompted via `Get-Credential`, passed only to `Register-ScheduledTask`, variables cleared in `finally`; gMSA path supplies no password. | `scripts/Register-GpoLensCollection.ps1:148-164`; `tests/powershell/collection.Tests.ps1` ("registers a gMSA Password principal without supplying a password") |
| Non-ASCII byte breaks parsing under Windows PowerShell 5.1 and a run silently collects less | Every `scripts/*.ps1` must parse and be ASCII-only. | `tests/powershell/scripts-parse.Tests.ps1` |

### B2 — Transport

| Threat | Mitigation | Evidence |
|--------|------------|----------|
| Export read in transit or at rest on the drop share (it contains `cpassword` files) | **None in gpo-lens.** Protection is the operator's share ACLs and transfer channel. The README and deployment guide tell operators to keep exports in restricted storage. | `README.md` ("Keep original exports in restricted storage"); `deploy/README.md` "Moving collector exports to the server" |
| Export tampered in transit to hide a condition (false all-clear) | **None.** No signature or hash is produced by the collector or verified at ingest (residual R4). Coverage reconciliation only detects *missing* GPOs against `gpo-inventory.json`, which travels in the same ZIP. | `src/gpo_lens/collection_zip.py` (no integrity check) |

### B3 — Ingest

| Threat | Mitigation | Evidence |
|--------|------------|----------|
| Zip-slip, absolute/UNC/ADS/device paths, duplicate or case-aliased entries | Pre-extract checks on every member; post-extract re-check of the resolved path. | `src/gpo_lens/collection_zip.py:89-117,133-137`; `tests/test_collection_zip.py` (`test_windows_unsafe_paths_rejected_and_partial_files_removed`, `test_separator_aliases_cannot_overwrite_files`, `test_windows_canonicalization_and_device_paths_rejected`) |
| Symlink entries | Rejected from the header mode and again after write. | `src/gpo_lens/collection_zip.py:106-108,133-134` |
| Decompression bomb / resource exhaustion | 500 MiB archive, 2 GiB expanded (counted on actual bytes, not headers), 1000:1 per-entry ratio, 120,000 members, 60,000 directories, 32 MiB of names, depth 24. Shared by CLI and web. | `src/gpo_lens/collection_zip.py:18-26,65-88,109-132`; `tests/test_collection_zip.py` (`test_shared_size_limits`, `test_ratio_limit_is_shared_with_web`, `test_expansion_cap_is_enforced_before_writing_beyond_budget`); `tests/test_review_zip_limits.py` |
| Partial extraction left on disk after a failure | Every failure removes extracted children before re-raising; temporary directories are removed after ingest. | `src/gpo_lens/collection_zip.py:138-159,170-180`; `src/gpo_lens/web/routes/ingest.py:168-170`; `tests/test_collection_zip.py::test_cli_ingests_zip_and_removes_temporary_files` |
| Oversized web upload / slow-drip upload | Streamed to disk with a 500 MiB cap; stops reading at the cap instead of draining. Non-upload POST bodies capped at 10 MiB by `Content-Length`. | `src/gpo_lens/web/_helpers.py:90-102`; `src/gpo_lens/web/app.py:454-472` |
| XML entity expansion / external entities | All untrusted XML is parsed with `defusedxml`. | `src/gpo_lens/ingest.py:17`; `src/gpo_lens/detection/_gpp.py:12`; `src/gpo_lens/admx_parser.py:34` |
| Ambiguous archive (two estates) silently merged | Exactly one `AllGPOs.xml` is required. | `src/gpo_lens/collection_zip.py:162-167`; `tests/test_collection_zip.py::test_cli_rejects_missing_or_ambiguous_estate` |
| Partial estate presented as complete | Coverage gaps from `gpo-inventory.json`, `collection-errors.json` and unreadable SYSVOL subtrees are persisted and surfaced as findings. | `AGENTS.md` "Coverage honesty"; `src/gpo_lens/ingest.py:1904,1965`; `tests/test_coverage.py` |

### B4 — Database at rest

| Threat | Mitigation | Evidence |
|--------|------------|----------|
| Other local users read the estate | DB and `-wal`/`-shm` chmod 0600 on every `init_db` and read-write open. POSIX only: `os.chmod` cannot express this on Windows, where the IIS installer grants the app-pool identity Modify on the install directory and relies on inherited NTFS ACLs. | `src/gpo_lens/store.py:619-645`; `src/gpo_lens/web/_helpers.py:109-118`; `tests/test_store.py` (`test_init_db_restricts_file_permissions_to_owner_only`, `test_init_db_retightens_permissions_on_existing_db`); `scripts/install-windows.ps1:867-875` |
| Raw credential persisted | Since schema v11 ingest redacts every labelled `cpassword` value (attribute or key in any casing or namespace, `<cpassword>` element, inline or escaped, split across XML nodes) and chases canonical copies through descriptive fields and finding text; a copy in an identity field refuses the import (`CredentialInIdentityError`). The result is re-verified over the sanitized estate, the rows written and the database/`-wal`/`-shm`/`-journal` bytes; a residual refuses the import (`CpasswordResidualError`). Upgrading an older database scrubs stored values the same way. Ingest warnings, logs, errors and `audit.log` are scrubbed against every discovered value. The finding stores `****` only; no hash is kept. | `src/gpo_lens/redaction.py`; `src/gpo_lens/ingest.py`; `src/gpo_lens/store.py` (v11 migration); `src/gpo_lens/detection/_hygiene.py` (`mask_cpassword`); `tests/test_cpassword_redaction.py`; `tests/test_cpassword_diagnostics.py`; `tests/test_cpassword_review_probes.py`; `CHANGELOG.md` (Security, Upgrade notes) |
| Ingest lock file abuse | Created 0600. | `src/gpo_lens/web/app.py:190` |

### B5 — Web server

| Threat | Mitigation | Evidence |
|--------|------------|----------|
| Unauthenticated network exposure | `serve` refuses a non-loopback bind unless `GPO_LENS_AUTH_TOKEN` is set. Without a token, only loopback TCP peers are accepted; with one, a constant-time bearer check applies even from loopback. | `src/gpo_lens/cli/_serve.py:28-34`; `src/gpo_lens/web/auth.py:112-140`; `tests/test_forwarded_proto.py` (non-loopback bind returns 1); `tests/test_web_auth.py` |
| Forwarded headers spoof the client address | uvicorn runs with `proxy_headers=False`; `X-Forwarded-Proto` is honored for scheme only and only from a loopback peer; `X-Forwarded-User` is opt-in, loopback-only and names (never elevates) the principal. | `src/gpo_lens/cli/_serve.py:51-58`; `src/gpo_lens/web/app.py:426-441`; `src/gpo_lens/web/auth.py:74-92`; `tests/test_forwarded_proto.py`; `tests/test_web_auth.py` (`test_header_ignored_from_remote_peer`) |
| DNS rebinding | Outermost ASGI middleware validates exactly one well-formed `Host` against `GPO_LENS_ALLOWED_HOSTS` (loopback names only when unset) before auth, CSRF or URL generation. | `src/gpo_lens/web/allowed_hosts.py:32-76`; `src/gpo_lens/web/app.py:571-577`; `tests/test_allowed_hosts.py` (`test_rebinding_rejected_before_auth_csrf_and_redirects`, `test_rebinding_cannot_read_or_delete_populated_snapshot`) |
| CSRF on state-changing requests | POST/PUT/PATCH/DELETE require an `Origin` (or, absent that, `Referer`) that is a loopback origin or matches the request `Host`; neither header means rejection. | `src/gpo_lens/web/app.py:474-495`; `tests/test_csrf.py` |
| Privilege separation between actions | Routes declare a permission (view / ingest / triage / narrate / admin); a test fails if a route declares none. | `src/gpo_lens/web/auth.py:13-37,143-152`; `tests/test_web_auth.py::TestRoutePermissions::test_all_routes_declare_a_permission` |
| Brute force / request flooding | Per-client-IP rate limits: 10/min for `/ask` and `/explain`, 3 per 5 min for ingest, 100/min general. | `src/gpo_lens/web/app.py:497-509`; `src/gpo_lens/web/rate_limit.py`; `tests/test_rate_limit.py` |
| API discovery surface | OpenAPI, Swagger and ReDoc endpoints disabled. | `src/gpo_lens/web/app.py:242` |

### B6 — Browser

| Threat | Mitigation | Evidence |
|--------|------------|----------|
| Stored XSS from estate strings (GPO names, setting values) | Jinja2 autoescaping for `.html` templates (Starlette's `select_autoescape()`); no template uses `|safe`. | `src/gpo_lens/web/app.py:313`; `grep -rn '|safe' src/gpo_lens/web/templates` returns nothing |
| Script injection, framing, MIME sniffing | `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'`, `X-Frame-Options: DENY`, `nosniff`, strict referrer policy. All JS, CSS and fonts are served from `/static`. | `src/gpo_lens/web/app.py:443-452`; `tests/test_ui_regression.py` (`test_security_headers_on_every_page`); `tests/test_web.py` (`test_csp_forbids_inline_scripts`) |
| Secrets rendered in pages or downloads | `safe_output` masks credential values (including flattened copies, escaped variants and URL userinfo) and omits raw XML/SDDL fields in every human export and view payload. | `src/gpo_lens/safe_output.py`; `tests/test_review_output_safety.py`; `tests/test_credential_projection.py`; `tests/test_broken_ref_redaction.py` |
| CSV formula injection | Cells starting with formula characters are prefixed. | `src/gpo_lens/web/_helpers.py:383-387` |

### Egress — E1 LLM narration, E2 Splunk HEC

Narration is off unless `GPO_LENS_API_KEY` is set. What leaves the host depends
on the path:

| Path | What is sent | Evidence |
|------|--------------|----------|
| Web `/explain` (page explanations) | Only an allowlisted projection: integer counts with fixed labels, snapshot/run IDs and a fixed caveat. The payload is HMAC-signed with a per-process random key, expires after one hour and is capped at 12,000 bytes; the model may only return fact IDs, which are fact-checked against the payload. No estate string is sent. | `src/gpo_lens/web/page_narration.py:62-150,154`; `tests/test_page_narration.py` (`test_tampering_never_reaches_narration`, `test_fact_check_rejects_claims_absent_from_payload`, `test_safe_projection_validation_and_bounds`) |
| Web `/ask` | The user's question only (control characters stripped, 500 characters), framed by random delimiters, for routing to a deterministic query. Query results are not sent. | `src/gpo_lens/web/_helpers.py:132-137`; `src/gpo_lens/narration.py:232-237`; `tests/test_page_narration.py::test_ask_does_not_send_serialized_results_to_narration` |
| CLI `ask` | The question **and the deterministic query result**, passed through `safe_data` with the estate's discovered secrets. Estate strings (GPO names, setting values) leave the host. | `src/gpo_lens/cli/_narration.py:72-84` |
| CLI `doctor --explain` | The doctor findings list through `safe_data`. Estate strings leave the host. | `src/gpo_lens/cli/_hygiene.py:264`; `src/gpo_lens/narration.py:268-274` |
| CLI `explain-setting` | The setting identity, truncated to 500 characters. | `src/gpo_lens/cli/_narration.py:141` |
| CLI `events` to Splunk HEC | Change events. Opt-in via `GPO_LENS_HEC_URL` + `GPO_LENS_HEC_TOKEN`; warns on `http://`; `GPO_LENS_HEC_VERIFY_TLS=false` disables certificate verification. | `src/gpo_lens/sinks.py:84-106,123-126` |

The LLM endpoint accepts `http://` as well as `https://`
(`src/gpo_lens/narration.py:143-146`), so the API key and payload can be sent in
cleartext if an operator configures that.

### Deployment (IIS, container, systemd)

| Threat | Mitigation | Evidence |
|--------|------------|----------|
| Every proxied request is "loopback", so the app's own check passes everyone the proxy forwards | Documented and enforced at the proxy: IIS `-WindowsAuth` (anonymous access requires the explicit `-AllowAnonymousNetworkAccess` opt-out), Caddy basic auth plus TLS, firewall scope `LocalSubnet` by default. | `deploy/README.md` "Access boundary"; `deploy/iis/README.md` "Access control — read this"; `tests/test_deployment.py::test_proxy_requires_explicit_tls_and_credentials` |
| Container privilege | Non-root UID 10001, read-only root filesystem, all capabilities dropped, `no-new-privileges`, loopback bind; the default Compose file cannot publish an unauthenticated listener. | `deploy/container/Dockerfile:18,24`; `deploy/container/compose.yaml:8-11`; `tests/test_deployment.py` (`test_image_is_pinned_non_root_and_loopback_only`, `test_default_compose_cannot_publish_an_unauthenticated_listener`); `deploy/container/smoke.py` (CI `container-smoke`) |
| systemd service privilege | Dedicated user, `StateDirectoryMode=0700`, `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, restricted address families. | `deploy/systemd/gpo-lens.service:7,18-30`; `tests/test_deployment.py::test_systemd_limits_writes_and_runs_a_dedicated_user_on_loopback` |
| Estates or secrets baked into an image | The Docker build context is an allowlist. | `deploy/container/Dockerfile.dockerignore`; `tests/test_deployment.py::test_build_context_is_an_allowlist_without_estates_or_secrets` |

## Residual risks

These are known and not mitigated by code at this commit.

- **R1 — Unredacted `cpassword` copies outside the database.** The database
  no longer stores `cpassword` values (redacted at ingest since schema v11; the
  earlier "stored unmasked in `setting.raw`" acceptance is withdrawn). What
  remains: the original exports on the collector host and drop share, and any
  database backup taken before upgrading, still contain the values (see
  `CHANGELOG.md` upgrade notes and R9). Copies are chased only for values of at
  least 12 characters that look like GPP ciphertext or mix letters and digits
  (from 8 characters inside the carrying setting); a short or word-like value
  is redacted only where it is labelled. A crafted export with a copy in an
  identity field can block its own import (it is refused, never stored).
- **R2 — No per-user identity in the app.** Every accepted caller on the
  loopback path is the same principal with view, ingest, delete, triage and
  narrate rights (`src/gpo_lens/web/auth.py:61-67`). Remote access control is
  entirely the reverse proxy's job; a misconfigured proxy exposes everything.
  Rate limits key on client IP, so behind a proxy all users share one bucket.
- **R3 — Loopback is trusted.** Any local process or user that can reach
  `127.0.0.1:<port>` is the analyst. The CSRF check accepts any `localhost`
  origin on any port (`src/gpo_lens/web/app.py:332-347`), so a page served by
  another local web app on the same host can make state-changing requests.
- **R4 — Exports carry no integrity protection.** A tampered ZIP can remove
  GPOs, settings or coverage evidence and produce a false all-clear. Coverage
  reconciliation cannot detect this because the inventory travels in the same
  archive.
- **R5 — Limits of the collector gate.** It is static and reasons only about
  the committed scripts.
  - *Completeness* is structural, not rule-by-rule. The golden syntax tree
    changes on any edit (its source digest is over exact bytes, LF pinned by
    `.gitattributes`, CR refused), and a hand-maintained digest table
    (`STATEMENT_DIGESTS`) pins every statement of every block body — top-level
    and inside each function/scriptblock — by a digest of its normalized AST
    subtree. Because that table is part of the semantic layer the generator must
    pass, and the generator never writes it, **a regeneration of any statement
    edit is refused until a human updates the table** — so "could a new
    allowlisted statement shape regenerate unreviewed?" has a structural answer,
    not a new rule each round. The other semantic checks are then the floor that
    still catches a *harmful* edit even when someone does update the digests:
    they are allowlists and pins, not a proof of read-only behaviour. A
    print-only helper (`scripts/print_statement_digests.py`, never wired into
    the generator) prints candidate digests for review.
  - The floor itself is broad: every command invocation, every .NET method call and every property
    access is pinned by exact text, multiplicity and control-flow context; every
    expression-valued pipeline input is pinned the same way; every cast/
    conversion target must be an inert value type (no side-effecting
    construction such as IO/Net/Diagnostics types); every variable read
    by a command/method argument, a pipeline input or a branch/loop condition is
    binding-pinned (transitively); and secret-bearing variables have an
    allowlist of uses. Interprocedural reasoning is by pinning, not analysis:
    every local function body and each script's param block are pinned by
    digest, and every call to a writer function is a guarded operation with its
    caller's context. A guard implemented other than as an `if` that exits, an
    `Assert-*` call or an exit statement is protected by the golden tree and the
    statement/body digests.
  - Instance methods are bound to a pinned receiver *variable*, not a resolved
    runtime type; the type-reference denylist (`[ADSI]`,
    `System.DirectoryServices.*`, COM, WMI/CIM, runspace) is the backstop.
    Variable names are merged per script (over-approximating dynamic scoping).
  - That the allowlisted `Get-*` AD/GroupPolicy cmdlets do not write rests on
    Microsoft's documentation.
  - `Run-GpoLensCollection.ps1` executes whatever `-CollectorPath` the operator
    registers at runtime, and script parameters (`-OutputRoot`, ...) are
    operator input; only their in-file bindings are pinned.
  - A module resolved at runtime is outside the gate's view, hence `using`,
    `Import-Module` and `#Requires` are rejected rather than inspected, and every
    PowerShell file under `scripts/` (`.ps1`/`.psm1`/`.psd1`/...) must be
    classified.
  - The capability-matrix dispatch check reads `cse` comparisons and `match`
    arms by AST; a dispatcher that selected a CSE by some wholly different
    mechanism would still need its merge-alias set (snapshotted) to change.
  `install-windows.ps1` and `uninstall-windows.ps1` run on the analysis host
  and are out of scope.
- **R6 — CLI narration sends estate strings.** `ask` and `doctor --explain`
  send `safe_data`-redacted estate content (GPO names, settings, finding text)
  to the configured endpoint; redaction targets credentials, not names or
  topology. `http://` endpoints are accepted.
- **R7 — `style-src 'unsafe-inline'`** remains in the CSP, so injected markup
  could still apply inline styles (no script execution).
- **R8 — Windows file permissions.** On IIS the DB relies on directory ACLs;
  `restrict_db_permissions` is effectively a no-op on Windows. The audit log is
  opened with `logging.FileHandler` and is not chmod-tightened on any platform
  (`src/gpo_lens/web/app.py:126-130`).
- **R9 — Exports at rest outside gpo-lens.** The collector output root keeps up
  to `-Retention` (default 14) exports including SYSVOL `cpassword` files, and
  the `-CopyTo` share holds delivered ZIPs. Their ACLs are the operator's.

## Maintenance

Update this file in the same change that adds an ingest path, an egress path,
a route without the standard middleware, or a deployment mode. Line citations
drift; re-verify them when editing a cited file.
