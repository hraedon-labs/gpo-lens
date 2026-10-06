# gpo-lens

Local-first, read-only Group Policy analysis. Ingests copies of a GPO estate
(never touches live AD) and answers questions about it. The deterministic core
has no AI in the truth path — the optional LLM layer explains computed facts.

## Install and quick start

From a trusted release checkout, install the locked CLI and optional web UI:

```bash
uv sync --locked --extra web
```

On a Windows DC or RSAT box, export the estate:

```powershell
.\scripts\Export-GpoEstate.ps1 -OutputRoot C:\GpoExport
```

Copy the collector ZIP (or the complete export directory) to the analysis
machine. From the checkout, ingest it and start a local browser session:

```bash
uv run gpo-lens --db ./gpo-lens.sqlite3 ingest ./lab.example.com-20261006-020000.zip
uv run gpo-lens --db ./gpo-lens.sqlite3 doctor
uv run gpo-lens --db ./gpo-lens.sqlite3 serve --open
```

The local server listens on `127.0.0.1:8000`. Browser upload through
**Tools → Ingest** also accepts collector ZIPs. CLI ingest still accepts directories.
Both ZIP paths share traversal/symlink rejection, a 500 MiB archive limit,
2 GiB total expansion limit and 1000:1 per-entry compression ratio limit.
Windows PowerShell 5.1 `Compress-Archive` backslash paths are safely normalized
before validation; a single enclosing export folder is supported. Temporary
extraction directories are removed after ingest, including on failure. Keep
original exports in restricted storage for later re-ingestion. Use one estate
and one app instance per database; multiple snapshots describe that same estate.

## Keep collection running

On a Windows DC/RSAT host, run either command in an elevated PowerShell session:

```powershell
# Already installed gMSA; Windows manages its password.
.\scripts\Register-GpoLensCollection.ps1 -GmsaAccount 'LABDOMAIN\collector$' -OutputRoot C:\GpoExport
# Standard service account; prompts securely with Get-Credential.
.\scripts\Register-GpoLensCollection.ps1 -ServiceAccount 'LABDOMAIN\svc-collector' -OutputRoot C:\GpoExport
```

Defaults: daily at 02:00 host local time, a hard two-hour runtime limit, last
14 successful exports, and a 5 MiB log with five rotated backups. Configure
`-At`, `-EveryDays`, `-ExecutionTimeLimit`, `-Retention`, `-LogMaxBytes` and
`-LogFiles`. Use `-CopyTo '\\lab.example.com\gpo-drop'` for ZIP delivery,
`-WhatIf` to preview, or `-Unregister` to remove the task. Delivery requires a
separate ingest step; dropping a ZIP in an inbox does not import it.

[The IIS collection guide](deploy/iis/README.md#scheduled-collection) covers
permissions, privileged inventory overlay, verification and lab validation.
[The handover checklist](docs/handover.md#3-keeping-collection-alive) explains
how to keep coverage honest. Briefing shows the newest imported snapshot's age
and warns after eight days. Set `GPO_LENS_STALE_SNAPSHOT_DAYS` to a positive
integer and restart the app to change that threshold. An unchanged estate can
still be stale; import age does not prove when the source data was collected.

## Feature tour

The primary navigation is **Briefing / Findings / Explore / History / Tools**.
The wordmark opens Briefing; existing bookmarks, including the original `/`
dashboard, retain their handlers and filters.

| Destination | What you can do |
|-------------|-----------------|
| **Briefing** | Read deterministic change and finding deltas, linked estate vitals, expiring accepted risks, and coverage/provenance warnings. Select a historical snapshot; a first snapshot or incomplete evaluation is labeled honestly. |
| **Findings** | Work the default new-or-regressed, open inbox; filter and page results, inspect occurrence observations and evaluation provenance, acknowledge findings, and record or revoke risk acceptance. Resolved and accepted findings remain accessible. |
| **Explore** | Browse GPO dossiers and their uniform settings ledgers, compare two GPOs, inspect exact settings across the estate, search configured settings, browse scopes, and open resultant, conflict, danger and delegation workbenches. |
| **History** | Compare stored snapshots with version-counter and per-setting changes. Trends remain available through Tools. Snapshot deltas describe what changed between captures; they do not identify the AD actor who made a change. |
| **Tools** | Upload exports, manage snapshots, compare Microsoft baselines or golden backups, inspect ADMX coverage, open the legacy dashboard and route reference, and use optional Ask narration. |

Hygiene checks include cpassword exposure, MS16-072, version skew, broken
references, unlinked/empty GPOs, disabled but populated sides, coverage gaps
and cited dangerous configurations. Baseline ZIP comparison uses an optional
ADMX/ADML crosswalk to turn registry identities into policy names.

For a staged rollout, set `GPO_LENS_LEGACY_NAV=1` before starting the server to
restore the earlier primary links. Ask stays under Tools. Unset the variable
and restart to return to the new navigation. This changes presentation;
[deployment access control](deploy/README.md#access-boundary) still applies.

The compact header search searches **configured settings**. It is not a general
GPO/GUID/OU/trustee search. Historical selection is supported by specific views
(such as Briefing and dossiers), rather than a global snapshot selector.

## Exports for change tickets and auditors

Major views offer deterministic **Markdown and CSV** downloads: dossiers and
settings ledgers, filtered findings, occurrence histories, accepted risks,
briefings, exact settings, and snapshot/GPO/comparison differences. Upload-based
comparisons have an output selector. Downloads retain the selected filters,
snapshot/evaluation provenance and scope caveats; secrets and raw source
fragments are redacted, and spreadsheet formula cells are neutralized. Triage
attribution is included only for authorized callers.

CLI equivalents read a stored database. For example:

```bash
uv run gpo-lens --db ./gpo-lens.sqlite3 export findings --format csv --lifecycle all --triage all > findings.csv
uv run gpo-lens --db ./gpo-lens.sqlite3 export briefing --format md --as-of 2026-10-06T00:00:00Z > briefing.md
uv run gpo-lens --db ./gpo-lens.sqlite3 report --output report.html --format html
```

Exports omit volatile generation timestamps. Supply `--as-of` for repeatable
time-sensitive briefing/risk classification. The findings export defaults to
the same actionable view as the inbox; `--lifecycle all --triage all` widens it.
Use `export --help` for supported views and their required selectors. The older
HTML/Markdown estate report remains available separately.

## CLI reference

Global `--db` and `--json` go **before** the subcommand. These are common entry
points; the help lists the full command set and required arguments:

```bash
uv run gpo-lens --help
uv run gpo-lens ingest --help
uv run gpo-lens export --help
```

| Command and required arguments | What it does |
|--------------------------------|-------------|
| `ingest <directory> --diff-latest` | Save a snapshot and emit differences/events against the previous one |
| `doctor` / `summary` | Prioritized configured-state findings / estate overview |
| `snapshots` | List stored snapshot IDs |
| `diff <a> <b>` / `diff-settings <a> <b>` / `changelog <a> <b>` | Compare snapshots |
| `settings-at <som>` / `scope <gpo>` | OU-level winning settings / GPO scoping gates and caveats |
| `baseline-diff <backup>` / `golden-diff <backup>` | Compare baseline or known-good GPO backups |
| `settings-dump` / `who-sets <query>` | Inventory settings / search configured settings |
| `delegation` / `danger` | Trustee rights / cited dangerous-configuration findings |
| `sites` / `loopback` / `wmi` / `wmi-filters` | Site links and scoping mechanisms |
| `broken-refs` / `admx-gaps` / `topology-check` | References, unresolved names and topology consistency |
| `gpp-tasks` / `gpp-groups` | Scheduled-task configuration / local-group membership changes |
| `resultant <principal_sid>` | Supported snapshot principal merge model, with explicit unevaluated gates |
| `events` / `events-export` | Read snapshot change events / send NDJSON or optional Splunk HEC output |
| `serve --open` | Start the local web UI |

## Machine-readable output

Add the global `--json` flag to emit a stable, versioned envelope on stdout:

```bash
uv run gpo-lens --db ./gpo-lens.sqlite3 --json doctor | jq '.data.findings[] | select(.severity=="critical")'
```

Every `--json` payload is wrapped as `{schema_version, kind, tool_version,
generated_at, data}`. Errors go to stderr with a nonzero exit; `report` and
`export` support human formats and reject `--json`. Use `--json summary` for a
machine-readable overview. The frozen shapes are documented in
[the JSON contract](docs/spec/json-contract.md) and pinned by
[contract tests](tests/test_json_contract.py).

## Optional narration under Tools

With `GPO_LENS_API_KEY` configured, **Tools → Ask** routes a question to a
deterministic query. Dossiers, OU details, finding histories and comparisons
also offer **Explain these facts** in a separate tab. Web explanations receive
only bounded counts, fixed caveats and snapshot/analysis provenance; names,
values, raw evidence and HTML are excluded. The model selects supplied fact
IDs, and the server rejects additional claims. Without a key, explain actions
are absent and Ask reports that configuration is needed. Pages never wait for
narration. Signed forms expire after an hour or a server restart; reload the
source page if necessary.

The CLI also offers `doctor --explain`, `ask <question>` and
`explain-setting <identity>`. CLI narration has a different data boundary:
it can send configured names and values to the selected provider. CLI Ask
requires a key to route a question; it cannot silently answer without one.
Review provider/data-egress policy before enabling narration. Core analysis
and every deterministic export run without a model or API key.

## Deployment and handover

Use the [deployment index](deploy/README.md) to choose:

- [Windows IIS](deploy/iis/README.md): same-host reverse proxy, TLS and IIS access control.
- [Linux container](deploy/container/README.md): non-root image, persistent data volume, loopback Compose default and optional TLS/basic-auth proxy.
- [Linux systemd](deploy/systemd/README.md): dedicated service user, hardened unit, root-owned code and optional same-host proxy.

All paths consume copied exports. For remote browser access, the proxy must
restrict who can reach the app; accepted users can replace the estate.
Fresh IIS installs require `-WindowsAuth` or the explicit anonymous-access
opt-out; upgrades preserve existing access and warn if anonymous. Every proxy
must set `GPO_LENS_ALLOWED_HOSTS` to the browser authority (IIS merges a missing
value, Compose/systemd provide it). Unset accepts only loopback Host authorities;
a disallowed Host returns 400 naming the variable. See the deployment guides
for firewall scope, locked installs and WAL-safe backup/restore commands.
Inherited a running installation? Start with the [v1.3.1 operator
handover](docs/handover.md), including backup and upgrade rules.

## External dependencies and ADMX templates

Run **v1.3.1** as the current released version; it fixes v1.3.0's over-redacted
broken-reference details. The following dependency inventory is Unreleased.

Before decommissioning or migrating a file or print server, ask “which GPOs
reference `\\old-fs01`?” Open **Explore → External dependencies**, filter by
server, or use `gpo-lens dependencies --server old-fs01 --json`. The inventory
shows servers, shares, counts, GPO links and targets, distinguishing drive maps,
printer connections, file copies, shortcuts, task actions, scripts, installation
packages and folder redirection wherever those paths are exposed in the inputs.
Markdown and CSV downloads preserve the filter and use deterministic redaction.
This is configured dependency evidence: no server is contacted, reachability is
unknown, and conditional/disabled settings do not imply actual use. Broken
references now mean malformed paths or missing files in the GPO's own collected
SYSVOL, not ordinary external UNC paths. Machine-local paths are unverifiable.

ADMX gaps now create one finding per GPO with the gap count and setting list.
Load additional templates with repeatable flags, for example:

```bash
gpo-lens ingest ./lab-export --admx-dir ./central-store --admx-dir ./toolkit-templates
gpo-lens admx-gaps --admx-dir ./central-store --admx-dir ./toolkit-templates
gpo-lens serve --admx-dir ./central-store --admx-dir ./toolkit-templates
```

Alternatively set `GPO_LENS_ADMX_DIR` to a platform path list (`:` on Linux/macOS,
`;` on Windows). Explicit CLI directories replace that environment list; absent
both, the usual central-store auto-detection applies. Keep each directory's
ADML resources beside its ADMX files (typically `en-US`). The first matching
policy in directory order supplies its display name. Missing/corrupt templates
are reported; they do not prevent other directories from loading.

Get MSS-legacy and SecGuide templates from Microsoft's
[Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
security baseline packages; see the [SCT guide](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10).
Microsoft's templates are not bundled. An unresolved registry setting is a
coverage gap in the loaded template catalogue, not proof of a bad configuration.

On the next completed ingest, superseded UNC and value-level ADMX findings
resolve as no longer observed, retaining observations and triage history. New
GPO-level ADMX findings require fresh review; old per-value acknowledgements do
not silently approve a broader finding. Partial coverage prevents resolution
claims for uncollected GPOs. Machine consumers should migrate to JSON contract
version 2; see [the contract](docs/spec/json-contract.md).

## Design principles

- **Deterministic core.** No AI in the truth path. Parse, normalize, query —
  all verifiable.
- **Read-only.** Never connects to or changes live AD. Input is file copies.
- **Minimal runtime dependencies.** The core CLI depends only on `defusedxml`
  beyond the standard library. The web UI is an optional extra.
- **Air-gappable.** No network is required for core analysis; prepare the
  dependency artifacts before moving an installation into an isolated network.
- **Flag, don't simulate.** OU-level topology flags security filtering, WMI,
  loopback, item-level targeting and sites. The supported snapshot principal
  model evaluates only documented collected inputs; it never claims live RSoP.

## Requirements

- Python 3.12+; `uv` for the locked installation commands above.
- The collector requires Windows with the `GroupPolicy` and `ActiveDirectory`
  RSAT modules (a DC or RSAT-equipped host).
- `jq` only for the JSON filtering example.

## Limits

- **One estate per store.** Each database holds snapshots of one domain.
  Use separate databases/instances for unrelated estates. Multi-domain,
  multi-forest and cross-estate comparison are not supported.
- **Site links.** Captured and flagged, but subnet/site membership is not
  resolved per machine and site GPOs are excluded from OU precedence views.
- **Live per-user/object RSoP.** Snapshot principal/token/CSE analysis is
  bounded by collected inputs. WMI truth, ILT and loopback runtime behavior
  remain caveats; it does not observe what a Windows client applied.
- **`<Blocked/>` extensions.** Unreadable report extensions remain opaque.
  For the Registry CSE, a collected `Registry.pol` can resolve them into
  key/value/type/data (`source_state="registry_pol"`). Other blocked CSEs
  remain flagged (`source_state="blocked"`).
- **Collection coverage.** A GPO with Authenticated Users Read stripped can
  be invisible to a routine collector. Reconciliation uses the inventory
  and errors supplied with **that export**. Periodically obtain an
  authoritative `gpo-inventory.json` with a privileged run and include it
  with routine exports; missing/error GPOs become `coverage_gap` findings.
  A prior privileged snapshot does not automatically supply the inventory
  for later exports. No sidecar means no evidence of complete collection.

## Development

```bash
uv sync --locked --extra dev --extra web
.venv/bin/pytest -q --cov=src --cov-report=term-missing --cov-fail-under=85
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src
```

See [AGENTS.md](AGENTS.md) for conventions, module map and build details, and
[docs](docs/) for the normalized model and behavior specifications.
