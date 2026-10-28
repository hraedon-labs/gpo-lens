# gpo-lens

Local-first, read-only Group Policy analysis. gpo-lens ingests copies of a GPO
estate (it never touches live AD) and answers questions about it. The
deterministic core has no AI in the truth path; the optional LLM layer only
explains facts the core computed.

**Project status:** the current release is **v1.5.0** (2026-10-14, tag `v1.5.0`); see the
[changelog](CHANGELOG.md). The commands below describe 1.4 and later. The
dependency inventory, scheduled collection helper, CLI ZIP ingest and freshness
warning require 1.4. Report security issues privately as described in
[SECURITY.md](SECURITY.md).

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
**Tools → Ingest** also accepts collector ZIPs; CLI ingest also accepts
directories. Both ZIP paths reject path traversal and symlinks and enforce a
500 MiB archive limit, a 2 GiB total expansion limit and a 1000:1 per-entry
compression ratio limit. Backslash paths from Windows PowerShell 5.1
`Compress-Archive` are normalized before validation, and a single enclosing
export folder is supported. Temporary extraction directories are removed after
ingest, including on failure. Keep original exports in restricted storage for
later re-ingestion. Use one estate and one app instance per database; multiple
snapshots describe that same estate.

ZIP members must use consistent directory casing. Conflicting path spellings
and file/directory aliases are rejected before extraction, so a Linux import
cannot silently separate a Windows-equivalent report and its sidecar inputs.

## Keep collection running

On a Windows DC/RSAT host, run either command in an elevated PowerShell session:

```powershell
# Already installed gMSA; Windows manages its password.
.\scripts\Register-GpoLensCollection.ps1 -GmsaAccount 'LABDOMAIN\collector$' -OutputRoot C:\GpoExport
# Standard service account; prompts securely with Get-Credential.
.\scripts\Register-GpoLensCollection.ps1 -ServiceAccount 'LABDOMAIN\svc-collector' -OutputRoot C:\GpoExport
```

Defaults: daily at 02:00 host local time, a hard two-hour runtime limit, the
last 14 successful exports, and a 5 MiB log with five rotated backups. Change
them with `-At`, `-EveryDays`, `-ExecutionTimeLimit`, `-Retention`,
`-LogMaxBytes` and `-LogFiles`. Use `-CopyTo '\\lab.example.com\gpo-drop'` for
ZIP delivery, `-WhatIf` to preview, or `-Unregister` to remove the task.
Delivery is separate from ingest: dropping a ZIP in an inbox does not import
it.

Each task owns its output root through the marker `.gpo-lens-collection-owner`.
Use a separate root for each `-TaskName`, including tasks that collect the same
domain. Registration refuses another task's marker. `-Force` transfers
ownership with a warning, and the previous task then refuses to run.
Re-register existing tasks to create the marker before their next run. Manual
runner calls must pass the registered `-TaskName`.

[The IIS collection guide](deploy/iis/README.md#scheduled-collection) covers
permissions, the privileged inventory overlay, verification and lab validation.
[The handover checklist](docs/handover.md#3-keeping-collection-alive) explains
how to keep coverage honest. Briefing shows the age of the newest imported
snapshot and warns after eight days. To change that threshold, set
`GPO_LENS_STALE_SNAPSHOT_DAYS` to a positive integer and restart the app. An
unchanged estate can still be stale, and import age does not prove when the
source data was collected.

## Feature tour

The primary navigation is **Briefing / Findings / Explore / History / Tools**.
The wordmark opens Briefing. Existing bookmarks, including the original `/`
dashboard, keep their handlers and filters.

| Destination | What you can do |
|-------------|-----------------|
| **Briefing** | Read deterministic change and finding deltas, linked estate vitals, expiring accepted risks, and coverage and provenance warnings. Select a historical snapshot; a first snapshot or an incomplete evaluation is labeled as such. |
| **Findings** | Work the default inbox of new or regressed, open findings. Filter and page results, inspect occurrence observations and evaluation provenance, acknowledge findings, and record or revoke risk acceptance. Resolved and accepted findings stay accessible. |
| **Explore** | Browse GPO dossiers and their uniform settings ledgers, compare two GPOs, inspect exact settings across the estate, search configured settings, browse scopes, and open the resultant, conflict, danger and delegation workbenches. |
| **History** | Compare stored snapshots by version counter and per-setting change. Trends are available through Tools. Snapshot deltas describe what changed between captures; they do not identify the AD actor who made a change. |
| **Tools** | Upload exports, manage snapshots, compare Microsoft baselines or golden backups, inspect ADMX coverage, open the legacy dashboard and route reference, and use optional Ask narration. |

Hygiene checks include cpassword exposure, MS16-072, version skew, broken
references, unlinked/empty GPOs, disabled but populated sides, coverage gaps
and cited dangerous configurations. Baseline ZIP comparison can use an
optional ADMX/ADML crosswalk to turn registry identities into policy names.

**cpassword values are never stored.** A GPP `cpassword` is encrypted with a
key Microsoft published (MS14-025), so it is a recoverable credential. Before
anything is written, ingest discovers every value *labelled* as one, across all
inputs of the import together (every report, including every report in a
baseline ZIP, the SYSVOL files and the JSON inputs). It recognizes the
attribute or key in any casing or namespace, a `<cpassword>` element, and an
inline `cpassword="…"`, including escaped XML and a word or value split across
XML nodes. Each labelled value becomes `[redacted cpassword]`.

Copies of a discovered value under another name (a GPO name or description, a
path, another setting, a SOM or WMI filter field) are replaced too. Values are
compared canonically: whitespace inside the value, the URL-safe base64 alphabet
and `=` padding do not matter. The replacement covers the copy as written,
including a copy split across the text or attribute values of nested XML
elements (`<P>AAEC…<Span>…Dw==</Span></P>`, `<P a="AAEC…" b="…Dw=="/>`). Its
pieces are redacted in place, and a field derived from one piece, such as a
display value taken from an attribute, loses that piece too. Two limits keep the
redaction from rewriting unrelated facts:

- Copies are chased only for values of at least 12 characters that look like
  GPP ciphertext or mix letters and digits, and below 22 characters only as a
  whole token. A short or word-like value (`Enabled`, `Administrators`) is
  redacted where it is labelled but left elsewhere, and a short value glued to
  other letters (`xVALUEy`) is left; no valid GPP cpassword looks like that.
  Inside the setting that carries the value, copies from 8 characters (and
  exact whole-field copies) are replaced.
- Copies are rewritten only in descriptive fields. A copy in an identity field
  (GPO GUID, owner, SID, SOM path, CSE name, event type, …) stops the import,
  or the upgrade, with an error that names the field and never the value. This
  is deliberate: a crafted export can block its own import, but it cannot get a
  credential stored or an identity silently rewritten.

The result is verified independently before it is kept. Discovery and the copy
search run again over the sanitized data, then over the rows as written (read
back from the database), and after commit over the raw bytes of the database,
`-wal`, `-shm` and `-journal`. Any remaining value refuses the import with
nothing stored.

Diagnostics follow the same rule. Warnings raised while loading are held back
until every value of the import is known, then scrubbed, as are log records and
error messages, including those for skipped GPOs and rejected inputs. The guard
spans the whole CLI command or web request, so the values stay known until its
last line of output, log record, HTTP response and `audit.log` entry.
Externally supplied names are never echoed: ZIP errors cite a member's position
(and the OS error, without the path), CLI path arguments are cited by position,
and the audit log records an upload's size, not its file name.

The finding is computed from the SYSVOL files at ingest and records only that a
cpassword is present, with no characters of it. No hash is kept, so replacing
one cpassword with another is not a visible change in diffs or events. The
finding persists on the GPO until the attribute is removed, which is the
remediation.

Text supplied after ingest cannot be redacted against a value the database no
longer holds. So a triage note or rationale, an Ask question, an
`explain-setting` identity and a forwarded user name that carry a cpassword are
**refused, not stored or sent**. This covers a labelled value in any form
ingest recognises, and an unlabelled token shaped like GPP ciphertext (also
when wrapped across lines with prose around it). The refusal names the field
and the reason, never the value; the triage form keeps the draft so the analyst
can remove it. `gpo-lens analyst-text-check` lists the ids of older rows that
would now be refused (read-only). False-positive and miss rates, known false
positives and limits are in
[`SECURITY.md`](SECURITY.md#credentials-in-analyst-typed-text).

The first read-write open by this release (`ingest`, `serve` or a web upload)
scrubs databases written by earlier releases. The scrub:

- discovers values in every column, whatever its declared type or the value's
  storage class (BLOBs are read as Latin-1/UTF-8 and UTF-16), and in SYSVOL
  still on disk at a stored path;
- rewrites them. A value in an identity column refuses the upgrade. A BLOB is
  rewritten in place in an exactly round-tripping reading, including misaligned
  or odd-length UTF-16. A BLOB whose value shows only in a reading that cannot
  be written back exactly is replaced whole, so it can never pin the database
  at schema 10;
- re-hashes the event chain from the first rewritten event;
- verifies the result by rediscovering over every column. The set of events
  that fail verification must be exactly the same before and after: an earlier
  break stays a break even if a rewritten payload would match its stored hash.

If anything remains, the whole scrub is rolled back and the database stays at
schema 10. The labelled sources stay in place, so every later open rediscovers
and refuses again. Otherwise it runs `VACUUM`, truncates the WAL and stamps
schema 11 once the chain verifies and no discovered value is in the file bytes.
(The byte check can only look for values known in that run; once a verified
scrub is committed, a later retry relies on `VACUUM` and a complete
checkpoint.) Allow free disk space about the size of the database for that
one-time `VACUUM`. Read-only commands do not migrate. Original exports and
backups made before the upgrade still contain the values; keep them restricted
or delete them.

For a staged rollout, set `GPO_LENS_LEGACY_NAV=1` before starting the server to
restore the earlier primary links; Ask stays under Tools. Unset the variable
and restart to return to the new navigation. This changes presentation only;
[deployment access control](deploy/README.md#access-boundary) still applies.

The compact header search searches **configured settings**. It is not a general
GPO/GUID/OU/trustee search. Specific views (such as Briefing and dossiers) let
you select a historical snapshot; there is no global snapshot selector.

## Exports for change tickets and auditors

Major views offer deterministic **Markdown and CSV** downloads: dossiers and
settings ledgers, filtered findings, occurrence histories, accepted risks,
briefings, exact settings, and snapshot, GPO and comparison differences.
Upload-based comparisons have an output selector. Downloads keep the selected
filters, snapshot and evaluation provenance, and scope caveats. Secrets and raw
source fragments are redacted, and spreadsheet formula cells are neutralized.
Triage attribution is included only for authorized callers.

CLI equivalents read a stored database. For example:

```bash
uv run gpo-lens --db ./gpo-lens.sqlite3 export findings --format csv --lifecycle all --triage all > findings.csv
uv run gpo-lens --db ./gpo-lens.sqlite3 export briefing --format md --as-of 2026-10-06T00:00:00Z > briefing.md
uv run gpo-lens --db ./gpo-lens.sqlite3 report --output report.html --format html
```

Exports omit volatile generation timestamps. Pass `--as-of` for repeatable
time-sensitive briefing and risk classification. The findings export defaults to
the same actionable view as the inbox; `--lifecycle all --triage all` widens it.
`export --help` lists the supported views and their required selectors. The
older HTML/Markdown estate report remains available separately.

## CLI reference

Global `--db` and `--json` go **before** the subcommand. These are the common
entry points; the help lists the full command set and required arguments:

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
| `analyst-text-check` | Read-only: ids of stored triage notes, rationales and Ask questions that carry cpassword material (never the values) |
| `serve --open` | Start the local web UI |

## Machine-readable output

The global `--json` flag emits a stable, versioned envelope on stdout:

```bash
uv run gpo-lens --db ./gpo-lens.sqlite3 --json doctor | jq '.data.findings[] | select(.severity=="critical")'
```

Every `--json` payload is wrapped as `{schema_version, kind, tool_version,
generated_at, data}`. Errors go to stderr with a nonzero exit. `report` and
`export` produce human formats and reject `--json`. `--json summary` gives a
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
source page if needed.

The CLI also offers `doctor --explain`, `ask <question>` and
`explain-setting <identity>`. CLI narration has a different data boundary: it
can send configured names and values to the selected provider. CLI Ask needs a
key to route a question and cannot silently answer without one. Review your
provider and data-egress policy before enabling narration. Core analysis and
every deterministic export run without a model or API key.

## Deployment and handover

Use the [deployment index](deploy/README.md) to choose:

- [Windows IIS](deploy/iis/README.md): same-host reverse proxy, TLS and IIS access control.
- [Linux container](deploy/container/README.md): non-root image, persistent data volume, loopback Compose default and optional TLS/basic-auth proxy.
- [Linux systemd](deploy/systemd/README.md): dedicated service user, hardened unit, root-owned code and optional same-host proxy.

All paths consume copied exports. For remote browser access, the proxy must
restrict who can reach the app, because accepted users can replace the estate.
Fresh IIS installs require `-WindowsAuth` or the explicit anonymous-access
opt-out; upgrades preserve existing access and warn if it is anonymous. Every
proxy must set `GPO_LENS_ALLOWED_HOSTS` to the browser authority (IIS merges a
missing value; Compose and systemd provide it). Unset, the app accepts only
loopback Host authorities, and a disallowed Host returns 400 naming the
variable. The deployment guides cover firewall scope, locked installs and
WAL-safe backup and restore commands. If you inherited a running installation,
start with the [operator handover](docs/handover.md), including its backup and
upgrade rules.

## Advanced audit and Public Key settings

Advanced Audit Configuration uses subcategory GUID identities and readable
No Auditing / Success / Failure / Success and Failure values. Copied SYSVOL
`audit.csv` entries are reconciled with the report; disagreements and
unsupported shapes are flagged, not silently interpreted. The override caveat
cites Microsoft and describes only what that GPO authors, not effective device
policy.

Public Key settings include EFS, root trust, autoenrollment, certificate path
validation and certificate entries with stable identities. Search, GPO ledgers,
exports, and baseline and golden comparisons use these settings. Legacy
Internet Explorer Maintenance is marked deprecated. Re-ingest copied exports to
get the new normalization; stored historical settings are kept.

## External dependencies and ADMX templates

In **v1.4**, external dependencies and ADMX coverage have separate views.

Before decommissioning or migrating a file or print server, ask “which GPOs
reference `\\old-fs01`?” Open **Explore → External dependencies** and filter by
server, or run `gpo-lens dependencies --server old-fs01 --json`. The inventory
shows servers, shares, counts, GPO links and targets. Wherever the inputs expose
the path, it distinguishes drive maps, printer connections, file copies,
shortcuts, task actions, scripts, installation packages and folder
redirection. Markdown and CSV downloads keep the filter and use deterministic
redaction. This is configured dependency evidence: no server is contacted,
reachability is unknown, and conditional or disabled settings do not imply
actual use. Broken references now mean malformed paths or missing files in the
GPO's own collected SYSVOL, not ordinary external UNC paths. Machine-local
paths are unverifiable.

ADMX gaps now create one finding per GPO, with the gap count and setting list.
Load additional templates with repeatable flags, for example:

```bash
gpo-lens ingest ./lab-export --admx-dir ./central-store --admx-dir ./toolkit-templates
gpo-lens admx-gaps --admx-dir ./central-store --admx-dir ./toolkit-templates
gpo-lens serve --admx-dir ./central-store --admx-dir ./toolkit-templates
```

Or set `GPO_LENS_ADMX_DIR` to a platform path list (`:` on Linux/macOS, `;` on
Windows). Explicit CLI directories replace that environment list; with neither,
the usual central-store auto-detection applies. Keep each directory's ADML
resources beside its ADMX files (typically `en-US`). The first matching policy
in directory order supplies its display name. Missing or corrupt templates are
reported and do not stop other directories from loading.

Get MSS-legacy and SecGuide templates from Microsoft's
[Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
security baseline packages; see the [SCT guide](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10).
Microsoft's templates are not bundled. An unresolved registry setting is a
coverage gap in the loaded template catalogue, not proof of a bad configuration.

After upgrading to 1.4, the next completed ingest resolves superseded UNC and
value-level ADMX findings as no longer observed, keeping their observations and
triage history. New GPO-level ADMX findings need fresh review; old per-value
acknowledgements do not silently approve a broader finding. Partial coverage
prevents resolution claims for uncollected GPOs. Machine consumers should
migrate to JSON contract version 2; see [the contract](docs/spec/json-contract.md).

## Design principles

- **Deterministic core.** No AI in the truth path. Parse, normalize and query;
  every step is verifiable.
- **Read-only.** Never connects to or changes live AD. Input is file copies.
- **Minimal runtime dependencies.** The core CLI depends only on `defusedxml`
  beyond the standard library. The web UI is an optional extra.
- **Air-gappable.** No network is required for core analysis; prepare the
  dependency artifacts before moving an installation into an isolated network.
- **Flag, don't simulate.** OU-level topology flags security filtering, WMI,
  loopback, item-level targeting and sites. The supported snapshot principal
  model evaluates only documented collected inputs and never claims live RSoP.

## Requirements

- Python 3.12+; `uv` for the locked installation commands above.
- The collector requires Windows with the `GroupPolicy` and `ActiveDirectory`
  RSAT modules (a DC or RSAT-equipped host).
- `jq` only for the JSON filtering example.

## Limits

The [capability matrix](docs/capability-matrix.md), generated from the code,
lists for every collector input, CSE and detector whether gpo-lens parses,
flags or resolves it; its last section repeats what is not supported.

- **One estate per store.** Each database holds snapshots of one domain.
  Use separate databases/instances for unrelated estates. Multi-domain,
  multi-forest and cross-estate comparison are not supported.
- **Site links.** Captured and flagged, but subnet and site membership is not
  resolved per machine, and site GPOs are excluded from OU precedence views.
- **Live per-user/object RSoP.** Snapshot principal, token and CSE analysis is
  bounded by collected inputs. WMI truth, ILT and loopback runtime behavior
  remain caveats; gpo-lens does not observe what a Windows client applied.
- **`<Blocked/>` extensions.** Unreadable report extensions stay opaque. For
  the Registry CSE, a collected `Registry.pol` can resolve them into
  key/value/type/data (`source_state="registry_pol"`). Other blocked CSEs
  stay flagged (`source_state="blocked"`).
- **Collection coverage.** A GPO with Authenticated Users Read stripped can be
  invisible to a routine collector. Reconciliation uses the inventory and
  errors supplied with **that export**. Periodically obtain an authoritative
  `gpo-inventory.json` with a privileged run and include it with routine
  exports; missing or error GPOs become `coverage_gap` findings. A prior
  privileged snapshot does not supply the inventory for later exports. No
  sidecar means no evidence of complete collection.

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
[The threat model](docs/threat-model.md) covers the tool's own attack surface
(collector, transport, ingest, database, web server, narration egress and
deployments), the mitigations with code and test citations, and the known
residual risks.

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
