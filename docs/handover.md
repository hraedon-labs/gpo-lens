# Taking over a gpo-lens installation

Start here if you've inherited a running gpo-lens and the person who set it up
isn't around to ask. This page describes the **v1.4.0 release candidate**.
The latest published release is **v1.3.1**, fixing v1.3.0's over-redacted
broken-reference details. Keep running 1.3.1 until the coordinator publishes 1.4;
the new capabilities below require 1.4. gpo-lens has two halves:

- **Collection.** A PowerShell script, run on a DC or RSAT box, exports the
  Group Policy estate to files. It is read-only and never writes to AD.
- **Analysis.** The gpo-lens web app (on IIS, a container, or systemd) ingests those exports
  and answers questions about them.

The app only knows what the last export told it. If collection stops, the app
keeps showing an increasingly old estate. In 1.4, Briefing warns when the newest
import is stale; 1.3.1 operators must check snapshot age manually. Import age does
not establish source collection age. Most of this page is about keeping collection alive.

## What's new in 1.4

- Advanced Audit Configuration and Public Key settings appear in search,
  ledgers, exports and baseline/golden comparisons. Audit CSV disagreements
  are flagged; override caveats make no device-level claim. Re-ingest copied
  inputs to obtain the new identities. Legacy IEM is marked deprecated.
- **Explore → External dependencies** inventories configured server/share
  references with redacted downloads. Broken-reference findings now cover only
  what can be verified offline; ADMX findings aggregate per GPO. See the
  dependency and ADMX guidance below for JSON contract version 2 and triage.
- The scheduled collector supports gMSA/service accounts, retention and ZIP
  delivery; delivery still needs a separate ingest. CLI ingest accepts bounded
  collector ZIPs as well as directories. Section 3 covers operations.
- Briefing warns after eight days without a new import by default and retains
  high-severity danger ordering. Exports and comparisons have large-estate
  performance budgets with deterministic output and preserved redaction.

## What's new for an operator in 1.3

- The primary navigation is **Briefing / Findings / Explore / History / Tools**.
  The wordmark opens Briefing; old URLs and filters remain valid, including the
  legacy dashboard at `/`. Ingest and optional Ask are under Tools.
- `GPO_LENS_LEGACY_NAV=1` restores the earlier primary links after a restart;
  Ask stays under Tools. Unset it and restart to return to the new navigation.
- Markdown/CSV downloads carry filters, snapshot/evaluation provenance and
  caveats for audit tickets. Dossiers, findings, occurrence history, accepted
  risks, briefings, settings and comparisons have deterministic exports;
  `gpo-lens export` provides CLI equivalents.
- Fresh IIS sites require `-WindowsAuth` or the explicit
  `-AllowAnonymousNetworkAccess` choice. Upgrades preserve existing access and
  warn prominently if anonymous; do not change authentication mid-upgrade
  without arranging and testing colleague access.
- New IIS firewall rules use `-FirewallRemoteAddress LocalSubnet` on
  Domain/Private profiles; existing rules stay intact. IIS installs consume
  hash-pinned web requirements exported from `uv.lock`, then install the local
  project with `--no-deps` using the shared Python.
- Every proxy needs `GPO_LENS_ALLOWED_HOSTS`. IIS merges a missing value from
  HTTPS bindings plus machine FQDN/short name without changing other variables;
  an existing policy is kept. Container proxy and systemd guides set it too.
  A 400 naming that variable means the browser authority needs configuration.
- [Container](../deploy/container/README.md) and
  [systemd](../deploy/systemd/README.md) are alternatives to IIS. Start at the
  [deployment index](../deploy/README.md) for their common access boundary and
  WAL-safe backup rules. The collector still runs on Windows.

## 1. Fill in the site sheet first

Keep these facts in your own records, **not in this repository**, which is
public. Fill them in with the previous owner before they leave.

| Fact | Where to find it | Value |
|------|------------------|-------|
| Version running | shown in the header of every page | |
| Server, site URL, and port | IIS Manager or proxy/service configuration; IIS defaults to port 8443 | |
| Checkout the installer ran from | the trusted release checkout, installed package, or container image | |
| Install/data directory | IIS: `C:\ProgramData\gpo-lens`; Linux: volume or `/var/lib/gpo-lens` (database and `audit.log`) | |
| How access is restricted | IIS Windows Authentication (`-WindowsAuth`), Linux proxy login, an IP allow-list, or network isolation; see [access boundary](../deploy/README.md#access-boundary) | |
| Collector host | the DC or RSAT box that runs `scripts/Export-GpoEstate.ps1` | |
| Collector account | the least-privilege account the routine export runs as | |
| Collector schedule | the Task Scheduler task on the collector host, and how often it runs | |
| Who runs the privileged inventory, and when it last ran | see section 3 | |
| How exports reach the app | uploaded through **Tools → Ingest**, or by whatever process was set up | |
| Where backups go and how often | your backup job | |
| AI narration on or off | whether `GPO_LENS_API_KEY` is set in `web.config`, the container, or service environment (see section 5) | |

## 2. Rules that are easy to break

1. **Anyone who can reach the site can replace the estate.** gpo-lens has no
   per-user login. Behind a same-host IIS or Linux proxy every request looks
   local and gets full rights, including ingest and delete. Access control is
   the proxy/network's job:
   Windows Authentication on IIS, TLS/basic auth in the Linux examples, an
   IP allow-list, or an isolated network. Don't remove it.
   `GPO_LENS_AUTH_TOKEN` is not a substitute (it breaks the browser UI).
   Details: [shared access boundary](../deploy/README.md#access-boundary) and
   [IIS access control](../deploy/iis/README.md#access-control--read-this).
2. **The coverage-gap check is only as good as the inventory you give it.** A
   GPO whose read permission has been stripped is *invisible* to the
   least-privilege collector, not just unreadable. gpo-lens catches that by
   comparing the export against `gpo-inventory.json`. Only an inventory from
   a privileged run can name what the routine account can't see (section 3).
3. **Use SQLite's online backup while running, or stop the app first.** Don't
   copy `gpo-lens.sqlite3` from under a running app. Both
   procedures are in [IIS backup and restore](../deploy/iis/README.md#backup-and-restore)
   and the [Linux backup rules](../deploy/README.md#backup-restore-and-upgrade-rules).
   A live main-file copy can omit committed WAL changes; an offline backup must
   preserve the complete data directory, including any WAL/SHM sidecars.
   A database restores into the same or a newer gpo-lens, but not into an
   older one.
4. **On IIS upgrade, re-run the installer with just `-ConfigureIIS`.** It keeps the
   live port, hostname, certificate binding, Windows Authentication, and
   `web.config` settings, adding a missing `GPO_LENS_ALLOWED_HOSTS`.
   Anonymous sites warn and continue; existing firewall rules stay intact. Pass binding flags only to change them deliberately.
   Container/systemd upgrades use their own guides and retain proxy configuration.

## 3. Keeping collection alive

The routine export runs as a least-privilege account (by default a Domain
User with read on SYSVOL Policies is enough; see the script's `.NOTES`). It
produces a folder, zipped by default, containing `AllGPOs.xml`, per-GPO
reports, `gpo-inventory.json`, `collection-errors.json`, the SOM/inheritance,
WMI and site data, and a copy of SYSVOL Policies.

**Coverage.** During ingest, every GPO listed in the export's
`gpo-inventory.json` that is missing from the export shows up as a named
`coverage_gap` finding in **Briefing** coverage warnings, **Findings**, the
legacy dashboard and `doctor`. So does every GPO in
`collection-errors.json`. A least-privilege run writes an inventory of only
what *it* could enumerate. To keep that check honest:

- Periodically (and whenever GPO permissions change) run the collector once
  as a privileged account to obtain an authoritative inventory. Include that
  `gpo-inventory.json` with each routine export being ingested. Ingesting a
  privileged snapshot once does not make its inventory apply to later exports.
- Treat any coverage gap as a real finding: a GPO someone has hidden from
  routine readers is exactly what this tool exists to surface.

**Schedule it (1.4).** On the DC/RSAT collector host, from an elevated PowerShell
session, choose one mode:

```powershell
.\scripts\Register-GpoLensCollection.ps1 -GmsaAccount 'LABDOMAIN\collector$' -OutputRoot C:\GpoExport
.\scripts\Register-GpoLensCollection.ps1 -ServiceAccount 'LABDOMAIN\svc-collector' -OutputRoot C:\GpoExport
```

The gMSA must already be installed/usable on that host; it supplies no stored
password. The service-account command prompts with `Get-Credential` and passes
credentials only to Windows Task Scheduler, never a file. Both run with
limited privileges and network-capable logon. Grant batch logon, read access
to GPO/SYSVOL and scripts, and write access to the output/drop directories.
Defaults: daily at 02:00 local time, **hard two-hour time limit**, last 14
successful export pairs, rotating 5 MiB logs with five backups. Customize with
`-At`, `-EveryDays`, `-ExecutionTimeLimit`, `-Retention`, `-LogMaxBytes` and
`-LogFiles`. Preview with `-WhatIf`; remove with `-Unregister`.

Use `-InventoryPath C:\GpoInventory\gpo-inventory.json` to overlay the
periodically refreshed privileged inventory into **both** the routine folder
and ZIP. Use `-CopyTo '\\lab.example.com\gpo-drop'` to deliver the newest ZIP.
Delivery is a copy; an operator must still ingest it through **Tools > Ingest**
or `gpo-lens --db <database> ingest <collector.zip> --diff-latest`. The app does
not watch an inbox. Use a dedicated output root per task; privileged exports
and the authoritative inventory belong outside routine retention.
Registration records `-TaskName` in `.gpo-lens-collection-owner`; missing or
mismatched markers stop the runner before collection or pruning. Re-register
older tasks to create the marker. Another task's root requires explicit
`-Force` takeover with a warning; the previous task then refuses to run.
[The IIS guide](../deploy/iis/README.md#scheduled-collection) has the full
permissions, manual privileged-inventory refresh and lab validation steps.

**Signs collection has stopped:** **Briefing** shows the newest imported
snapshot's age and warns with **Collection may have stopped** when it is older
than eight days, even if no settings changed. Set
`GPO_LENS_STALE_SNAPSHOT_DAYS` to a positive integer before startup and restart
the app to change the threshold. Unknown/future timestamps also warn. This
measures import age; verify the source export age too. An old ZIP re-imported
today can look fresh by import time.

Verify the task and export age on the collector host:

```powershell
Get-ScheduledTaskInfo -TaskName GpoLensCollection | Select-Object LastRunTime, LastTaskResult, NextRunTime
$newest = Get-ChildItem C:\GpoExport -File -Filter '*.zip' | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if ($newest) { ((Get-Date).ToUniversalTime() - $newest.LastWriteTimeUtc).TotalHours } else { 'No ZIP collected yet' }
Get-Content C:\GpoExport\collection.log -Tail 20
```

The task must finish with `LastTaskResult = 0` (`0x0`); confirm a new ZIP and
`Collection succeeded` log line after that run. A `0x0` result can still be a partial
collection: check the log's `Failed` list and the `coverage_gap` findings after
ingest. ZIPs delivered with `-CopyTo` are never pruned. Check **Tools > Ingest >
Snapshots** to verify the import happened too. A hard timeout can leave a
partial export folder or `.partial` copy; investigate before removing it.
Routine failures preserve existing exports and do not prune them. Check monthly,
or wire the task result/newest-export age into your site's monitoring.

**One-off export** on the collector host:

```powershell
.\scripts\Export-GpoEstate.ps1 -OutputRoot C:\GpoExport
```

Then upload the ZIP through **Tools > Ingest**, or in 1.4 use CLI `ingest <file.zip>`.
On 1.3.1, CLI ingest takes the complete export directory.
Both safely handle Windows PowerShell 5.1 backslash ZIP entries; no manual
repacking is needed. Real exports are often 50-100 MB+; the site's
`web.config` allows up to 500 MB.

## 4. Routine

| How often | What |
|-----------|------|
| After each ingest | Open **Findings**. New critical findings and new coverage gaps are the point of the tool. |
| Monthly | Collection is current (section 3); make a backup and **test-restore it** off the production server |
| Monthly | Check for a new tagged release, and read its [CHANGELOG](../CHANGELOG.md) entry |
| When GPO permissions change, and at least yearly | Privileged inventory run (section 3) |
| When someone joins or leaves | Update whatever restricts the site: the AD group behind Windows Authentication, or the IP allow-list |

## 5. AI narration (optional, off unless configured)

**Tools → Ask** and separate **Explain these facts** actions are optional.
Configure `GPO_LENS_API_KEY` (and optionally `GPO_LENS_LLM_PROVIDER`,
`GPO_LENS_LLM_ENDPOINT`, `GPO_LENS_LLM_MODEL`) only after your organisation
approves the provider and data egress. Know who approved it if already enabled.
Web explanations send bounded counts, fixed caveats and analysis provenance;
names, configured values, raw evidence and HTML are excluded. Ask also sends
the user's question for routing. Without a key, explanation actions are absent
and Ask reports missing configuration; deterministic pages remain available.

CLI `doctor --explain`, `ask` and `explain-setting` can send configured names
and values to the provider; their data boundary differs from the new web
explanation actions. CLI Ask requires a key for routing. Narration never
produces deterministic findings or exports.

## 6. Upgrading

**Target v1.4.0 once published. Back up first.** The upgrade suite covers releases since
v0.5.0 with actual databases created by v0.5.0, v0.7.0, v0.7.1, v1.0.0,
v1.1.0, v1.2.0 and v1.3.1 (including the latest released schema). This is the tested upgrade
path from any release since v0.5.0; it is not a separate fixture for every patch
tag. [Upgrade tests](../tests/test_released_db_upgrades.py) preserve snapshots,
entities, events, audit logs and supported finding/risk history; they also test
online backup/restore while committed changes remain in WAL. Test your own
backup on an isolated instance before upgrading production.

### Before you upgrade an existing site

- Record `/api/version`, the actual browser URL, data/site paths, HTTPS
  bindings and TLS certificate. Keep the previous release and configuration.
- Check in IIS Manager whether **Windows Authentication is on and anonymous
  authentication is off**. If anonymous access is intentional, confirm the
  existing IP/network restrictions. An upgrade preserves it; schedule any
  access-control change separately and test the colleague's login.
- Review the existing firewall address/profile scope. New rules default to
  LocalSubnet; retained rules are not tightened automatically.
- Check `GPO_LENS_ALLOWED_HOSTS` against the browser authority and approved
  aliases. If absent, the installer derives it; keep an existing value.
- Make and test a WAL-safe backup: online SQLite `.backup` plus
  `PRAGMA integrity_check` and `audit.log`, or stop the pool and copy the whole
  data directory including sidecars. Restore while stopped, preserve the old
  directory, remove unrelated sidecars, fix ACLs, verify integrity/snapshot
  count/a known GPO. Use the [tested IIS commands](../deploy/iis/README.md#backup-and-restore).
- Confirm the chosen checkout includes `deploy/iis/requirements-web.lock.txt`;
  hash-pinned installs keep the dependency set aligned with the release.

The steps below are for IIS. Alternatives:
[container upgrade/rollback](../deploy/container/README.md#upgrade-and-rollback)
and [systemd upgrade/rollback](../deploy/systemd/README.md#upgrade-and-rollback).

1. Read the [CHANGELOG](../CHANGELOG.md) entries between your version and the
   target **v1.4.0** once published. Releases are annotated git tags (`vX.Y.Z`).
2. Back up the database and `audit.log` (rule 3).
3. In the server's checkout: `git fetch --tags` then `git checkout v1.4.0` once the coordinator publishes the tag.
4. From an elevated PowerShell in that checkout:
   `.\scripts\install-windows.ps1 -ConfigureIIS`. It stops the pool, refreshes
   the venv using the committed hash-pinned requirements and the checkout
   with `--no-deps`, adds the host policy if missing, and restarts it.
5. Confirm the header and `/api/version` show **1.4.0**, then run one ingest. Schema
   changes are additive and applied automatically when the database is opened.

**To roll back**, stop the pool, restore the previous code/venv and the
matching backup from step 2 using the stopped restore procedure, then restart.
Preserve the current data directory and remove stale WAL/SHM for a standalone
backup before restoring; repair ACLs and verify integrity/snapshots/a known GPO. A database a newer version has opened
isn't guaranteed to work with an older one.

## 7. Where updates come from

gpo-lens is MIT-licensed open source; releases are tags on the project's
GitHub repository. If upstream ever stops, the license lets your organisation
fork the repository and keep building it. The test suite (`pytest -q`) comes
with it; see [AGENTS.md](../AGENTS.md) for the module map and conventions.

## 8. Where everything else is

| Question | Document |
|----------|----------|
| What it does, its commands, and its limits | [README](../README.md) |
| Deployment choices and shared backup/access rules | [deploy](../deploy/README.md) |
| Linux container or service | [container](../deploy/container/README.md), [systemd](../deploy/systemd/README.md) |
| Installing, access control, SNI with cert-watch, backups, troubleshooting | [deploy/iis](../deploy/iis/README.md) |
| What the collector exports and what permissions it needs | `scripts/Export-GpoEstate.ps1` (comment-based help: `Get-Help .\scripts\Export-GpoEstate.ps1 -Full`) |
| The JSON output contract | [docs/spec/json-contract.md](spec/json-contract.md) |
| The data model | [docs/tier1-normalized-model.md](tier1-normalized-model.md) |

## Dependency and ADMX guidance for 1.4

Version 1.4 adds **Explore → External
dependencies** and `gpo-lens dependencies --server old-fs01 --json` for file/print
server migration planning. Counts and targets describe configured paths, not
reachability or application. The view has deterministic, authorized, redacted
Markdown/CSV downloads. External paths no longer create doctor findings.

Load central-store and Microsoft toolkit templates together with repeatable
`--admx-dir` on ingest, doctor, ADMX queries, comparisons and serve, or
`GPO_LENS_ADMX_DIR` (platform separator: `:` on Linux, `;` on Windows). Explicit
flags replace the environment list. Each directory resolves its own ADML
resources; the first matching policy wins. Obtain MSS-legacy and SecGuide from
the [Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319);
no Microsoft templates are vendored. Re-ingest after loading templates to
refresh durable findings. ADMX gaps aggregate per GPO with counts and setting
identities, while the raw gap query continues to return individual settings.

JSON contract version 2 changes the meaning of broken-reference counts/rows and
aggregates doctor ADMX findings. Old noise resolves only after a completed
evaluation with meaningful coverage; history and triage remain available by
occurrence ID. Aggregated ADMX findings require fresh review. High-severity
dangers lead the default inbox and appear in briefing problems.
