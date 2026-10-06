# Taking over a gpo-lens installation

Start here if you've inherited a running gpo-lens and the person who set it up
isn't around to ask. **Run v1.3.0 and upgrade older installations to v1.3.0**
once the coordinator publishes that release. The release candidate is not a
dated/tagged release yet. gpo-lens has two halves that are easy to forget about
separately:

- **Collection.** A PowerShell script, run on a DC or RSAT box, exports the
  Group Policy estate to files. It is read-only and never writes to AD.
- **Analysis.** The gpo-lens web app (on IIS, a container, or systemd) ingests those exports
  and answers questions about them.

The app only knows what the last export told it. If collection stops, the app
keeps showing an increasingly old estate and doesn't complain about it. Most of
this page is about keeping collection alive.

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
   `web.config`. Pass binding flags only to change them deliberately.
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

**Signs collection has stopped:** the newest entry under
**Tools → Ingest → Snapshots** is
older than your schedule, or the collector task's last-run result in Task
Scheduler isn't `0x0`. Check monthly, or alert on the task.

**One-off export** on the collector host:

```powershell
.\scripts\Export-GpoEstate.ps1 -OutputRoot C:\GpoExport
```

Then upload the zip through **Tools → Ingest**. Real exports are often 50–100 MB+;
the site's `web.config` allows up to 500 MB.

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

**Target v1.3.0. Back up first.** The upgrade suite covers releases since
v0.5.0 with actual databases created by v0.5.0, v0.7.0, v0.7.1, v1.0.0,
v1.1.0 and v1.2.0 (the released schema generations). This is the tested upgrade
path from any release since v0.5.0; it is not a separate fixture for every patch
tag. [Upgrade tests](../tests/test_released_db_upgrades.py) preserve snapshots,
entities, events, audit logs and supported finding/risk history; they also test
online backup/restore while committed changes remain in WAL. Test your own
backup on an isolated instance before upgrading production.

The steps below are for IIS. Alternatives:
[container upgrade/rollback](../deploy/container/README.md#upgrade-and-rollback)
and [systemd upgrade/rollback](../deploy/systemd/README.md#upgrade-and-rollback).

1. Read the [CHANGELOG](../CHANGELOG.md) entries between your version and the
   target **v1.3.0**, once released. Releases are annotated git tags (`vX.Y.Z`).
2. Back up the database and `audit.log` (rule 3).
3. In the server's checkout: `git fetch --tags` then `git checkout v1.3.0` (after the coordinator publishes the tag).
4. From an elevated PowerShell in that checkout:
   `.\scripts\install-windows.ps1 -ConfigureIIS`. It stops the pool, refreshes
   the venv from the checkout, and restarts it.
5. Confirm the header and `/api/version` show **1.3.0**, then run one ingest. Schema
   changes are additive and applied automatically when the database is opened.

**To roll back**, check out the previous tag, re-run the installer, and
restore the backup you took in step 2. A database a newer version has opened
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
