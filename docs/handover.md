# Taking over a gpo-lens installation

Start here if you've inherited a running gpo-lens and the person who set it up
isn't around to ask. gpo-lens has two halves that are easy to forget about
separately:

- **Collection.** A PowerShell script, run on a DC or RSAT box, exports the
  Group Policy estate to files. It is read-only and never writes to AD.
- **Analysis.** The gpo-lens web app (usually on IIS) ingests those exports
  and answers questions about them.

The app only knows what the last export told it. If collection stops, the app
keeps showing an increasingly old estate and doesn't complain about it. Most of
this page is about keeping collection alive.

## 1. Fill in the site sheet first

Keep these facts in your own records, **not in this repository**, which is
public. Fill them in with the previous owner before they leave.

| Fact | Where to find it | Value |
|------|------------------|-------|
| Version running | shown in the header of every page | |
| Server, site URL, and port | IIS Manager; the installer defaults to port 8443 | |
| Checkout the installer ran from | the server's copy of this repo, at a tag | |
| Install/data directory | default `C:\ProgramData\gpo-lens` (database, `audit.log`, `logs\`, venv) | |
| How access is restricted | Windows Authentication (`-WindowsAuth`), an IP allow-list, or network isolation; see [deploy/iis](../deploy/iis/README.md#access-control--read-this) | |
| Collector host | the DC or RSAT box that runs `scripts/Export-GpoEstate.ps1` | |
| Collector account | the least-privilege account the routine export runs as | |
| Collector schedule | the Task Scheduler task on the collector host, and how often it runs | |
| Who runs the privileged inventory, and when it last ran | see section 3 | |
| How exports reach the app | uploaded through **Ingest**, or by whatever process was set up | |
| Where backups go and how often | your backup job | |
| AI narration on or off | whether `GPO_LENS_API_KEY` is set in the site's `web.config` (see section 5) | |

## 2. Rules that are easy to break

1. **Anyone who can reach the site can replace the estate.** gpo-lens has no
   per-user login. Behind IIS every request looks local and gets full rights,
   including ingest and delete. Access control is IIS's job: Windows
   Authentication, an IP allow-list, or an isolated network. Don't remove it.
   `GPO_LENS_AUTH_TOKEN` is not a substitute (it breaks the browser UI).
   Details: [deploy/iis: access control](../deploy/iis/README.md#access-control--read-this).
2. **The coverage-gap check is only as good as the inventory you give it.** A
   GPO whose read permission has been stripped is *invisible* to the
   least-privilege collector, not just unreadable. gpo-lens catches that by
   comparing the export against `gpo-inventory.json`. Only an inventory from
   a privileged run can name what the routine account can't see (section 3).
3. **Back up while running with SQLite's online backup, or stop the pool
   first.** Don't copy `gpo-lens.sqlite3` from under a running app. Both
   procedures are in [deploy/iis: backup and restore](../deploy/iis/README.md#backup-and-restore).
   A database restores into the same or a newer gpo-lens, but not into an
   older one.
4. **On upgrade, re-run the installer with just `-ConfigureIIS`.** It keeps the
   live port, hostname, certificate binding, Windows Authentication, and
   `web.config`. Pass binding flags only to change them deliberately.

## 3. Keeping collection alive

The routine export runs as a least-privilege account (by default a Domain
User with read on SYSVOL Policies is enough; see the script's `.NOTES`). It
produces a folder, zipped by default, containing `AllGPOs.xml`, per-GPO
reports, `gpo-inventory.json`, `collection-errors.json`, the SOM/inheritance,
WMI and site data, and a copy of SYSVOL Policies.

**Coverage.** During ingest, every GPO listed in the export's
`gpo-inventory.json` that is missing from the export shows up as a named
`coverage_gap` finding, on the **Dashboard**, in **Findings**, and in `doctor`. So does every GPO in
`collection-errors.json`. A least-privilege run writes an inventory of only
what *it* could enumerate. To keep that check honest:

- Periodically (and whenever GPO permissions change) run the collector once
  as a privileged account, and ingest that export so a complete inventory is
  in play.
- Treat any coverage gap as a real finding: a GPO someone has hidden from
  routine readers is exactly what this tool exists to surface.

**Signs collection has stopped:** the newest entry under **Snapshots** is
older than your schedule, or the collector task's last-run result in Task
Scheduler isn't `0x0`. Check monthly, or alert on the task.

**One-off export** on the collector host:

```powershell
.\scripts\Export-GpoEstate.ps1 -OutputRoot C:\GpoExport
```

Then upload the zip through **Ingest**. Real exports are often 50–100 MB+;
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

`doctor --explain` and **Ask** can narrate findings with a language model if
`GPO_LENS_API_KEY` (and optionally `GPO_LENS_LLM_PROVIDER`,
`GPO_LENS_LLM_ENDPOINT`, `GPO_LENS_LLM_MODEL`) are set. The deterministic
findings never depend on it, and without a key those features fall back to
the raw output. **If it's enabled, GPO data is sent to that provider.** Make
sure your organisation's policy allows it before turning it on, and know who
approved it if it's already on.

## 6. Upgrading

1. Read the [CHANGELOG](../CHANGELOG.md) entries between your version and the
   target. Releases are annotated git tags (`vX.Y.Z`).
2. Back up the database and `audit.log` (rule 3).
3. In the server's checkout: `git fetch --tags` then `git checkout vX.Y.Z`.
4. From an elevated PowerShell in that checkout:
   `.\scripts\install-windows.ps1 -ConfigureIIS`. It stops the pool, refreshes
   the venv from the checkout, and restarts it.
5. Confirm the header shows the new version, then run one ingest. Schema
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
| Installing, access control, SNI with cert-watch, backups, troubleshooting | [deploy/iis](../deploy/iis/README.md) |
| What the collector exports and what permissions it needs | `scripts/Export-GpoEstate.ps1` (comment-based help: `Get-Help .\scripts\Export-GpoEstate.ps1 -Full`) |
| The JSON output contract | [docs/spec/json-contract.md](spec/json-contract.md) |
| The data model | [docs/tier1-normalized-model.md](tier1-normalized-model.md) |
