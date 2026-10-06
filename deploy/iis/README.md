# Hosting gpo-lens on IIS

gpo-lens runs as a normal ASGI app (uvicorn). On Windows the supported pattern
is **IIS + HttpPlatformHandler**: IIS terminates TLS and reverse-proxies to a
uvicorn process it launches and supervises. This mirrors the cert-watch
deployment so the two tools install and run the same way — gpo-lens just takes
its own port (default **8443**) since cert-watch typically owns 443.

## Prerequisites

- Windows Server with IIS.
- [HttpPlatformHandler](https://www.iis.net/downloads/microsoft/httpplatformhandler)
  (Microsoft-signed module — the only third-party prerequisite).
- Python 3.12+ available to the installer (the Python Install Manager runtime is
  fine; see *Why a shared Python install* below).
- A TLS certificate in `LocalMachine\My` (you can reuse the machine certificate).

## Quick start

From an **elevated** PowerShell, in a checkout of this repo:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 `
    -ConfigureIIS -WindowsAuth `
    -Port 8443 `
    -HostName lens.lab.example.com `
    -TlsCertThumbprint "<thumbprint from LocalMachine\My>"
```

That single command:

1. Resolves a usable Python and (if it is user-scoped) copies it to a shared
   location the app pool can read.
2. Creates `C:\ProgramData\gpo-lens` (data dir + logs) and a venv, and
   `pip install --require-hashes` installs the committed `requirements-web.lock.txt`
   exported from `uv.lock`, plus `requirements-build.lock.txt` for Hatchling
   and its build dependencies. It then installs the checkout with
   `--no-build-isolation --no-deps`, so pip cannot resolve another build backend.
   Regenerate the build artifact with
   `uv export --locked --only-group build --no-emit-project --no-header --format requirements-txt -o deploy/iis/requirements-build.lock.txt`.
   For offline installation, download the wheels for both requirement files
   in advance and configure `PIP_NO_INDEX=1` and `PIP_FIND_LINKS` to that folder.
   uv is not needed on the IIS server; the shared-Python design is unchanged.
3. Lays down `web.config` in `C:\inetpub\gpo-lens` (paths rewritten to your
   `-InstallDir`).
4. Creates the `gpo-lens` app pool (No Managed Code, AlwaysRunning) and IIS site
   bound to `https://*:<Port>`, grants the pool identity the ACLs it needs,
   binds the TLS cert for that port, enables Windows Authentication and disables
   anonymous access, opens the firewall to `LocalSubnet` on Domain/Private
   profiles, and starts the pool.

Re-running is safe and idempotent: the estate database and an existing
`web.config` settings are preserved (a missing host allow-list is added); use it for upgrades too (it stops the pool, refreshes
the venv, restarts).

## Upgrading an existing installation

To refresh the app code on a site that's already configured, re-run the
installer with **just `-ConfigureIIS`** and omit the binding flags:

```powershell
.\scripts\install-windows.ps1 -ConfigureIIS
```

The installer detects the existing IIS site and **preserves** the live binding
configuration — port, hostname, SNI flag, and bound TLS certificate — for any
flag you do not pass. So an upgrade-in-place leaves the HTTPS endpoint untouched
and you do **not** have to re-specify `-Sni`/`-Port`/`-HostName`/
`-TlsCertThumbprint`. (The script reads the live IIS/http.sys state via
`Get-WebBinding` and `netsh http show sslcert`; an explicit flag still wins if
you pass one — e.g. `-Port 443` changes the port, `-TlsCertThumbprint` rotates
the certificate.)

An existing anonymous site **continues working** during an upgrade. The
installer prints a prominent warning and the exact command to enable Windows
Authentication later. It does not fail or change authentication unless you
explicitly pass `-WindowsAuth`; arrange and test that change separately so a
production upgrade cannot lock out the colleague. Existing firewall rules are
also preserved; review their scope separately.

Windows Authentication is sticky: once enabled it is not disabled by an upgrade
run without `-WindowsAuth` (a security-positive default). The `web.config` is
also preserved (all operator-set environment variables are kept). A missing
`GPO_LENS_ALLOWED_HOSTS` is merged on both configured and plain upgrades; an
existing value is left alone, including an empty value. If `-SitePath` is
omitted, the existing site's physical path is used.

A fresh estate starts **empty**. Open the site and use **Ingest** to upload a
collector export, or drop an existing `gpo-lens.sqlite3` into the data dir.

## Scheduled collection

Run the optional task registration on the domain-joined DC/RSAT collector host,
from an elevated Windows PowerShell 5.1 session. Keep the trusted checkout
(including `Export-GpoEstate.ps1`, `Run-GpoLensCollection.ps1` and
`Register-GpoLensCollection.ps1`) at a stable path. The task calls the runner
using that absolute path; do not move it without re-registering. Scripts must
be permitted by the host execution policy (sign them if your policy requires
it). Registration does not alter execution policy or create AD accounts.

The account needs **Log on as a batch job**, RSAT GroupPolicy/ActiveDirectory
modules, domain GPO/SYSVOL read, write access to a dedicated output root, and
share/NTFS write access to an optional drop folder. It needs read access to the
scripts and authoritative inventory. Grant script/inventory write access only
to administrators/maintainers. Use UNC paths for network delivery; mapped
letters are not available in noninteractive tasks. Use a separate root for
each task/account; never point retention at a shared archive root. Linked output
roots and reparse points anywhere within a folder to be pruned are rejected.
Protect the output tree from other writers; pre-deletion checks require that ACL boundary.

For a gMSA, provision it through your normal AD administration process, install
it on the collector host and verify `Test-ADServiceAccount collector` returns
`True`. Register with no credential prompt:

```powershell
.\scripts\Register-GpoLensCollection.ps1 -GmsaAccount 'LABDOMAIN\collector$' -OutputRoot C:\GpoExport -CopyTo '\\lab.example.com\gpo-drop'
```

For a standard least-privilege account, the single command prompts securely:

```powershell
.\scripts\Register-GpoLensCollection.ps1 -ServiceAccount 'LABDOMAIN\svc-collector' -OutputRoot C:\GpoExport -CopyTo '\\lab.example.com\gpo-drop'
```

`-Credential (Get-Credential 'LABDOMAIN\svc-collector')` also works. Passwords
are passed only in memory to `Register-ScheduledTask -User/-Password`; Windows
Task Scheduler stores its protected credential, and our scripts/files/action
arguments/logs never contain it. Re-register after a normal-account password
rotation. Both principals use `Password` logon to permit network reads/copies;
`ServiceAccount` logon is intended for built-in accounts, not a domain gMSA.
See [Microsoft's principal documentation](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal).

The default task `GpoLensCollection` runs daily at 02:00 host local time. It
starts a missed run when available and ignores overlapping launches. A runner
lock also prevents concurrent manual runs using the same output root. The hard
`ExecutionTimeLimit` is **02:00:00**, explicitly set in the task definition;
use `-ExecutionTimeLimit '04:00:00'` for longer estates. Zero/unlimited is
rejected. Change the schedule with `-At '03:30' -EveryDays 7`, retention with
`-Retention 30`, or use `-TaskName` for another task. Re-registration replaces
the named task; review it with `-WhatIf` first.

Registration writes the TaskName to `.gpo-lens-collection-owner` in the output
root, and passes it to the runner. Every task needs its own root, even when two
tasks collect the same domain. A different owner blocks registration unless
`-Force` explicitly transfers ownership with a warning. Stop the previous task
first: it will refuse subsequent runs, and its existing exports become subject
to the new owner's retention. Ownership changes share the runner's lock.
`-WhatIf` writes no marker. Re-register tasks installed before 1.4 to initialize
their marker. A missing, linked or mismatched marker prevents collection and
pruning. Manual runner calls must supply the registered `-TaskName`.
Credentials are checked before ownership changes. Registration holds the
collection lock through the Scheduler call and restores the prior marker if
that call fails, keeping the previous task runnable.

The runner keeps the last N successful timestamp-named export folder/ZIP pairs
(default 14), without pruning unrelated files. It prunes only after successful
collection by the root's owner, retaining the exact domain-prefix check as well.
Inventory overlay and delivery must also succeed. Unreadable or incomplete ZIPs are
excluded from retention counts. Failed/unfinished export folders and partial
archives remain for diagnosis and require manual cleanup; a hard timeout may leave such
folders and a log ending with `Collection started`. `collection.log` rotates
at 5 MiB with five backups (`-LogMaxBytes`, `-LogFiles`). Failure returns a
nonzero task result; existing exports are preserved. ZIP delivery copies to a
unique `.partial` file, then renames it after the copy completes. If a hard
timeout interrupts delivery, remove the orphan `.partial` after checking the
task is stopped. Failed normal copies remove their partial file.

`-CopyTo` can be a UNC drop or a local server data inbox (for example
`C:\inetpub\gpo-lens\data\inbox` when collection runs on that server). It
copies the new ZIP, without importing it. Upload through **Tools > Ingest**, or
run the locked CLI against the server database using an authorized maintenance
account:

```powershell
uv run gpo-lens --db C:\inetpub\gpo-lens\data\gpo-lens.sqlite3 ingest C:\inetpub\gpo-lens\data\inbox\lab.example.com-20261006-020000.zip --diff-latest
```

Use your site's actual database path. No inbox watcher, automatic ingest,
alert transport or privileged recurring task is installed by this script.

**Partial collections still succeed.** If the account cannot read some GPOs
(for example SYSVOL folders of security-filtered policies that deny it), the
collector records them in `collection-errors.json`, the log's export summary
lists them under `Failed`, and the task still finishes `0x0` with
`Collection succeeded`. After ingest they appear as `coverage_gap` findings
(`gpo-lens doctor`, **Findings**). Check for those, not only the task result.
Use the privileged inventory overlay below or grant read access to close them.

**The drop folder is not pruned.** Retention applies only to the output root;
ZIPs delivered with `-CopyTo` accumulate until the ingest side removes them.

### Authoritative inventory (manual, less frequent)

A routine least-privilege inventory sees only what that account can enumerate.
A privileged snapshot imported once does not supply coverage for later
snapshots. Initially, periodically (for example monthly), and whenever GPO
permissions or membership change, run this in a session with approved
privileged directory read access, using a **separate root**:

```powershell
.\scripts\Export-GpoEstate.ps1 -OutputRoot C:\GpoPrivileged
$latest = Get-ChildItem C:\GpoPrivileged -Directory | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
New-Item -ItemType Directory -Path C:\GpoInventory -Force | Out-Null
Copy-Item (Join-Path $latest.FullName 'gpo-inventory.json') C:\GpoInventory\gpo-inventory.json -Force
```

Verify that the privileged collector reported a successful GPC enumeration and
that the inventory is complete for this domain before promoting the file.
Refresh it when policies are added/deleted too: an old inventory can miss new
hidden GPOs or retain deleted ones. Keep its refresh date in the site sheet.
Give the routine account read permission, then re-register with the overlay:

```powershell
.\scripts\Register-GpoLensCollection.ps1 -GmsaAccount 'LABDOMAIN\collector$' -OutputRoot C:\GpoExport -InventoryPath C:\GpoInventory\gpo-inventory.json -CopyTo '\\lab.example.com\gpo-drop'
```

`-InventoryPath` captures and validates the inventory bytes before collecting,
then uses those same bytes in both the new export folder and ZIP before delivery.
Missing/empty/malformed inventories, invalid GUIDs or duplicate IDs fail the run; it never
silently falls back to the less-privileged inventory. The routine
`collection-errors.json` stays with the export so ingest can report named
`coverage_gap` findings. Do not run routine collection as Domain Admin.

### Verify and lab-validate

After registration, start one run and inspect its definition and result:

```powershell
Start-ScheduledTask -TaskName GpoLensCollection
Get-ScheduledTaskInfo -TaskName GpoLensCollection | Select-Object LastRunTime, LastTaskResult, NextRunTime
(Get-ScheduledTask -TaskName GpoLensCollection).Principal | Format-List UserId, LogonType, RunLevel
(Get-ScheduledTask -TaskName GpoLensCollection).Settings | Format-List ExecutionTimeLimit, MultipleInstances
$newest = Get-ChildItem C:\GpoExport -File -Filter '*.zip' | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if ($newest) { [pscustomobject]@{ Zip = $newest.Name; AgeHours = ((Get-Date).ToUniversalTime() - $newest.LastWriteTimeUtc).TotalHours } } else { 'No ZIP collected yet' }
Get-Content C:\GpoExport\collection.log -Tail 20
```

Wait for the running task to finish; its last result should be `0` (`0x0`) and
the log should end with `Collection succeeded`. Confirm a new ZIP exists in
the optional drop folder. Ingest it, then check **Briefing** and coverage gaps.
A running/never-run task is not a successful collection. For a retention probe,
set `-Retention 2` and complete three runs at least a second apart; expect two
ZIP/folder pairs. Repeat registration and a run for each account mode. Verify
`-WhatIf` prompts for no password and changes no task, then remove a lab task:

```powershell
.\scripts\Register-GpoLensCollection.ps1 -Unregister -WhatIf
.\scripts\Register-GpoLensCollection.ps1 -Unregister -Confirm:$false
```

Unregister leaves exports/logs intact. **Briefing** reports the newest imported
snapshot's age, including when viewing a historical snapshot, and warns when
it is strictly older than `GPO_LENS_STALE_SNAPSHOT_DAYS` (default 8). Set a
positive integer in the site's environment before app startup and restart the
app to apply it; invalid values log a warning and use 8. Unknown or future
snapshot timestamps warn that freshness cannot be verified. Markdown/CSV
briefing exports include the same signal. Their links pin an offset-aware `as_of`
query parameter to the page's calculation time; direct export requests without
it redirect to an explicit timestamp URL. Replay that URL for reproducible age
calculations. This is import freshness: copying
or repeatedly importing an old ZIP does not prove current AD collection.

## Access control — read this

**gpo-lens has no per-user login.** Behind IIS every request arrives from
`127.0.0.1`, so the app treats *all* callers as the trusted local analyst
(view + ingest + narrate — including replacing the estate). This is by design
for a local-first tool, but it means the IIS site is as open as the network in
front of it.

Do **not** rely on `GPO_LENS_AUTH_TOKEN` to fix this: it requires a `Bearer`
header that a browser cannot send, which only breaks the UI. Instead, restrict
access at the IIS layer:

- **Pass `-WindowsAuth` to the installer** (recommended). It installs the
  `Web-Windows-Auth` role service if missing, enables Windows Authentication
  on the site, and disables anonymous access — so only authenticated domain
  users reach gpo-lens. Unauthenticated requests get 401; browsers prompt for
  credentials automatically. The role service must be installed for the module
  to load; the installer handles this.
  **Note:** Windows Auth is sticky — once enabled, re-running the installer
  without `-WindowsAuth` does *not* re-enable anonymous access (a
  security-positive default). To revert, re-enable anonymous auth in IIS
  Manager or `Set-WebConfigurationProperty … anonymousAuthentication -Name
  enabled -Value $true`.
- A fresh install without Windows Authentication requires the explicit
  `-AllowAnonymousNetworkAccess` opt-out and prints a warning: every reachable
  caller can view, ingest, delete, triage and narrate. Use this only after
  arranging the alternative access boundary.
- An **IP allow-list** (IIS "IP Address and Domain Restrictions").
- Or keep the site on an **isolated/management network**.


### Firewall scope and accepted hosts

New firewall rules default to `-FirewallRemoteAddress LocalSubnet` and only
Domain/Private profiles. Set an explicit management range when needed, for
example `-FirewallRemoteAddress 192.0.2.0/24`. Existing rules are kept during
upgrades to preserve access; inspect their address/profile scope in Windows
Defender Firewall before deliberately changing them.

Every proxied deployment must set `GPO_LENS_ALLOWED_HOSTS`. The installer
derives it from **all HTTPS binding hostnames plus the machine FQDN and short
name**, with the binding ports. A catch-all binding contributes only the machine
names. The merge is idempotent and preserves every other variable. Include any
additional approved DNS aliases you use with a catch-all binding yourself.

For manual IIS setup add, for example, this to
`httpPlatform/environmentVariables` and recycle the pool:

```xml
<environmentVariable name="GPO_LENS_ALLOWED_HOSTS" value="lens.lab.example.com:8443,lens:8443" />
```

The comma-separated authorities are case-insensitive `host` or `host:port`
(bracket IPv6). When unset only `localhost`, `127.0.0.1` and `[::1]`, on any
port, are accepted. A rejected Host returns **400 before authentication, CSRF
and URL generation**, naming the variable. Use the browser's real DNS
authority, preserve Host at the proxy, and keep authentication enabled; the
host policy is an additional boundary.

### Optional: per-user audit attribution

With Windows Auth on, IIS knows who each caller is — but the app sees only
loopback, so `audit.log` records every ingest/delete as `local-analyst`. To
put the real operator in the audit trail, forward the authenticated username
in a request header and tell gpo-lens to trust it:

1. Install the IIS **URL Rewrite** module.
2. In the site's URL Rewrite config, allow the server variable
   `HTTP_X_FORWARDED_USER`, then add an inbound rule (match `.*`, action
   "None") that **sets** `HTTP_X_FORWARDED_USER = {LOGON_USER}` on every
   request. Setting (not conditionally appending) is what makes this safe:
   any client-supplied `X-Forwarded-User` is overwritten before it reaches
   the app. Do **not** configure a pass-through.
3. Set `GPO_LENS_FORWARDED_USER_HEADER=X-Forwarded-User` in the site's
   `web.config` `<httpPlatform><environmentVariables>` block.

The forwarded name only labels the principal in `audit.log` (role
`forwarded`); it grants exactly the same permissions as the loopback
analyst and is ignored entirely when the request does not arrive from the
same-host proxy. Without Windows Auth, `{LOGON_USER}` is empty and the app
falls back to `local-analyst` — so enable `-WindowsAuth` first.

## Why a shared Python install

The Python Install Manager installs runtimes per-user (under
`%LocalAppData%\Python`). The IIS app pool identity (`IIS AppPool\gpo-lens`)
cannot read another user's profile, so the installer copies the runtime to
`C:\ProgramData\gpo-lens\python` and points the venv at that. If you install
Python machine-wide (e.g. under `C:\Program Files`), this copy is skipped.

## Running alongside cert-watch

cert-watch binds the catch-all certificate on `0.0.0.0:443`. gpo-lens uses its
own port (default 8443) with a separate `netsh` SSL binding on
`0.0.0.0:<Port>`, so the two never collide. Both can reuse the same machine
certificate. Browse to `https://lens.lab.example.com:8443/`.

### Sharing port 443 via SNI

If you would rather not use a separate port, gpo-lens can share **443** with
cert-watch via SNI (Server Name Indication). Add `-Sni` (and `-HostName`) to
the installer:

```powershell
.\scripts\install-windows.ps1 -ConfigureIIS -Port 443 `
    -HostName gpo-lens.lab.example.com -TlsCertThumbprint "<thumb>" -Sni -WindowsAuth
```

With `-Sni` the installer:

- Sets `sslFlags=1` (SNI) on the IIS binding so http.sys routes by hostname.
- Binds the certificate via `netsh http add sslcert hostnameport=…` (per-host),
  **not** the catch-all `ipport=0.0.0.0:443` — so cert-watch's binding is
  untouched.
- Requires IIS 8+ (Windows Server 2012+) and a `-HostName` (SNI selects a cert
  by hostname; there is no SNI without one).

The ordering matters: `sslFlags=1` must be on the IIS binding *before* the
`hostnameport` sslcert add, or http.sys rejects it with error 87. The installer
handles this; if you bind by hand, set the binding flags first.

cert-watch keeps the catch-all `0.0.0.0:443` binding (non-SNI), so it serves
any request whose SNI hostname does not match `gpo-lens.lab.example.com`. This is
the desired fallback. Browse to `https://gpo-lens.lab.example.com/` (no port).

## Files

| File | Purpose |
|------|---------|
| `web.config` | HttpPlatformHandler config: launches `python -m gpo_lens --db <data>\gpo-lens.sqlite3 serve` and proxies to it. Copy into the site path. |
| `web.config.reverse-proxy` | *(not provided)* — gpo-lens supports `--root-path` if you front it with a path-based reverse proxy instead. |

## Troubleshooting

- **HTTP 413 / "The page was not displayed because the request entity is too
  large"**: IIS refused the upload before it reached uvicorn. The default
  `maxAllowedContentLength` is 30 MB, which real collector exports exceed
  (a medium estate is often 50–100+ MB). `web.config` raises it to 500 MB to
  match the app's `_MAX_UPLOAD_BYTES`; if you hand-rolled the config or are
  hitting a higher limit, set
  `<requestFiltering><requestLimits maxAllowedContentLength="524288000" />`
  (or raise it further). Also confirm the upload itself is under 500 MB —
  beyond that the app returns its own 413.
- **HTTP 503**: the app pool is stopped or the process failed to start. Check
  `C:\ProgramData\gpo-lens\logs\stdout*.log`.
- **HTTP 403 `{"detail":"CSRF validation failed"}`** on a POST: the request's
  `Origin` (or `Referer`, when `Origin` is absent) did not match the request's
  own `Host`. Browser uploads through this IIS site are accepted automatically
  (the browser's `Origin: https://<iis-host>` matches `Host: <iis-host>`), so a
  403 here usually means either a reverse proxy that rewrites/strips the
  `Host` header, or a non-browser client. `curl` and scripts must send an
  `Origin` or `Referer` header whose host matches the URL they are POSTing to.
- **HTTPS refused / cert errors**: verify the binding with
  `netsh http show sslcert ipport=0.0.0.0:8443` and that the thumbprint exists in
  `LocalMachine\My` with a private key. Verify reachability with an **external**
  client (`curl https://host:8443/`), not in-box .NET, which can mask binding
  issues.
- **HTTP 400 naming `GPO_LENS_ALLOWED_HOSTS`**: add the browser URL authority
  to that variable in `web.config`, then recycle the pool. Check HTTPS bindings
  and aliases; an existing operator value is never overwritten.
- **Port blocked**: confirm the firewall rule `gpo-lens HTTPS <Port>` exists
  (the installer adds it).

## Backup and restore

The estate lives in `C:\ProgramData\gpo-lens\gpo-lens.sqlite3`. It holds the
full ingested estate (GPOs, SOMs, settings, delegation), snapshot history,
and the audit log (`audit.log` alongside it). Back it up regularly.

### Online backup (preferred — no downtime)

Python's SQLite `Connection.backup` is the equivalent of SQLite `.backup`; it
includes committed WAL data while the pool is running. Save this block as
`online-backup.ps1` and run from an elevated PowerShell. Parameters allow a
custom install location. Use a **new backup directory** per run; the procedure
refuses to overwrite one. Keep backups outside the install/data directory.

<!-- regression: online-backup -->
```powershell
param(
    [string]$Data = 'C:\ProgramData\gpo-lens',
    [string]$Backup = 'C:\Backup\gpo-lens-before-upgrade',
    [string]$Py = 'C:\ProgramData\gpo-lens\venv\Scripts\python.exe'
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $Backup -ErrorAction Stop | Out-Null
$databaseBackup = @'
import sqlite3, sys
from pathlib import Path
source = sqlite3.connect((Path(sys.argv[1]) / 'gpo-lens.sqlite3').as_uri() + '?mode=ro', uri=True)
destination = sqlite3.connect(str(Path(sys.argv[2]) / 'gpo-lens.sqlite3'))
source.backup(destination)
assert destination.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
print('integrity_check ok; snapshots', destination.execute('SELECT count(*) FROM snapshot').fetchone()[0])
destination.close()
source.close()
'@
& $Py -c $databaseBackup $Data $Backup
if ($LASTEXITCODE -ne 0) { throw 'SQLite backup or integrity check failed' }
Copy-Item (Join-Path $Data 'audit.log') (Join-Path $Backup 'audit.log') -ErrorAction Stop
```

Schedule the saved script daily or before upgrades. `audit.log` exists after
the first audited action; on an empty install verify that no audited actions
have occurred if it is absent, rather than treating a missing audit log as a
successful backup. Move verified backups to restricted off-host storage. A
concurrent audit copy can have a slightly different cutoff; stop all writers
for a matched estate/audit trail.

### Offline backup (brief downtime)

Save as `offline-backup.ps1`. Stop the pool and copy the **whole data directory**,
including `audit.log` and any matching `-wal`/`-shm` files. The default directory
also includes Python/venv/logs, so allow sufficient backup space. Do not rely
on a stopped worker having checkpointed WAL. Use a fresh destination.

<!-- regression: offline-backup -->
```powershell
param(
    [string]$Data = 'C:\ProgramData\gpo-lens',
    [string]$Backup = 'C:\Backup\gpo-lens-data-before-upgrade',
    [string]$Py = 'C:\ProgramData\gpo-lens\venv\Scripts\python.exe',
    [string]$AppPool = 'gpo-lens'
)
$ErrorActionPreference = 'Stop'
if (Test-Path $Backup) { throw 'Use a new backup directory' }
Stop-WebAppPool -Name $AppPool
try {
    Copy-Item -LiteralPath $Data -Destination $Backup -Recurse -ErrorAction Stop
} finally {
    Start-WebAppPool -Name $AppPool
}
```

### Restore a standalone online backup

Save as `restore.ps1`; supply the **recorded snapshot count** and a **known GPO's
canonical ID** from the backup (lowercase, braces/hyphens stripped). Stop all
writers first. The script preserves the old directory, removes stale sidecars,
restores the DB/audit log, grants the pool modify access, checks integrity and
the recorded evidence, then starts the pool. A failed check leaves it stopped.

<!-- regression: restore -->
```powershell
param(
    [string]$Data = 'C:\ProgramData\gpo-lens',
    [string]$Backup = 'C:\Backup\gpo-lens-before-upgrade',
    [string]$Py = 'C:\ProgramData\gpo-lens\venv\Scripts\python.exe',
    [string]$AppPool = 'gpo-lens',
    [Parameter(Mandatory=$true)][int]$ExpectedSnapshots,
    [Parameter(Mandatory=$true)][string]$KnownGpo
)
$ErrorActionPreference = 'Stop'
Stop-WebAppPool -Name $AppPool
$preserved = "$Data-before-restore-$(Get-Date -Format yyyyMMddHHmmssffff)"
if (Test-Path $preserved) { throw 'Preservation directory already exists' }
Copy-Item -LiteralPath $Data -Destination $preserved -Recurse -ErrorAction Stop
foreach ($suffix in @('-wal', '-shm')) {
    $sidecar = Join-Path $Data "gpo-lens.sqlite3$suffix"
    if (Test-Path $sidecar) { Remove-Item -LiteralPath $sidecar -Force }
}
Copy-Item (Join-Path $Backup 'gpo-lens.sqlite3') (Join-Path $Data 'gpo-lens.sqlite3') -Force
Copy-Item (Join-Path $Backup 'audit.log') (Join-Path $Data 'audit.log') -Force
icacls $Data /grant:r "IIS AppPool\${AppPool}:(OI)(CI)M"
if ($LASTEXITCODE -ne 0) { throw 'Data ACL repair failed' }
$verifyRestore = @'
import sqlite3, sys
from pathlib import Path
connection = sqlite3.connect((Path(sys.argv[1]) / 'gpo-lens.sqlite3').as_uri() + '?mode=ro', uri=True)
assert connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
count = connection.execute('SELECT count(*) FROM snapshot').fetchone()[0]
assert count == int(sys.argv[2]), (count, sys.argv[2])
known = sys.argv[3].strip().strip('{}').replace('-', '').lower()
assert any(row[0].strip().strip('{}').replace('-', '').lower() == known for row in connection.execute('SELECT id FROM gpo')), 'Known GPO missing'
connection.close()
print('integrity_check ok; snapshot count and known GPO verified')
'@
& $Py -c $verifyRestore $Data $ExpectedSnapshots $KnownGpo
if ($LASTEXITCODE -ne 0) { throw 'Restore verification failed; pool remains stopped' }
Start-WebAppPool -Name $AppPool
```

For example: `.\restore.ps1 -ExpectedSnapshots 2 -KnownGpo <recorded-id>`.
Check `/healthz`, `/api/version`, snapshot count and that known GPO through the
actual browser URL after restart. Restore a complete offline directory **as a
unit with its own sidecars**, never mix files from different backups. Preserve
the old directory and repair ACLs before verification/restart in that case too.

Older databases are additive-migrated on open. Rollback requires the previous
code **and its matching pre-upgrade data backup**; a newer migrated database is
not guaranteed to work with older code. Test recovery on an isolated instance.


## Reversible navigation rollout

The default primary navigation is Briefing / Findings / Explore / History /
Tools; existing specialist URLs retain their handlers and query parameters.
To restore the earlier primary links at work, add this environment variable to
the HttpPlatformHandler `environmentVariables` block in `web.config`:

```xml
<environmentVariable name="GPO_LENS_LEGACY_NAV" value="1" />
```

Recycle the application pool to apply it. Remove the variable and recycle to
return to the new navigation. Ask remains under Tools in either mode. The flag
changes presentation only: IIS remains the only access control in this
loopback deployment; do not add an application token.

Optional **Explain these facts** actions require `GPO_LENS_API_KEY`. Without it,
they are absent. Actions open a separate tab and send only bounded counts,
fixed caveats, and snapshot/analysis provenance to the configured narration
endpoint. Raw evidence, names, setting values and rendered HTML are excluded.
The model may only select supplied fact IDs; unsupported claims are rejected.
No narration request runs while a deterministic page loads. Forms are signed
by the serving process, expire after one hour and become invalid on recycle;
reload the original page in that case. This follows the existing single-process
IIS deployment. Ask remains the separate exploratory workbench; its query results are never
sent to narration. It routes the user question to a deterministic query, then
offers the same checked explain action over result counts.
