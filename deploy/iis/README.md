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
    -ConfigureIIS `
    -Port 8443 `
    -HostName host.example.com `
    -TlsCertThumbprint "<thumbprint from LocalMachine\My>"
```

That single command:

1. Resolves a usable Python and (if it is user-scoped) copies it to a shared
   location the app pool can read.
2. Creates `C:\ProgramData\gpo-lens` (data dir + logs) and a venv, and
   `pip install`s `gpo-lens[web]` into it.
3. Lays down `web.config` in `C:\inetpub\gpo-lens` (paths rewritten to your
   `-InstallDir`).
4. Creates the `gpo-lens` app pool (No Managed Code, AlwaysRunning) and IIS site
   bound to `https://*:<Port>`, grants the pool identity the ACLs it needs,
   binds the TLS cert for that port, opens the firewall, and starts the pool.

Re-running is safe and idempotent: the estate database and an existing
`web.config` are preserved; use it for upgrades too (it stops the pool, refreshes
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

Windows Authentication is sticky: once enabled it is not disabled by an upgrade
run without `-WindowsAuth` (a security-positive default). The `web.config` is
also preserved (operator-set narration env vars are kept); delete it to reset to
the template.

The estate starts **empty**. Open the site and use **Ingest** to upload a
collector export, or drop an existing `gpo-lens.sqlite3` into the data dir.

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
- An **IP allow-list** (IIS "IP Address and Domain Restrictions").
- Or keep the site on an **isolated/management network**.

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
certificate. Browse to `https://host.example.com:8443/`.

### Sharing port 443 via SNI

If you would rather not use a separate port, gpo-lens can share **443** with
cert-watch via SNI (Server Name Indication). Add `-Sni` (and `-HostName`) to
the installer:

```powershell
.\scripts\install-windows.ps1 -ConfigureIIS -Port 443 `
    -HostName gpo-lens.example.com -TlsCertThumbprint "<thumb>" -Sni
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
any request whose SNI hostname does not match `gpo-lens.example.com`. This is
the desired fallback. Browse to `https://gpo-lens.example.com/` (no port).

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
- **Port blocked**: confirm the firewall rule `gpo-lens HTTPS <Port>` exists
  (the installer adds it).

## Backup and restore

The estate lives in `C:\ProgramData\gpo-lens\gpo-lens.sqlite3`. It holds the
full ingested estate (GPOs, SOMs, settings, delegation), snapshot history,
and the audit log (`audit.log` alongside it). Back it up regularly.

### Online backup (preferred — no downtime)

SQLite supports hot backups via the `.backup` command. The app pool can stay
running — WAL mode handles concurrent readers:

```powershell
$py = "C:\ProgramData\gpo-lens\venv\Scripts\python.exe"
& $py -c "import sqlite3; src=sqlite3.connect(r'C:\ProgramData\gpo-lens\gpo-lens.sqlite3'); dst=sqlite3.connect(r'C:\Backup\gpo-lens-$(Get-Date -Format yyyyMMdd).sqlite3'); src.backup(dst); dst.close(); src.close()"
```

Schedule this via Task Scheduler (daily or before each ingest). Copy the
`audit.log` alongside it if you need the audit trail preserved.

### Offline backup (simpler, brief downtime)

Stop the app pool, copy the file, restart:

```powershell
Stop-WebAppPool gpo-lens
Copy-Item C:\ProgramData\gpo-lens\gpo-lens.sqlite3 C:\Backup\gpo-lens-backup.sqlite3
Start-WebAppPool gpo-lens
```

### Restore

Stop the app pool, replace the file, restart:

```powershell
Stop-WebAppPool gpo-lens
Copy-Item C:\Backup\gpo-lens-backup.sqlite3 C:\ProgramData\gpo-lens\gpo-lens.sqlite3 -Force
Start-WebAppPool gpo-lens
```

The schema is additive-migrated on open (`_migrate_schema`), so a DB from an
older gpo-lens version can be restored into a newer install without manual
steps. The reverse (newer DB into older gpo-lens) is not guaranteed.


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
