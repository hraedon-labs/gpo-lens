# Linux systemd deployment

Requires Linux with systemd, Python 3.12+ with `venv`, [uv](https://docs.astral.sh/uv/getting-started/installation/)
for exporting locked dependencies, and a trusted release checkout. Root-owned
code lives in `/opt/gpo-lens`; service-owned data lives in `/var/lib/gpo-lens`.
The dedicated `gpo-lens` user has no interactive login. The app binds only
`127.0.0.1:8000`, which must be free. Read the
[access boundary](../README.md#access-boundary) first. Local users and
processes are trusted analysts; use an access-controlled TLS proxy for remote
browsers.

## Install

Run from the release checkout. Replace `/usr/bin/python3.12` if your Python
3.12+ binary is elsewhere. Install prerequisites with your OS package manager.
Never make the application user the owner of its executable code.

```bash
sudo useradd --system --user-group --home-dir /var/lib/gpo-lens --no-create-home --shell /usr/sbin/nologin gpo-lens
sudo install -d -o root -g root -m 0755 /opt/gpo-lens
sudo install -d -o gpo-lens -g gpo-lens -m 0700 /var/lib/gpo-lens
sudo /usr/bin/python3.12 -m venv /opt/gpo-lens/venv
install_work=$(mktemp -d)
uv export --quiet --locked --extra web --no-dev --no-emit-project --format requirements-txt -o "$install_work/runtime.txt"
sudo /opt/gpo-lens/venv/bin/python -m pip install --require-hashes -r "$install_work/runtime.txt"
sudo /opt/gpo-lens/venv/bin/python -m pip install --no-deps '.[web]'
rm -r "$install_work"
sudo install -o root -g root -m 0644 deploy/systemd/gpo-lens.service /etc/systemd/system/gpo-lens.service
sudo install -d -o root -g root -m 0755 /etc/gpo-lens
sudo install -o root -g root -m 0600 deploy/systemd/environment /etc/gpo-lens/environment
sudo systemctl daemon-reload
sudo systemctl enable --now gpo-lens
curl --fail http://127.0.0.1:8000/healthz
curl --fail http://127.0.0.1:8000/api/version
```

If the dedicated account already exists, verify it and skip `useradd`. The pip
commands install this checkout and its locked web dependencies, matching the
CI and container versions. The requirement export uses a private temporary
directory. Core dependencies are unchanged; web packages are the existing
optional extra. uv is an installation tool, not a runtime dependency.

Open `http://127.0.0.1:8000/` on the host and use **Ingest** for the collector
ZIP ([transfer instructions](../README.md#moving-collector-exports-to-the-server)).
`PrivateTmp=true` provides isolated disk-backed upload and extraction space;
allow at least 2.5 GiB plus working headroom for the largest supported upload.
The database, WAL/SHM files and audit log live in `/var/lib/gpo-lens`, the
unit's only persistent writable path. `ProtectSystem=strict`, `ProtectHome`,
`NoNewPrivileges`, empty capabilities and kernel protection directives restrict
the service. To fix errors, never place the venv in a user's home directory or
make `/opt/gpo-lens` writable. Logs go to the journal
(`journalctl -u gpo-lens -n 100`); the audit log sits alongside the DB.

## Optional same-host TLS/basic-auth proxy

Install Caddy with its [official package instructions](https://caddyserver.com/docs/install).
Use a CA-issued certificate covering the server's DNS hostname, and the
packaged `caddy` service account. The [bundled Caddyfile](../container/Caddyfile)
is also the systemd example. It listens on TLS **8443**, authenticates every
route, preserves Host, overwrites the scheme and strips untrusted audit
identity. It uses manual certificates; restart Caddy after you renew and
replace them.

```bash
sudo install -d -o root -g caddy -m 0750 /etc/caddy/tls
sudo install -o root -g caddy -m 0644 /secure/server.crt /etc/caddy/tls/server.crt
sudo install -o root -g caddy -m 0640 /secure/server.key /etc/caddy/tls/server.key
sudo install -o root -g caddy -m 0640 deploy/container/Caddyfile /etc/caddy/Caddyfile
caddy hash-password
```

Generate the hash interactively. In `/etc/caddy/Caddyfile`, replace
`{$GPO_LENS_HOSTNAME}`, `{$GPO_LENS_BASIC_USER}` and `{$GPO_LENS_BASIC_HASH}`
with your DNS hostname, login name and complete generated hash. Keep the file
root-owned, mode 0640. Do not set an app bearer token: it would require Bearer
auth even for the proxy's loopback requests and break normal browsers.
Before starting the proxy, edit `/etc/gpo-lens/environment` as root and set
`GPO_LENS_ALLOWED_HOSTS=localhost,127.0.0.1,[::1],gpo-lens.lab.example.com:8443`
with your real proxy authority. Restart `gpo-lens` to apply it. The unit loads
this mandatory environment file; keep it root-owned, mode 0600. The
comma-separated authorities are case-insensitive `host` or `host:port` (bracket
IPv6). Unset, it accepts only loopback authorities on any port. A rejected Host
returns 400 naming the variable, before authentication, CSRF or URL generation.
Keep the loopback entries for direct local health checks. The bundled Caddyfile
strips Basic `Authorization` after authenticating, before forwarding upstream.

Every permitted basic-auth user can ingest and replace snapshots. This is proxy
access control, not app per-user authorization.

Validate configuration and start the packaged proxy service:

```bash
sudo -u caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl enable caddy
sudo systemctl restart caddy
```

Point the certificate-covered hostname to this server. Allow TCP 8443 from the
intended management network and keep TCP 8000 blocked externally. Open
`https://gpo-lens.lab.example.com:8443/` (substitute your name). From an
external client, verify that anonymous index, Ingest and health requests return
401, valid basic auth returns 200, links use HTTPS, and a small upload
succeeds. Use your CA trust store; do not turn off certificate verification.
Start the app with `gpo-lens serve`, not an ad-hoc uvicorn command, to keep
`proxy_headers=False`.

## Backup and restore

For a WAL-safe online backup, create a directory outside the app's writable
area and run the installed Python as the service user:

```bash
sudo install -d -o gpo-lens -g gpo-lens -m 0700 /var/backups/gpo-lens
sudo -u gpo-lens /opt/gpo-lens/venv/bin/python -c "import sqlite3; s=sqlite3.connect('file:/var/lib/gpo-lens/gpo-lens.sqlite3?mode=ro',uri=True); d=sqlite3.connect('/var/backups/gpo-lens/before-upgrade.sqlite3'); s.backup(d); assert d.execute('PRAGMA integrity_check').fetchone()[0]=='ok'; d.close(); s.close()"
sudo cp -p /var/lib/gpo-lens/audit.log /var/backups/gpo-lens/audit.log
```

`audit.log` exists after the first audited action. Move verified backups off
the host into restricted storage. For a matched or offline backup, stop the
app, copy the entire directory (including any WAL/SHM sidecars), then restart:

```bash
sudo systemctl stop gpo-lens
sudo cp -a /var/lib/gpo-lens /var/backups/gpo-lens/data-before-upgrade
sudo systemctl start gpo-lens
```

To restore a standalone online-backup database, stop the app and save the
current directory first. Remove unrelated old sidecars, install the restored
database with the service's ownership, and verify integrity:

```bash
sudo systemctl stop gpo-lens
sudo cp -a /var/lib/gpo-lens /var/backups/gpo-lens/data-before-restore
sudo rm -f /var/lib/gpo-lens/gpo-lens.sqlite3-wal /var/lib/gpo-lens/gpo-lens.sqlite3-shm
sudo install -o gpo-lens -g gpo-lens -m 0600 /var/backups/gpo-lens/before-upgrade.sqlite3 /var/lib/gpo-lens/gpo-lens.sqlite3
sudo -u gpo-lens /opt/gpo-lens/venv/bin/python -c "import sqlite3; c=sqlite3.connect('file:/var/lib/gpo-lens/gpo-lens.sqlite3?mode=ro',uri=True); assert c.execute('PRAGMA integrity_check').fetchone()[0]=='ok'; c.close()"
sudo systemctl start gpo-lens
```

If needed, restore the matching `audit.log` with owner `gpo-lens:gpo-lens` and
mode 0600. Restore a complete offline directory backup as a unit with its own
sidecars; never combine files from different backups. After restart, check
health, snapshot count and a known GPO. See the [shared WAL and rollback
rules](../README.md#backup-restore-and-upgrade-rules).

## Upgrade and rollback

Back up first, record `/api/version`, and keep the previous trusted release
checkout. Stop the app before changing the venv. From the new release:

```bash
sudo systemctl stop gpo-lens
install_work=$(mktemp -d)
uv export --quiet --locked --extra web --no-dev --no-emit-project --format requirements-txt -o "$install_work/runtime.txt"
sudo /opt/gpo-lens/venv/bin/python -m pip install --require-hashes -r "$install_work/runtime.txt"
sudo /opt/gpo-lens/venv/bin/python -m pip install --upgrade --no-deps '.[web]'
rm -r "$install_work"
sudo install -o root -g root -m 0644 deploy/systemd/gpo-lens.service /etc/systemd/system/gpo-lens.service
# On upgrade, create the environment file only if absent; preserve operator values.
sudo install -d -o root -g root -m 0755 /etc/gpo-lens
if ! sudo test -e /etc/gpo-lens/environment; then
    sudo install -o root -g root -m 0600 deploy/systemd/environment /etc/gpo-lens/environment
fi
# Edit GPO_LENS_ALLOWED_HOSTS to the actual proxy hostname:port before restarting.
sudo systemctl daemon-reload
sudo systemctl start gpo-lens
curl --fail http://127.0.0.1:8000/healthz
curl --fail http://127.0.0.1:8000/api/version
```

Preserve any operator unit drop-ins and proxy configuration. Check the index,
existing snapshots and a known GPO through the real browser URL. Rollback needs
both the pre-upgrade database and the previous code: stop, recreate the
root-owned venv from the previous release (so no newer dependencies linger),
restore its backup, then restart. A newer migrated database is not a supported
substitute for the matching older backup.

## Troubleshooting

- Startup/permission errors: `systemctl status gpo-lens` and
  `journalctl -u gpo-lens -n 100`; verify data ownership and root-owned venv.
- App 400 naming `GPO_LENS_ALLOWED_HOSTS`: edit `/etc/gpo-lens/environment`
  to include the actual proxy hostname:port, preserve loopback entries, and
  restart `gpo-lens`.
- App 401 behind proxy: ensure the token is empty and the upstream is exactly
  `127.0.0.1:8000`; keep forwarded-IP handling disabled.
- POST 403: preserve Host; scripts need a matching HTTPS `Origin` or `Referer`.
- Proxy 502: app stopped, port collision or mismatched upstream.
- TLS errors: certificate hostname, expiration, full chain and client CA trust.
- Upload errors: 500 MiB compressed / 2 GiB expanded limit and temporary-disk
  capacity. Do not change systemd hardening to fix an invalid export.
