# Linux container deployment

Requires Linux Docker Engine, Docker Compose v2+, and a trusted checkout of the
release to install. The examples use Linux **host networking**: the app binds
only `127.0.0.1:8000`, and the optional Caddy proxy connects to that same
loopback socket. This preserves the [app's auth boundary](../README.md#access-boundary).
Docker Desktop and rootless engines are not covered by this recipe; use the
systemd path or validate their host-network semantics independently. Port 8000
must be free. Run either the container or systemd app, not both on that port.

The Compose files use JSON syntax, which is valid YAML, so their safety guards
can parse them with Python's standard library. The app image uses pinned Python
and build-tool digests, installs only the existing locked core + web closure,
and runs as UID/GID **10001**. No collector inputs, local env files or git history
enter the allowlisted build context. Runtime root is read-only; the named
volume at `/data` holds the database and audit log. `/tmp` is a private 3 GiB
tmpfs for upload ZIPs plus extraction: this is a ceiling, not preallocated RAM.
Allow enough host memory for large uploads (up to 500 MiB ZIP / 2 GiB expanded).
If memory is limited, use a private disk-backed temporary mount with matching
permissions instead. Never share temporary upload storage with untrusted users.

## Install: local browser only

From the repository checkout:

```bash
cd deploy/container
docker compose build
docker compose up -d --wait
curl --fail http://127.0.0.1:8000/healthz
curl --fail http://127.0.0.1:8000/api/version
```

Open `http://127.0.0.1:8000/` on this host and upload through **Ingest** as
described in [collector transfers](../README.md#moving-collector-exports-to-the-server).
The default has no reverse proxy, no published ports, no authentication token,
and no app listener on external interfaces. Local users/processes are trusted
analysts. Do not change `--host` to `0.0.0.0`. A Docker bridge/published port
does not preserve this loopback peer model.

Do not use `docker compose down --volumes` in normal operation: it deletes the
estate. Recreating the app preserves the volume. A bind mount instead of the
named volume must be pre-created with owner `10001:10001` and mode `0700`.
Do not make the app root or make the directory world-writable to fix permission
errors. View logs with `docker compose logs --tail 100 app` and check health
with `docker compose ps`.

## Optional remote browser: Caddy TLS + basic auth

The non-root Caddy container retains only `NET_BIND_SERVICE`: its official
binary has that file capability, so dropping it from the bounding set prevents
execution even on port 8443. The app itself retains no capabilities.

This adds a single TLS listener on **8443**; there is no HTTP listener or ACME
automation. Supply and renew a certificate from your organization's CA (or
another trusted issuer) covering your chosen DNS name. Point that name to this
host, allow TCP 8443 from the intended management network, and keep TCP 8000
blocked by firewall policy as defense in depth. Confirm port 8443 is free.

From `deploy/container`, create the certificate mount:

```bash
sudo install -d -o root -g 10001 -m 0750 tls
sudo install -o root -g 10001 -m 0644 /secure/server.crt tls/server.crt
sudo install -o root -g 10001 -m 0640 /secure/server.key tls/server.key
```

`server.crt` should contain the certificate chain needed by your clients.
Generate a Caddy password hash interactively (the password stays out of shell
history):

```bash
proxy_image=$(python3 -c 'import json; print(json.load(open("compose.proxy.yaml"))["services"]["proxy"]["image"])')
docker run --rm -it --entrypoint caddy "$proxy_image" hash-password
```

Create a local `.env` (gitignored) with the real hostname, chosen login name
and generated hash. **Single-quote the hash** so Compose keeps its dollar signs
literal. Restrict the file to the operator (`chmod 600 .env`):

```dotenv
GPO_LENS_HOSTNAME=gpo-lens.lab.example.com
GPO_LENS_BASIC_USER=analyst
GPO_LENS_BASIC_HASH='<paste the complete Caddy password hash>'
```

Start both services:

```bash
docker compose -f compose.yaml -f compose.proxy.yaml config --quiet
docker compose -f compose.yaml -f compose.proxy.yaml up -d --wait
```

The overlay refuses to start without explicit hostname/user/hash. Caddy also
refuses invalid hashes or missing certificates. Open
`https://gpo-lens.lab.example.com:8443/`; the browser prompts for basic auth.
Every admitted user has full analyst capabilities, including replacing estate
data. Configure additional proxy accounts only if they should have those same
permissions. Access control is Caddy's/network's job; do not set
`GPO_LENS_AUTH_TOKEN` as a browser login. The proxy strips caller-supplied audit
identity and the Basic-auth `Authorization` credential, preserves Host, and overwrites `X-Forwarded-Proto` with `https`.

The overlay sets `GPO_LENS_ALLOWED_HOSTS` to the site authority
`${GPO_LENS_HOSTNAME}:8443` plus loopback authorities for local health checks.
Use a DNS hostname without a scheme or port in `GPO_LENS_HOSTNAME`. If you change
the Caddy site port, change the app's allowed authority too. For additional
approved aliases set a comma-separated list of case-insensitive `host` or
`host:port` authorities (bracket IPv6) in an app environment override. Unset
accepts only `localhost`, `127.0.0.1`, `[::1]` on any port. A disallowed Host
returns 400 naming the variable before authentication, CSRF or URL generation.
Recreate `app` after changing its environment; an app 400 means the browser
authority is absent from the policy.

For **every subsequent Compose command**, include
`-f compose.yaml -f compose.proxy.yaml` if you enabled the proxy. For brevity,
the operations below show the local-only `docker compose` spelling. The data
volume is the same for both configurations.

Verify from an external client with your CA trusted: unauthenticated index,
Ingest and health requests must return 401; authenticated index must return
200. `curl -u analyst https://gpo-lens.lab.example.com:8443/` prompts for the
password. Check HTTPS asset links and a small Ingest upload. Do not disable TLS
verification to make certificate errors disappear. After certificate renewal,
restart `proxy` to load the replacement files. A 502 usually means the app is
down or a port changed; app 401s usually mean a token was configured or the
proxy is connecting through a bridge instead of loopback. A POST 403 usually
means Host/Origin mismatch. Command-line upload clients must send an `Origin`
matching the HTTPS URL's host/port.

## Backup and restore

Create a WAL-safe online database backup inside the data volume, then copy it
and the audit log to a restricted off-host backup location. Do not run two
backup commands concurrently using the same destination:

```bash
docker compose exec -T app python -c "import sqlite3; s=sqlite3.connect('file:/data/gpo-lens.sqlite3?mode=ro', uri=True); d=sqlite3.connect('/data/backup.sqlite3'); s.backup(d); assert d.execute('PRAGMA integrity_check').fetchone()[0]=='ok'; d.close(); s.close()"
docker compose cp app:/data/backup.sqlite3 /secure/backups/gpo-lens-before-upgrade.sqlite3
docker compose cp app:/data/audit.log /secure/backups/audit.log
```

`audit.log` appears after the first audited action. An online log copy may
have a different cut-off from the database. For a matched/offline backup, stop
the app (and proxy if enabled), copy **all** of `/data`, then restart:

```bash
docker compose stop
docker compose cp app:/data /secure/backups/data-before-upgrade
docker compose start
```

Protect all copied files with restrictive permissions. For a standalone
online-backup restore, stop the services, preserve the old directory, stream
the backup into the volume as the service user, and remove unrelated sidecars:

```bash
docker compose stop
docker compose cp app:/data /secure/backups/data-before-restore
docker compose run --rm --no-deps -T --entrypoint python app -c "from pathlib import Path; import sys; p=Path('/data/gpo-lens.sqlite3'); p.write_bytes(sys.stdin.buffer.read()); p.chmod(0o600); [p.with_name(p.name+s).unlink(missing_ok=True) for s in ('-wal','-shm')]" < /secure/backups/gpo-lens-before-upgrade.sqlite3
docker compose run --rm --no-deps --entrypoint python app -c "import sqlite3; c=sqlite3.connect('file:/data/gpo-lens.sqlite3?mode=ro',uri=True); assert c.execute('PRAGMA integrity_check').fetchone()[0]=='ok'; c.close()"
docker compose start
```

Streaming the restore as UID 10001 preserves service ownership without adding
capabilities or running as root. Restore the matching `audit.log` if required
using the same streaming method (mode 0600). For a complete offline directory backup,
restore its contents (including its own WAL/SHM files) as a unit; do not run the
sidecar-removal command against that backup. See the [shared recovery rules](../README.md#backup-restore-and-upgrade-rules).

## Upgrade and rollback

Take and verify a backup first. Record `/api/version` and retain the running
image before replacing the `local` tag:

```bash
docker image tag gpo-lens:local gpo-lens:before-upgrade
```

Switch the checkout to the desired trusted release (do not discard local
configuration). From its `deploy/container` directory:

```bash
docker compose build --pull
docker compose up -d --wait
curl --fail http://127.0.0.1:8000/healthz
curl --fail http://127.0.0.1:8000/api/version
```

Also confirm index, existing snapshots and a known GPO through your actual
browser URL. Refresh base/proxy digests deliberately when security updates are
needed, rebuild and audit; a mutable tag alone cannot update a pinned image.
Rollback requires the pre-upgrade database plus previous image: stop, restore
as above, retag `gpo-lens:before-upgrade` to `gpo-lens:local`, and use
`docker compose up -d --no-build --wait`. Keep the same Compose project name
and file location or explicitly reuse its named volume.

## Reproducible acceptance smoke

From the repository root, after building the image:

```bash
python3 deploy/container/smoke.py gpo-lens:local
```

Requires Python 3.12+, `openssl`, Docker and Compose. The smoke uses the shipped
Compose/Caddy configurations with disposable ports, credentials, a verified
self-signed test certificate and synthetic fixture export. It checks the
actual loopback listener, health/index, read-only/non-root operation, proxy
denial/success, scheme-only forwarding, CSRF, upload, restart persistence and
WAL-safe backup/restore,
then removes only its disposable containers/volume. CI runs the same smoke.
See the upstream [host networking](https://docs.docker.com/engine/network/drivers/host/)
and [Caddy basic auth](https://caddyserver.com/docs/caddyfile/directives/basic_auth)
references for their respective boundaries.
