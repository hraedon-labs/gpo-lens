# Linux container deployment

Requires Linux Docker Engine, Docker Compose v2+, and a trusted checkout of the
release to install. The examples use Linux **host networking**: the app binds
only `127.0.0.1:8000`, and the optional Caddy proxy connects to that same
loopback socket. This preserves the [app's auth boundary](../README.md#access-boundary).
Docker Desktop and rootless engines are not covered; use the systemd path or
validate their host-network semantics independently. Port 8000 must be free.
Run either the container or the systemd app, not both on that port.

The Compose files use JSON syntax, which is valid YAML, so their safety guards
can parse them with Python's standard library. The app image uses pinned Python
and build-tool digests, installs only the existing locked core + web closure,
and runs as UID/GID **10001**. No collector inputs, local env files or git
history enter the allowlisted build context. The runtime root is read-only; the
named volume at `/data` holds the database and audit log. `/tmp` is a private
3 GiB tmpfs for upload ZIPs and extraction. This is a ceiling, not preallocated
RAM, but allow enough host memory for large uploads (up to 500 MiB ZIP / 2 GiB
expanded). If memory is limited, use a private disk-backed temporary mount with
matching permissions instead. Never share temporary upload storage with
untrusted users.

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
The default has no reverse proxy, no published ports, no authentication token
and no app listener on external interfaces. Local users and processes are
trusted analysts. Do not change `--host` to `0.0.0.0`: a Docker bridge or
published port does not preserve the loopback peer model.

Do not use `docker compose down --volumes` in normal operation; it deletes the
estate. Recreating the app preserves the volume. A bind mount instead of the
named volume must be pre-created with owner `10001:10001` and mode `0700`. To
fix permission errors, never make the app root or make the directory
world-writable. View logs with `docker compose logs --tail 100 app` and check
health with `docker compose ps`.

## Optional remote browser: Caddy TLS + basic auth

The non-root Caddy container retains only `NET_BIND_SERVICE`. Its official
binary has that file capability, so dropping it from the bounding set prevents
execution even on port 8443. The app itself retains no capabilities.

This adds a single TLS listener on **8443**. There is no HTTP listener or ACME
automation. Supply and renew a certificate from your organization's CA (or
another trusted issuer) covering your chosen DNS name. Point that name to this
host, allow TCP 8443 from the intended management network, and keep TCP 8000
blocked by firewall policy as defense in depth. Port 8443 must be free.

From `deploy/container`, create the certificate mount:

```bash
sudo install -d -o root -g 10001 -m 0750 tls
sudo install -o root -g 10001 -m 0644 /secure/server.crt tls/server.crt
sudo install -o root -g 10001 -m 0640 /secure/server.key tls/server.key
```

`server.crt` should contain the certificate chain your clients need. Generate
a Caddy password hash interactively (this keeps the password out of shell
history):

```bash
proxy_image=$(python3 -c 'import json; print(json.load(open("compose.proxy.yaml"))["services"]["proxy"]["image"])')
docker run --rm -it --entrypoint caddy "$proxy_image" hash-password
```

Create a local `.env` (gitignored) with the real hostname, your chosen login
name and the generated hash. **Single-quote the hash** so Compose keeps its
dollar signs literal. Restrict the file to the operator (`chmod 600 .env`):

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

The overlay refuses to start without an explicit hostname, user and hash, and
Caddy refuses invalid hashes or missing certificates. Open
`https://gpo-lens.lab.example.com:8443/`; the browser prompts for basic auth.
Every admitted user has full analyst capabilities, including replacing estate
data, so add proxy accounts only for people who should have them. Access
control is Caddy's and the network's job; do not set `GPO_LENS_AUTH_TOKEN` as a
browser login. The proxy strips caller-supplied audit identity and the
Basic-auth `Authorization` credential, preserves Host, and overwrites
`X-Forwarded-Proto` with `https`.

The overlay sets `GPO_LENS_ALLOWED_HOSTS` to the site authority
`${GPO_LENS_HOSTNAME}:8443` plus loopback authorities for local health checks.
Put a DNS hostname without scheme or port in `GPO_LENS_HOSTNAME`. If you change
the Caddy site port, change the app's allowed authority too. For additional
approved aliases, set a comma-separated list of case-insensitive `host` or
`host:port` authorities (bracket IPv6) in an app environment override. Unset,
it accepts only `localhost`, `127.0.0.1`, `[::1]` on any port. A disallowed Host
returns 400 naming the variable, before authentication, CSRF or URL generation.
Recreate `app` after changing its environment. An app 400 means the browser
authority is missing from the policy.

With the proxy enabled, include `-f compose.yaml -f compose.proxy.yaml` in
**every subsequent Compose command**. The operations below show the local-only
`docker compose` spelling for brevity. The data volume is the same in both
configurations.

Verify from an external client that trusts your CA. Unauthenticated index,
Ingest and health requests must return 401; an authenticated index must return
200. `curl -u analyst https://gpo-lens.lab.example.com:8443/` prompts for the
password. Check HTTPS asset links and a small Ingest upload. Do not disable TLS
verification to make certificate errors disappear. After certificate renewal,
restart `proxy` to load the replacement files.

- A 502 usually means the app is down or a port changed.
- An app 401 usually means a token was configured, or the proxy is connecting
  through a bridge instead of loopback.
- A POST 403 usually means a Host/Origin mismatch. Command-line upload clients
  must send an `Origin` matching the HTTPS URL's host and port.

## Backup and restore

Create a WAL-safe online database backup inside the data volume, then copy it
and the audit log to a restricted off-host backup location. Do not run two
backup commands at once with the same destination:

```bash
docker compose exec -T app python -c "import sqlite3; s=sqlite3.connect('file:/data/gpo-lens.sqlite3?mode=ro', uri=True); d=sqlite3.connect('/data/backup.sqlite3'); s.backup(d); assert d.execute('PRAGMA integrity_check').fetchone()[0]=='ok'; d.close(); s.close()"
docker compose cp app:/data/backup.sqlite3 /secure/backups/gpo-lens-before-upgrade.sqlite3
docker compose cp app:/data/audit.log /secure/backups/audit.log
```

`audit.log` appears after the first audited action. An online log copy may
have a different cut-off from the database. For a matched or offline backup,
stop the app (and the proxy, if enabled), copy **all** of `/data`, then restart:

```bash
docker compose stop
docker compose cp app:/data /secure/backups/data-before-upgrade
docker compose start
```

Protect all copied files with restrictive permissions. To restore a standalone
online backup, stop the services, keep the old directory, stream the backup
into the volume as the service user, and remove unrelated sidecars:

```bash
docker compose stop
docker compose cp app:/data /secure/backups/data-before-restore
docker compose run --rm --no-deps -T --entrypoint python app -c "from pathlib import Path; import sys; p=Path('/data/gpo-lens.sqlite3'); p.write_bytes(sys.stdin.buffer.read()); p.chmod(0o600); [p.with_name(p.name+s).unlink(missing_ok=True) for s in ('-wal','-shm')]" < /secure/backups/gpo-lens-before-upgrade.sqlite3
docker compose run --rm --no-deps --entrypoint python app -c "import sqlite3; c=sqlite3.connect('file:/data/gpo-lens.sqlite3?mode=ro',uri=True); assert c.execute('PRAGMA integrity_check').fetchone()[0]=='ok'; c.close()"
docker compose start
```

Streaming the restore as UID 10001 preserves service ownership without adding
capabilities or running as root. If needed, restore the matching `audit.log`
the same way (mode 0600). Restore a complete offline directory backup's
contents (including its own WAL/SHM files) as a unit; do not run the
sidecar-removal command against it. See the
[shared recovery rules](../README.md#backup-restore-and-upgrade-rules).

## Upgrade and rollback

Take and verify a backup first. Record `/api/version` and keep the running
image before replacing the `local` tag:

```bash
docker image tag gpo-lens:local gpo-lens:before-upgrade
```

Switch the checkout to the trusted release you want, keeping local
configuration. From its `deploy/container` directory:

```bash
docker compose build --pull
docker compose up -d --wait
curl --fail http://127.0.0.1:8000/healthz
curl --fail http://127.0.0.1:8000/api/version
```

Also confirm the index, existing snapshots and a known GPO through your actual
browser URL. When security updates are needed, refresh the base and proxy
digests deliberately, rebuild and audit; a mutable tag alone cannot update a
pinned image. Rollback needs the pre-upgrade database plus the previous image:
stop, restore as above, retag `gpo-lens:before-upgrade` to `gpo-lens:local`, and
run `docker compose up -d --no-build --wait`. Keep the same Compose project name
and file location, or explicitly reuse its named volume.

## Reproducible acceptance smoke

From the repository root, after building the image:

```bash
python3 deploy/container/smoke.py gpo-lens:local
```

Requires Python 3.12+, `openssl`, Docker and Compose. The smoke uses the
shipped Compose and Caddy configurations with disposable ports and credentials,
a verified self-signed test certificate and a synthetic fixture export. It
checks the actual loopback listener, health and index, read-only non-root
operation, proxy denial and success, scheme-only forwarding, CSRF, upload,
restart persistence and WAL-safe backup/restore. It then removes only its
disposable containers and volume. CI runs the same smoke. See the upstream
[host networking](https://docs.docker.com/engine/network/drivers/host/)
and [Caddy basic auth](https://caddyserver.com/docs/caddyfile/directives/basic_auth)
references for their respective boundaries.
