# Deploying gpo-lens

Choose [IIS](iis/README.md), [Linux containers](container/README.md), or a
[Linux systemd service](systemd/README.md). Run one instance against each
database. Keep the collector on a Windows DC/RSAT host; the analysis server
receives file copies and never connects to Active Directory.

## Access boundary

**gpo-lens has no per-user login.** Without `GPO_LENS_AUTH_TOKEN`, only TCP
loopback peers are accepted. Every accepted caller can view, ingest (including
replace/delete snapshots), triage and narrate. Local processes/users therefore
belong inside the trust boundary. For remote browser access, the same-host
proxy terminates TLS and enforces access control before forwarding to
`127.0.0.1:8000`. The Linux examples use Caddy basic auth; each permitted user
has the same app permissions. Restrict the proxy further with firewall/network
policy when needed. These examples do not provide per-user authorization.

The existing **loopback XOR token** model is unchanged: setting a token
requires a matching `Authorization: Bearer ...` even from loopback. A browser
cannot automatically send that header. Leave the token unset for these browser
deployments; Caddy basic auth is the browser's login. Direct non-loopback API
hosting requires the existing token plus operator-managed TLS and network
controls; it is not the default example.

Keep `gpo-lens serve` as the entry point. It sets `proxy_headers=False` on
uvicorn so forwarded client addresses cannot replace the loopback TCP peer.
The app's middleware honors `X-Forwarded-Proto` **for scheme only**, and only
from loopback. The proxy must preserve the browser's Host (including port) and
overwrite the scheme with `https`; this gives HTTPS asset links and correct
same-origin POST/redirect behavior. Never change to uvicorn's default proxy
header handling or trust forwarded IPs. Use a hostname covered by the TLS
certificate, not a plain-HTTP remote listener. The supplied proxy clears
`X-Forwarded-User`; audit attribution stays `local-analyst`. Basic auth does not
create app identities. Optional identity forwarding requires a proxy to
overwrite the header with its authenticated username on every request, as
described in the [IIS guide](iis/README.md#optional-per-user-audit-attribution).

## Moving collector exports to the server

1. On the DC/RSAT host, run the read-only collector:
   `scripts/Export-GpoEstate.ps1 -OutputRoot C:\GpoExport`.
2. Preserve the complete output, including `SYSVOL-Policies`, inventory and
   collection-errors sidecars. ZIP **the directory's contents**, so
   `AllGPOs.xml` is at the archive root. For example in PowerShell:
   `Compress-Archive -Path C:\GpoExport\* -DestinationPath C:\GpoExport.zip`.
3. Open the local URL or authenticated HTTPS proxy, choose **Ingest**, and
   upload the ZIP. No SMB share, domain account, or collector credentials are
   required on the analysis server. Transfers and stored exports contain
   sensitive configuration; keep originals/backups in restricted storage.
4. Check the snapshot/domain and coverage findings after ingest. An empty
   installation is expected before its first upload; a partial collection must
   still be reported as partial. The app allows ZIP uploads up to 500 MiB and
   expanded contents up to 2 GiB. Allow temporary space for both; see each
   guide's storage notes. Keep original exports for re-ingestion: the upload's
   temporary extraction is removed after ingest.

## Backup, restore and upgrade rules

The persistent directory holds `gpo-lens.sqlite3` and `audit.log`. Back up both
and keep original collector exports separately. Include proxy configuration,
login hashes and TLS certificates/keys in your restricted operational backup;
they are outside the estate volume. The container and systemd guides below
provide exact commands for their paths.

**Never copy just a live SQLite main file.** Committed data may still be in
`gpo-lens.sqlite3-wal`. For a live database use Python's SQLite `Connection.backup`
(a consistent, WAL-safe snapshot). Verify the resulting backup with
`PRAGMA integrity_check`, then move it off the server. A concurrent copy of
`audit.log` can have a slightly different cut-off; stop ingestion/the service
when you need a matched database and audit trail.

For an offline backup, stop all writers and copy the **whole data directory**,
including any `-wal`/`-shm` sidecars still present. Do not depend on shutdown
having checkpointed the WAL. Keep file ownership and restrictive permissions.

For restore, stop all app processes, preserve the current directory as a
rollback copy, and replace the database. For a standalone online-backup file,
remove the stopped instance's old WAL/SHM files before starting with the
replacement. Never combine a restored main file with unrelated sidecars. For
a complete offline directory backup, restore that directory as a unit instead.
Verify integrity, fix ownership, restart and check health, snapshot count and a
known GPO. Do not run two instances against the restored file.

**Back up before every upgrade**, record the running release/image and retain
its source/image and matching database backup. Install/build the chosen release
from a trusted checkout, restart, then check `/healthz`, `/api/version`, index,
existing snapshots and a known GPO. Schema migrations run automatically when
the database opens. Older databases can move forward; a migrated newer
database is not guaranteed to work with older code. Rollback means restoring
the pre-upgrade data **and** running the previous code. Test restore on an
isolated installation before depending on it for recovery.
