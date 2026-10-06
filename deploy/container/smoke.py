"""Exercise the real Compose examples using disposable ports, volumes and TLS.

Run from a checkout after building: python3 deploy/container/smoke.py gpo-lens:local
Requires Linux Docker Engine, Compose v2+, Python 3.12+ and openssl. No Python
packages are needed. Only synthetic tests/fixtures data enters the container.
"""

from __future__ import annotations

import base64
import io
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(url, *, headers=None, data=None, context=None):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        NoRedirect(),
    )
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        response = opener.open(req, timeout=30)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        return response.code, response.headers, response.read()


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main(image):
    with tempfile.TemporaryDirectory(prefix="gpo-lens-smoke-") as scratch:
        work = Path(scratch)
        for filename in ("compose.yaml", "compose.proxy.yaml", "Caddyfile"):
            shutil.copyfile(HERE / filename, work / filename)
        app_port, proxy_port = unused_port(), unused_port()
        while proxy_port == app_port:
            proxy_port = unused_port()
        caddyfile = work / "Caddyfile"
        caddyfile.write_text(
            caddyfile.read_text()
            .replace(":8000", f":{app_port}")
            .replace(":8443", f":{proxy_port}")
        )
        override = {
            "services": {
                "app": {
                    "image": image,
                    "command": ["--host", "127.0.0.1", "--port", str(app_port)],
                    "healthcheck": {
                        "test": [
                            "CMD",
                            "python",
                            "-c",
                            "import urllib.request; "
                            f"urllib.request.urlopen('http://127.0.0.1:{app_port}/healthz').read()",
                        ],
                        "interval": "1s",
                        "timeout": "5s",
                        "start_period": "5s",
                    },
                }
            }
        }
        (work / "smoke.json").write_text(json.dumps(override))
        project = "gpo-lens-smoke-" + secrets.token_hex(6)
        command = [
            "docker",
            "compose",
            "-p",
            project,
            "-f",
            str(work / "compose.yaml"),
            "-f",
            str(work / "compose.proxy.yaml"),
            "-f",
            str(work / "smoke.json"),
        ]
        proxy_image = json.loads((work / "compose.proxy.yaml").read_text())["services"]["proxy"][
            "image"
        ]
        # Disposable credentials only. Never accept an operator's real password.
        password = secrets.token_urlsafe(24)
        hashed = subprocess.check_output(
            [
                "docker",
                "run",
                "--rm",
                proxy_image,
                "caddy",
                "hash-password",
                "--plaintext",
                password,
            ],
            text=True,
        ).strip()
        env = dict(
            os.environ,
            GPO_LENS_HOSTNAME="localhost",
            GPO_LENS_BASIC_USER="analyst",
            GPO_LENS_BASIC_HASH=hashed,
        )
        tls = work / "tls"
        tls.mkdir(mode=0o755)
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-keyout",
                str(tls / "server.key"),
                "-out",
                str(tls / "server.crt"),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # The throwaway test key is readable inside the non-root proxy mount.
        (tls / "server.key").chmod(0o644)
        context = ssl.create_default_context(cafile=str(tls / "server.crt"))

        def compose(*args, capture=False, check=True, stdin=None):
            return subprocess.run(
                command + list(args),
                env=env,
                check=check,
                capture_output=capture,
                text=True,
                stdin=stdin,
            )

        try:
            compose("config", "--quiet")
            compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "90")
            direct = f"http://127.0.0.1:{app_port}"
            assert request(direct + "/healthz")[0] == 200
            assert request(direct + "/")[0] == 200
            # Inspect the actual listener, not only the configured command.
            listener_probe = (
                "from pathlib import Path; "
                "lines=Path('/proc/net/tcp').read_text().splitlines()[1:]; "
                "rows=[line.split() for line in lines]; "
                "listeners=[row[1] for row in rows if row[3]=='0A' "
                f"and row[1].endswith(':{app_port:04X}')]; "
                f"assert listeners==['0100007F:{app_port:04X}'], listeners"
            )
            compose("exec", "-T", "app", "python", "-c", listener_probe)
            filesystem_probe = """import errno, os
from pathlib import Path
assert os.getuid() == 10001
try:
    Path('/app/write-probe').touch()
except OSError as exc:
    assert exc.errno in (errno.EROFS, errno.EACCES)
else:
    raise AssertionError('image root is writable')
for directory in ('/data', '/tmp'):
    probe = Path(directory) / 'write-probe'
    probe.touch()
    probe.unlink()
"""
            compose("exec", "-T", "app", "python", "-c", filesystem_probe)
            print(
                "PASS: loopback health/index, actual loopback listener, non-root read-only image",
                flush=True,
            )

            proxy = f"https://localhost:{proxy_port}"
            # Compose's --wait only checks "running" for a service without a
            # healthcheck. Wait for the actual TLS listener before assertions.
            deadline = time.monotonic() + 30
            while True:
                try:
                    request(proxy + "/healthz", context=context)
                    break
                except urllib.error.URLError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.2)
            auth = "Basic " + base64.b64encode(f"analyst:{password}".encode()).decode()
            headers = {"Authorization": auth}
            for path in ("/", "/healthz", "/ingest"):
                assert request(proxy + path, context=context)[0] == 401, path
            assert (
                request(
                    proxy + "/", headers={"Authorization": "Basic aW52YWxpZA=="}, context=context
                )[0]
                == 401
            )
            status, _, body = request(
                proxy + "/",
                context=context,
                headers=dict(
                    headers, **{"X-Forwarded-Proto": "http", "X-Forwarded-For": "192.0.2.1"}
                ),
            )
            assert status == 200, status
            assert f"https://localhost:{proxy_port}/static/".encode() in body
            assert f"http://localhost:{proxy_port}/static/".encode() not in body
            print(
                "PASS: verified TLS, basic-auth denial/success, HTTPS links, "
                "forwarded client stays loopback",
                flush=True,
            )

            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
                for path in sorted((ROOT / "tests/fixtures").rglob("*")):
                    if path.is_file():
                        archive.write(path, path.relative_to(ROOT / "tests/fixtures"))
            boundary = "gpo-lens-" + secrets.token_hex(12)
            payload = (
                (
                    f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
                    'filename="fixture.zip"\r\n'
                    "Content-Type: application/zip\r\n\r\n"
                ).encode()
                + buf.getvalue()
                + f"\r\n--{boundary}--\r\n".encode()
            )
            upload_headers = dict(
                headers,
                Origin=proxy,
                **{"Content-Type": f"multipart/form-data; boundary={boundary}"},
            )
            rejected = dict(upload_headers, Origin="https://other.example.com")
            assert (
                request(proxy + "/ingest", headers=rejected, data=payload, context=context)[0]
                == 403
            )
            status, result_headers, _ = request(
                proxy + "/ingest", headers=upload_headers, data=payload, context=context
            )
            assert status == 303, status
            assert result_headers["Location"] == proxy + "/"
            status, _, body = request(
                proxy + "/api/v1/query/estate_summary", headers=headers, context=context
            )
            assert status == 200 and json.loads(body)["data"]["gpo_count"] > 0
            compose("restart", "app")
            compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "90")
            status, _, body = request(proxy + "/api/v1/snapshots", headers=headers, context=context)
            assert status == 200 and len(json.loads(body)["snapshots"]) == 1
            print(
                "PASS: cross-origin denial, synthetic Ingest upload/HTTPS redirect, "
                "persisted snapshot after restart",
                flush=True,
            )
            # Keep a WAL writer open so a main-file-only copy MUST lose this
            # committed canary. This exercises the documented backup primitive.
            backup_probe = """import sqlite3
writer = sqlite3.connect('/data/gpo-lens.sqlite3')
assert writer.execute('PRAGMA journal_mode=WAL').fetchone()[0] == 'wal'
writer.execute('CREATE TABLE backup_probe (value TEXT)')
writer.execute("INSERT INTO backup_probe VALUES ('included')")
writer.commit()
source = sqlite3.connect('file:/data/gpo-lens.sqlite3?mode=ro', uri=True)
destination = sqlite3.connect('/data/backup.sqlite3')
source.backup(destination)
assert destination.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
assert destination.execute('SELECT value FROM backup_probe').fetchone()[0] == 'included'
destination.close()
source.close()
writer.close()
"""
            compose("exec", "-T", "app", "python", "-c", backup_probe)
            compose("stop", "app")
            restore_file = work / "restore.sqlite3"
            compose("cp", "app:/data/backup.sqlite3", str(restore_file))
            # Use the exact stopped-instance stream/sidecar pattern
            # from the install guide; the disposable volume is the only target.
            restore_probe = """from pathlib import Path
import sys
p = Path('/data/gpo-lens.sqlite3')
p.write_bytes(sys.stdin.buffer.read())
p.chmod(0o600)
for suffix in ('-wal', '-shm'):
    p.with_name(p.name + suffix).unlink(missing_ok=True)
"""
            with restore_file.open("rb") as backup:
                compose(
                    "run",
                    "--rm",
                    "--no-deps",
                    "-T",
                    "--entrypoint",
                    "python",
                    "app",
                    "-c",
                    restore_probe,
                    stdin=backup,
                )
            compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "90")
            status, _, body = request(proxy + "/api/v1/snapshots", headers=headers, context=context)
            assert status == 200 and len(json.loads(body)["snapshots"]) == 1
            compose(
                "exec",
                "-T",
                "app",
                "python",
                "-c",
                "import sqlite3; c=sqlite3.connect('/data/gpo-lens.sqlite3'); "
                "assert c.execute('SELECT value FROM backup_probe').fetchone()[0]=='included'",
            )
            print(
                "PASS: online backup includes committed WAL data; "
                "stopped restore preserves snapshot",
                flush=True,
            )
        except BaseException:
            compose("logs", "--no-color", "--tail", "60", check=False)
            raise
        finally:
            compose("down", "--volumes", "--remove-orphans", check=False)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "gpo-lens:local")
