"""Mock-upstream regression adapted from Daybreak Blue glr2/caddy_header_probe.py.

Exercise the shipped Caddyfile with throwaway TLS and Basic credentials. Only
disposable containers and the local synthetic upstream are used.
"""

from __future__ import annotations

import base64
import http.server
import json
import queue
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    container = "gpo-lens-caddy-header-" + secrets.token_hex(6)
    proxy_image = json.loads((HERE / "compose.proxy.yaml").read_text())["services"]["proxy"][
        "image"
    ]
    received: queue.Queue[dict[str, str]] = queue.Queue()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            received.put({k.lower(): v for k, v in self.headers.items()})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format, *args):
            return

    upstream_port = unused_port()
    proxy_port = unused_port()
    while proxy_port == upstream_port:
        proxy_port = unused_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", upstream_port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    with tempfile.TemporaryDirectory(prefix="gpo-lens-caddy-header-") as d:
        root = Path(d)
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
        caddyfile = root / "Caddyfile"
        caddyfile.write_text(
            (HERE / "Caddyfile")
            .read_text()
            .replace("{$GPO_LENS_HOSTNAME}", "localhost")
            .replace("{$GPO_LENS_BASIC_USER}", "analyst")
            .replace("{$GPO_LENS_BASIC_HASH}", hashed)
            .replace(":8443", f":{proxy_port}")
            .replace(":8000", f":{upstream_port}")
            .replace("/etc/caddy/tls/", "/tls/")
        )
        tls = root / "tls"
        tls.mkdir()
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
        caddyfile.chmod(0o644)
        (tls / "server.key").chmod(0o644)
        (tls / "server.crt").chmod(0o644)
        if (
            subprocess.run(
                ["docker", "container", "inspect", container],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        ):
            raise SystemExit(f"unexpected pre-existing container {container}")
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                container,
                "--network",
                "host",
                "--user",
                "10001:10001",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "NET_BIND_SERVICE",
                "--security-opt",
                "no-new-privileges:true",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777",  # noqa: S108 - private tmpfs
                "--tmpfs",
                "/config:rw,noexec,nosuid,nodev,size=16777216,mode=1777",
                "--tmpfs",
                "/data:rw,noexec,nosuid,nodev,size=16777216,mode=1777",
                "-v",
                f"{caddyfile}:/etc/caddy/Caddyfile:ro",
                "-v",
                f"{tls}:/tls:ro",
                proxy_image,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        try:
            context = ssl.create_default_context(cafile=str(tls / "server.crt"))
            auth = "Basic " + base64.b64encode(f"analyst:{password}".encode()).decode()
            req = urllib.request.Request(
                f"https://localhost:{proxy_port}/",
                headers={
                    "Authorization": auth,
                    "X-Forwarded-For": "198.51.100.99",
                    "X-Forwarded-Proto": "http",
                    "X-Forwarded-Host": "evil.example",
                    "X-Forwarded-User": "spoofed-admin",
                },
            )
            for _ in range(100):
                try:
                    with urllib.request.urlopen(req, context=context, timeout=1) as response:
                        assert response.status == 200
                    break
                except Exception:
                    time.sleep(0.1)
            else:
                subprocess.run(["docker", "logs", container], check=False)
                raise AssertionError("proxy did not become ready")
            headers = received.get(timeout=2)
            selected = {
                key: headers.get(key)
                for key in (
                    "host",
                    "x-forwarded-for",
                    "x-forwarded-proto",
                    "x-forwarded-host",
                    "x-forwarded-user",
                )
            }
            authorization = headers.get("authorization")
            selected["authorization"] = (
                "present-basic"
                if authorization and authorization.startswith("Basic ")
                else authorization
            )
            print(json.dumps(selected, sort_keys=True))
            assert headers.get("authorization") is None, "Basic credential reached upstream"
            assert headers.get("x-forwarded-user") is None, "Caller identity reached upstream"
            assert headers["x-forwarded-proto"] == "https"
            assert headers["host"] == f"localhost:{proxy_port}"
            print("PASS: reviewer mock upstream receives no Authorization")
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            server.shutdown()


if __name__ == "__main__":
    main()
