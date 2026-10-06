"""Deployment boundaries are contracts, checked without optional YAML dependencies.

Compose accepts JSON as YAML; the examples deliberately use that subset so these
guards run in every test job, including machines without Docker.
"""

from __future__ import annotations

import configparser
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTAINER = ROOT / "deploy" / "container"


def test_image_is_pinned_non_root_and_loopback_only() -> None:
    dockerfile = (CONTAINER / "Dockerfile").read_text()
    bases = re.findall(r"^FROM (\S+)", dockerfile, re.MULTILINE)
    assert bases
    assert all(re.search(r"@sha256:[0-9a-f]{64}$", base) for base in bases)
    assert "USER 10001:10001" in dockerfile
    assert 'VOLUME ["/data"]' in dockerfile
    assert 'CMD ["--host", "127.0.0.1", "--port", "8000"]' in dockerfile
    assert "HEALTHCHECK" in dockerfile and "127.0.0.1:8000/healthz" in dockerfile
    assert "uv sync --locked --no-dev --extra web --no-editable" in dockerfile


def test_default_compose_cannot_publish_an_unauthenticated_listener() -> None:
    compose = json.loads((CONTAINER / "compose.yaml").read_text())
    assert set(compose["services"]) == {"app"}
    app = compose["services"]["app"]
    # Host networking preserves the actual loopback peer used by app auth.
    assert app["network_mode"] == "host"
    assert app["command"] == ["--host", "127.0.0.1", "--port", "8000"]
    assert "ports" not in app and "environment" not in app and "env_file" not in app
    assert app["read_only"] is True
    assert app["cap_drop"] == ["ALL"]
    assert app["security_opt"] == ["no-new-privileges:true"]
    assert app["volumes"] == ["estate:/data"]
    assert any(mount.startswith("/tmp:") for mount in app["tmpfs"])  # noqa: S108 - tmpfs contract


def test_proxy_requires_explicit_tls_and_credentials() -> None:
    compose = json.loads((CONTAINER / "compose.proxy.yaml").read_text())
    assert set(compose["services"]) == {"proxy"}
    proxy = compose["services"]["proxy"]
    assert re.search(r"@sha256:[0-9a-f]{64}$", proxy["image"])
    assert proxy["network_mode"] == "host"
    assert proxy["user"] == "10001:10001"
    assert proxy["read_only"] is True
    assert proxy["cap_drop"] == ["ALL"]
    assert proxy["cap_add"] == ["NET_BIND_SERVICE"]
    for name in ("GPO_LENS_HOSTNAME", "GPO_LENS_BASIC_USER", "GPO_LENS_BASIC_HASH"):
        assert proxy["environment"][name].startswith("${" + name + ":?")
    assert not any("AUTH_TOKEN" in name for name in proxy["environment"])
    assert proxy["volumes"] == ["./Caddyfile:/etc/caddy/Caddyfile:ro", "./tls:/etc/caddy/tls:ro"]


def test_proxy_preserves_host_and_overwrites_scheme_and_identity() -> None:
    caddyfile = (CONTAINER / "Caddyfile").read_text()
    assert "https://{$GPO_LENS_HOSTNAME}:8443" in caddyfile
    assert "tls /etc/caddy/tls/server.crt /etc/caddy/tls/server.key" in caddyfile
    assert "basic_auth {" in caddyfile
    assert "{$GPO_LENS_BASIC_USER} {$GPO_LENS_BASIC_HASH}" in caddyfile
    assert "reverse_proxy 127.0.0.1:8000" in caddyfile
    assert "header_up Host {http.request.hostport}" in caddyfile
    assert "header_up X-Forwarded-Proto https" in caddyfile
    assert "header_up -X-Forwarded-User" in caddyfile
    assert "admin off" in caddyfile
    assert "auto_https off" in caddyfile
    # Keep the existing uvicorn boundary: only the app middleware trusts scheme.
    serve = (ROOT / "src/gpo_lens/cli/_serve.py").read_text()
    assert "proxy_headers=False" in serve


def test_build_context_is_an_allowlist_without_estates_or_secrets() -> None:
    rules = (CONTAINER / "Dockerfile.dockerignore").read_text().splitlines()
    rules = [rule for rule in rules if rule and not rule.startswith("#")]
    assert rules[0] == "**"
    assert {rule for rule in rules if rule.startswith("!")} == {
        "!pyproject.toml",
        "!uv.lock",
        "!README.md",
        "!src/",
        "!src/**",
    }
    assert "**/__pycache__" in rules and "**/*.pyc" in rules


def test_systemd_limits_writes_and_runs_a_dedicated_user_on_loopback() -> None:
    unit = configparser.ConfigParser(interpolation=None)
    unit.read(ROOT / "deploy/systemd/gpo-lens.service")
    service = unit["Service"]
    assert service["User"] == "gpo-lens" and service["Group"] == "gpo-lens"
    assert service["ProtectSystem"] == "strict"
    assert service["NoNewPrivileges"] == "true"
    assert service["PrivateTmp"] == "true"
    assert service["ProtectHome"] == "true"
    assert service["ReadWritePaths"] == "/var/lib/gpo-lens"
    assert service["UMask"] == "0077"
    assert service["ExecStart"].endswith("serve --host 127.0.0.1 --port 8000")
    assert "--db /var/lib/gpo-lens/gpo-lens.sqlite3" in service["ExecStart"]
    assert "GPO_LENS_AUTH_TOKEN=" in service["Environment"]
    assert service["CapabilityBoundingSet"] == ""
    assert service["Restart"] == "on-failure"
