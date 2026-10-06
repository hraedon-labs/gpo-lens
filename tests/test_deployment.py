"""Deployment boundaries are contracts, checked without optional YAML dependencies.

Compose accepts JSON as YAML; the examples deliberately use that subset so these
guards run in every test job, including machines without Docker.
"""

from __future__ import annotations

import ast
import configparser
import json
import re
import shutil
import subprocess
import sys
import sysconfig
import tomllib
import zipfile
from pathlib import Path

from gpo_lens.ingest import load_estate
from gpo_lens.web.app import _safe_extract

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
    assert set(compose["services"]) == {"app", "proxy"}
    allowed = compose["services"]["app"]["environment"]["GPO_LENS_ALLOWED_HOSTS"]
    assert "${GPO_LENS_HOSTNAME:?" in allowed and ":8443" in allowed
    assert "127.0.0.1" in allowed  # retain the direct-loopback healthcheck
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
    assert "header_up -Authorization" in caddyfile
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
    assert service["EnvironmentFile"] == "/etc/gpo-lens/environment"
    environment = (ROOT / "deploy/systemd/environment").read_text()
    assert "GPO_LENS_ALLOWED_HOSTS=" in environment
    assert "gpo-lens.lab.example.com:8443" in environment


def test_iis_requirements_match_lock(tmp_path: Path) -> None:
    exported = tmp_path / "requirements.txt"
    subprocess.run(
        [
            "uv",
            "export",
            "--locked",
            "--extra",
            "web",
            "--no-dev",
            "--no-emit-project",
            "--no-header",
            "--format",
            "requirements-txt",
            "-o",
            str(exported),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    assert exported.read_bytes() == (ROOT / "deploy/iis/requirements-web.lock.txt").read_bytes()
    installer = (ROOT / "scripts/install-windows.ps1").read_text()
    assert "pip install --require-hashes -r $requirements" in installer
    assert "pip install --upgrade --no-build-isolation --no-deps $pkg" in installer


def test_iis_build_lock_matches_uv_and_backend_contract(tmp_path: Path) -> None:
    exported = tmp_path / "build.txt"
    subprocess.run(
        [
            "uv",
            "export",
            "--locked",
            "--only-group",
            "build",
            "--no-emit-project",
            "--no-header",
            "--format",
            "requirements-txt",
            "-o",
            str(exported),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    assert exported.read_bytes() == (ROOT / "deploy/iis/requirements-build.lock.txt").read_bytes()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert project["dependency-groups"]["build"] == project["build-system"]["requires"]
    installer = (ROOT / "scripts/install-windows.ps1").read_text()
    assert "pip install --require-hashes -r $buildRequirements" in installer
    assert installer.index("pip install --require-hashes -r $buildRequirements") < installer.index(
        "pip install --upgrade --no-build-isolation --no-deps $pkg"
    )


def test_glv2_offline_project_install(tmp_path: Path) -> None:
    """Repeat buildprobe's no-index install using the installer's actual options.

    The dev environment supplies the locked build backend, just as the IIS
    hash-checked build requirements do. The disposable venv supplies pip.
    """
    import os

    subprocess.run([sys.executable, "-m", "venv", str(tmp_path / "venv")], check=True)
    python = tmp_path / "venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    source = (ROOT / "scripts/install-windows.ps1").read_text()
    flags = re.search(r"pip install (--upgrade[^\n]+) \$pkg", source)
    assert flags
    env = dict(os.environ, PIP_NO_INDEX="1", PYTHONPATH=sysconfig.get_paths()["purelib"])
    env.update(PIP_NO_CACHE_DIR="1", PIP_DISABLE_PIP_VERSION_CHECK="1")
    checkout = tmp_path / "source"
    checkout.mkdir()
    for name in ("pyproject.toml", "README.md"):
        shutil.copyfile(ROOT / name, checkout / name)
    shutil.copytree(ROOT / "src", checkout / "src", ignore=shutil.ignore_patterns("__pycache__"))
    result = subprocess.run(
        [str(python), "-m", "pip", "install", *flags[1].split(), str(checkout) + "[web]"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Installing build dependencies" not in result.stdout
    version = subprocess.check_output(
        [
            str(python),
            "-c",
            "import importlib.metadata; print(importlib.metadata.version('gpo-lens'))",
        ],
        text=True,
    ).strip()
    assert version == tomllib.loads((checkout / "pyproject.toml").read_text())["project"]["version"]


def test_installer_uses_the_tested_endpoint_transition() -> None:
    body = (
        (ROOT / "scripts/install-windows.ps1")
        .read_text()
        .split("# 5. Create / update the IIS site.", 1)[1]
    )
    assert "Set-IisEndpoint -SiteName $siteName" in body
    assert "-CertThumbprint $effCert -Existing $existing" in body
    assert "-Name bindings" not in body


def test_transfer_uses_collector_zip_and_changelog_covers_shipped_fixes() -> None:
    transfer = (ROOT / "deploy/README.md").read_text().split("## Moving collector exports")[1]
    transfer = transfer.split("## Backup")[0]
    assert "Compress-Archive" not in transfer
    assert "collector-produced ZIP" in transfer
    assert "forward slashes" in transfer
    assert "260" in transfer
    assert "partial ZIP" in transfer
    assert "folder" in transfer and "shorter" in transfer
    assert "Windows PowerShell 5.1" in transfer
    assert "-NoZip" in transfer
    # Shipped fixes remain in history when a new Unreleased section is added.
    changelog = (ROOT / "CHANGELOG.md").read_text()
    for term in ("double-conversion", "snapshot-scoped", "batched persistence"):
        assert term in changelog


def test_collector_zip_paths_preserve_linux_sysvol(tmp_path: Path) -> None:
    """glr4/review_probes.py's ZIP scenario using the collector's slash convention."""
    transfer = (ROOT / "deploy/README.md").read_text()
    assert "collector-produced ZIP" in transfer
    archive, extracted = tmp_path / "collector.zip", tmp_path / "extracted"
    extracted.mkdir()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.write(ROOT / "tests/fixtures/AllGPOs.xml", "AllGPOs.xml")
        # Same synthetic entry as the reviewer, with collector-normalized slashes.
        zipped.writestr(
            "SYSVOL-Policies/{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}/Machine/Registry.pol",
            b"PReg",
        )
    _safe_extract(archive, extracted)
    estate = load_estate(extracted)
    assert (extracted / "SYSVOL-Policies").is_dir()
    assert "missing_sysvol" not in {gap.kind for gap in estate.coverage_gaps}


def test_smoke_embedded_probes_are_standalone() -> None:
    tree = ast.parse((CONTAINER / "smoke.py").read_text())
    for node in ast.walk(tree):
        # Inspect complete assigned scripts, excluding f-string fragments.
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            payload = node.value.value
            if isinstance(payload, str) and "from pathlib import Path" in payload:
                compile(payload, "embedded probe", "exec")
                assert "header_probe" not in payload
