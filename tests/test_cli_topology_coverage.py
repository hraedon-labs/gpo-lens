"""Coverage tests for CLI topology subcommands (sites, topology-check, scope, etc.)."""

from __future__ import annotations

import json
import subprocess
import sys

GPO_LENS = [sys.executable, "-m", "gpo_lens.cli"]

FIXTURE_DIR = "tests/fixtures"


class TestSitesCommand:
    def test_sites_text_output(self):
        r = subprocess.run(
            GPO_LENS + ["sites", FIXTURE_DIR],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "Branch-Office" in r.stdout
        assert "Default-First-Site-Name" in r.stdout
        assert "site-linked GPOs" in r.stdout.lower() or "AD site" in r.stdout

    def test_sites_json_output(self):
        r = subprocess.run(
            GPO_LENS + ["--json", "sites", FIXTURE_DIR],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        env = json.loads(r.stdout)
        assert env["schema_version"] == 2
        assert env["kind"] == "sites"
        assert isinstance(env["data"], list)
        assert len(env["data"]) >= 2
        names = [s["name"] for s in env["data"]]
        assert "Default-First-Site-Name" in names
        assert "Branch-Office" in names

    def test_sites_json_branch_office_has_links(self):
        r = subprocess.run(
            GPO_LENS + ["--json", "sites", FIXTURE_DIR],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        env = json.loads(r.stdout)
        branch = [s for s in env["data"] if s["name"] == "Branch-Office"][0]
        assert len(branch["links"]) >= 1
        assert branch["links"][0]["gpo_name"]


class TestTopologyCheckCommand:
    def test_topology_check_text_output(self):
        r = subprocess.run(
            GPO_LENS + ["topology-check", FIXTURE_DIR],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0

    def test_topology_check_json_output(self):
        r = subprocess.run(
            GPO_LENS + ["--json", "topology-check", FIXTURE_DIR],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        env = json.loads(r.stdout)
        assert env["schema_version"] == 2
        assert env["kind"] == "topology-check"
        assert isinstance(env["data"], list)


class TestScopeCommand:
    def test_scope_text_output_with_gpo_name(self):
        r = subprocess.run(
            GPO_LENS + ["scope", "gpo-cpassword", FIXTURE_DIR],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "gpo-cpassword" in r.stdout
        assert "Domain:" in r.stdout
        assert "Links" in r.stdout
        assert "Security filtering" in r.stdout

    def test_scope_text_output_with_loopback_gpo(self):
        r = subprocess.run(
            GPO_LENS + ["scope", "gpo-loopback-merge", FIXTURE_DIR],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "Loopback" in r.stdout or "loopback" in r.stdout.lower()

    def test_scope_not_found(self):
        r = subprocess.run(
            GPO_LENS + ["scope", "nonexistent-gpo", FIXTURE_DIR],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1
        assert "not found" in r.stderr.lower()
        assert r.stdout == ""


class TestWmiFiltersCommand:
    def test_wmi_filters_text_output(self):
        r = subprocess.run(
            GPO_LENS + ["wmi-filters", FIXTURE_DIR],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "Fake WMI Filter" in r.stdout or "Nonexistent WMI Filter" in r.stdout

    def test_wmi_filters_json_output(self):
        r = subprocess.run(
            GPO_LENS + ["--json", "wmi-filters", FIXTURE_DIR],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        env = json.loads(r.stdout)
        assert env["schema_version"] == 2
        assert env["kind"] == "wmi-filters"
        assert isinstance(env["data"], list)
        assert len(env["data"]) >= 1


class TestDanglingCommand:
    def test_dangling_text_output(self):
        r = subprocess.run(
            GPO_LENS + ["dangling", FIXTURE_DIR],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0

    def test_dangling_json_output(self):
        r = subprocess.run(
            GPO_LENS + ["--json", "dangling", FIXTURE_DIR],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        env = json.loads(r.stdout)
        assert env["schema_version"] == 2
        assert env["kind"] == "dangling"
        assert isinstance(env["data"], list)


class TestEnforcedCommand:
    def test_enforced_text_output(self):
        r = subprocess.run(
            GPO_LENS + ["enforced", FIXTURE_DIR],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "som_path" in r.stdout
        assert "Branch-Office" in r.stdout or "fakefixture" in r.stdout.lower()

    def test_enforced_json_output(self):
        r = subprocess.run(
            GPO_LENS + ["--json", "enforced", FIXTURE_DIR],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        env = json.loads(r.stdout)
        assert env["schema_version"] == 2
        assert env["kind"] == "enforced"
        assert isinstance(env["data"], list)
