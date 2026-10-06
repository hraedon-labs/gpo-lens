"""Coverage tests for CLI estate subcommands (summary, unlinked, empty, show, perms, ingest)."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys

import pytest

from gpo_lens import model, store

GPO_LENS = [sys.executable, "-m", "gpo_lens.cli"]

FIXTURE_DIR = "tests/fixtures"


@pytest.fixture
def rich_estate_db(tmp_path):
    db = tmp_path / "rich_estate.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    estate = model.Estate(
        domain="test.local",
        gpos=[
            model.Gpo(
                id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
                name="GPO Alpha",
                domain="test.local",
                created=None,
                modified=None,
                read=None,
                computer_enabled=True,
                user_enabled=False,
                computer_ver_ds=1,
                computer_ver_sysvol=2,
                user_ver_ds=0,
                user_ver_sysvol=0,
                sddl=None,
                owner="BUILTIN\\Admins",
                filter_data_available=False,
                wmi_filter="MyFilter",
                sysvol_path=None,
                settings=[
                    model.Setting(
                        gpo_id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
                        side="Computer",
                        cse="Security",
                        identity="Account:LockoutBadCount",
                        display_name="LockoutBadCount",
                        display_value="5",
                        raw={},
                        from_disabled_side=False,
                    ),
                ],
                delegation=[
                    model.DelegationEntry(
                        gpo_id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
                        trustee="Authenticated Users",
                        trustee_sid="S-1-5-11",
                        permission="Read",
                        allowed=True,
                    ),
                ],
                links=[
                    model.GpoLink(
                        gpo_id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
                        som_name="Workstations",
                        som_path="ou=workstations,dc=test,dc=local",
                        link_enabled=True,
                        enforced=False,
                    ),
                ],
            ),
            model.Gpo(
                id="ccccccccccccccccccccccccccccccc1",
                name="GPO Beta Unlinked",
                domain="test.local",
                created=None,
                modified=None,
                read=None,
                computer_enabled=False,
                user_enabled=True,
                computer_ver_ds=0,
                computer_ver_sysvol=0,
                user_ver_ds=0,
                user_ver_sysvol=0,
                sddl=None,
                owner=None,
                filter_data_available=False,
                wmi_filter=None,
                sysvol_path=None,
                settings=[
                    model.Setting(
                        gpo_id="ccccccccccccccccccccccccccccccc1",
                        side="Computer",
                        cse="Security",
                        identity="Account:LockoutBadCount",
                        display_name="LockoutBadCount",
                        display_value="10",
                        raw={},
                        from_disabled_side=True,
                    ),
                ],
            ),
        ],
        soms=[
            model.Som(
                path="ou=workstations,dc=test,dc=local",
                name="Workstations",
                container_type="ou",
                inheritance_blocked=False,
                links=[
                    model.SomLink(
                        gpo_id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
                        order=1,
                        enabled=True,
                        enforced=True,
                        target="ou=workstations,dc=test,dc=local",
                    ),
                    model.SomLink(
                        gpo_id="missing-gpo",
                        order=2,
                        enabled=True,
                        enforced=False,
                        target="ou=workstations,dc=test,dc=local",
                    ),
                ],
            ),
        ],
        wmi_filters=[
            model.WmiFilter(name="MyFilter", query="SELECT * FROM Win32_OperatingSystem"),
        ],
    )
    store.save_estate(conn, estate)
    conn.close()
    return db


@pytest.fixture
def empty_estate_db(tmp_path):
    db = tmp_path / "empty_estate.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    estate = model.Estate(domain="test.local")
    store.save_estate(conn, estate)
    conn.close()
    return db


class TestSummaryCommand:
    def test_summary_text_populated(self, rich_estate_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_estate_db), "summary"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "Domain: test.local" in r.stdout
        assert "GPOs:" in r.stdout
        assert "SOMs:" in r.stdout
        assert "Hygiene & security:" in r.stdout
        assert "Unlinked GPOs:" in r.stdout
        assert "Empty GPOs:" in r.stdout or "Disabled-but-populated:" in r.stdout
        assert "Version skew:" in r.stdout
        assert "Enforced links:" in r.stdout
        assert "Dangling links:" in r.stdout
        assert "WMI-filtered GPOs:" in r.stdout

    def test_summary_json_populated(self, rich_estate_db):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(rich_estate_db), "summary"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        env = json.loads(r.stdout)
        assert env["schema_version"] == 2
        assert env["kind"] == "summary"
        data = env["data"]
        assert data["domain"] == "test.local"
        assert data["gpo_count"] == 2
        assert data["som_count"] == 1
        assert data["wmi_filter_count"] == 1
        assert data["unlinked_count"] >= 1
        assert data["enforced_link_count"] >= 1
        assert data["dangling_link_count"] >= 1

    def test_summary_text_empty_estate(self, empty_estate_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(empty_estate_db), "summary"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "Domain: test.local" in r.stdout
        assert "GPOs:  0" in r.stdout or "GPOs: 0" in r.stdout
        assert "No issues detected." in r.stdout

    def test_summary_json_empty_estate(self, empty_estate_db):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(empty_estate_db), "summary"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        env = json.loads(r.stdout)
        data = env["data"]
        assert data["gpo_count"] == 0
        assert data["unlinked_count"] == 0


class TestUnlinkedCommand:
    def test_unlinked_text_populated(self, rich_estate_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_estate_db), "unlinked"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "GPO Beta Unlinked" in r.stdout

    def test_unlinked_text_empty_estate(self, empty_estate_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(empty_estate_db), "unlinked"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "No unlinked" in r.stdout or "No results" in r.stdout or r.stdout.strip() == ""


class TestEmptyCommand:
    def test_empty_text_populated(self, rich_estate_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_estate_db), "empty"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0

    def test_empty_text_empty_estate(self, empty_estate_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(empty_estate_db), "empty"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0


class TestShowCommand:
    def test_show_text_with_known_gpo(self, rich_estate_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_estate_db), "show", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "GPO Alpha" in r.stdout

    def test_show_text_empty_estate(self, empty_estate_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(empty_estate_db), "show", "nonexistent"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0


class TestPermsCommand:
    def test_perms_text_populated(self, rich_estate_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_estate_db), "perms"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "Authenticated Users" in r.stdout or "GPO Alpha" in r.stdout

    def test_perms_text_empty_estate(self, empty_estate_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(empty_estate_db), "perms"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0


class TestIngestDiffLatestJson:
    def test_ingest_json_diff_latest_with_prior(self, tmp_path):
        db = tmp_path / "ingest_diff.db"
        conn = sqlite3.connect(str(db))
        store.init_db(conn)
        gpo = model.Gpo(
            id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            name="gpo-cpassword",
            domain="fakefixture.local",
            created=None,
            modified=None,
            read=None,
            computer_enabled=True,
            user_enabled=True,
            computer_ver_ds=1,
            computer_ver_sysvol=1,
            user_ver_ds=1,
            user_ver_sysvol=1,
            sddl=None,
            owner=None,
            filter_data_available=False,
            wmi_filter=None,
            sysvol_path=None,
        )
        estate = model.Estate(domain="fakefixture.local", gpos=[gpo])
        store.save_estate(conn, estate)
        conn.close()

        r = subprocess.run(
            GPO_LENS
            + [
                "--db",
                str(db),
                "ingest",
                "--json",
                "--diff-latest",
                FIXTURE_DIR,
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        env = json.loads(r.stdout)
        assert env["schema_version"] == 2
        assert env["kind"] == "ingest"
        data = env["data"]
        assert data["domain"] == "fakefixture.local"
        assert data["gpo_count"] > 1
        assert "changelog" in data
        assert isinstance(data["changelog"], list)
        assert len(data["changelog"]) > 0

    def test_ingest_json_diff_latest_no_prior(self, tmp_path):
        db = tmp_path / "ingest_noprior.db"
        r = subprocess.run(
            GPO_LENS
            + [
                "--db",
                str(db),
                "ingest",
                "--json",
                "--diff-latest",
                FIXTURE_DIR,
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        env = json.loads(r.stdout)
        data = env["data"]
        assert "changelog" not in data

    def test_ingest_text_diff_latest_shows_changelog_entries(self, tmp_path):
        db = tmp_path / "ingest_text.db"
        conn = sqlite3.connect(str(db))
        store.init_db(conn)
        gpo = model.Gpo(
            id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            name="gpo-cpassword",
            domain="fakefixture.local",
            created=None,
            modified=None,
            read=None,
            computer_enabled=True,
            user_enabled=True,
            computer_ver_ds=1,
            computer_ver_sysvol=1,
            user_ver_ds=1,
            user_ver_sysvol=1,
            sddl=None,
            owner=None,
            filter_data_available=False,
            wmi_filter=None,
            sysvol_path=None,
        )
        estate = model.Estate(domain="fakefixture.local", gpos=[gpo])
        store.save_estate(conn, estate)
        conn.close()

        r = subprocess.run(
            GPO_LENS
            + [
                "--db",
                str(db),
                "ingest",
                "--diff-latest",
                FIXTURE_DIR,
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "snapshot=" in r.stdout
        assert "Changes since previous snapshot" in r.stdout
        assert "[META]" in r.stdout or "[DETAIL]" in r.stdout
