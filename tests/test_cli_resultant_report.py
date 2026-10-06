"""CLI integration tests for the resultant and report subcommands.

These exercise the argparse wiring, output rendering (both text and
--json), error paths, and the baseline/changelog options on report.
The underlying merge/report logic is covered by test_principal_resultant
and test_report; this file tests the CLI layer itself.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

GPO_LENS = [sys.executable, "-m", "gpo_lens.cli"]

DOMAIN_SID = "s-1-5-21-1000000000-2000000000-3000000000"
USER_SID = f"{DOMAIN_SID}-1001"
GROUP_SID = f"{DOMAIN_SID}-2001"

GPO_BROAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
GPO_GROUP_APPLY = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
GPO_OTHER_GROUP = "cccccccccccccccccccccccccccccccc"
GPO_WMI = "dddddddddddddddddddddddddddddddd"
GPO_NO_DELEGATION = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
ROOT_DN = "dc=test,dc=local"


def _make_principal_db(tmp_path: Path) -> Path:
    """Build a SQLite DB with principals, group members, and GPOs for resultant testing."""
    from gpo_lens import store
    from gpo_lens.model import (
        DelegationEntry,
        Estate,
        Gpo,
        GroupMembership,
        ResolvedPrincipal,
        Setting,
        Som,
        SomLink,
        WmiFilter,
    )

    db = tmp_path / "principal.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    principals = {
        USER_SID: ResolvedPrincipal(
            sid=USER_SID,
            name="TEST\\jdoe",
            sam="jdoe",
            principal_type="User",
            domain="TEST",
            resolved=True,
        ),
        GROUP_SID: ResolvedPrincipal(
            sid=GROUP_SID,
            name="TEST\\Helpdesk Operators",
            sam="Helpdesk Operators",
            principal_type="Group",
            domain="TEST",
            resolved=True,
        ),
    }
    group_members = {
        GROUP_SID: GroupMembership(
            sid=GROUP_SID,
            name="TEST\\Helpdesk Operators",
            members=(USER_SID,),
            member_count=1,
        ),
    }

    def _gpo(gpo_id, name, *, settings=None, delegation=None, wmi_filter=None):
        return Gpo(
            id=gpo_id,
            name=name,
            domain="test.local",
            created=None,
            modified=None,
            read=None,
            computer_enabled=True,
            user_enabled=True,
            computer_ver_ds=None,
            computer_ver_sysvol=None,
            user_ver_ds=None,
            user_ver_sysvol=None,
            sddl=None,
            owner=None,
            filter_data_available=False,
            wmi_filter=wmi_filter,
            sysvol_path=None,
            settings=settings or [],
            delegation=delegation or [],
        )

    def _user_setting(gpo_id, identity, value):
        return Setting(
            gpo_id=gpo_id,
            side="User",
            cse="Registry",
            identity=identity,
            display_name=identity,
            display_value=value,
            raw={},
            from_disabled_side=False,
        )

    gpos = [
        _gpo(
            GPO_BROAD,
            "gpo-broad",
            settings=[_user_setting(GPO_BROAD, r"HKCU\Software\A", "1")],
            delegation=[
                DelegationEntry(
                    gpo_id=GPO_BROAD,
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Apply Group Policy",
                    allowed=True,
                )
            ],
        ),
        _gpo(
            GPO_GROUP_APPLY,
            "gpo-group-apply",
            settings=[_user_setting(GPO_GROUP_APPLY, r"HKCU\Software\B", "2")],
            delegation=[
                DelegationEntry(
                    gpo_id=GPO_GROUP_APPLY,
                    trustee="Helpdesk Operators",
                    trustee_sid=GROUP_SID,
                    permission="Apply Group Policy",
                    allowed=True,
                )
            ],
        ),
        _gpo(
            GPO_OTHER_GROUP,
            "gpo-other-group",
            settings=[_user_setting(GPO_OTHER_GROUP, r"HKCU\Software\C", "3")],
            delegation=[
                DelegationEntry(
                    gpo_id=GPO_OTHER_GROUP,
                    trustee="Server Admins",
                    trustee_sid=f"{DOMAIN_SID}-2002",
                    permission="Apply Group Policy",
                    allowed=True,
                )
            ],
        ),
        _gpo(
            GPO_WMI,
            "gpo-wmi",
            settings=[_user_setting(GPO_WMI, r"HKCU\Software\D", "4")],
            delegation=[
                DelegationEntry(
                    gpo_id=GPO_WMI,
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Apply Group Policy",
                    allowed=True,
                )
            ],
            wmi_filter="Some WMI Filter",
        ),
        _gpo(
            GPO_NO_DELEGATION,
            "gpo-no-delegation",
            settings=[_user_setting(GPO_NO_DELEGATION, r"HKCU\Software\E", "5")],
        ),
    ]

    som = Som(
        path=ROOT_DN,
        name="test",
        container_type="domain",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id=GPO_BROAD, order=1, enabled=True, enforced=False, target=ROOT_DN),
            SomLink(gpo_id=GPO_GROUP_APPLY, order=2, enabled=True, enforced=False, target=ROOT_DN),
            SomLink(gpo_id=GPO_OTHER_GROUP, order=3, enabled=True, enforced=False, target=ROOT_DN),
            SomLink(gpo_id=GPO_WMI, order=4, enabled=True, enforced=False, target=ROOT_DN),
            SomLink(
                gpo_id=GPO_NO_DELEGATION, order=5, enabled=True, enforced=False, target=ROOT_DN
            ),
        ],
    )
    wmi_filters = [WmiFilter(name="Some WMI Filter", query="SELECT * FROM Win32_OperatingSystem")]

    estate = Estate(
        domain="test.local",
        gpos=gpos,
        soms=[som],
        wmi_filters=wmi_filters,
        principals=principals,
        group_members=group_members,
    )
    store.save_estate(conn, estate)
    conn.close()
    return db


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    """Create a small SQLite DB with one snapshot for testing."""
    from gpo_lens import model, store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    estate = model.Estate(
        domain="test.local",
        gpos=[
            model.Gpo(
                id="aaa-bbb",
                name="Test GPO",
                domain="test.local",
                created=None,
                modified=None,
                read=None,
                computer_enabled=True,
                user_enabled=True,
                computer_ver_ds=None,
                computer_ver_sysvol=None,
                user_ver_ds=None,
                user_ver_sysvol=None,
                sddl=None,
                owner=None,
                filter_data_available=False,
                wmi_filter=None,
                sysvol_path=None,
            ),
        ],
    )
    store.save_estate(conn, estate)
    conn.close()
    return db


@pytest.fixture()
def principal_db(tmp_path: Path) -> Path:
    return _make_principal_db(tmp_path)


class TestResultantCLI:
    def test_invalid_sid_returns_1(self, principal_db: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(principal_db), "resultant", "not-a-sid"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1
        assert "Invalid SID format" in r.stderr

    def test_text_output_shows_principal(self, principal_db: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(principal_db), "resultant", USER_SID],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "jdoe" in r.stdout
        assert USER_SID in r.stdout
        assert "Effective settings" in r.stdout

    def test_text_output_shows_excluded_gpos(self, principal_db: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(principal_db), "resultant", USER_SID],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "Excluded GPOs" in r.stdout
        assert "gpo-other-group" in r.stdout

    def test_text_output_shows_settings_from_broad_gpo(self, principal_db: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(principal_db), "resultant", USER_SID],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert r"HKCU" in r.stdout
        assert "gpo-broad" in r.stdout

    def test_json_output_valid_envelope(self, principal_db: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(principal_db), "resultant", "--json", USER_SID],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert data["schema_version"] == 2
        assert data["kind"] == "resultant"
        assert data["data"]["principal_sid"] == USER_SID
        assert data["data"]["principal_name"] == "TEST\\jdoe"
        assert len(data["data"]["settings"]) > 0
        assert isinstance(data["data"]["excluded"], list)
        assert isinstance(data["data"]["excluded_settings"], list)
        assert isinstance(data["data"]["conditional_dangers"], list)
        assert isinstance(data["data"]["token_caveats"], list)
        assert isinstance(data["data"]["caveat_summary"], str)

    def test_json_settings_have_merge_mode(self, principal_db: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(principal_db), "resultant", "--json", USER_SID],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)
        for s in data["data"]["settings"]:
            assert "merge_mode" in s
            assert "overridden_by" in s
            assert "approximate" in s
            assert "conditional" in s

    def test_json_excluded_have_kind_and_reason(self, principal_db: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(principal_db), "resultant", "--json", USER_SID],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)
        excluded = data["data"]["excluded"]
        assert len(excluded) > 0
        for e in excluded:
            assert "gpo_id" in e
            assert "gpo_name" in e
            assert "kind" in e
            assert "reason" in e

    def test_unknown_principal_returns_0_with_sid_as_name(self, principal_db: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(principal_db), "resultant", "S-1-5-21-999-999-999-9999"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "s-1-5-21-999-999-999-9999" in r.stdout.lower()

    def test_with_computer_sid(self, principal_db: Path) -> None:
        comp_sid = f"{DOMAIN_SID}-5001"
        r = subprocess.run(
            GPO_LENS
            + [
                "--db",
                str(principal_db),
                "resultant",
                USER_SID,
                "--computer-sid",
                comp_sid,
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0

    def test_with_dn(self, principal_db: Path) -> None:
        r = subprocess.run(
            GPO_LENS
            + [
                "--db",
                str(principal_db),
                "resultant",
                USER_SID,
                "--dn",
                f"cn=jdoe,ou=users,{ROOT_DN}",
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0

    def test_caveat_summary_in_output(self, principal_db: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(principal_db), "resultant", USER_SID],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert (
            "resultant given collected inputs" in r.stdout.lower() or "caveat" in r.stdout.lower()
        )

    def test_wmi_excluded_gpo_listed(self, principal_db: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(principal_db), "resultant", USER_SID],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "gpo-wmi" in r.stdout

    def test_no_delegation_gpo_included_with_caveat(self, principal_db: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(principal_db), "resultant", USER_SID],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "HKCU" in r.stdout


class TestReportCLI:
    def test_report_markdown_to_stdout(self, db_path: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "report"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "Test GPO" in r.stdout or "test.local" in r.stdout

    def test_report_html_to_stdout(self, db_path: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "report", "--format", "html"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "<html" in r.stdout.lower() or "<!doctype" in r.stdout.lower()

    def test_report_to_file(self, db_path: Path, tmp_path: Path) -> None:
        out = tmp_path / "report.md"
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "report", "--output", str(out)],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert f"Report written to {out}" in r.stdout
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert len(content) > 0

    def test_report_html_to_file(self, db_path: Path, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        r = subprocess.run(
            GPO_LENS
            + [
                "--db",
                str(db_path),
                "report",
                "--format",
                "html",
                "--output",
                str(out),
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "<html" in content.lower() or "<!doctype" in content.lower()

    def test_report_refuses_json(self, db_path: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(db_path), "report"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 2
        assert "not JSON" in r.stderr or "human-readable" in r.stderr

    def test_report_baseline_not_found(self, db_path: Path) -> None:
        r = subprocess.run(
            GPO_LENS
            + [
                "--db",
                str(db_path),
                "report",
                "--baseline",
                "/nonexistent/baseline.json",
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1
        assert "Baseline file not found" in r.stderr

    def test_report_baseline_invalid_json(self, db_path: Path, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not json{{")
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "report", "--baseline", str(bad)],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1
        assert "not valid JSON" in r.stderr

    def test_report_baseline_valid(self, db_path: Path, tmp_path: Path) -> None:
        baseline = tmp_path / "baseline.json"
        baseline.write_text(
            json.dumps(
                [
                    {
                        "side": "Computer",
                        "cse": "Security",
                        "identity": "Account:LockoutBadCount",
                        "display_name": "LockoutBadCount",
                        "expected_value": "10",
                    },
                ]
            )
        )
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "report", "--baseline", str(baseline)],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0

    def test_report_since_no_db(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / "nope.db"
        r = subprocess.run(
            GPO_LENS
            + [
                "--db",
                str(nonexistent),
                "report",
                "--since",
                "1",
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 2
        assert "Database not found" in r.stderr

    def test_report_since_no_snapshots(self, tmp_path: Path) -> None:
        db = tmp_path / "empty.db"
        conn = sqlite3.connect(str(db))
        from gpo_lens.store import init_db

        init_db(conn)
        conn.close()
        r = subprocess.run(
            GPO_LENS + ["--db", str(db), "report", "--since", "1"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1
        assert "No snapshots found" in r.stderr

    def test_report_since_with_snapshots(self, db_path: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "report", "--since", "1"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0

    def test_report_max_settings(self, db_path: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "report", "--max-settings", "1"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0

    def test_report_admx_dir_without_baseline_warns(self, db_path: Path) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "report", "--admx-dir", "/some/dir"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "has no effect without --baseline" in r.stderr


class TestResultantDirectCall:
    """Direct main() calls for coverage measurement (subprocess tests don't instrument)."""

    def test_text_output(self, principal_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(principal_db), "resultant", USER_SID])
        assert ret == 0
        captured = capsys.readouterr()
        assert "jdoe" in captured.out
        assert "Effective settings" in captured.out

    def test_json_output(self, principal_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(principal_db), "resultant", "--json", USER_SID])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["kind"] == "resultant"
        assert data["data"]["principal_sid"] == USER_SID

    def test_invalid_sid(self, principal_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(principal_db), "resultant", "not-a-sid"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "Invalid SID format" in captured.err

    def test_with_computer_sid(self, principal_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        comp_sid = f"{DOMAIN_SID}-5001"
        ret = main(
            [
                "--db",
                str(principal_db),
                "resultant",
                USER_SID,
                "--computer-sid",
                comp_sid,
            ]
        )
        assert ret == 0

    def test_with_dn(self, principal_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(
            [
                "--db",
                str(principal_db),
                "resultant",
                USER_SID,
                "--dn",
                f"cn=jdoe,ou=users,{ROOT_DN}",
            ]
        )
        assert ret == 0


class TestReportDirectCall:
    """Direct main() calls for coverage measurement."""

    def test_markdown_output(self, db_path: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(db_path), "report"])
        assert ret == 0
        captured = capsys.readouterr()
        assert len(captured.out) > 0

    def test_html_output(self, db_path: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(db_path), "report", "--format", "html"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "<html" in captured.out.lower() or "<!doctype" in captured.out.lower()

    def test_output_to_file(self, db_path: Path, tmp_path: Path, capsys) -> None:
        from gpo_lens.cli import main

        out = tmp_path / "report.md"
        ret = main(["--db", str(db_path), "report", "--output", str(out)])
        assert ret == 0
        captured = capsys.readouterr()
        assert f"Report written to {out}" in captured.out
        assert out.exists()

    def test_refuses_json(self, db_path: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(db_path), "report"])
        assert ret == 2
        captured = capsys.readouterr()
        assert "not JSON" in captured.err or "human-readable" in captured.err

    def test_baseline_not_found(self, db_path: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(db_path), "report", "--baseline", "/nonexistent/baseline.json"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "Baseline file not found" in captured.err

    def test_baseline_invalid_json(self, db_path: Path, tmp_path: Path, capsys) -> None:
        from gpo_lens.cli import main

        bad = tmp_path / "bad.json"
        bad.write_text("not json{{")
        ret = main(["--db", str(db_path), "report", "--baseline", str(bad)])
        assert ret == 1
        captured = capsys.readouterr()
        assert "not valid JSON" in captured.err

    def test_baseline_valid(self, db_path: Path, tmp_path: Path, capsys) -> None:
        from gpo_lens.cli import main

        baseline = tmp_path / "baseline.json"
        baseline.write_text(
            json.dumps(
                [
                    {
                        "side": "Computer",
                        "cse": "Security",
                        "identity": "Account:LockoutBadCount",
                        "display_name": "LockoutBadCount",
                        "expected_value": "10",
                    },
                ]
            )
        )
        ret = main(["--db", str(db_path), "report", "--baseline", str(baseline)])
        assert ret == 0

    def test_since_with_snapshots(self, db_path: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(db_path), "report", "--since", "1"])
        assert ret == 0

    def test_admx_dir_without_baseline_warns(self, db_path: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(db_path), "report", "--admx-dir", "/some/dir"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "has no effect without --baseline" in captured.err
