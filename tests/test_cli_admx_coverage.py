"""Direct-call CLI tests for the admx-coverage subcommand."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from gpo_lens.model import Estate, Gpo, Setting

GPO_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
GPO_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _make_gpo(gpo_id: str, name: str, settings: list[Setting] | None = None) -> Gpo:
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
        wmi_filter=None,
        sysvol_path=None,
        settings=settings or [],
    )


def _make_registry_setting(
    gpo_id: str,
    side: str,
    identity: str,
    value: str = "1",
    display_name: str = "",
) -> Setting:
    parts = identity.split(":", 1)
    raw = {
        "@attr": {
            "key": parts[0],
            "name": parts[1] if len(parts) > 1 else "",
        },
        "children": [],
    }
    return Setting(
        gpo_id=gpo_id,
        side=side,
        cse="Registry",
        identity=identity,
        display_name=display_name or identity,
        display_value=value,
        raw=raw,
        from_disabled_side=False,
        source_state="normal",
    )


def _make_db(tmp_path: Path) -> Path:
    from gpo_lens import store

    db = tmp_path / "admx.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    key_a = "HKLM\\SOFTWARE\\Policies\\Example\\PolicyA"
    key_b = "HKCU\\SOFTWARE\\Policies\\Example\\PolicyB"
    gap = "HKLM\\SOFTWARE\\Policies\\Example\\GapValue"

    settings_a = [
        _make_registry_setting(GPO_A, "Computer", f"{key_a}:value_a", display_name="Value A"),
    ]
    settings_b = [
        _make_registry_setting(GPO_B, "User", f"{key_b}:value_b", display_name="Value B"),
    ]
    settings_gap = [
        _make_registry_setting(GPO_A, "Computer", f"{gap}:data", display_name="Gap Data"),
    ]
    gpos = [
        _make_gpo(GPO_A, "gpo-a", settings_a + settings_gap),
        _make_gpo(GPO_B, "gpo-b", settings_b),
    ]
    estate = Estate(domain="test.local", gpos=gpos)
    store.save_estate(conn, estate)
    conn.close()
    return db


class FakeAdmxPolicy:
    def __init__(
        self,
        name: str,
        display_name: str,
        class_scope: str,
        key: str,
        value_name: str,
    ):
        self.name = name
        self.display_name = display_name
        self.class_scope = class_scope
        self.key = key
        self.value_name = value_name


class FakeAdmxResolver:
    def __init__(self):
        self.policies = [
            FakeAdmxPolicy(
                "PolA",
                "Policy A",
                "Machine",
                "HKLM\\SOFTWARE\\Policies\\Example\\PolicyA",
                "value_a",
            ),
            FakeAdmxPolicy(
                "PolB",
                "Policy B",
                "User",
                "HKCU\\SOFTWARE\\Policies\\Example\\PolicyB",
                "value_b",
            ),
            FakeAdmxPolicy(
                "PolC",
                "Policy C",
                "Machine",
                "HKLM\\SOFTWARE\\Policies\\Example\\PolicyC",
                "value_c",
            ),
        ]

    def resolve_display_name(self, identity: str) -> str | None:
        if "PolicyA" in identity or "value_a" in identity:
            return "Policy A"
        if "PolicyB" in identity or "value_b" in identity:
            return "Policy B"
        return None


@pytest.fixture
def admx_db(tmp_path: Path) -> Path:
    return _make_db(tmp_path)


@pytest.fixture
def fake_admx():
    return FakeAdmxResolver()


class TestAdmxCoverageDirectCall:
    def test_text_output(self, admx_db: Path, fake_admx, monkeypatch, capsys) -> None:
        from gpo_lens.cli import _settings, main

        monkeypatch.setattr(_settings, "_get_admx", lambda _args: fake_admx)

        ret = main(["--db", str(admx_db), "admx-coverage"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "ADMX Coverage" in captured.out
        assert "Total policies: 3" in captured.out
        assert "Referenced:     2" in captured.out
        assert "Unreferenced:   1" in captured.out
        assert "Gap settings:   1" in captured.out
        assert "--- Gap Settings" in captured.out
        assert "--- Referenced Policies" in captured.out
        assert "gpo-a" in captured.out
        assert "gpo-b" in captured.out

    def test_text_output_no_admx(self, admx_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(admx_db), "admx-coverage"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "ADMX Coverage" in captured.out
        assert "Total policies: 0" in captured.out
        assert "Gap settings:   3" in captured.out

    def test_json_output(self, admx_db: Path, fake_admx, monkeypatch, capsys) -> None:
        from gpo_lens.cli import _settings, main

        monkeypatch.setattr(_settings, "_get_admx", lambda _args: fake_admx)

        ret = main(["--json", "--db", str(admx_db), "admx-coverage"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["kind"] == "admx-coverage"
        summary = data["data"]["summary"]
        assert summary["total_policies"] == 3
        assert summary["referenced_policies"] == 2
        assert summary["unreferenced_policies"] == 1
        assert summary["gap_count"] == 1

        referenced = data["data"]["referenced"]
        assert len(referenced) == 2
        assert any(
            e["policy_name"] == "PolA" and e["referenced_gpos"] == "gpo-a" for e in referenced
        )
        assert any(
            e["policy_name"] == "PolB" and e["referenced_gpos"] == "gpo-b" for e in referenced
        )

        unreferenced = data["data"]["unreferenced"]
        assert len(unreferenced) == 1
        assert unreferenced[0]["policy_name"] == "PolC"
        assert unreferenced[0]["is_referenced"] is False

        gaps = data["data"]["gaps"]
        assert len(gaps) == 1
        assert gaps[0]["registry_key"] == "HKLM\\SOFTWARE\\Policies\\Example\\GapValue"
        assert gaps[0]["value_name"] == "data"


@pytest.mark.parametrize("command", ["admx-gaps", "danger", "admx-coverage"])
@pytest.mark.parametrize("as_json", [False, True])
def test_cli_poisoned_templates(admx_db, tmp_path, capsys, command, as_json):
    from gpo_lens.cli import main

    pd_dir = tmp_path / "PolicyDefinitions"
    pd_dir.mkdir()
    (pd_dir / "poison.admx").write_bytes(b'<?xml version="1.0" encoding="unicode"?><x>\xff</x>')
    args = ["--db", str(admx_db), command, "--admx-dir", str(pd_dir)]
    if as_json:
        args.insert(0, "--json")
    assert main(args) == 0
    captured = capsys.readouterr()
    assert "1 template files could not be read" in captured.err
    if as_json:
        data = json.loads(captured.out)
        if command == "admx-coverage":
            assert data["data"]["summary"]["unreadable_file_count"] == 1
            assert data["data"]["skipped_files"] == [
                {"filename": "poison.admx", "reason_class": "UnicodeDecodeError"}
            ]
