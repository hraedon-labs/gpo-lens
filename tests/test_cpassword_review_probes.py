"""Replays of the executing-review probes against ecdc2cf (cpassword redaction).

Each test reproduces one probe from the two independent reviews (Sol B-01..B-03,
N-03; DS B1, B2, N1..N4) with the reviewer's own values. Every test failed on
ecdc2cf; they only use APIs that existed there, so they can be replayed against
that revision unchanged.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import json
import shutil
import sqlite3
import warnings
import zipfile
from contextlib import closing
from pathlib import Path

import pytest

from gpo_lens import ingest
from gpo_lens.events import append_event, query_events, verify_event_chain
from gpo_lens.model import Setting
from gpo_lens.store import init_db, load_estate, save_estate

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests/fixtures/released_databases/v1.4.0-cpassword.sqlite3"

_spec = importlib.util.spec_from_file_location(
    "cpassword_fixture_builder_probes", ROOT / "scripts" / "build_cpassword_upgrade_fixture.py"
)
assert _spec is not None and _spec.loader is not None
B = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(B)

INLINE = "PROBEcpwINLINE111"
PADDED = "PROBEcpwPADDED222"
DIRECT = "PROBEcpwDIRECT333"
SYSVOL = "PROBEcpwSYSVOL555"
SPLIT = "PROBEcpwSPLITDB"
DS_BARE = "PROBEexbare0012"
DS_SYSVOL = "PROBEexsysvol13"
DS_INLINE = "SECRETmiginl2"


def _file_hits(db: Path, probes: tuple[str, ...]) -> dict[str, list[str]]:
    hits = {}
    for suffix in ("", "-wal", "-shm", "-journal"):
        path = Path(f"{db}{suffix}")
        if path.exists():
            data = path.read_bytes()
            found = [p for p in probes if p.encode() in data]
            if found:
                hits[path.name] = found
    return hits


def _gpo(guid: str, name: str, description: str, ext: str) -> str:
    return (
        f"<GPO><Identifier><Identifier>{guid}</Identifier><Domain>LABDOMAIN</Domain>"
        f"</Identifier><Name>{name}</Name><Description>{description}</Description>"
        "<Computer><Enabled>true</Enabled><VersionDirectory>1</VersionDirectory>"
        "<VersionSysvol>1</VersionSysvol><ExtensionData><Name>Drive Maps</Name><Extension>"
        f"{ext}</Extension></ExtensionData></Computer><User><Enabled>true</Enabled>"
        "<VersionDirectory>1</VersionDirectory><VersionSysvol>1</VersionSysvol></User></GPO>"
    )


# Sol's fresh-ingest export (B-01 inline + padded copies, B-03 "Enabled").
SOL_REPORT = (
    "<GPOs>"
    + _gpo(
        "{11111111-1111-1111-1111-111111111111}",
        f"inline-copy-{INLINE}",
        f"&lt;Properties cpassword=&quot;{INLINE}&quot;/&gt;",
        '<Drives clsid="x"><Drive uid="1" name="inline"><Properties path="x"/></Drive></Drives>',
    )
    + _gpo(
        "{22222222-2222-2222-2222-222222222222}",
        f"padded-copy-{PADDED}",
        "",
        f'<Drives clsid="x"><Drive uid="2" name="padded"><Properties path="x" '
        f'cpassword="  {PADDED}  "/></Drive></Drives>',
    )
    + _gpo(
        "{33333333-3333-3333-3333-333333333333}",
        "Enabled Policy",
        "Legitimate Enabled description",
        '<Drives clsid="x"><Drive uid="3" name="common"><Properties path="Enabled share" '
        'cpassword="Enabled"/></Drive></Drives>',
    )
    + "</GPOs>"
)


def _sol_gpos(kind: str, tmp_path: Path) -> list:
    if kind == "directory":
        (tmp_path / "export").mkdir()
        (tmp_path / "export" / "AllGPOs.xml").write_text(SOL_REPORT, encoding="utf-8")
        return ingest.load_estate(tmp_path / "export").gpos
    if kind == "single_path":
        (tmp_path / "single.xml").write_text(SOL_REPORT, encoding="utf-8")
        return ingest.parse_report(tmp_path / "single.xml")
    if kind == "single_bytes":
        return ingest.parse_report_xml(SOL_REPORT.encode())
    with zipfile.ZipFile(tmp_path / "baseline.zip", "w") as archive:
        archive.writestr("GPOs/probe/gpreport.xml", SOL_REPORT)
    return ingest.load_baseline_from_zip(tmp_path / "baseline.zip")


@pytest.mark.parametrize("kind", ["directory", "single_path", "single_bytes", "baseline_zip"])
def test_sol_b01_b03_every_parse_path(kind: str, tmp_path: Path) -> None:
    gpos = _sol_gpos(kind, tmp_path)
    model = json.dumps([dataclasses.asdict(g) for g in gpos], default=str)
    assert INLINE not in model and PADDED not in model
    by_id = {g.id: g for g in gpos}
    # B-03: a short, word-like cpassword must not rewrite unrelated truth.
    common = by_id["33333333333333333333333333333333"]
    assert (common.name, common.description) == (
        "Enabled Policy",
        "Legitimate Enabled description",
    )


def test_sol_b01_collector_zip_ingest_bytes_and_exports(tmp_path: Path, capsys) -> None:
    from gpo_lens.cli import main
    from gpo_lens.safe_output import safe_data

    with zipfile.ZipFile(tmp_path / "collector.zip", "w") as archive:
        archive.writestr("AllGPOs.xml", SOL_REPORT)
    db = tmp_path / "collector.sqlite3"
    assert main(["--db", str(db), "ingest", str(tmp_path / "collector.zip")]) in (0, None)
    assert _file_hits(db, (INLINE, PADDED)) == {}
    outputs = []
    for argv in (
        ["export", "dossier", "--format", "md", "--gpo-id", "1" * 32],
        ["export", "dossier", "--format", "csv", "--gpo-id", "1" * 32],
        ["report", "--format", "html"],
    ):
        assert main(["--db", str(db), *argv]) in (0, None)
        outputs.append(capsys.readouterr().out)
    with closing(sqlite3.connect(db)) as conn:
        outputs.append(str(safe_data(load_estate(conn).gpo_by_id("1" * 32))))
    joined = "\n".join(outputs)
    assert INLINE not in joined and PADDED not in joined
    assert "Enabled Policy" in joined


def test_sol_b01_direct_save_chases_sibling_settings_and_gpo_name(tmp_path: Path) -> None:
    (tmp_path / "e").mkdir()
    (tmp_path / "e" / "AllGPOs.xml").write_text(
        "<GPOs>" + _gpo("{44444444-4444-4444-4444-444444444444}", "source-gpo", "", "") + "</GPOs>",
        encoding="utf-8",
    )
    estate = ingest.load_estate(tmp_path / "e")
    gpo = estate.gpos[0]
    gpo.name = f"gpo-copy-{DIRECT}"
    gpo.settings.append(
        Setting(gpo.id, "Computer", "Synthetic", "source", "source", "x",
                {"@attr": {"cpassword": DIRECT}}, False)
    )  # fmt: skip
    gpo.settings.append(
        Setting(gpo.id, "Computer", "Synthetic", "copy", "copy", f"unlabelled copy {DIRECT}",
                {"note": f"unlabelled copy {DIRECT}"}, False)
    )  # fmt: skip
    db = tmp_path / "direct.sqlite3"
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        save_estate(conn, estate)
        assert _file_hits(db, (DIRECT,)) == {}
    assert _file_hits(db, (DIRECT,)) == {}


def _v140_copy(tmp_path: Path, name: str) -> Path:
    db = tmp_path / name
    shutil.copyfile(FIXTURE, db)
    return db


def test_sol_b01_migration_chases_inline_padded_and_event_copies(tmp_path: Path) -> None:
    from gpo_lens.cli import main

    db = _v140_copy(tmp_path, "migration.sqlite3")
    with closing(sqlite3.connect(db)) as conn:
        gpo = conn.execute("SELECT id FROM gpo LIMIT 1").fetchone()[0]
        for identity, raw in (
            ("inline", {"note": f'<Properties cpassword="{INLINE}"/>'}),
            ("padded", {"@attr": {"cpassword": f"  {PADDED}  "}}),
        ):
            value = INLINE if identity == "inline" else PADDED
            conn.execute(
                "INSERT INTO setting VALUES (2, ?, 'Computer', 'Synthetic', ?, ?, ?, ?, 0, "
                "'normal')",
                (gpo, identity, identity, f"unlabelled copy {value}", json.dumps(raw)),
            )
        append_event(conn, "probe.copy", {"copy": INLINE})
        append_event(conn, "probe.copy", {"copy": PADDED})
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 11
        assert verify_event_chain(conn) == (True, [])
        live = str(conn.execute("SELECT * FROM setting").fetchall())
        live += str(query_events(conn))
        assert INLINE not in live and PADDED not in live
    assert _file_hits(db, (INLINE, PADDED)) == {}
    ndjson = tmp_path / "events.ndjson"
    assert main(["--db", str(db), "events-export", "--ndjson", str(ndjson)]) in (0, None)
    assert INLINE not in ndjson.read_text() and PADDED not in ndjson.read_text()


def test_sol_b01_split_inline_across_nodes(tmp_path: Path) -> None:
    import defusedxml.ElementTree as ET

    from gpo_lens.cli import main
    from gpo_lens.redaction import redact_element_tree

    root = ET.fromstring('<x>cpass<part/>word="PROBEcpwSPLIT"</x>')
    redact_element_tree(root)
    assert "PROBEcpwSPLIT" not in "".join(root.itertext())

    report = (
        "<GPOs>"
        + _gpo(
            "{55555555-5555-5555-5555-555555555555}",
            "split",
            "",
            '<Drives clsid="x"><Drive uid="1" name="x"><Properties>cpass'
            f'<Span>word="{SPLIT}"</Span></Properties></Drive></Drives>',
        )
        + "</GPOs>"
    )
    (tmp_path / "e").mkdir()
    (tmp_path / "e" / "AllGPOs.xml").write_text(report, encoding="utf-8")
    db = tmp_path / "split-inline.sqlite3"
    assert main(["--db", str(db), "ingest", str(tmp_path / "e")]) in (0, None)
    with closing(sqlite3.connect(db)) as conn:
        assert SPLIT not in str(conn.execute("SELECT raw FROM setting").fetchall())
        assert _file_hits(db, (SPLIT,)) == {}
    assert _file_hits(db, (SPLIT,)) == {}


def _probe_export(tmp_path: Path, sysvol_value: str) -> Path:
    export = B.build_probe_export(tmp_path / "export")
    groups = export / "SYSVOL-Policies" / B._SYSVOL_GROUPS
    groups.write_text(groups.read_text().replace(B.SYSVOL_PROBE, sysvol_value), encoding="utf-8")
    return export


def test_sol_b01_sysvol_value_copied_into_gpo_name(tmp_path: Path, capsys) -> None:
    from gpo_lens.cli import main

    export = _probe_export(tmp_path, SYSVOL)
    report = export / "AllGPOs.xml"
    report.write_text(
        report.read_text().replace(
            "<Name>golden-v2-task</Name>", f"<Name>golden-v2-task-{SYSVOL}</Name>"
        ),
        encoding="utf-8",
    )
    db = tmp_path / "sysvol-copy.sqlite3"
    assert main(["--db", str(db), "ingest", str(export)]) in (0, None)
    with closing(sqlite3.connect(db)) as conn:
        names = [r[0] for r in conn.execute("SELECT name FROM gpo")]
        assert "golden-v2-task-[redacted cpassword]" in names
        assert _file_hits(db, (SYSVOL,)) == {}
    assert _file_hits(db, (SYSVOL,)) == {}


def test_ds_b2_sysvol_value_copied_into_gpo_description(tmp_path: Path) -> None:
    export = _probe_export(tmp_path, DS_SYSVOL)
    report = export / "AllGPOs.xml"
    old = "Domain baseline with embedded local-admin password (MS14-025)."
    report.write_text(
        report.read_text().replace(old, f"{old} secret {DS_SYSVOL}"), encoding="utf-8"
    )
    estate = ingest.load_estate(export)
    assert not any(g.description and DS_SYSVOL in g.description for g in estate.gpos)
    db = tmp_path / "desc_leak.sqlite3"
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        save_estate(conn, estate)
    assert _file_hits(db, (DS_SYSVOL,)) == {}


def test_ds_b1_inline_value_copied_under_another_name(tmp_path: Path) -> None:
    export = B.build_probe_export(tmp_path / "export")
    report = export / "AllGPOs.xml"
    ext = (
        "<ExtensionData><Name>Exotic Bare</Name><Extension>"
        '<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">'
        '<Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="bare" '
        'uid="{60000000-0000-0000-0000-000000000009}">'
        f'<Properties action="U" path="\\\\x\\bare" name="{DS_BARE}" '
        f'description="&lt;Properties cpassword=&quot;{DS_BARE}&quot;/&gt;"/>'
        "</Drive></Drives></Extension></ExtensionData>"
    )
    xml = report.read_text()
    at = xml.index("</Computer>", xml.index("<Name>golden-v2-task</Name>"))
    report.write_text(xml[:at] + ext + xml[at:], encoding="utf-8")
    for gpos in (ingest.parse_report(report), ingest.parse_report_xml(report.read_bytes())):
        assert DS_BARE not in json.dumps([dataclasses.asdict(g) for g in gpos], default=str)
    db = tmp_path / "cli_exotic.sqlite3"
    estate = ingest.load_estate(export)
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        save_estate(conn, estate)
    assert _file_hits(db, (DS_BARE,)) == {}


def test_ds_b1_migration_inline_value_copied_in_same_row(tmp_path: Path) -> None:
    # DS's probe put an unrelated string (never labelled) in ``name``; that one
    # is correctly kept. Its intent, a copy of the inline value, is replayed.
    db = _v140_copy(tmp_path, "inline_bare.sqlite3")
    with closing(sqlite3.connect(db)) as conn:
        conn.execute(
            "UPDATE setting SET raw = ?, display_value = ? WHERE rowid = 15",
            (
                json.dumps(
                    {
                        "tag": "Properties",
                        "@attr": {"name": DS_INLINE, "description": f'cpassword="{DS_INLINE}"'},
                    },
                    sort_keys=True,
                ),
                "prefix " + DS_INLINE,
            ),
        )
        conn.commit()
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
    assert _file_hits(db, (DS_INLINE,)) == {}


def test_ds_n2_migration_keeps_pre_existing_tamper_visible(tmp_path: Path) -> None:
    db = _v140_copy(tmp_path, "tamper.sqlite3")
    with closing(sqlite3.connect(db)) as conn:
        conn.execute(
            "UPDATE events SET payload = ? WHERE id = 4",
            (json.dumps({"deltas": [{"tampered": True}]}),),
        )
        conn.commit()
        assert verify_event_chain(conn) == (False, [4])
    with closing(sqlite3.connect(db)) as conn, warnings.catch_warnings():
        warnings.simplefilter("ignore")
        init_db(conn)
        assert verify_event_chain(conn) == (False, [4])
        scrub = [e for e in query_events(conn) if e["event_type"] == "maintenance.cpassword_scrub"]
        assert scrub[0]["payload"]["pre_existing_broken_event_ids"] == [4]
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 11


def test_ds_n3_read_only_init_on_current_schema(tmp_path: Path) -> None:
    db = _v140_copy(tmp_path, "ro.sqlite3")
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
    with closing(sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True)) as conn:
        init_db(conn)  # no write is needed on an up-to-date database
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 11


def test_ds_n4_fresh_database_is_not_vacuumed(tmp_path: Path) -> None:
    statements: list[str] = []
    with closing(sqlite3.connect(tmp_path / "fresh.sqlite3")) as conn:
        conn.set_trace_callback(statements.append)
        init_db(conn)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 11
    assert not any(s.strip().upper() == "VACUUM" for s in statements)


def test_ds_n1_short_value_cannot_erase_gpo_guids(tmp_path: Path) -> None:
    export = B.build_probe_export(tmp_path / "export")
    report = export / "AllGPOs.xml"
    ext = (
        "<ExtensionData><Name>Over</Name><Extension>"
        '<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">'
        '<Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="o" '
        'uid="{70000000-0000-0000-0000-000000000001}">'
        '<Properties action="U" path="x" cpassword="AAAAAA"/>'
        "</Drive></Drives></Extension></ExtensionData>"
    )
    xml = report.read_text()
    at = xml.index("</Computer>", xml.index("<Name>golden-v2-task</Name>"))
    report.write_text(xml[:at] + ext + xml[at:], encoding="utf-8")
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # "no valid identifier" would be a warning
        assert len(ingest.load_estate(export).gpos) == 6


def _fixture_with_short_value_and_event(tmp_path: Path, name: str, value: str) -> Path:
    db = _v140_copy(tmp_path, name)
    with closing(sqlite3.connect(db)) as conn:
        gpo = conn.execute("SELECT id FROM gpo LIMIT 1").fetchone()[0]
        conn.execute(
            "INSERT INTO setting VALUES (2, ?, 'Computer', 'Synthetic', 'v', 'v', 'v', ?, 0, "
            "'normal')",
            (gpo, json.dumps({"@attr": {"cpassword": value}})),
        )
        append_event(conn, f"ingest.{value}", {"count": 1})
        conn.commit()
    return db


def test_sol_b02_short_value_never_touches_event_types(tmp_path: Path) -> None:
    db = _fixture_with_short_value_and_event(tmp_path, "event-integrity.sqlite3", "summary")
    with closing(sqlite3.connect(db)) as conn:
        before = [e["event_type"] for e in query_events(conn)]
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 11
        assert verify_event_chain(conn) == (True, [])
        after = [e["event_type"] for e in query_events(conn)]
        assert after[: len(before)] == before  # no event type rewritten


def test_sol_b02_copy_in_hashed_event_type_refuses_unchanged(tmp_path: Path) -> None:
    db = _fixture_with_short_value_and_event(tmp_path, "event-type.sqlite3", "PROBEcpwEVENT444")
    before = db.read_bytes()
    with closing(sqlite3.connect(db)) as conn:
        with pytest.raises(ValueError, match=r"events\.event_type"):
            init_db(conn)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 10
        assert verify_event_chain(conn) == (True, [])
        assert "ingest.PROBEcpwEVENT444" in [e["event_type"] for e in query_events(conn)]
    assert db.read_bytes() == before


def test_sol_n03_fixture_readme_has_no_trailing_blank_line() -> None:
    text = (ROOT / "tests/fixtures/released_databases/README.md").read_text()
    assert text.endswith("\n") and not text.endswith("\n\n")


# --- Round 2 (reviews of ca5fe76) ------------------------------------------------

import base64  # noqa: E402

URLSAFE = base64.urlsafe_b64encode(bytes([251, 255, 190, 237]) * 4).decode().rstrip("=")


def _drives(values: list[tuple[str, str]]) -> str:
    return (
        '<Drives clsid="x">'
        + "".join(
            f'<Drive uid="{{00000000-0000-0000-0000-{i:012d}}}" name="{name}">'
            f'<Properties action="U" path="\\\\server\\{name}" cpassword="{value}"/></Drive>'
            for i, (name, value) in enumerate(values, 1)
        )
        + "</Drives>"
    )


def test_sol_r2_b01_whitespace_split_copies_fresh_ingest_and_outputs(
    tmp_path: Path, capsys
) -> None:
    from gpo_lens.cli import main
    from gpo_lens.safe_output import safe_data

    compact = base64.b64encode(b"PROBEcpwSplitXXX").decode()
    mid = len(compact) // 2
    same = compact[:mid] + "\n" + compact[mid:]
    other = compact[:mid] + "\t" + compact[mid:]
    short12 = "PROBEcpw12A1"
    description = (
        f"p=({short12}), u=__{short12}__ | split-compact={compact} | "
        f"split-same={same} | split-other={other} | url={URLSAFE}x"
    )
    report = (
        "<GPOs>"
        + _gpo(
            "{91919191-9191-9191-9191-919191919191}",
            "boundary",
            description.replace("\n", "&#10;").replace("\t", "&#9;"),
            _drives(
                [
                    ("split", compact[:mid] + "&#10;" + compact[mid:]),
                    ("short12", short12),
                    ("url", URLSAFE),
                ]
            ),
        )
        + "</GPOs>"
    )
    (tmp_path / "e").mkdir()
    (tmp_path / "e" / "AllGPOs.xml").write_text(report, encoding="utf-8")
    db = tmp_path / "fresh.sqlite3"
    assert main(["--db", str(db), "ingest", str(tmp_path / "e")]) in (0, None)
    capsys.readouterr()
    needles = (compact, same, other, URLSAFE, f"({short12})", f"__{short12}__")
    assert _file_hits(db, needles) == {}
    outputs = []
    for argv in (
        ["export", "dossier", "--format", "md", "--gpo-id", "91" * 16],
        ["export", "dossier", "--format", "csv", "--gpo-id", "91" * 16],
        ["report", "--format", "html"],
    ):
        assert main(["--db", str(db), *argv]) in (0, None)
        outputs.append(capsys.readouterr().out)
    with closing(sqlite3.connect(db)) as conn:
        outputs.append(str(safe_data(load_estate(conn).gpo_by_id("91" * 16))))
    text = "\n".join(outputs)
    for needle in (compact, same, other, URLSAFE):
        assert needle not in text and needle.replace("\n", "\\n") not in text


def test_sol_r2_b01_whitespace_split_copies_migration(tmp_path: Path) -> None:
    compact = base64.b64encode(b"PROBEcpwMigrateX").decode()
    mid = len(compact) // 2
    newline = compact[:mid] + "\n" + compact[mid:]
    tab = compact[:mid] + "\t" + compact[mid:]
    db = _v140_copy(tmp_path, "migration-whitespace.sqlite3")
    with closing(sqlite3.connect(db)) as conn:
        gpo_id = conn.execute("SELECT id FROM gpo LIMIT 1").fetchone()[0]
        conn.execute(
            "INSERT INTO setting VALUES (2, ?, 'Computer', 'Synthetic', 'split', 'split', "
            "'split', ?, 0, 'normal')",
            (gpo_id, json.dumps({"cpassword": newline})),
        )
        conn.execute(
            "UPDATE gpo SET description = ? WHERE rowid = (SELECT rowid FROM gpo LIMIT 1)",
            (f"same={newline}; other={tab}; compact={compact}",),
        )
        conn.commit()
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 11
        assert _file_hits(db, (compact, newline, tab)) == {}
    assert _file_hits(db, (compact, newline, tab)) == {}


def _mixed_raw(value: str) -> dict:
    return {
        "tag": "Properties",
        "text": "cpass",
        "children": [{"tag": "Span", "text": f'word="{value}"'}],
    }


def test_sol_r2_b02_mixed_content_setting_direct_save(tmp_path: Path) -> None:
    compact = base64.b64encode(b"PROBEcpwDirectXX").decode()
    parsed = ingest.parse_report_xml(
        (
            "<GPOs>" + _gpo("{94949494-9494-9494-9494-949494949494}", "m", "safe", "") + "</GPOs>"
        ).encode()
    )
    parsed[0].settings.append(
        Setting(parsed[0].id, "Computer", "Synthetic", "mixed", "mixed", f"copy={compact}",
                _mixed_raw(compact), False)
    )  # fmt: skip
    from gpo_lens.model import Estate

    db = tmp_path / "direct-save-mixed.sqlite3"
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        save_estate(conn, Estate(domain="LABDOMAIN", gpos=parsed))
        conn.commit()
        assert _file_hits(db, (compact,)) == {}
    assert _file_hits(db, (compact,)) == {}


def test_sol_r2_b02_mixed_content_setting_migration(tmp_path: Path) -> None:
    compact = base64.b64encode(b"PROBEcpwMixedXXX").decode()
    db = _v140_copy(tmp_path, "migration-mixed-json.sqlite3")
    with closing(sqlite3.connect(db)) as conn:
        gpo_id = conn.execute("SELECT id FROM gpo LIMIT 1").fetchone()[0]
        conn.execute(
            "INSERT INTO setting VALUES (2, ?, 'Computer', 'Synthetic', 'mixed', 'mixed', ?, "
            "?, 0, 'normal')",
            (gpo_id, f"copy={compact}", json.dumps(_mixed_raw(compact))),
        )
        conn.commit()
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 11
        raw = json.loads(
            conn.execute("SELECT raw FROM setting WHERE identity = 'mixed'").fetchone()[0]
        )
        assert raw["children"][0]["tag"] == "Span"  # structure kept (DS NB-3)
    assert _file_hits(db, (compact,)) == {}


def test_sol_r2_b03_baseline_zip_cross_report_copy(tmp_path: Path) -> None:
    from gpo_lens.model import Estate

    compact = base64.b64encode(b"PROBEcpwBaseline").decode()
    archive = tmp_path / "baseline-cross-report.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(
            "GPOs/source/gpreport.xml",
            _gpo("{95959595-9595-9595-9595-959595959595}", "source", "safe",
                 _drives([("source", compact)])),
        )  # fmt: skip
        output.writestr(
            "GPOs/copy/gpreport.xml",
            _gpo("{96969696-9696-9696-9696-969696969696}", "copy", f"copy={compact}", ""),
        )
    gpos = ingest.load_baseline_from_zip(archive)
    assert compact not in json.dumps([dataclasses.asdict(g) for g in gpos], default=str)
    db = tmp_path / "baseline-cross-report.sqlite3"
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        save_estate(conn, Estate(domain="LABDOMAIN", gpos=gpos))
        conn.commit()
    assert _file_hits(db, (compact,)) == {}


def test_ds_r2_b1_urlsafe_embedded_copy_is_chased() -> None:
    from gpo_lens.redaction import Chaser

    chaser = Chaser([URLSAFE])
    for text in (f"a-{URLSAFE}-b", f"a-{URLSAFE}x-b", f"a-x{URLSAFE}-b"):
        assert URLSAFE not in chaser.sub(text), text


def test_ds_r2_b1_urlsafe_copy_fresh_ingest(tmp_path: Path) -> None:
    report = (
        "<GPOs>"
        + _gpo("{97979797-9797-9797-9797-979797979797}", "url", f"adjacent {URLSAFE}x inside",
               _drives([("url", URLSAFE)]))
        + "</GPOs>"
    )  # fmt: skip
    (tmp_path / "e").mkdir()
    (tmp_path / "e" / "AllGPOs.xml").write_text(report, encoding="utf-8")
    estate = ingest.load_estate(tmp_path / "e")
    assert URLSAFE not in json.dumps(dataclasses.asdict(estate), default=str)
    db = tmp_path / "fresh.sqlite3"
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        save_estate(conn, estate)
        conn.commit()
    assert _file_hits(db, (URLSAFE,)) == {}


def test_ds_r2_b1_urlsafe_copy_two_pass_migration_never_stamps_dirty(tmp_path: Path) -> None:
    db = _v140_copy(tmp_path, "twopass.sqlite3")
    with closing(sqlite3.connect(db)) as conn:
        gpo_id = conn.execute("SELECT id FROM gpo LIMIT 1").fetchone()[0]
        conn.execute(
            "INSERT INTO setting VALUES (2, ?, 'Computer', 'Synthetic', 'l', 'l', 'l', ?, 0, "
            "'normal')",
            (gpo_id, json.dumps({"@attr": {"cpassword": URLSAFE}})),
        )
        conn.execute(
            "UPDATE gpo SET description = ? WHERE id = ?", (f"adjacent {URLSAFE}x inside", gpo_id)
        )
        conn.commit()
    for _ in range(3):
        with closing(sqlite3.connect(db)) as conn, warnings.catch_warnings():
            warnings.simplefilter("ignore")
            init_db(conn)
            version = conn.execute("PRAGMA user_version").fetchone()[0]
        in_bytes = URLSAFE.encode() in db.read_bytes()
        assert not (version == 11 and in_bytes)
        assert not in_bytes


def test_ds_r2_b1_unverifiable_scrub_rolls_back_on_every_open(tmp_path: Path, monkeypatch) -> None:
    """A chase miss must never be stamped: verification rolls the scrub back."""
    from gpo_lens import redaction

    db = _v140_copy(tmp_path, "miss.sqlite3")
    monkeypatch.setattr(redaction.Chaser, "sub", lambda self, text: text)
    for _ in range(2):
        with closing(sqlite3.connect(db)) as conn, warnings.catch_warnings():
            warnings.simplefilter("ignore")
            init_db(conn)
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 10
            # The labelled source is still there to rediscover next time.
            assert "PROBEcpwDSP890" in str(conn.execute("SELECT raw FROM setting").fetchall())
    monkeypatch.undo()
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 11
    assert _file_hits(db, ("PROBEcpwDSP890", "PROBEcpwZZ123")) == {}


def test_ds_r2_nb3_mixed_content_keeps_child_elements() -> None:
    import defusedxml.ElementTree as ET

    from gpo_lens.redaction import redact_element_tree

    root = ET.fromstring(
        '<Properties>cpass<Span>word="PROBEcpwKEEP1234"</Span>tail<Keep a="1"/></Properties>'
    )
    redact_element_tree(root)
    assert [child.tag for child in root] == ["Span", "Keep"]
    assert "PROBEcpwKEEP1234" not in "".join(root.itertext())


def test_ds_r2_nb7_bare_value_trailing_punctuation(tmp_path: Path) -> None:
    value = "PROBEcpwPUNCT123"
    report = (
        "<GPOs>"
        + _gpo("{98989898-9898-9898-9898-989898989898}", f"x-{value}",
               f"note cpassword={value}. end", "")
        + "</GPOs>"
    )  # fmt: skip
    gpos = ingest.parse_report_xml(report.encode())
    assert value not in json.dumps([dataclasses.asdict(g) for g in gpos], default=str)
    assert gpos[0].description.endswith(". end")
