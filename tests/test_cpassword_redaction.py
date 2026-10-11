"""GPP cpassword values never reach the database (schema v11).

Fresh ingest redacts the report tree before parsing; opening a database written
by v1.4.0 scrubs every stored copy and purges the old bytes from free pages and
the WAL. Probes and the v1.4.0 fixture come from
``scripts/build_cpassword_upgrade_fixture.py`` (real released-code output).
"""

from __future__ import annotations

import dataclasses
import importlib.util
import json
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from gpo_lens import ingest
from gpo_lens.events import query_events, verify_event_chain
from gpo_lens.queries import cpassword_scan, estate_doctor
from gpo_lens.redaction import (
    CPASSWORD_FINDING_DETAIL,
    CPASSWORD_MARKER,
    Chaser,
    redact_structure,
    redact_text,
)
from gpo_lens.store import (
    CURRENT_SCHEMA_VERSION,
    init_db,
    list_snapshots,
    load_estate,
    save_estate,
)
from gpo_lens.trend import compute_trend

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests/fixtures/released_databases/v1.4.0-cpassword.sqlite3"
ROTATED_SYSVOL_PROBE = "WVUTrotatedSYSVOL4567"


def _load_builder():
    path = ROOT / "scripts" / "build_cpassword_upgrade_fixture.py"
    spec = importlib.util.spec_from_file_location("cpassword_fixture_builder", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


B = _load_builder()
SECRETS = (*B.ALL_PROBES, B.SYSVOL_PREFIX, ROTATED_SYSVOL_PROBE, ROTATED_SYSVOL_PROBE[:4])


def _leaks_in(data: bytes | str) -> list[str]:
    if isinstance(data, str):
        return [s for s in SECRETS if s in data]
    return [s for s in SECRETS if s.encode() in data or s.encode("utf-16-le") in data]


def _file_leaks(db: Path) -> dict[str, list[str]]:
    """Probe strings in the raw bytes of the database and its side files."""
    found = {}
    for suffix in ("", "-wal", "-shm", "-journal"):
        path = Path(f"{db}{suffix}")
        if path.exists():
            hits = _leaks_in(path.read_bytes())
            if hits:
                found[path.name] = hits
    return found


def _cli(capsys, *argv: str) -> str:
    from gpo_lens.cli import main

    assert main(list(argv)) in (0, None)
    return capsys.readouterr().out


def _ingest_stages(tmp_path: Path, capsys) -> tuple[Path, Path]:
    """Two CLI ingests; the second adds the display-value probe (an event delta).

    A probe that merely changes between snapshots writes no event any more:
    both sides are the marker, so the diff sees no change (see
    ``test_presence_is_tracked_without_a_fingerprint``).
    """
    db = tmp_path / "fresh.sqlite3"
    first = B.build_probe_export(tmp_path / "s1", display_probe=None)
    second = B.build_probe_export(tmp_path / "s2", display_probe=B.DISPLAY_PROBES[1])
    _cli(capsys, "--db", str(db), "ingest", "--diff-latest", str(first))
    _cli(capsys, "--db", str(db), "ingest", "--diff-latest", str(second))
    return db, second


# --- Fresh ingest ------------------------------------------------------------


def test_report_probes_are_redacted_before_the_model_is_built(tmp_path: Path) -> None:
    estate = ingest.load_estate(B.build_probe_export(tmp_path / "export"))
    model = json.dumps(
        [dataclasses.asdict(s) for g in estate.gpos for s in g.settings]
        + [g.description for g in estate.gpos]
    )
    assert _leaks_in(model) == []
    settings = {s.identity: s for g in estate.gpos for s in g.settings}
    # One marker per planted shape: GPP attribute in four element types and
    # four casings, a <cpassword> child element and an escaped XML fragment.
    for identity, attribute in (
        ("User:LabAdmin", "cpassword"),
        ("NTService:LabSvc", "CPassword"),
        ("TaskV2:LabTask", "CPASSWORD"),
        ("DataSource:LabDsn", "cPassword"),
        ("Drive:L:", "cpassword"),
    ):
        props = next(c for c in settings[identity].raw["children"] if c["tag"] == "Properties")
        assert props["@attr"][attribute] == CPASSWORD_MARKER, identity
    drive = settings["Drive:L:"].raw
    assert {"tag": "cpassword", "text": CPASSWORD_MARKER} in drive["children"]
    props = next(c for c in drive["children"] if c["tag"] == "Properties")
    assert props["@attr"]["description"] == f'<Properties cpassword="{CPASSWORD_MARKER}"/>'
    # The first-attribute display fallback used to surface the value itself.
    assert settings["Widget:lab-widget"].display_value == CPASSWORD_MARKER


def test_fresh_ingest_leaves_no_probe_in_database_bytes(tmp_path: Path, capsys) -> None:
    db, _ = _ingest_stages(tmp_path, capsys)
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION
        assert _file_leaks(db) == {}  # while open: the WAL holds the ingests
        payloads = [e["payload"] for e in query_events(conn, event_type="gpo.modified")]
        widget = [d for p in payloads for d in p["deltas"] if d["cse"] == "Lab Widgets"]
        assert widget and all(d["new"] == CPASSWORD_MARKER for d in widget)
        # The finding still fires, at full severity, without a single character.
        rows = conn.execute(
            "SELECT severity, summary, detail FROM finding WHERE detector_id = 'cpassword'"
        ).fetchall()
        assert rows == [
            (
                "critical",
                "cpassword in MACHINE/Preferences/Groups/Groups.xml <Properties> (MS14-025)",
                CPASSWORD_FINDING_DETAIL,
            )
        ]
    assert _file_leaks(db) == {}


def test_save_estate_backstop_redacts_estates_built_elsewhere(tmp_path: Path) -> None:
    from gpo_lens.model import Setting

    estate = ingest.load_estate(B.build_probe_export(tmp_path / "export", sysvol=False))
    gpo = estate.gpos[0]
    gpo.settings.append(
        Setting(
            gpo.id,
            "Computer",
            "Synthetic",
            f"Item:{B.REPORT_PROBE}",
            "Item",
            f"user=lab {B.REPORT_PROBE}",
            {"@attr": {"CPassword": B.REPORT_PROBE}, "note": f"cpassword='{B.TASK_PROBE}'"},
            False,
        )
    )
    db = tmp_path / "direct.sqlite3"
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        save_estate(conn, estate)
        row = conn.execute(
            "SELECT identity, display_value, raw FROM setting WHERE cse = 'Synthetic'"
        ).fetchone()
    assert row[0] == f"Item:{CPASSWORD_MARKER}"
    assert row[1] == f"user=lab {CPASSWORD_MARKER}"
    assert json.loads(row[2]) == {
        "@attr": {"CPassword": CPASSWORD_MARKER},
        "note": f"cpassword='{CPASSWORD_MARKER}'",
    }
    assert _file_leaks(db) == {}


def test_detector_matches_any_casing_and_the_element_form(tmp_path: Path) -> None:
    export = B.build_probe_export(tmp_path / "export")
    prefs = export / "SYSVOL-Policies/{AAAAAAAA-0002-0002-0002-AAAAAAAAAAAA}/MACHINE/Preferences"
    files = {
        "Services/Services.xml": (
            "<NTServices><NTService name='s' uid='{1}'>"
            "<Properties serviceName='s' CPassword='PROBEdetSVC1'/></NTService></NTServices>"
        ),
        "DataSources/DataSources.xml": (
            "<DataSources><DataSource name='d' uid='{2}'>"
            "<Properties dsn='d' CPASSWORD=''/></DataSource></DataSources>"
        ),
        "Drives/Drives.xml": (
            "<Drives><Drive name='L:' uid='{3}'><Properties path='x'/>"
            "<cpassword>PROBEdetELM2</cpassword></Drive></Drives>"
        ),
    }
    for rel, xml in files.items():
        (prefs / rel).parent.mkdir(parents=True)
        (prefs / rel).write_text(xml, encoding="utf-8")
    estate = ingest.load_estate(export)
    hits = sorted((Path(h.file).name, h.tag) for h in cpassword_scan(estate))
    assert hits == [
        ("DataSources.xml", "Properties"),
        ("Drives.xml", "cpassword"),
        ("Groups.xml", "Properties"),
        ("Services.xml", "Properties"),
    ]
    doctor = [f for f in estate_doctor(estate) if f.category == "cpassword"]
    assert len(doctor) == 4
    assert {f.detail for f in doctor} == {CPASSWORD_FINDING_DETAIL}


def test_presence_is_tracked_without_a_fingerprint(tmp_path: Path, capsys) -> None:
    """No hash is stored: rotation is invisible by design, presence is not.

    Every cpassword is recoverable with the published key, so rotating one is
    not a remediation. The finding persists across snapshots on the same GPO,
    the trend counts hits, and nothing derived from either value is stored.
    """
    db = tmp_path / "trend.sqlite3"
    first = B.build_probe_export(tmp_path / "s1")
    second = B.build_probe_export(tmp_path / "s2")
    groups = second / "SYSVOL-Policies" / B._SYSVOL_GROUPS
    groups.write_text(
        groups.read_text().replace(B.SYSVOL_PROBE, ROTATED_SYSVOL_PROBE), encoding="utf-8"
    )
    _cli(capsys, "--db", str(db), "ingest", str(first))
    _cli(capsys, "--db", str(db), "ingest", str(second))
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        rows = conn.execute(
            "SELECT id, first_seen_snapshot, last_seen_snapshot, resolved_in_snapshot, detail "
            "FROM finding WHERE detector_id = 'cpassword'"
        ).fetchall()
        assert rows == [(rows[0][0], 1, 2, None, CPASSWORD_FINDING_DETAIL)]
        assert [p.cpassword_hit_count for p in compute_trend(conn)] == [1, 1]
        columns = {row[1] for row in conn.execute("PRAGMA table_info(finding)")} | {
            row[1] for row in conn.execute("PRAGMA table_info(setting)")
        }
        assert not any("hmac" in c or "cpassword" in c for c in columns)
    assert _file_leaks(db) == {}


# --- Exports -----------------------------------------------------------------


def test_cli_and_web_outputs_carry_no_probe(tmp_path: Path, capsys, monkeypatch) -> None:
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    db, export = _ingest_stages(tmp_path, capsys)
    gpo = "aaaaaaaa000100010001aaaaaaaaaaaa"
    cpw_gpo = "aaaaaaaa000200020002aaaaaaaaaaaa"
    outputs = {
        "doctor": _cli(capsys, "--db", str(db), "--json", "doctor"),
        "cpassword": _cli(capsys, "--db", str(db), "--json", "cpassword"),
        "cpassword-src": _cli(capsys, "cpassword", str(export)),
        "settings-dump": _cli(capsys, "--db", str(db), "--json", "settings-dump"),
        "show": _cli(capsys, "--db", str(db), "show", gpo, "--format", "json"),
        "events": _cli(capsys, "--db", str(db), "--json", "events"),
        "trends": _cli(capsys, "--db", str(db), "trends", "--json"),
        "diff-settings": _cli(capsys, "--db", str(db), "--json", "diff-settings", "1", "2"),
        "report-html": _cli(capsys, "--db", str(db), "report", "--format", "html"),
    }
    for view, extra in (
        ("dossier", ["--gpo-id", gpo]),
        ("ledger", ["--gpo-id", gpo]),
        ("findings", []),
        ("settings-dump", []),
    ):
        for fmt in ("md", "csv"):
            outputs[f"export-{view}-{fmt}"] = _cli(
                capsys, "--db", str(db), "export", view, "--format", fmt, *extra
            )
    ndjson = tmp_path / "events.ndjson"
    _cli(capsys, "--db", str(db), "events-export", "--ndjson", str(ndjson))
    outputs["events-export"] = ndjson.read_text()
    # Even the explicit flag is masked by the shared output projection.
    outputs["cpassword-show-secrets"] = _cli(capsys, "cpassword", str(export), "--show-secrets")

    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "cpassword-test-token")
    client = TestClient(
        create_app(str(db)), headers={"Authorization": "Bearer cpassword-test-token"}
    )
    for url in (
        f"/gpo/{gpo}",
        f"/gpo/{cpw_gpo}",
        "/findings",
        "/search?q=Lab",
        "/trends",
        "/api/v1/query/cpassword_scan",
        "/api/v1/query/estate_doctor",
        f"/export/gpo/{gpo}?format=json",
        f"/export/gpo/{gpo}?format=csv",
        f"/export/gpo/{gpo}?format=md",
        "/setting?identity=Widget:lab-widget&cse=Lab Widgets",
    ):
        response = client.get(url)
        assert response.status_code == 200, url
        outputs[url] = response.text
    leaks = {name: _leaks_in(text) for name, text in outputs.items() if _leaks_in(text)}
    assert leaks == {}
    assert all(text.strip() for text in outputs.values())


# --- Upgrading a v1.4.0 database ---------------------------------------------


def _upgrade_copy(tmp_path: Path) -> Path:
    db = tmp_path / "v1.4.0-cpassword.sqlite3"
    shutil.copyfile(FIXTURE, db)
    return db


def test_fixture_really_holds_v140_plaintext() -> None:
    """Guard: the upgrade tests below are meaningless if the fixture is clean."""
    data = FIXTURE.read_bytes()
    for probe in (*B.REPORT_PROBES, B.SYSVOL_PREFIX):
        assert probe.encode() in data, probe
    with closing(sqlite3.connect(f"{FIXTURE.as_uri()}?mode=ro", uri=True)) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 10
        live = "".join(str(r) for r in conn.execute("SELECT * FROM setting"))
        assert B.DELETED_PROBE not in live  # only in free pages of a deleted snapshot


def test_v140_database_is_scrubbed_and_purged(tmp_path: Path) -> None:
    db = _upgrade_copy(tmp_path)
    with closing(sqlite3.connect(f"{FIXTURE.as_uri()}?mode=ro", uri=True)) as conn:
        before_events = query_events(conn)
        estates_before = {sid: load_estate(conn, sid) for sid, _, _ in list_snapshots(conn)}
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION
        assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert _file_leaks(db) == {}  # main file, WAL and shm, connection still open
        assert Path(f"{db}-wal").stat().st_size == 0
        # Re-chained, and the rewrite is itself on the record.
        assert verify_event_chain(conn) == (True, [])
        events = query_events(conn)
        assert len(events) == len(before_events) + 1
        scrub = events[-1]
        assert scrub["event_type"] == "maintenance.cpassword_scrub"
        assert scrub["payload"]["rewritten_event_ids"] == [1, 4]
        assert scrub["payload"]["rehashed_event_ids"] == [1, 2, 3, 4, 5]
        assert scrub["payload"]["pre_existing_broken_event_ids"] == []
        assert scrub["payload"]["discovered_value_count"] >= len(B.REPORT_PROBES) - 1
        assert scrub["payload"]["changed"] == {
            "events.payload": 2,
            "finding.detail": 1,
            "finding_triage_event.note": 1,
            "setting.display_value": 2,
            "setting.raw": 12,  # six probed settings in each of two snapshots
        }
        assert [e["event_type"] for e in events[:-1]] == [e["event_type"] for e in before_events]
        assert conn.execute(
            "SELECT detail FROM finding WHERE detector_id = 'cpassword'"
        ).fetchall() == [(CPASSWORD_FINDING_DETAIL,)]
        assert conn.execute("SELECT note FROM finding_triage_event").fetchall() == [
            (f"report shows cpassword {CPASSWORD_MARKER}; ticket raised",)
        ]
        # Everything except the redacted values survives the upgrade.
        for sid, before in estates_before.items():
            after = load_estate(conn, sid)
            assert [g.id for g in after.gpos] == [g.id for g in before.gpos]
            for g_after, g_before in zip(after.gpos, before.gpos, strict=True):
                assert len(g_after.settings) == len(g_before.settings)
                for s_after, s_before in zip(g_after.settings, g_before.settings, strict=True):
                    expected, _ = redact_structure(s_before.raw)
                    assert s_after.raw == expected
                    assert s_after.identity == s_before.identity
                    assert s_after.display_value == Chaser(B.REPORT_PROBES).sub(
                        redact_text(s_before.display_value)
                    )
        first = {
            t: conn.execute(f'SELECT * FROM "{t}"').fetchall()
            for (t,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert _file_leaks(db) == {}
    # A second open is a no-op: no further rewrite, no second scrub event.
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        again = {t: conn.execute(f'SELECT * FROM "{t}"').fetchall() for t in first}
        assert again == first


def test_purge_is_retried_until_old_pages_are_gone(tmp_path: Path) -> None:
    db = _upgrade_copy(tmp_path)
    reader = sqlite3.connect(db)
    try:
        reader.execute("BEGIN")
        reader.execute("SELECT count(*) FROM setting").fetchone()  # pins an old snapshot
        with closing(sqlite3.connect(db)) as conn:
            with pytest.warns(UserWarning, match="cpassword purge"):
                init_db(conn)
            # Logically scrubbed, but not stamped: the old bytes may remain.
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 10
            live = "".join(str(r) for r in conn.execute("SELECT raw FROM setting"))
            assert _leaks_in(live) == []
    finally:
        reader.close()
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION
        assert verify_event_chain(conn) == (True, [])
        assert _file_leaks(db) == {}
        scrubs = query_events(conn, event_type="maintenance.cpassword_scrub")
        assert len(scrubs) == 1  # the retry found nothing left to rewrite
    assert _file_leaks(db) == {}


# --- Redaction primitives ----------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('cpassword="PROBEa"', f'cpassword="{CPASSWORD_MARKER}"'),
        ("CPassword='PROBEb'", f"CPassword='{CPASSWORD_MARKER}'"),
        ("cpassword=PROBEc rest", f"cpassword={CPASSWORD_MARKER} rest"),
        ('{"cpassword": "PROBEd"}', f'{{"cpassword": "{CPASSWORD_MARKER}"}}'),
        ('cpassword=\\"PROBEe\\"', f'cpassword=\\"{CPASSWORD_MARKER}\\"'),
        ("cpassword=&quot;PROBEf&quot;", f"cpassword=&quot;{CPASSWORD_MARKER}&quot;"),
        ('cpassword=""', 'cpassword=""'),
        ("cpassword in Groups.xml <Properties>", "cpassword in Groups.xml <Properties>"),
        ("golden-cpassword", "golden-cpassword"),
        ("cpassword_hit_count=3", "cpassword_hit_count=3"),
    ],
)
def test_inline_redaction(text: str, expected: str) -> None:
    assert redact_text(text) == expected
    assert redact_text(expected) == expected  # idempotent


# --- Copy-chasing safety rules (review B-03) ------------------------------------


def test_short_or_word_like_values_are_not_chased_into_unrelated_fields(tmp_path: Path) -> None:
    """Labelled values are always redacted; only distinctive values are chased.

    ``Enabled``/``Administrators`` (no digit, not ciphertext-shaped) and values
    under 12 characters stay wherever they occur unlabelled, so a malformed
    cpassword cannot blank unrelated names, descriptions or GUIDs.
    """
    from gpo_lens.redaction import chase_eligible

    assert not chase_eligible("Enabled")
    assert not chase_eligible("Administrators")
    assert not chase_eligible("P5x")
    assert chase_eligible("PROBEcpwZZ123")
    # Real GPP ciphertext (base64 of whole AES blocks) is chased even without digits.
    assert chase_eligible("A" * 43)
    chaser = Chaser(["PROBEcpwZZ123"])
    assert chaser.sub("x-PROBEcpwZZ123-y") == f"x-{CPASSWORD_MARKER}-y"
    assert chaser.sub("xPROBEcpwZZ123y") == "xPROBEcpwZZ123y"  # not a whole token

    from gpo_lens.model import Setting

    estate = ingest.load_estate(B.build_probe_export(tmp_path / "export", sysvol=False))
    gpo = estate.gpos[0]
    gpo.settings.append(
        Setting(
            gpo.id,
            "Computer",
            "Synthetic",
            "w",
            "w",
            "x",
            {"@attr": {"cpassword": "Administrators"}},
            False,
        )
    )
    before = {g.id: (g.name, g.description) for g in estate.gpos}
    db = tmp_path / "words.sqlite3"
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        save_estate(conn, estate)
        stored = {r[0]: (r[1], r[2]) for r in conn.execute("SELECT id, name, description FROM gpo")}
        trustees = {r[0] for r in conn.execute("SELECT trustee FROM delegation")}
    assert stored == before
    assert any("Authenticated Users" in t for t in trustees)


def test_copy_in_an_identity_field_refuses_the_save(tmp_path: Path) -> None:
    from gpo_lens.model import Setting
    from gpo_lens.redaction import CredentialInIdentityError

    estate = ingest.load_estate(B.build_probe_export(tmp_path / "export", sysvol=False))
    gpo = estate.gpos[0]
    gpo.settings.append(
        Setting(
            gpo.id,
            "Computer",
            "Synthetic",
            "s",
            "s",
            "x",
            {"@attr": {"cpassword": "PROBEcpwPATH9999"}},
            False,
        )
    )
    estate.soms[0].path = "OU=PROBEcpwPATH9999,DC=golden,DC=local"
    db = tmp_path / "refuse.sqlite3"
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        with pytest.raises(CredentialInIdentityError, match=r"Som\.path") as caught:
            save_estate(conn, estate)
        assert "PROBEcpwPATH9999" not in str(caught.value)
        conn.rollback()
        assert conn.execute("SELECT count(*) FROM snapshot").fetchone() == (0,)
    assert _file_leaks(db) == {}
