"""Analyst-typed text carrying GPP cpassword material is refused, never stored.

Since schema v11 no cpassword value is kept at rest, so output masking cannot
learn one, and text an analyst types after ingest would be stored (or sent to
the model) exactly as typed. ``gpo_lens.analyst_text.check_analyst_text`` is
the one guard; these tests pin

* the predicate: what it refuses (labelled forms the ingest redactor
  recognises, unlabelled GPP-ciphertext-shaped tokens) and what it must not
  (hex digests, GUIDs, SIDs, URLs, paths, prose, identifiers), including the
  measured miss rate on random ciphertext;
* that refusals never echo the value (exception, HTTP body, audit log, events,
  CLI output);
* every write path's behaviour (core triage writers, web triage, web Ask, CLI
  ask/explain-setting) and the read-only ``analyst-text-check`` command;
* an AST inventory of every write path, so a new one cannot bypass the guard
  silently: SQL writes to analyst-text tables, ``append_event`` call sites, web
  ``Form``/``File``/``Body`` fields and LLM calls must each be guarded or
  classified here.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import json
import random
import re
import sqlite3
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from gpo_lens.analyst_text import (
    ANALYST_TEXT_COLUMNS,
    ANALYST_TEXT_EVENT_FIELDS,
    CpasswordInAnalystTextError,
    check_analyst_text,
    cpassword_material,
    refusable_rows,
)
from gpo_lens.redaction import ciphertext_shaped

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "gpo_lens"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

_RNG = random.Random(20261013)  # noqa: S311 - reproducible test data
_BLOB = _RNG.randbytes(64)


def _ciphertext(blocks: int, rng: random.Random = _RNG) -> str:
    """Base64 of *blocks* random AES blocks, unpadded, as GPP writes it."""
    return base64.b64encode(rng.randbytes(16 * blocks)).decode().rstrip("=")


# Fixed so the parametrized ids are stable. Two blocks (an 8-15 character
# password) is the common GPP shape.
CT1 = _ciphertext(1)
CT2 = _ciphertext(2)
CT3 = _ciphertext(3)
# The worked example published with MS14-025 write-ups (a public demo value).
PUBLISHED_EXAMPLE = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"


# --- (a) labelled forms --------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        'cpassword="hunter2"',
        "cPassword: hunter2",
        "CPASSWORD='two words'",
        'cpassword=\\"escaped\\"',
        "cpassword=&quot;xml-escaped&quot;",
        'cpassword =\n "split across a line"',
        '<Properties action="U" cpassword="short" userName="Administrator"/>',
        "<cpassword>element form</cpassword>",
        '{"cpassword": "json"}',
        '{"cpass\\u0077ord": "json with an escaped key"}',
        'cpass<b/>word="split across nodes"',
        '&#99;password="character reference"',
        f"Old Groups.xml had cpassword={CT2} on the local admin.",
    ],
)
def test_labelled_forms_are_refused(text: str) -> None:
    assert cpassword_material(text) == "labelled"


@pytest.mark.parametrize(
    "text",
    [
        'cpassword=""',
        'cpassword="[redacted cpassword]"',
        "cpassword=[redacted cpassword]",
        "Removed the cpassword attribute from Groups.xml; LAPS manages the account now.",
        "The cpassword finding was a false alarm: the attribute was already blank.",
        "cpassword-bearing GPOs: two, both unlinked.",
    ],
)
def test_empty_redacted_or_mentioned_cpassword_passes(text: str) -> None:
    assert cpassword_material(text) is None


def test_labelled_prose_false_positive_is_documented() -> None:
    """``cpassword:`` followed by a word is an assignment to the redactor too.

    Known, documented false positive (SECURITY.md): the guard reuses the
    ingest redactor's discovery, which reads ``cpassword: removed`` as the
    value ``removed``. The refusal hint says how to reword it.
    """
    assert cpassword_material("Fixed. cpassword: removed from the GPO.") == "labelled"
    with pytest.raises(CpasswordInAnalystTextError) as info:
        check_analyst_text("cpassword: removed", "note")
    assert "'cpassword:'" in str(info.value)


# --- (b) unlabelled ciphertext-shaped tokens -------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        CT1,
        CT2,
        CT3,
        PUBLISHED_EXAMPLE,
        f"The old value was {CT2}, now removed.",
        CT2 + "=",
        CT2.replace("+", "-").replace("/", "_"),
        f'<Properties password="{CT2}" userName="x"/>',
        f"'{CT2}'",
        f"({CT2})",
        CT2[:20] + "\n" + CT2[20:],
        f"value:\n{CT3[:30]}\n{CT3[30:]}\nend",
        f"pw-{CT2}",
        f"see /tmp/{CT2}/x",
    ],
)
def test_unlabelled_ciphertext_is_refused(text: str) -> None:
    assert cpassword_material(text) == "ciphertext"


def _encoded_command() -> str:
    """A PowerShell -EncodedCommand (UTF-16LE) whose bytes are whole AES blocks."""
    command = "Get-ChildItem C:\\Windows\\SYSVOL -Recurse | Out-Null"
    while len(command) % 8:
        command += " "
    encoded = base64.b64encode(command.encode("utf-16-le")).decode()
    assert ciphertext_shaped(encoded)  # the exclusion, not the shape, saves it
    return f"powershell.exe -NoProfile -EncodedCommand {encoded}"


_SHA1 = hashlib.sha1(_BLOB).hexdigest()  # noqa: S324 - test data, not security
_GUID = uuid.UUID(bytes=_BLOB[:16])

NOT_REFUSED = {
    "sha1 hex": _SHA1,
    "sha1 hex upper": _SHA1.upper(),
    "sha256 hex": hashlib.sha256(_BLOB).hexdigest(),
    "sha256 hex upper": hashlib.sha256(_BLOB).hexdigest().upper(),
    "md5 hex": hashlib.md5(_BLOB).hexdigest(),  # noqa: S324 - test data
    "sha512 hex upper": hashlib.sha512(_BLOB).hexdigest().upper(),
    "thumbprint, spaced": " ".join(_SHA1.upper()[i : i + 2] for i in range(0, 40, 2)),
    "thumbprint in prose": f"Pinned the issuing CA by thumbprint {_SHA1.upper()} in the GPO.",
    "guid": str(_GUID),
    "guid braced upper": "{" + str(_GUID).upper() + "}",
    "guid no dashes": _GUID.hex,
    "domain sid": "S-1-5-21-3623811015-3361044348-30300820-1013",
    "builtin sid": "S-1-5-32-544",
    "bulletin url": (
        "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025"
    ),
    "kb url": (
        "https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-"
        "policy-preferences-could-allow-elevation-of-privilege-may-13-2014-" + str(_GUID)
    ),
    "wiki url": "https://wiki.example.test/display/SEC/GPO+Baseline+Exceptions?pageId=123456#R",
    "unc path": (
        r"\\example.test\SYSVOL\example.test\Policies"
        r"\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml"
    ),
    "windows path": r"C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions\en-US\Firewall.adml",
    "posix path": "/var/lib/gpo-lens/exports/2026-10-13/gpo-inventory.json",
    "registry path": r"HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast",
    "distinguished name": "CN=Domain Admins,CN=Users,DC=example,DC=test",
    "prose": (
        "Accepted risk: the legacy app needs NTLMv1 until the vendor upgrade "
        "(CHG0012345). Revisit in Q1."
    ),
    "references": "KB2962486 / MS14-025 / CVE-2014-1812",
    # 22 characters: one AES block by length alone.
    "setting names": "Set DisableIPSourceRouting to 2; AllowInsecureGuestAuth stays 0.",
    "cmdlet": "Use ConvertTo-SecureString in the script, never Get-GPPPassword.",
    "base64 not whole blocks": "SGVsbG8gV29ybGQh",
    "sha1 base64": base64.b64encode(hashlib.sha1(_BLOB).digest()).decode(),  # noqa: S324
    "encoded command": _encoded_command(),
}


@pytest.mark.parametrize("text", list(NOT_REFUSED.values()), ids=list(NOT_REFUSED))
def test_common_identifiers_and_prose_are_not_refused(text: str) -> None:
    assert cpassword_material(text) is None
    check_analyst_text(text, "note")  # no raise


def test_base64_digests_of_whole_blocks_are_a_documented_false_positive() -> None:
    """Base64 of any 16/32/48-byte value looks exactly like GPP ciphertext.

    Documented (SECURITY.md): an MD5 or SHA-256 digest, or a random key, in
    *base64* is refused; the hint says to write digests in hex.
    """
    assert cpassword_material(base64.b64encode(hashlib.sha256(_BLOB).digest()).decode())
    assert cpassword_material(base64.b64encode(hashlib.md5(_BLOB).digest()).decode())  # noqa: S324


def test_exclusions_never_drop_canonical_ciphertext_shapes() -> None:
    """Every exclusion keys on something GPP output cannot be: a token whose
    pad bits are set is not a canonical encoding, so it is let through."""
    # Same length and alphabet as CT1, but the last character carries pad bits.
    non_canonical = CT1[:-1] + ("B" if CT1[-1] != "B" else "C")
    assert ciphertext_shaped(non_canonical)
    assert cpassword_material(non_canonical) is None


# Measured with this seed: the word-shape exclusion lets through 0.1-0.2 % of
# one-block values (passwords up to 7 characters) and essentially none of two or
# more blocks. SECURITY.md quotes these rates; keep them in step.
_FN_BOUNDS = {1: 0.003, 2: 0.0002, 3: 0.0, 4: 0.0}


def _measure_script():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(
        "measure_analyst_text_guard", ROOT / "scripts" / "measure_analyst_text_guard.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("blocks", sorted(_FN_BOUNDS))
def test_measured_miss_rate_on_random_ciphertext(blocks: int) -> None:
    """Same function and seeds as scripts/measure_analyst_text_guard.py, which
    produces the figures SECURITY.md quotes (with 200,000 samples)."""
    samples = 20_000
    misses = _measure_script().miss_count(blocks, samples)
    assert misses <= _FN_BOUNDS[blocks] * samples, misses


@pytest.mark.parametrize(
    "text",
    [
        ("a/" * 50_000) + " " + ("-x" * 50_000),
        "a-b/c_d " * 20_000,
        "a\n" * 20_000,
        "ab\n" * 10_000 + "ab=\n" * 10_000,
        # Quadratic for an unanchored search ending in ``$`` (13 s at 20,000
        # characters before the line-end scan was made linear).
        "a" * 200_000 + "!\nb",
        # Exponential for a repeated word alternation (about 7x per 4 characters
        # before the word-shape check matched piece by piece).
        "x " + "a" * 39 + "B1xQ",
        "x " + "a" * 60 + "B1xQ" + "\n" + "a" * 60 + "B1xQ",
    ],
    ids=[
        "separator runs",
        "short separated tokens",
        "one-char lines",
        "padded lines",
        "long run not ending its line",
        "crafted word token",
        "crafted wrapped word token",
    ],
)
def test_adversarial_input_is_checked_in_bounded_time(text: str) -> None:
    """Every scan is linear or bounded. Expected time is milliseconds; the
    bound is loose so coverage tracing and a loaded CI runner cannot flake it,
    while the quadratic and exponential versions took seconds to hours."""
    start = time.perf_counter()
    cpassword_material(text)
    assert time.perf_counter() - start < 10


# --- refusal message ------------------------------------------------------------


@pytest.mark.parametrize("value", [CT2, 'cpassword="hunter2-secret"'])
def test_refusal_names_field_and_reason_but_never_the_value(value: str) -> None:
    with pytest.raises(CpasswordInAnalystTextError) as info:
        check_analyst_text(f"note body {value} end", "rationale")
    exc = info.value
    for rendered in (str(exc), repr(exc), " ".join(map(str, exc.args))):
        assert CT2 not in rendered
        assert "hunter2" not in rendered
    assert str(exc).startswith("The rationale looks like it contains a Group Policy Preferences")
    assert "recoverable credential" in str(exc)
    assert "remove it" in str(exc)
    assert exc.field == "rationale"
    assert isinstance(exc, ValueError)


# --- core write paths -------------------------------------------------------------


def _db_with_finding() -> tuple[sqlite3.Connection, int]:
    from gpo_lens._legacy_findings import update_finding_lifecycle
    from gpo_lens.findings import load_active_findings
    from gpo_lens.store import init_db

    conn = sqlite3.connect(":memory:")
    init_db(conn)
    conn.execute("INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')")
    finding = MagicMock(
        category="test_rule",
        gpo_id="gpo1",
        gpo_name="GPO-gpo1",
        severity="medium",
        summary="test",
        detail="",
        subject_key=(),
    )
    update_finding_lifecycle(conn, 1, [finding])
    return conn, load_active_findings(conn)[0].id


def _event_rows(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM finding_triage_event").fetchone()[0])


@pytest.mark.parametrize("status", ["acknowledged", "accepted_risk", "open"])
def test_triage_finding_refuses_and_writes_nothing(status: str) -> None:
    from gpo_lens.findings import triage_finding

    conn, finding_id = _db_with_finding()
    try:
        with pytest.raises(CpasswordInAnalystTextError):
            triage_finding(conn, finding_id, status, f"pasted {CT2}", "alice")
        assert _event_rows(conn) == 0
        triage_finding(conn, finding_id, status, "a clean note", "alice")
        assert _event_rows(conn) == 1
    finally:
        conn.close()


@pytest.mark.parametrize("field", ["note", "rationale"])
def test_append_triage_event_refuses_each_field(field: str) -> None:
    from gpo_lens.findings import append_triage_event

    conn, finding_id = _db_with_finding()
    try:
        kwargs = {"note": "clean", "rationale": "clean", field: f'cpassword="{CT1}"'}
        with pytest.raises(CpasswordInAnalystTextError) as info:
            append_triage_event(conn, finding_id, "accepted_risk", "bob", **kwargs)
        assert info.value.field == field
        assert _event_rows(conn) == 0
    finally:
        conn.close()


def test_a_value_cut_by_the_2000_character_limit_is_still_refused() -> None:
    from gpo_lens.findings import append_triage_event

    conn, finding_id = _db_with_finding()
    try:
        note = "x " * 995 + CT3  # the value straddles the stored prefix
        assert len(note) > 2000 > 1990
        with pytest.raises(CpasswordInAnalystTextError):
            append_triage_event(conn, finding_id, "commented", "bob", note=note)
        assert _event_rows(conn) == 0
    finally:
        conn.close()


# --- web: triage form ----------------------------------------------------------------


@pytest.fixture()
def web_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    pytest.importorskip("fastapi")
    from gpo_lens.findings import evaluate_finding_lifecycle_v2
    from gpo_lens.ingest import load_estate
    from gpo_lens.store import init_db, list_snapshots, save_estate

    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    monkeypatch.setenv("GPO_LENS_AUDIT_LOG", str(tmp_path / "audit.log"))
    db = tmp_path / "lens.sqlite3"
    estate = load_estate(FIXTURE_DIR)
    conn = sqlite3.connect(db)
    try:
        init_db(conn)
        save_estate(conn, estate)
        evaluate_finding_lifecycle_v2(conn, list_snapshots(conn)[0][0], estate)
    finally:
        conn.close()
    return db


def _client(db: Path):  # type: ignore[no-untyped-def]
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    return TestClient(
        create_app(str(db)),
        headers={"Authorization": "Bearer test-secret-token", "Origin": "http://testserver"},
    )


def _all_bytes(*paths: Path) -> bytes:
    data = b""
    for path in paths:
        for sidecar in (path, Path(f"{path}-wal"), Path(f"{path}-journal")):
            if sidecar.exists():
                data += sidecar.read_bytes()
    return data


def _first_finding_id(db: Path) -> int:
    from gpo_lens.findings import load_active_findings

    conn = sqlite3.connect(db)
    try:
        return load_active_findings(conn)[0].id
    finally:
        conn.close()


def test_web_triage_refusal_is_a_400_with_the_reason_and_no_echo(
    web_db: Path, tmp_path: Path
) -> None:
    finding_id = _first_finding_id(web_db)
    client = _client(web_db)
    resp = client.post(
        f"/findings/{finding_id}/triage",
        data={"status": "acknowledged", "note": f"local admin pw was {CT2}"},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "Group Policy Preferences cpassword" in resp.text
    assert "recoverable credential" in resp.text
    assert CT2 not in resp.text
    conn = sqlite3.connect(web_db)
    try:
        assert _event_rows(conn) == 0
    finally:
        conn.close()
    audit = (tmp_path / "audit.log").read_text(encoding="utf-8")
    entry = json.loads(audit.strip().splitlines()[-1])
    assert entry["action"] == "triage"
    assert entry["outcome"] == "refused"
    assert CT2 not in audit
    assert CT2.encode() not in _all_bytes(web_db)

    # The same decision with the value removed goes through.
    ok = client.post(
        f"/findings/{finding_id}/triage",
        data={"status": "acknowledged", "note": "local admin pw rotated via LAPS"},
        follow_redirects=False,
    )
    assert ok.status_code == 303


def test_findings_page_loads_the_draft_keeping_script(web_db: Path) -> None:
    client = _client(web_db)
    html = client.get("/findings?lifecycle=all&triage=all").text
    assert 'class="gp-triage-error" role="alert" hidden' in html
    assert "triage-form.js" in html
    script = client.get("/static/triage-form.js")
    assert script.status_code == 200
    assert "gp-triage-form" in script.text


# --- web: Ask -------------------------------------------------------------------------------


def test_web_ask_refuses_before_storing_or_sending(
    web_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GPO_LENS_API_KEY", "test-key")
    route = MagicMock(return_value={"query": "estate_summary", "params": {}})
    with patch("gpo_lens.narration.route_question", route):
        resp = _client(web_db).post("/ask", data={"question": f"what is {CT2}?"})
    assert resp.status_code == 400
    assert "Group Policy Preferences cpassword" in resp.text
    assert CT2 not in resp.text
    route.assert_not_called()
    conn = sqlite3.connect(web_db)
    try:
        payloads = [
            json.loads(row[0])
            for row in conn.execute("SELECT payload FROM events WHERE event_type='audit.narrate'")
        ]
    finally:
        conn.close()
    assert payloads == [
        {"principal": payloads[0]["principal"], "question": "", "outcome": "refused"}
    ]
    assert CT2.encode() not in _all_bytes(web_db)


def test_web_ask_refuses_a_token_formed_by_joining_lines(
    web_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stored question has newlines removed; that join is checked too."""
    monkeypatch.setenv("GPO_LENS_API_KEY", "test-key")
    route = MagicMock(return_value={"query": "estate_summary", "params": {}})
    question = f"value {CT2[:11]}\n{CT2[11:]} ok"
    with patch("gpo_lens.narration.route_question", route):
        resp = _client(web_db).post("/ask", data={"question": question})
    assert resp.status_code == 400
    route.assert_not_called()


# --- CLI ---------------------------------------------------------------------------------------


def _cli_db(tmp_path: Path) -> Path:
    from gpo_lens.ingest import load_estate
    from gpo_lens.store import init_db, save_estate

    db = tmp_path / "cli.sqlite3"
    conn = sqlite3.connect(db)
    try:
        init_db(conn)
        save_estate(conn, load_estate(FIXTURE_DIR))
    finally:
        conn.close()
    return db


def test_cli_ask_refuses_before_calling_the_model(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from gpo_lens.cli import main

    monkeypatch.setenv("GPO_LENS_API_KEY", "test-key")
    db = _cli_db(tmp_path)
    route = MagicMock(return_value={"query": "estate_summary", "params": {}})
    with patch("gpo_lens.narration.route_question", route):
        code = main(["--db", str(db), "ask", f"why is {CT2} here?"])
    out, err = capsys.readouterr()
    assert code == 1
    route.assert_not_called()
    assert "Group Policy Preferences cpassword" in err
    assert CT2 not in out + err


def test_cli_explain_setting_refuses_before_calling_the_model(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from gpo_lens.cli import main

    monkeypatch.setenv("GPO_LENS_API_KEY", "test-key")
    db = _cli_db(tmp_path)
    call = MagicMock(return_value="NARRATED/UNVERIFIED: x")
    with patch("gpo_lens.narration.call_llm", call):
        code = main(["--db", str(db), "explain-setting", f'Groups:cpassword="{CT1}"'])
    out, err = capsys.readouterr()
    assert code == 1
    call.assert_not_called()
    assert CT1 not in out + err


# --- existing rows: read-only operator check ------------------------------------------------


def _seed_legacy_rows(db: Path) -> dict[str, int]:
    """Rows written before the guard existed (raw SQL bypasses it)."""
    conn = sqlite3.connect(db)
    try:
        finding_id = conn.execute("SELECT id FROM finding ORDER BY id LIMIT 1").fetchone()[0]
        ids: dict[str, int] = {}
        for label, note, rationale in (
            ("clean", "looked at it", ""),
            ("note", f"pw {CT2}", ""),
            ("rationale", "ok", f'cpassword="{CT1}"'),
        ):
            cursor = conn.execute(
                "INSERT INTO finding_triage_event (occurrence_id, action, actor, "
                "occurred_at, note, rationale) "
                "VALUES (?, 'commented', 'old', '2025-01-01T00:00:00+00:00', ?, ?)",
                (finding_id, note, rationale),
            )
            ids[label] = int(cursor.lastrowid or 0)
        cursor = conn.execute(
            "INSERT INTO events (timestamp, event_type, schema_version, payload) "
            "VALUES ('2025-01-01T00:00:00+00:00', 'audit.narrate', 1, ?)",
            (json.dumps({"principal": "old", "question": f"is {CT3} bad?", "outcome": "error"}),),
        )
        ids["question"] = int(cursor.lastrowid or 0)
        # Sol r3 B2: the legacy v1 table's rationale (unlabelled, so the v11
        # scrub leaves it) must be listed too.
        cursor = conn.execute(
            "INSERT INTO finding_triage (finding_id, status, note, rationale, actor, timestamp) "
            "VALUES (?, 'accepted_risk', 'clean', ?, 'old', '2025-01-01')",
            (finding_id, CT3),
        )
        ids["legacy_rationale"] = int(cursor.lastrowid or 0)
        # Sol r3 B1: a BLOB in a TEXT column, as UTF-16, is read every way.
        cursor = conn.execute(
            "INSERT INTO finding_triage_event (occurrence_id, action, actor, occurred_at, note) "
            "VALUES (?, 'commented', 'old', '2025-01-02T00:00:00+00:00', ?)",
            (finding_id, f"pw {CT2}".encode("utf-16-le")),
        )
        ids["blob_note"] = int(cursor.lastrowid or 0)
        conn.commit()
        return ids
    finally:
        conn.close()


def test_refusable_rows_lists_ids_and_kinds_only(web_db: Path) -> None:
    ids = _seed_legacy_rows(web_db)
    conn = sqlite3.connect(f"{web_db.as_uri()}?mode=ro", uri=True)
    try:
        rows = refusable_rows(conn)
    finally:
        conn.close()
    assert {(r.table, r.column, r.row_id, r.kind) for r in rows} == {
        ("finding_triage_event", "note", ids["note"], "ciphertext"),
        ("finding_triage_event", "rationale", ids["rationale"], "labelled"),
        ("events", "payload.question", ids["question"], "ciphertext"),
        ("finding_triage", "rationale", ids["legacy_rationale"], "ciphertext"),
        ("finding_triage_event", "note", ids["blob_note"], "uninspectable"),
    }


def test_analyst_text_check_cli_is_read_only_and_never_prints_values(
    web_db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from gpo_lens.cli import main

    ids = _seed_legacy_rows(web_db)
    before = web_db.read_bytes()
    assert main(["--db", str(web_db), "analyst-text-check"]) == 1
    text, _ = capsys.readouterr()
    assert main(["--db", str(web_db), "--json", "analyst-text-check"]) == 1
    raw, _ = capsys.readouterr()
    assert web_db.read_bytes() == before
    for output in (text, raw):
        for secret in (CT1, CT2, CT3):
            assert secret not in output
    assert "Nothing was changed" in text
    data = json.loads(raw)["data"]
    assert data["count"] == 5
    assert {(row["table"], row["id"]) for row in data["rows"]} == {
        ("finding_triage_event", ids["note"]),
        ("finding_triage_event", ids["rationale"]),
        ("events", ids["question"]),
        ("finding_triage", ids["legacy_rationale"]),
        ("finding_triage_event", ids["blob_note"]),
    }
    assert any(
        line.split()[:3] == ["finding_triage", "rationale", str(ids["legacy_rationale"])]
        for line in text.splitlines()
        if line.strip()
    )


def test_analyst_text_check_cli_clean_database_exits_zero(
    web_db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from gpo_lens.cli import main

    assert main(["--db", str(web_db), "analyst-text-check"]) == 0
    assert "No stored analyst text" in capsys.readouterr().out


# --- review round 1 regressions ---------------------------------------------------------------
#
# Each probe from the two-lineage review of 4687510 (Sol, DeepSeek) as a test.

_LOOPBACK = ("127.0.0.1", 50000)
# A forwarded-user header carrying GPP-shaped ciphertext (Sol B1).
_HEADER_VALUE = base64.b64encode(hashlib.sha256(b"forwarded-user-probe").digest()).decode()


def test_forwarded_user_value_used_by_the_review_probe_is_cpassword_shaped() -> None:
    assert cpassword_material(_HEADER_VALUE) == "ciphertext"


def _loopback_client(db: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("GPO_LENS_FORWARDED_USER_HEADER", "X-Forwarded-User")
    return TestClient(
        create_app(str(db)),
        base_url="http://127.0.0.1",
        client=_LOOPBACK,
        headers={"Origin": "http://127.0.0.1"},
    )


@pytest.mark.parametrize(
    "header",
    [
        _HEADER_VALUE,  # base64 alphabet: refused by shape
        "RXx2nznYZEGZwOW9vPvIWzfOkcveH8Gw6mtE8TBDbdc",  # no + / =: refused by the guard
    ],
)
def test_forwarded_user_header_carrying_a_cpassword_reaches_no_sink(
    web_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, header: str
) -> None:
    """Sol B1: the header named the principal and was written to the Ask event,
    the triage actor and audit.log unguarded. It is now refused on entry."""
    monkeypatch.setenv("GPO_LENS_API_KEY", "test-key")
    client = _loopback_client(web_db, monkeypatch)
    finding_id = _first_finding_id(web_db)
    route = MagicMock(return_value={"query": "estate_summary", "params": {}})
    with patch("gpo_lens.narration.route_question", route):
        ask = client.post(
            "/ask", data={"question": "summary"}, headers={"X-Forwarded-User": header}
        )
    triage = client.post(
        f"/findings/{finding_id}/triage",
        data={"status": "acknowledged", "note": "clean"},
        headers={"X-Forwarded-User": header},
        follow_redirects=False,
    )
    assert ask.status_code == 401
    assert triage.status_code == 401
    route.assert_not_called()
    for response in (ask, triage):
        assert header not in response.text
    conn = sqlite3.connect(web_db)
    try:
        assert _event_rows(conn) == 0
        assert refusable_rows(conn) == []
    finally:
        conn.close()
    assert header.encode() not in _all_bytes(web_db)
    audit = tmp_path / "audit.log"
    assert not audit.exists() or header not in audit.read_text(encoding="utf-8")

    # A valid account name still names the principal and is stored as actor.
    ok = client.post(
        f"/findings/{finding_id}/triage",
        data={"status": "acknowledged", "note": "clean"},
        headers={"X-Forwarded-User": "CONTOSO\\alice"},
        follow_redirects=False,
    )
    assert ok.status_code == 303
    conn = sqlite3.connect(web_db)
    try:
        assert conn.execute("SELECT actor FROM finding_triage_event").fetchall() == [
            ("CONTOSO\\alice",)
        ]
    finally:
        conn.close()


def test_core_writers_refuse_a_cpassword_in_the_actor() -> None:
    """Sol B1 / DeepSeek N5: the core writers' actor argument was unconstrained."""
    from gpo_lens.findings import append_triage_event, triage_finding

    conn, finding_id = _db_with_finding()
    try:
        with pytest.raises(CpasswordInAnalystTextError) as info:
            triage_finding(conn, finding_id, "acknowledged", "clean", _HEADER_VALUE)
        assert info.value.field == "actor"
        with pytest.raises(CpasswordInAnalystTextError):
            append_triage_event(conn, finding_id, "commented", _HEADER_VALUE, note="clean")
        assert _event_rows(conn) == 0
    finally:
        conn.close()


@pytest.mark.parametrize(
    ("event_type", "field"),
    [("audit.narrate", "principal"), ("audit.ingest", "principal"), ("audit.narrate", "question")],
)
def test_event_log_refuses_a_cpassword_in_operator_fields(event_type: str, field: str) -> None:
    from gpo_lens.events import append_event, append_events, init_events_table

    conn = sqlite3.connect(":memory:")
    try:
        init_events_table(conn)
        with pytest.raises(CpasswordInAnalystTextError):
            append_event(conn, event_type, {field: _HEADER_VALUE, "outcome": "x"})
        with pytest.raises(CpasswordInAnalystTextError):
            append_events(conn, [(event_type, {field: _HEADER_VALUE})])
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    finally:
        conn.close()


def test_audit_log_never_records_a_cpassword_principal_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defence in depth behind the header validation: _audit masks the name."""
    from types import SimpleNamespace

    from starlette.requests import Request

    from gpo_lens.web.app import _audit
    from gpo_lens.web.auth import LOCAL_PRINCIPAL, Principal

    log = tmp_path / "audit.log"
    monkeypatch.setenv("GPO_LENS_AUDIT_LOG", str(log))
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/x",
            "headers": [],
            "app": SimpleNamespace(state=SimpleNamespace(db_path=str(tmp_path / "db"))),
            "state": {"request_id": "r"},
        }
    )
    principal = Principal(_HEADER_VALUE, "forwarded", LOCAL_PRINCIPAL.permissions)
    _audit("snapshot_delete", principal, "failure", "snapshot 1 not found", request)
    text = log.read_text(encoding="utf-8")
    assert _HEADER_VALUE not in text
    assert json.loads(text.splitlines()[-1])["principal"] == "[refused principal name]"


def test_checker_reports_actor_and_event_principal_rows(web_db: Path) -> None:
    """Sol B1: analyst-text-check reported none of the persisted header copies."""
    conn = sqlite3.connect(web_db)
    try:
        finding_id = conn.execute("SELECT id FROM finding ORDER BY id LIMIT 1").fetchone()[0]
        triage_id = conn.execute(
            "INSERT INTO finding_triage_event (occurrence_id, action, actor, occurred_at) "
            "VALUES (?, 'acknowledged', ?, '2025-01-01T00:00:00+00:00')",
            (finding_id, _HEADER_VALUE),
        ).lastrowid
        event_id = conn.execute(
            "INSERT INTO events (timestamp, event_type, schema_version, payload) "
            "VALUES ('2025-01-01T00:00:00+00:00', 'audit.ingest', 1, ?)",
            (json.dumps({"principal": _HEADER_VALUE}),),
        ).lastrowid
        conn.commit()
        rows = {(r.table, r.column, r.row_id) for r in refusable_rows(conn)}
    finally:
        conn.close()
    assert rows == {
        ("finding_triage_event", "actor", triage_id),
        ("events", "payload.principal", event_id),
    }


# Sol B2 / DeepSeek N1: a wrapped value with prose after the last wrapped line.
_WRAPPED_WITH_PROSE = [
    f"old {PUBLISHED_EXAMPLE[:32]}\n{PUBLISHED_EXAMPLE[32:]} removed",
    f"old {CT2[:20]}\n{CT2[20:]} ok",
    f"value {CT2[:20]}\n{CT2[20:]}",
    f"note:\n{CT3[:30]}\n{CT3[30:50]}\n{CT3[50:]} - rotated.",
    f"{CT2[:20]}\n{CT2[20:]}, removed from Groups.xml",
]


@pytest.mark.parametrize("text", _WRAPPED_WITH_PROSE)
def test_wrapped_value_with_prose_after_it_is_refused(text: str) -> None:
    assert cpassword_material(text) == "ciphertext"


def test_wrapped_value_with_prose_is_refused_by_core_triage() -> None:
    from gpo_lens.findings import triage_finding

    conn, finding_id = _db_with_finding()
    try:
        with pytest.raises(CpasswordInAnalystTextError):
            triage_finding(conn, finding_id, "acknowledged", _WRAPPED_WITH_PROSE[0], "alice")
        assert _event_rows(conn) == 0
    finally:
        conn.close()


def test_wrapped_value_with_prose_is_refused_by_web_triage(web_db: Path) -> None:
    finding_id = _first_finding_id(web_db)
    resp = _client(web_db).post(
        f"/findings/{finding_id}/triage",
        data={"status": "acknowledged", "note": _WRAPPED_WITH_PROSE[0]},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert PUBLISHED_EXAMPLE[:32] not in resp.text


def test_wrapped_value_with_prose_is_refused_by_cli_ask(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from gpo_lens.cli import main

    monkeypatch.setenv("GPO_LENS_API_KEY", "test-key")
    db = _cli_db(tmp_path)
    route = MagicMock(return_value={"query": "estate_summary", "params": {}})
    with patch("gpo_lens.narration.route_question", route):
        code = main(["--db", str(db), "ask", _WRAPPED_WITH_PROSE[0]])
    out, err = capsys.readouterr()
    assert code == 1
    route.assert_not_called()
    assert PUBLISHED_EXAMPLE[:32] not in out + err


def test_hard_wrapped_prose_is_not_refused_by_the_line_join() -> None:
    """The new join (last token of a line + first token of the next) on
    ordinary hard-wrapped prose: word-built joins are excluded."""
    text = (
        "Reviewed the Default Domain Policy with the security team; the\n"
        "Administrators group change is expected and the ticket is CHG0012345.\n"
        "DisableIPSourceRouting stays 2, AllowInsecureGuestAuth stays 0, and the\n"
        "ConvertTo-SecureString call in the logon script was removed."
    )
    assert cpassword_material(text) is None


# DeepSeek B1: the guard must be total.
def _total(text: str) -> None:
    try:
        check_analyst_text(text, "note")
    except CpasswordInAnalystTextError:
        pass


_DEPTHS = [1_000, 1_200, 5_000, 20_000, 50_000]


@pytest.mark.parametrize("depth", _DEPTHS)
@pytest.mark.parametrize(
    "shape",
    [
        lambda d: "[" * d + '"cpassword"' + "]" * d,
        lambda d: '{"a":' * d + '"cpassword"' + "}" * d,
        lambda d: '{"a":' * d + '"\\u0063password"' + "}" * d,
        lambda d: "<a>" * d + "cpassword" + "</a>" * d,
        lambda d: "".join(f"<a{i}>t" for i in range(d)) + "cpass<b/>word=x" + "</x>",
        lambda d: "<a>t" * d + 'cpass<b/>word="x"' + "</a>" * d,
        lambda d: "<b/>" * d + "cpassword",
    ],
    ids=["json-array", "json-object", "json-escape", "xml", "xml-broken", "xml-mixed", "xml-flat"],
)
def test_guard_is_total_on_deep_structure(shape, depth: int) -> None:  # type: ignore[no-untyped-def]
    _total(shape(depth))


def test_deep_structure_that_cannot_be_inspected_is_refused_as_uninspectable() -> None:
    for text in (
        "[" * 1200 + '"cpassword"' + "]" * 1200,
        '{"a":' * 5000 + '"cpassword"' + "}" * 5000,
    ):
        assert cpassword_material(text) == "uninspectable"
    with pytest.raises(CpasswordInAnalystTextError) as info:
        check_analyst_text("[" * 1200 + '"cpassword"' + "]" * 1200, "note")
    assert "could not be checked" in str(info.value)
    assert info.value.kind == "uninspectable"


def test_xml_with_entity_declarations_is_uninspectable() -> None:
    text = '<!DOCTYPE x [<!ENTITY p "password">]><x>c&p;="hunter2"</x>'
    assert cpassword_material(text) == "uninspectable"


@pytest.mark.parametrize(
    "text",
    [
        "\\u" * 1000,
        "\\u0041" * 1000,
        "\x00" * 100 + "cpassword=x",
        "\x01\x02" * 500 + "cpassword: y",
        "\ud800" * 10 + "cpassword: z",
        "<a>\ud800</a> cpassword",
        "\u202e" + "cpassword" + "\u202c",
        "\ufeffcpassword=q",
        "c\u0301password=x",
        "<" * 10_000,
        "&" * 10_000,
        "<![CDATA[" * 1000,
    ],
)
def test_guard_is_total_on_exotic_text(text: str) -> None:
    _total(text)


def test_guard_is_total_on_random_bytes() -> None:
    rng = random.Random(7)  # noqa: S311 - reproducible test data
    alphabet = '<>&;="\\{}[]/:aAcpasword0123456789+-_ \n\t'
    for _ in range(2_000):
        raw = rng.randbytes(rng.randrange(0, 400))
        _total(raw.decode("latin-1"))
        _total(raw.decode("utf-8", "surrogateescape"))
        _total("".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 200))))


def test_deep_json_is_a_400_not_a_500_on_web_triage_and_ask(
    web_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DeepSeek B1: the web routes answered HTTP 500 (uncaught RecursionError)."""
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    monkeypatch.setenv("GPO_LENS_API_KEY", "test-key")
    client = TestClient(
        create_app(str(web_db)),
        headers={"Authorization": "Bearer test-secret-token", "Origin": "http://testserver"},
        raise_server_exceptions=False,
    )
    finding_id = _first_finding_id(web_db)
    route = MagicMock(return_value={"query": "estate_summary", "params": {}})
    deep = "[" * 1200 + '"cpassword"' + "]" * 1200
    nested = '{"a":' * 1500 + '"cpassword"' + "}" * 1500  # the reviewer's exact probe
    for text in (deep, nested):
        triage = client.post(
            f"/findings/{finding_id}/triage",
            data={"status": "acknowledged", "note": text},
            follow_redirects=False,
        )
        assert triage.status_code in (303, 400), triage.status_code
        with patch("gpo_lens.narration.route_question", route):
            ask = client.post("/ask", data={"question": text})
        assert ask.status_code in (200, 400), ask.status_code
    deep_triage = client.post(
        f"/findings/{finding_id}/triage",
        data={"status": "acknowledged", "note": deep},
        follow_redirects=False,
    )
    assert deep_triage.status_code == 400


def test_checker_survives_a_stored_row_that_cannot_be_inspected(web_db: Path) -> None:
    conn = sqlite3.connect(web_db)
    try:
        finding_id = conn.execute("SELECT id FROM finding ORDER BY id LIMIT 1").fetchone()[0]
        conn.execute(
            "INSERT INTO finding_triage_event (occurrence_id, action, actor, occurred_at, note) "
            "VALUES (?, 'commented', 'old', '2025-01-01T00:00:00+00:00', ?)",
            (finding_id, '{"a":' * 5000 + '"cpassword"' + "}" * 5000),
        )
        conn.commit()
        kinds = {r.kind for r in refusable_rows(conn)}
    finally:
        conn.close()
    assert kinds == {"uninspectable"}


# DeepSeek N3: the guarded slice is bounded whatever the submitted size.
@pytest.mark.parametrize(
    "note",
    [
        "a\n" * 500_000,
        "ab=\n" * 250_000,
        "a-b/c_d " * 125_000,
        "x " * 1_000 + CT2 + " " + "a\n" * 500_000,  # value inside the stored part
    ],
    ids=["one-char lines", "padded lines", "separated tokens", "value then 1 MB"],
)
def test_megabyte_triage_note_is_checked_in_bounded_time(note: str) -> None:
    from gpo_lens.findings import triage_finding

    conn, finding_id = _db_with_finding()
    try:
        start = time.perf_counter()
        try:
            triage_finding(conn, finding_id, "acknowledged", note, "alice")
        except CpasswordInAnalystTextError:
            assert CT2 in note
        else:
            assert CT2 not in note
        assert time.perf_counter() - start < 2
    finally:
        conn.close()


def test_a_value_only_past_the_checked_slice_is_never_stored() -> None:
    """Text beyond what is stored plus STRADDLE_MARGIN is not checked because
    it is discarded by the 2000-character truncation."""
    from gpo_lens.analyst_text import STRADDLE_MARGIN
    from gpo_lens.findings import triage_finding

    conn, finding_id = _db_with_finding()
    try:
        note = "x " * ((2000 + STRADDLE_MARGIN) // 2 + 10) + CT2
        triage_finding(conn, finding_id, "acknowledged", note, "alice")
        stored = conn.execute("SELECT note FROM finding_triage_event").fetchone()[0]
        assert CT2 not in stored and len(stored) == 2000
    finally:
        conn.close()


# DeepSeek predicate probe, recorded: refused forms and documented limits.
def _ds_ct(blocks: int) -> str:
    raw = hashlib.sha512(b"x" * 32).digest()
    while len(raw) < 16 * blocks:
        raw += hashlib.sha512(raw).digest()
    return base64.b64encode(raw[: 16 * blocks]).decode().rstrip("=")


_DS2 = _ds_ct(2)


@pytest.mark.parametrize(
    "text",
    [
        _ds_ct(1),
        _DS2,
        _ds_ct(3),
        _DS2.replace("+", "-").replace("/", "_"),
        _DS2 + "==",
        _DS2[:20] + "\n" + _DS2[20:],
        _DS2[:20] + "\n" + _DS2[20:] + " ok",
        "value " + _DS2[:20] + "\n" + _DS2[20:],
        f'cpassword="{_DS2}"',
        f"<cpassword>{_DS2}</cpassword>",
        "cpassword=%22" + _DS2 + "%22",
        f"cpassword=&quot;{_DS2}&quot;",
        'cpassw\u043erd="' + _DS2 + '"',
        "value:" + _DS2,
        "`" + _DS2 + "`",
        "/var/" + _DS2 + "/x",
        "pw-" + _DS2,
        "\\\\server\\" + _DS2,
    ],
)
def test_review_probe_forms_are_refused(text: str) -> None:
    assert cpassword_material(text) is not None


@pytest.mark.parametrize(
    "text",
    [
        _DS2[:20] + " " + _DS2[20:],
        _DS2[:20] + "\u200b" + _DS2[20:],
        _DS2[:20] + "\t" + _DS2[20:],
        "cpassword%3D%22" + _DS2 + "%22",
        "x" + _DS2,
    ],
    ids=["space", "zero-width", "tab", "percent-encoded label", "glued to a word"],
)
def test_documented_limits_pass(text: str) -> None:
    """SECURITY.md "Known limits": deliberate break-up, re-encoding or gluing."""
    assert cpassword_material(text) is None


@pytest.mark.parametrize("size", [16, 32, 48, 64, 80, 96, 112, 128])
def test_base64_of_any_whole_number_of_blocks_is_a_documented_false_positive(
    size: int,
) -> None:
    """DeepSeek N2: not only 16/32/48 bytes; SECURITY.md now says so."""
    rng = random.Random(size)  # noqa: S311 - reproducible test data
    for _ in range(20):
        assert cpassword_material(base64.b64encode(rng.randbytes(size)).decode())


@pytest.mark.parametrize(
    ("size", "low", "high"),
    [(20, 0.0, 0.02), (24, 0.0, 0.02), (40, 0.005, 0.08), (100, 0.08, 0.25), (200, 0.2, 0.4)],
)
def test_base64_of_other_sizes_is_refused_only_through_separator_windows(
    size: int, low: float, high: float
) -> None:
    """A long base64 blob of any size can hold a block-length run between two
    ``/`` (or ``-``/``_``), which the window search refuses. SECURITY.md quotes
    these measured rates (2,000 samples, seed 1)."""
    rng = random.Random(1)  # noqa: S311 - reproducible test data
    samples = [base64.b64encode(rng.randbytes(size)).decode() for _ in range(2_000)]
    refused = sum(1 for value in samples if cpassword_material(value)) / len(samples)
    assert low <= refused <= high, refused
    # Without a separator inside, a non-block size is never refused.
    plain = [v for v in samples if not set(v) & set("/-_")]
    assert plain and not any(cpassword_material(v) for v in plain)


def test_pem_certificate_lines_are_refused_with_a_practical_hint() -> None:
    """Sol N1: a 64-character PEM line is base64 of 48 bytes. Documented; the
    hint names certificates and points to the thumbprint."""
    line = base64.b64encode(bytes(range(48))).decode()
    pem = f"-----BEGIN CERTIFICATE-----\n{line}\n-----END CERTIFICATE-----"
    with pytest.raises(CpasswordInAnalystTextError) as info:
        check_analyst_text(pem, "note")
    assert "certificate" in str(info.value) and "thumbprint" in str(info.value)
    assert line not in str(info.value)


# --- review round 2 regressions ---------------------------------------------------------------


def test_cli_kind_labels_are_exhaustive_over_kind() -> None:
    """DeepSeek r2 BLOCKING-1: a Kind without a label crashed the table."""
    import typing

    from gpo_lens.analyst_text import Kind
    from gpo_lens.cli._hygiene import _KIND_LABEL

    assert set(_KIND_LABEL) == set(typing.get_args(Kind))


def test_analyst_text_check_table_lists_an_uninspectable_row(
    web_db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from gpo_lens.cli import main

    deep = '{"a":' * 5000 + '"cpassword"' + "}" * 5000
    conn = sqlite3.connect(web_db)
    try:
        finding_id = conn.execute("SELECT id FROM finding ORDER BY id LIMIT 1").fetchone()[0]
        row_id = conn.execute(
            "INSERT INTO finding_triage_event (occurrence_id, action, actor, occurred_at, note) "
            "VALUES (?, 'commented', 'old', '2025-01-01T00:00:00+00:00', ?)",
            (finding_id, deep),
        ).lastrowid
        conn.commit()
    finally:
        conn.close()
    assert main(["--db", str(web_db), "analyst-text-check"]) == 1
    out, err = capsys.readouterr()
    assert err == ""
    line = next(x for x in out.splitlines() if "finding_triage_event" in x)
    assert str(row_id) in line and "structure the guard cannot inspect" in line
    assert deep[:50] not in out


def _legacy_db(tmp_path: Path) -> tuple[Path, int]:
    """A current-schema database marked v7, so the next init_db runs the
    v7->v8 triage migration again (Sol r2 B1's reproduction)."""
    from gpo_lens._legacy_findings import update_finding_lifecycle
    from gpo_lens.store import init_db

    db = tmp_path / "legacy.sqlite3"
    conn = sqlite3.connect(db)
    try:
        init_db(conn)
        conn.execute("INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 't', '2025-01-01')")
        finding = MagicMock(
            category="test_rule",
            gpo_id="gpo1",
            gpo_name="GPO-gpo1",
            severity="medium",
            summary="test",
            detail="",
            subject_key=(),
        )
        update_finding_lifecycle(conn, 1, [finding])
        finding_id = conn.execute("SELECT id FROM finding").fetchone()[0]
        conn.commit()
        conn.execute("PRAGMA user_version = 7")
    finally:
        conn.close()
    return db, finding_id


_LEGACY_ACTOR = "RXx2nznYZEGZwOW9vPvIWzfOkcveH8Gw6mtE8TBDbdc"


def _seed_legacy_triage(db: Path, finding_id: int) -> dict[str, int]:
    conn = sqlite3.connect(db)
    try:
        ids = {}
        for label, status, note, rationale, actor, ts in (
            ("clean", "acknowledged", "looked at it", "", "CONTOSO\\alice", "2025-01-01T00:00:00"),
            ("actor", "acknowledged", "ok", "", _LEGACY_ACTOR, "2025-01-02T00:00:00"),
            ("note", "accepted_risk", f"pw {CT2}", "", "bob", "2025-01-03T00:00:00"),
            ("rationale", "accepted_risk", "fine", f'cpassword="{CT1}"', "bob", "2025-01-04"),
        ):
            ids[label] = int(
                conn.execute(
                    "INSERT INTO finding_triage (finding_id, status, note, rationale, actor, "
                    "timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                    (finding_id, status, note, rationale, actor, ts),
                ).lastrowid
                or 0
            )
        conn.commit()
        return ids
    finally:
        conn.close()


def _reopen(db: Path) -> None:
    from gpo_lens.store import init_db

    conn = sqlite3.connect(db)
    try:
        init_db(conn)
    finally:
        conn.close()


def test_v8_migration_copies_refused_legacy_text_as_markers(tmp_path: Path) -> None:
    """Sol r2 B1: the v7->v8 copy wrote a legacy cpassword-shaped actor into
    the active append-only log verbatim. It now copies a marker, leaves the
    legacy row as it was, and reports the substitution by id and field."""
    from gpo_lens.analyst_text import REFUSED_PRINCIPAL_MARKER, REFUSED_TEXT_MARKER

    db, finding_id = _legacy_db(tmp_path)
    ids = _seed_legacy_triage(db, finding_id)
    with pytest.warns(UserWarning, match=r"4 legacy field\(s\) carried GPP cpassword material"):
        _reopen(db)
    conn = sqlite3.connect(db)
    try:
        events = conn.execute(
            "SELECT actor, note, rationale FROM finding_triage_event ORDER BY occurred_at"
        ).fetchall()
        legacy = conn.execute(
            "SELECT actor, note, rationale FROM finding_triage ORDER BY id"
        ).fetchall()
        record = conn.execute(
            "SELECT payload FROM events WHERE event_type = 'maintenance.analyst_text_substituted'"
        ).fetchall()
        refusable = {(r.table, r.column, r.row_id) for r in refusable_rows(conn)}
    finally:
        conn.close()
    assert events == [
        ("CONTOSO\\alice", "looked at it", ""),
        (REFUSED_PRINCIPAL_MARKER, "ok", ""),
        ("bob", REFUSED_TEXT_MARKER, REFUSED_TEXT_MARKER),  # rationale falls back to the note
        ("bob", "fine", REFUSED_TEXT_MARKER),
    ]
    # The triage copy leaves the legacy source as it was, so the operator
    # check still lists the unlabelled values. The labelled one is redacted in
    # place by the v11 cpassword scrub that runs in the same upgrade (ingest
    # redaction of a labelled value, not this copy).
    assert legacy[1][0] == _LEGACY_ACTOR and CT2 in legacy[2][1]
    assert CT1 not in legacy[3][2] and "[redacted cpassword]" in legacy[3][2]
    assert refusable == {
        ("finding_triage", "actor", ids["actor"]),
        ("finding_triage", "note", ids["note"]),
    }
    assert len(record) == 1
    payload = json.loads(record[0][0])
    assert payload["source_table"] == "finding_triage"
    assert {(x["row_id"], x["field"]) for x in payload["substitutions"]} == {
        (ids["actor"], "actor"),
        (ids["note"], "note"),
        (ids["note"], "rationale"),
        (ids["rationale"], "rationale"),
    }
    for secret in (_LEGACY_ACTOR, CT1, CT2):
        assert secret not in record[0][0]


def test_v8_migration_rerun_inserts_nothing_twice(tmp_path: Path) -> None:
    db, finding_id = _legacy_db(tmp_path)
    _seed_legacy_triage(db, finding_id)
    with pytest.warns(UserWarning):
        _reopen(db)
    conn = sqlite3.connect(db)
    try:
        conn.execute("PRAGMA user_version = 7")
    finally:
        conn.close()
    _reopen(db)  # interrupted-run replay: nothing new, no new substitutions
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM finding_triage_event").fetchone()[0] == 4
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM events "
                "WHERE event_type = 'maintenance.analyst_text_substituted'"
            ).fetchone()[0]
            == 1
        )
    finally:
        conn.close()


def test_v8_migration_does_not_duplicate_a_row_an_older_release_copied_verbatim(
    tmp_path: Path,
) -> None:
    """A database migrated by an earlier release holds the verbatim copy; the
    re-run must recognise it rather than add a marker row beside it."""
    db, finding_id = _legacy_db(tmp_path)
    _seed_legacy_triage(db, finding_id)
    conn = sqlite3.connect(db)
    try:
        conn.execute(
            "INSERT INTO finding_triage_event (occurrence_id, action, actor, occurred_at, note, "
            "rationale) VALUES (?, 'acknowledged', ?, '2025-01-02T00:00:00', 'ok', '')",
            (finding_id, _LEGACY_ACTOR),
        )
        conn.commit()
    finally:
        conn.close()
    with pytest.warns(UserWarning, match=r"3 legacy field"):
        _reopen(db)
    conn = sqlite3.connect(db)
    try:
        actors = [
            r[0]
            for r in conn.execute(
                "SELECT actor FROM finding_triage_event WHERE occurred_at = '2025-01-02T00:00:00'"
            )
        ]
        rows = {(r.table, r.column) for r in refusable_rows(conn)}
    finally:
        conn.close()
    assert actors == [_LEGACY_ACTOR]  # not duplicated; still reported below
    assert ("finding_triage_event", "actor") in rows


@pytest.mark.parametrize(
    "name",
    [
        "DOMAIN\\svc#batch",
        "DOMAIN\\svc!batch",
        "DOMAIN\\Jöhn Döe",
        "DOMAIN\\svc_backup$",
        "DOMAIN\\Jane  Doe",
        "NT AUTHORITY\\SYSTEM",
        "IIS APPPOOL\\DefaultAppPool",
        "José",
        "用户",
        "Ανδρέας@example.gr",
        "jean-luc.picard",
        "DOMAIN\\user@x",
        "CONTOSO\\user@dept",  # Sol r4 N1: "@" is legal in a SAM account name
    ],
)
def test_legal_account_names_are_accepted(name: str) -> None:
    """Sol r2 N1 / DeepSeek r2 NB-2: reject only what AD forbids."""
    from gpo_lens.analyst_text import valid_principal_name

    assert valid_principal_name(name)


@pytest.mark.parametrize(
    "name",
    [
        *(f"DOMAIN\\a{ch}b" for ch in '"/[]:;|=,+*?<>'),
        "DOMAIN\\a\x01b",
        "a\\b\\c",
        "\\user",
        "DOMAIN\\",
        "@example.com",
        "user@",
        "user@exa mple.com",
        "x" * 257,
        "RXx2nznYZEGZwOW9vPvIWzfOkcveH8Gw6mtE8TBDbdc",
    ],
)
def test_forbidden_account_names_are_refused(name: str) -> None:
    from gpo_lens.analyst_text import valid_principal_name

    assert not valid_principal_name(name)


def test_xml_entity_declarations_stay_uninspectable_with_a_hint() -> None:
    """Sol r2 N3, decided: keep refusing (an entity can spell the label, and
    expanding it is what defusedxml forbids); the message says what to do.
    A bare external DTD reference is not a declaration and is inspected."""
    benign = '<!DOCTYPE x [<!ENTITY y "hello">]><x>&y;</x>'
    assert cpassword_material(benign) == "uninspectable"
    with pytest.raises(CpasswordInAnalystTextError) as info:
        check_analyst_text(benign, "note")
    assert "<!DOCTYPE" in str(info.value) and "declares an entity" in str(info.value)
    assert cpassword_material('<!DOCTYPE t SYSTEM "http://example.test/"><t/>') is None
    assert cpassword_material("<!DOCTYPE x><x>&amp;</x>") is None


# --- review round 3 regressions ---------------------------------------------------------------


def _v7_db_with_raw_triage(tmp_path: Path, rows: list[tuple[Any, ...]]) -> tuple[Path, int]:
    """Sol r3's probe setup: a v7-marked database with raw legacy rows
    (status, note, rationale, actor, timestamp), values of any storage class."""
    db, finding_id = _legacy_db(tmp_path)
    conn = sqlite3.connect(db)
    try:
        for status, note, rationale, actor, ts in rows:
            conn.execute(
                "INSERT INTO finding_triage (finding_id, status, note, rationale, actor, "
                "timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (finding_id, status, note, rationale, actor, ts),
            )
        conn.commit()
    finally:
        conn.close()
    return db, finding_id


_BLOB_FORMS = {
    "utf-8": _LEGACY_ACTOR.encode(),
    "utf-16-le": _LEGACY_ACTOR.encode("utf-16-le"),
    "utf-16-be": _LEGACY_ACTOR.encode("utf-16-be"),
    # Sol r4 B1 / DeepSeek r4 BLOCKING-1: readings the old guard did not try.
    "utf-32": _LEGACY_ACTOR.encode("utf-32"),
    "utf-32-le": _LEGACY_ACTOR.encode("utf-32-le"),
    "cp500 (EBCDIC)": _LEGACY_ACTOR.encode("cp500"),
    "utf-16-le + trailing byte": _LEGACY_ACTOR.encode("utf-16-le") + b"X",
    "leading byte + utf-16-le": b"X" + _LEGACY_ACTOR.encode("utf-16-le"),
    "utf-16-le misaligned even": b"X" + _LEGACY_ACTOR.encode("utf-16-le") + b"Y",
}


@pytest.mark.parametrize("form", list(_BLOB_FORMS))
def test_v8_migration_never_copies_a_refused_blob(tmp_path: Path, form: str) -> None:
    """Sol r3 B1, r4 B1 / DeepSeek r4 BLOCKING-1: a BLOB actor/note was
    copied verbatim whenever no reading tried showed the token. Now no BLOB
    is copied, whatever its encoding."""
    from gpo_lens.analyst_text import REFUSED_PRINCIPAL_MARKER, REFUSED_TEXT_MARKER

    blob = _BLOB_FORMS[form]
    db, _ = _v7_db_with_raw_triage(tmp_path, [("acknowledged", blob, "", blob, "2025-01-03")])
    with pytest.warns(UserWarning, match=r"2 legacy field"):
        _reopen(db)
    conn = sqlite3.connect(db)
    try:
        active = conn.execute(
            "SELECT typeof(actor), actor, typeof(note), note FROM finding_triage_event"
        ).fetchall()
        record = conn.execute(
            "SELECT payload FROM events WHERE event_type = 'maintenance.analyst_text_substituted'"
        ).fetchone()[0]
        listed = {(r.table, r.column) for r in refusable_rows(conn)}
    finally:
        conn.close()
    assert active == [("text", REFUSED_PRINCIPAL_MARKER, "text", REFUSED_TEXT_MARKER)]
    assert _LEGACY_ACTOR not in record
    assert listed == {("finding_triage", "actor"), ("finding_triage", "note")}
    assert _all_bytes(db).count(blob) == 2  # the two untouched legacy cells only
    payload = json.loads(record)
    assert {x["kind"] for x in payload["substitutions"]} == {"uninspectable"}


def test_v8_migration_storage_class_rule(tmp_path: Path) -> None:
    """Round 4 rule: TEXT checked; NULL/INTEGER/REAL copied; a BLOB is never
    copied — every BLOB becomes the marker as uninspectable (it has no
    declared encoding, so no reading can show it is clean)."""
    from gpo_lens.analyst_text import REFUSED_TEXT_MARKER, migrated_value, stored_kind

    for blob in (b"clean note", b"\xff\xfe\xfd", b""):
        assert migrated_value(blob, "note") == (REFUSED_TEXT_MARKER, "uninspectable")
        assert stored_kind(blob) == "uninspectable"
    assert migrated_value(42, "note") == (42, None)
    assert migrated_value(1.5, "note") == (1.5, None)
    assert migrated_value(None, "note") == (None, None)
    assert migrated_value(object(), "note")[1] == "uninspectable"
    db, _ = _v7_db_with_raw_triage(
        tmp_path, [("acknowledged", b"clean note", "", "alice", "2025-01-05")]
    )
    with pytest.warns(UserWarning, match=r"1 legacy field"):
        _reopen(db)
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT typeof(note), note FROM finding_triage_event").fetchall() == [
            ("text", REFUSED_TEXT_MARKER)
        ]
    finally:
        conn.close()


def test_checker_covers_every_operator_column_the_migration_reads() -> None:
    """Sol r3 B2: the checker and the migration must not drift. Every column
    the v7->v8 copy reads from finding_triage is either a system column or in
    ANALYST_TEXT_COLUMNS, and every operator column it reads is listed."""
    node = INVENTORY["gpo_lens.store"].functions["_migrate_legacy_triage"]
    sql = next(
        c.value
        for c in ast.walk(node)
        if isinstance(c, ast.Constant)
        and isinstance(c.value, str)
        and "FROM finding_triage t" in c.value
    )
    from gpo_lens.analyst_text import LEGACY_TRIAGE_STRUCTURAL

    read = set(re.findall(r"\bt\.(\w+)", sql))
    keys = {"id", "finding_id"}  # the row id and the joined, FK-checked finding id
    operator = {column for table, column in ANALYST_TEXT_COLUMNS if table == "finding_triage"}
    structural = set(LEGACY_TRIAGE_STRUCTURAL)  # validated, and listed by the checker
    assert operator == {"actor", "note", "rationale"}
    assert structural == {"status", "timestamp", "expires_at"}
    assert read - keys == operator | structural
    guarded = GUARDED_FIELDS[("gpo_lens.store", "_copy_legacy_triage_row")]
    assert {re.sub(r"^row\['(\w+)'\]$", r"\1", f) for f in guarded} == operator


def test_v8_migration_marker_event_does_not_swallow_a_clean_row(tmp_path: Path) -> None:
    """Sol r3 N1: a marker event used to satisfy the match for a clean row."""
    from gpo_lens.analyst_text import REFUSED_PRINCIPAL_MARKER, REFUSED_TEXT_MARKER

    db, finding_id = _v7_db_with_raw_triage(
        tmp_path, [("acknowledged", "clean legacy note", "", "alice", "2025-01-04")]
    )
    conn = sqlite3.connect(db)
    try:
        conn.execute(
            "INSERT INTO finding_triage_event (occurrence_id, action, actor, occurred_at, "
            "note, rationale) VALUES (?, 'acknowledged', ?, '2025-01-04', ?, ?)",
            (finding_id, REFUSED_PRINCIPAL_MARKER, REFUSED_TEXT_MARKER, REFUSED_TEXT_MARKER),
        )
        conn.commit()
    finally:
        conn.close()
    _reopen(db)
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute("SELECT actor, note FROM finding_triage_event ORDER BY id").fetchall()
    finally:
        conn.close()
    assert rows == [
        (REFUSED_PRINCIPAL_MARKER, REFUSED_TEXT_MARKER),
        ("alice", "clean legacy note"),
    ]


def test_v8_migration_keeps_multiplicity(tmp_path: Path) -> None:
    """One existing copy stands for one legacy row: of three identical legacy
    rows with one already copied, exactly two are added."""
    row = ("acknowledged", "same", "", "alice", "2025-01-06")
    db, finding_id = _v7_db_with_raw_triage(tmp_path, [row, row, row])
    conn = sqlite3.connect(db)
    try:
        conn.execute(
            "INSERT INTO finding_triage_event (occurrence_id, action, actor, occurred_at, "
            "note, rationale) VALUES (?, 'acknowledged', 'alice', '2025-01-06', 'same', '')",
            (finding_id,),
        )
        conn.commit()
    finally:
        conn.close()
    _reopen(db)
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM finding_triage_event").fetchone()[0] == 3
    finally:
        conn.close()


@pytest.mark.parametrize(
    "name",
    [
        " ",
        "a b\\ ",
        "a@b\\user",
        "a@b@c",
        "NT AUTHORITY SYSTEM",
        "NT AUTHORITY\x85SYSTEM",
        "DOM\\ali‮ce",
        "DOM\\ali​ce",
        "DOM\\a b",
        "DOM\\ali\rce",
        "DOM\\ali\tce",
        "DOM\\ali\x7fce",
        " DOM\\alice",
        "DOM \\alice",
        "DOM\\alice ",
    ],
)
def test_names_with_control_format_or_stray_space_are_refused(name: str) -> None:
    """Sol r3 N2 / DeepSeek r3 NB-2/NB-3: the code does what the docs say."""
    from gpo_lens.analyst_text import valid_principal_name

    assert not valid_principal_name(name)


# --- review round 4 regressions ---------------------------------------------------------------


def _provenance(db: Path) -> list[tuple[int, int]]:
    conn = sqlite3.connect(db)
    try:
        return conn.execute(
            "SELECT legacy_id, event_id FROM finding_triage_legacy_copy ORDER BY legacy_id"
        ).fetchall()
    finally:
        conn.close()


def test_v8_migration_records_provenance_and_replays_exactly(tmp_path: Path) -> None:
    """Sol r4 B2: re-runs copy exactly the legacy rows not yet recorded. The
    copy re-runs on every open below the current schema (an upgrade from v8-v10,
    or after a refused v11 scrub / pending purge, which leave the schema at 10
    with the copy already committed); this replays that by re-marking v7."""
    db, finding_id = _legacy_db(tmp_path)
    ids = _seed_legacy_triage(db, finding_id)
    with pytest.warns(UserWarning):
        _reopen(db)
    first = _provenance(db)
    assert [legacy for legacy, _ in first] == sorted(ids.values())
    conn = sqlite3.connect(db)
    try:
        # A new legacy row appears (as if written by an old release) and the
        # earlier rows' text was since redacted in place.
        new_id = conn.execute(
            "INSERT INTO finding_triage (finding_id, status, note, rationale, actor, timestamp) "
            "VALUES (?, 'acknowledged', 'late row', '', 'carol', '2025-02-01')",
            (finding_id,),
        ).lastrowid
        conn.execute("UPDATE finding_triage SET note = '[redacted cpassword]'")
        conn.execute("PRAGMA user_version = 7")
        conn.commit()
    finally:
        conn.close()
    _reopen(db)
    second = _provenance(db)
    assert second[: len(first)] == first
    assert [legacy for legacy, _ in second] == [*sorted(ids.values()), new_id]
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM finding_triage_event").fetchone()[0] == 5
    finally:
        conn.close()


def _sol_r4_db(tmp_path: Path, legacy_notes: list[str], event_notes: list[str]) -> Path:
    db, finding_id = _legacy_db(tmp_path)
    conn = sqlite3.connect(db)
    try:
        for note in legacy_notes:
            conn.execute(
                "INSERT INTO finding_triage (finding_id, status, note, rationale, actor, "
                "timestamp) VALUES (?, 'acknowledged', ?, '', 'alice', '2025-01-03')",
                (finding_id, note),
            )
        for note in event_notes:
            conn.execute(
                "INSERT INTO finding_triage_event (occurrence_id, action, actor, occurred_at, "
                "note, rationale) VALUES (?, 'acknowledged', 'alice', '2025-01-03', ?, '')",
                (finding_id, note),
            )
        conn.commit()
    finally:
        conn.close()
    return db


_CLEAN_REDACTED = "reviewed [redacted cpassword] in source"


def test_sol_r4_greedy_probe_neither_duplicates_nor_misassigns(tmp_path: Path) -> None:
    """Sol r4 B2 (greedy): legacy [clean, refused]; existing events [a marker,
    the exact clean note]. Without provenance only an exact verbatim copy (what
    pre-fix releases wrote) stands for a legacy row: the clean row gets the
    exact event; the marker is not a copy of anything (pre-fix releases never
    wrote markers, and this release's own copies carry provenance), so the
    refused row is copied once as a marker."""
    from gpo_lens.analyst_text import REFUSED_TEXT_MARKER

    db = _sol_r4_db(
        tmp_path, [_CLEAN_REDACTED, _LEGACY_ACTOR], [REFUSED_TEXT_MARKER, _CLEAN_REDACTED]
    )
    with pytest.warns(UserWarning, match=r"1 legacy field"):
        _reopen(db)
    conn = sqlite3.connect(db)
    try:
        notes = conn.execute("SELECT id, note FROM finding_triage_event ORDER BY id").fetchall()
    finally:
        conn.close()
    assert notes == [(1, REFUSED_TEXT_MARKER), (2, _CLEAN_REDACTED), (3, REFUSED_TEXT_MARKER)]
    assert _provenance(db) == [(1, 2), (2, 3)]


def test_sol_r4_skip_probe_copies_the_clean_row(tmp_path: Path) -> None:
    """Sol r4 B2 (skip): a lone marker event no longer swallows a clean row."""
    from gpo_lens.analyst_text import REFUSED_TEXT_MARKER

    db = _sol_r4_db(tmp_path, [_CLEAN_REDACTED], [REFUSED_TEXT_MARKER])
    _reopen(db)
    conn = sqlite3.connect(db)
    try:
        notes = conn.execute("SELECT id, note FROM finding_triage_event ORDER BY id").fetchall()
    finally:
        conn.close()
    assert notes == [(1, REFUSED_TEXT_MARKER), (2, _CLEAN_REDACTED)]
    assert _provenance(db) == [(1, 2)]


def _sqlite_compatible(conn: sqlite3.Connection, a: tuple[Any, ...], b: tuple[Any, ...]) -> bool:
    """SQLite's own verdict: ``=`` on every field, ``IS`` on expires_at."""
    *fa, ea = a
    *fb, eb = b
    clauses = " AND ".join(["? = ?"] * len(fa) + ["? IS ?"])
    params: list[Any] = [x for pair in zip(fa, fb, strict=True) for x in pair] + [ea, eb]
    return bool(conn.execute(f"SELECT coalesce({clauses}, 0)", params).fetchone()[0])  # noqa: S608


def _brute_force_max(n_legacy: int, n_events: int, ok: list[list[bool]]) -> int:
    best = 0

    def walk(i: int, used: frozenset[int], size: int) -> None:
        nonlocal best
        if size + (n_legacy - i) <= best:
            return
        if i == n_legacy:
            best = max(best, size)
            return
        for j in range(n_events):
            if j not in used and ok[i][j]:
                walk(i + 1, used | {j}, size + 1)
        walk(i + 1, used, size)

    walk(0, frozenset(), 0)
    return best


def test_legacy_matching_is_a_maximum_one_to_one_matching_under_sqlite_equality() -> None:
    """Random differential against a brute-force maximum matching, with
    compatibility decided by SQLite itself (storage classes included)."""
    from gpo_lens.store import legacy_triage_matches

    rng = random.Random(4)  # noqa: S311 - reproducible test data
    pool: list[Any] = [
        "a",
        "b",
        "1",
        1,
        1.0,
        2,
        b"a",
        bytearray(b"a"),
        None,
        "",
        "[refused analyst text]",
        # Sol r5 B1: 53- and 64-bit boundaries, signed zero, infinities, NaN
        # (which SQLite stores as NULL).
        2**53,
        2**53 + 1,
        float(2**53),
        -(2**53) - 1,
        2**63 - 1,
        -(2**63),
        float(2**63),
        -0.0,
        0,
        float("inf"),
        float("-inf"),
        float("nan"),
    ]
    conn = sqlite3.connect(":memory:")
    try:
        for _ in range(400):

            def fields() -> tuple[Any, ...]:
                return (
                    rng.choice([1, 2, 2**53, 2**53 + 1, float(2**53)]),
                    "acknowledged",
                    "t",
                    rng.choice(pool),
                    rng.choice(pool),
                    rng.choice(pool[:3]),
                    rng.choice([None, "x", 2**53, 2**53 + 1, float("nan")]),
                )

            legacy = [(i + 1, fields()) for i in range(rng.randrange(0, 6))]
            events = [(j + 10, fields()) for j in range(rng.randrange(0, 6))]
            ok = [[_sqlite_compatible(conn, lf, ef) for _, ef in events] for _, lf in legacy]
            got = legacy_triage_matches(legacy, events)
            assert len(set(got.values())) == len(got)  # one event per legacy row
            index_l = {lid: i for i, (lid, _) in enumerate(legacy)}
            index_e = {eid: j for j, (eid, _) in enumerate(events)}
            for lid, eid in got.items():
                assert ok[index_l[lid]][index_e[eid]], (legacy, events, got)
            assert len(got) == _brute_force_max(len(legacy), len(events), ok)
    finally:
        conn.close()


def test_checker_reports_a_blob_event_payload(web_db: Path) -> None:
    """Sol r4 N2: a UTF-32 JSON payload naming a principal was invisible."""
    conn = sqlite3.connect(web_db)
    try:
        event_id = conn.execute(
            "INSERT INTO events (timestamp, event_type, schema_version, payload) "
            "VALUES ('2025-01-01T00:00:00+00:00', 'audit.ingest', 1, ?)",
            (json.dumps({"principal": _LEGACY_ACTOR}).encode("utf-32"),),
        ).lastrowid
        conn.commit()
        rows = {(r.table, r.column, r.row_id, r.kind) for r in refusable_rows(conn)}
    finally:
        conn.close()
    assert rows == {("events", "payload", event_id, "uninspectable")}


# --- review round 5 regressions ---------------------------------------------------------------


def test_match_keys_agree_with_sqlite_on_numeric_edges() -> None:
    """Sol r5 B1 / DeepSeek r5 NB-2/NB-6: keys are lossless and hashable."""
    from gpo_lens.store import _is_key, _match_key

    values: list[Any] = [
        2**53,
        2**53 + 1,
        float(2**53),
        -(2**53),
        -(2**53) - 1,
        2**63 - 1,
        -(2**63),
        float(2**63),
        -0.0,
        0,
        0.0,
        1,
        1.0,
        True,
        float("inf"),
        float("-inf"),
        "1",
        b"1",
        bytearray(b"1"),
        memoryview(b"1"),
    ]
    conn = sqlite3.connect(":memory:")
    try:
        for a in values:
            for b in values:
                bind_a = bytes(a) if isinstance(a, bytearray | memoryview) else a
                bind_b = bytes(b) if isinstance(b, bytearray | memoryview) else b
                same = conn.execute("SELECT ? = ?", (bind_a, bind_b)).fetchone()[0]
                assert (_match_key(a) == _match_key(b)) == bool(same), (a, b)
                if same:
                    assert hash(_match_key(a)) == hash(_match_key(b)), (a, b)
        assert _match_key(None) != _match_key(None)  # NULL = NULL is not true
        assert _is_key(None) == _is_key(float("nan"))  # NaN is stored as NULL
    finally:
        conn.close()


def _add_finding(conn: sqlite3.Connection, finding_id: int) -> None:
    conn.execute(
        "INSERT INTO finding (id, finding_key, rule_id, subject_identity, severity, summary, "
        "first_seen_snapshot, last_seen_snapshot) "
        "VALUES (?, ?, 'rule', 'subject', 'medium', 'summary', 1, 1)",
        (finding_id, f"key-{finding_id}"),
    )


def test_sol_r5_large_integer_probe(tmp_path: Path) -> None:
    """Sol r5 B1: finding ids 2**53 and 2**53+1 collapsed through float."""
    from gpo_lens.store import legacy_triage_matches

    lower, upper = 2**53, 2**53 + 1
    assert (
        legacy_triage_matches(
            [(1, (lower, "acknowledged", "t", "alice", "same", "", None))],
            [(10, (upper, "acknowledged", "t", "alice", "same", "", None))],
        )
        == {}
    )
    db, _ = _legacy_db(tmp_path)
    conn = sqlite3.connect(db)
    try:
        for finding_id in (lower, upper):
            _add_finding(conn, finding_id)
            conn.execute(
                "INSERT INTO finding_triage (finding_id, status, note, rationale, actor, "
                "timestamp) VALUES (?, 'acknowledged', 'same', '', 'alice', '2025-01-03')",
                (finding_id,),
            )
        upper_event = conn.execute(
            "INSERT INTO finding_triage_event (occurrence_id, action, actor, occurred_at, "
            "note, rationale) VALUES (?, 'acknowledged', 'alice', '2025-01-03', 'same', '')",
            (upper,),
        ).lastrowid
        conn.commit()
    finally:
        conn.close()
    _reopen(db)
    conn = sqlite3.connect(db)
    try:
        events = conn.execute(
            "SELECT id, occurrence_id FROM finding_triage_event ORDER BY id"
        ).fetchall()
        provenance = dict(
            conn.execute(
                "SELECT t.finding_id, p.event_id FROM finding_triage_legacy_copy p "
                "JOIN finding_triage t ON t.id = p.legacy_id"
            ).fetchall()
        )
    finally:
        conn.close()
    assert sorted(occ for _, occ in events) == [lower, upper]
    assert provenance[upper] == upper_event
    assert dict(events)[provenance[lower]] == lower


def test_legacy_copy_columns_cover_every_event_column() -> None:
    """Sol r5 B2: every finding_triage_event column is compared or pinned to
    the value a legacy copy writes, so a new column cannot be omitted."""
    from gpo_lens.store import LEGACY_COPY_COMPARED, LEGACY_COPY_NULL, init_db

    conn = sqlite3.connect(":memory:")
    try:
        init_db(conn)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(finding_triage_event)")}
    finally:
        conn.close()
    assert columns == {"id", *LEGACY_COPY_COMPARED, *LEGACY_COPY_NULL}
    assert not set(LEGACY_COPY_COMPARED) & set(LEGACY_COPY_NULL)


def test_sol_r5_supersedes_probe(tmp_path: Path) -> None:
    """Sol r5 B2: an event with a supersedes link is not a verbatim copy."""
    db, finding_id = _v7_db_with_raw_triage(
        tmp_path, [("acknowledged", "same", "", "alice", "2025-01-03")]
    )
    conn = sqlite3.connect(db)
    try:
        first = conn.execute(
            "INSERT INTO finding_triage_event (occurrence_id, action, actor, occurred_at, note, "
            "rationale) VALUES (?, 'commented', 'bob', '2025-01-02', 'other', '')",
            (finding_id,),
        ).lastrowid
        conn.execute(
            "INSERT INTO finding_triage_event (occurrence_id, action, actor, occurred_at, note, "
            "rationale, supersedes_event_id) "
            "VALUES (?, 'acknowledged', 'alice', '2025-01-03', 'same', '', ?)",
            (finding_id, first),
        )
        conn.commit()
    finally:
        conn.close()
    _reopen(db)
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute(
            "SELECT id, supersedes_event_id FROM finding_triage_event ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    assert rows == [(1, None), (2, 1), (3, None)]
    assert _provenance(db) == [(1, 3)]


# An unlabelled cpassword-shaped token: the v11 scrub (same upgrade) does not
# discover it, so these tests see the copy's own behaviour.
_SMUGGLED = _LEGACY_ACTOR
_LABELLED_SMUGGLED = "cpassword=AAECAwQFBgcICQoLDA0ODw=="  # DeepSeek r5's exact probe


def test_unknown_legacy_status_becomes_a_commented_event(tmp_path: Path) -> None:
    """DeepSeek r5 NB-1: free text in finding_triage.status reached the
    action column. An unknown status now copies as 'commented' (no status
    effect), the substitution is recorded, and the checker lists the row."""
    db, _ = _v7_db_with_raw_triage(tmp_path, [(_SMUGGLED, "kept note", "", "alice", "2025-01-03")])
    with pytest.warns(UserWarning, match=r"1 legacy field"):
        _reopen(db)
    conn = sqlite3.connect(db)
    try:
        events = conn.execute("SELECT action, note, rationale FROM finding_triage_event").fetchall()
        record = conn.execute(
            "SELECT payload FROM events WHERE event_type = 'maintenance.analyst_text_substituted'"
        ).fetchone()[0]
        listed = {(r.table, r.column, r.kind) for r in refusable_rows(conn)}
    finally:
        conn.close()
    assert events == [("commented", "kept note", "")]
    assert _SMUGGLED not in record and '"field": "status"' in record
    assert ("finding_triage", "status", "uninspectable") in listed


# Sol r6 B1: shape-valid but impossible times (the fold cannot read them; an
# unreadable expiry used to fold to a permanent risk acceptance).
_IMPOSSIBLE_TIMES = [
    "2025-99-99T99:99:99Z",
    "2025-13-01T00:00:00+00:00",  # month
    "2025-01-32T00:00:00+00:00",  # day
    "2025-02-30T00:00:00Z",  # day in month
    "2025-02-29T00:00:00+00:00",  # not a leap year
    "2025-01-01T25:00:00+00:00",  # hour
    "2025-01-01T10:60:00+00:00",  # minute
    "2025-01-01T10:00:60+00:00",  # second
    "0001-01-01T00:00:00+05:00",  # UTC conversion overflows
]


@pytest.mark.parametrize(
    ("field", "timestamp", "expires"),
    [
        ("timestamp", _SMUGGLED, None),
        ("timestamp", "yesterday", None),
        ("timestamp", b"2025-01-03", None),
        ("expires_at", "2025-01-03", _SMUGGLED),
        ("expires_at", "2025-01-03", 20251399),  # stored as TEXT; month 13
        ("expires_at", "2025-01-03", ""),
        *(("timestamp", bad, None) for bad in _IMPOSSIBLE_TIMES),
        *(("expires_at", "2025-01-03", bad) for bad in _IMPOSSIBLE_TIMES),
    ],
)
def test_malformed_legacy_time_withholds_the_row(
    tmp_path: Path, field: str, timestamp: Any, expires: Any
) -> None:
    """DeepSeek r5 NB-1: a timestamp or expiry that is not a timestamp is not
    copied (no neutral replacement exists); the row is recorded as withheld so
    a re-run does not report it again, and the checker lists it."""
    db, finding_id = _legacy_db(tmp_path)
    conn = sqlite3.connect(db)
    try:
        legacy_id = conn.execute(
            "INSERT INTO finding_triage (finding_id, status, note, rationale, actor, timestamp, "
            "expires_at) VALUES (?, 'accepted_risk', 'n', 'r', 'alice', ?, ?)",
            (finding_id, timestamp, expires),
        ).lastrowid
        conn.commit()
    finally:
        conn.close()
    with pytest.warns(UserWarning, match=r"1 row\(s\) with a malformed timestamp"):
        _reopen(db)
    conn = sqlite3.connect(db)
    try:
        conn.execute("PRAGMA user_version = 7")
        conn.commit()
    finally:
        conn.close()
    _reopen(db)  # replay: nothing new, no second report
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM finding_triage_event").fetchone()[0] == 0
        records = conn.execute(
            "SELECT payload FROM events WHERE event_type = 'maintenance.analyst_text_substituted'"
        ).fetchall()
        listed = {(r.table, r.column, r.row_id) for r in refusable_rows(conn)}
    finally:
        conn.close()
    assert _provenance(db) == [(legacy_id, None)]
    assert len(records) == 1 and _SMUGGLED not in records[0][0]
    assert ("finding_triage", field, legacy_id) in listed


@pytest.mark.parametrize("column", ["status", "timestamp"])
def test_deepseek_r5_labelled_value_in_a_structural_column_never_reaches_the_log(
    tmp_path: Path, column: str
) -> None:
    """DeepSeek r5 NB-1, exact probe: the labelled value made the v11 scrub
    refuse (correctly: a structural column) after the copy had already put it
    into the event log. The copy no longer carries it; the scrub still refuses
    and the checker lists the legacy row."""
    from gpo_lens.redaction import CredentialInIdentityError

    status = _LABELLED_SMUGGLED if column == "status" else "acknowledged"
    timestamp = _LABELLED_SMUGGLED if column == "timestamp" else "2025-01-03"
    db, _ = _v7_db_with_raw_triage(tmp_path, [(status, "n", "", "alice", timestamp)])
    with pytest.warns(UserWarning), pytest.raises(CredentialInIdentityError):
        _reopen(db)
    conn = sqlite3.connect(db)
    try:
        log = conn.execute(
            "SELECT action || occurred_at || note FROM finding_triage_event"
        ).fetchall()
        listed = {(r.table, r.column) for r in refusable_rows(conn)}
    finally:
        conn.close()
    assert all(_LABELLED_SMUGGLED not in row[0] for row in log)
    assert ("finding_triage", column) in listed


def test_legacy_time_is_accepted_exactly_when_the_fold_can_read_it() -> None:
    """Sol r6 B1, property: for any string, the legacy validation accepts a
    timestamp/expiry exactly when the triage fold's parser returns a datetime.
    Mutations of valid timestamps, with random characters, explore the edges."""
    from gpo_lens.analyst_text import legacy_triage_field_ok
    from gpo_lens.findings import _parse_triage_dt

    rng = random.Random(6)  # noqa: S311 - reproducible test data
    seeds = [
        "2026-10-06T00:08:24.632435+00:00",
        "2025-01-03",
        "2024-02-29T23:59:59Z",
        "2025-W01-1T10:00",
        "20250103T101010Z",
        "9999-12-31T23:59:59-05:00",
        "0001-01-01T00:00:00+00:00",
        *_IMPOSSIBLE_TIMES,
    ]
    alphabet = "0123456789-:.+,TWZtz xX\u0660\uff10" + "cpasword="
    accepted = 0
    for _ in range(30_000):
        text = list(rng.choice(seeds))
        for _ in range(rng.randrange(0, 3)):
            at = rng.randrange(len(text) + 1)
            roll = rng.random()
            if roll < 0.4 and text:
                text[min(at, len(text) - 1)] = rng.choice(alphabet)
            elif roll < 0.7:
                text.insert(at, rng.choice(alphabet))
            elif text:
                text.pop(min(at, len(text) - 1))
        value = "".join(text)
        readable = _parse_triage_dt(value) is not None
        accepted += readable
        for field in ("timestamp", "expires_at"):
            assert legacy_triage_field_ok(field, value) is readable, (field, value)
        if readable:
            assert cpassword_material(value) is None
    assert 1_000 < accepted < 29_000  # both sides of the boundary were explored
    for value in _IMPOSSIBLE_TIMES:
        assert _parse_triage_dt(value) is None
        assert not legacy_triage_field_ok("expires_at", value)


def test_provenance_ddl_rolls_back_with_a_failed_copy(tmp_path: Path) -> None:
    """Sol r5 N2: the lazy CREATE TABLE is inside the copy's transaction, so
    a copy that fails leaves no table behind."""
    db, _ = _v7_db_with_raw_triage(tmp_path, [("acknowledged", "n", "", "alice", "2025-01-03")])
    conn = sqlite3.connect(db)
    try:
        conn.execute(
            "CREATE TRIGGER fail_copy BEFORE INSERT ON finding_triage_event "
            "BEGIN SELECT RAISE(ABORT, 'injected'); END"
        )
        conn.commit()
    finally:
        conn.close()
    from gpo_lens.store import init_db

    conn = sqlite3.connect(db)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="injected"):
            init_db(conn)
        conn.rollback()
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    finally:
        conn.close()
    assert "finding_triage_legacy_copy" not in tables


# --- review round 7 regressions ---------------------------------------------------------------


def _event_db(tmp_path: Path) -> tuple[sqlite3.Connection, int]:
    from gpo_lens.store import init_db

    conn = sqlite3.connect(tmp_path / "events.sqlite3")
    init_db(conn)
    conn.execute("INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')")
    finding_id = conn.execute(
        "INSERT INTO finding (finding_key, rule_id, subject_identity, severity, summary, "
        "first_seen_snapshot, last_seen_snapshot) "
        "VALUES ('key', 'rule', 'subject', 'medium', 'summary', 1, 1)"
    ).lastrowid
    return conn, int(finding_id or 0)


def _event(conn: sqlite3.Connection, finding_id: int, action: str, at: str, expires: Any) -> int:
    return int(
        conn.execute(
            "INSERT INTO finding_triage_event (occurrence_id, action, actor, occurred_at, note, "
            "rationale, expires_at) VALUES (?, ?, 'alice', ?, 'n', 'r', ?)",
            (finding_id, action, at, expires),
        ).lastrowid
        or 0
    )


def _both_folds(conn: sqlite3.Connection, finding_id: int, as_of: datetime) -> tuple[Any, Any]:
    from gpo_lens.findings import accepted_risk_register, get_triage_status, load_triage_status_map

    status = get_triage_status(conn, finding_id)
    assert load_triage_status_map(conn)[finding_id] == status
    register = [
        r for r in accepted_risk_register(conn, as_of=as_of) if r.occurrence_id == finding_id
    ]
    return status, register


_IMPOSSIBLE_EXPIRY = "2025-02-30T00:00:00Z"


def test_sol_r7_already_copied_bad_expiry_is_never_permanent(tmp_path: Path) -> None:
    """Sol r7 B1, probe 1: an event with an unreadable expiry, already copied
    (provenance recorded), folded to a permanent acceptance in both views."""
    conn, finding_id = _event_db(tmp_path)
    try:
        legacy_id = conn.execute(
            "INSERT INTO finding_triage (finding_id, status, note, rationale, actor, timestamp, "
            "expires_at) VALUES (?, 'accepted_risk', 'n', 'r', 'alice', "
            "'2025-01-01T00:00:00Z', ?)",
            (finding_id, _IMPOSSIBLE_EXPIRY),
        ).lastrowid
        event_id = _event(
            conn, finding_id, "accepted_risk", "2025-01-01T00:00:00Z", _IMPOSSIBLE_EXPIRY
        )
        conn.execute(
            "CREATE TABLE finding_triage_legacy_copy "
            "(legacy_id INTEGER PRIMARY KEY, event_id INTEGER UNIQUE)"
        )
        conn.execute("INSERT INTO finding_triage_legacy_copy VALUES (?, ?)", (legacy_id, event_id))
        conn.commit()
        from gpo_lens.store import init_db

        init_db(conn)  # the migration needs no special case: the readers are strict
        status, register = _both_folds(conn, finding_id, datetime(2030, 1, 1, tzinfo=UTC))
        listed = {(r.table, r.column, r.row_id) for r in refusable_rows(conn)}
    finally:
        conn.close()
    assert status.status == "open" and status.expires_at is None
    assert status.integrity and f"event {event_id}" in status.integrity[0]
    assert _IMPOSSIBLE_EXPIRY not in " ".join(status.integrity)
    assert len(register) == 1 and register[0].is_expired and register[0].integrity
    assert ("finding_triage_event", "expires_at", event_id) in listed
    assert ("finding_triage", "expires_at", legacy_id) in listed


def test_sol_r7_v10_recognised_bad_copy_is_never_permanent(tmp_path: Path) -> None:
    """Sol r7 B1, probe 2: a pre-provenance exact copy with an unreadable
    expiry is recognised (provenance recorded, nothing rewritten) and the
    strict readers then treat the acceptance as expired."""
    db, finding_id = _legacy_db(tmp_path)
    conn = sqlite3.connect(db)
    try:
        legacy_id = conn.execute(
            "INSERT INTO finding_triage (finding_id, status, note, rationale, actor, timestamp, "
            "expires_at) VALUES (?, 'accepted_risk', 'n', 'r', 'alice', "
            "'2025-01-01T00:00:00Z', ?)",
            (finding_id, _IMPOSSIBLE_EXPIRY),
        ).lastrowid
        event_id = _event(
            conn, finding_id, "accepted_risk", "2025-01-01T00:00:00Z", _IMPOSSIBLE_EXPIRY
        )
        conn.execute("PRAGMA user_version = 10")
        conn.commit()
    finally:
        conn.close()
    _reopen(db)
    assert _provenance(db) == [(legacy_id, event_id)]
    conn = sqlite3.connect(db)
    try:
        status, register = _both_folds(conn, finding_id, datetime(2030, 1, 1, tzinfo=UTC))
    finally:
        conn.close()
    assert status.status == "open" and status.integrity
    assert register[0].is_expired and register[0].integrity


@pytest.mark.parametrize("unreadable_first", [False, True])
def test_unreadable_event_time_fails_both_folds_closed(
    tmp_path: Path, unreadable_first: bool
) -> None:
    """Sol r7 B1: a year-9999 reopen whose UTC conversion overflows sorted
    before a 2025 acceptance (datetime.min placeholder). Any unreadable time
    now fails the history closed: open, no active acceptance, a note."""
    conn, finding_id = _event_db(tmp_path)
    try:
        overflow = "9999-12-31T23:59:59-05:00"
        if unreadable_first:
            bad = _event(conn, finding_id, "accepted_risk", overflow, None)
            _event(conn, finding_id, "acknowledged", "2025-01-01T00:00:00Z", None)
        else:
            _event(conn, finding_id, "accepted_risk", "2025-01-01T00:00:00Z", None)
            bad = _event(conn, finding_id, "reopened", overflow, None)
        conn.commit()
        status, register = _both_folds(conn, finding_id, datetime(2030, 1, 1, tzinfo=UTC))
        listed = {(r.table, r.column, r.row_id) for r in refusable_rows(conn)}
    finally:
        conn.close()
    assert status.status == "open" and status.expires_at is None and status.rationale == ""
    assert status.integrity == (
        f"occurrence {finding_id}: triage event {bad} has an unreadable timestamp, so the "
        "order of its decisions cannot be established; no triage decision is applied",
    )
    assert len(register) == 1 and register[0].is_expired and register[0].integrity
    assert ("finding_triage_event", "occurred_at", bad) in listed


def test_expiry_sweep_ignores_a_history_that_failed_closed(tmp_path: Path) -> None:
    from gpo_lens.findings import expire_risk_acceptances

    conn, finding_id = _event_db(tmp_path)
    try:
        _event(conn, finding_id, "accepted_risk", "2025-01-01T00:00:00Z", _IMPOSSIBLE_EXPIRY)
        conn.commit()
        assert expire_risk_acceptances(conn, now=datetime(2030, 1, 1, tzinfo=UTC)) == 0
    finally:
        conn.close()


def test_readable_expiry_still_folds_as_before(tmp_path: Path) -> None:
    conn, finding_id = _event_db(tmp_path)
    try:
        _event(conn, finding_id, "accepted_risk", "2025-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
        conn.commit()
        status, register = _both_folds(conn, finding_id, datetime(2025, 6, 1, tzinfo=UTC))
    finally:
        conn.close()
    assert status.status == "accepted_risk" and status.integrity == ()
    assert register[0].is_expired is False and register[0].integrity == ()


def test_every_triage_event_reader_goes_through_the_strict_row_reader() -> None:
    """Sol r7: TriageEvent is built only by findings._triage_event_from_row;
    the strict parser is called only there and by the legacy validation and
    checker; every SQL that reads finding_triage_event times is in a reader
    that uses the row reader (or is the migration/checker); and events are
    ordered (_triage_order) only after unreadable times were ruled out."""
    built = {
        (m, w)
        for m, inv in INVENTORY.items()
        for w, node in inv.functions.items()
        for call in ast.walk(node)
        if isinstance(call, ast.Call)
        and inv._name(call.func) == "TriageEvent"
        # nested functions are walked by their parent too: keep the innermost
        and not any(
            isinstance(inner, ast.FunctionDef | ast.AsyncFunctionDef)
            and inner is not node
            and call in ast.walk(inner)
            for inner in ast.walk(node)
        )
    }
    assert built == {("gpo_lens.findings", "_triage_event_from_row")}

    parsers = {
        (m, w)
        for m, inv in INVENTORY.items()
        for w, node in inv.functions.items()
        for call in ast.walk(node)
        if isinstance(call, ast.Call)
        and inv._name(call.func) in {"_parse_triage_dt", "parse_triage_dt"}
    }
    assert parsers == {
        ("gpo_lens.findings", "_triage_event_from_row"),
        ("gpo_lens.findings", "_parse_triage_dt"),
        ("gpo_lens.analyst_text", "legacy_triage_field_ok"),
        ("gpo_lens.analyst_text", "refusable_rows"),
    }

    time_readers = {
        (m, w)
        for m, inv in INVENTORY.items()
        for w, node in inv.functions.items()
        for c in ast.walk(node)
        if isinstance(c, ast.Constant)
        and isinstance(c.value, str)
        and "FROM finding_triage_event" in c.value
        and re.search(r"\b(?:occurred_at|expires_at)\b", c.value)
        and "SELECT" in c.value
    }
    row_reader_users = {
        (m, w)
        for m, inv in INVENTORY.items()
        for w, node in inv.functions.items()
        if any(
            isinstance(c, ast.Call) and inv._name(c.func) == "_triage_event_from_row"
            for c in ast.walk(node)
        )
    }
    classified = {
        ("gpo_lens.analyst_text", "refusable_rows"),  # strict parser, lists bad rows
    }
    assert time_readers - row_reader_users == classified
    assert "FROM finding_triage_event" in "".join(
        c.value
        for c in ast.walk(INVENTORY["gpo_lens.findings"].functions["accepted_risk_register"])
        if isinstance(c, ast.Constant) and isinstance(c.value, str)
    )

    ordered = {
        (m, w)
        for m, inv in INVENTORY.items()
        for w, node in inv.functions.items()
        for c in ast.walk(node)
        if isinstance(c, ast.Name | ast.Attribute)
        and (c.id if isinstance(c, ast.Name) else c.attr) == "_triage_order"
    }
    assert ordered == {
        ("gpo_lens.findings", "fold_triage"),
        ("gpo_lens.findings", "load_triage_events"),
        ("gpo_lens.findings", "accepted_risk_register"),
    }


# --- inventory: every write path goes through the guard -------------------------------------
#
# Each sink and each request source below is either GUARDED or classified with
# the reason it carries no operator-supplied text. GUARDED means: for every
# listed field, the function passes that field (``field``, ``field[:n]`` or
# ``checked_slice(field, n)``) to a guard call (check_analyst_text, or a helper
# that calls it) on a line before its first sink. A new sink, source, payload
# key or field fails these tests until it is guarded or classified. Removing
# the only guard for a field fails them; a field guarded twice (a truncating
# writer) is covered by TRUNCATING_WRITERS, which requires both stages. Other
# redundant guards are not individually required.
#
# Blind spots (this is a static heuristic, not dataflow analysis):
# * SQL writes are found from string constants and f-strings; SQL assembled by
#   concatenation, ``.format`` or in another module's helper is not seen, and a
#   new table/column of operator text must be added to ANALYST_TEXT_COLUMNS by
#   hand before it is inventoried at all.
# * "Guarded" is per function and per field name: a value renamed or copied to
#   another variable before the sink, or a sink reached through a helper in
#   another function, is not traced.
# * Event payloads are checked by literal dict keys; a payload built elsewhere
#   (the ingest change events, the scrub record) is classified as a whole.
# * Request sources are the declared FastAPI parameters (Form/File/Body/Header/
#   Query/Cookie), POST-route parameters, ``.headers``/``.cookies``/
#   ``.query_params`` reads, ASGI ``scope["headers"]`` and request body reads.
#   ``request.state``, path parameters of GET routes, and anything a template
#   renders are not inventoried; GET routes are asserted to hold no sink, but a
#   sink reached through a helper they call is not seen.
# * Writes outside SQLite, the event log, audit.log and model calls (files,
#   subprocesses, other network egress) are not inventoried.

GUARD_CALLS = frozenset(
    {"check_analyst_text", "_refused", "_guard_payload", "valid_principal_name", "migrated_value"}
)
ANALYST_TABLES = frozenset(table for table, _ in ANALYST_TEXT_COLUMNS)

# Per guarded function, the field names each needing its own guard call.
GUARDED_FIELDS: dict[tuple[str, str], frozenset[str]] = {
    ("gpo_lens.findings", "append_triage_event"): frozenset({"note", "rationale", "actor"}),
    ("gpo_lens.findings", "triage_finding"): frozenset({"note", "actor"}),
    ("gpo_lens.events", "append_event"): frozenset({"payload"}),
    ("gpo_lens.events", "append_events"): frozenset({"payload"}),
    ("gpo_lens.web.routes.ask", "register.ask_post"): frozenset({"question", "sanitized"}),
    ("gpo_lens.cli._narration", "cmd_ask"): frozenset({"args.question"}),
    ("gpo_lens.cli._narration", "cmd_explain_setting"): frozenset({"identity"}),
    ("gpo_lens.web.auth", "_forwarded_user"): frozenset({"cleaned"}),
    ("gpo_lens.store", "_copy_legacy_triage_row"): frozenset(
        {"row['actor']", "row['note']", "rationale"}
    ),
}

SQL_WRITERS = {
    # Operator-text tables (finding_triage_event, finding_triage).
    ("gpo_lens.findings", "append_triage_event"): "GUARDED",
    ("gpo_lens.findings", "expire_risk_acceptances"): (
        "system text: actor 'system', note 'Risk acceptance expired at <timestamp>'"
    ),
    # v7->v8 copy: a refused legacy value is copied as a marker; the legacy
    # row is left as it was and analyst-text-check reports it.
    ("gpo_lens.store", "_copy_legacy_triage_row"): "GUARDED",
    # The event log: every payload passes _guard_payload first.
    ("gpo_lens.events", "append_event"): "GUARDED",
    ("gpo_lens.events", "append_events"): "GUARDED",
    ("gpo_lens.events", "rehash_event_chain"): "rewrites prev_hash only",
}
DYNAMIC_SQL_WRITERS = {
    ("gpo_lens.store", "_scrub_guarded"): (
        "v11 cpassword scrub: replaces discovered values with the redaction marker"
    ),
}
# append_event(s) call sites and the payload keys each may write. Keys listed in
# ANALYST_TEXT_EVENT_FIELDS are guarded centrally by events._guard_payload.
EVENT_WRITERS: dict[tuple[str, str], frozenset[str] | str] = {
    ("gpo_lens.web.routes.ask", "register.ask_post"): frozenset(
        {"principal", "question", "outcome"}
    ),
    ("gpo_lens.web.routes.ask", "register._refuse"): frozenset(
        {"principal", "question", "outcome"}
    ),
    ("gpo_lens.web.routes.ingest", "register._ingest_post._persist"): frozenset({"principal"}),
    ("gpo_lens.web.routes.ingest", "register.ingest_delete"): frozenset(
        {"principal", "snapshot_id"}
    ),
    ("gpo_lens.cli._estate", "_emit_ingest_events"): (
        "estate change events built from the ingest-sanitized estate"
    ),
    ("gpo_lens.store", "_migrate_legacy_triage"): frozenset({"source_table", "substitutions"}),
    ("gpo_lens.store", "_scrub_guarded"): frozenset(
        {
            "changed",
            "discovered_value_count",
            "rewritten_event_ids",
            "rehashed_event_ids",
            "pre_existing_broken_event_ids",
        }
    ),
}
# Payload keys that are not operator text: fixed strings, counts and ids.
# Per event type (DeepSeek r3 NB-5): a key is only "system" for the type that
# writes it, so reusing one of these names for operator text elsewhere fails.
EVENT_SYSTEM_KEYS: dict[str, frozenset[str]] = {
    "audit.narrate": frozenset({"outcome"}),
    "audit.ingest": frozenset(),
    "audit.snapshot_delete": frozenset({"snapshot_id"}),
    "maintenance.analyst_text_substituted": frozenset({"source_table", "substitutions"}),
    "maintenance.cpassword_scrub": frozenset(
        {
            "changed",
            "discovered_value_count",
            "rewritten_event_ids",
            "rehashed_event_ids",
            "pre_existing_broken_event_ids",
        }
    ),
}
LLM_CALLERS = {
    ("gpo_lens.cli._narration", "cmd_ask"): "GUARDED",
    ("gpo_lens.cli._narration", "cmd_explain_setting"): "GUARDED",
    ("gpo_lens.web.routes.ask", "register.ask_post"): "GUARDED",
    ("gpo_lens.web.page_narration", "register.explain_facts"): (
        "server-built facts in an HMAC-signed payload; nothing typed"
    ),
    ("gpo_lens.cli._hygiene", "cmd_doctor"): "estate doctor findings (ingest-sanitized)",
}
WEB_INPUTS = {
    ("register.findings_triage", "status"): "enum, validated against a fixed set",
    ("register.findings_triage", "note"): "GUARDED via findings.triage_finding",
    ("register.findings_triage", "return_q"): "redirect target only, never stored",
    ("register.findings_triage", "return_severity"): "redirect target only, never stored",
    ("register.findings_triage", "return_category"): "redirect target only, never stored",
    ("register.findings_triage", "return_lifecycle"): "redirect target only, never stored",
    ("register.findings_triage", "return_triage"): "redirect target only, never stored",
    ("register.findings_triage", "return_page"): "redirect target only, never stored",
    ("register.ask_post", "question"): "GUARDED",
    ("register.explain_facts", "payload"): "HMAC-signed server facts; refused if altered",
    ("register.baseline_post", "file"): "uploaded baseline: parsed through ingest redaction",
    ("register.baseline_post", "format"): "output format selector",
    ("register.golden_diff_post", "file"): "uploaded golden backup: ingest redaction",
    ("register.golden_diff_post", "format"): "output format selector",
    ("register.ingest_post", "file"): "uploaded export: ingest redaction + verification",
    ("register.ingest_delete", "snapshot_id"): "integer id",
    ("register.resultant_compute", "principal_sid"): "transient lookup, never stored",
    ("register.resultant_compute", "computer_sid"): "transient lookup, never stored",
    ("register.resultant_compute", "dn"): "transient lookup, never stored",
    ("register.resultant_compute", "computer_dn"): "transient lookup, never stored",
    ("get_principal", "authorization"): "bearer token, compared in constant time, never stored",
}
# Raw request reads: (module, function, attribute) -> why it is safe.
RAW_REQUEST_READS = {
    ("gpo_lens.web.auth", "_forwarded_user", "headers"): (
        "GUARDED: forwarded user name, valid_principal_name or 401"
    ),
    ("gpo_lens.web.app", "create_app._http_exception_handler", "headers"): (
        "Accept, content negotiation only"
    ),
    ("gpo_lens.web.app", "create_app._forwarded_proto", "headers"): "X-Forwarded-Proto: scheme",
    ("gpo_lens.web.app", "create_app._body_size_limit", "headers"): "Content-Length compared",
    ("gpo_lens.web.app", "create_app._csrf_check", "headers"): "Origin/Referer/Host compared",
    ("gpo_lens.web.allowed_hosts", "HostAllowListMiddleware.__call__", "scope[headers]"): (
        "Host compared to the allow-list"
    ),
    ("gpo_lens.web._helpers", "parse_pagination", "query_params"): "page numbers",
    ("gpo_lens.web._helpers", "base_qs", "query_params"): "filters echoed into links",
    ("gpo_lens.web.routes.api", "register.run_query", "query_params"): "read-only query",
    ("gpo_lens.web.routes.briefing", "register.briefing_page", "query_params"): "as-of",
    ("gpo_lens.web.routes.export", "register.export_findings", "query_params"): "filters",
    ("gpo_lens.web.routes.export", "register.export_gpo", "query_params"): "view selector",
    ("gpo_lens.web.routes.gpo", "register.gpo_detail", "query_params"): "view selector",
}

_SQL_WRITE = re.compile(
    r"\b(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|UPDATE|REPLACE\s+INTO)\s+[\"'`]?(\w+)", re.IGNORECASE
)
_EVENT_SINKS = frozenset({"append_event", "append_events"})
_LLM_SINKS = frozenset({"route_question", "call_llm", "explain_findings"})
_WEB_INPUTS = frozenset({"Form", "File", "Body", "Header", "Query", "Cookie"})
_REQUEST_ATTRS = frozenset({"headers", "cookies", "query_params"})
_BODY_READS = frozenset({"json", "form", "body", "stream"})


class _Inventory(ast.NodeVisitor):
    """Collect sinks and request sources per enclosing function."""

    def __init__(self, module: str, aliases: dict[str, str]) -> None:
        self.module = module
        self.aliases = aliases
        self.stack: list[str] = []
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.routes: dict[str, str] = {}  # function -> HTTP method
        self.sql: dict[tuple[str, str], list[int]] = {}
        self.dynamic_sql: set[str] = set()
        self.events: dict[str, list[ast.Call]] = {}
        self.llm: dict[str, list[int]] = {}
        self.inputs: set[tuple[str, str]] = set()
        self.raw_reads: set[tuple[str, str]] = set()
        self.body_reads: set[str] = set()

    @property
    def where(self) -> str:
        return ".".join(self.stack)

    def _scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        self.stack.append(node.name)
        if not isinstance(node, ast.ClassDef):
            self.functions[self.where] = node
            for decorator in node.decorator_list:
                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr in {"get", "post", "put", "patch", "delete"}
                ):
                    self.routes[self.where] = decorator.func.attr
            for arg, default in _params(node):
                if isinstance(default, ast.Call) and self._name(default.func) in _WEB_INPUTS:
                    self.inputs.add((self.where, arg.arg))
        self.generic_visit(node)
        self.stack.pop()

    visit_FunctionDef = _scope  # noqa: N815
    visit_AsyncFunctionDef = _scope  # noqa: N815
    visit_ClassDef = _scope  # noqa: N815

    def _name(self, func: ast.expr) -> str | None:
        if isinstance(func, ast.Attribute):
            return func.attr
        if isinstance(func, ast.Name):
            return self.aliases.get(func.id, func.id)
        return None

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            for match in _SQL_WRITE.finditer(node.value):
                key = (self.where, match.group(1).lower())
                self.sql.setdefault(key, []).append(node.lineno)
            if node.value == "headers":
                self.raw_reads.add((self.where, "scope[headers]"))

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        literal = "".join(v.value for v in node.values if isinstance(v, ast.Constant))
        if re.search(r"\b(?:INSERT|UPDATE|REPLACE)\b", literal) and any(
            isinstance(v, ast.FormattedValue) for v in node.values
        ):
            self.dynamic_sql.add(self.where)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        base = ast.unparse(node.value)
        if node.attr in _REQUEST_ATTRS and base not in {"response", "resp"}:
            self.raw_reads.add((self.where, node.attr))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self._name(node.func)
        if name in _EVENT_SINKS:
            self.events.setdefault(self.where, []).append(node)
        if name in _LLM_SINKS:
            self.llm.setdefault(self.where, []).append(node.lineno)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in _BODY_READS
            and ast.unparse(node.func.value) in {"request", "req"}
        ):
            self.body_reads.add(self.where)
        self.generic_visit(node)


def _params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[ast.arg, ast.expr | None]]:
    args = node.args
    positional = args.posonlyargs + args.args
    defaults: list[ast.expr | None] = [None] * (len(positional) - len(args.defaults))
    defaults += list(args.defaults)
    pairs = list(zip(positional, defaults, strict=True))
    pairs += list(zip(args.kwonlyargs, args.kw_defaults, strict=True))
    return pairs


def _modules() -> dict[str, _Inventory]:
    out: dict[str, _Inventory] = {}
    for path in sorted(SRC.rglob("*.py")):
        module = ".".join(path.relative_to(SRC.parent).with_suffix("").parts)
        if module == "gpo_lens.narration":
            continue  # the LLM client itself (call_llm's own callers are below)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        aliases = {
            alias.asname: alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
            if alias.asname
        }
        inventory = _Inventory(module, aliases)
        inventory.visit(tree)
        out[module] = inventory
    return out


INVENTORY = _modules()


def _subject(expr: ast.expr) -> str:
    """The value a guard argument checks: ``field``, ``field[:n]`` or
    ``checked_slice(field, n)`` all check ``field``; nothing else counts."""
    if isinstance(expr, ast.Call) and getattr(expr.func, "id", "") == "checked_slice":
        expr = expr.args[0]
    if isinstance(expr, ast.Subscript) and isinstance(expr.slice, ast.Slice):
        if expr.slice.lower is None and expr.slice.step is None:
            expr = expr.value
    return ast.unparse(expr)


def _guarded_fields(module: str, function: str) -> dict[str, int]:
    """Field name -> first line of a guard call whose checked value is it.

    For ``_guard_payload(event_type, payload)`` the checked value is its second
    argument; for every other guard, its first."""
    inv = INVENTORY[module]
    out: dict[str, int] = {}
    calls = [c for c in ast.walk(inv.functions[function]) if isinstance(c, ast.Call)]
    for call in calls:
        name = inv._name(call.func)
        if name not in GUARD_CALLS or not call.args:
            continue
        checked = call.args[1] if name == "_guard_payload" else call.args[0]
        field = _subject(checked)
        if field in GUARDED_FIELDS[(module, function)]:
            out[field] = min(out.get(field, call.lineno), call.lineno)
    return out


def _assert_guarded(module: str, function: str, sink_lines: list[int]) -> None:
    assert sink_lines, f"{module}.{function}: no sink found"
    guarded = _guarded_fields(module, function)
    for field in GUARDED_FIELDS[(module, function)]:
        assert field in guarded, f"{module}.{function} never guards {field!r}"
        assert guarded[field] < min(sink_lines), f"{module}.{function} guards {field!r} late"


def test_every_guarded_function_is_listed_with_its_fields() -> None:
    for (module, function), fields in GUARDED_FIELDS.items():
        assert function in INVENTORY[module].functions, (module, function)
        assert fields


# Writers that truncate need two guards per field: one on what is kept plus the
# straddle margin (``checked_slice(field, n)``) before the truncating assignment,
# and one on the exact truncated value after it (truncation can form a token).
TRUNCATING_WRITERS = {
    ("gpo_lens.findings", "append_triage_event"): ("note", "rationale", "actor"),
}


def test_truncating_writers_guard_before_and_after_truncation() -> None:
    for (module, function), fields in TRUNCATING_WRITERS.items():
        inv = INVENTORY[module]
        node = inv.functions[function]
        sink = min(lines for (where, _t), lines in inv.sql.items() if where == function)[0]
        for field in fields:
            cut = [
                n.lineno
                for n in ast.walk(node)
                if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == field for t in n.targets)
                and isinstance(n.value, ast.Subscript)
            ]
            assert len(cut) == 1, (function, field, cut)
            before = after = False
            for call in ast.walk(node):
                if not isinstance(call, ast.Call) or inv._name(call.func) != "check_analyst_text":
                    continue
                arg = call.args[0]
                is_slice = (
                    isinstance(arg, ast.Call)
                    and getattr(arg.func, "id", "") == "checked_slice"
                    and ast.unparse(arg.args[0]) == field
                )
                if is_slice and call.lineno < cut[0]:
                    before = True
                if ast.unparse(arg) == field and cut[0] < call.lineno < sink:
                    after = True
            assert before, f"{function}: no checked_slice guard on {field!r} before truncation"
            assert after, f"{function}: no guard on the truncated {field!r} before the write"


def test_every_sql_write_to_an_operator_text_table_is_inventoried() -> None:
    found = {
        (module, where): lines
        for module, inv in INVENTORY.items()
        for (where, table), lines in inv.sql.items()
        if table in ANALYST_TABLES or table == "events"
    }
    assert set(found) == set(SQL_WRITERS)
    for key, how in SQL_WRITERS.items():
        if how == "GUARDED":
            _assert_guarded(*key, found[key])


def test_the_guarded_triage_writer_checks_every_operator_column() -> None:
    node = INVENTORY["gpo_lens.findings"].functions["append_triage_event"]
    fields = {
        call.args[1].value
        for call in ast.walk(node)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "check_analyst_text"
        and isinstance(call.args[1], ast.Constant)
    }
    assert fields == {c for t, c in ANALYST_TEXT_COLUMNS if t == "finding_triage_event"}


def test_every_dynamic_sql_write_is_inventoried() -> None:
    found = {(m, w) for m, inv in INVENTORY.items() for w in inv.dynamic_sql}
    assert found == set(DYNAMIC_SQL_WRITERS)


def _payload_keys(call: ast.Call) -> frozenset[str] | None:
    payload = call.args[2] if len(call.args) > 2 else None
    for keyword in call.keywords:
        if keyword.arg == "payload":
            payload = keyword.value
    if not isinstance(payload, ast.Dict):
        return None
    return frozenset(k.value for k in payload.keys if isinstance(k, ast.Constant))


def test_every_event_write_and_payload_key_is_inventoried() -> None:
    found = {(m, w): calls for m, inv in INVENTORY.items() for w, calls in inv.events.items()}
    found = {k: v for k, v in found.items() if k[0] != "gpo_lens.events"}
    assert set(found) == set(EVENT_WRITERS)
    for key, expected in EVENT_WRITERS.items():
        if isinstance(expected, str):
            continue  # payload built elsewhere: classified as a whole
        keys: set[str] = set()
        for call in found[key]:
            literal = _payload_keys(call)
            assert literal is not None, f"{key}: payload is no longer a literal dict"
            event_type = call.args[1] if len(call.args) > 1 else None
            assert isinstance(event_type, ast.Constant), f"{key}: event type is not a literal"
            # Operator keys must be guarded for *this* event type, not for
            # some other one (_guard_payload checks per type).
            guarded = {
                field
                for kind, field in ANALYST_TEXT_EVENT_FIELDS
                if kind in ("*", event_type.value)
            }
            system = EVENT_SYSTEM_KEYS.get(event_type.value, frozenset())
            assert literal <= guarded | system, (key, event_type.value, literal)
            keys |= literal
        assert keys == expected, key


def test_event_payload_guard_covers_every_scanned_field() -> None:
    from gpo_lens.events import _guard_payload

    assert ANALYST_TEXT_EVENT_FIELDS == (("audit.narrate", "question"), ("*", "principal"))
    for event_type, field in ANALYST_TEXT_EVENT_FIELDS:
        with pytest.raises(CpasswordInAnalystTextError):
            _guard_payload(
                "audit.narrate" if event_type == "*" else event_type, {field: f"x {CT2}"}
            )


def test_every_llm_call_is_inventoried() -> None:
    found = {(m, w): lines for m, inv in INVENTORY.items() for w, lines in inv.llm.items()}
    assert set(found) == set(LLM_CALLERS)
    for key, how in LLM_CALLERS.items():
        if how == "GUARDED":
            _assert_guarded(*key, found[key])


def test_every_declared_web_input_is_inventoried() -> None:
    found = {key for m, inv in INVENTORY.items() if ".web." in m for key in inv.inputs}
    assert found == set(WEB_INPUTS)
    ask = INVENTORY["gpo_lens.web.routes.ask"]
    _assert_guarded("gpo_lens.web.routes.ask", "register.ask_post", ask.llm["register.ask_post"])
    # The triage form's note reaches the database only through triage_finding.
    triage = INVENTORY["gpo_lens.web.routes.findings"].functions["register.findings_triage"]
    called = {
        INVENTORY["gpo_lens.web.routes.findings"]._name(c.func)
        for c in ast.walk(triage)
        if isinstance(c, ast.Call)
    }
    assert "triage_finding" in called
    _assert_guarded(
        "gpo_lens.findings",
        "triage_finding",
        [
            c.lineno
            for c in ast.walk(INVENTORY["gpo_lens.findings"].functions["triage_finding"])
            if isinstance(c, ast.Call) and getattr(c.func, "id", "") == "append_triage_event"
        ],
    )


def test_every_raw_request_read_is_inventoried() -> None:
    found = {(m, where, attr) for m, inv in INVENTORY.items() for where, attr in inv.raw_reads}
    assert found == set(RAW_REQUEST_READS)
    # The one header that names something stored is validated before return.
    _assert_guarded(
        "gpo_lens.web.auth",
        "_forwarded_user",
        [
            node.lineno
            for node in ast.walk(INVENTORY["gpo_lens.web.auth"].functions["_forwarded_user"])
            if isinstance(node, ast.Return)
            and node.value is not None
            and not (isinstance(node.value, ast.Constant) and node.value.value is None)
        ],
    )


def test_no_handler_reads_a_raw_request_body() -> None:
    assert {(m, w) for m, inv in INVENTORY.items() for w in inv.body_reads} == set()


def test_post_route_parameters_are_declared_inputs() -> None:
    """A new POST parameter must be a declared Form/File field (inventoried
    above), a dependency, the Request, or an integer path id."""
    for module, inv in INVENTORY.items():
        for function, method in inv.routes.items():
            if method == "get":
                continue
            for arg, default in _params(inv.functions[function]):
                annotation = ast.unparse(arg.annotation) if arg.annotation else ""
                declared = isinstance(default, ast.Call) and inv._name(default.func) in (
                    _WEB_INPUTS | {"Depends"}
                )
                assert declared or annotation in {"Request", "int"}, (module, function, arg.arg)


def test_get_routes_hold_no_sink() -> None:
    for module, inv in INVENTORY.items():
        for function, method in inv.routes.items():
            if method != "get":
                continue
            assert function not in inv.events, (module, function)
            assert function not in inv.llm, (module, function)
            assert not any(where == function for where, _ in inv.sql), (module, function)


def test_no_json_api_route_accepts_a_request_body() -> None:
    """The JSON API is read-only: no POST/PUT/PATCH routes to guard there."""
    source = (SRC / "web" / "routes" / "api.py").read_text(encoding="utf-8")
    assert not re.search(r"@app\.(?:post|put|patch|delete)\(", source)
