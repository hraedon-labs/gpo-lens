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
import json
import random
import re
import sqlite3
import time
import uuid
from pathlib import Path
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


@pytest.mark.parametrize("blocks", sorted(_FN_BOUNDS))
def test_measured_miss_rate_on_random_ciphertext(blocks: int) -> None:
    rng = random.Random(blocks)  # noqa: S311 - reproducible test data
    samples = [_ciphertext(blocks, rng) for _ in range(20_000)]
    misses = sum(1 for value in samples if cpassword_material(value) is None)
    assert misses <= _FN_BOUNDS[blocks] * len(samples), misses


@pytest.mark.parametrize(
    "text",
    [
        ("a/" * 50_000) + " " + ("-x" * 50_000),
        "a-b/c_d " * 20_000,
        "a\n" * 100_000,
        "ab\n" * 50_000 + "ab=\n" * 50_000,
    ],
    ids=["separator runs", "short separated tokens", "one-char lines", "padded lines"],
)
def test_large_input_is_checked_in_bounded_time(text: str) -> None:
    """Window and wrapped-line search are bounded; megabyte input stays fast."""
    start = time.perf_counter()
    assert cpassword_material(text) is None
    assert time.perf_counter() - start < 5


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
    assert data["count"] == 3
    assert {row["id"] for row in data["rows"]} == {ids["note"], ids["rationale"], ids["question"]}


def test_analyst_text_check_cli_clean_database_exits_zero(
    web_db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from gpo_lens.cli import main

    assert main(["--db", str(web_db), "analyst-text-check"]) == 0
    assert "No stored analyst text" in capsys.readouterr().out


# --- inventory: every write path goes through the guard -------------------------------------
#
# Each sink below is either GUARDED (the function calls check_analyst_text, or a
# helper that does, before the sink) or classified with the reason it carries
# no analyst-typed text. A new sink fails these tests until it is one or the
# other.

GUARD_CALLS = frozenset({"check_analyst_text", "_refused"})
ANALYST_TABLES = frozenset(table for table, _ in ANALYST_TEXT_COLUMNS)

SQL_WRITERS = {
    # Analyst-text tables (finding_triage_event, finding_triage).
    ("gpo_lens.findings", "append_triage_event"): "GUARDED",
    ("gpo_lens.findings", "expire_risk_acceptances"): (
        "system text: 'Risk acceptance expired at <timestamp>'"
    ),
    ("gpo_lens.store", "_migrate_schema"): (
        "v7->v8 copies existing finding_triage rows; older rows are reported by "
        "analyst-text-check, never rewritten"
    ),
}
DYNAMIC_SQL_WRITERS = {
    ("gpo_lens.store", "_scrub_guarded"): (
        "v11 cpassword scrub: replaces discovered values with the redaction marker"
    ),
}
EVENT_WRITERS = {
    ("gpo_lens.web.routes.ask", "register.ask_post"): "GUARDED",
    ("gpo_lens.web.routes.ask", "register._refuse"): (
        "refusal record: the question is stored as an empty string"
    ),
    ("gpo_lens.web.routes.ingest", "register._ingest_post._persist"): "principal name only",
    ("gpo_lens.web.routes.ingest", "register.ingest_delete"): "principal name and snapshot id",
    ("gpo_lens.cli._estate", "_emit_ingest_events"): "estate change events (ingest-sanitized)",
    ("gpo_lens.store", "_scrub_guarded"): "scrub audit event: counts and table names",
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
}

_SQL_WRITE = re.compile(
    r"\b(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|UPDATE|REPLACE\s+INTO)\s+[\"'`]?(\w+)", re.IGNORECASE
)
_EVENT_SINKS = frozenset({"append_event", "append_events"})
_LLM_SINKS = frozenset({"route_question", "call_llm", "explain_findings"})
_WEB_INPUTS = frozenset({"Form", "File", "Body"})


class _Inventory(ast.NodeVisitor):
    """Collect sinks per enclosing function (qualified within the module)."""

    def __init__(self, module: str, aliases: dict[str, str]) -> None:
        self.module = module
        self.aliases = aliases
        self.stack: list[str] = []
        self.functions: dict[str, ast.AST] = {}
        self.sql: set[tuple[str, str]] = set()
        self.dynamic_sql: set[str] = set()
        self.events: dict[str, list[int]] = {}
        self.llm: dict[str, list[int]] = {}
        self.inputs: set[tuple[str, str]] = set()

    @property
    def where(self) -> str:
        return ".".join(self.stack)

    def _scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        self.stack.append(node.name)
        if not isinstance(node, ast.ClassDef):
            self.functions[self.where] = node
            args = node.args
            positional = args.posonlyargs + args.args
            defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
            pairs = list(zip(positional, defaults, strict=True))
            pairs += list(zip(args.kwonlyargs, args.kw_defaults, strict=True))
            for arg, default in pairs:
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
                self.sql.add((self.where, match.group(1).lower()))

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        literal = "".join(v.value for v in node.values if isinstance(v, ast.Constant))
        if re.search(r"\b(?:INSERT|UPDATE|REPLACE)\b", literal) and any(
            isinstance(v, ast.FormattedValue) for v in node.values
        ):
            self.dynamic_sql.add(self.where)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self._name(node.func)
        if name in _EVENT_SINKS:
            self.events.setdefault(self.where, []).append(node.lineno)
        if name in _LLM_SINKS:
            self.llm.setdefault(self.where, []).append(node.lineno)
        self.generic_visit(node)


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


def _guard_lines(module: str, function: str) -> list[int]:
    node = INVENTORY[module].functions[function]
    return [
        call.lineno
        for call in ast.walk(node)
        if isinstance(call, ast.Call) and INVENTORY[module]._name(call.func) in GUARD_CALLS
    ]


def _assert_guarded(module: str, function: str, sink_lines: list[int]) -> None:
    guards = _guard_lines(module, function)
    assert guards, f"{module}.{function} writes analyst text without check_analyst_text"
    assert min(guards) < min(sink_lines), f"{module}.{function} guards after its sink"


def test_every_sql_write_to_an_analyst_text_table_is_inventoried() -> None:
    found = {
        (module, where)
        for module, inv in INVENTORY.items()
        for where, table in inv.sql
        if table in ANALYST_TABLES
    }
    assert found == set(SQL_WRITERS)
    for (module, function), how in SQL_WRITERS.items():
        if how == "GUARDED":
            node = INVENTORY[module].functions[function]
            sinks = [
                c.lineno
                for c in ast.walk(node)
                if isinstance(c, ast.Constant)
                and isinstance(c.value, str)
                and _SQL_WRITE.search(c.value)
            ]
            _assert_guarded(module, function, sinks)


def test_the_guarded_triage_writer_checks_every_analyst_column() -> None:
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


def test_every_event_write_is_inventoried() -> None:
    found = {(m, w): lines for m, inv in INVENTORY.items() for w, lines in inv.events.items()}
    found = {k: v for k, v in found.items() if k[0] != "gpo_lens.events"}
    assert set(found) == set(EVENT_WRITERS)
    for key, how in EVENT_WRITERS.items():
        if how == "GUARDED":
            _assert_guarded(*key, found[key])


def test_event_fields_scanned_for_older_rows_match_the_guarded_writers() -> None:
    assert ANALYST_TEXT_EVENT_FIELDS == (("audit.narrate", "question"),)


def test_every_llm_call_is_inventoried() -> None:
    found = {(m, w): lines for m, inv in INVENTORY.items() for w, lines in inv.llm.items()}
    assert set(found) == set(LLM_CALLERS)
    for key, how in LLM_CALLERS.items():
        if how == "GUARDED":
            _assert_guarded(*key, found[key])


def test_every_web_form_field_is_inventoried() -> None:
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


def test_no_json_api_route_accepts_a_request_body() -> None:
    """The JSON API is read-only: no POST/PUT/PATCH routes to guard there."""
    source = (SRC / "web" / "routes" / "api.py").read_text(encoding="utf-8")
    assert not re.search(r"@app\.(?:post|put|patch|delete)\(", source)
