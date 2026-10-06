"""Daybreak Blue round-two probes, with synthetic inputs and released DBs."""

import json
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gpo_lens.cli import main
from gpo_lens.exports import snapshot_secrets
from gpo_lens.findings import (
    accepted_risk_register,
    finding_inbox,
    fold_triage,
    get_triage_status,
    load_triage_events,
    load_triage_status_map,
)
from gpo_lens.ingest import load_estate
from gpo_lens.model import Setting
from gpo_lens.safe_output import REDACTED, safe_data, safe_text, secret_values
from gpo_lens.store import init_db, save_estate

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("legacy_time", "reopen_time"),
    [
        ("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
        ("2026-01-01T01:00:00+01:00", "2026-01-01T00:30:00Z"),
        ("2026-01-01T01:00:00+01:00", "2026-01-01T00:00:00Z"),
        ("2026-01-01 00:00:00", "2026-01-01T00:30:00+00:00"),
    ],
)
def test_released_triage_edge_probe(tmp_path, legacy_time, reopen_time):
    """glv1/probe_triage_edges.py, extended to every status consumer."""
    db = tmp_path / "upgrade.sqlite3"
    shutil.copyfile(FIXTURES / "released_databases/v1.2.0-with-reopen.sqlite3", db)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE finding_triage SET timestamp=? WHERE finding_id=2", (legacy_time,))
        conn.execute(
            "UPDATE finding_triage_event SET occurred_at=? "
            "WHERE occurrence_id=2 AND action='reopened'",
            (reopen_time,),
        )
        conn.commit()
        original = conn.execute("SELECT * FROM finding_triage_event ORDER BY id").fetchall()
        for _ in range(2):
            init_db(conn)
            events = load_triage_events(conn, 2)
            assert all(e.occurred_at.tzinfo is UTC for e in events)
            assert get_triage_status(conn, 2).status == "open"
            assert fold_triage(list(reversed(events))).status == "open"
            assert load_triage_status_map(conn)[2].status == "open"
            assert 2 in {
                v.occurrence_id
                for v in finding_inbox(conn, lifecycle_state="all", triage_status="open")
            }
            risk = next(
                r
                for r in accepted_risk_register(conn, as_of=datetime(2030, 1, 1, tzinfo=UTC))
                if r.occurrence_id == 2
            )
            assert risk.revoked_by == "lab-reviewer"
            assert risk.revoked_at is not None
            assert all(
                row in conn.execute("SELECT * FROM finding_triage_event").fetchall()
                for row in original
            )


@pytest.mark.parametrize(
    "action", ["reopened", "risk_acceptance_revoked", "risk_acceptance_expired"]
)
def test_equal_time_removal_wins_over_acceptance(tmp_path, action):
    db = tmp_path / "upgrade.sqlite3"
    shutil.copyfile(FIXTURES / "released_databases/v1.2.0-with-reopen.sqlite3", db)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE finding_triage SET timestamp='2026-01-01T00:00:00Z'")
        conn.execute(
            "UPDATE finding_triage_event SET action=?, occurred_at='2026-01-01T00:00:00Z' "
            "WHERE occurrence_id=2 AND action='reopened'",
            (action,),
        )
        conn.commit()
        init_db(conn)
        assert get_triage_status(conn, 2).status == "open"


TASK_CASES = [
    ("schtasks.exe", '/Create /RU LAB\\svc-deploy /RP "SYNTH TASK SECRET"'),
    (r"C:\Windows\System32\schtasks.exe", "/Query /S lens /P SYNTH-TASK-SECRET"),
    ("cmdkey", "/add:lens /user:LAB\\svc /pass:SYNTH-TASK-SECRET"),
    ("powershell.exe", '-File deploy.ps1 -Password "SYNTH TASK SECRET"'),
    ("pwsh", "-File deploy.ps1 -ProxyPassword 'SYNTH TASK SECRET'"),
    (r"C:\Program Files\PowerShell\7\pwsh.exe", '-File deploy.ps1 -Password "SYNTH TASK SECRET"'),
]


@pytest.mark.parametrize(("command", "arguments"), TASK_CASES)
def test_task_credentials_and_copied_evidence_are_redacted(command, arguments):
    secret = "SYNTH TASK SECRET" if "SYNTH TASK SECRET" in arguments else "SYNTH-TASK-SECRET"
    task = {"command": command, "arguments": arguments}
    assert secret in secret_values(task)
    assert secret not in json.dumps(safe_data({"task": task, "evidence": "Copied " + secret}))
    assert REDACTED in safe_data(task)["arguments"]
    assert secret not in safe_text("Copied " + secret, secrets=secret_values(task))
    # Collector raw trees and flattened setting text feed DB-backed exports.
    setting = Setting(
        "lab",
        "Computer",
        "Scheduled Tasks",
        "task",
        "Task",
        command + " " + arguments,
        {"tag": "Properties", "@attr": task},
        False,
    )
    estate = load_estate(FIXTURES)
    setting.gpo_id = estate.gpos[0].id
    estate.gpos[0].settings.append(setting)
    with sqlite3.connect(":memory:") as conn:
        init_db(conn)
        sid = save_estate(conn, estate)
        secrets = snapshot_secrets(conn, [sid])
        assert secret in secrets
        assert secret not in safe_data({"summary": "Copied " + secret}, secrets=secrets)["summary"]


def test_password_policy_switch_is_not_a_task_credential():
    value = {"command": "net.exe", "arguments": "accounts /minpwlen:14 /maxpwage:30"}
    assert secret_values(value) == ()
    assert safe_data(value) == value
    assert (
        safe_data({"display_value": "PasswordComplexity=1"})["display_value"]
        == "PasswordComplexity=1"
    )


@pytest.mark.parametrize(
    ("command", "arguments", "secret"),
    [
        ("schtasks.exe", r'/RP "SYNTH \"QUOTE\" SECRET"', 'SYNTH "QUOTE" SECRET'),
        ("pwsh.exe", '-Password "SYNTH `"QUOTE`" SECRET"', 'SYNTH "QUOTE" SECRET'),
        ("powershell.exe", "-Password 'SYNTH ''QUOTE'' SECRET'", "SYNTH 'QUOTE' SECRET"),
    ],
)
def test_escaped_task_passwords_and_decoded_copies(command, arguments, secret):
    task = {"command": command, "arguments": arguments}
    assert secret in secret_values(task)
    projected = safe_data({"task": task, "evidence": secret})
    assert projected["evidence"] == REDACTED
    assert "QUOTE" not in projected["task"]["arguments"]


@pytest.mark.parametrize("as_json", [True, False])
@pytest.mark.parametrize("db_backed", [True, False])
def test_task_credential_cli_probe(tmp_path, capsys, as_json, db_backed):
    """Same /RP carrier as glv1/evidence/credential-fixture."""
    export = tmp_path / "export"
    export.mkdir()
    shutil.copyfile(FIXTURES / "AllGPOs.xml", export / "AllGPOs.xml")
    prefs = export / "SYSVOL-Policies/{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}/Machine/Preferences"
    prefs.mkdir(parents=True)
    secret = "SYNTH-TASK-RP-SECRET-ONLY"
    (prefs / "ScheduledTasks.xml").write_text(
        '<ScheduledTasks><Task name="Lab task"><Properties action="U" '
        'appName="schtasks.exe" arguments="/Create /RU LAB\\svc-deploy /RP '
        + secret
        + '"/></Task></ScheduledTasks>'
    )
    argv = ["--json"] if as_json else []
    if db_backed:
        db = tmp_path / "estate.sqlite3"
        with sqlite3.connect(db) as conn:
            init_db(conn)
            save_estate(conn, load_estate(export))
        argv += ["--db", str(db), "gpp-tasks"]
    else:
        argv += ["gpp-tasks", str(export)]
    assert main(argv) == 0
    output = capsys.readouterr().out
    assert secret not in output
    assert "schtasks.exe" in output
    if as_json:
        assert REDACTED in output
