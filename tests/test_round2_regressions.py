"""Daybreak Blue glv1/glv2 probes adapted to portable synthetic regressions."""

import json
import shutil
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from xml.sax.saxutils import quoteattr

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

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
from gpo_lens.safe_output import REDACTED, safe_data, secret_values
from gpo_lens.store import init_db, save_estate
from gpo_lens.web.allowed_hosts import HostAllowListMiddleware

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures"


@pytest.mark.parametrize(
    ("legacy_time", "reopen_time"),
    [
        ("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
        ("2026-01-01T01:00:00+01:00", "2026-01-01T00:30:00Z"),
        ("2026-01-01T01:00:00+01:00", "2026-01-01T00:00:00Z"),
        ("2026-01-01 00:00:00", "2026-01-01T00:30:00+00:00"),
    ],
)
@pytest.mark.parametrize(
    "action", ["reopened", "risk_acceptance_revoked", "risk_acceptance_expired"]
)
def test_glv1_triage_edges(tmp_path, legacy_time, reopen_time, action):
    db = tmp_path / "upgrade.sqlite3"
    shutil.copyfile(FIXTURES / "released_databases/v1.2.0-with-reopen.sqlite3", db)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE finding_triage SET timestamp=? WHERE finding_id=2", (legacy_time,))
        conn.execute(
            "UPDATE finding_triage_event SET occurred_at=?, action=? "
            "WHERE occurrence_id=2 AND action='reopened'",
            (reopen_time, action),
        )
        conn.commit()
        original = conn.execute("SELECT * FROM finding_triage_event ORDER BY id").fetchall()
        for _ in range(2):
            init_db(conn)
            assert get_triage_status(conn, 2).status == "open"
            assert load_triage_status_map(conn)[2].status == "open"
            assert 2 in {
                v.occurrence_id
                for v in finding_inbox(conn, lifecycle_state="all", triage_status="open")
            }
            events = load_triage_events(conn, 2)
            assert fold_triage(list(reversed(events))).status == "open"
            assert all(e.occurred_at.tzinfo == UTC for e in events)
            risk = next(
                r
                for r in accepted_risk_register(conn, as_of=datetime(2030, 1, 1, tzinfo=UTC))
                if r.occurrence_id == 2
            )
            assert risk.is_expired if action == "risk_acceptance_expired" else risk.revoked_at
            if action != "risk_acceptance_expired":
                assert risk.revoked_by == "lab-reviewer"
            assert all(
                row in conn.execute("SELECT * FROM finding_triage_event").fetchall()
                for row in original
            )


COMMANDS = [
    (
        r"%SystemRoot%\System32\schtasks.exe",
        "/Create /RU LAB\\svc-deploy /RP",
        "SYNTH-TASK-RP-SECRET-ONLY",
    ),
    ("SCHTASKS.EXE", "/Create /P", '"SYNTH TASK P SECRET"'),
    ("cmdkey.exe", "/add:lab /user:svc /pass:", '"SYNTH CMDKEY SECRET"'),
    ("powershell.exe", "-Password", "'SYNTH POWERSHELL SECRET'"),
    ("pwsh.exe", "-ProxyPassword:", "SYNTH-PROXY-SECRET"),
    (r"C:\Windows\System32\schtasks.exe", "/Query /S lens /P", "SYNTH-TASK-SECRET"),
    (r"C:\Program Files\PowerShell\7\pwsh.exe", "-Password", '"SYNTH TASK SECRET"'),
    ("pwsh", "-ProxyPassword", "'SYNTH TASK SECRET'"),
]


@pytest.mark.parametrize(("command", "switch", "quoted"), COMMANDS)
def test_task_command_secrets_and_copied_evidence(command, switch, quoted):
    secret = quoted.strip("\"'")
    args = switch + ("" if switch.endswith(":") else " ") + quoted
    task = {"command": command, "arguments": args}
    assert secret in secret_values(task)
    result = safe_data({"task": task, "evidence": {"summary": "Copied " + secret}})
    assert secret not in json.dumps(result)
    assert REDACTED in result["task"]["arguments"]
    assert result["evidence"]["summary"] == "Copied " + REDACTED
    # Collector XML has a different shape from the structured scanner result.
    raw = {"tag": "Properties", "@attr": {"appName": command, "arguments": args}}
    assert secret in secret_values({"raw": raw})
    # Persisted setting projections must carry the same discovered credentials.
    estate = load_estate(FIXTURES)
    estate.gpos[0].settings.append(
        Setting(
            estate.gpos[0].id,
            "Computer",
            "Scheduled Tasks",
            "task",
            "Task",
            command + " " + args,
            raw,
            False,
        )
    )
    with sqlite3.connect(":memory:") as conn:
        init_db(conn)
        sid = save_estate(conn, estate)
        secrets = snapshot_secrets(conn, [sid])
        assert secret in secrets
        assert safe_data({"summary": "Copied " + secret}, secrets=secrets)["summary"] == (
            "Copied " + REDACTED
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


@pytest.mark.parametrize(("command", "switch", "quoted"), COMMANDS)
@pytest.mark.parametrize("db_backed", [False, True])
@pytest.mark.parametrize("json_output", [False, True])
def test_glv1_credential_fixture_cli(tmp_path, command, switch, quoted, db_backed, json_output):
    source = tmp_path / "estate"
    shutil.copytree(FIXTURES, source)
    tasks = (
        source
        / "SYSVOL-Policies/{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
        / "Machine/Preferences/ScheduledTasks.xml"
    )
    secret = quoted.strip("\"'")
    args = switch + ("" if switch.endswith(":") else " ") + quoted
    tasks.write_text(
        '<ScheduledTasks><Task name="Synthetic task"><Properties action="CREATE" '
        f"appName={quoteattr(command)} arguments={quoteattr(args)} /></Task></ScheduledTasks>"
    )
    # Include a copy in the visible task name, proving source context reaches text too.
    tasks.write_text(tasks.read_text().replace("Synthetic task", "Copy " + secret))
    cli_args = ["--json"] if json_output else []
    if db_backed:
        db = tmp_path / "estate.sqlite3"
        with sqlite3.connect(db) as conn:
            init_db(conn)
            save_estate(conn, load_estate(source))
        cli_args += ["--db", str(db), "gpp-tasks"]
    else:
        cli_args += ["gpp-tasks", str(source)]
    result = subprocess.run(
        [sys.executable, "-m", "gpo_lens", *cli_args], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert secret not in result.stdout
    assert REDACTED in result.stdout


def test_password_policy_command_is_not_masked():
    value = {"command": "policy-tool.exe", "arguments": "-Password 14 /P 30 /RP 90"}
    assert secret_values(value) == ()
    assert safe_data(value) == value


def test_v2_task_xml_command_context_masks_copied_evidence():
    raw = {
        "tag": "Exec",
        "@attr": {},
        "children": [
            {"tag": "Command", "text": "schtasks.exe"},
            {"tag": "Arguments", "text": "/Create /RP SYNTH-V2-TASK-SECRET"},
        ],
    }
    assert "SYNTH-V2-TASK-SECRET" in secret_values(raw)
    assert safe_data({"raw": raw, "summary": "SYNTH-V2-TASK-SECRET"})["summary"] == REDACTED


def test_glv2_concrete_ip_policy_reaches_asgi():
    # The reviewer used these exact synthetic bindings and ASGI requests.
    script = """
function Get-WebBinding { @(
    [pscustomobject]@{protocol="https"; bindingInformation="192.0.2.10:8443:"},
    [pscustomobject]@{protocol="https"; bindingInformation="[2001:db8::10]:9443:"}
) }
. ./scripts/install-windows.ps1
Get-IisAllowedHosts -SiteName gpo-lens -MachineFqdn lens.lab.example.com -MachineName LENS
"""
    if not shutil.which("pwsh"):
        pytest.skip("PowerShell unavailable; equivalent Pester checks run in Windows CI")
    policy = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    app = FastAPI()
    app.get("/")(lambda: {"ok": True})
    app.add_middleware(HostAllowListMiddleware, allowed_hosts=policy)
    with TestClient(app) as client:
        for host in ("192.0.2.10:8443", "[2001:db8::10]:9443", "lens:8443"):
            assert client.get("/", headers={"Host": host}).status_code == 200
        assert client.get("/", headers={"Host": "192.0.2.11:8443"}).status_code == 400
