"""Run the documented IIS commands against the reviewer's interrupted WAL scenario."""

from __future__ import annotations

import re
import shutil
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KNOWN_GPO = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def documented_step(name: str) -> str:
    guide = (ROOT / "deploy/iis/README.md").read_text()
    match = re.search(rf"<!-- regression: {name} -->\s*```powershell\n(.*?)\n```", guide, re.S)
    assert match, f"Missing executable {name} procedure"
    return match.group(1)


def run_step(name: str, tmp_path: Path, data: Path, backup: Path) -> None:
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell is required to execute IIS documentation commands")
    script = tmp_path / f"{name}.ps1"
    # Platform services/ACLs are mocked; all filesystem and SQLite commands run.
    script.write_text(
        "& {\n"
        + documented_step(name).replace(
            "$ErrorActionPreference = 'Stop'",
            "$ErrorActionPreference = 'Stop'\n"
            "function Stop-WebAppPool { param($Name) }\n"
            "function Start-WebAppPool { param($Name) }\n"
            "function icacls { $global:LASTEXITCODE = 0 }",
        )
        + "\n} @args\n"
    )
    args = [
        pwsh,
        "-NoProfile",
        "-File",
        str(script),
        "-Data",
        str(data),
        "-Backup",
        str(backup),
        "-Py",
        sys.executable,
    ]
    if name == "restore":
        args += ["-ExpectedSnapshots", "1", "-KnownGpo", KNOWN_GPO]
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def wal_fixture(data: Path, stored_gpo: str = KNOWN_GPO) -> Path:
    """Reuse glr2/sqlite_wal_probe.py's crash-with-committed-sidecars setup."""
    data.mkdir()
    live = data / "gpo-lens.sqlite3"
    with closing(sqlite3.connect(live)) as conn, conn:
        conn.executescript(
            "CREATE TABLE evidence(value TEXT); INSERT INTO evidence VALUES ('before');"
            "CREATE TABLE snapshot(id INTEGER); INSERT INTO snapshot VALUES (1);"
            "CREATE TABLE gpo(id TEXT);"
        )
        conn.execute("INSERT INTO gpo VALUES (?)", (stored_gpo,))
    (data / "audit.log").write_text("synthetic audit trail\n")
    old = data.parent / "old.sqlite3"
    shutil.copy2(live, old)
    child = """
import os, sqlite3, sys
c=sqlite3.connect(sys.argv[1])
assert c.execute('PRAGMA journal_mode=WAL').fetchone()[0] == 'wal'
c.execute('PRAGMA wal_autocheckpoint=0')
c.execute("INSERT INTO evidence VALUES ('committed-only-in-wal')")
c.commit()
os._exit(0)
"""
    subprocess.run([sys.executable, "-c", child, str(live)], check=True)
    assert Path(str(live) + "-wal").exists()
    assert Path(str(live) + "-shm").exists()
    return old


def rows(db: Path) -> list[str]:
    with closing(sqlite3.connect(db)) as conn, conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        return [r[0] for r in conn.execute("SELECT value FROM evidence ORDER BY rowid")]


def test_documented_online_backup_includes_wal_and_audit(tmp_path: Path) -> None:
    data, backup = tmp_path / "data", tmp_path / "backup"
    wal_fixture(data)
    run_step("online-backup", tmp_path, data, backup)
    assert rows(backup / "gpo-lens.sqlite3") == ["before", "committed-only-in-wal"]
    assert (backup / "audit.log").read_bytes() == (data / "audit.log").read_bytes()


def test_documented_offline_backup_keeps_matching_sidecars(tmp_path: Path) -> None:
    data, backup = tmp_path / "data", tmp_path / "backup"
    wal_fixture(data)
    run_step("offline-backup", tmp_path, data, backup)
    assert (backup / "gpo-lens.sqlite3-wal").exists()
    assert (backup / "gpo-lens.sqlite3-shm").exists()
    assert rows(backup / "gpo-lens.sqlite3") == ["before", "committed-only-in-wal"]
    assert (backup / "audit.log").read_bytes() == (data / "audit.log").read_bytes()


def test_documented_restore_prevents_stale_wal_replay(tmp_path: Path) -> None:
    data, backup = tmp_path / "data", tmp_path / "backup"
    old = wal_fixture(data)
    backup.mkdir()
    shutil.copy2(old, backup / "gpo-lens.sqlite3")
    (backup / "audit.log").write_text("older synthetic audit\n")
    run_step("restore", tmp_path, data, backup)
    assert rows(data / "gpo-lens.sqlite3") == ["before"]
    assert (data / "audit.log").read_bytes() == (backup / "audit.log").read_bytes()
    preserved = list(tmp_path.glob("data-before-restore-*"))
    assert len(preserved) == 1
    assert (preserved[0] / "gpo-lens.sqlite3-wal").exists()


@pytest.mark.parametrize("step", ["online-backup", "restore"])
def test_python_payload_survives_windows_powershell_51_native_arguments(step: str) -> None:
    # PS 5.1's legacy native argument marshalling strips embedded double quotes
    # from python -c. Literal here-strings with Python single quotes survive.
    payloads = re.findall(r"= @'\n(.*?)\n'@", documented_step(step), re.S)
    assert payloads
    for payload in payloads:
        assert '"' not in payload
        compile(payload, "documented Python payload", "exec")


def test_documented_restore_verifies_legacy_guid_forms(tmp_path: Path) -> None:
    data, backup = tmp_path / "data", tmp_path / "backup"
    old = wal_fixture(data, stored_gpo="{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}")
    backup.mkdir()
    shutil.copy2(old, backup / "gpo-lens.sqlite3")
    (backup / "audit.log").write_text("older synthetic audit\n")
    run_step("restore", tmp_path, data, backup)
    assert rows(data / "gpo-lens.sqlite3") == ["before"]
