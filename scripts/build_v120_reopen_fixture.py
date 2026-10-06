"""Prepare the F-01 upgrade fixture through the released v1.2.0 public API.

Starts with the immutable released DB; archives the local release tag so no
current code can affect preparation. Run from the project root with .venv Python.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/released_databases"


def main() -> None:
    destination = FIXTURES / "v1.2.0-with-reopen.sqlite3"
    with tempfile.TemporaryDirectory() as raw:
        scratch = Path(raw)
        archive = subprocess.check_output(["git", "archive", "v1.2.0", "src"], cwd=ROOT)
        subprocess.run(["tar", "-x", "-C", raw], input=archive, check=True)
        db = scratch / "upgrade.sqlite3"
        shutil.copyfile(FIXTURES / "v1.2.0.sqlite3", db)
        env = dict(os.environ, PYTHONPATH=str(scratch / "src"))
        subprocess.run(
            [
                str(ROOT / ".venv/bin/python"),
                "-c",
                """
import sqlite3, sys
from contextlib import closing
from gpo_lens.findings import append_triage_event, triage_finding
with closing(sqlite3.connect(sys.argv[1])) as conn, conn:
    oid = conn.execute(
        "SELECT finding_id FROM finding_triage "
        "WHERE status='accepted_risk' ORDER BY id LIMIT 1"
    ).fetchone()[0]
    triage_finding(conn, oid, 'accepted_risk', 'lab-owner', 'Lab approval before withdrawal')
    append_triage_event(
        conn, oid, 'reopened', 'lab-reviewer', note='exception withdrawn before upgrade'
    )
    conn.execute('PRAGMA journal_mode=DELETE')
""",
                str(db),
            ],
            env=env,
            cwd=scratch,
            check=True,
        )
        shutil.copyfile(db, destination)


if __name__ == "__main__":
    main()
