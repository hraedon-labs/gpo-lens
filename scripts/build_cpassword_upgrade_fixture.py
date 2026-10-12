"""Build the v1.4.0 cpassword upgrade fixture with installed v1.4.0 code.

Run: .venv/bin/python scripts/build_cpassword_upgrade_fixture.py
Requires the local ``v1.4.0`` tag, uv, and access to the package index/cache.

v1.4.0 stored GPP ``cpassword`` values verbatim in ``setting.raw`` (and, through
the display-value fallback, in setting text, diffs and event payloads) and kept
the first four characters of the SYSVOL value in each cpassword finding. This
fixture is what that release actually wrote, so the schema-v11 scrub is tested
against real released bytes rather than a simulation:

* snapshot 1 (later deleted, so its rows are left in free pages) carries
  ``DELETED_PROBE`` and no SYSVOL;
* snapshots 2 and 3 carry every report probe in several GPP element types and
  casings, a ``<cpassword>`` child element, an escaped XML blob and a
  display-value probe that changes between them (so a ``gpo.modified`` event
  payload holds it), plus a SYSVOL cpassword whose prefix the finding stores;
* a triage note quotes ``REPORT_PROBE``.

The database is NOT vacuumed after that delete. ``tests/test_cpassword_redaction.py``
imports ``build_probe_export`` and the probe constants from this file.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests/golden_estate"
OUTPUT = ROOT / "tests/fixtures/released_databases"
TAG = "v1.4.0"
NAME = "v1.4.0-cpassword"

# Obvious synthetic probes (never realistic secrets); each at least 6 chars.
REPORT_PROBE = "PROBEcpwZZ123"  # Groups <User>/<Properties cpassword=…>
SERVICE_PROBE = "PROBEcpwSVC234"  # Services, attribute spelled CPassword
TASK_PROBE = "PROBEcpwTSK345"  # Scheduled Tasks, CPASSWORD
DSN_PROBE = "PROBEcpwDSN456"  # Data Sources, cPassword
DRIVE_PROBE = "PROBEcpwDRV567"  # Drive Maps, cpassword
ELEMENT_PROBE = "PROBEcpwELM678"  # <cpassword> child element
BLOB_PROBE = "PROBEcpwBLB789"  # escaped XML fragment stored verbatim
DISPLAY_PROBES = ("PROBEcpwDSP890", "PROBEcpwDSP901")  # first attribute -> display value
DELETED_PROBE = "PROBEcpwDEL012"  # only in the deleted snapshot
SYSVOL_PROBE = "QZXJprobeSYSVOL0123"  # SYSVOL Groups.xml; v1.4.0 kept "QZXJ"
SYSVOL_PREFIX = SYSVOL_PROBE[:4]

REPORT_PROBES = (
    REPORT_PROBE,
    SERVICE_PROBE,
    TASK_PROBE,
    DSN_PROBE,
    DRIVE_PROBE,
    ELEMENT_PROBE,
    BLOB_PROBE,
    *DISPLAY_PROBES,
    DELETED_PROBE,
)
ALL_PROBES = (*REPORT_PROBES, SYSVOL_PROBE)

_GPO_ANCHOR = "<Name>golden-v2-task</Name>"
_SYSVOL_GROUPS = "{AAAAAAAA-0002-0002-0002-AAAAAAAAAAAA}/MACHINE/Preferences/Groups/Groups.xml"


def _probe_extensions(*, drive_probe: str, display_probe: str | None) -> str:
    widget = (
        "<ExtensionData><Name>Lab Widgets</Name><Extension>"
        f'<Widget cpassword="{display_probe}" Name="lab-widget"/>'
        "</Extension></ExtensionData>"
        if display_probe
        else ""
    )
    return (
        "<ExtensionData><Name>Local Users and Groups</Name><Extension>"
        '<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">'
        '<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="LabAdmin" '
        'uid="{11111111-1111-1111-1111-111111111111}">'
        f'<Properties action="U" userName="LabAdmin" cpassword="{REPORT_PROBE}"/>'
        "</User></Groups></Extension></ExtensionData>"
        "<ExtensionData><Name>Services</Name><Extension>"
        '<NTServices clsid="{2CFB484A-4E96-4b5d-A0B6-093D2F91E6AE}">'
        '<NTService clsid="{AB6F0B67-341F-4e51-92F9-005FBFBA1A43}" name="LabSvc" '
        'uid="{22222222-2222-2222-2222-222222222222}">'
        f'<Properties serviceName="LabSvc" accountName="LAB\\svc" CPassword="{SERVICE_PROBE}"/>'
        "</NTService></NTServices></Extension></ExtensionData>"
        "<ExtensionData><Name>Scheduled Tasks</Name><Extension>"
        '<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">'
        '<TaskV2 clsid="{D8896631-B747-47a7-84A6-C155337F3BC8}" name="LabTask" '
        'uid="{33333333-3333-3333-3333-333333333333}">'
        f'<Properties action="C" runAs="LAB\\task" CPASSWORD="{TASK_PROBE}"/>'
        "</TaskV2></ScheduledTasks></Extension></ExtensionData>"
        "<ExtensionData><Name>Data Sources</Name><Extension>"
        '<DataSources clsid="{380F820F-F21B-41ac-A3CC-24D4F80F067B}">'
        '<DataSource clsid="{5C209626-D820-4d69-8D50-1FACD6214488}" name="LabDsn" '
        'uid="{44444444-4444-4444-4444-444444444444}">'
        f'<Properties dsn="LabDsn" username="lab" cPassword="{DSN_PROBE}"/>'
        "</DataSource></DataSources></Extension></ExtensionData>"
        "<ExtensionData><Name>Drive Maps</Name><Extension>"
        '<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">'
        '<Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="L:" '
        'uid="{55555555-5555-5555-5555-555555555555}">'
        f'<Properties action="U" path="\\\\lab-files\\share" userName="lab" '
        f'cpassword="{drive_probe}" '
        f'description="&lt;Properties cpassword=&quot;{BLOB_PROBE}&quot;/&gt;"/>'
        f"<cpassword>{ELEMENT_PROBE}</cpassword>"
        "</Drive></Drives></Extension></ExtensionData>" + widget
    )


def build_probe_export(
    destination: Path,
    *,
    drive_probe: str = DRIVE_PROBE,
    display_probe: str | None = DISPLAY_PROBES[0],
    sysvol: bool = True,
) -> Path:
    """Copy the golden estate to *destination* and plant the probes."""
    shutil.copytree(GOLDEN, destination, ignore=shutil.ignore_patterns("*.py"))
    report = destination / "AllGPOs.xml"
    xml = report.read_text(encoding="utf-8")
    computer = xml.index("<Computer>", xml.index(_GPO_ANCHOR))
    insert_at = xml.index("</Computer>", computer)
    xml = (
        xml[:insert_at]
        + _probe_extensions(drive_probe=drive_probe, display_probe=display_probe)
        + xml[insert_at:]
    )
    report.write_text(xml, encoding="utf-8")
    sysvol_root = destination / "SYSVOL-Policies"
    if not sysvol:
        shutil.rmtree(sysvol_root)
        return destination
    groups = sysvol_root / _SYSVOL_GROUPS
    text = groups.read_text(encoding="utf-8")
    start = text.index('cpassword="') + len('cpassword="')
    end = text.index('"', start)
    groups.write_text(text[:start] + SYSVOL_PROBE + text[end:], encoding="utf-8")
    return destination


def worker(scratch: Path, destination: Path) -> None:
    # These imports MUST resolve in the scratch venv to the installed release.
    import gpo_lens
    from gpo_lens.findings import append_triage_event
    from gpo_lens.store import delete_snapshot

    assert not Path(gpo_lens.__file__).resolve().is_relative_to(ROOT / "src")
    assert gpo_lens.__version__ == TAG.removeprefix("v"), gpo_lens.__version__
    db = destination / f"{NAME}.sqlite3"
    stages = (
        build_probe_export(
            scratch / "s1", drive_probe=DELETED_PROBE, display_probe=None, sysvol=False
        ),
        build_probe_export(scratch / "s2"),
        build_probe_export(scratch / "s3", display_probe=DISPLAY_PROBES[1]),
    )
    for export in stages:
        subprocess.run(
            [sys.executable, "-m", "gpo_lens", "--db", str(db), "ingest", "--diff-latest"]
            + [str(export)],
            check=True,
        )
    with closing(sqlite3.connect(db)) as conn:
        (finding_id,) = conn.execute(
            "SELECT id FROM finding WHERE detector_id = 'cpassword' "
            "AND resolved_in_snapshot IS NULL"
        ).fetchone()
        append_triage_event(
            conn,
            finding_id,
            "acknowledged",
            "lab-analyst",
            note=f"report shows cpassword {REPORT_PROBE}; ticket raised",
        )
        conn.commit()
        # Keep the scratch host path out of a committed file (only sysvol_path
        # records it), then VACUUM so the old cells are gone too. Snapshot 1 has
        # no SYSVOL, so deleting it afterwards leaves only probes in free pages.
        conn.execute(
            "UPDATE gpo SET sysvol_path = '/lab/export' || substr(sysvol_path, ?) "
            "WHERE sysvol_path IS NOT NULL",
            (len(str(scratch)) + 1,),
        )
        conn.commit()
        conn.execute("VACUUM")
        assert delete_snapshot(conn, 1)
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        names = sorted(
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        )
        counts = {
            name: conn.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0] for name in names
        }
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    # Closing checkpoints and removes the WAL; the main file keeps free pages.
    data = db.read_bytes()
    # The full SYSVOL value was never stored, only its four-character prefix.
    missing = [p for p in (*REPORT_PROBES, SYSVOL_PREFIX) if p.encode() not in data]
    assert not missing, f"v1.4.0 did not persist {missing}; fixture would prove nothing"
    assert str(scratch).encode() not in data, "scratch host path left in the fixture"
    (destination / f"{NAME}.json").write_text(
        json.dumps(
            {"tag": TAG, "schema_version": version, "counts": counts},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--scratch", type=Path)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    if args.worker:
        worker(args.scratch, args.output)
        return
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gpo-cpassword-fixture-") as temporary:
        scratch = Path(temporary)
        checkout = scratch / "code"
        subprocess.run(
            ["git", "worktree", "add", "--detach", str(checkout), TAG], cwd=ROOT, check=True
        )
        try:
            venv = scratch / "venv"
            subprocess.run(["uv", "venv", str(venv), "--python", sys.executable], check=True)
            python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            subprocess.run(
                ["uv", "pip", "install", "--python", str(python), str(checkout)], check=True
            )
            produced = scratch / "produced"
            produced.mkdir()
            exports = scratch / "exports"
            exports.mkdir()
            environment = {
                k: v
                for k, v in os.environ.items()
                if not k.startswith("GPO_LENS_") and k != "PYTHONPATH"
            }
            subprocess.run(
                [str(python), str(Path(__file__).resolve()), "--worker"]
                + ["--scratch", str(exports), "--output", str(produced)],
                cwd=checkout,
                env=environment,
                check=True,
            )
            manifest_path = produced / f"{NAME}.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["commit"] = subprocess.check_output(
                ["git", "rev-parse", f"{TAG}^{{commit}}"], cwd=ROOT, text=True
            ).strip()
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            for artifact in produced.iterdir():
                if artifact.suffix in {".sqlite3", ".json"}:
                    shutil.copyfile(artifact, args.output / artifact.name)
        finally:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(checkout)], cwd=ROOT, check=True
            )


if __name__ == "__main__":
    main()
