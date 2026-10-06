"""Build upgrade fixtures using installed released code, never today's schema.

Run: .venv/bin/python scripts/build_released_db_fixtures.py
Requires local release tags, uv, and access to the Python package index/cache.
Each tag gets a detached scratch worktree and its own scratch virtualenv.
The worker runs in that virtualenv; it uses the release's CLI and web/API.
Timestamps/request IDs come from the released code, so regeneration is semantic,
not byte-identical. No source DB or workplace export is read.
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
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "tests/fixtures/released_databases"
TAGS = ("v0.5.0", "v0.7.0", "v0.7.1", "v1.0.0", "v1.1.0", "v1.2.0")
GPO_IDS = {"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "cccccccc-cccc-cccc-cccc-cccccccccccc"}


def build_export(destination: Path) -> None:
    """Small subset of the existing synthetic fixture: two GPOs, two SOMs."""
    destination.mkdir()
    fixtures = ROOT / "tests/fixtures"
    tree = ET.parse(fixtures / "AllGPOs.xml")  # noqa: S314 — trusted repo fixture
    root = tree.getroot()
    for gpo in list(root):
        identifier = gpo.findtext("Identifier/Identifier", "").strip("{}").lower()
        if identifier not in GPO_IDS:
            root.remove(gpo)
    xml = ET.tostring(root, encoding="unicode")
    xml = xml.replace("fakefixture.local", "lab.example.com").replace(
        "dc=fakefixture,dc=local", "dc=lab,dc=example,dc=com"
    )
    (destination / "AllGPOs.xml").write_text(xml, encoding="utf-8")
    for name in ("gp-inheritance.json", "gpo-metadata.json", "ou-tree.json"):
        records = json.loads((fixtures / name).read_text(encoding="utf-8-sig"))
        if name == "gpo-metadata.json":
            records = [r for r in records if r["Id"].strip("{}").lower() in GPO_IDS]
        if name == "gp-inheritance.json":
            for record in records:
                record["InheritedGpoLinks"] = [
                    link
                    for link in record["InheritedGpoLinks"]
                    if link["GpoId"].strip("{}").lower() in GPO_IDS
                ]
        text = json.dumps(records).replace("fakefixture.local", "lab.example.com")
        text = text.replace("dc=fakefixture,dc=local", "dc=lab,dc=example,dc=com")
        (destination / name).write_text(text, encoding="utf-8-sig")
    # Distinct GPOs exercise both inventory and collector-error gap persistence.
    for name, records in (
        (
            "gpo-inventory.json",
            [{"Id": "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}", "DisplayName": "Lab missing GPO"}],
        ),
        (
            "collection-errors.json",
            [
                {
                    "GpoId": "{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}",
                    "DisplayName": "Lab unreadable GPO",
                    "Error": "Synthetic collection failure",
                }
            ],
        ),
    ):
        (destination / name).write_text(json.dumps(records), encoding="utf-8-sig")


def worker(tag: str, export: Path, destination: Path) -> None:
    # These imports MUST resolve in the scratch venv to the installed release.
    from fastapi.testclient import TestClient

    import gpo_lens
    from gpo_lens.web.app import create_app

    assert not Path(gpo_lens.__file__).resolve().is_relative_to(ROOT / "src")
    db = destination / f"{tag}.sqlite3"
    subprocess.run(
        [sys.executable, "-m", "gpo_lens", "--db", str(db), "ingest", str(export)],
        check=True,
    )
    # A real change between snapshots, without fixing the version-skew finding.
    xml_path = export / "AllGPOs.xml"
    xml = xml_path.read_text().replace("gpo-version-skew", "Lab renamed policy")
    xml_path.write_text(xml.replace('ValueName="FakeValue">1<', 'ValueName="FakeValue">2<'))
    upload = export.parent / "export.zip"
    with zipfile.ZipFile(upload, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(export.iterdir()):
            archive.write(path, path.name)
    with TestClient(create_app(str(db)), base_url="http://localhost") as client:
        with upload.open("rb") as handle:
            response = client.post(
                "/ingest",
                files={"file": ("lab-export.zip", handle, "application/zip")},
                headers={"Origin": "http://localhost", "Authorization": "Bearer fixture-token"},
                follow_redirects=False,
            )
        assert response.status_code == 303, response.text
        with sqlite3.connect(db) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master")}
            if "finding" in tables:
                from gpo_lens.findings import append_triage_event, triage_finding

                ids = [
                    row[0]
                    for row in conn.execute(
                        "SELECT id FROM finding WHERE resolved_in_snapshot IS NULL ORDER BY id"
                    )
                ]
                assert len(ids) >= 3
                # Deployed legacy public API writes the table migrated by v8.
                triage_finding(conn, ids[0], "acknowledged", "Lab investigation", "lab-analyst")
                triage_finding(conn, ids[1], "accepted_risk", "Lab exception approved", "lab-owner")
                # Plan 024 API was also available to callers at these releases.
                append_triage_event(
                    conn,
                    ids[2],
                    "accepted_risk",
                    "lab-reviewer",
                    note="Lab risk review",
                    rationale="Lab compensating control",
                )
                conn.commit()
    with sqlite3.connect(db) as conn:
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
        assert counts["snapshot"] == 2
        assert counts["gpo"] == 4
        assert counts["setting"] > 0 and counts["delegation"] > 0 and counts["coverage_gap"] > 0
        conn.execute("VACUUM")
    audit = destination / "audit.log"
    audit_name = None
    if audit.exists():
        audit_name = f"{tag}.audit.log"
        audit.rename(destination / audit_name)
    (destination / f"{tag}.json").write_text(
        json.dumps(
            {"tag": tag, "schema_version": version, "counts": counts, "audit_file": audit_name},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", choices=TAGS)
    parser.add_argument("--export", type=Path)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker, args.export, args.output)
        return
    args.output.mkdir(parents=True, exist_ok=True)
    for tag in TAGS:
        with tempfile.TemporaryDirectory(prefix="gpo-release-") as temporary:
            scratch = Path(temporary)
            checkout = scratch / "code"
            subprocess.run(
                ["git", "worktree", "add", "--detach", str(checkout), tag], cwd=ROOT, check=True
            )
            try:
                venv = scratch / "venv"
                subprocess.run(["uv", "venv", str(venv), "--python", sys.executable], check=True)
                python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
                subprocess.run(
                    [
                        "uv",
                        "pip",
                        "install",
                        "--python",
                        str(python),
                        f"{checkout}[web]",
                        "httpx==0.28.1",
                    ],
                    check=True,
                )
                export = scratch / "export"
                build_export(export)
                produced = scratch / "produced"
                produced.mkdir()
                environment = {
                    k: v
                    for k, v in os.environ.items()
                    if not k.startswith("GPO_LENS_") and k != "PYTHONPATH"
                }
                environment["GPO_LENS_AUTH_TOKEN"] = "fixture-token"  # noqa: S105 — synthetic fixture
                subprocess.run(
                    [
                        str(python),
                        str(Path(__file__).resolve()),
                        "--worker",
                        tag,
                        "--export",
                        str(export),
                        "--output",
                        str(produced),
                    ],
                    cwd=checkout,
                    env=environment,
                    check=True,
                )
                manifest_path = produced / f"{tag}.json"
                manifest = json.loads(manifest_path.read_text())
                manifest["commit"] = subprocess.check_output(
                    ["git", "rev-parse", f"{tag}^{{commit}}"], cwd=ROOT, text=True
                ).strip()
                manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
                for artifact in produced.iterdir():
                    if artifact.suffix in {".sqlite3", ".json", ".log"}:
                        shutil.copyfile(artifact, args.output / artifact.name)
            finally:
                subprocess.run(
                    ["git", "worktree", "remove", "--force", str(checkout)], cwd=ROOT, check=True
                )


if __name__ == "__main__":
    main()
