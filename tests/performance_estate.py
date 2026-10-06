"""Seeded lab-only estate, comparator upload and three-snapshot finding history.

Defaults model the calibration's scale without reading any external inputs.
The smaller sizes used by ordinary tests preserve the same data relationships.
"""

from __future__ import annotations

import io
import json
import random
import sqlite3
import zipfile
from datetime import UTC, datetime
from uuid import UUID
from xml.etree import ElementTree as ET

from gpo_lens.finding_model import EvidenceRef, FindingCandidate
from gpo_lens.findings import create_evaluation_run, run_evaluation
from gpo_lens.ingest import parse_report_xml
from gpo_lens.model import Estate, GpoLink, Som, SomLink
from gpo_lens.store import init_db, save_estate

LAB_SECRET = "SYNTH-PERFORMANCE-CREDENTIAL-ONLY"


def report_xml(index: int, settings: int = 31, *, drift: bool = False) -> bytes:
    root = ET.Element("GPO")
    identifier = ET.SubElement(root, "Identifier")
    ET.SubElement(identifier, "Identifier").text = str(UUID(int=index + 1))
    ET.SubElement(identifier, "Domain").text = "lab.example.com"
    ET.SubElement(root, "Name").text = f"Lab policy {index:03}"
    for side in ("Computer", "User"):
        node = ET.SubElement(root, side)
        ET.SubElement(node, "Enabled").text = "true"
        extension_data = ET.SubElement(node, "ExtensionData")
        ET.SubElement(extension_data, "Name").text = "Registry"
        extension = ET.SubElement(extension_data, "Extension")
        for j in range(settings):
            if (j % 2 == 0) != (side == "Computer"):
                continue
            name = "DefaultPassword" if index == 0 and j == 0 else f"Value{j:03}"
            setting = ET.SubElement(
                extension, "Registry", KeyName=r"HKLM\Software\Lab", ValueName=name
            )
            setting.text = LAB_SECRET if name == "DefaultPassword" else str((j + int(drift)) % 3)
    # Every scale includes the 1.4 parsers and dependency inventory, so export
    # budgets exercise the integrated release rather than registry-only data.
    computer = root.find("Computer")
    assert computer is not None
    audit = ET.SubElement(computer, "ExtensionData")
    ET.SubElement(audit, "Name").text = "Advanced Audit Configuration"
    item = ET.SubElement(ET.SubElement(audit, "Extension"), "AuditSetting")
    for name, value in (
        ("PolicyTarget", "System"),
        ("SubcategoryGuid", "{0CCE923F-69AE-11D9-BED3-505054503030}"),
        ("SubcategoryName", "Audit Credential Validation"),
        ("SettingValue", str(1 if drift else 3)),
    ):
        ET.SubElement(item, name).text = value
    pki = ET.SubElement(computer, "ExtensionData")
    ET.SubElement(pki, "Name").text = "Public Key"
    extension = ET.SubElement(pki, "Extension")
    ET.SubElement(ET.SubElement(extension, "EFSSettings"), "KeyLen").text = (
        "4096" if drift else "2048"
    )
    ET.SubElement(ET.SubElement(extension, "AutoEnrollmentSettings"), "Enabled").text = "true"
    user = root.find("User")
    assert user is not None
    for cse, tag, share in (("Drives", "Drive", "share"), ("Printers", "SharedPrinter", "queue")):
        data = ET.SubElement(user, "ExtensionData")
        ET.SubElement(data, "Name").text = cse
        item = ET.SubElement(ET.SubElement(ET.SubElement(data, "Extension"), cse), tag)
        item.set("name", f"Lab {cse} {index:03}")
        ET.SubElement(item, "Properties", path=rf"\\lab-fs{index % 4:02}\{share}\Lab{index:03}")
    return ET.tostring(root, encoding="utf-16")


def make_estate(
    *,
    seed: int = 140,
    gpos: int = 130,
    soms: int = 1500,
    settings: int = 31,
    links: int = 22,
) -> Estate:
    rng = random.Random(seed)  # noqa: S311 — reproducible fixture selection, no cryptography
    policies = [parse_report_xml(report_xml(i, settings))[0] for i in range(gpos)]
    nodes = []
    for i in range(soms):
        path = f"OU=Lab{i:04},DC=lab,DC=example,DC=com"
        chain = []
        for order, gpo in enumerate(rng.sample(policies, min(links, gpos)), 1):
            enforced = order % 7 == 0
            chain.append(SomLink(gpo.id, order, True, enforced, path))
            gpo.links.append(GpoLink(gpo.id, f"Lab{i:04}", path, True, enforced))
        nodes.append(Som(path, f"Lab{i:04}", "ou", i % 17 == 0, chain))
    return Estate(domain="lab.example.com", gpos=policies, soms=nodes)


def comparator_zip(gpos: int = 130, settings: int = 31) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for i in range(gpos):
            info = zipfile.ZipInfo(f"GPOs/{UUID(int=i + 1)}/gpreport.xml", (2025, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, report_xml(i, settings, drift=True))
    return buffer.getvalue()


def collector_zip(estate: Estate) -> bytes:
    """The same generated estate in the collector's file-only input format."""
    root = ET.Element("GPOs")
    for i, gpo in enumerate(estate.gpos):
        registry_count = sum(s.cse == "Registry" for s in gpo.settings)
        node = ET.fromstring(report_xml(i, registry_count))
        for link in gpo.links:
            item = ET.SubElement(node, "LinksTo")
            for key, value in (
                ("SOMName", link.som_name),
                ("SOMPath", link.som_path),
                ("Enabled", str(link.link_enabled).lower()),
                ("NoOverride", str(link.enforced).lower()),
            ):
                ET.SubElement(item, key).text = value
        root.append(node)
    inheritance = [
        {
            "Path": som.path,
            "Name": som.name,
            "ContainerType": som.container_type,
            "GpoInheritanceBlocked": som.inheritance_blocked,
            "InheritedGpoLinks": [
                {
                    "GpoId": link.gpo_id,
                    "Order": link.order,
                    "Enabled": link.enabled,
                    "Enforced": link.enforced,
                    "Target": link.target,
                }
                for link in som.links
            ],
        }
        for som in estate.soms
    ]
    files = {
        "AllGPOs.xml": ET.tostring(root, encoding="utf-8"),
        "gp-inheritance.json": json.dumps(inheritance, sort_keys=True).encode(),
        "gpo-metadata.json": json.dumps(
            [{"Id": g.id} for g in estate.gpos], sort_keys=True
        ).encode(),
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (2025, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    return buffer.getvalue()


def populate_db(
    conn: sqlite3.Connection, estate: Estate, *, findings_per_gpo: int = 36, snapshots: int = 3
) -> None:
    init_db(conn)
    for n in range(snapshots):
        timestamp = datetime(2025, 1, n + 1, tzinfo=UTC)
        sid = save_estate(conn, estate, taken_at=timestamp)
        run = create_evaluation_run(conn, sid, detector_set_digest="synthetic-performance")
        candidates = [
            FindingCandidate(
                detector_id="lab-calibration",
                detector_version="1",
                category=f"lab:{j % 4}",
                severity=("high", "medium", "low")[j % 3],
                subject_type="gpo",
                subject_key=(gpo.id,),
                dimensions=(("setting", str(j)),),
                gpo_name=gpo.name,
                summary=f"Lab finding {j:03} for {gpo.name}",
                detail=f"Synthetic copied credential {LAB_SECRET}" if j == 0 else "Lab evidence",
                evidence_refs=(EvidenceRef(sid, gpo.id, "lab", f"setting.{j}", "Lab evidence"),),
            )
            for gpo in estate.gpos
            for j in range(findings_per_gpo)
        ]
        run_evaluation(conn, run, candidates)
        # Pin persisted clocks too: independent builds have identical exports.
        conn.execute(
            "UPDATE evaluation_run SET started_at=?,completed_at=? WHERE id=?",
            (timestamp.isoformat(), timestamp.isoformat(), run),
        )
        conn.commit()
