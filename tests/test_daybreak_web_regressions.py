"""One-off synthetic probes for the independent v1.3.0 security review."""

from __future__ import annotations

import csv
import io
import sqlite3
from datetime import UTC, datetime

from test_exports import export_client  # noqa: F401

# The reviewer imports this shared pytest fixture as a module-level definition.
# Function arguments request it from pytest.
# ruff: noqa: F811


def test_extended_secret_corpus_across_export_routes(export_client, monkeypatch) -> None:
    import copy

    from gpo_lens.finding_model import EvidenceRef, FindingCandidate
    from gpo_lens.findings import append_triage_event, create_evaluation_run, run_evaluation
    from gpo_lens.model import Setting
    from gpo_lens.store import load_estate, save_estate

    registry_secret = "SYNTH-REGPASS-REVIEW-ONLY"
    path_secret = "SYNTH-PATHPASS-REVIEW-ONLY"
    cpassword_secret = "SYNTH-CPASS-REVIEW-ONLY"
    gpp_secret = "SYNTH-GPPPASS-REVIEW-ONLY"

    conn = sqlite3.connect(export_client.db_path)
    estate = load_estate(conn)
    gpo = estate.gpos[0]
    gpo.settings.extend(
        [
            Setting(
                gpo.id,
                "Computer",
                "Registry",
                r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon:DefaultPassword",
                "DefaultPassword",
                registry_secret,
                {
                    "tag": "Value",
                    "children": [
                        {"tag": "Name", "text": "DefaultPassword"},
                        {"tag": "String", "text": registry_secret},
                    ],
                },
                False,
            ),
            Setting(
                gpo.id,
                "Computer",
                "Files",
                "File:credentialed-source",
                "credentialed-source",
                f"https://lab-user:{path_secret}@files.invalid/share",
                {
                    "tag": "Properties",
                    "@attr": {"fromPath": f"https://lab-user:{path_secret}@files.invalid/share"},
                },
                False,
            ),
            Setting(
                gpo.id,
                "Computer",
                "Synthetic",
                "Control:cpassword",
                "control-cpassword",
                cpassword_secret,
                {"@attr": {"cpassword": cpassword_secret}},
                False,
            ),
            Setting(
                gpo.id,
                "Computer",
                "Synthetic",
                "Control:password",
                "password",
                gpp_secret,
                {"password": gpp_secret},
                False,
            ),
        ]
    )
    snapshot_id = save_estate(conn, estate)
    run_id = create_evaluation_run(conn, snapshot_id, detector_set_digest="review-only")
    run_evaluation(
        conn,
        run_id,
        [
            FindingCandidate(
                detector_id="review-probe",
                detector_version="1",
                category="review.synthetic-secret",
                subject_type="gpo",
                subject_key=(gpo.id,),
                severity="high",
                summary=f"Registry {registry_secret}; path {path_secret}",
                detail=f"Observed {registry_secret} and {path_secret}",
                evidence_refs=(
                    EvidenceRef(
                        snapshot_id,
                        gpo.id,
                        "registry_pol",
                        "DefaultPassword",
                        f"value={registry_secret}",
                    ),
                ),
                gpo_name=gpo.name,
            )
        ],
    )
    occurrence_id = 2
    append_triage_event(
        conn,
        occurrence_id,
        "accepted_risk",
        "review-actor",
        note="review-note",
        rationale="review-rationale",
        expires_at=datetime(2030, 1, 1, tzinfo=UTC),
    )
    conn.close()

    gpo_id = gpo.id
    ou_path = gpo.links[0].som_path
    routes = [
        f"/gpo/{gpo_id}",
        f"/gpo/{gpo_id}?view=ledger",
        "/search?q=DefaultPassword",
        "/search?q=credentialed-source",
        "/setting?identity=HKLM%5CSoftware%5CMicrosoft%5CWindows%20NT%5CCurrentVersion%5CWinlogon%3ADefaultPassword",
        "/findings?lifecycle=all&triage=all",
        f"/findings/{occurrence_id}",
        "/accepted-risks?as_of=2027-01-01T00:00:00Z",
        "/briefing",
        f"/changelog?snap_a=1&snap_b={snapshot_id}",
        f"/export/gpo/{gpo_id}?format=json",
        f"/export/gpo/{gpo_id}?format=csv",
        f"/export/gpo/{gpo_id}?format=md",
        "/export/findings?format=json",
        "/export/findings?format=csv&lifecycle=all&triage=all",
        "/export/findings?format=md&lifecycle=all&triage=all",
        f"/export/ou/{ou_path}?format=csv",
        f"/export/ou/{ou_path}?format=json",
    ]
    formats = ("csv", "md")
    leak_rows: list[str] = []
    control_failures: list[str] = []
    tested = 0
    for route in routes:
        variants = [route]
        if not route.startswith("/export/"):
            sep = "&" if "?" in route else "?"
            variants.extend(route + sep + "format=" + fmt for fmt in formats)
        for variant in variants:
            response = export_client.get(variant)
            assert response.status_code == 200, (variant, response.status_code, response.text[:300])
            tested += 1
            leaked = [
                label
                for label, secret in (("registry", registry_secret), ("path", path_secret))
                if secret in response.text
            ]
            if leaked:
                leak_rows.append(f"{variant} -> {','.join(leaked)}")
            for label, secret in (("cpassword", cpassword_secret), ("gpp-password", gpp_secret)):
                if secret in response.text:
                    control_failures.append(f"{variant} -> {label}")

    comparator = copy.deepcopy(gpo)
    for setting in comparator.settings:
        if setting.identity.endswith(":DefaultPassword"):
            setting.display_value = "different-registry-value"
        elif setting.identity == "File:credentialed-source":
            setting.display_value = "different-path-value"
    from gpo_lens import ingest

    monkeypatch.setattr(ingest, "load_baseline_from_zip", lambda _path: [comparator])
    for endpoint in ("baseline", "golden-diff"):
        for fmt in formats:
            variant = f"/{endpoint} format={fmt}"
            response = export_client.post(
                f"/{endpoint}",
                files={"file": ("synthetic.zip", b"review", "application/zip")},
                data={"format": fmt},
                headers={"Origin": "http://testserver"},
            )
            assert response.status_code == 200, (variant, response.status_code, response.text[:300])
            tested += 1
            leaked = [
                label
                for label, secret in (("registry", registry_secret), ("path", path_secret))
                if secret in response.text
            ]
            if leaked:
                leak_rows.append(f"{variant} -> {','.join(leaked)}")
            for label, secret in (("cpassword", cpassword_secret), ("gpp-password", gpp_secret)):
                if secret in response.text:
                    control_failures.append(f"{variant} -> {label}")

    print(f"PROBE routes={tested} leaked_responses={len(leak_rows)}")
    print("CONTROL_SECRET_LEAKS", control_failures)
    assert not leak_rows, leak_rows
    assert not control_failures


def test_csv_and_markdown_injection_probe() -> None:
    from gpo_lens.exports import ExportDocument, ExportSection, render_export

    values = [
        "=1+1",
        "+1+1",
        "-1+1",
        "@SUM(1,1)",
        "\t=1+1",
        "\r=1+1",
        "\n=1+1",
        " =1+1",
        "\u00a0=1+1",
        '"=1+1',
        "＝1+1",
        "=cmd|' /C calc'!A0",
        "[link](https://invalid.example)",
        "![image](https://invalid.example/pixel)",
        "<img src=https://invalid.example/pixel>",
        "<script>alert(1)</script>",
    ]
    doc = ExportDocument("probe", {}, (ExportSection("rows", ({"value": v} for v in values)),))
    csv_text = "".join(render_export(doc, "csv"))
    md_text = "".join(render_export(doc, "md"))
    rows = list(csv.reader(io.StringIO(csv_text)))
    dangerous = {"=", "+", "-", "@", "\t", "\r"}
    unneutralized = [row[3] for row in rows[1:] if row[3] and row[3][0] in dangerous]
    active_markdown = [
        token for token in ("[link](", "![image](", "<img ", "<script>") if token in md_text
    ]
    print("CSV_ACTIVE_PREFIXES", unneutralized)
    print("MARKDOWN_ACTIVE_TOKENS", active_markdown)
    print(
        "CSV_LITERAL_LEADING_CASES",
        [v for v in values if v.startswith(("\n", " ", "\u00a0", '"', "＝"))],
    )
    assert not unneutralized
    assert not active_markdown


def test_gpo_controlled_xss_probe(export_client) -> None:
    from urllib.parse import quote

    from gpo_lens.finding_model import EvidenceRef, FindingCandidate
    from gpo_lens.findings import append_triage_event, create_evaluation_run, run_evaluation
    from gpo_lens.model import Setting
    from gpo_lens.store import load_estate, save_estate

    payload = '<img src=x onerror="alert(9713)">'
    second_payload = '<svg/onload="alert(9714)">'
    conn = sqlite3.connect(export_client.db_path)
    estate = load_estate(conn)
    gpo = estate.gpos[0]
    gpo.name = "XSS name " + payload
    gpo.description = "XSS description " + payload
    gpo.owner = "XSS owner " + second_payload
    gpo.wmi_filter = "XSS WMI " + second_payload
    gpo.settings.append(
        Setting(
            gpo.id,
            "Computer",
            "Synthetic-XSS",
            "XSS:probe",
            "XSS display " + payload,
            "XSS value " + second_payload,
            {"comment": "XSS comment " + payload},
            False,
        )
    )
    snapshot_id = save_estate(conn, estate)
    run_id = create_evaluation_run(conn, snapshot_id, detector_set_digest="review-xss")
    run_evaluation(
        conn,
        run_id,
        [
            FindingCandidate(
                detector_id="review-xss",
                detector_version="1",
                category="review.xss",
                subject_type="gpo",
                subject_key=(gpo.id,),
                severity="high",
                summary="XSS summary " + payload,
                detail="XSS detail " + second_payload,
                remediation="XSS remediation " + payload,
                evidence_refs=(
                    EvidenceRef(snapshot_id, gpo.id, "review", "xss", "XSS evidence " + payload),
                ),
                gpo_name=gpo.name,
            )
        ],
    )
    append_triage_event(conn, 2, "commented", "review-actor", note="XSS note " + payload)
    conn.close()

    routes = [
        "/inventory?q=XSS",
        f"/gpo/{gpo.id}",
        "/search?q=XSS",
        "/setting?identity=" + quote("XSS:probe", safe=""),
        "/findings?lifecycle=all&triage=all",
        "/findings/2",
        f"/ou/{gpo.links[0].som_path}",
    ]
    escaped_count = 0
    for route in routes:
        response = export_client.get(route)
        assert response.status_code == 200, (route, response.status_code)
        assert payload not in response.text
        assert second_payload not in response.text
        escaped_count += int("&lt;img" in response.text or "&lt;svg" in response.text)
    print(f"XSS routes={len(routes)} raw_payloads=0 escaped_routes={escaped_count}")
    assert escaped_count >= 3


def test_loopback_dns_rebinding_can_mutate_new_triage_route(tmp_path, monkeypatch) -> None:
    from pathlib import Path

    from fastapi.testclient import TestClient

    from gpo_lens.finding_model import FindingCandidate
    from gpo_lens.findings import create_evaluation_run, get_triage_status, run_evaluation
    from gpo_lens.ingest import load_estate
    from gpo_lens.store import init_db, save_estate
    from gpo_lens.web.app import create_app

    db_path = tmp_path / "rebind.sqlite3"
    conn = sqlite3.connect(db_path)
    init_db(conn)
    snapshot_id = save_estate(conn, load_estate(Path("tests/fixtures")))
    run_id = create_evaluation_run(conn, snapshot_id, detector_set_digest="review-rebind")
    run_evaluation(
        conn,
        run_id,
        [
            FindingCandidate(
                detector_id="review-rebind",
                detector_version="1",
                category="review.rebind",
                severity="high",
                subject_type="estate",
                subject_key=("estate",),
                summary="Synthetic finding for CSRF review",
            )
        ],
    )
    conn.close()
    monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("GPO_LENS_ALLOWED_HOSTS", raising=False)

    hostile_origin = "http://rebind.attacker.invalid"
    client = TestClient(
        create_app(str(db_path)),
        base_url=hostile_origin,
        client=("127.0.0.1", 49152),
    )
    response = client.post(
        "/findings/1/triage",
        data={"status": "acknowledged", "note": "set by rebind origin"},
        headers={"Origin": hostile_origin},
        follow_redirects=False,
    )
    conn = sqlite3.connect(db_path)
    status = get_triage_status(conn, 1)
    conn.close()
    print(
        "DNS_REBIND",
        f"status={response.status_code}",
        f"location={response.headers.get('location')}",
        f"triage={status.status}",
        f"actor={status.actor}",
    )
    assert response.status_code == 400
    assert "GPO_LENS_ALLOWED_HOSTS" in response.text
    assert status.status == "open"
