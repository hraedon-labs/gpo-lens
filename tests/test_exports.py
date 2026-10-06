"""Plan 025 WI-6: deterministic, bounded, safe evidence exports."""

from __future__ import annotations

import csv
import io

import pytest

from gpo_lens.exports import ExportDocument, ExportSection, render_export


@pytest.fixture
def export_client(tmp_path, monkeypatch, secret_corpus):
    import sqlite3
    from pathlib import Path

    from fastapi.testclient import TestClient

    from gpo_lens.finding_model import EvidenceRef, FindingCandidate
    from gpo_lens.findings import append_triage_event, create_evaluation_run, run_evaluation
    from gpo_lens.ingest import load_estate
    from gpo_lens.model import Setting
    from gpo_lens.store import init_db, save_estate
    from gpo_lens.web.app import create_app

    estate = load_estate(Path(__file__).parent / "fixtures")
    gpo = estate.gpos[0]
    for i, secret in enumerate(secret_corpus):
        gpo.settings.append(
            Setting(
                gpo.id,
                "Computer",
                "Synthetic",
                f"Carrier{i}",
                f"Carrier{i}",
                secret,
                {"@attr": {"cpassword": secret}},
                False,
            )
        )
    gpo.settings.append(
        Setting(
            gpo.id,
            "User",
            "Registry",
            "Synthetic:Password",
            "Password",
            secret_corpus[-1],
            {},
            False,
        )
    )
    db_path = tmp_path / "exports.sqlite3"
    conn = sqlite3.connect(db_path)
    init_db(conn)
    snapshot_id = save_estate(conn, estate)
    run_id = create_evaluation_run(conn, snapshot_id, detector_set_digest="test-rule-digest")
    run_evaluation(
        conn,
        run_id,
        [
            FindingCandidate(
                detector_id="synthetic",
                detector_version="1",
                category="synthetic",
                subject_type="gpo",
                subject_key=(gpo.id,),
                dimensions=(),
                severity="high",
                summary="Carrier finding",
                evidence_refs=(
                    EvidenceRef(
                        snapshot_id, gpo.id, "setting", "Carrier0", "cpassword=" + secret_corpus[0]
                    ),
                ),
                gpo_name=gpo.name,
            )
        ],
    )
    append_triage_event(
        conn, 1, "accepted_risk", "audit-actor", note="audit-note", rationale="audit-rationale"
    )
    conn.execute("UPDATE finding_triage_event SET occurred_at='2026-01-01T00:00:00+00:00'")
    conn.commit()
    conn.close()
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "export-test-token")
    client = TestClient(
        create_app(str(db_path)), headers={"Authorization": "Bearer export-test-token"}
    )
    client.db_path = db_path
    return client


@pytest.mark.parametrize(
    "url",
    [
        "/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?view=ledger",
        "/findings?lifecycle=all&triage=all",
        "/findings/1",
        "/accepted-risks?as_of=2026-02-01T00:00:00Z",
        "/briefing?as_of=2026-02-01T00:00:00Z",
        "/setting?identity=Carrier0&cse=Synthetic",
        "/search?q=Carrier",
        "/changelog?snap_a=1&snap_b=1",
    ],
)
@pytest.mark.parametrize("format", ["md", "csv"])
def test_view_exports_are_deterministic_provenance_bearing(
    export_client, url, format, secret_corpus
):
    sep = "&" if "?" in url else "?"
    response = export_client.get(url + sep + "format=" + format)
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    assert response.content == export_client.get(url + sep + "format=" + format).content
    for secret in secret_corpus:
        assert secret not in response.text
    for key in ("snapshot", "evaluation", "filters", "caveats", "REDACTED"):
        assert key in response.text


def test_cli_export_available(export_client, capsys):
    from gpo_lens.cli import main

    assert (
        main(
            [
                "--db",
                str(export_client.db_path),
                "export",
                "ledger",
                "--gpo-id",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--format",
                "csv",
            ]
        )
        == 0
    )
    assert "settings_ledger" in capsys.readouterr().out


@pytest.mark.parametrize(
    "url",
    [
        "/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "/search?q=Carrier",
        "/setting?identity=Carrier0&cse=Synthetic",
        "/api/v1/query/settings_at_som?ou_path=dc=fakefixture,dc=local",
        "/api/v1/query/cpassword_scan",
        "/export/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?format=json",
    ],
)
def test_shared_secret_corpus_html_api(export_client, secret_corpus, url):
    response = export_client.get(url)
    assert response.status_code == 200
    for secret in secret_corpus:
        assert secret not in response.text
    assert "REDACTED" in response.text or "****" in response.text


def test_shared_secret_corpus_narration(export_client, secret_corpus, monkeypatch):
    from gpo_lens import narration

    captured = []
    monkeypatch.setenv("GPO_LENS_LLM_ENDPOINT", "https://narration.example.com")
    monkeypatch.setenv("GPO_LENS_API_KEY", "synthetic-api-key")
    monkeypatch.setattr(
        narration,
        "route_question",
        lambda q: {"query": "settings_at_som", "params": {"ou_path": "dc=fakefixture,dc=local"}},
    )
    monkeypatch.setattr(
        narration, "call_llm", lambda system, user: captured.append(user) or "Computed facts only."
    )
    response = export_client.post(
        "/ask", data={"question": "Who sets Carrier?"}, headers={"Origin": "http://testserver"}
    )
    assert response.status_code == 200
    assert captured
    for secret in secret_corpus:
        assert secret not in captured[0]
        assert secret not in response.text
    narration.explain_findings(
        [
            {
                "summary": "password=" + secret_corpus[-1],
                "detail": '<Properties cpassword="' + secret_corpus[0] + '" />',
            }
        ]
    )
    for secret in secret_corpus:
        assert secret not in captured[-1]


@pytest.mark.parametrize(
    "url",
    [
        "/findings?lifecycle=all&triage=all",
        "/findings/1",
        "/accepted-risks?as_of=2026-02-01T00:00:00Z",
        "/briefing?as_of=2026-02-01T00:00:00Z",
    ],
)
@pytest.mark.parametrize("format", ["", "csv", "md"])
def test_authorization_applies_to_audit_fields(export_client, url, format):
    from gpo_lens.web.auth import Permission, Principal, get_principal

    principal = Principal("read-only", "viewer", frozenset({Permission.VIEW}))
    export_client.app.dependency_overrides[get_principal] = lambda: principal
    separator = "&" if "?" in url else "?"
    response = export_client.get(url + separator + "format=" + format)
    assert response.status_code == 200
    for field in ("audit-actor", "audit-note", "audit-rationale"):
        assert field not in response.text
    principal = Principal("triager", "triager", frozenset({Permission.VIEW, Permission.TRIAGE}))
    response = export_client.get(url + separator + "format=" + format)
    assert response.status_code == 200
    if "briefing" not in url:
        assert "audit-actor" in response.text


@pytest.mark.parametrize(
    "url",
    [
        "/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?format=csv",
        "/findings?format=md",
        "/findings/1?format=csv",
        "/briefing?format=csv",
        "/accepted-risks?format=csv",
        "/setting?identity=Carrier0&format=md",
        "/changelog?format=csv",
        "/export/findings?format=csv",
    ],
)
def test_exports_require_view_permission(export_client, url):
    from fastapi.testclient import TestClient

    response = TestClient(export_client.app).get(url)
    assert response.status_code == 401


def test_filter_and_pagination_match_html(export_client):
    import re

    response = export_client.get("/search?q=Carrier&side=Computer&cse=Synthetic&per_page=1")
    assert response.status_code == 200
    url = (
        "/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?ledger_q=Carrier1"
        "&view=ledger&side=Computer&cse=Synthetic"
    )
    html = export_client.get(url).text
    rows = list(csv.DictReader(io.StringIO(export_client.get(url + "&format=csv").text)))
    setting_rows = [r for r in rows if r["section"] == "settings_ledger"]
    assert {r["record"] for r in setting_rows} == {"1"}
    assert next(r["value"] for r in setting_rows if r["field"] == "identity") == "Carrier1"
    assert len(re.findall(r'class="gp-ledger-row', html)) == 1
    assert "Carrier1" in html


def test_non_secret_password_policy_remains_visible():
    from gpo_lens.safe_output import safe_data

    assert (
        safe_data(
            {
                "identity": "Security:MinimumPasswordLength",
                "display_name": "Minimum password length",
                "display_value": "14",
            }
        )["display_value"]
        == "14"
    )


@pytest.mark.parametrize(
    "view,extra",
    [
        (
            "dossier",
            [
                "--gpo-id",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--compare",
                "cccccccccccccccccccccccccccccccc",
            ],
        ),
        ("findings", ["--lifecycle", "all", "--triage", "all"]),
        ("occurrence", ["--occurrence-id", "1"]),
        ("accepted-risks", ["--as-of", "2026-02-01T00:00:00Z"]),
        ("briefing", ["--as-of", "2026-02-01T00:00:00Z"]),
        ("setting", ["--identity", "Carrier0"]),
        ("settings-dump", ["--side", "Computer"]),
        ("who-sets", ["--q", "Carrier"]),
        ("diff", ["--snapshot-a", "1", "--snapshot-b", "1"]),
        ("diff-settings", ["--snapshot-a", "1", "--snapshot-b", "1"]),
        ("changelog", ["--snapshot-a", "1", "--snapshot-b", "1"]),
    ],
)
def test_cli_export_views(export_client, capsys, view, extra, secret_corpus):
    from gpo_lens.cli import main

    arguments = ["--db", str(export_client.db_path), "export", view, "--format", "csv", *extra]
    assert main(arguments) == 0
    first = capsys.readouterr().out
    assert main(arguments) == 0
    assert first == capsys.readouterr().out
    assert "snapshot_ids" in first
    for secret in secret_corpus:
        assert secret not in first


@pytest.mark.parametrize("endpoint", ["baseline", "golden-diff"])
@pytest.mark.parametrize("format", ["md", "csv"])
def test_uploaded_comparison_exports(export_client, monkeypatch, secret_corpus, endpoint, format):

    from gpo_lens import ingest
    from gpo_lens.model import Gpo, Setting

    gpo = Gpo(
        id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        name="gpo-cpassword",
        domain="lab.example.com",
        created=None,
        modified=None,
        read=None,
        sddl="",
        owner="",
        filter_data_available=False,
        wmi_filter=None,
        sysvol_path=None,
        computer_enabled=True,
        user_enabled=True,
        computer_ver_ds=1,
        computer_ver_sysvol=1,
        user_ver_ds=1,
        user_ver_sysvol=1,
        settings=[
            Setting(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "Computer",
                "Synthetic",
                "Carrier0",
                "Carrier0",
                secret_corpus[1],
                {"cpassword": secret_corpus[1]},
                False,
            )
        ],
    )
    monkeypatch.setattr(ingest, "load_baseline_from_zip", lambda path: [gpo])

    def upload():
        return export_client.post(
            "/" + endpoint,
            files={"file": ("synthetic.zip", b"test", "application/zip")},
            data={"format": format},
            headers={"Origin": "http://testserver"},
        )

    response = upload()
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    assert response.content == upload().content
    for secret in secret_corpus:
        assert secret not in response.text
    assert "comparator" in response.text


def test_no_raw_fragments_and_markdown_escaping(secret_corpus):
    doc = ExportDocument(
        "Test",
        {},
        (
            ExportSection(
                "rows",
                (
                    {
                        "raw": {"cpassword": secret_corpus[0]},
                        "safe_projection": '<Properties cpassword="' + secret_corpus[0] + '"/>',
                        "summary": "[link](https://example.com) <script>",
                    },
                ),
            ),
        ),
    )
    for format in ("md", "csv"):
        output = "".join(render_export(doc, format))
        assert secret_corpus[0] not in output
        assert "<Properties" not in output
        assert "<script>" not in output
        assert "REDACTED" in output


def test_provenance_remains_pinned_when_latest_snapshot_changes(export_client, monkeypatch):
    import sqlite3

    from gpo_lens.store import load_estate, save_estate
    from gpo_lens.web.routes import gpo as route

    original = route.view_export

    def concurrent_ingest(*args, **kwargs):
        conn = sqlite3.connect(export_client.db_path)
        try:
            estate = load_estate(conn)
            save_estate(conn, estate)
        finally:
            conn.close()
        return original(*args, **kwargs)

    monkeypatch.setattr(route, "view_export", concurrent_ingest)
    response = export_client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?format=csv")
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert (
        next(
            r["value"] for r in rows if r["section"] == "metadata" and r["field"] == "snapshot_ids"
        )
        == "[1]"
    )
    assert (
        next(
            r["value"]
            for r in rows
            if r["section"] == "metadata" and r["field"] == "evaluation_ids"
        )
        == "[1]"
    )


@pytest.mark.parametrize("format", ["md", "csv"])
def test_snapshot_diff_redacts_copied_values(export_client, secret_corpus, format):
    import sqlite3

    from gpo_lens.store import load_estate, save_estate

    conn = sqlite3.connect(export_client.db_path)
    try:
        estate = load_estate(conn)
        gpo = estate.gpo_by_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        setting = next(s for s in gpo.settings if s.identity == "Carrier0")
        setting.display_value = secret_corpus[1]
        setting.raw = {"cpassword": secret_corpus[1]}
        save_estate(conn, estate)
    finally:
        conn.close()
    for suffix in ("", "&format=" + format):
        response = export_client.get("/changelog?snap_a=1&snap_b=2" + suffix)
        assert response.status_code == 200
        assert "Carrier0" in response.text
        for secret in secret_corpus:
            assert secret not in response.text


@pytest.mark.parametrize("format", ["csv", "md"])
def test_active_secret_filter_is_redacted(export_client, secret_corpus, format):
    response = export_client.get("/search", params={"q": secret_corpus[0], "format": format})
    assert response.status_code == 200
    assert secret_corpus[0] not in response.text
    assert "REDACTED" in response.text


def test_no_export_calls_narration(export_client, monkeypatch):
    from gpo_lens import narration

    def forbidden(*args, **kwargs):
        pytest.fail("An export invoked narration")

    monkeypatch.setattr(narration, "call_llm", forbidden)
    for url in (
        "/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?format=csv",
        "/findings?format=md",
        "/briefing?format=csv",
        "/setting?identity=Carrier0&format=md",
    ):
        assert export_client.get(url).status_code == 200


def test_safe_mapping_setting_labels_keep_admx_names():
    from gpo_lens.admx_parser import AdmxPolicy, PolicyDefinitions
    from gpo_lens.web._helpers import setting_label

    admx = PolicyDefinitions(
        policies=[
            AdmxPolicy(
                name="Synthetic",
                class_scope="Both",
                key="Synthetic",
                value_name="Value",
                display_name_ref="",
                display_name="Synthetic policy",
                explain_text="",
            )
        ]
    )
    assert setting_label({"identity": "Synthetic:Value", "display_name": "Value"}, admx) == (
        "Synthetic policy",
        "Synthetic:Value",
    )


def test_gpo_comparison_only_export(export_client):
    response = export_client.get(
        "/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?compare=cccccccccccccccccccccccccccccccc&view=comparison&format=csv"
    )
    assert response.status_code == 200
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert {r["section"] for r in rows} == {"metadata", "gpo_comparison"}


@pytest.mark.parametrize("view", ["briefing", "accepted-risks"])
def test_time_sensitive_exports_reject_naive_time(export_client, view):
    assert (
        export_client.get("/" + view + "?as_of=2026-08-01T00:00:00&format=csv").status_code == 422
    )


def test_risk_filter_form_keeps_default_time_valid(export_client):
    html = export_client.get("/accepted-risks").text
    assert 'name="as_of" value=""' not in html
    assert export_client.get("/accepted-risks?q=Carrier&category=synthetic").status_code == 200


@pytest.mark.parametrize("view", ["baseline-diff", "golden-diff", "settings-diff"])
def test_cli_comparison_exports(export_client, capsys, view, tmp_path, secret_corpus):
    import json
    from pathlib import Path

    from gpo_lens.cli import main

    if view == "settings-diff":
        old = {
            "gpo_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "gpo_name": "Synthetic",
            "side": "Computer",
            "cse": "Registry",
            "identity": "Synthetic:Carrier",
            "display_name": "Carrier",
            "display_value": secret_corpus[0],
            "raw": {"cpassword": secret_corpus[0]},
        }
        new = {**old, "display_value": secret_corpus[1], "raw": {"cpassword": secret_corpus[1]}}
        import sqlite3

        from gpo_lens.model import Estate
        from gpo_lens.store import save_estate

        conn = sqlite3.connect(export_client.db_path)
        save_estate(conn, Estate())
        conn.close()
        file_a = tmp_path / "a.json"
        file_b = tmp_path / "b.json"
        file_a.write_text(json.dumps([old]))
        file_b.write_text(json.dumps([new]))
        extra = ["--file-a", str(file_a), "--file-b", str(file_b)]
    else:
        extra = ["--comparator", str(Path(__file__).parent / "fixtures")]
    assert (
        main(["--db", str(export_client.db_path), "export", view, "--format", "csv", *extra]) == 0
    )
    output = capsys.readouterr().out
    assert "snapshot_ids" in output
    for secret in secret_corpus:
        assert secret not in output


@pytest.mark.parametrize("view", ["accepted-risks", "findings?lifecycle=all&triage=all"])
def test_historical_workflow_export_keeps_source_provenance(
    export_client, secret_corpus, view, capsys
):
    import json
    import sqlite3

    from gpo_lens.cli import main
    from gpo_lens.model import Estate
    from gpo_lens.store import save_estate

    conn = sqlite3.connect(export_client.db_path)
    save_estate(conn, Estate())
    conn.execute("UPDATE finding SET summary=?", ("Copied " + secret_corpus[-1],))
    conn.commit()
    conn.close()
    separator = "&" if "?" in view else "?"
    response = export_client.get("/" + view + separator + "format=csv")
    assert response.status_code == 200
    assert secret_corpus[-1] not in response.text
    rows = list(csv.DictReader(io.StringIO(response.text)))
    evaluations = next(r["value"] for r in rows if r["field"] == "evaluation_ids")
    assert json.loads(evaluations) == [1]
    extra = ["--lifecycle", "all", "--triage", "all"] if view.startswith("findings") else []
    assert main(["--db", str(export_client.db_path), "export", view.split("?")[0], *extra]) == 0
    assert secret_corpus[-1] not in capsys.readouterr().out
