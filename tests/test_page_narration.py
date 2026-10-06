"""Narration may select computed facts; it cannot supply new factual prose."""

import base64
import html
import json
import re
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from gpo_lens.web.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    from gpo_lens.ingest import load_estate
    from gpo_lens.store import init_db, save_estate

    db = tmp_path / "estate.db"
    conn = sqlite3.connect(db)
    init_db(conn)
    estate = load_estate(Path(__file__).parent / "fixtures")
    # Secrets in arbitrary names, display values and raw evidence must never
    # become a narration input. Count-only projection excludes all three.
    estate.gpos[0].name = "synthetic-secret-name"
    if estate.gpos[0].settings:
        estate.gpos[0].settings[0].display_value = "synthetic-secret-value"
        estate.gpos[0].settings[0].raw = {"password": "synthetic-secret-raw"}
    save_estate(conn, estate)
    conn.close()
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-narration-token")
    monkeypatch.setenv("GPO_LENS_API_KEY", "test-key")
    return TestClient(
        create_app(str(db)),
        headers={"Authorization": "Bearer test-narration-token", "origin": "http://localhost"},
    )


def token_from(response):
    match = re.search(r'name="payload" value="([^"]+)"', response.text)
    assert match
    return html.unescape(match[1])


def decode_token(token):
    return json.loads(base64.urlsafe_b64decode(token.split(".")[0]))


@pytest.mark.parametrize(
    "url",
    [
        "/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "/ou/dc=fakefixture,dc=local",
        "/changelog?snap_a=1&snap_b=1",
    ],
)
def test_explain_is_optional_and_never_calls_model_on_page(client, monkeypatch, url):
    with patch("gpo_lens.narration.call_llm", side_effect=AssertionError("page invoked narration")):
        page = client.get(url)
        assert page.status_code == 200
        assert 'target="_blank"' in page.text
        token_from(page)
        monkeypatch.delenv("GPO_LENS_API_KEY")
        page = client.get(url)
        assert page.status_code == 200
        assert 'name="payload"' not in page.text


def test_payload_is_bounded_and_has_snapshot_and_analysis_provenance(client):
    page = client.get(
        "/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?compare=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )
    payload = decode_token(token_from(page))
    assert payload["snapshot_ids"] == [1]
    assert payload["analysis"] == "gpo_comparison"
    assert payload["application_version"]
    assert payload["evaluation_runs"] == []
    assert len(json.dumps(payload)) < 12000
    for secret in ("synthetic-secret-name", "synthetic-secret-value", "synthetic-secret-raw"):
        assert secret not in json.dumps(payload)
    assert "raw" not in payload and "html" not in payload


def test_valid_projection_uses_only_payload_text(client):
    token = token_from(client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    payload = decode_token(token)
    fact_id = next(iter(payload["facts"]))
    with patch(
        "gpo_lens.narration.call_llm", return_value=json.dumps({"fact_ids": [fact_id]})
    ) as model:
        result = client.post("/explain", data={"payload": token})
    assert result.status_code == 200
    assert "Narrative projection" in result.text
    assert payload["facts"][fact_id] in result.text
    assert json.loads(model.call_args.args[1]) == payload
    assert "synthetic-secret" not in model.call_args.args[1]


@pytest.mark.parametrize(
    "reply",
    [
        '{"fact_ids":["invented-gpo"]}',
        '{"fact_ids":["settings"],"claim":"Everything is compliant"}',
        "Everything is compliant",
        '{"fact_ids":[]}',
        '{"fact_ids":[1]}',
    ],
)
def test_fact_check_rejects_claims_absent_from_payload(client, reply):
    token = token_from(client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    with patch("gpo_lens.narration.call_llm", return_value=reply):
        result = client.post("/explain", data={"payload": token})
    assert "Narration unavailable" in result.text
    assert "Everything is compliant" not in result.text
    assert "invented-gpo" not in result.text
    assert client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").status_code == 200


def test_failure_is_isolated_and_does_not_disclose_error(client):
    token = token_from(client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    with patch("gpo_lens.narration.call_llm", side_effect=RuntimeError("secret endpoint detail")):
        result = client.post("/explain", data={"payload": token})
    assert "Narration unavailable" in result.text
    assert "secret endpoint detail" not in result.text
    assert client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").status_code == 200


def test_tampering_never_reaches_narration(client):
    token = token_from(client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    data = decode_token(token)
    data["facts"]["invented"] = "invented secret claim"
    forged = (
        base64.urlsafe_b64encode(json.dumps(data).encode()).decode() + "." + token.split(".")[1]
    )
    with patch("gpo_lens.narration.call_llm") as model:
        result = client.post("/explain", data={"payload": forged})
    assert result.status_code == 400
    model.assert_not_called()


def test_no_key_and_permission_are_enforced(client, monkeypatch):
    token = token_from(client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    monkeypatch.delenv("GPO_LENS_API_KEY")
    with patch("gpo_lens.narration.call_llm") as model:
        result = client.post("/explain", data={"payload": token})
    assert "Narration unavailable" in result.text
    model.assert_not_called()
    assert TestClient(client.app).post("/explain", data={"payload": token}).status_code in (
        401,
        403,
    )


def test_historical_finding_carries_observation_provenance(client, monkeypatch):
    from gpo_lens.finding_model import FindingCandidate
    from gpo_lens.findings import create_evaluation_run, finding_inbox, run_evaluation
    from gpo_lens.store import load_estate, save_estate

    conn = sqlite3.connect(client.app.state.db_path)
    candidate = FindingCandidate(
        detector_id="synthetic",
        detector_version="1",
        category="synthetic",
        severity="high",
        subject_type="estate",
        subject_key=("estate",),
        summary="synthetic-secret-summary",
        detail="synthetic-secret-evidence",
    )
    run_id = create_evaluation_run(
        conn, 1, detector_set_digest="a" * 64, application_version="1.2.3"
    )
    run_evaluation(conn, run_id, [candidate])
    occurrence_id = finding_inbox(conn)[0].occurrence_id
    # A newer snapshot must not relabel the old occurrence's observation.
    save_estate(conn, load_estate(conn))
    conn.close()
    page = client.get(f"/findings/{occurrence_id}")
    assert page.status_code == 200
    payload = decode_token(token_from(page))
    assert payload["snapshot_ids"] == [1]
    assert payload["evaluation_runs"][0]["run_id"] == run_id
    assert payload["evaluation_runs"][0]["snapshot_id"] == 1
    assert "synthetic-secret" not in json.dumps(payload)
    monkeypatch.delenv("GPO_LENS_API_KEY")
    assert 'name="payload"' not in client.get(f"/findings/{occurrence_id}").text


def test_historical_comparison_keeps_selected_snapshots(client):
    from gpo_lens.store import load_estate, save_estate

    conn = sqlite3.connect(client.app.state.db_path)
    estate = load_estate(conn)
    save_estate(conn, estate)
    save_estate(conn, estate)
    conn.close()
    payload = decode_token(token_from(client.get("/changelog?snap_a=1&snap_b=2")))
    assert payload["snapshot_ids"] == [1, 2]
    assert payload["analysis"] == "snapshot_comparison"


@pytest.mark.parametrize(
    ("url", "analysis"),
    [("/baseline", "baseline_comparison"), ("/golden-diff", "golden_comparison")],
)
def test_upload_comparison_explain_is_optional(client, monkeypatch, url, analysis):
    import io
    import zipfile

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(
            "GPOs/synthetic/gpreport.xml",
            (
                "<GPO><Identifier><Identifier>{99999999-9999-9999-9999-999999999999}</Identifier>"
                "<Domain>lab.example.com</Domain></Identifier><Name>Synthetic baseline</Name>"
                "<Computer><Enabled>true</Enabled></Computer>"
                "<User><Enabled>true</Enabled></User></GPO>"
            ),
        )
    with patch(
        "gpo_lens.narration.call_llm", side_effect=AssertionError("comparison invoked narration")
    ):
        response = client.post(
            url, files={"file": ("baseline.zip", archive.getvalue(), "application/zip")}
        )
    assert response.status_code == 200
    payload = decode_token(token_from(response))
    assert payload["analysis"] == analysis
    assert payload["snapshot_ids"] == [1]
    assert "Synthetic baseline" not in json.dumps(payload)
    monkeypatch.delenv("GPO_LENS_API_KEY")
    response = client.post(
        url, files={"file": ("baseline.zip", archive.getvalue(), "application/zip")}
    )
    assert response.status_code == 200
    assert 'name="payload"' not in response.text


def test_ask_does_not_send_serialized_results_to_narration(client):
    with (
        patch(
            "gpo_lens.narration.route_question",
            return_value={"query": "unlinked_gpos", "params": {}},
        ),
        patch("gpo_lens.narration.call_llm") as model,
    ):
        response = client.post("/ask", data={"question": "Which policies are unlinked?"})
    assert response.status_code == 200
    model.assert_not_called()
    payload = decode_token(token_from(response))
    assert payload["analysis"] == "ask:unlinked_gpos"
    assert "synthetic-secret" not in json.dumps(payload)


def test_viewer_has_no_action_and_cannot_narrate(client):
    from gpo_lens.web.auth import Permission, Principal, get_principal

    token = token_from(client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    client.app.dependency_overrides[get_principal] = lambda: Principal(
        "synthetic-viewer", "viewer", frozenset({Permission.VIEW})
    )
    assert 'name="payload"' not in client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").text
    assert client.post("/explain", data={"payload": token}).status_code == 403


def test_expired_malformed_and_excessive_forms_fail_before_model(client):
    from gpo_lens.web.page_narration import read_payload

    token = token_from(client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    with (
        patch("gpo_lens.web.page_narration.time.time", return_value=10**12),
        patch("gpo_lens.narration.call_llm") as model,
    ):
        assert client.post("/explain", data={"payload": token}).status_code == 400
        model.assert_not_called()
    assert client.post("/explain", data={"payload": "not a signed payload"}).status_code == 400
    assert client.post("/explain", data={"payload": "x" * 24001}).status_code == 422
    with pytest.raises(ValueError):
        read_payload("x" * 24001, client.app.state.page_narration_key)


def test_safe_projection_validation_and_bounds(client):
    from gpo_lens.web.auth import LOCAL_PRINCIPAL
    from gpo_lens.web.page_narration import make_action

    request = client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").context["request"]
    with pytest.raises(ValueError):
        make_action(request, LOCAL_PRINCIPAL, "dossier", [1], {"raw": 1})
    with pytest.raises(ValueError):
        make_action(request, LOCAL_PRINCIPAL, "unsafe", [1], {"settings": 1})
    with pytest.raises(ValueError):
        make_action(request, LOCAL_PRINCIPAL, "dossier", [1], {"settings": -1})
    token = make_action(
        request,
        LOCAL_PRINCIPAL,
        "finding_history",
        list(range(1, 100)),
        {"observations": 99},
        evaluation_runs=[
            {"run_id": i, "snapshot_id": i, "summary": "synthetic-secret"} for i in range(99)
        ],
    )
    payload = decode_token(token)
    assert payload["provenance_truncated"]
    assert len(payload["evaluation_runs"]) == 64
    assert len(payload["snapshot_ids"]) == 64
    assert "synthetic-secret" not in json.dumps(payload)


def test_explain_uses_narration_rate_limit_without_blocking_page(client):
    # Malformed forms still consume the narration budget. Page GETs use the
    # separate general limiter and must stay available when that budget is used.
    for _ in range(10):
        assert client.post("/explain", data={"payload": "invalid"}).status_code == 400
    assert client.post("/explain", data={"payload": "invalid"}).status_code == 429
    assert client.get("/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").status_code == 200


def test_invalid_comparison_snapshot_has_no_explain_action(client):
    response = client.get("/changelog?snap_a=999999&snap_b=1")
    assert response.status_code == 200
    assert 'name="payload"' not in response.text
