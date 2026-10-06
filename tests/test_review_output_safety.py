"""Independent-review regressions using synthetic PKI and secret values."""

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gpo_lens import store
from gpo_lens.cli import main
from gpo_lens.ingest import load_estate
from gpo_lens.safe_output import REDACTED, safe_data, safe_text, secret_values
from gpo_lens.web.app import create_app

FIXTURE = Path(__file__).parent / "fixtures/cse_audit_pki/report.xml"
GPO_ID = "a" * 32


@pytest.fixture(params=["PrivateKey", "password", "token", "credential"])
def pki_source(request, tmp_path):
    secret = "SYNTH-PKI-PRIVATE-MATERIAL-ONLY"
    tag = request.param
    text = FIXTURE.read_text().replace(
        "</p:Certificate>",
        f"<p:{tag}>{secret}</p:{tag}><p:Unrecognized>UNKNOWN-LEAF</p:Unrecognized></p:Certificate>",
    )
    source = tmp_path / "source"
    source.mkdir()
    (source / "AllGPOs.xml").write_text(text)
    return source, secret


def test_certificate_public_metadata_allowlist(pki_source):
    source, secret = pki_source
    estate = load_estate(source)
    certificate = next(s for s in estate.gpos[0].settings if ":Certificate:" in s.identity)
    assert secret not in certificate.display_value
    assert "UNKNOWN-LEAF" not in certificate.display_value
    assert "Lab Root CA" in certificate.display_value


def test_xml_leaf_secret_discovery(pki_source):
    source, secret = pki_source
    assert secret in secret_values(load_estate(source))
    assert safe_data({"tag": "PrivateKey", "text": secret})["text"] == REDACTED


@pytest.mark.parametrize("format", [None, "json", "md", "csv"])
def test_pki_secret_cli_outputs(pki_source, tmp_path, capsys, format):
    source, secret = pki_source
    db = tmp_path / "estate.db"
    with closing(sqlite3.connect(db)) as conn:
        store.init_db(conn)
        store.save_estate(conn, load_estate(source))
    if format in {"md", "csv"}:
        args = ["--db", str(db), "export", "dossier", "--gpo-id", GPO_ID, "--format", format]
    else:
        args = ["show", GPO_ID, str(source)]
        if format:
            args = ["--json", "settings-dump", str(source)]
    assert main(args) == 0
    output = capsys.readouterr().out
    assert secret not in output
    assert "UNKNOWN-LEAF" not in output
    assert "Lab Root CA" in output


@pytest.mark.parametrize("format", [None, "json", "md", "csv"])
def test_pki_secret_web_outputs(pki_source, tmp_path, monkeypatch, format):
    source, secret = pki_source
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "lab-test-token")
    db = tmp_path / "estate.db"
    with closing(sqlite3.connect(db)) as conn:
        store.init_db(conn)
        store.save_estate(conn, load_estate(source))
    with TestClient(
        create_app(str(db)),
        base_url="http://localhost",
        headers={"Authorization": "Bearer lab-test-token"},
    ) as client:
        params = {"view": "ledger", "format": format} if format else {}
        if format == "json":
            response = client.get(f"/export/gpo/{GPO_ID}", params={"format": "json"})
        else:
            response = client.get(f"/gpo/{GPO_ID}", params=params)
        assert response.status_code == 200
        assert secret not in response.text
        assert "UNKNOWN-LEAF" not in response.text
        assert "Lab Root CA" in response.text


@pytest.mark.parametrize("key", ["password", "token", "credential", "PrivateKey", "secret"])
@pytest.mark.parametrize("value", [1234567890123456, 0, -7, 1.25, True, [123], {"pin": 123}])
def test_secret_key_dominates_primitive_type(key, value):
    result = safe_data({key: value})
    assert result[key] == REDACTED
    assert str(value) in secret_values({key: value})


def test_numeric_secret_in_raw_drives_sensitive_projection():
    result = safe_data({"raw": {"password": 0}, "display_value": 0, "cpassword_hit_count": 7})
    assert result["display_value"] == REDACTED
    assert result["cpassword_hit_count"] == 7


@pytest.mark.parametrize("secret", [0, 1234, "0", "1234", "abc"])
def test_short_secret_does_not_corrupt_dates_identifiers_or_counts(secret):
    public = {
        "date": "2026-10-06",
        "identifier": "gpo-0000-1234-abc",
        "gpo_id": "00001234abcd00000000000000001234",
        "gpo_count": 20,
        "cpassword_hit_count": 0,
        "summary": "12340 GPOs on 2026-10-06; gpo-0000-1234-abc",
    }
    value = {**public, "password": secret, "nested": [{"private_key": secret}]}
    projected = safe_data(value)
    assert projected["password"] == REDACTED
    assert projected["nested"] == [{"private_key": REDACTED}]
    assert {k: projected[k] for k in public} == public
    assert safe_text(public["summary"], secrets=secret_values(value)) == public["summary"]
    # WI-101 still masks a copied standalone credential, including numeric ones.
    assert safe_data({"copy": f"Copied {secret}"}, secrets=secret_values(value)) == {
        "copy": f"Copied {REDACTED}"
    }


@pytest.mark.parametrize("secret,escaped", [("a&", "a&amp;"), ('a"', "a&quot;"), ("a<", "a&lt;")])
def test_short_secret_keeps_token_policy_after_html_escaping(secret, escaped):
    public = "public-x" + escaped + "y"
    assert safe_text(public, secrets=[secret]) == public
    assert safe_data({"password": secret})["password"] == REDACTED
    assert safe_text("Copied " + escaped, secrets=[secret]) == "Copied " + REDACTED


def test_escaped_variant_collision_keeps_long_secret_substring_masking():
    assert safe_text("public-xa&amp;y", secrets=["a&", "a&amp;"]) == "public-x[REDACTED]y"
