"""Credential carriers use one projection; policy values remain useful."""

import inspect
import json
import re
import sqlite3
from contextlib import closing

import pytest

from gpo_lens.exports import snapshot_secrets
from gpo_lens.model import Setting
from gpo_lens.safe_output import REDACTED, safe_data, secret_values
from gpo_lens.store import init_db, save_estate


@pytest.mark.parametrize("key", ["Cpassword", "password", "token", "secret"])
@pytest.mark.parametrize("count", [0, 7, 129, 2.5])
def test_numeric_aggregates_are_not_credential_material(key, count):
    value = {key: count, "date": "2026-10-06", "other_count": 10}
    assert secret_values(value) == ()
    assert safe_data(value) == value


@pytest.mark.parametrize("secret", ["0", "123456", "SYNTH-CPASSWORD-ONLY"])
def test_credential_strings_including_numeric_passwords_stay_masked(secret):
    value = {"cpassword": secret, "copy": "Copied " + secret}
    assert secret_values(value) == (secret,)
    assert safe_data(value) == {"cpassword": REDACTED, "copy": "Copied " + REDACTED}


def test_table_headers_do_not_classify_cells_as_credentials(capsys):
    from gpo_lens.cli._helpers import _print_table
    from gpo_lens.display import render_table

    headers = ["Date", "Cpassword", "Password", "Token"]
    rows = [["2026-10-06", "0", "7", "129"]]
    _print_table(headers, rows)
    assert capsys.readouterr().out == render_table(headers, rows) + "\n"


def test_table_cells_mask_credential_assignments_and_known_copies(capsys):
    from gpo_lens.cli._helpers import _output_secrets, _print_table

    secret = "SYNTH-TABLE-CPASSWORD-ONLY"
    token = _output_secrets.set((secret,))
    try:
        _print_table(["Description", "Copy"], [["cpassword=" + secret, secret]])
    finally:
        _output_secrets.reset(token)
    output = capsys.readouterr().out
    assert secret not in output
    assert output.count(REDACTED) == 2


@pytest.mark.parametrize("secret", ["0", "123456", "SYNTH-SYSVOL-CPASSWORD-ONLY"])
@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize("show_secrets", [False, True])
@pytest.mark.parametrize("input_mode", ["source", "database"])
def test_sysvol_only_cpassword_stays_masked(
    tmp_path, capsys, secret, as_json, show_secrets, input_mode
):
    from gpo_lens.cli import main
    from gpo_lens.ingest import load_estate

    source = tmp_path / "lab-estate"
    source.mkdir()
    source.joinpath("AllGPOs.xml").write_text(
        "<AllGPOs><GPO><Identifier>"
        "<Identifier>{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}</Identifier>"
        "<Domain>lab.example.com</Domain></Identifier><Name>Lab preferences</Name>"
        "<Computer><Enabled>true</Enabled></Computer><User><Enabled>true</Enabled></User>"
        "</GPO></AllGPOs>",
        encoding="utf-8",
    )
    carrier = (
        source
        / "SYSVOL-Policies"
        / "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
        / "Machine"
        / "Preferences"
        / "Groups.xml"
    )
    carrier.parent.mkdir(parents=True)
    carrier.write_text(
        f'<Groups><User><Properties cpassword="{secret}"/></User></Groups>', encoding="utf-8"
    )
    estate = load_estate(source)
    assert secret_values(estate) == ()  # No credential in report settings.
    db = tmp_path / "lab.sqlite3"
    with closing(sqlite3.connect(db)) as conn, conn:
        init_db(conn)
        save_estate(conn, estate)
    conn.close()
    arguments = ["--db", str(db), *(["--json"] if as_json else []), "cpassword"]
    if input_mode == "source":
        arguments.append(str(source))
    if show_secrets:
        arguments.append("--show-secrets")
    assert main(arguments) == 0
    output = capsys.readouterr().out
    if as_json:
        masked = json.loads(output)["data"][0]["cpassword"]
    else:
        masked = output.splitlines()[2].split()[-1]
    assert secret != masked
    assert secret not in masked


def test_numeric_aggregate_regression_kills_classification_mutant(monkeypatch):
    from gpo_lens import safe_output

    # Reintroduce key-only masking of numeric aggregates.
    monkeypatch.setattr(safe_output, "_credential_material", lambda value: value not in (None, ""))
    with pytest.raises(AssertionError):
        test_numeric_aggregates_are_not_credential_material("Cpassword", 0)


def test_sysvol_cpassword_regression_kills_source_context_mutant(monkeypatch, tmp_path, capsys):
    from gpo_lens.cli import _hygiene

    monkeypatch.setattr(_hygiene, "_add_secret_source", lambda _: None)
    with pytest.raises(AssertionError):
        test_sysvol_only_cpassword_stays_masked(
            tmp_path, capsys, "SYNTH-SYSVOL-CPASSWORD-ONLY", False, True, "source"
        )


def test_numeric_password_regression_kills_discovery_mutant(monkeypatch):
    from gpo_lens import safe_output

    # Disabling credential keys would make the numeric-count test pass, but leak passwords.
    monkeypatch.setattr(safe_output, "_SECRET_KEY", re.compile(r"(?!)"))
    with pytest.raises(AssertionError):
        test_credential_strings_including_numeric_passwords_stay_masked("123456")


def test_table_regression_kills_header_classification_mutant(monkeypatch, capsys):
    from gpo_lens.cli import _helpers

    source = inspect.getsource(_helpers._print_table)
    mutant = source.replace(
        "[list(row) for row in rows]",
        "[dict(zip(headers, row, strict=True)) for row in rows]",
    ).replace(
        "[[str(cell) for cell in row] for row in projected]",
        "[[str(row[h]) for h in headers] for row in projected]",
    )
    assert mutant != source
    namespace = dict(vars(_helpers))
    exec(compile(mutant, "<table-mutant>", "exec"), namespace)  # noqa: S102
    monkeypatch.setattr(_helpers, "_print_table", namespace["_print_table"])
    with pytest.raises(AssertionError):
        test_table_headers_do_not_classify_cells_as_credentials(capsys)


@pytest.mark.parametrize(
    "name",
    [
        "DefaultPassword",
        "AltDefaultPassword",
        "ProxyPassword",
        "ServicePassword",
        "BindPassword",
        "AdminPassword",
    ],
)
def test_registry_credential_values(name):
    secret = "SYNTH-REGISTRY-CREDENTIAL-ONLY"
    setting = Setting(
        "lab",
        "Computer",
        "Registry",
        rf"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon:{name}",
        name,
        "[REG_SZ] " + secret,
        {
            "tag": "Properties",
            "@attr": {
                "key": r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "name": name,
                "value": secret,
            },
        },
        False,
    )
    assert secret in secret_values(setting)
    assert secret not in json.dumps(safe_data({"setting": setting, "copy": secret}))


@pytest.mark.parametrize(
    "name",
    [
        "MinimumPasswordLength",
        "PasswordComplexity",
        "MaximumPasswordAge",
        "MinimumPasswordAge",
        "PasswordHistorySize",
        "ClearTextPassword",
        "AutoAdminLogon",
    ],
)
def test_benign_password_policy_values_are_not_credentials(name):
    setting = Setting(
        "lab", "Computer", "Security", "PasswordPolicy:" + name, name, "14", {}, False
    )
    assert secret_values(setting) == ()
    assert safe_data(setting)["display_value"] == "14"


@pytest.mark.parametrize(
    "path",
    [
        "https://lab-user:SYNTH-PATHPASS-ONLY@files.lab.example.com/share",
        r"\\lab-user:SYNTH-PATHPASS-ONLY@files.lab.example.com\share",
        "//lab-user:SYNTH-PATHPASS-ONLY@files.lab.example.com/share",
        "smb://lab-user:SYNTH-PATHPASS-ONLY@files.lab.example.com/share",
        "https://lab-user:SYNTH%2DPATHPASS%2DONLY@files.lab.example.com/share",
    ],
)
def test_userinfo_secret_and_copies_are_masked(path):
    value = {"display_value": path, "copy": "SYNTH-PATHPASS-ONLY"}
    assert "SYNTH-PATHPASS-ONLY" in secret_values(value)
    projected = json.dumps(safe_data(value))
    assert "SYNTH" not in projected
    assert REDACTED in projected


def test_parser_value_record_feeds_snapshot_secret_context():
    secret = "SYNTH-XML-CREDENTIAL-ONLY"
    setting = Setting(
        "lab",
        "Computer",
        "Registry",
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon:DefaultPassword",
        "DefaultPassword",
        "[REG_SZ] " + secret,
        {
            "tag": "Value",
            "children": [
                {"tag": "Name", "text": "DefaultPassword"},
                {"tag": "String", "text": secret},
            ],
        },
        False,
    )
    # Use the existing full synthetic estate so required GPO fields are realistic.
    from pathlib import Path

    from gpo_lens.ingest import load_estate

    estate = load_estate(Path(__file__).parent / "fixtures")
    setting.gpo_id = estate.gpos[0].id
    estate.gpos[0].settings.append(setting)
    with closing(sqlite3.connect(":memory:")) as conn, conn:
        init_db(conn)
        sid = save_estate(conn, estate)
        secrets = snapshot_secrets(conn, [sid])
        assert secret in secrets
        assert (
            safe_data({"summary": "Copy " + secret}, secrets=secrets)["summary"]
            == "Copy " + REDACTED
        )


def test_uri_userinfo_with_empty_username_is_credential():
    uri = "https://:SYNTH-PASSWORD-ONLY@files.lab.example.com/"
    assert "SYNTH-PASSWORD-ONLY" in secret_values(uri)
    assert "SYNTH-PASSWORD-ONLY" not in safe_data(uri)
