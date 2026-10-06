"""Credential carriers use one projection; policy values remain useful."""

import json
import sqlite3
from contextlib import closing

import pytest

from gpo_lens.exports import snapshot_secrets
from gpo_lens.model import Setting
from gpo_lens.safe_output import REDACTED, safe_data, secret_values
from gpo_lens.store import init_db, save_estate


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
