"""Tests for ADMX/ADML template parser."""

from __future__ import annotations

import codecs
from pathlib import Path

import pytest

from gpo_lens.admx_parser import PolicyDefinitions, parse_admx_dir

_ADMX_SAMPLE = """\
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions
    xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"
    revision="1.0" schemaVersion="1.0">
  <policyNamespaces>
    <target prefix="test" namespace="Microsoft.Policies.Test" />
  </policyNamespaces>
  <resources minRequiredRevision="1.0" />
  <policies>
    <policy name="LockoutPolicy" class="Machine"
            displayName="$(string.LockoutPolicy)"
            explainText="$(string.LockoutPolicy_Help)"
            key="Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
            valueName="LockoutBadCount">
      <enabledValue><decimal value="1" /></enabledValue>
      <disabledValue><decimal value="0" /></disabledValue>
    </policy>
    <policy name="NoControlPanel" class="User"
            displayName="$(string.NoControlPanel)"
            key="Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
            valueName="NoControlPanel">
    </policy>
    <policy name="DisableOneDrive" class="Both"
            displayName="$(string.DisableOneDrive)"
            key="Software\\Policies\\Microsoft\\Windows\\OneDrive"
            valueName="DisableFileSyncNGSC">
    </policy>
    <policy name="EmptyValuePolicy" class="Machine"
            displayName="$(string.EmptyValuePolicy)"
            key="Software\\Policies\\Microsoft\\Example">
    </policy>
  </policies>
</policyDefinitions>
"""

_ADML_SAMPLE = """\
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitionResources
    xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"
    revision="1.0" schemaVersion="1.0">
  <resources>
    <stringTable>
      <string id="LockoutPolicy">Account Lockout Threshold</string>
      <string id="LockoutPolicy_Help">Sets the lockout threshold.</string>
      <string id="NoControlPanel">Prohibit Control Panel</string>
      <string id="DisableOneDrive">Prevent OneDrive sync</string>
      <string id="EmptyValuePolicy">Example policy with no valueName</string>
    </stringTable>
  </resources>
</policyDefinitionResources>
"""


def _write_policy_defs(tmp_path: Path) -> Path:
    """Create a minimal PolicyDefinitions directory."""
    pd = tmp_path / "PolicyDefinitions"
    pd.mkdir()
    (pd / "TestPolicies.admx").write_text(_ADMX_SAMPLE, encoding="utf-8")
    en_us = pd / "en-US"
    en_us.mkdir()
    (en_us / "TestPolicies.adml").write_text(_ADML_SAMPLE, encoding="utf-8")
    return pd


def test_parse_admx_dir_finds_policies(tmp_path):
    pd_dir = _write_policy_defs(tmp_path)
    pd = parse_admx_dir(pd_dir)
    assert len(pd.policies) == 4


def test_parse_admx_dir_resolves_display_names(tmp_path):
    pd_dir = _write_policy_defs(tmp_path)
    pd = parse_admx_dir(pd_dir)
    by_name = {p.name: p for p in pd.policies}
    assert by_name["LockoutPolicy"].display_name == "Account Lockout Threshold"
    assert by_name["NoControlPanel"].display_name == "Prohibit Control Panel"


def test_parse_admx_dir_resolves_explain_text(tmp_path):
    pd_dir = _write_policy_defs(tmp_path)
    pd = parse_admx_dir(pd_dir)
    by_name = {p.name: p for p in pd.policies}
    assert "lockout threshold" in by_name["LockoutPolicy"].explain_text.lower()


def test_parse_admx_dir_class_scope(tmp_path):
    pd_dir = _write_policy_defs(tmp_path)
    pd = parse_admx_dir(pd_dir)
    by_name = {p.name: p for p in pd.policies}
    assert by_name["LockoutPolicy"].class_scope == "Machine"
    assert by_name["NoControlPanel"].class_scope == "User"
    assert by_name["DisableOneDrive"].class_scope == "Both"


def test_parse_admx_dir_registry_key(tmp_path):
    pd_dir = _write_policy_defs(tmp_path)
    pd = parse_admx_dir(pd_dir)
    by_name = {p.name: p for p in pd.policies}
    p = by_name["LockoutPolicy"]
    assert p.key == "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    assert p.value_name == "LockoutBadCount"


def test_lookup_case_insensitive(tmp_path):
    pd_dir = _write_policy_defs(tmp_path)
    pd = parse_admx_dir(pd_dir)
    results = pd.lookup(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        "lockoutbadcount",
    )
    assert len(results) == 1
    assert results[0].name == "LockoutPolicy"


def test_lookup_no_match(tmp_path):
    pd_dir = _write_policy_defs(tmp_path)
    pd = parse_admx_dir(pd_dir)
    results = pd.lookup("Software\\NonExistent", "Nope")
    assert results == []


def test_lookup_empty_value_name_matches_any(tmp_path):
    """A policy with no valueName matches any value for that key."""
    pd_dir = _write_policy_defs(tmp_path)
    pd = parse_admx_dir(pd_dir)
    results = pd.lookup("Software\\Policies\\Microsoft\\Example", "anything")
    assert len(results) == 1
    assert results[0].name == "EmptyValuePolicy"


def test_resolve_display_name(tmp_path):
    pd_dir = _write_policy_defs(tmp_path)
    pd = parse_admx_dir(pd_dir)
    result = pd.resolve_display_name(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System:LockoutBadCount"
    )
    assert result == "Account Lockout Threshold"


def test_resolve_display_name_no_match(tmp_path):
    pd_dir = _write_policy_defs(tmp_path)
    pd = parse_admx_dir(pd_dir)
    result = pd.resolve_display_name("NonExistent:Value")
    assert result is None


def test_parse_admx_dir_missing_dir():
    pd = parse_admx_dir("/nonexistent/path")
    assert pd.policies == []


def test_parse_admx_dir_empty_dir(tmp_path):
    pd_dir = tmp_path / "Empty"
    pd_dir.mkdir()
    pd = parse_admx_dir(pd_dir)
    assert pd.policies == []


def test_parse_admx_dir_skips_broken_xml(tmp_path):
    pd_dir = tmp_path / "PolicyDefinitions"
    pd_dir.mkdir()
    en_us = pd_dir / "en-US"
    en_us.mkdir()
    (pd_dir / "broken.admx").write_text("not xml", encoding="utf-8")
    (en_us / "broken.adml").write_text("not xml", encoding="utf-8")
    (pd_dir / "good.admx").write_text(_ADMX_SAMPLE, encoding="utf-8")
    (en_us / "good.adml").write_text(_ADML_SAMPLE, encoding="utf-8")
    pd = parse_admx_dir(pd_dir)
    assert len(pd.policies) == 4


def test_parse_admx_dir_falls_back_to_first_locale(tmp_path):
    pd_dir = tmp_path / "PolicyDefinitions"
    pd_dir.mkdir()
    (pd_dir / "TestPolicies.admx").write_text(_ADMX_SAMPLE, encoding="utf-8")
    de_de = pd_dir / "de-de"
    de_de.mkdir()
    de_adml = _ADML_SAMPLE.replace("Account Lockout Threshold", "Kontosperrschwelle")
    (de_de / "TestPolicies.adml").write_text(de_adml, encoding="utf-8")
    pd = parse_admx_dir(pd_dir)
    by_name = {p.name: p for p in pd.policies}
    assert by_name["LockoutPolicy"].display_name == "Kontosperrschwelle"


def test_policy_definitions_lookup_empty():
    pd = PolicyDefinitions()
    assert pd.lookup("any", "thing") == []
    assert pd.resolve_display_name("any:thing") is None


@pytest.mark.parametrize(
    "encoding,bom",
    [
        ("utf-8", b""),
        ("utf-8-sig", b""),
        ("utf-16-le", codecs.BOM_UTF16_LE),
        ("utf-16-be", codecs.BOM_UTF16_BE),
        ("utf-16-le", b""),
        ("utf-16-be", b""),
        ("utf-32-le", codecs.BOM_UTF32_LE),
        ("utf-32-be", codecs.BOM_UTF32_BE),
        ("utf-32-le", b""),
        ("utf-32-be", b""),
    ],
)
@pytest.mark.parametrize("declared", ["unicode", "synthetic-unknown-encoding"])
def test_unrecognized_declaration_decodes_both_templates(tmp_path, encoding, bom, declared):
    pd_dir = _write_policy_defs(tmp_path)
    for path, sample in [
        (pd_dir / "TestPolicies.admx", _ADMX_SAMPLE),
        (pd_dir / "en-US" / "TestPolicies.adml", _ADML_SAMPLE),
    ]:
        path.write_bytes(
            bom + sample.replace('encoding="utf-8"', f"encoding='{declared}'").encode(encoding)
        )
    pd = parse_admx_dir(pd_dir)
    assert len(pd.policies) == 4
    assert pd.policies[0].display_name == "Account Lockout Threshold"
    assert pd.skipped_files == []


def test_known_encoding_and_bom_precedence(tmp_path):
    pd_dir = _write_policy_defs(tmp_path)
    sample = _ADML_SAMPLE.replace("Account Lockout Threshold", "Synthetic café")
    path = pd_dir / "en-US" / "TestPolicies.adml"
    path.write_bytes(sample.replace("utf-8", "iso-8859-1").encode("iso-8859-1"))
    assert parse_admx_dir(pd_dir).policies[0].display_name == "Synthetic café"
    path.write_bytes(sample.replace("utf-8", "ascii").encode("utf-32"))
    assert parse_admx_dir(pd_dir).policies[0].display_name == "Synthetic café"


def test_poisoned_files_are_counted_and_good_files_survive(tmp_path):
    pd_dir = _write_policy_defs(tmp_path)
    poisons = {
        "garbage": (b"\xff\xfe\xff", "UnicodeDecodeError"),
        "truncated": (b"<policyDefinitions>", "ParseError"),
        "unknown": (
            b'<?xml version="1.0" encoding="unknown-synthetic"?><x>\xff</x>',
            "UnicodeDecodeError",
        ),
        "entity": (
            b'<!DOCTYPE x [<!ENTITY label "synthetic">]><x>&label;</x>',
            "EntitiesForbidden",
        ),
    }
    expected = {}
    for directory, suffix in [(pd_dir, "admx"), (pd_dir / "en-US", "adml")]:
        for name, (payload, reason) in poisons.items():
            path = directory / f"{name}.{suffix}"
            path.write_bytes(payload)
            expected[str(path.relative_to(pd_dir))] = reason
    pd = parse_admx_dir(pd_dir)
    assert len(pd.policies) == 4
    assert pd.policies[0].display_name == "Account Lockout Threshold"
    assert {skip.filename: skip.reason_class for skip in pd.skipped_files} == expected


@pytest.mark.parametrize("suffix", ["admx", "adml"])
@pytest.mark.parametrize("error", [LookupError, UnicodeError, ValueError, OSError, RuntimeError])
def test_file_exception_is_isolated(tmp_path, monkeypatch, suffix, error):
    pd_dir = _write_policy_defs(tmp_path)
    directory = pd_dir if suffix == "admx" else pd_dir / "en-US"
    poison = directory / f"poison.{suffix}"
    poison.touch()
    read_bytes = Path.read_bytes

    def poisoned_read(path):
        if path == poison:
            raise error("synthetic failure")
        return read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", poisoned_read)
    pd = parse_admx_dir(pd_dir)
    assert len(pd.policies) == 4
    assert pd.policies[0].display_name == "Account Lockout Threshold"
    assert [(s.filename, s.reason_class) for s in pd.skipped_files] == [
        (str(poison.relative_to(pd_dir)), error.__name__)
    ]
