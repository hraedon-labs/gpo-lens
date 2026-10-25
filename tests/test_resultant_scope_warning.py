"""Approximation warnings describe a missing scope match, not a missing OU."""

from __future__ import annotations

import pytest
from _helpers import _make_gpo

from gpo_lens.merge import principal_resultant
from gpo_lens.model import DelegationEntry, Estate, ResolvedPrincipal, Setting, Som, SomLink

ROOT = "DC=example,DC=com"
OU = "OU=Known," + ROOT
USER = "s-1-5-21-1000000000-2000000000-3000000000-1001"
COMPUTER = "s-1-5-21-1000000000-2000000000-3000000000-1002"
TARGETS = [
    ("CN=Synthetic," + OU, "known OU"),
    ("CN=Synthetic,OU=Uncollected," + OU, "known OU"),
    ("CN=Synthetic,DC=elsewhere,DC=example", "domain"),
]


@pytest.fixture
def estate():
    model = Estate(domain="example.com")
    for sid, kind in [(USER, "User"), (COMPUTER, "Computer")]:
        model.principals[sid] = ResolvedPrincipal(
            sid, "EXAMPLE\\synthetic-" + kind.lower(), "synthetic", kind, "EXAMPLE", True
        )
    for path, gpo_id, value, kind in [
        (ROOT, "11111111222243338444555555555555", "domain", "domain"),
        (OU, "66666666777748889999aaaaaaaaaaaa", "known OU", "ou"),
    ]:
        model.soms.append(
            Som(path, value, kind, kind == "ou", [SomLink(gpo_id, 1, True, False, path)])
        )
        model.gpos.append(
            _make_gpo(
                id=gpo_id,
                name=value,
                domain="example.com",
                settings=[
                    Setting(
                        gpo_id,
                        side,
                        "Registry",
                        r"Software\Synthetic:Value",
                        "Value",
                        value,
                        {},
                        False,
                    )
                    for side in ("User", "Computer")
                ],
                delegation=[
                    DelegationEntry(
                        gpo_id, "Authenticated Users", "S-1-5-11", "Apply Group Policy", True
                    )
                ],
            )
        )
    return model


@pytest.mark.parametrize("sid", [USER, COMPUTER])
@pytest.mark.parametrize("dn,expected", TARGETS)
def test_object_dn_warning_does_not_claim_its_ou_is_missing(estate, sid, dn, expected):
    result = principal_resultant(estate, sid, dn=dn, danger=[])
    assert len(result.settings) == 1
    assert result.settings[0].winning_value == expected
    message = result.caveat_mechanisms[0]
    assert message.startswith("Principal target DN")
    assert "did not match a collected scope" in message
    assert "ancestor or fallback scope" in message
    assert "Inheritance blocking on uncollected intermediate OUs" in message
    assert "OU is not in the collected estate" not in message


@pytest.mark.parametrize("sid", [USER, COMPUTER])
@pytest.mark.parametrize("dn", [None, ROOT, OU])
def test_exact_scope_and_unspecified_dn_do_not_gain_approximation_warning(estate, sid, dn):
    result = principal_resultant(estate, sid, dn=dn, danger=[])
    assert result.settings[0].winning_value == ("known OU" if dn == OU else "domain")
    assert not any(
        "target DN" in message or "OU is not in the collected estate" in message
        for message in result.caveat_mechanisms
    )


@pytest.mark.parametrize("dn,expected", TARGETS)
def test_computer_pair_warning_describes_only_the_computer_target(estate, dn, expected):
    result = principal_resultant(estate, USER, COMPUTER, dn=OU, computer_dn=dn, danger=[])
    assert {setting.side: setting.winning_value for setting in result.settings} == {
        "User": "known OU",
        "Computer": expected,
    }
    message = result.caveat_mechanisms[0]
    assert message.startswith("Computer target DN")
    assert "did not match a collected scope" in message
    assert "ancestor or fallback scope" in message
    assert "OU is not in the collected estate" not in message
    assert not any(
        message.startswith("Principal target DN") for message in result.caveat_mechanisms
    )


def test_both_object_targets_retain_separate_approximation_messages(estate):
    dn = "CN=Synthetic," + OU
    result = principal_resultant(estate, USER, COMPUTER, dn=dn, computer_dn=dn, danger=[])
    assert {setting.side: setting.winning_value for setting in result.settings} == {
        "User": "known OU",
        "Computer": "known OU",
    }
    messages = result.caveat_mechanisms[:2]
    assert messages[0].startswith("Principal target DN")
    assert messages[1].startswith("Computer target DN")
    assert all("did not match a collected scope" in message for message in messages)
    assert all("OU is not in the collected estate" not in message for message in messages)
