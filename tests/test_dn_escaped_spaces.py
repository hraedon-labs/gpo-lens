"""DN ancestry must retain escaped spaces that belong to an OU name."""

from __future__ import annotations

import pytest
from _helpers import _make_gpo

from gpo_lens.merge import _resolve_som_path_for_principal, principal_resultant
from gpo_lens.model import (
    DelegationEntry,
    Estate,
    ResolvedPrincipal,
    Setting,
    Som,
    SomLink,
)
from gpo_lens.topology import som_effective_gpos

ROOT = "DC=example,DC=com"
ROOT_GPO = "11111111222243338444555555555555"
OU_GPO = "66666666777748889999aaaaaaaaaaaa"
ESCAPED_RDNS = [
    r"OU=Name\ ",
    r"OU=Name\\\ ",
    r"OU=Last\,First\ ",
    r"OU=Name\ \ ",
    r"OU=Name+CN=Alias\ ",
]


def estate_with_ou(path: str) -> Estate:
    root = Som(ROOT, "example", "domain", False, [SomLink(ROOT_GPO, 1, True, False, ROOT)])
    # The collector's resolved chain excludes the non-enforced root link.
    ou = Som(path, "Synthetic OU", "ou", True, [SomLink(OU_GPO, 1, True, False, path)])
    return Estate(domain="example.com", soms=[root, ou])


@pytest.mark.parametrize("rdn", ESCAPED_RDNS)
def test_topology_uses_collected_ou_chain_for_child_of_escaped_space(rdn):
    path = rdn + "," + ROOT
    estate = estate_with_ou(path)
    result = som_effective_gpos(estate, "CN=Synthetic User," + path)
    assert [g.gpo_id for g in result] == [OU_GPO]
    assert [g.target for g in result] == [path]


@pytest.mark.parametrize("rdn", ESCAPED_RDNS)
@pytest.mark.parametrize("prefix", ["", "CN=Synthetic User,", "CN=Synthetic User,OU=Uncollected,"])
def test_principal_lookup_keeps_escaped_space_for_exact_and_ancestor_matches(rdn, prefix):
    path = rdn + "," + ROOT
    assert _resolve_som_path_for_principal(estate_with_ou(path), prefix + path) == path


@pytest.mark.parametrize(
    "rdn,presented",
    [
        ("OU=Normal", "CN=Synthetic User, OU=Normal , DC=example , DC=com "),
        (r"OU=Name\\", r"CN=Synthetic User, OU=Name\\ , DC=example, DC=com"),
        (r"OU=Name\20", r"CN=Synthetic User, OU=Name\20 , DC=example, DC=com"),
        (r"OU=Name\ ", r"CN=Synthetic User, OU=Name\  , DC=example, DC=com"),
    ],
)
def test_existing_separator_padding_backslashes_and_hex_spelling_still_match(rdn, presented):
    path = rdn + "," + ROOT
    estate = estate_with_ou(path)
    assert _resolve_som_path_for_principal(estate, presented) == path
    assert [g.gpo_id for g in som_effective_gpos(estate, presented)] == [OU_GPO]


def test_escaped_space_and_plain_ou_stay_distinct():
    escaped = r"OU=Name\ ," + ROOT
    plain = "OU=Name," + ROOT
    estate = estate_with_ou(escaped)
    estate.soms.append(Som(plain, "Plain", "ou", False, []))
    assert _resolve_som_path_for_principal(estate, "CN=Synthetic User," + escaped) == escaped
    assert _resolve_som_path_for_principal(estate, "CN=Synthetic User," + plain) == plain
    assert som_effective_gpos(estate, "CN=Synthetic User," + plain) == []


@pytest.mark.parametrize("side", ["User", "Computer"])
def test_resultant_uses_the_collected_ou_setting_instead_of_domain_fallback(side):
    path = r"OU=Name\ ," + ROOT
    estate = estate_with_ou(path)
    sid = "s-1-5-21-1000000000-2000000000-3000000000-1001"
    estate.principals[sid] = ResolvedPrincipal(
        sid=sid,
        name="EXAMPLE\\synthetic",
        sam="synthetic",
        principal_type=side,
        domain="EXAMPLE",
        resolved=True,
    )
    for gpo_id, value in [(ROOT_GPO, "domain"), (OU_GPO, "collected OU")]:
        estate.gpos.append(
            _make_gpo(
                id=gpo_id,
                name=value,
                domain="example.com",
                settings=[
                    Setting(
                        gpo_id=gpo_id,
                        side=side,
                        cse="Registry",
                        identity=r"Software\Synthetic\Policy:Value",
                        display_name="Synthetic policy",
                        display_value=value,
                        raw={},
                        from_disabled_side=False,
                    )
                ],
                delegation=[
                    DelegationEntry(
                        gpo_id, "Authenticated Users", "S-1-5-11", "Apply Group Policy", True
                    )
                ],
            )
        )
    result = principal_resultant(estate, sid, dn="CN=Synthetic Principal," + path, danger=[])
    assert len(result.settings) == 1
    assert result.settings[0].winning_value == "collected OU"
    assert result.settings[0].winning_gpo_id == OU_GPO


@pytest.mark.parametrize(
    "presented",
    [
        "OU=A , DC=example,DC=com",
        "OU=A,DC=example , DC=com",
        " OU=A , DC=example , DC=com ",
        "ou=a ,dc=EXAMPLE,DC=com",
        "OU=A,\tDC=example,DC=com",
    ],
)
def test_padded_own_dn_resolves_to_the_ou_not_its_parent(presented):
    estate = estate_with_ou("OU=A," + ROOT)
    result = som_effective_gpos(estate, presented)
    assert [g.gpo_id for g in result] == [OU_GPO]
    assert _resolve_som_path_for_principal(estate, presented) == "OU=A," + ROOT


def test_padded_dn_of_uncollected_ou_still_falls_back_to_collected_parent():
    estate = estate_with_ou("OU=A," + ROOT)
    result = som_effective_gpos(estate, "OU=Uncollected , OU=A , DC=example,DC=com")
    assert [g.gpo_id for g in result] == [OU_GPO]
    # A different, uncollected sibling falls back to the domain root chain.
    sibling = som_effective_gpos(estate, "OU=A2 , DC=example,DC=com")
    assert [g.gpo_id for g in sibling] == [ROOT_GPO]


def test_padded_escaped_space_ou_is_not_conflated_with_plain_ou():
    escaped = r"OU=Name\ ," + ROOT
    estate = estate_with_ou(escaped)
    estate.soms.append(Som("OU=Name," + ROOT, "Plain", "ou", False, []))
    result = som_effective_gpos(estate, r"OU=Name\  , DC=example,DC=com")
    assert [g.gpo_id for g in result] == [OU_GPO]
    assert som_effective_gpos(estate, "OU=Name , DC=example,DC=com") == []
