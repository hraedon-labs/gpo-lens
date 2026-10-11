"""Hygiene scans: cpassword, version skew, unlinked, empty, disabled-but-populated, MS16-072."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from gpo_lens.authz import (
    MS16_072_TRUSTEES,
    broad_trustee_key,
    permission_implies_read,
)
from gpo_lens.detection._gpp import _walk_gpp_xml
from gpo_lens.model import Side
from gpo_lens.normalize import localname
from gpo_lens.redaction import is_cpassword_name

if TYPE_CHECKING:
    from gpo_lens.model import DelegationEntry, Estate, Gpo, Som, SomLink


@dataclass(frozen=True)
class CpasswordHit:
    """One ``cpassword`` attribute found in a GPP XML file."""

    gpo_id: str
    gpo_name: str
    file: str
    tag: str
    cpassword: str


def _scan_gpo_for_cpassword(gpo: Gpo) -> list[CpasswordHit]:
    """Every non-``None`` cpassword in the GPO's GPP XML, in any casing.

    The real GPP form is a ``cpassword`` attribute (usually on ``<Properties>``);
    the attribute name is matched case-insensitively and namespace-blind, and a
    ``<cpassword>`` element's text is reported too. ``cpassword=""`` is still a
    hit: the attribute's presence is what MS14-025 remediation removes.
    """
    results: list[CpasswordHit] = []
    for walk in _walk_gpp_xml(gpo, only_known=True):
        root = walk.tree.getroot()
        if root is None:
            continue
        for elem in root.iter():
            tag = localname(elem.tag)
            values = [v for k, v in elem.attrib.items() if is_cpassword_name(k)]
            if is_cpassword_name(elem.tag):
                values.append("".join(elem.itertext()).strip())
            for cpw in values:
                results.append(
                    CpasswordHit(
                        gpo_id=gpo.id,
                        gpo_name=gpo.name,
                        file=str(walk.rel_file),
                        tag=tag,
                        cpassword=cpw,
                    )
                )
    return results


# WI-047: authorization predicates consolidated into authz.py.


def _has_ms16_072_read(delegation: list[DelegationEntry]) -> bool:
    return any(
        e.allowed
        and broad_trustee_key(e.trustee, e.trustee_sid, MS16_072_TRUSTEES) is not None
        and permission_implies_read(e.permission)
        for e in delegation
    )


# Public API aliases
has_ms16_072_read = _has_ms16_072_read


def unlinked_gpos(estate: Estate) -> list[Gpo]:
    """GPOs with no links.  These apply nowhere."""
    return [g for g in estate.gpos if not g.links]


def empty_gpos(estate: Estate) -> list[Gpo]:
    """GPOs with no readable settings on either side.

    Per ``docs/spec/wi_queries.md`` AC-02, a GPO with only ``<Blocked/>``
    extensions (and therefore source_state="blocked" settings) counts as
    empty.  Blocked extensions are still surfaced separately by
    ``blocked_extensions``.
    """
    return [g for g in estate.gpos if not any(s.source_state != "blocked" for s in g.settings)]


def disabled_but_populated(estate: Estate) -> list[tuple[Gpo, Side]]:
    """(Gpo, Side) pairs where the side is disabled but has settings."""
    results: list[tuple[Gpo, Side]] = []
    for g in estate.gpos:
        comp_disabled = not g.computer_enabled and any(
            s.side == "Computer" and s.from_disabled_side for s in g.settings
        )
        user_disabled = not g.user_enabled and any(
            s.side == "User" and s.from_disabled_side for s in g.settings
        )
        if comp_disabled:
            results.append((g, "Computer"))
        if user_disabled:
            results.append((g, "User"))
    return results


def version_skew(estate: Estate) -> list[tuple[Gpo, Side]]:
    """GPOs where GPC (AD) and GPT (SYSVOL) version numbers differ."""
    results: list[tuple[Gpo, Side]] = []
    for g in estate.gpos:
        if g.computer_version_skew:
            results.append((g, "Computer"))
        if g.user_version_skew:
            results.append((g, "User"))
    return results


def ms16_072_vulnerable(estate: Estate) -> list[Gpo]:
    """GPOs missing Read for Authenticated Users or Domain Computers (MS16-072)."""
    return [g for g in estate.gpos if not _has_ms16_072_read(g.delegation)]


def cpassword_scan(estate: Estate) -> list[CpasswordHit]:
    """Scan SYSVOL GPP XML for lingering ``cpassword`` attributes (MS14-025)."""
    results: list[CpasswordHit] = []
    for g in estate.gpos:
        results.extend(_scan_gpo_for_cpassword(g))
    return results


def dangling_links(estate: Estate) -> list[tuple[Som, SomLink]]:
    """SOM links that point to GPO ids not present in the estate."""
    gpo_ids = {g.id for g in estate.gpos}
    results: list[tuple[Som, SomLink]] = []
    for som in estate.soms:
        for link in som.links:
            if link.gpo_id not in gpo_ids:
                results.append((som, link))
    return results


def enforced_links(estate: Estate) -> list[tuple[Som, SomLink]]:
    """All enforced (NoOverride) links across the estate."""
    results: list[tuple[Som, SomLink]] = []
    for som in estate.soms:
        for link in som.links:
            if link.enforced:
                results.append((som, link))
    return results


def _mask_cpassword(cpw: str) -> str:
    """Fixed mask that reveals nothing about the value.

    Earlier releases kept the first four characters. With a fixed IV and the
    published key those characters are a deterministic function of the start
    of the password, so even a prefix narrows a guess; it is no longer shown.
    """
    del cpw
    return "****"


# Public API alias
mask_cpassword = _mask_cpassword
