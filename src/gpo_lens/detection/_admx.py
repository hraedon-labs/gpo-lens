"""ADMX gap detection — Registry CSE settings with no resolved policy name."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from gpo_lens.model import Side
from gpo_lens.normalize import is_registry_cse

if TYPE_CHECKING:
    from gpo_lens.model import AdmxResolver, Estate


_ADMX_REGISTRY_PREFIXES = (
    "software\\",
    "hklm\\",
    "hkcu\\",
    "hkcr\\",
    "hku\\",
    "hkcc\\",
    "hkey_",
    "system\\",
    "policies\\",
    "microsoft\\",
    "windows\\",
    "control set",
    "currentversion",
)


@dataclass(frozen=True)
class AdmxGap:
    """A Registry CSE setting where no ADMX policy name was resolved."""

    gpo_id: str
    gpo_name: str
    side: Side
    identity: str
    display_name: str
    key_path: str
    value_name: str


def _is_raw_registry_path(identity: str, display_name: str) -> bool:
    id_lower = identity.lower()
    if any(id_lower.startswith(p) for p in _ADMX_REGISTRY_PREFIXES):
        return True
    dn_lower = display_name.lower()
    if any(dn_lower.startswith(p) for p in _ADMX_REGISTRY_PREFIXES):
        return True
    if "\\" in identity and any(p in id_lower for p in _ADMX_REGISTRY_PREFIXES):
        return True
    return False


def admx_gaps(
    estate: Estate,
    admx: AdmxResolver | None = None,
) -> list[AdmxGap]:
    """Flag Registry CSE settings where no ADMX policy name was resolved."""
    results: list[AdmxGap] = []
    for g in estate.gpos:
        for s in g.settings:
            if not is_registry_cse(s.cse):
                continue
            if s.source_state == "blocked":
                continue
            if not _is_raw_registry_path(s.identity, s.display_name):
                continue
            if admx is not None and admx.resolve_display_name(s.identity, side=s.side):
                continue
            parts = s.identity.split(":", 1)
            key_path = parts[0] if parts else s.identity
            value_name = parts[1] if len(parts) > 1 else s.display_name
            results.append(
                AdmxGap(
                    gpo_id=g.id,
                    gpo_name=g.name,
                    side=s.side,
                    identity=s.identity,
                    display_name=s.display_name,
                    key_path=key_path,
                    value_name=value_name,
                )
            )
    return results
