"""Pure helpers for normalization and parsing."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element


def localname(tag: str) -> str:
    """Strip XML namespace prefix from a tag: ``{ns}local`` → ``local``."""
    return tag.split("}")[-1] if "}" in tag else tag


def child_by_localname(parent: Element, name: str) -> Element | None:
    """First child whose localname matches ``name``."""
    for child in parent:
        if localname(child.tag) == name:
            return child
    return None


def children_by_localname(parent: Element, name: str) -> list[Element]:
    """All children whose localname matches ``name``."""
    return [child for child in parent if localname(child.tag) == name]


def canonical_guid(raw: str) -> str:
    """Lowercase and strip surrounding braces, whitespace, and hyphens.

    ``"{31B2F340-016D-11D2-945F-00C04FB984F9}"`` →
    ``"31b2f340016d11d2945f00c04fb984f9"``.
    """
    cleaned = raw.strip().strip("{}").strip()
    # Validate: 32 hex digits optionally with hyphens
    bare = cleaned.replace("-", "")
    if len(bare) != 32 or not all(c in "0123456789abcdefABCDEF" for c in bare):
        raise ValueError(f"Not a valid GUID: {raw!r}")
    return bare.lower()


def load_json(path: str | Path) -> Any:
    """Read JSON using ``encoding="utf-8-sig"`` so a PowerShell 5.1 UTF-8 BOM is tolerated."""
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def parse_bool(text: str | None) -> bool:
    """``"true"`` → True, ``"false"``/None → False (case-insensitive)."""
    if text is None:
        return False
    return text.strip().lower() == "true"


def parse_dt(text: str | None) -> datetime | None:
    """ISO-8601 datetime; None/empty → None."""
    if not text:
        return None
    # The report uses e.g. 2026-03-10T16:32:00
    # A malformed timestamp in one GPO should not prevent loading the rest
    # of the estate.
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def parse_triage_dt(value: object) -> datetime | None:
    """A triage timestamp as the triage fold reads it: ISO-8601
    (``datetime.fromisoformat``), naive values taken as UTC, converted to UTC.
    None for anything that is not such a string, including values whose UTC
    conversion overflows (``0001-01-01T00:00:00+05:00``).

    The one parser for triage times: the fold (``findings``) and the v7->v8
    legacy validation (``analyst_text.legacy_triage_field_ok``) both use it,
    so a legacy time is copied exactly when the fold can read it.
    """
    if not isinstance(value, str):
        return None
    parsed = parse_dt(value)
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    try:
        return parsed.astimezone(UTC)
    except (OverflowError, ValueError):
        return None


def parse_int(text: str | None) -> int | None:
    """None/empty/non-numeric → None."""
    if text is None:
        return None
    text = text.strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        pass
    # PowerShell's ConvertTo-Json can emit floats for integer fields.
    try:
        return int(float(text))
    except (ValueError, OverflowError):
        return None


def sqlite_int(value: int) -> int | None:
    """Return a bindable SQLite integer, or None outside its signed 64-bit range."""
    return value if -(2**63) <= value <= 2**63 - 1 else None


REGISTRY_CSES = frozenset({"registry", "windows registry"})


def is_registry_cse(cse: str) -> bool:
    """True if the CSE name is the Registry extension (case-insensitive)."""
    return cse.strip().lower() in REGISTRY_CSES
