"""Golden-backup comparison: live estate vs the org's own known-good GPO backup.

Unlike baseline diff (which compares against a flat list of expected values),
golden diff compares two full estates GPO-by-GPO.  GPOs are matched by name
(case-insensitive) because a backup's GUIDs may differ from the live estate's.
For each matched GPO pair, settings are compared by ``(side, cse, identity)``.

Result statuses:
- ``compliant`` — setting exists in both with the same value
- ``changed``   — setting exists in both but value differs (drift)
- ``added``      — setting exists in live but not in golden (new since backup)
- ``removed``    — setting exists in golden but not in live (deleted since backup)
- ``gpo_added``   — GPO exists in live but not in golden
- ``gpo_removed`` — GPO exists in golden but not in live
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gpo_lens.model import AdmxResolver, Estate, Gpo, Side


@dataclass(frozen=True)
class GoldenDiffEntry:
    """One finding from a golden-backup comparison."""

    status: str  # "compliant"|"changed"|"added"|"removed"|"gpo_added"|"gpo_removed"
    gpo_name: str
    side: str  # "Computer" | "User" | "" (empty for GPO-level entries)
    cse: str
    identity: str
    display_name: str
    golden_value: str
    live_value: str
    golden_gpo_id: str
    live_gpo_id: str
    admx_name: str  # resolved ADMX policy name (empty if no crosswalk)


@dataclass(frozen=True)
class GoldenDiffSummary:
    """Aggregate counts from a golden-backup comparison."""

    gpos_matched: int
    gpos_added: int
    gpos_removed: int
    settings_compliant: int
    settings_changed: int
    settings_added: int
    settings_removed: int


def golden_diff(
    live_estate: Estate,
    golden_estate: Estate,
    admx: AdmxResolver | None = None,
) -> list[GoldenDiffEntry]:
    """Compare a live estate against a golden-backup estate.

    GPOs are matched by name (case-insensitive).  Settings within matched GPOs
    are compared by ``(side, cse, identity)`` (case-insensitive).  Blocked
    extensions (``source_state == "blocked"``) are skipped — they are not
    active settings.

    Returns entries sorted by severity: GPO-level changes first, then
    setting-level drift/removed/added, then compliant.
    """
    if admx is None:
        from gpo_lens.admx_parser import PolicyDefinitions as _PD

        admx = _PD()

    live_by_name: dict[str, list[Gpo]] = {}
    for g in live_estate.gpos:
        live_by_name.setdefault(g.name.lower(), []).append(g)

    golden_by_name: dict[str, list[Gpo]] = {}
    for g in golden_estate.gpos:
        golden_by_name.setdefault(g.name.lower(), []).append(g)

    live_names = set(live_by_name.keys())
    golden_names = set(golden_by_name.keys())

    results: list[GoldenDiffEntry] = []

    for name in sorted(golden_names - live_names):
        for g in golden_by_name[name]:
            results.append(
                GoldenDiffEntry(
                    status="gpo_removed",
                    gpo_name=g.name,
                    side="",
                    cse="",
                    identity="",
                    display_name="",
                    golden_value="",
                    live_value="",
                    golden_gpo_id=g.id,
                    live_gpo_id="",
                    admx_name="",
                )
            )

    for name in sorted(live_names - golden_names):
        for g in live_by_name[name]:
            results.append(
                GoldenDiffEntry(
                    status="gpo_added",
                    gpo_name=g.name,
                    side="",
                    cse="",
                    identity="",
                    display_name="",
                    golden_value="",
                    live_value="",
                    golden_gpo_id="",
                    live_gpo_id=g.id,
                    admx_name="",
                )
            )

    matched_names: set[str] = set()

    for name in sorted(live_names & golden_names):
        live_gpos = live_by_name[name]
        golden_gpos = golden_by_name[name]

        if len(live_gpos) > 1 or len(golden_gpos) > 1:
            import warnings

            warnings.warn(
                f"Duplicate GPO name '{live_gpos[0].name}' — only first of each compared",
                stacklevel=2,
            )

        live_gpo = live_gpos[0]
        golden_gpo = golden_gpos[0]
        matched_names.add(name)

        live_settings: dict[tuple[Side, str, str], set[str]] = {}
        live_display: dict[tuple[Side, str, str], str] = {}
        live_cse: dict[tuple[Side, str, str], str] = {}
        live_ident: dict[tuple[Side, str, str], str] = {}
        for s in live_gpo.settings:
            if s.source_state == "blocked":
                continue
            key = (s.side, s.cse.lower(), s.identity.lower())
            if key not in live_settings:
                live_settings[key] = set()
                live_display[key] = s.display_name
                live_cse[key] = s.cse
                live_ident[key] = s.identity
            live_settings[key].add(s.display_value)

        golden_settings: dict[tuple[Side, str, str], set[str]] = {}
        golden_display: dict[tuple[Side, str, str], str] = {}
        golden_cse: dict[tuple[Side, str, str], str] = {}
        golden_ident: dict[tuple[Side, str, str], str] = {}
        for s in golden_gpo.settings:
            if s.source_state == "blocked":
                continue
            key = (s.side, s.cse.lower(), s.identity.lower())
            if key not in golden_settings:
                golden_settings[key] = set()
                golden_display[key] = s.display_name
                golden_cse[key] = s.cse
                golden_ident[key] = s.identity
            golden_settings[key].add(s.display_value)

        all_keys = set(live_settings.keys()) | set(golden_settings.keys())

        for skey in sorted(all_keys):
            side = skey[0]
            orig_cse = live_cse.get(skey) or golden_cse.get(skey, "")
            orig_ident = live_ident.get(skey) or golden_ident.get(skey, "")
            admx_name = admx.resolve_display_name(orig_ident, side=side) or ""
            disp = golden_display.get(skey) or live_display.get(skey, "")

            if skey in golden_settings and skey not in live_settings:
                results.append(
                    GoldenDiffEntry(
                        status="removed",
                        gpo_name=live_gpo.name,
                        side=side,
                        cse=orig_cse,
                        identity=orig_ident,
                        display_name=disp,
                        golden_value="; ".join(sorted(golden_settings[skey])),
                        live_value="",
                        golden_gpo_id=golden_gpo.id,
                        live_gpo_id=live_gpo.id,
                        admx_name=admx_name,
                    )
                )
            elif skey in live_settings and skey not in golden_settings:
                results.append(
                    GoldenDiffEntry(
                        status="added",
                        gpo_name=live_gpo.name,
                        side=side,
                        cse=orig_cse,
                        identity=orig_ident,
                        display_name=disp,
                        golden_value="",
                        live_value="; ".join(sorted(live_settings[skey])),
                        golden_gpo_id=golden_gpo.id,
                        live_gpo_id=live_gpo.id,
                        admx_name=admx_name,
                    )
                )
            elif (
                live_settings[skey] != golden_settings[skey]
                or len(live_settings[skey]) != 1
                or len(golden_settings[skey]) != 1
            ):
                results.append(
                    GoldenDiffEntry(
                        status="changed",
                        gpo_name=live_gpo.name,
                        side=side,
                        cse=orig_cse,
                        identity=orig_ident,
                        display_name=disp,
                        golden_value="; ".join(sorted(golden_settings[skey])),
                        live_value="; ".join(sorted(live_settings[skey])),
                        golden_gpo_id=golden_gpo.id,
                        live_gpo_id=live_gpo.id,
                        admx_name=admx_name,
                    )
                )
            else:
                results.append(
                    GoldenDiffEntry(
                        status="compliant",
                        gpo_name=live_gpo.name,
                        side=side,
                        cse=orig_cse,
                        identity=orig_ident,
                        display_name=disp,
                        golden_value="; ".join(sorted(golden_settings[skey])),
                        live_value="; ".join(sorted(live_settings[skey])),
                        golden_gpo_id=golden_gpo.id,
                        live_gpo_id=live_gpo.id,
                        admx_name=admx_name,
                    )
                )

    _STATUS_ORDER = {
        "gpo_removed": 0,
        "gpo_added": 1,
        "changed": 2,
        "removed": 3,
        "added": 4,
        "compliant": 5,
    }
    results.sort(
        key=lambda e: (
            _STATUS_ORDER.get(e.status, 9),
            e.gpo_name.lower(),
            e.side,
            e.cse,
            e.identity,
        )
    )
    return results


def golden_diff_summary(
    entries: list[GoldenDiffEntry],
    *,
    matched_gpo_count: int | None = None,
) -> GoldenDiffSummary:
    """Compute aggregate counts from a list of :class:`GoldenDiffEntry`.

    ``matched_gpo_count`` should be the number of GPOs that exist in both
    estates.  When ``None``, it is derived from entries (which undercounts
    matched GPOs that have zero settings on both sides).
    """
    if matched_gpo_count is None:
        matched_gpo_count = len(
            {e.gpo_name for e in entries if e.status not in ("gpo_added", "gpo_removed")}
        )
    return GoldenDiffSummary(
        gpos_matched=matched_gpo_count,
        gpos_added=len({e.gpo_name for e in entries if e.status == "gpo_added"}),
        gpos_removed=len({e.gpo_name for e in entries if e.status == "gpo_removed"}),
        settings_compliant=sum(1 for e in entries if e.status == "compliant"),
        settings_changed=sum(1 for e in entries if e.status == "changed"),
        settings_added=sum(1 for e in entries if e.status == "added"),
        settings_removed=sum(1 for e in entries if e.status == "removed"),
    )
