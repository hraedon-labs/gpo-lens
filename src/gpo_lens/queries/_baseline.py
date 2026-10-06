"""Baseline comparison (Tier 2): estate settings vs a security baseline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from gpo_lens.model import Side

if TYPE_CHECKING:
    from gpo_lens.model import AdmxResolver, Estate


@dataclass(frozen=True)
class BaselineSetting:
    """One expected setting from a baseline."""

    side: Side
    cse: str
    identity: str
    display_name: str
    expected_value: str


@dataclass(frozen=True)
class BaselineDiffEntry:
    """One finding from a baseline comparison."""

    status: str  # "compliant", "drift", "missing", "extra"
    side: Side
    cse: str
    identity: str
    display_name: str
    expected_value: str
    actual_value: str
    gpo_id: str  # GPO(s) that set this value (comma-separated if multiple)
    admx_name: str  # resolved ADMX policy name (empty if no crosswalk)


def load_baseline_from_estate(estate: Estate) -> list[BaselineSetting]:
    """Extract baseline settings from an estate (typically a single baseline GPO)."""
    results: list[BaselineSetting] = []
    for g in estate.gpos:
        for s in g.settings:
            if s.source_state == "blocked":
                continue
            results.append(
                BaselineSetting(
                    side=s.side,
                    cse=s.cse,
                    identity=s.identity,
                    display_name=s.display_name,
                    expected_value=s.display_value,
                )
            )
    return results


def baseline_diff(
    estate: Estate,
    baseline: list[BaselineSetting],
    admx: AdmxResolver | None = None,
) -> list[BaselineDiffEntry]:
    """Compare estate settings against a baseline."""
    from gpo_lens.admx_parser import PolicyDefinitions as _PD

    if admx is None:
        admx = _PD()

    baseline_keys: dict[tuple[Side, str, str], BaselineSetting] = {}
    for bs in baseline:
        key = (bs.side, bs.cse.lower(), bs.identity.lower())
        if key not in baseline_keys:
            baseline_keys[key] = bs

    estate_settings: dict[tuple[Side, str, str], list[tuple[str, str]]] = {}
    for g in estate.gpos:
        for s in g.settings:
            if s.source_state == "blocked":
                continue
            key = (s.side, s.cse.lower(), s.identity.lower())
            estate_settings.setdefault(key, []).append((g.id, s.display_value))

    results: list[BaselineDiffEntry] = []

    for bs in baseline:
        bkey = (bs.side, bs.cse.lower(), bs.identity.lower())
        actuals = estate_settings.get(bkey, [])
        admx_name = admx.resolve_display_name(bs.identity, side=bs.side) or ""

        if not actuals:
            results.append(
                BaselineDiffEntry(
                    status="missing",
                    side=bs.side,
                    cse=bs.cse,
                    identity=bs.identity,
                    display_name=bs.display_name,
                    expected_value=bs.expected_value,
                    actual_value="",
                    gpo_id="",
                    admx_name=admx_name,
                )
            )
        else:
            values = {v for _, v in actuals}
            gpo_ids = ",".join(sorted({gid for gid, _ in actuals}))
            compliant = values == {bs.expected_value}
            # Preserve the old single row for homogeneous values. Mixed
            # sources all drift, and each value remains tied to its GPO.
            sources = [(gpo_ids, next(iter(values)))] if len(values) == 1 else sorted(set(actuals))
            for gid, value in sources:
                results.append(
                    BaselineDiffEntry(
                        status="compliant" if compliant else "drift",
                        side=bs.side,
                        cse=bs.cse,
                        identity=bs.identity,
                        display_name=bs.display_name,
                        expected_value=bs.expected_value,
                        actual_value=value,
                        gpo_id=gid,
                        admx_name=admx_name,
                    )
                )

    baseline_identity_set = {(bs.side, bs.cse.lower(), bs.identity.lower()) for bs in baseline}
    for (side, cse, ident), entries in estate_settings.items():
        if (side, cse, ident) not in baseline_identity_set:
            display_name = ""
            for g in estate.gpos:
                for s in g.settings:
                    if s.side == side and s.cse.lower() == cse and s.identity.lower() == ident:
                        display_name = s.display_name
                        break
                if display_name:
                    break
            gpo_ids = ",".join(sorted({gid for gid, _ in entries}))
            admx_name = admx.resolve_display_name(ident, side=side) or ""
            results.append(
                BaselineDiffEntry(
                    status="extra",
                    side=side,
                    cse=cse,
                    identity=ident,
                    display_name=display_name,
                    expected_value="",
                    actual_value=entries[0][1],
                    gpo_id=gpo_ids,
                    admx_name=admx_name,
                )
            )

    results.sort(
        key=lambda e: (
            {"drift": 0, "missing": 1, "extra": 2, "compliant": 3}[e.status],
            e.cse,
            e.side,
            e.identity,
        )
    )
    return results
