"""Centralized query dispatch for CLI and web ask commands.

Single source of truth: the ``_QUERIES`` registry maps each query name to a
:class:`QuerySpec` that colocates the callable, description, and parameter
metadata. The legacy derived names (``_QUERY_DISPATCH``,
``_QUERY_DESCRIPTIONS``, ``QUERY_REQUIRED_PARAMS``, ``QUERY_OPTIONAL_PARAMS``,
``_PARAM_VALIDATORS``) are produced from this registry so adding a query only
requires one edit. See ``docs/spec/wi_query_dispatch.md`` for the contract.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from gpo_lens import merge as _merge
from gpo_lens import queries


@dataclass(frozen=True)
class QuerySpec:
    """Per-query metadata colocated with its callable (WI-063).

    ``required_params``/``optional_params``/``param_validators`` list non-``estate``
    parameters only; ``estate`` is always implicitly accepted by every query.
    """

    name: str
    func: Callable[..., Any]
    description: str
    required_params: list[str] = field(default_factory=list)
    optional_params: list[str] = field(default_factory=list)
    param_validators: dict[str, type] = field(default_factory=dict)


_QUERIES: dict[str, QuerySpec] = {
    "estate_summary": QuerySpec(
        name="estate_summary",
        func=lambda **kw: queries.estate_summary(kw["estate"]),
        description="Overview of the estate (GPO count, domain, SOM count, etc.)",
    ),
    "estate_doctor": QuerySpec(
        name="estate_doctor",
        func=lambda **kw: queries.estate_doctor(kw["estate"]),
        description=(
            "Health and hygiene findings across GPOs (cpassword, version skew, broken refs, etc.)"
        ),
    ),
    "cpassword_scan": QuerySpec(
        name="cpassword_scan",
        func=lambda **kw: queries.cpassword_scan(kw["estate"]),
        description="GPOs containing encrypted cpassword values",
    ),
    "unlinked_gpos": QuerySpec(
        name="unlinked_gpos",
        func=lambda **kw: queries.unlinked_gpos(kw["estate"]),
        description="GPOs that are not linked to any SOM",
    ),
    "empty_gpos": QuerySpec(
        name="empty_gpos",
        func=lambda **kw: queries.empty_gpos(kw["estate"]),
        description="GPOs that contain no settings",
    ),
    "version_skew": QuerySpec(
        name="version_skew",
        func=lambda **kw: queries.version_skew(kw["estate"]),
        description="GPOs where Active Directory and SYSVOL versions differ",
    ),
    "broken_refs": QuerySpec(
        name="broken_refs",
        func=lambda **kw: queries.broken_refs(kw["estate"]),
        description="Malformed paths or files missing from the GPO own collected SYSVOL",
    ),
    "enforced_links": QuerySpec(
        name="enforced_links",
        func=lambda **kw: queries.enforced_links(kw["estate"]),
        description="GPO links that are enforced (NoOverride)",
    ),
    "dangling_links": QuerySpec(
        name="dangling_links",
        func=lambda **kw: queries.dangling_links(kw["estate"]),
        description="Links that point to GPOs which no longer exist",
    ),
    "ms16_072_vulnerable": QuerySpec(
        name="ms16_072_vulnerable",
        func=lambda **kw: queries.ms16_072_vulnerable(kw["estate"]),
        description="GPOs vulnerable to MS16-072 (missing Authenticated Users Read)",
    ),
    "topology_crosscheck": QuerySpec(
        name="topology_crosscheck",
        func=lambda **kw: queries.topology_crosscheck(kw["estate"]),
        description="Discrepancies between OU tree and SOM inheritance data",
    ),
    "disabled_but_populated": QuerySpec(
        name="disabled_but_populated",
        func=lambda **kw: queries.disabled_but_populated(kw["estate"]),
        description="GPO sides that are disabled but still contain settings",
    ),
    "settings_at_som": QuerySpec(
        name="settings_at_som",
        func=lambda **kw: queries.settings_at_som(kw["estate"], kw["ou_path"]),
        description="Effective settings applied to a specific SOM (Scope of Management) path",
        required_params=["ou_path"],
        param_validators={"ou_path": str},
    ),
    "effective_scope": QuerySpec(
        name="effective_scope",
        func=lambda **kw: queries.effective_scope(kw["estate"], kw["gpo_id"]),
        description=(
            "Effective scoping for a single GPO: links, security filtering, "
            'WMI filter, loopback (requires param: "gpo_id")'
        ),
        required_params=["gpo_id"],
        param_validators={"gpo_id": str},
    ),
    "orphaned_wmi_filters": QuerySpec(
        name="orphaned_wmi_filters",
        func=lambda **kw: queries.orphaned_wmi_filters(kw["estate"]),
        description="WMI filters defined but not referenced by any GPO",
    ),
    "broken_wmi_refs": QuerySpec(
        name="broken_wmi_refs",
        func=lambda **kw: queries.broken_wmi_refs(kw["estate"]),
        description="GPOs referencing a WMI filter that does not exist in the estate",
    ),
    "stale_gpos": QuerySpec(
        name="stale_gpos",
        func=lambda **kw: queries.stale_gpos(kw["estate"]),
        description="GPOs that are linked but have not been modified in over 2 years",
    ),
    "danger_findings": QuerySpec(
        name="danger_findings",
        func=lambda **kw: queries.danger_findings(kw["estate"]),
        description=(
            "Curated, cited dangerous-configuration findings "
            "(GPO hijack paths, local-admin push, over-broad scope, dangerous values)"
        ),
    ),
    "principal_resultant": QuerySpec(
        name="principal_resultant",
        func=lambda **kw: _merge.principal_resultant(
            kw["estate"],
            kw["principal_sid"],
            computer_sid=kw.get("computer_sid") or None,
            dn=kw.get("dn") or None,
            computer_dn=kw.get("computer_dn") or None,
        ),
        description=(
            "Principal resultant (RSoP) — effective policy for a given principal SID "
            'from the static snapshot (requires param: "principal_sid")'
        ),
        required_params=["principal_sid"],
        optional_params=["computer_sid", "dn", "computer_dn"],
        param_validators={
            "principal_sid": str,
            "computer_sid": str,
            "dn": str,
            "computer_dn": str,
        },
    ),
    "golden_diff": QuerySpec(
        name="golden_diff",
        func=lambda **kw: queries.golden_diff(
            kw["estate"],
            kw["golden_estate"],
            admx=kw.get("admx"),
        ),
        description=(
            "Golden-backup comparison — drift between live estate and a known-good "
            'GPO backup (requires param: "golden_estate")'
        ),
        required_params=["golden_estate"],
        optional_params=["admx"],
        param_validators={"golden_estate": object, "admx": object},
    ),
    "admx_coverage": QuerySpec(
        name="admx_coverage",
        func=lambda **kw: queries.admx_coverage(
            kw["estate"],
            admx=kw.get("admx"),
        ),
        description=("ADMX coverage view — estate-wide template inventory and gap detection"),
        optional_params=["admx"],
        param_validators={"admx": object},
    ),
    "delegation_rollup": QuerySpec(
        name="delegation_rollup",
        func=lambda **kw: queries.delegation_rollup(kw["estate"]),
        description=(
            "Estate-wide delegation rollup — trustee → editable-GPO matrix "
            "with unknown-SID detection"
        ),
    ),
}


# --- Derived views (kept for backward compatibility with the existing API) ---
# These are computed from the single ``_QUERIES`` registry so they cannot
# drift out of sync (WI-063). Only entries with non-empty payloads are
# included, matching the pre-refactor shapes consumed by callers/tests.

_QUERY_DISPATCH: dict[str, Callable[..., Any]] = {
    name: spec.func for name, spec in _QUERIES.items()
}

_QUERY_DESCRIPTIONS: dict[str, str] = {name: spec.description for name, spec in _QUERIES.items()}

QUERY_REQUIRED_PARAMS: dict[str, list[str]] = {
    name: list(spec.required_params) for name, spec in _QUERIES.items() if spec.required_params
}

QUERY_OPTIONAL_PARAMS: dict[str, list[str]] = {
    name: list(spec.optional_params) for name, spec in _QUERIES.items() if spec.optional_params
}

_PARAM_VALIDATORS: dict[str, dict[str, type]] = {
    name: dict(spec.param_validators) for name, spec in _QUERIES.items() if spec.param_validators
}


def validate_params(query_name: str, params: dict[str, object]) -> dict[str, object]:
    """Validate and filter params for a query. Raises ValueError on type mismatch."""
    if query_name not in _QUERY_DISPATCH:
        raise ValueError(f"Unknown query: {query_name}")
    required = set(QUERY_REQUIRED_PARAMS.get(query_name, []))
    optional = set(QUERY_OPTIONAL_PARAMS.get(query_name, []))
    expected = {"estate", *required, *optional}
    schema = _PARAM_VALIDATORS.get(query_name, {})
    validated: dict[str, object] = {}
    for key, value in params.items():
        if key == "estate":
            validated[key] = value
            continue
        if key not in expected:
            continue
        expected_type = schema.get(key)
        if expected_type and not isinstance(value, expected_type):
            raise ValueError(
                f"Parameter '{key}' must be {expected_type.__name__}, got {type(value).__name__}"
            )
        validated[key] = value
    missing = required - set(validated.keys())
    if missing:
        raise ValueError(f"Query '{query_name}' requires parameter '{missing.pop()}'")
    return validated


VALID_QUERIES: frozenset[str] = frozenset(_QUERY_DISPATCH.keys())


def dispatch_query(name: str, **kwargs: Any) -> Any:
    """Dispatch a named query with the given kwargs. Raises KeyError if name unknown."""
    return _QUERY_DISPATCH[name](**kwargs)
