"""ADMX coverage view: estate-wide template inventory and gap detection.

Extends the per-setting ``admx_gaps`` scanner into an estate-wide view that
answers two questions:

1. **Which ADMX policies are actually used?** — for each policy in the
   PolicyDefinitions, show which GPOs reference it (if any).
2. **Which estate settings have no ADMX match?** — the gap list, showing
   Registry CSE settings whose identity doesn't resolve to any ADMX policy.

This is the coverage view that ``admx-gaps`` only half-addresses: it shows
both sides of the crosswalk — referenced policies *and* unresolved gaps — in
one place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from gpo_lens.admx_parser import TemplateFileSkip
from gpo_lens.normalize import is_registry_cse

if TYPE_CHECKING:
    from gpo_lens.model import AdmxResolver, Estate


@dataclass(frozen=True)
class AdmxCoverageEntry:
    """One ADMX policy's coverage status in the estate."""

    policy_name: str  # ADMX policy name (e.g. "Pol_NoControlPanel")
    display_name: str  # resolved display name from ADML
    class_scope: str  # "Machine" | "User" | "Both"
    registry_key: str  # registry key path
    value_name: str  # registry value name
    is_referenced: bool  # True if any GPO sets this policy
    referenced_gpos: str  # comma-separated GPO names (empty if not referenced)


@dataclass(frozen=True)
class AdmxCoverageSummary:
    """Summary of ADMX template coverage across the estate."""

    total_policies: int  # total policies defined in ADMX templates
    referenced_policies: int  # policies referenced by >=1 GPO
    unreferenced_policies: int  # policies defined but not used
    gap_count: int  # estate Registry settings with no ADMX match
    unreadable_file_count: int = 0


@dataclass(frozen=True)
class AdmxCoverageReport:
    """Full ADMX coverage report."""

    summary: AdmxCoverageSummary
    referenced: list[AdmxCoverageEntry] = field(default_factory=list)
    unreferenced: list[AdmxCoverageEntry] = field(default_factory=list)
    gaps: list[AdmxCoverageEntry] = field(default_factory=list)
    skipped_files: list[TemplateFileSkip] = field(default_factory=list)


def admx_coverage(
    estate: Estate,
    admx: AdmxResolver | None = None,
) -> AdmxCoverageReport:
    """Build an estate-wide ADMX coverage report.

    Requires a resolved :class:`~gpo_lens.admx_parser.PolicyDefinitions`.
    If ``admx`` is ``None``, an empty report with zero counts is returned.

    The report has three sections:

    * ``referenced`` — ADMX policies that match at least one estate setting,
      with the GPO names that reference them.
    * ``unreferenced`` — ADMX policies defined in the templates but not used
      by any GPO in the estate.
    * ``gaps`` — estate Registry CSE settings whose identity does not resolve
      to any ADMX policy (the same set ``admx_gaps`` reports, reformatted as
      coverage entries).
    """
    from gpo_lens.admx_parser import PolicyDefinitions as _PD
    from gpo_lens.detection import _is_raw_registry_path

    if admx is None:
        admx = _PD()

    policies = getattr(admx, "policies", [])
    skipped_files = list(getattr(admx, "skipped_files", []))

    referenced: list[AdmxCoverageEntry] = []
    unreferenced: list[AdmxCoverageEntry] = []

    estate_settings: dict[tuple[str, str], list[str]] = {}
    for g in estate.gpos:
        for s in g.settings:
            if s.source_state == "blocked":
                continue
            if not is_registry_cse(s.cse):
                continue
            norm_key = s.identity.split(":", 1)[0].lower().strip("\\")
            if ":" in s.identity:
                norm_val = s.identity.split(":", 1)[1].lower()
            else:
                norm_val = s.display_name.lower()
            key = (norm_key, norm_val)
            estate_settings.setdefault(key, []).append(g.name)

    for policy in policies:
        norm_key = policy.key.lower().strip("\\") if policy.key else ""
        norm_val = policy.value_name.lower() if policy.value_name else ""
        lookup_key = (norm_key, norm_val)

        refs = estate_settings.get(lookup_key, [])
        if not refs and not norm_val:
            for ek, gpos in estate_settings.items():
                if ek[0] == norm_key:
                    refs = gpos
                    break

        if refs:
            referenced.append(
                AdmxCoverageEntry(
                    policy_name=policy.name,
                    display_name=policy.display_name,
                    class_scope=policy.class_scope,
                    registry_key=policy.key,
                    value_name=policy.value_name,
                    is_referenced=True,
                    referenced_gpos=",".join(sorted(set(refs))),
                )
            )
        else:
            unreferenced.append(
                AdmxCoverageEntry(
                    policy_name=policy.name,
                    display_name=policy.display_name,
                    class_scope=policy.class_scope,
                    registry_key=policy.key,
                    value_name=policy.value_name,
                    is_referenced=False,
                    referenced_gpos="",
                )
            )

    gaps: list[AdmxCoverageEntry] = []
    for g in estate.gpos:
        for s in g.settings:
            if s.source_state == "blocked":
                continue
            if not is_registry_cse(s.cse):
                continue
            if not _is_raw_registry_path(s.identity, s.display_name):
                continue
            if admx.resolve_display_name(s.identity):
                continue

            parts = s.identity.split(":", 1)
            key_path = parts[0] if parts else s.identity
            value_name = parts[1] if len(parts) > 1 else s.display_name

            gaps.append(
                AdmxCoverageEntry(
                    policy_name="",
                    display_name=s.display_name,
                    class_scope="Machine" if s.side == "Computer" else "User",
                    registry_key=key_path,
                    value_name=value_name,
                    is_referenced=False,
                    referenced_gpos=g.name,
                )
            )

    summary = AdmxCoverageSummary(
        total_policies=len(policies),
        referenced_policies=len(referenced),
        unreferenced_policies=len(unreferenced),
        gap_count=len(gaps),
        unreadable_file_count=len(skipped_files),
    )
    return AdmxCoverageReport(
        summary=summary,
        referenced=referenced,
        unreferenced=unreferenced,
        gaps=gaps,
        skipped_files=skipped_files,
    )
