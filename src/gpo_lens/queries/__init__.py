"""Deterministic queries over an Estate — composition, Tier 2, and Tier 2.5.

This package is the public query surface. It has two layers:

* **Re-export facade** (this ``__init__``): re-exports the pure
  detection/scanner functions from ``detection``, ``danger``,
  ``topology``, and ``snapshot_diff`` so callers can do
  ``from gpo_lens.queries import X`` for anything.
* **Composition submodules** (``_search``, ``_delegation``, ``_topology``,
  ``_summary``, ``_wmi``, ``_settings``, ``_baseline``, ``_doctor``): the
  functions that combine multiple scanners (estate_doctor, estate_summary,
  baseline_diff, search, etc.). Adding a new composition query means
  editing the submodule that owns the concern, plus one ``__all__`` line
  here — not three spots in a 1000-line file.

The ``__all__`` below is the backward-compatible contract; every name it
listed before the split is still listed now, from the same source modules.
"""

from __future__ import annotations

from gpo_lens.danger import DangerFinding, danger_findings  # noqa: F401
from gpo_lens.dependencies import external_dependencies as external_dependencies
from gpo_lens.detection import (  # noqa: F401, I001
    AdmxGap,
    BrokenRef,
    CpasswordHit,
    DenyAce,
    ExcessiveWriter,
    SddlAce,
    SddlAcl,
    admx_gaps,
    broken_refs,
    cpassword_scan,
    dangling_links,
    deny_aces,
    disabled_but_populated,
    empty_gpos,
    enforced_links,
    excessive_writers,
    has_ms16_072_read,
    mask_cpassword,
    ms16_072_vulnerable,
    parse_sddl,
    scan_ilt,
    unlinked_gpos,
    version_skew,
)
from gpo_lens.queries._admx_coverage import (  # noqa: F401
    AdmxCoverageEntry,
    AdmxCoverageReport,
    AdmxCoverageSummary,
    admx_coverage,
)
from gpo_lens.queries._baseline import (  # noqa: F401
    BaselineDiffEntry,
    BaselineSetting,
    baseline_diff,
    load_baseline_from_estate,
)
from gpo_lens.queries._delegation import (  # noqa: F401
    DelegationAudit,
    DelegationRollupEntry,
    delegation_deep_dive,
    delegation_rollup,
    permissions_audit,
)
from gpo_lens.queries._doctor import DoctorFinding, estate_doctor  # noqa: F401
from gpo_lens.queries._golden import (  # noqa: F401
    GoldenDiffEntry,
    GoldenDiffSummary,
    golden_diff,
    golden_diff_summary,
)
from gpo_lens.queries._search import (  # noqa: F401
    Conflict,
    SearchResult,
    blocked_extensions,
    conflicts,
    search,
    who_sets,
)
from gpo_lens.queries._settings import (  # noqa: F401
    LedgerRow,
    SettingsDiffRow,
    SettingsDumpRow,
    settings_diff,
    settings_dump,
    settings_ledger,
)
from gpo_lens.queries._summary import EstateSummary, estate_summary  # noqa: F401
from gpo_lens.queries._topology import TopologyDiscrepancy, topology_crosscheck  # noqa: F401
from gpo_lens.queries._wmi import (  # noqa: F401
    BrokenWmiRef,
    broken_wmi_refs,
    orphaned_wmi_filters,
    stale_gpos,
)
from gpo_lens.snapshot_diff import (  # noqa: F401
    ChangelogEntry,
    GpoMetadataChange,
    SnapshotDiff,
    SnapshotSettingChange,
    VersionChangeLog,
    snapshot_changelog,
    snapshot_diff,
    snapshot_settings_diff,
)
from gpo_lens.topology import (  # noqa: F401
    EffectiveGpo,
    EffectiveScope,
    EffectiveSetting,
    GateSummary,
    SecurityFiltering,
    SiteGpoLink,
    SiteScope,
    SomConflict,
    WmiFilterScope,
    effective_scope,
    gate_summaries,
    has_site_links,
    is_security_filtered,
    loopback_awareness,
    loopback_gpos,
    precedence_conflicts,
    scope_caveats,
    security_filtering_detail,
    settings_at_som,
    site_scopes,
    som_conflicts,
    som_effective_gpos,
    wmi_filtered_gpos,
)

__all__ = [
    "external_dependencies",
    "AdmxCoverageEntry",
    "AdmxCoverageReport",
    "AdmxCoverageSummary",
    "AdmxGap",
    "BaselineDiffEntry",
    "BaselineSetting",
    "BrokenRef",
    "BrokenWmiRef",
    "CpasswordHit",
    "ChangelogEntry",
    "Conflict",
    "DelegationAudit",
    "DelegationRollupEntry",
    "DenyAce",
    "DangerFinding",
    "DoctorFinding",
    "EffectiveGpo",
    "EffectiveScope",
    "EffectiveSetting",
    "EstateSummary",
    "ExcessiveWriter",
    "GpoMetadataChange",
    "GateSummary",
    "GoldenDiffEntry",
    "GoldenDiffSummary",
    "LedgerRow",
    "SearchResult",
    "SecurityFiltering",
    "SettingsDiffRow",
    "SettingsDumpRow",
    "SiteGpoLink",
    "SiteScope",
    "SnapshotDiff",
    "SnapshotSettingChange",
    "SddlAce",
    "SddlAcl",
    "SomConflict",
    "TopologyDiscrepancy",
    "VersionChangeLog",
    "WmiFilterScope",
    "admx_coverage",
    "admx_gaps",
    "baseline_diff",
    "blocked_extensions",
    "broken_refs",
    "broken_wmi_refs",
    "conflicts",
    "cpassword_scan",
    "danger_findings",
    "dangling_links",
    "delegation_deep_dive",
    "delegation_rollup",
    "deny_aces",
    "disabled_but_populated",
    "effective_scope",
    "empty_gpos",
    "enforced_links",
    "gate_summaries",
    "golden_diff",
    "golden_diff_summary",
    "has_site_links",
    "estate_doctor",
    "estate_summary",
    "excessive_writers",
    "has_ms16_072_read",
    "is_security_filtered",
    "load_baseline_from_estate",
    "loopback_awareness",
    "loopback_gpos",
    "mask_cpassword",
    "ms16_072_vulnerable",
    "orphaned_wmi_filters",
    "parse_sddl",
    "permissions_audit",
    "precedence_conflicts",
    "scope_caveats",
    "search",
    "security_filtering_detail",
    "settings_at_som",
    "settings_diff",
    "settings_dump",
    "settings_ledger",
    "site_scopes",
    "snapshot_changelog",
    "snapshot_diff",
    "snapshot_settings_diff",
    "som_conflicts",
    "som_effective_gpos",
    "stale_gpos",
    "topology_crosscheck",
    "unlinked_gpos",
    "version_skew",
    "who_sets",
    "wmi_filtered_gpos",
]
