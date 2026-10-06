"""Normalized data model for a Group Policy estate.

This is the contract. Implementations (ingest, store, queries) populate and read
these structures; their shape is fixed here so behavior specs in ``docs/spec/``
can reference concrete fields. See ``docs/tier1-normalized-model.md`` for the
mapping from collector outputs (GPO report XML, GPInheritance/metadata JSON,
SYSVOL) to these types, and the join-key normalization rules.

All GPO ids are *canonical*: lowercase, braces stripped (see
``normalize.canonical_guid``). Joins across report/topology/SYSVOL use that key.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol, TypedDict, runtime_checkable

Side = Literal["Computer", "User"]

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

SettingRaw = TypedDict(
    "SettingRaw",
    {
        "tag": str,
        "text": str,
        "@attr": dict[str, str],
        "children": list["SettingRaw"],
    },
    total=False,
)
"""Lossless dict representation of a CSE setting's XML element.

Produced by :func:`gpo_lens.ingest.element_to_dict` and stored as
``Setting.raw``.  All fields are optional (present only when the source
XML element has corresponding content).  The ``@attr`` key holds the
element's attributes; ``children`` is a recursive list of the same type.
"""


@dataclass(frozen=True)
class SddlAce:
    """One ACE parsed from an SDDL string."""

    ace_type: str  # "allow" | "deny"
    flags: str  # e.g. "CI", "OI", "CI_OI", ""
    rights: str  # e.g. "GA", "GR", "GW", "WD", "SD", "CC", "DC", "LC", "LO", "RP", "WP"
    object_guid: str  # usually ""
    inherit_object_guid: str  # usually ""
    trustee_sid: str  # SID string, e.g. "S-1-5-32-544"


@dataclass(frozen=True)
class SddlAcl:
    """Parsed SDDL descriptor."""

    owner_sid: str | None
    group_sid: str | None
    dacl: tuple[SddlAce, ...]
    sacl: tuple[SddlAce, ...]
    # ACL control flags preceding the ACE list, e.g. "PAI" from ``D:PAI(...)``.
    # "P" (protected) blocks inheritance from the parent container — a
    # posture-relevant signal the parser previously discarded.
    dacl_flags: str = ""
    sacl_flags: str = ""


@dataclass(frozen=True)
class DenyAce:
    """A deny ACE found in a GPO's SDDL."""

    gpo_id: str
    gpo_name: str
    trustee_sid: str
    rights: str
    flags: str
    acl_section: str
    trustee_name: str = ""


@dataclass(frozen=True)
class ExcessiveWriter:
    """A trustee with write access to many GPOs."""

    trustee_sid: str
    gpo_count: int
    gpo_names: tuple[str, ...]
    rights: tuple[str, ...]
    trustee_name: str = ""


@dataclass(frozen=True)
class GpoLink:
    """One ``GPO/LinksTo`` element — where a GPO is linked."""

    gpo_id: str
    som_name: str  # LinksTo/SOMName
    som_path: str  # LinksTo/SOMPath
    link_enabled: bool  # LinksTo/Enabled
    enforced: bool  # LinksTo/NoOverride  (this is the enforced flag)


@dataclass
class Setting:
    """One leaf setting inside ``<Side>/ExtensionData/Extension``.

    Each CSE (``cse``) has a different child schema, so ``raw`` preserves the
    CSE-specific subtree losslessly while ``display_*`` give a flattened
    projection used for search and conflict detection.
    """

    gpo_id: str
    side: Side
    cse: str  # ExtensionData/Name (e.g. "Registry", "Security")
    identity: str  # CSE-specific natural key (conflict identity)
    display_name: str
    display_value: str
    raw: dict[str, object]  # CSE-specific subtree (element_to_dict or registry_pol)
    from_disabled_side: bool  # side's Enabled=false but settings present
    source_state: str = "normal"  # "normal" | "blocked" (<Blocked/> extension)


@dataclass(frozen=True)
class DelegationEntry:
    """One trustee permission, parsed from ``SecurityDescriptor/Permissions``.

    Powers the delegation audit and the MS16-072 check (a GPO missing
    Authenticated Users / Domain Computers read/apply).
    """

    gpo_id: str
    trustee: str
    trustee_sid: str | None
    permission: str  # normalized label, e.g. "Apply Group Policy", "Read"
    allowed: bool


@dataclass
class Gpo:
    """One ``GPO`` element, enriched with metadata + SYSVOL path."""

    id: str  # canonical guid
    name: str
    domain: str
    created: datetime | None
    modified: datetime | None
    read: datetime | None
    computer_enabled: bool
    user_enabled: bool
    computer_ver_ds: int | None
    computer_ver_sysvol: int | None
    user_ver_ds: int | None
    user_ver_sysvol: int | None
    sddl: str | None
    owner: str | None
    filter_data_available: bool
    wmi_filter: str | None  # from gpo-metadata.json
    sysvol_path: str | None  # matched SYSVOL-Policies/{GUID} dir
    description: str | None = None  # <Description> from the report (admin's note)
    links: list[GpoLink] = field(default_factory=list)
    settings: list[Setting] = field(default_factory=list)
    delegation: list[DelegationEntry] = field(default_factory=list)

    @property
    def computer_version_skew(self) -> bool:
        # Unknown vs known is not skew.
        if self.computer_ver_ds is None or self.computer_ver_sysvol is None:
            return False
        return self.computer_ver_ds != self.computer_ver_sysvol

    @property
    def user_version_skew(self) -> bool:
        # Unknown vs known is not skew.
        if self.user_ver_ds is None or self.user_ver_sysvol is None:
            return False
        return self.user_ver_ds != self.user_ver_sysvol


@dataclass(frozen=True)
class SomLink:
    """One entry of a SOM's resolved, ordered, inheritance-aware GPO chain."""

    gpo_id: str
    order: int  # precedence order (platform-resolved)
    enabled: bool
    enforced: bool
    target: str  # DN the link originates from


@dataclass
class Som:
    """One scope-of-management node from the GPInheritance dump."""

    path: str
    name: str
    container_type: str
    inheritance_blocked: bool
    links: list[SomLink] = field(default_factory=list)


@dataclass(frozen=True)
class WmiFilter:
    """A WMI filter with its name and query text, from ``wmi-filters.json``."""

    name: str
    query: str


@dataclass(frozen=True)
class OuRecord:
    """One OU from the raw ``ou-tree.json`` (gPLink / gPOptions)."""

    dn: str
    name: str
    gp_link: str | None  # raw gPLink attribute (DN-list of GUIDs)
    gp_options: int | None  # gPOptions: 0=not blocked, 1=block inheritance


@dataclass(frozen=True)
class CoverageGap:
    """A GPO known to exist but missing from the collected export.

    ``kind`` is ``"inaccessible"`` (present in the authoritative inventory but
    not in the export — e.g. Authenticated Users Read stripped) or
    ``"collection_error"`` (the collector saw it but failed to pull its report).
    """

    gpo_id: str
    display_name: str | None
    kind: str
    detail: str


@dataclass(frozen=True)
class GroupMembership:
    """One group's membership as collected by the Plan 020-B collector.

    SIDs are canonical (lowercase). ``members`` is the direct membership list;
    transitive expansion is performed by :func:`gpo_lens.merge.build_token`.
    ``implicit`` is a note for well-known groups with no enumerable membership
    (e.g. Authenticated Users).
    """

    sid: str
    name: str
    members: tuple[str, ...]
    member_count: int
    implicit: str = ""


@dataclass(frozen=True)
class ResolvedPrincipal:
    """A SID resolved to a name, with the original SID always retained.

    The SID is the source of truth; the name is a point-in-time annotation
    (Plan 020, decision 2). ``resolved`` is ``False`` when no name could be
    found — in that case ``name`` carries the raw SID so a display surface is
    never blank (decision 3: unresolved is a result, not an error).
    """

    sid: str
    name: str
    sam: str
    principal_type: str  # "Group"|"User"|"Computer"|"WellKnown"|"Unresolved"
    domain: str  # NetBIOS/domain or ""
    resolved: bool  # False if no name could be found


@dataclass
class Estate:
    """The whole normalized estate for one domain snapshot."""

    domain: str = ""
    gpos: list[Gpo] = field(default_factory=list)
    soms: list[Som] = field(default_factory=list)
    wmi_filters: list[WmiFilter] = field(default_factory=list)
    ou_tree: list[OuRecord] = field(default_factory=list)
    coverage_gaps: list[CoverageGap] = field(default_factory=list)
    principals: dict[str, ResolvedPrincipal] = field(default_factory=dict)
    group_members: dict[str, GroupMembership] = field(default_factory=dict)
    _gpo_index: dict[str, Gpo] | None = field(default=None, repr=False, compare=False)

    @property
    def gpo_index(self) -> dict[str, Gpo]:
        """Lazy, cached ``{gpo_id: Gpo}`` index.

        Built on first access and reused for all subsequent lookups, eliminating
        the O(n) scan previously performed by ``gpo_by_id`` and the duplicated
        ``{g.id: g for g in estate.gpos}`` dicts that appeared across 5+ call
        sites. If ``gpos`` is mutated after first access the cache goes stale;
        callers that modify ``gpos`` should set ``_gpo_index = None`` to
        invalidate.

        Each GPO is indexed under both its stored ``id`` and a
        hyphen-stripped, lowercased form. This bridges DBs written before
        ``canonical_guid`` was changed to strip hyphens (cb21237): old
        estates stored IDs like ``31b2f340-016d-11d2-945f-00c04fb984f9``
        while the current canonical form is ``31b2f340016d11d2945f00c04fb984f9``.
        Without the dual key, a canonical-form URL lookup misses the
        hyphenated index key and returns 404.
        """
        if self._gpo_index is None:
            idx: dict[str, Gpo] = {}
            for g in self.gpos:
                if g.id in idx:
                    warnings.warn(
                        f"Duplicate GPO id '{g.id}': '{idx[g.id].name}' shadowed by '{g.name}'.",
                        stacklevel=2,
                    )
                idx[g.id] = g
                stripped = g.id.strip().strip("{}").strip().replace("-", "").lower()
                if stripped != g.id:
                    if stripped in idx:
                        warnings.warn(
                            f"GPO id collision in dual-key index: "
                            f"'{g.id}' and '{idx[stripped].id}' both map to "
                            f"stripped key '{stripped}'. The first GPO "
                            f"('{idx[stripped].name}') shadows the second "
                            f"('{g.name}').",
                            stacklevel=2,
                        )
                    else:
                        idx[stripped] = g
            self._gpo_index = idx
        return self._gpo_index

    @property
    def gpo_names(self) -> dict[str, str]:
        """``{gpo_id: gpo_name}`` map with stored and canonical ID keys."""
        return {gpo_id: g.name for gpo_id, g in self.gpo_index.items()}

    def gpo_by_id(self, gpo_id: str) -> Gpo | None:
        result = self.gpo_index.get(gpo_id)
        if result is None:
            stripped = gpo_id.strip().strip("{}").strip().replace("-", "").lower()
            if stripped != gpo_id:
                result = self.gpo_index.get(stripped)
        return result


@runtime_checkable
class AdmxResolver(Protocol):
    """Contract for ADMX display-name resolution (duck-typed previously).

    Any object with a ``resolve_display_name(identity, *, side=None) -> str | None``
    method satisfies this protocol — structural subtyping, no inheritance
    required. ``admx_parser.PolicyDefinitions`` is the canonical implementor.
    """

    def resolve_display_name(self, identity: str, *, side: Side | None = None) -> str | None: ...
