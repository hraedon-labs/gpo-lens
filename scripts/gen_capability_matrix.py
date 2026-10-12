"""Generate docs/capability-matrix.md from the code it describes.

Every table row is derived from, or checked against, a code registry:

* finding detectors: ``gpo_lens.findings.INTRINSIC_DETECTOR_VERSIONS`` (the
  registry of every executed intrinsic check), with a one-line description
  below that must exist for every key and only for existing keys;
* setting-value danger rules: the shipped ``danger_rules.toml`` via
  ``gpo_lens.danger.load_danger_rules``;
* per-CSE resolution mode: ``gpo_lens.merge.cse_merge_mode`` evaluated on the
  CSE names in ``CSE_ROWS``;
* GPP SYSVOL files scanned: ``gpo_lens.detection._gpp._GPP_XML_FILES``.

The prose and the per-CSE parser column are curated here, next to the code
facts; ``tests/test_capability_matrix.py`` fails if the committed file differs
from this output, if a detector or parser exists without a row, or if a row
names a detector, parser or CSE that the code does not have.

Usage: python scripts/gen_capability_matrix.py [--check]
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "docs" / "capability-matrix.md"

# One line per INTRINSIC_DETECTOR_VERSIONS key: what the finding flags.
DETECTOR_DESCRIPTIONS: dict[str, str] = {
    "coverage_gap": (
        "GPO missing from the export versus `gpo-inventory.json`, a "
        "`collection-errors.json` entry, missing SYSVOL (GPP/cpassword detectors "
        "blind), or an unreadable Preferences subtree"
    ),
    "cpassword": "`cpassword` attribute in a known GPP XML file in collected SYSVOL (MS14-025)",
    "ms16_072": "GPO without Authenticated Users / Domain Computers Read (MS16-072)",
    "version_skew": "AD (GPC) and SYSVOL (GPT) version counters disagree for a side",
    "dangling_link": "Link to a GPO that is not in the export",
    "topology_discrepancy": (
        "`ou-tree.json` and `gp-inheritance.json` disagree (block-inheritance mismatch, "
        "OU missing from SOMs, unparseable gPLink)"
    ),
    "disabled_but_populated": "A disabled side (Computer/User) still carries settings",
    "broken_ref:*": (
        "Malformed path, or a script / scheduled-task path / GPP file reference "
        "missing from the GPO's own collected SYSVOL (`malformed_path`, "
        "`missing_script`, `scheduled_task_path`, `gpp_file_ref`); external UNC "
        "and machine-local paths are inventoried, never flagged"
    ),
    "admx_gap": "Registry settings without a loaded ADMX template (one finding per GPO)",
    "unlinked": "GPO with no links (applies nowhere)",
    "empty": "GPO with no readable settings on either side",
    "enforced_link": "Enforced (No Override) link",
    "deny_ace": "Deny ACE on a GPO",
    "excessive_writer": "Non-default trustee with write access to 5 or more GPOs",
    "broken_wmi_ref": "GPO references a WMI filter that is not in the export",
    "orphaned_wmi_filter": "WMI filter no GPO references",
    "ilt_gpo": "Item-level targeting (`<Filters>`) in GPP XML; flagged, never evaluated",
    "stale_gpo": "Linked GPO last modified more than 2 years ago",
    "audit_source_disagreement": "Duplicate Advanced Audit subcategory values disagree",
    "audit_parse_warning": "Advanced Audit evidence the parser could not fully classify",
    "pki_parse_warning": "Public Key evidence the parser could not fully classify",
    "legacy_extension": "Deprecated Internet Explorer Maintenance extension (informational)",
    "danger:gpo_owner_nonadmin": "GPO owned by a non-admin trustee",
    "danger:gpo_writable_nonadmin": "GPO writable by a non-admin trustee",
    "danger:local_admin_push": "GPO pushes local Administrators membership",
    "danger:overbroad_apply_gp": "Apply Group Policy granted to Everyone / Anonymous",
    "danger:audit_subcategory_override": (
        "Advanced Audit subcategories authored without the force-subcategory "
        "option in the same GPO (authoring caveat; not a device-level claim)"
    ),
    "danger:setting_rules": "Setting-value rules from `danger_rules.toml` (next table)",
}


@dataclass(frozen=True)
class CseRow:
    # The <ExtensionData><Name> text. tests/test_capability_matrix.py requires
    # each name to occur in a synthetic fixture report or in a name set the code
    # matches, so no row describes a CSE name the tool has never been shown.
    name: str
    parsers: tuple[str, ...]  # gpo_lens.ingest functions that build its settings
    parsing: str


_GPP = ("_parse_gpp_container",)
CSE_ROWS: tuple[CseRow, ...] = (
    CseRow(
        "Registry",
        (
            "_parse_admin_template_policy",
            "_parse_classic_registry_setting",
            "_parse_registry_setting",
            "_parse_gpp_registry",
            "augment_blocked_registry_from_pol",
        ),
        "Administrative Template policies and registry values by `key:value` identity; "
        "ADMX/ADML names when templates are loaded; a `<Blocked/>` extension is resolved "
        "from a collected `Registry.pol`",
    ),
    CseRow(
        "Security",
        ("_parse_security_setting",),
        "Account policies, user rights, security options, restricted groups and other "
        "security-template entries",
    ),
    CseRow(
        "Advanced Audit Configuration",
        ("_parse_audit_setting", "augment_audit_from_csv"),
        "Subcategory GUID identities and named audit values, reconciled with a copied "
        "`audit.csv`; disagreements and unclassified evidence stay visible",
    ),
    CseRow(
        "Public Key",
        ("_parse_public_key",),
        "EFS, root certificate trust, autoenrollment, path validation and certificate "
        "entries; unrecognized structures are kept as `blocked` evidence",
    ),
    CseRow(
        "Folder Redirection",
        ("_parse_folder_redirection",),
        "One setting per redirected folder",
    ),
    CseRow("Scripts", ("_parse_generic_setting",), "Generic element parse"),
    CseRow("Software Installation", ("_parse_generic_setting",), "Generic element parse"),
    CseRow("Drive Maps", _GPP, "One setting per GPP item"),
    CseRow("Printers", _GPP, "One setting per GPP item"),
    CseRow("Scheduled Tasks", _GPP, "One setting per GPP item"),
    CseRow("Files", _GPP, "One setting per GPP item"),
    CseRow("Folders", _GPP, "One setting per GPP item"),
    CseRow("Services", _GPP, "One setting per GPP item"),
    CseRow(
        "Internet Explorer Maintenance",
        ("_readable_identity",),
        "Kept as `legacy_deprecated` evidence with an informational note",
    ),
    CseRow("Wireless", ("_parse_generic_setting",), "Generic element parse"),
    CseRow(
        "(any other CSE)",
        ("_parse_generic_setting",),
        "Generic element parse with a readable identity; a non-Registry `<Blocked/>` "
        "extension stays opaque and is flagged",
    ),
)

# Collector inputs read by gpo_lens.ingest.load_estate, and the function that
# reads each. The test requires every file literal in load_estate to have a row.
INPUT_ROWS: tuple[tuple[str, str, str], ...] = (
    ("AllGPOs.xml", "parse_report", "Required; missing or unparseable fails the ingest"),
    ("gp-inheritance.json", "parse_inheritance", "Optional"),
    ("sites.json", "parse_sites", "Optional; adds `site` SOMs"),
    ("gpo-metadata.json", "merge_metadata", "Optional"),
    (
        "SYSVOL-Policies/ (or SYSVOL/Policies/)",
        "attach_sysvol_paths",
        "Optional; absence is a `coverage_gap` (GPP/cpassword detectors blind)",
    ),
    ("Machine|User/Registry.pol in SYSVOL", "augment_blocked_registry_from_pol", "Optional"),
    ("Machine/.../Audit/audit.csv in SYSVOL", "augment_audit_from_csv", "Optional"),
    ("wmi-filters.json", "parse_wmi_filters", "Optional"),
    ("ou-tree.json", "parse_ou_tree", "Optional"),
    (
        "gpo-inventory.json, collection-errors.json",
        "parse_coverage_gaps",
        "Optional; drive `coverage_gap` reconciliation",
    ),
    ("principals.json", "parse_principals", "Optional"),
    ("group-members.json", "parse_group_members", "Optional"),
)

_MODE_MEANING = {
    "last_writer_wins": "resolved: highest-precedence GPO wins per identity",
    "union": "resolved: all GPOs' entries apply",
    "authoritative_replace": "resolved: the winning GPO's list replaces others",
    "additive": "resolved: memberships add",
    "accumulate": "resolved: entries accumulate across GPOs",
    "single_winner": "resolved: one GPO's policy object wins",
    "merge_replace_flag": "resolved per setting flag (merge vs. replace)",
    "approximate": (
        "**approximate**: precedence order applied and the row marked `approximate`; "
        "no CSE-specific rule"
    ),
}

_HEADER = """\
# Capability matrix

<!-- Generated by scripts/gen_capability_matrix.py from the code registries it
names. Do not edit by hand: change the code or the curated rows in that script,
then run `python scripts/gen_capability_matrix.py`. tests/test_capability_matrix.py
fails when this file is stale. -->

What gpo-lens does with each part of a collected estate. The verbs are used
strictly:

- **Parses** — ingest turns the input into normalized `Setting` rows that
  search, ledgers, exports, diffs and baseline/golden comparison use.
- **Flags** — a detector raises a finding (Findings inbox, `doctor`).
- **Resolves** — the OU-level resultant and principal resultant merge settings
  across the precedence chain with a defined per-CSE rule. Resolution is over
  *collected inputs at OU level*; it is never live RSoP.
- **Does not support** — listed at the end; nothing here simulates it.
"""

_UNSUPPORTED = """\
## Does not support

From the README "Limits" and the "Flag, don't simulate" rule in `AGENTS.md`:

- **Live or per-object RSoP.** WMI filter truth, item-level targeting and
  loopback runtime behavior are flagged as caveats, never evaluated. The tool
  does not observe what a Windows client applied.
- **Per-machine site membership.** Site-linked GPOs are captured as `site`
  SOMs and flagged; subnet/site resolution per machine is not done, and site
  GPOs are excluded from OU precedence views.
- **More than one estate per database.** Multi-domain, multi-forest and
  cross-estate comparison are not supported.
- **Opaque `<Blocked/>` extensions other than Registry.** They remain flagged
  as blocked.
- **Collection the collector account cannot see.** Coverage is bounded by the
  export; reconciliation needs the authoritative `gpo-inventory.json` supplied
  with that export.
- **External reachability.** UNC and machine-local paths are inventoried
  (Explore → dependencies) but never contacted or verified.
"""


def _escape(text: str) -> str:
    return text.replace("|", "\\|")


def render() -> str:
    """Return the full Markdown document. Raises ValueError on registry drift."""
    from gpo_lens.danger import load_danger_rules
    from gpo_lens.detection._gpp import _GPP_XML_FILES
    from gpo_lens.findings import INTRINSIC_DETECTOR_VERSIONS
    from gpo_lens.merge import cse_merge_mode

    registry = set(INTRINSIC_DETECTOR_VERSIONS)
    described = set(DETECTOR_DESCRIPTIONS)
    if registry != described:
        raise ValueError(
            "DETECTOR_DESCRIPTIONS drifted from INTRINSIC_DETECTOR_VERSIONS: "
            f"undescribed {sorted(registry - described)}, stale {sorted(described - registry)}"
        )

    out = [_HEADER]
    out.append("## Flags: finding detectors\n")
    out.append(
        "Source: `gpo_lens.findings.INTRINSIC_DETECTOR_VERSIONS`, the registry of every "
        "executed intrinsic check (findings are emitted by `queries.estate_doctor` and "
        "`danger.danger_findings`).\n"
    )
    out.append("| Finding category | Detector version | What it flags |")
    out.append("|------------------|------------------|---------------|")
    for key in sorted(INTRINSIC_DETECTOR_VERSIONS):
        version = INTRINSIC_DETECTOR_VERSIONS[key]
        out.append(f"| `{key}` | {version} | {_escape(DETECTOR_DESCRIPTIONS[key])} |")
    out.append("")

    out.append("## Flags: setting-value danger rules\n")
    out.append(
        "Source: the shipped `src/gpo_lens/danger_rules.toml` (finding category "
        "`danger:<id>`). `GPO_LENS_DANGER_RULES_DIR` can add or override rules at "
        "run time; those are not listed here.\n"
    )
    out.append("| Rule id | Severity | Side | Registry identity | Title | Reference |")
    out.append("|---------|----------|------|-------------------|-------|-----------|")
    for rule in sorted(load_danger_rules(), key=lambda r: r.id):
        out.append(
            f"| `{rule.id}` | {rule.severity} | {rule.applies} | `{_escape(rule.identity)}` "
            f"| {_escape(rule.title)} | <{rule.reference}> |"
        )
    out.append("")

    out.append("## Parses: collector inputs\n")
    out.append(
        "Source: `gpo_lens.ingest.load_estate`. An optional JSON input that is absent "
        "or unparseable is skipped with a Python warning (`_try_load`), not a finding; "
        "only the inputs noted below create `coverage_gap` findings.\n"
    )
    out.append("| Input | Reader (`gpo_lens.ingest`) | Notes |")
    out.append("|-------|----------------------------|-------|")
    for name, reader, note in INPUT_ROWS:
        out.append(f"| `{_escape(name)}` | `{reader}` | {_escape(note)} |")
    out.append("")

    out.append("## Parses and resolves: client-side extensions\n")
    out.append(
        "Every CSE in the GPMC report is parsed at least generically; the parser "
        "column names the `gpo_lens.ingest` functions that build its settings. The "
        "resolution column is `gpo_lens.merge.cse_merge_mode(<name>)` evaluated on the "
        "name exactly as listed. Some resolution modes depend "
        "on a per-setting flag (Restricted Groups members vs. member-of; Folder "
        "Redirection merge vs. replace).\n"
    )
    out.append("| CSE (report name) | Parsing | Parser functions | Resolution |")
    out.append("|-------------------|---------|------------------|------------|")
    for row in CSE_ROWS:
        mode = cse_merge_mode(row.name).value
        parsers = ", ".join(f"`{p}`" for p in row.parsers)
        out.append(
            f"| {_escape(row.name)} | {_escape(row.parsing)} | {parsers} | "
            f"`{mode}` — {_MODE_MEANING[mode]} |"
        )
    out.append("")

    out.append("## Parses: GPP XML files scanned in collected SYSVOL\n")
    out.append(
        "Source: `gpo_lens.detection._gpp._GPP_XML_FILES`. These files (under "
        "`Machine|User/Preferences/`, either nested per CSE or flat) feed the cpassword "
        "scan, the scheduled-task and local-group inventories (Explore), and broken "
        "reference checks; item-level targeting is detected in any Preferences XML. "
        "Without a SYSVOL copy these detectors are blind, which is itself a "
        "`coverage_gap` finding.\n"
    )
    out.append(", ".join(f"`{name}`" for name in _GPP_XML_FILES) + "\n")
    out.append(_UNSUPPORTED)
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate docs/capability-matrix.md")
    parser.add_argument("--check", action="store_true", help="fail if the file is stale")
    args = parser.parse_args(argv)
    text = render()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != text:
            print(f"{OUTPUT.relative_to(ROOT)} is stale; regenerate it.", file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
