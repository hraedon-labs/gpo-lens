# Collector export format (on-disk input contract)

**Status:** draft (first formal capture of the de-facto format).
**Produced by:** `scripts/Export-GpoEstate.ps1` (PowerShell, read-only).
**Consumed by:** `src/gpo_lens/ingest.py` (`load_estate` and helpers).

This is the *input* contract: the on-disk layout the collector writes and the
parser reads. The JSON output contract (`docs/spec/json-contract.md`) is
separate and governs what gpo-lens emits downstream.

## Directory layout

```
<export-dir>/
├── AllGPOs.xml              UTF-8, combined Get-GPOReport -ReportType Xml -All
├── gpo-metadata.json        Per-GPO metadata (versions, SDDL, WMI filter names)
├── gp-inheritance.json      Per-SOM inheritance (block, enforced, precedence order)
├── ou-tree.json             Raw OU tree (gPLink / gPOptions attributes)
├── sites.json               AD site GPO links (gPLink / gPOptions from Config NC)
├── wmi-filters.json         WMI filter definitions (name + query text)
├── principals.json          SID -> name map for all SIDs in GPO SDDL (Plan 020)
├── group-members.json       Group SID -> member SIDs, transitive expansion (Plan 020-B)
├── collection-errors.json   GPOs that could not be collected (always present; may be `[]`)
├── gpo-inventory.json       Authoritative GPO list from privileged enumeration
├── reports/                 Per-GPO XML reports (UTF-16)
│   └── <SafeName>__<GUID>.xml
└── SYSVOL-Policies/         Copied SYSVOL policy file tree
    └── {<GUID>}/
        ├── gpreport.xml     Per-GPO XML report (UTF-16, from SYSVOL copy)
        ├── MACHINE/         (or "Machine" — casing varies; see below)
        │   ├── Registry.pol PReg binary format
        │   └── Preferences/
        │       ├── Groups/
        │       │   └── Groups.xml
        │       ├── ScheduledTasks/
        │       │   └── ScheduledTasks.xml
        │       ├── LocalUsersAndGroups/
        │       │   └── LocalUsersAndGroups.xml
        │       ├── DriveMaps/
        │       │   └── DriveMaps.xml
        │       └── ...
        └── USER/            (or "User" — casing varies; see below)
            ├── Registry.pol
            └── Preferences/
                └── ...
```

### Export directory naming

The collector names the export directory
`<DNS-domain>-<YYYYMMDD-HHmmss>` (e.g.
`workdomain.local-20260614-153000`). The parser does not depend on the name;
it finds files by well-known names relative to the supplied root.

## Per-CSE subfolder layout

On a real SYSVOL, each Group Policy Preferences CSE lives in its own
subfolder under `Preferences/`:

```
Preferences/
├── Groups/
│   └── Groups.xml
├── ScheduledTasks/
│   └── ScheduledTasks.xml
├── DriveMaps/
│   └── DriveMaps.xml
└── ...
```

This is the **canonical** (nested) shape produced by the collector, which
copies the SYSVOL tree verbatim.

Some hand-built or older exports flatten this structure:

```
Preferences/
├── Groups.xml
├── ScheduledTasks.xml
└── ...
```

The parser handles **both** shapes. It walks `Preferences/` one level deep and
collects XML files from direct children and from one level of subdirectories.
The implementation is `_walk_gpp_xml` in `src/gpo_lens/detection/_gpp.py`.

## Side-directory casing

Real SYSVOL uses **uppercase** `MACHINE` / `USER` for the default GPOs
(`{31B2F340-…}`, `{6AC1786C-…}`). Custom GPOs typically use title-case
`Machine` / `User`. Other casings are possible.

The analysis host is typically **Linux** (case-sensitive filesystem), so the
parser resolves side-directory names case-insensitively through
`paths.ci_child` and `paths.ci_path`. It tries the literal path first (the fast
path on case-insensitive hosts), then falls back to a case-insensitive
directory scan.

The GPO report XML (`AllGPOs.xml`, per-GPO `reports/*.xml`) uses the
canonical element names `<Computer>` and `<User>` regardless of SYSVOL casing.

## File inventory

| File | Format | Source | Purpose |
|------|--------|--------|---------|
| `AllGPOs.xml` | XML, UTF-8 | `Get-GPOReport -All -ReportType Xml` | Combined GPO settings, delegation, links |
| `reports/<name>__<guid>.xml` | XML, UTF-16 | `Get-GPOReport -Guid <id> -ReportType Xml` | Per-GPO report; used by baseline-zip loader, not by `load_estate` (which reads `AllGPOs.xml`) |
| `gpo-metadata.json` | JSON, UTF-8 (may have BOM) | `Get-GPO -All` piped to `Select-Object` | Version skew (DS vs SYSVOL), WMI filter name, timestamps |
| `gp-inheritance.json` | JSON, UTF-8 (may have BOM) | `Get-GPInheritance` per SOM | SOM chain: block, enforced, precedence order |
| `ou-tree.json` | JSON, UTF-8 (may have BOM) | `Get-ADOrganizationalUnit` with `gPLink`/`gPOptions` | Raw gPLink attribute for topology cross-check |
| `sites.json` | JSON, UTF-8 (may have BOM) | `Get-ADObject` from Config NC | AD site GPO links (parallel scoping axis) |
| `wmi-filters.json` | JSON, UTF-8 (may have BOM) | `Get-ADObject -Filter "objectClass -eq 'msWMI-Som'"` | WMI filter name + query text |
| `principals.json` | JSON, UTF-8 (may have BOM) | SID resolution from SDDL + `Get-ADObject` | SID -> name/type/sam/domain map; optional (Plan 020) |
| `group-members.json` | JSON, UTF-8 (may have BOM) | `Get-ADGroupMember -Recursive` | Group SID -> member SIDs (transitive); optional (Plan 020-B) |
| `collection-errors.json` | JSON, UTF-8 (may have BOM) | Collector error accumulation | GPOs that could not be read; always present (may be `[]`) |
| `gpo-inventory.json` | JSON, UTF-8 (may have BOM) | `Get-ADObject` from Policies container | Authoritative GPC GUID list; produced by privileged run |
| `SYSVOL-Policies/` | Directory tree | `Copy-Item -Recurse` from `\\domain\SYSVOL\domain\Policies` | Raw policy files (Registry.pol, GPP XML, gpreport.xml) |

### Required vs optional files

`AllGPOs.xml` is the **only required** file; without it `load_estate` raises
`FileNotFoundError`. All other files are optional. The parser skips missing
files silently and uses defaults (empty lists, no metadata, no SYSVOL
augmentation), so partial exports (a SYSVOL-only copy, or an export from a
machine without RSAT) still produce useful results.

### principals.json format (Plan 020)

SID -> name map. SIDs are canonical (lowercase). Written by the collector's
principals section (integrated in v0.6.2) or the standalone
`Export-Principals.ps1`.

```json
{
  "collected": "2026-06-19T15:30:00Z",
  "domain": "workdomain.local",
  "principals": {
    "s-1-5-21-1234567890-1234567890-1234567890-1000": {
      "name": "WORKDOMAIN\\GPO-Admins",
      "sam": "GPO-Admins",
      "type": "Group",
      "domain": "WORKDOMAIN"
    },
    "s-1-5-11": {
      "name": "Authenticated Users",
      "sam": "Authenticated Users",
      "type": "WellKnown",
      "domain": ""
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `name` | Resolved display name (DOMAIN\sam or UPN). Raw SID if unresolved. |
| `sam` | sAMAccountName (or name for well-known SIDs). |
| `type` | `"Group"`, `"User"`, `"Computer"`, `"WellKnown"`, or `"Unresolved"`. |
| `domain` | NetBIOS domain name (or empty for well-known SIDs). |

### group-members.json format (Plan 020-B)

Transitive group membership. Written by the collector's group membership
section (integrated in v0.6.2) or the standalone `Export-GroupMembers.ps1`.

```json
{
  "collected": "2026-06-19T15:30:00Z",
  "domain": "workdomain.local",
  "groups": {
    "s-1-5-21-1234567890-1234567890-1234567890-1000": {
      "name": "WORKDOMAIN\\GPO-Admins",
      "members": [
        "s-1-5-21-1234567890-1234567890-1234567890-1100",
        "s-1-5-21-1234567890-1234567890-1234567890-1101"
      ],
      "member_count": 2
    },
    "s-1-5-11": {
      "name": "Authenticated Users",
      "members": [],
      "member_count": 0,
      "implicit": "All authenticated domain principals (users + computers)"
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `name` | Group display name. |
| `members` | Array of member SIDs (transitive expansion, canonical lowercase). |
| `member_count` | Count of transitive members. |
| `implicit` | Present for well-known groups with no enumerable membership. |

## Encoding

| File | Encoding | Parser handling |
|------|----------|-----------------|
| `AllGPOs.xml` | UTF-8 | Parsed directly by `defusedxml`; no BOM stripping needed |
| Per-GPO `gpreport.xml` (SYSVOL) | UTF-16 (PowerShell 5.1 default) | `parse_report_xml` detects BOM (`FF FE` / `FE FF`) and decodes as UTF-16 |
| All `.json` files | UTF-8, **may carry UTF-8 BOM** (`EF BB BF`) | `normalize.load_json` uses `utf-8-sig` encoding, which transparently strips BOM |
| `Registry.pol` | PReg binary format | `registry_pol.parse_registry_pol` reads raw bytes |

**BOM tolerance is mandatory.** PowerShell 5.1's `Set-Content -Encoding UTF8`
prepends a UTF-8 BOM. `build_fixture.py` deliberately writes a BOM on
`ou-tree.json` and `sites.json` so the parser is tested against it.

## Zip handling

When the collector is run without `-NoZip`, it produces a `.zip` archive of
the export directory. Key properties:

- **Forward-slash separators.** The collector replaces backslashes with forward
  slashes in zip entry names, so the archive extracts cleanly on Linux.
- **File-only entries.** The collector adds files only, with no directory
  entries. This avoids the missing-traversal-bit problem that `Compress-Archive`
  on PowerShell 5.1 can produce.
- **Zip-slip protection.** Extraction (`src/gpo_lens/collection_zip.py`)
  normalizes entry paths, including backslashes, and rejects any entry that
  would land outside the target directory. It also rejects symlinks, duplicate
  paths and excessive compression ratios.
- **Decompression-bomb guard.** `_streaming_zip_read` in `ingest.py` enforces a
  2 GB decompressed-size cap during streaming reads, which stops zip bombs that
  spoof `info.file_size` headers. `collection_zip.py` applies the same 2 GB cap
  to extraction.

## Permissions and unreadable subtrees

The SYSVOL copy preserves Windows ACLs. On a Linux analysis host:

- An **unreadable directory** (e.g. a security-filtered GPO whose folder the
  collector account cannot enter) produces a `collection-errors.json` entry
  with `Stage: sysvol`.
- The parser never crashes on an unreadable subtree: `ci_child` returns `None`
  on `OSError`, and `_walk_gpp_xml` catches `OSError` per entry.
- Missing SYSVOL data surfaces as a `coverage_gap` finding (kind
  `"inaccessible"` or `"collection_error"`), never silently dropped.

### Zip extraction and lost traversal bits (common gotcha)

Windows-produced zips extracted on Linux with `unzip` may **lose the execute
(traversal) bit** on `Preferences/` subdirectories. All GPP content
(Groups.xml, ScheduledTasks.xml, Drives.xml, etc.) then becomes invisible, with
no crash or error from the extractor.

The parser detects this and raises a `coverage_gap` finding with
`kind: "unreadable_sysvol"`, which includes the fix:

```bash
chmod -R +rX SYSVOL-Policies/
```

If you see `unreadable_sysvol` coverage gaps after extraction, run that command
and re-run the analysis. This is the most common cause of "the tool found zero
GPP settings on a known-active estate."

## GPO ID normalization

All GPO IDs are **canonical**: lowercase, braces stripped. The parser applies
`normalize.canonical_guid` to every ID read from XML, JSON and gPLink
attributes, and joins across inputs (report, metadata, SYSVOL, inheritance) on
that key.

## SYSVOL path matching

The parser matches each GPO to its SYSVOL folder by trying, in order:

1. `SYSVOL-Policies/{<UPPER-CASE-GUID>}` (brace-wrapped, upper-case — the
   SYSVOL convention)
2. `SYSVOL-Policies/<canonical-id>` (lowercase, no braces)
3. `SYSVOL-Policies/<CANONICAL-ID>` (upper-case, no braces)

The first match that resolves inside the SYSVOL base directory wins. A path that
escapes the base (symlink attacks) is rejected.

## Versioning (proposed)

The current format has no version indicator (no `format_version` exists in the
code). To support future collector changes without breaking the parser, add a
`format_version` field to `gpo-metadata.json` or a new `manifest.json` at the
export root.

Proposed schema:

```json
{
  "format_version": 1,
  "collector": "Export-GpoEstate.ps1",
  "collected_at": "2026-06-14T15:30:00Z",
  "domain": "workdomain.local"
}
```

The parser would read this field and adjust. Version 0 (field absent) is the
current format; incrementing `format_version` signals a breaking change to the
on-disk layout.

Until then, the parser infers the format from which well-known files are
present. That is sufficient but fragile. Adding the field is a low-risk change
that should ship with the next collector revision.
