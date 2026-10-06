# F1: Advanced audit and Public Key report extensions

Inputs are copied GPO reports and copied SYSVOL only. These parsers make no
network calls, write no inputs, add no runtime dependencies and infer no
per-machine resultant policy.

## Normalization

- `AuditSetting` is recognized by its local XML element name, regardless of
  namespace prefix. System audit identities are `canonical_guid(SubcategoryGuid)`
  (lowercase, braces and hyphens removed, matching the existing GUID helper).
  Display names use `SubcategoryName`, with the GUID as a fallback. `SettingValue`
  maps exactly: 0 = No Auditing, 1 = Success, 2 = Failure, 3 = Success and Failure.
  Names and values never participate in the identity. Report side and disabled
  state are retained; ordinary reports put these settings on Computer.
- Per-user targets use `guid:PolicyTarget` to avoid colliding with system settings.
  Their numeric flags are preserved with a caveat, without interpreting exclusions
  or claiming object-level RSoP. Unknown or missing targets, invalid GUIDs or
  system values become blocked
  evidence with a doctor note, rather than No Auditing or a comparable value.
- Public Key singleton policies expand into scalar settings with schema-path
  identities, such as `EFSSettings:KeyLen` and
  `RootCertificateSettings:RequireUPNNamingConstraints`. EFS and root trust fields
  have explicit friendly labels. Autoenrollment, certificate trust and path
  validation groups expose their scalar fields using readable labels; numeric
  flags are retained as numbers, without inventing enum meanings.
- Certificate entries use the store plus normalized thumbprint (or issuer and
  serial number). Subject names never define certificate identity. Entries with
  no stable key remain blocked evidence. Scalar rows preserve the entire policy
  group's XML, including attributes, and their property path. Unrecognized PKI
  shapes retain blocked raw evidence and an explicit source note.
- Internet Explorer Maintenance keeps its existing readable projection, with
  `source_state="legacy_deprecated"` and an informational source note. There is
  no new IEM parser. Microsoft documents its [deprecation and lack of support in
  IE 10 and newer](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-it-pro/internet-explorer-11/ie11-deploy-guide/missing-internet-explorer-maintenance-settings-for-ie11).

## Audit CSV reconciliation

`augment_audit_from_csv(gpos)` reads
`Machine/Microsoft/Windows NT/Audit/audit.csv` below each attached policy folder.
Path lookup is case-insensitive; paths resolving outside that folder are refused.
UTF-8 (including BOM) and BOM-marked UTF-16 are supported. The Windows CSV column
names are used; quoted fields are handled by the stdlib CSV parser. The same GUID,
policy-target and value normalization is used for XML and CSV.

Matching rows add raw CSV evidence to the XML setting, without adding duplicate
settings. The XML display value is retained on disagreement. CSV-only entries
become first-class Computer settings, retaining disabled-side state. When XML
contains audit subcategories, membership differences in either direction are
flagged. Duplicate CSV rows retain every row; differing values are flagged and
the first value is retained. Duplicate XML subcategories keep one GUID identity
and all duplicate evidence, flagging conflicting values. Missing CSV is optional,
with no disagreement claim.
Unreadable files, malformed rows, audit options and global SACL rows remain
visible blocked evidence. Those last two structures share the CSV transport but
are outside this subcategory parser's scope.

CSV format and per-user flag semantics are described in Microsoft's
[Audit Configuration Extension specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/10d91136-2d82-46b9-9677-cf4d47ba2261).

## Findings and presentation

Doctor emits observed source disagreements, parse warnings and one informational
IEM finding per GPO. Their identity dimensions use side and setting identity,
never prose. Source notes are also carried by the existing ledger, dossier and
Markdown/CSV export pipeline. Existing search, OU chain folding, baseline,
golden-backup and snapshot comparison consume the normalized settings unchanged.
The new settings retain the existing OU-level scope limitations and merge caveats.

`audit_subcategory_override(estate)` contributes a low-severity danger/doctor
finding when an enabled Computer side authors valid system audit subcategories
without enabling `SCENoApplyLegacyAuditPolicy` in the same GPO. It recognizes
SecurityOptions and concrete registry forms at the exact LSA path. User-side,
disabled, blocked, unrelated-path and delete-action entries do not establish
that option. Conflicting values do not count as enabled. The description cites
[Microsoft's force-subcategory security option documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/audit-force-audit-policy-subcategory-settings-to-override).
It explicitly states that another GPO or device default may enable the option;
it does not claim auditing is ineffective, absent or insecure on a device.

## Storage and compatibility

No SQLite schema or model migration is needed: existing `Setting.identity`,
`display_*`, `source_state` and JSON `raw` fields store the normalization and
reconciliation evidence. `LedgerRow.source_note` is an additive query projection.
Released database fixtures still open, upgrade and accept the new settings.
Previously ingested snapshots retain their original parser output; ingest the
copied input again to obtain the new identities. Nothing rewrites historical
snapshots or live policy.

Synthetic report/CSV fixtures and the PKI golden projection live in
`tests/fixtures/cse_audit_pki/`. Tests cover values, localization-independent keys,
encodings, partial/malformed inputs, evidence preservation, disabled sides,
registry option matching, differences, OU precedence, old databases, safe web
rendering and deterministic authorized exports. Mutation checks deliberately
break value mapping, GUID identities, XML retention, disagreement detection,
exact option paths, enabled-value detection and disabled-side exclusion; each
must be killed by the focused tests before the final CI gates are run.
