# gpo-lens

Local-first, read-only Group Policy analysis. Ingests copies of a GPO estate
(never touches live AD) and answers questions about it. The deterministic core
has no AI in the truth path — the LLM layer only narrates facts the core
already computed.

## Quick start

```powershell
# On a DC or RSAT box, export the estate (read-only, no changes):
scripts/Export-GpoEstate.ps1 -OutputRoot C:\GpoExport
```

```bash
# Copy the export to your analysis machine, then:
gpo-lens ingest C:\GpoExport
gpo-lens doctor
# Optional: set GPO_LENS_API_KEY for AI narration (ask, doctor --explain). Without it, narration silently degrades to raw deterministic output.
```

## What it does

- **Tier 1 — Hygiene scans.** cpassword detection, MS16-072 traps, version
  skew, broken references, unlinked and empty GPOs, disabled-but-populated
  sides.
- **Tier 2 — Baseline comparison.** Diff your estate against a Microsoft
  Security Baseline (shipped as GPO backups). ADMX crosswalk resolves registry
  paths back to policy names.
- **Tier 2.5 — OU-level topology.** Per-OU settings-at-SOM, precedence
  ordering, conflict surface (same setting, different values). Flags loopback
  but does not simulate per-user RSoP.
- **Tier 3 — AI narration (optional).** `doctor --explain` and natural-language
  `ask` command. Narrates verified facts only; never the source of truth.
  Requires `GPO_LENS_API_KEY`; degrades gracefully without it.

## Install

```bash
uv pip install -e .
# or
pip install -e .
```

## Key commands

| Command | What it does |
|---------|-------------|
| `doctor` | Prioritized health findings |
| `doctor --explain` | AI-powered explanation of findings |
| `ask "..."` | Natural-language GPO question |
| `summary` | Estate overview |
| `ingest <path>` | Parse collector output into DB |
| `baseline-diff` | Compare against MS baseline |
| `diff` | Full snapshot diff |
| `diff-settings` | Per-setting snapshot diff |
| `changelog` | Version-aware change log |
| `report --output report.html --format html` | Export audit-ready HTML report |
| `repl` | Interactive Python REPL with the estate loaded |
| `settings-at <som>` | Effective settings at a SOM path |
| `loopback` | GPOs that configure loopback processing |
| `wmi` | GPOs with WMI filters attached |
| `wmi-filters` | List WMI filters with query text |
| `sites` | AD sites and their GPO links (lowest precedence; not resolved per-machine) |
| `broken-refs` | Detect broken references in settings |
| `admx-gaps` | Settings with raw key paths (no ADMX policy name) |
| `gpp-tasks` | Inventory of scheduled tasks deployed by GPO |
| `gpp-groups` | Local-group membership changes deployed by GPO |
| `topology-check` | Cross-check OU tree against inheritance |
| `delegation` | Delegation deep-dive audit |
| `danger` | Dangerous-configuration detectors |
| `resultant` | Per-principal resultant view |

## Machine-readable output

Add the global `--json` flag to emit a stable, versioned envelope on stdout:

```bash
gpo-lens --json doctor | jq '.data.findings[] | select(.severity=="critical")'
```

Every `--json` payload is wrapped as `{schema_version, kind, tool_version,
generated_at, data}`, so downstream tools can depend on the shape and detect
contract evolution. Errors go to stderr with a nonzero exit (stdout stays clean
JSON); `report` is human-format only and refuses `--json` (use `summary --json`
for the machine-readable snapshot). The frozen shapes — and which sibling tools
consume them — are documented in
[`docs/spec/json-contract.md`](docs/spec/json-contract.md) and pinned by
`tests/test_json_contract.py`.

## Design principles

- **Deterministic core.** No AI in the truth path. Parse, normalize, query —
  all pure and verifiable.
- **Read-only.** Never touches live AD. Input is file copies only.
- **Minimal runtime dependencies.** The core CLI depends only on `defusedxml`
  (XML bomb protection) beyond the standard library — portable and
  air-gappable. The web UI is an optional extra (`pip install -e ".[web]"`).
- **Air-gappable.** No network required for core features.
- **Flag, don't simulate.** Topology resolution is OU-level; never claims
  object-level RSoP (no per-user security/WMI/loopback evaluation). Scoping
  mechanisms (loopback, security filtering, WMI filters, item-level targeting)
  are flagged with caveats, not simulated.

## Web navigation and optional explanations

The web UI starts with Briefing / Findings / Explore / History / Tools.
Explore and Tools retain the specialist workbenches; existing URLs and their
filters keep their meaning. The compact search box searches configured settings
through `/search`. Tools includes a complete route reference.

For a staged rollout, set `GPO_LENS_LEGACY_NAV=1` before starting the server to
restore the old primary links (Ask remains under Tools). Unset it and restart to
return to the new default. This controls presentation only; see the
[IIS deployment guide](deploy/iis/README.md) for the unchanged access model.

With `GPO_LENS_API_KEY` configured, dossiers, OU details, finding histories and
comparison results offer **Explain these facts** in a separate tab. Only bounded
page counts, fixed scope caveats, and snapshot/analysis provenance are sent.
Names, values, raw evidence and HTML are excluded. The model selects computed
fact IDs; the server rejects additional claims and renders the corresponding
facts. Without a key, these actions are absent. Explanations never run during
page loading. Signed forms expire after an hour or a server restart; reload the
original page if needed. Ask remains a separate Tools workbench: it routes the user question to a
deterministic query and offers the same checked explain action over result
counts. Query results and raw evidence are never sent to narration.

## Requirements

- Python 3.12+
- The collector (`scripts/Export-GpoEstate.ps1`) requires Windows with the
  `GroupPolicy` and `ActiveDirectory` RSAT modules (a DC or RSAT-equipped host).

## Limits

- **Single-domain estates.** The `Estate` model holds one domain's GPOs, SOMs,
  and WMI filters. Multi-domain or multi-forest estates are not supported.
- **Site-level GPO links.** Captured and surfaced (`sites` command) and flagged
  as a caveat on OU views, but **not resolved per-machine**: which computers a
  site-linked GPO reaches depends on IP subnet → site membership, which is
  runtime/RSoP state the deterministic core does not evaluate (flag, don't
  simulate).
- **Per-user/object RSoP simulation.** The tool resolves settings at the OU
  level and flags scoping mechanisms (loopback, security filtering, WMI, ILT)
  with caveats. It does not simulate per-user effective policy.
- **`<Blocked/>` extensions.** When the GPO report renders an extension as
  `<Blocked/>` (the CSE was unreadable in-report — common with some third-party
  extensions), gpo-lens records the setting with `source_state="blocked"` and
  surfaces it in `admx-gaps`. For the Registry CSE specifically, the binary
  `Registry.pol` (collected in SYSVOL) is parsed to **resolve** blocked
  settings into real key/value/type triples (`source_state="registry_pol"`).
  Other blocked CSEs remain opaque.
- **Collection coverage is bounded by the collector account's access.** A GPO
  with *Authenticated Users Read* fully stripped is invisible to a
  least-privilege account — not just unreadable. Rather than chase full read by
  granting per-GPO permissions, gpo-lens **reconciles**: run the collector once
  as a privileged account to produce an authoritative `gpo-inventory.json`, run
  it routinely as a least-privilege account for the export, and any GPO in the
  inventory but missing from the export (or named in `collection-errors.json`)
  is surfaced as a **coverage gap** in `doctor`/`summary` — named, never
  silently dropped.

## Development

```bash
uv venv && uv pip install -e ".[dev]"
pytest -q
ruff check .
mypy src
```

Inherited a running installation? Start with [`docs/handover.md`](docs/handover.md).

See [`AGENTS.md`](AGENTS.md) for conventions, module map, and build details.
See [`docs/`](docs/) for the normalized model spec and per-work-item specs.
