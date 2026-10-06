# Plan 028 — Decompose `findings.py` and `ingest.py`

**Status:** Not pursued for v1.3.0; deferred by coordinator 2026-10-06. Evidence: [src/gpo_lens/findings.py](../src/gpo_lens/findings.py), [src/gpo_lens/ingest.py](../src/gpo_lens/ingest.py).

Both remain modules, not the proposed packages. Decomposition is deferred because a refactor carries risk before production handover. No behavioral or module-layout change is part of this docs pass.

The design below is the historical specification; this status records the verified release scope.

**Depends on:** nothing. Deliberately independent of Plan 027 — this is
maintenance debt, and sequencing it behind the 027 finish line would mean
touching these files most while they are hardest to read.

**Strategic role:** `detection.py` was split on 2026-08-07 from 907 lines into
four themed modules behind a re-export facade, and the split cost nothing in
review because it was pure motion with an unchanged public surface. The two
files that are now larger than `detection.py` ever was never got the same
treatment:

| File | Lines | Shape |
|---|---|---|
| `ingest.py` | 1707 | A pipeline: bytes → XML → `Gpo` → `Estate`, plus five directory-JSON loaders |
| `findings.py` | 1702 | Seven cohesive groups that happen to share a file |
| `merge.py` | 1198 | *Out of scope — see §5* |

This plan splits both, in that order of value, using the method the
`detection` split proved.

---

## 1. Non-goals

- **No behaviour change.** Every commit is code motion plus imports. If a
  function needs fixing, that is a different commit on a different branch.
- **No public API change.** `from gpo_lens.findings import X` and
  `from gpo_lens.ingest import X` keep working for every `X` that works today.
  The facade `__all__` is the contract, exactly as `detection/__init__.py` is.
- **No re-layering.** This is not an excuse to introduce a repository pattern,
  a service layer, or dependency injection.
- **`merge.py` is not in scope.** See §5 for why.

## 2. `findings.py` → `findings/` (do this one first)

Higher value than `ingest.py`: the groups below are genuinely independent
subjects, not stages of one pipeline, and this is the file most likely to be
edited next (Plan 025 WI-4/5/6 all touch the inbox).

| New module | Current lines | Contents |
|---|---|---|
| `_runs.py` | 234–356 | `register_analysis_input`, `create_evaluation_run`, `complete_evaluation_run`, `list_evaluation_runs` |
| `_lifecycle.py` | 358–607 | `LifecycleResult`, `absence_is_meaningful`, `run_evaluation` |
| `_triage.py` | 72–232, 609–820 | The v1 read surface (`FindingRecord`, `load_active_findings`, `load_finding_triage`, `triage_finding`, `load_finding_triage_map`) and the v2 append-only log (`append_triage_event`, `fold_triage`, `load_triage_events`, `get_triage_status`, `load_triage_status_map`, `expire_risk_acceptances`) |
| `_inbox.py` | 822–1293 | `_LATEST_CLAIM_SQ`, `_INBOX_BASE_WHERE`, `_like_escape`, `_inbox_predicate`, `finding_inbox_categories`, `finding_inbox_count`, `finding_inbox`, `finding_history`, `finding_observation_history`, `_safe_json_list` |
| `_analytics.py` | 1295–1469 | `finding_delta`, `accepted_risk_register`, `evaluation_runs` |
| `_adapters.py` | 1471–1702 | `_doctor_finding_to_candidate`, `_danger_finding_to_candidate`, `candidates_from_estate`, `evaluate_finding_lifecycle_v2` |
| `__init__.py` | — | Re-export facade; `__all__` is the backward-compatible contract |

### Constraints the split must respect

- **`_inbox_predicate` stays in the same module as `finding_inbox` and
  `finding_inbox_count`.** Those two sharing one predicate is *why* a page and
  its total cannot disagree (WI-1.2). Splitting readers from writers, or
  queries from their predicate builder, would put the guarantee at the mercy of
  an import. This is the one seam that is not negotiable.
- **`_legacy_findings` imports `absence_is_meaningful` from `findings`.** Once
  `findings` is a package whose `__init__` imports the submodules, that import
  becomes a cycle if it goes through the facade. `_legacy_findings` must import
  from `gpo_lens.findings._lifecycle` directly. Verify with a cold
  `python -c "import gpo_lens._legacy_findings"`, not just via pytest, which may
  already have the package imported.
- **`tests/_arch.py` `CORE_MODULES` and the AGENTS.md import-boundary list**
  are updated in the same commit as the module they describe — the arch test
  and the doc are one change, as the `_legacy_findings` extraction did it.
- **`docs/spec/` files that name `findings` as an `interface_ref`** are updated
  to name the submodule, the way `wi_danger.md` was corrected when
  `has_write_right` moved to `authz`.

### Commit sequence

One commit per module, each green on its own so the history stays bisectable
(the audit split's seven commits were each verified individually; do the same).
Order chosen so each commit's dependencies already exist:

1. `_runs.py` — depends on nothing else in the file
2. `_triage.py` — depends on `_runs`
3. `_lifecycle.py` — depends on `_runs`, `_triage`
4. `_inbox.py` — depends on `_triage`
5. `_analytics.py` — depends on `_inbox`
6. `_adapters.py` — depends on `_lifecycle`
7. Facade `__init__.py` + `_arch.py` + AGENTS.md + specs

## 3. `ingest.py` → `ingest/`

Lower value, and worth saying why: this file is one pipeline, so the modules
below are *stages* rather than independent subjects. The payoff is smaller than
the `findings` split, and it should be sequenced second — or dropped if the
`findings` split proves more disruptive than expected.

| New module | Current lines | Contents |
|---|---|---|
| `_archive.py` | 53–167 | `SizeLimitedReader`, `_streaming_zip_read`, `_load_json_records`, the decompression bomb limits |
| `_settings_xml.py` | 169–640 | The GPO-report setting parsers: security, registry, ADMX summarization, GPP registry/container, folder redirection, `_parse_settings` (~470 lines — the largest single win) |
| `_report.py` | 641–993 | `_parse_links`, `_parse_delegation`, `parse_report`, `parse_report_xml`, `load_baseline_from_zip`, `_extract_gpos_from_zip`, `_parse_single_gpo` |
| `_directory.py` | 995–1408 | `parse_inheritance`, `merge_metadata`, `attach_sysvol_paths`, `augment_blocked_registry_from_pol`, `parse_wmi_filters`, `parse_ou_tree`, `parse_principals`, `parse_group_members`, `parse_sites`, `_parse_gplink` |
| `_coverage.py` | 1409–1604 | `parse_coverage_gaps`, `_scan_sysvol_gaps`, `_scan_missing_sysvol` |
| `__init__.py` | 1606–1707 | Facade, plus `load_estate`/`_try_load`/`_try_action` — the assembly step is the package's job |

### Constraint

`_archive.py` holds the decompression-bomb limits
(`_MAX_DECOMPRESSED_BYTES`, `_MAX_BASELINE_UNCOMPRESSED_BYTES`) and
`SizeLimitedReader`. These are a security boundary, not a utility. The module
docstring must say so, and no other module may read a zip without going
through it — otherwise the split creates a second, unguarded path to the same
data. Add a test asserting `zipfile` is imported nowhere else under `ingest/`.

## 4. Acceptance criteria

- `pytest` green, `ruff check` clean, `mypy` clean after **each** commit, not
  merely at the tip.
- Coverage stays at or above the 85% CI gate (pure motion should not move it;
  a drop means something was dropped).
- No module produced by this plan exceeds ~700 lines. This is a bound on the
  split's output, not on the tree: `merge.py` (1198), `store.py` (1095),
  `report.py` (1010), and `topology.py` (1001) are all still over 900
  afterwards. Three of those are candidates for the same treatment later;
  `merge.py` is not (§5). Stating the residue here so the plan is not read as
  "large files are gone".
- `from gpo_lens.findings import *` and `from gpo_lens.ingest import *` expose
  exactly the names they expose today — pin with a test that compares
  `sorted(__all__)` against a checked-in list, so an accidental omission fails
  loudly rather than surfacing as an ImportError in the web layer.
- A cold `python -c "import gpo_lens.<mod>"` succeeds for every new submodule
  (catches import cycles pytest can mask).

## 5. Why `merge.py` is out of scope

`merge.py` is 1198 lines, and once the two files above are split it becomes the
largest module in the tree, so it is a fair question. It is excluded because it
implements the RSoP/precedence model —
one algorithm with genuinely interdependent parts, where the "modules" would be
arbitrary slices of a single computation and the facade would re-export a set of
names that only make sense together. Splitting it would move lines without
making anything easier to find. Revisit only if it grows a second
responsibility.

## 6. Risks

- **Review fatigue.** Thirteen commits of pure motion is a lot to read. Mitigate
  as the audit split did: one concern per commit, an explicit "pure code motion
  — no logic edited" line in each message, and a diffstat that shows deletions
  matching insertions.
- **`git blame` disruption.** Every moved line gets a new blame entry. Add each
  motion commit to `.git-blame-ignore-revs` (the file introduced when `ruff
  format` was adopted), so `git blame` still reaches the real author.
- **Merge conflicts with Plan 025 WI-4/5/6.** WI-4 touches routes and WI-6 adds
  exports; both import from `findings`. The facade means their imports do not
  change, but if WI-4/5/6 are in flight on a branch, land this first or land it
  after — not alongside. Today nothing is in flight, which is the argument for
  doing it now.
