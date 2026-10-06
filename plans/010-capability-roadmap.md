# Plan 010 — Capability Roadmap (post-Tier-2)

**Status:** Partially shipped across v0.1.0–v0.3.0; verified 2026-10-06. Evidence: [src/gpo_lens/snapshot_diff.py](../src/gpo_lens/snapshot_diff.py), [tests/test_narration_integration.py](../tests/test_narration_integration.py).

CI, release history, reports, ingest diffs, delegation, ADMX and narration shipped (see CHANGELOG). Publication rules are in `docs/publication-review.md`. PyPI distribution remains unshipped and is not pursued for v1.3.0; installation is from a trusted checkout.

The design below is the historical specification; this status records the verified release scope.
**Author:** Fable 5 (repo scan + portfolio review)
**Strategic role:** gpo-lens has built features faster than it has built project
infrastructure. This plan sequences (a) the infrastructure a 4-day-old project
needs before it accretes more code, (b) the capability work that completes the
AGPM-replacement and security-depth stories, and (c) Tier 3 — the layer that
makes this tool unlike anything else in the niche.

## Ground truth at time of writing

- Working tree: **233 tests pass (12s)**, ruff clean, **mypy --strict clean**.
  Uncommitted: `snapshot_settings_diff` (per-setting delta between snapshots —
  the core AGPM-replacement query) + CLI command + 370 lines of tests. Complete
  and green; needs commit.
- ~~**No git remote, no CI, no tags, no CHANGELOG.**~~ **(Resolved post-hoc:
  remote at `github.com/hraedon/gpo-lens`, `.github/workflows/ci.yml`, tags
  through v0.7.2, real `CHANGELOG.md` — all Phase 0 items landed by 2026-06-25.)**
  Earlier reflections flagged these as outstanding; that framing is outdated.
- 4 active breadcrumbs: changelog-over-time, delegation-audit-deep-dive,
  estate-doc-export, settings-diff-pipeline. All filed 2026-06-09; the
  uncommitted work partially addresses the first and last.
- Tier 1, Tier 2 (baseline diff vs Win11 24H2), and Tier 2.5 (topology) are
  implemented. ~~Tier 3 (LLM narration) — the charter's differentiator — has no
  code and no design doc.~~ **(Resolved: Tier 3 narration landed across
  `narration.py`, `cli/_narration.py`, `web/routes/ask.py`.)**
- Data hygiene verified: `samples/` (incl. the real WORK-DOMAIN.local work-domain
  SYSVOL) is gitignored and has **never been committed**. Committed calibration
  tests carry only aggregate counts (100+ GPOs, 1,000+ SOMs), but a sanitization
  review is still required before any public publication.

---

## Phase 0 — Project infrastructure (before more features) — **DONE**

~~The codebase quality is ahead of its scaffolding.~~ Phase 0 is complete as
of v0.7.x: remote + CI + tags + CHANGELOG all landed. The sub-items below are
kept as the historical record of what was sequenced.

### WI-0.1 — Commit the in-flight settings-diff work
- `snapshot_settings_diff` + `settings-diff` CLI + tests are green in the tree.
  Commit them; update the `settings-diff-pipeline` and `changelog-over-time`
  breadcrumbs to reflect what landed vs what remains.
- **AC:** clean `git status`; breadcrumbs updated.

### WI-0.2 — Remote + CI
- Create the GitHub repo (private until WI-0.4 decides visibility) and a CI
  workflow: ruff, mypy --strict, pytest. Pin action SHAs (cert-watch
  `ci.yml` is the template).
- ~~**Blocker to solve:** sample-dependent calibration tests skip when `samples/`
  is absent, so naive CI would pass while testing a fraction of the suite.
  Build a **synthetic fixture estate** (3–5 fake GPOs: one cpassword, one
  MS16-072 case, one version-skew, one broken UNC, an OU tree with one
  block-inheritance and one enforced link) committed under `tests/fixtures/`,
  and port the structural assertions to it. Real-sample calibration tests stay
  as a local-only marker.~~ **(Resolved: two synthetic fixture estates landed —
  `tests/fixtures/` (14 GPOs, `fakefixture.local`) and `tests/golden_estate/`
  (6 GPOs, `GOLDEN.local`) — driving CI coverage to ~92% without samples. The
  coverage gate was raised from 20% to 85% to reflect this.)**
- **AC:** CI green on push; CI test count within ~10% of local; no real-export
  data in the fixture.

### WI-0.3 — Release discipline
- `CHANGELOG.md`, bump to v0.1.0 once WI-0.1/0.2 land, tag it. Keep the
  cert-watch convention (tags + changelog entries per release).
- **AC:** `git tag` shows v0.1.0; CHANGELOG documents Tier 1→2.5 retroactively
  in one summary entry.

### WI-0.4 — Decision: publication & sanitization review
- The portfolio goal wants this visible; the inputs are from a real workplace.
  Before any public flip: grep docs/tests/reflections for work-domain
  identifiers (domain name, OU names, GPO display names), confirm `samples/`
  ignore rules survive a fresh clone, and decide whether aggregate calibration
  numbers are acceptable to publish. Output is a one-page note in `docs/`,
  not code.
- **AC:** written decision (public now / public after scrub / private
  indefinitely) with the checklist results.

---

## Workstream A — Complete the AGPM-replacement story (v0.1.x)

The change-log-over-time feature is the headline "replaces dead tooling" claim.
The per-setting diff (WI-0.1) is the hard core; what remains is wrapping it
into a workflow an admin would actually run weekly.

### WI-A.1 — Level 2 version-aware change log (breadcrumb: changelog-over-time)
- Use GPC/GPT version counters already ingested in metadata: report which side
  (Computer/User) changed and how many edits occurred between snapshots even
  when only metadata is available; pair with `snapshot_settings_diff` detail
  when both snapshots carry settings.
- **AC:** `gpo-lens diff` output distinguishes "metadata says changed, N edits"
  from full per-setting detail; calibration fixture covers both paths.

### WI-A.2 — Estate documentation export (breadcrumb: estate-doc-export)
- Self-contained report (Markdown + HTML, print-to-PDF friendly) synthesizing:
  estate summary, doctor findings by severity, topology overview, baseline
  compliance %, change log since a chosen snapshot. All data already computed —
  this is formatting plus an opinionated layout. cert-watch's compliance
  report is the proven pattern (point-in-time, auditor-facing).
- **AC:** `gpo-lens report --out estate.html` produces a document a manager
  can read without the tool installed.

### WI-A.3 — Scheduled-snapshot ergonomics
- A documented loop: run collector → ingest → auto-diff against previous
  snapshot → append to change log. One `gpo-lens ingest --diff-latest` flag
  plus a runbook section; no daemon, stays a CLI.
- **AC:** two ingests of evolving fixture data produce a cumulative,
  readable change history.

---

## Workstream B — Security-analysis depth (v0.2.0)

### WI-B.1 — Delegation deep-dive (breadcrumb: delegation-audit-deep-dive)
- The model already stores full `DelegationEntry` records. Add: estate-wide
  privilege rollup ("which trustees can edit which GPOs"), unknown/orphaned
  SID detection, non-default-editor flagging (trustees beyond Domain Admins /
  Enterprise Admins / SYSTEM with edit rights), and a `doctor` severity for
  write-delegated-to-broad-groups. SDDL/ACE parsing only if the XML reports
  prove insufficient — check what the collector already captures first.
- **AC:** fixture with a rogue `Authenticated Users:Edit` ACE is flagged
  critical; rollup lists it under the trustee.

### WI-B.2 — ADMX crosswalk integration
- `baseline-diff --admx-dir` and `admx-gaps` resolve raw registry paths to
  policy display names using the estate's own PolicyDefinitions (Central
  Store from the SYSVOL copy — already in the export). Cuts the dominant
  noise source in baseline results (1,605 "missing" entries are unreadable
  registry paths today).
- **AC:** baseline diff rows show policy names where the ADMX resolves them;
  unresolved rate reported.

### WI-B.3 — Loopback awareness (charter backlog)
- Detect loopback-enabled GPOs + mode (merge/replace); annotate
  `settings_at_som` and precedence-conflict output with a loopback caveat
  banner when any GPO in scope sets it. The charter calls this **required for
  the OU conflict view to be honest** — it is currently silently wrong for
  estates using loopback (most RDS/VDI shops).
- **AC:** fixture with a loopback-replace GPO produces the annotation; views
  without loopback in scope are unchanged.

---

## Workstream C — Tier 3: LLM narration (v0.3.0, the differentiator)

This is the layer no competitor has and the reason the project carries the
"deterministic core, no AI in the truth path" charter. It is also the piece
that ties gpo-lens to the broader portfolio (auditable AI: verified facts in,
narration out, provenance kept).

### WI-C.1 — Narration contract design doc (no code)
- Define: input = the JSON output of existing queries (facts, already
  `--json` everywhere); output = plain-English narration with **every claim
  traceable to an input fact id**; failure mode = degrade to raw facts, never
  block; transport = configurable endpoint (Claude API default, local model
  possible, fully optional extra — core stays stdlib-only).
- Decide the first three narration targets: `doctor` findings (why does this
  matter / what to do), a single setting ("what does this do"), and the
  estate report executive summary.
- **AC:** design doc in `docs/`; charter principles restated as testable
  constraints (e.g., "narration layer importable nowhere in queries/ingest").

### WI-C.2 — `gpo-lens explain` (first narration surface)
- Implement against the contract for `doctor` findings. Tests mock the model;
  an integration marker hits a real endpoint when a key is present. An
  architecture test asserts the import boundary (core modules cannot import
  the narration package).
- **AC:** `doctor --explain` produces prioritized plain-English remediation
  narrative; with no API key it prints facts unchanged and exits 0.

### WI-C.3 — Natural-language query routing (after C.2 proves the seam)
- "Who sets the lockout threshold?" → maps to existing query primitives +
  parameters, executes deterministically, narrates the result. The LLM picks
  the query; the core computes the answer.
- **AC:** a test corpus of ~20 NL questions routes to correct primitives;
  wrong/unroutable questions say so rather than hallucinating.

---

## Workstream D — Distribution & polish (continuous)

- **Packaging:** installable via `uv tool install` / `pipx` from the repo;
  PyPI only after WI-0.4 says public. Zero runtime deps is a selling point —
  keep it.
- **Collector hardening:** parameter validation, progress output, a
  `-WhatIf`-style dry run listing what would be exported; document the
  least-privilege account needed (read-only domain user + SYSVOL read).
- **`doctor` as front door:** README quick-start should be collector → ingest
  → `doctor` in three commands.
- **queries.py decomposition** (flagged in two reflections, ~1,300 lines and
  growing): extract `detection.py` (cpassword/broken-refs/ADMX-gap scanners)
  the next time a Workstream B item opens the file. Gated, like cert-watch
  Workstream E — don't do it as a standalone session.

---

## Decisions requested

1. **Repo visibility** (WI-0.4) — public is the portfolio-aligned answer, but
   only after the sanitization checklist passes. Recommend: create private
   remote *now* (backup + CI), decide public separately.
2. **Name** — README calls "gpo-lens" provisional. If publishing, settle it
   before the URL exists. No strong recommendation; current name is serviceable.
3. **GPO↔Intune crosswalk** stays declined/stretch (charter already says so);
   re-affirm rather than letting it drift onto the board.

## Release framing

| Release | Headline | Contents |
|---------|----------|----------|
| v0.1.0 | Exists durably | Phase 0 + Workstream A |
| v0.2.0 | Security depth | Workstream B |
| v0.3.0 | Narration (Tier 3) | Workstream C |

Sequencing rationale: Phase 0 first because a remote-less, CI-less repo is one
disk failure from not existing; A before B because the changelog story is the
strongest "replaces dead tooling" claim and is nearly done; C after B because
narration is only as good as the facts beneath it, and B fixes the one place
the facts are currently dishonest (loopback).
