# Plan 022 — Web responsiveness + defect-pattern consolidation

**Status:** Superseded by Plans 024/025 for the web workflow; consolidation shipped in v1.0.0; verified 2026-10-06. Evidence: [src/gpo_lens/web/templates/ou_detail.html](../src/gpo_lens/web/templates/ou_detail.html), [tests/test_registry_cse_guard.py](../tests/test_registry_cse_guard.py).

Sync DB handlers, registry/datetime helpers, deterministic 409 test, GUID fixture lint, forwarded audit attribution, grouped danger cards and OU caveat counts are present (see also `tests/test_datetime_guard.py`, `tests/test_fixture_guid_lint.py`, `tests/test_web.py`). The proposed WI-1 dedicated async-store AST guard and slow/fast concurrent-request acceptance test are not present; their acceptance is not claimed. Plan 025 replaces the old nav while retaining specialist routes.

The design below is the historical specification; this status records the verified release scope.
**Author:** Claude (Fable 5), from the 2026-07-01 portfolio evaluation
**Strategic role:** gpo-lens is deployed and load-bearing at work; the 2026-06-29
adversarial cycle (31 + 4 findings) is done and fixed. What the cycle left behind is not
a list of bugs but a list of *patterns that produced bugs*: async routes doing blocking
SQLite (a UX cliff under concurrent use of a deployed UI), the same case-sensitive CSE
comparison independently re-implemented in three modules, unguarded `fromisoformat`
scattered rather than centralized, a timing-dependent flaky test, and hand-built test
fixtures whose GUID format can mask join bugs. This plan converts each pattern into a
structural fix plus an enforcement test, in the repo's established style (the AST
architecture test being the precedent). Deliberately small — a consolidation plan, not a
feature arc.

**Out of scope (already reported to the team from the evaluation):** the `merge.py` →
`topology._split_dn` private import, the blocked regista write path /
PENDING-REGISTA-WI drain, and TLS-deployment items (M-10 DNS rebinding).

**Resolved 2026-07-01 (SDDL review session):** the "replace the hand-rolled SDDL parser
with a library" question is settled as **keep it**. A differential test of the full
real-estate corpus (67 unique SDDL strings, 767 ACEs, lab + work exports) against .NET
`RawSecurityDescriptor` on a real Windows host showed zero verdict-level disagreements;
the defects it did find (SW dropped from the rights set, hex-map `0x8`/`0x100`
mislabeling, `PS`/RID-555 alias errors, discarded ACL control flags, whitespace GPO
owner) are all fixed, and a 27-string reference corpus
(`tests/test_sddl_reference_corpus.py`) now pins parser-vs-Windows agreement in CI.
WI-6 and WI-7 below also landed in that session.

## WI-1 — Stop blocking the event loop in web routes

13 `async def` handlers across `web/app.py` and `web/routes/*` call synchronous SQLite
through the store. Under the deployed single-process uvicorn, one slow estate-wide query
(WI-082 search on a large estate) freezes *every* concurrent request, including static
assets. Fix structurally, not per-route:

- Convert DB-touching handlers to plain `def` (FastAPI runs sync handlers in its
  threadpool; SQLite in WAL mode tolerates this) **or**, where a handler must stay
  `async` (uploads/streaming), wrap store calls in `asyncio.to_thread`. Pick one rule and
  state it in a module docstring.
- Confirm the store's connection handling is thread-safe under the chosen rule
  (per-request connections or `check_same_thread=False` with the existing lock —
  document which).
- **Enforcement:** extend the AST architecture test with the new rule — no `async def`
  route may call the store directly. That is how this stays fixed.
- **AC:** a two-request test (slow query via injected store + fast `/healthz`-style
  route) shows the fast request completes while the slow one runs; architecture test
  fails on a violating route; full suite green.

## WI-2 — One registry-CSE predicate

The case-sensitive CSE comparison bug was found and fixed in `danger.py`, then again in
`detection.py:641`, then again in `_admx_coverage.py:93,141` — same bug, three
implementations. Centralize as `is_registry_cse()` (single module, casefold inside), and
add a grep-style test asserting no other module compares CSE GUID/name strings directly
(the repo's identifier-gate pattern, turned inward).

- **AC:** three call sites migrated; the guard test fails on a new inline comparison;
  behaviour-identical on existing fixtures.

## WI-3 — One guarded ISO-datetime helper

`store._iso_to_dt` now wraps `ValueError`, but `normalize.py` still calls
`datetime.fromisoformat` unguarded, and nothing prevents the next module from doing the
same. Move the guarded helper to a shared module (`_time.py` or similar), migrate both
call sites, and add the same style of guard test: `datetime.fromisoformat` appears only
inside the helper.

- **AC:** malformed-timestamp fixture exercises the error path through `normalize`; guard
  test in place; no behaviour change on valid input.

## WI-4 — Deterministic 409 ingest-concurrency test

`test_concurrent_upload_returns_409` races two real requests against the in-process
ingest lock and goes flaky under full-suite CPU load (documented in the
PENDING-REGISTA-WI holding pen, 2026-06-29). Make it deterministic: inject an event into
the ingest path (constructor/fixture injection, not a test-only branch) so the test
*holds* the lock at a known point, asserts the second request's 409, then releases.

- **AC:** test passes under `pytest -n auto` repeatedly (no timing window); the
  cross-process lock coverage (WI-043/044) is untouched.

## WI-5 — Canonical-GUID fixture hygiene

The `canonical_guid` hyphen bug was a latent landmine precisely because fixtures always
used the collector's hyphenated form. Hand-built fixtures in `test_danger.py`,
`test_scope_honesty.py` etc. still construct `Gpo(id="11111111-2222-...")` with hyphens —
non-canonical, and able to mask a future join bug the moment a test crosses hand-built
and canonicalized IDs.

- Sweep hand-built `Gpo(...)`/setting fixtures to the bare canonical key form (or route
  them through `canonical_guid()` at construction).
- Add a lightweight fixture-lint test: any `Gpo(id=...)` literal in `tests/` must already
  be canonical.
- **AC:** suite green after the sweep; lint test fails on a hyphenated literal.

## WI-6 — Nav IA + orphan pages — **DONE 2026-07-01**

`/delegation`, `/admx-coverage`, and `/golden-diff` were registered, gated, and
templated but linked from nowhere. Nav regrouped by workflow (Estate / Posture /
Change / Tools) with hairline dividers; all three pages linked; single row at 1440px,
graceful group-wrap below. `test_ui_regression._NAV_LINKS` updated.

## WI-7 — Forwarded-user audit attribution — **DONE 2026-07-01**

Behind IIS every caller was `local-analyst` in audit.log. Opt-in
`GPO_LENS_FORWARDED_USER_HEADER`: on the no-token loopback path the named header
(set by the same-host proxy from `{LOGON_USER}`) names the principal (role
`forwarded`, loopback permission set, sanitized/capped). Ignored from remote peers
and in token mode. IIS URL Rewrite wiring documented in deploy/iis/README.md.

## WI-8 — Danger table → finding cards (from the 2026-07-01 style review)

The 7-column danger table forces remediation prose into a ~220px column and repeats
the identical remediation text for every finding of the same check; a single row can
exceed a screen height. Restructure as one card per finding (severity + GPO + finding
line; check/compliance/citation as chips; remediation once per check, collapsible),
or group rows by check with remediation in a group footer. Min-widths landed
2026-07-01 are a stopgap.

## WI-9 — OU-detail scope-caveat summary (from the 2026-07-01 style review)

On a real OU the "Scope caveats" callout is a 22-bullet wall of near-identical
boilerplate, duplicating what the precedence-chain chips below already show per-GPO.
Replace the bullet list with mechanism counts ("9 security-filtered · 6 loopback ·
5 item-level targeting — not simulated") linking attention to the chips; keep the
full text available behind a details element for export/print parity.

## Sequencing

Independent WIs; land in any order. WI-1 first by value (it is the only one a deployed
user can feel). Each WI is deliberately shaped to be a single small PR with its
enforcement test in the same diff — the pattern fix and the thing that keeps it fixed
travel together.
