# Plan 017 — Directory search & scoping

**Status:** Partially shipped in v0.6.1; verified 2026-10-06. Evidence: [src/gpo_lens/web/routes/ou.py](../src/gpo_lens/web/routes/ou.py), [tests/test_web.py](../tests/test_web.py).

Phase A directory search/type/sort/pagination shipped. Phase B nested tree/focus/search expansion is not implemented and is not pursued for v1.3.0; the current Directory is a filtered list.

The design below is the historical specification; this status records the verified release scope.
**Author:** GLM 5.2 (from live IIS-deployment feedback)
**Strategic role:** The Directory page (`/ou`, `ou_list.html`) is the entry
point to topology — every OU/domain/site a GPO can link to. Today it is a flat,
paginated list with no search. AGENTS.md measures real estates at **1,000+ SOMs**,
so finding one OU means paging through dozens of screens. This plan adds the same
filter/search/sort UX the dashboard findings table already has, plus an optional
hierarchical scoping view, so the Directory is usable on a real estate. It is a
pure web-layer change over the existing `Estate.soms` list — no core changes, no
new computation, no charter impact.

## Ground truth at time of writing

- `ou_list` route (`src/gpo_lens/web/app.py:750`) loads all SOMs and paginates
  via the shared `_paginate` / `_parse_pagination` / `_base_qs` helpers. No
  filtering or search exists.
- The dashboard `home` route (`app.py:601`) already implements the pattern to
  copy: query params `q` / `severity` / `sort` / `per_page`, validated against
  `_VALID_SEVERITIES` / `_VALID_SORTS` (`app.py:77-78`), with filters preserved
  across pagination by `_base_qs`. WI-025 (open) tracks hardening that table.
- `Som` dataclass fields available for filtering (`model.py`):
  `name`, `path` (distinguished name), `container_type`
  (`"domain"` / `"ou"` / `"site"`), `inheritance_blocked`, and `links`
  (count drives a "busiest scope" sort).
- The Directory already distinguishes the three container types with chips
  (`ou_list.html:32-38`) and shows link count + inheritance state — so the data
  for type/sort filters is already on the row.
- Pagination is server-side and shared; this plan keeps that — no client-side JS
  table.

## Charter addendum (decisions this plan records)

1. **Search is substring, server-side, over `name` and `path` (DN).**
   Case-insensitive `in` match, mirroring the dashboard `q`. No fuzzy/index.
2. **Filters and sort are query params, bookmarkable.** Same convention as the
   dashboard (`?q=&type=&sort=&page=&per_page=`) so a filtered view is a
   shareable link — important for an ops handoff.
3. **Pre-declined:**
   - *Client-side filtering / a JS table library.* The project is server-rendered
     Jinja + CSS with zero JS files (cert-watch lesson, Plan 012). Keep it.
   - *Object-level scope search* (e.g. "which GPOs apply to *this user*"). That
     is RSoP and explicitly out of charter (AGENTS.md "Flag, don't simulate").
     Search here is over *scopes of management*, not principals.

## Phase A — Search, filter, sort on the Directory (MVP)

Mirrors the dashboard findings table exactly so there is one learned UX.

### A.1 Route + query params

`ou_list` (`app.py:750`) gains the same param shape as `home`:

- `q` (str, default `""`) — substring over `som.name` and `som.path`,
  case-insensitive.
- `type` (str, default `""`) — one of `""` / `domain` / `ou` / `site`;
  validated against the `container_type` values. Unknown → ignored (not 500).
- `sort` (str, default `name`) — `name` (DN-aware, case-insensitive),
  `links` (link count desc), `type`. Validated like `_VALID_SORTS`.
- Existing `page` / `per_page` preserved via `_base_qs(request, "page",
  "per_page")` → extend to include `q`, `type`, `sort`.

Filtering/sorting is applied to `list(estate.soms)` **before** `_paginate`, so
pagination counts reflect the filtered set (consistent with how the dashboard
counts findings).

### A.2 Template

`ou_list.html`: add a filter bar above the table matching the dashboard's
(search input + type `<select>` + sort `<select>`), and keep `pg.pagination`
wired through `base_qs` so paging preserves filters. Empty-result state
(`gp-empty`) already exists — extend its copy to mention the active filter
("No scopes match '<q>'.").

### A.3 Acceptance criteria

- `AC-1` `GET /ou?q=finance&type=ou` returns only OUs whose name **or** DN
  contains "finance" (case-insensitive), paginated.
- `AC-2` `GET /ou?type=site` returns only `container_type == "site"` SOMs
  (the parallel scoping axis, per AGENTS.md).
- `AC-3` `GET /ou?sort=links` orders by link count descending.
- `AC-4` Pagination links carry `q`/`type`/`sort` so page 2 of a filtered view
  stays filtered (parity with dashboard: `test_web.py:1130-1135`).
- `AC-5` An unknown `type`/`sort` value does not 500 — it is ignored (treated as
  the default), matching the dashboard's tolerant validation.
- `AC-6` With no params, behaviour is byte-identical to today (no regression on
  the unfiltered Directory).

### A.4 Tests (`tests/test_web.py`)

Parametrised cases mirroring the dashboard search tests
(`test_web.py:1044,1091,1130,1185`): filtered result sets, type filter, sort
order, filter-preserved-across-pagination, unknown-value tolerance, and a
no-regression test that the unfiltered page matches the current output.

## Phase B — Hierarchical scoping view (gated, opt-in)

The flat list loses the OU tree — a real estate is a hierarchy, and "show me
everything under OU=Servers,DC=…" is a common ask. **Gated:** only if Phase A's
flat search proves insufficient in use, because a tree view is a larger lift
(collapsible nesting, DN parsing to reconstruct parent→child edges) and the
flat search may be enough.

### B.1 Approach

- Reconstruct the OU tree from `som.path` DN components at render time (pure
  derivation from `Estate.soms`; no new storage). Domain SOMs are roots; sites
  remain a parallel axis (chips, not nested) per AGENTS.md.
- Collapsible `<details>` rows, zero JS. Deep-link a `?focus=<dn>` to pre-expand
  a subtree (bookmarkable, same convention as Phase A).
- Reuse Phase A's `q` to highlight matches within the tree (expand their
  ancestor chain).

### B.2 Acceptance criteria (if pursued)

- `AC-7` OUs render nested under their parent OU/domain by DN.
- `AC-8` `?focus=` expands only the target subtree; the rest collapsed.
- `AC-9` A search query expands matching branches and collapses the rest.

## Non-goals

- Per-user / per-computer effective scope (RSoP) — out of charter.
- Editing or creating SOMs — read-only by construction.
- A separate "sites" page — sites are already a `container_type` filter in the
  same Directory (Phase A `type=site`), and modelling them as a parallel axis
  is a settled decision (AGENTS.md).

## Sequencing

Phase A is small, self-contained, and unblocks the immediate "I can't find my
OU in 1,000+" pain. It reuses existing helpers and the dashboard's exact UX, so
it should land in one session with tests. Phase B is filed, not started —
defer until Phase A gets real-estate feedback.
