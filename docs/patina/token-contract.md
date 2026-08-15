<!-- VENDORED FROM patina 0.5.0 (e7024c1) -- patina-owned. Do not edit, reformat or lint this file; edit patina and re-run sync.sh. -->
# The patina token contract

This is the canonical list of design tokens every family tool shares, the rules
for using them, and the per-tool accent registry. It is the design spine of
patina: change it deliberately, because a change here ripples to every tool.

## Principle

Coherence comes from **shared token names and values**, not shared component
classes. Two tools can have entirely different components and still read as one
product line if they draw every colour, size, and space from these tokens.
A tool that hardcodes a hex value or a pixel size outside this contract is where
drift begins.

## Tokens

All are CSS custom properties on `:root`, themed via `:root[data-theme="…"]`.

### Surfaces (warm charcoal dark / warm paper light)
`--bg` `--bg-soft` `--panel` `--panel-2` `--panel-3` `--inset` `--border`
`--border-2` — a low-to-high elevation ramp. Backgrounds and hairlines only.

### Text
`--text` (primary) `--text-2` (secondary) `--text-3` (muted/labels).

### Accent (the one per-tool override)
`--accent` `--accent-2` `--accent-soft` (tint bg) `--accent-line` (tinted
border). Links, focus rings, wordmark, active nav. **Never** status.

### Status (shared verbatim — do not re-tint per tool)
`--ok` `--warn` `--crit` `--info`, each with a matching `*-soft` tint.

**Decided 2026-08-14 (plan 004): the "warm & quiet" quad** — dark: sage
`#7fd091` / antique gold `#ce9d44` / terracotta `#cc6050` / steel `#60aeda`;
light: deep inks `#004e19` / `#836101` / `#b64461` / `#25729e`. Chosen from
three constraint-searched candidates rendered on real components (owner +
review concurred). Every value ≥4.5:1 on `--bg` and `--panel` in both themes.

*Recorded one-time manual measurement (2026-08-14, NOT a gated invariant):* all
6 status pairs measured ≥8 ΔE under protanopia/deuteranopia/tritanopia
simulation (Machado 2009, severity 1.0), normal-vision ≥15. **No script in this
repo or any consumer computes those figures** — `check_contrast.py` gates the
WCAG contrast floors only, and its own docstring says CVD pairwise validation is
deliberately not gated there because it needs simulation matrices and judgment.
**Open item:** Plan 004's acceptance criterion asked for the validator + CVD
simulation pass to be recorded in the plan folder, and it never was —
`git ls-files plans/` shows only `.md` files, so the underlying measurement data
is uncommitted and these numbers are currently unreproducible from this repo.
Re-deriving or committing that record is unassigned; see `plans/004`.

The same caveat applies to the figures for the *previous* quad below: they are
recorded measurements, not gated ones.

The previous quad — which happened to be Tailwind emerald/amber/red-400 — was
replaced for its measured failures (light ok 2.90:1; deutan collapse of
ok/warn/crit at ΔE 4.1–5.5), NOT for its provenance. Two hue choices are
physics, not taste: light-theme warn is golden ochre (sRGB has no dark
high-chroma amber at 4.5:1 on warm paper) and light-theme crit runs crimson
(warm-red vs amber is not protan-separable at this contrast).
`scripts/check_contrast.py` gates the WCAG contrast floors in CI — that is the
mechanical half. The CVD half is not mechanical: changing these values again
requires redoing the plan-004-grade CVD validation by hand, and the gate will
not tell you that you skipped it.

### Type
Faces: `--font-sans` (system UI), `--font-mono` (IBM Plex Mono — figures,
labels, identifiers). Use `.tnum` for tabular figures.

**Each step says what it is for (added 2026-08-15).** The scale was seven bare
numbers, which is how it became an accidental convention: adopting gpo-lens
turned up `--fs-xs` forked to 12px, and nothing in the contract could settle
whether 12 was load-bearing or drift — the answer had to be reconstructed from
that tool's own internal consistency. A number with no stated job is a value
nobody can defend or overrule. These are roles and contraindications, not
component assignments; a tool still chooses.

| token | px | for | not for |
|---|---|---|---|
| `--fs-xs` | 11 | tertiary operational metadata — timestamps, eyebrow labels, table column headers, compact annotations | primary controls, or anything read for more than a glance |
| `--fs-sm` | 12.5 | secondary text that is still read — helper text, chip and badge labels, dense table cells | body copy on a page a person stays on |
| `--fs-base` | 13.5 | default UI text: body copy, form inputs, buttons, most table cells | headings of any level |
| `--fs-md` | 15 | emphasised body, section leads, the value in a stat cell | a substitute for a heading token |
| `--fs-lg` | 18 | panel and section headings | page titles |
| `--fs-xl` | 22 | the page title | display or hero text |
| `--fs-2xl` | 30 | a single dominant figure — the one number a page exists to show | anything a page has more than one of |

Deliberately **not** doing yet: semantic aliases (`--text-metadata` and
friends). Document the meaning the scale has actually earned before minting
names for it.

### Space / shape
`--space-1`…`--space-6` (4px base). `--radius-sm` `--radius` `--radius-md`
`--radius-lg`. `--shadow`, `--row-hover`.

### Base helpers shipped in `tokens.css`
`.mono` `.tnum` `.muted`, link + `:focus-visible` styling, scrollbar, and a
`prefers-reduced-motion` reset. Everything else is the tool's own components.

## Accent registry

Each tool picks one distinct, non-status accent. "Same metal, different finish."

| Tool | Finish | Dark | Light |
|------|--------|------|-------|
| cert-watch | struck bronze (certificate seal) | `#c9a25a` | `#8a6a28` |
| gpo-lens | verdigris (patinated bronze) | `#5fb3a3` | `#2c7d6e` |
| dossier | plum (registry seal) | `#b07cc6` | `#7a4d8f` |
| sluice | aqua (flow register) | `#5fcde4` | `#2a8ca8` |
| _(default)_ | neutral warm steel | `#b9a98c` | `#6f6552` |

When adding a tool, choose an accent that is (1) not another tool's, (2) not a
status hue, (3) legible on both themes, and record it here and as
`accents/<tool>.css`.

## Tool-local tokens: the prefix rule (Plan 005, 2026-08-14)

Shared tokens are unprefixed and defined only in `tokens.css`. A tool that
needs its own tokens (`--cw-topbar-h`, `--gp-grid-gap`) MUST prefix them with
its 2–3 letter tool prefix, so contract vocabulary and local vocabulary can
never collide, and a consumer can never shadow a contract value (redefining an
unprefixed token in tool CSS is a conformance failure — `check_patina.py`
enforces both directions). If a local token turns out to be generally useful,
promote it into this contract; don't drop the prefix locally.

## Shared component patterns (Plan 006, ratified 2026-08-14 — a reversal)

**Decided 2026-08-14 by the owner, reversing "share tokens and shapes, not
class names":** patina ships a **reference implementation** of the shared
components — `components.css` (neutral `pt-` prefix) plus a Jinja macro library
`macros/ui.j2` — vendored by `sync.sh` (delimited and stamped per Plan 005)
alongside the tokens.

- **New tools adopt it wholesale.** A new tool stands up the family frame with
  zero component CSS of its own.
- **Existing tools keep their prefixes** (cert-watch `cw-`, gpo-lens `gp-`,
  dossier `ds-`) and may adopt per-component opportunistically — when a page is
  being rebuilt anyway. Owner amendment, same day: a full retrofit is
  *permitted* where the initial pain is worth the downstream simplification,
  but opportunistic remains the default; assess per tool when its UI is next
  touched.

**Why the reversal.** The old rule was reasoned for *human* autonomy: each
tool's author keeps freedom at the component layer. But the estate's UIs are
written by agents, not authors, and for an agent `patterns.md` is a description
to re-implement from scratch per tool. Measured 2026-08-14: four parallel
component layers (`cw-` ~40 sections, `ds-` ~830 lines, gpo-lens's own,
sluice's per-page CSS) implementing the same 14 shapes with drifting details.
Every re-implementation is a drift surface. The catalog was the right idea with
the wrong delivery — prose for humans instead of code for machines. What made
the reversal *safe* is Plan 005: shared code is only safe to share once drift
in a vendored copy fails mechanically.

**Status: ratified, not built.** Neither `components.css` nor `macros/ui.j2`
exists yet — Plan 006 WI-2 (extract), WI-3 (prove on a thin consumer), WI-4
(document) are open. Do not write code that assumes a `pt-` class exists.

Until they ship — and after, as the human-readable half — **`patterns.md`**
catalogs the shared component shapes (topbar, stat strip, table, pill, chip,
callout, panel, empty state, etc.) with canonical structure, token usage, and
naming conventions, and **`archetypes.md`** covers whole-page structure. New
tools follow those so the family stays visually coherent even without the
shared stylesheet.
