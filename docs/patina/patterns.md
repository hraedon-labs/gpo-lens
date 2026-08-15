<!-- VENDORED FROM patina 0.5.0 (e7024c1) -- patina-owned. Do not edit, reformat or lint this file; edit patina and re-run sync.sh. -->
# patina patterns catalog

A reference for the shared component shapes across the tool family. Tokens
(`tokens.css`) give every tool the same colour, type, and space palette. This
catalog goes one step further: it shows the **shapes** that tools reuse — the
topbar, stat strip, table, pill, and so on — so a new tool can build the same
instrument-panel feel without reverse-engineering an existing one.

Today each tool owns its own component CSS with its own prefix (`cw-`, `gp-`,
etc.), and the patterns below describe **what to build and how to name it**, not
a shared stylesheet. That is no longer the end state: **Plan 006 (ratified
2026-08-14) decided patina will ship a reference implementation** —
`components.css` (neutral `pt-` prefix) + `macros/ui.j2` — that new tools vendor
wholesale, while existing tools keep their prefixes and adopt opportunistically.
**Neither file is built yet** (Plan 006 WI-2/3/4 open), so this catalog is still
the whole delivery; when they land, each section gains a pointer to its `pt-`
counterpart (WI-4).

**Tiers.** `archetypes.md` sorts these sections into two tiers with different
rules: §§1–2 (the frame) and §§3–5, 7–14 (the invisible shapes) are Tier 1 —
standardize aggressively. §6 (stat strip) is Tier 2 — it is a page-archetype
element with a deliberate grammar and a banned failure mode. Whole-page layout
rules live in `archetypes.md`, not here; where one constrains a component's
shape, the section below carries the implementation and points back.

## Naming convention

| Piece | Rule |
|-------|------|
| Prefix | 2–3 letters + hyphen: `cw-`, `gp-`, `ad-` |
| BEM style | Flat hyphenated names (`cw-stat-val`), not strict BEM |
| Modifiers | Bare class additions (`.active`, `.primary`, `.ok`) or `--` suffixes for layout variants |
| Tone/variant | Domain words (`.expired`, `.critical`, `.healthy`) mapped to status tokens |
| Utilities | Optional — cert-watch has a rich utility layer; gpo-lens keeps it lean |

## 1 — App shell

A full-viewport flex column: fixed topbar at the top, scrollable content below.

```
.<prefix>-app          flex-direction: column; height/min-height: 100vh
  .<prefix>-topbar     fixed top bar, full-width surface (see §2)
    .<prefix>-wrap     the SAME centered container as the page below
  .<prefix>-page       flex: 1; overflow: auto — the scrollable region
    .<prefix>-wrap     max-width: 1080px; margin: auto; padding → page content
```

`.<prefix>-wrap` appears twice on purpose: one centered container, used by both
the chrome and the body, is what keeps the page on a single grid
(`archetypes.md`, "One persistent page grid").

Tokens: `--bg` on the app, `--panel` on the topbar, `--border` on topbar
bottom edge.

## 2 — Topbar + navigation

A flex row containing the brand, nav links, spacer, and action buttons.

> **Chrome shares the page grid — implementation of a page-level rule.** The
> normative statement lives in `archetypes.md`, "One persistent page grid"
> (whole-page layout is that file's job, per its stated boundary): the topbar's
> surface and border run full-width, but its *contents* sit on the same centered
> max-width container as the page, because chrome pinned to the viewport edge
> while content is centered creates two competing left edges and the whole page
> reads as indented even though it is mathematically centered. **Here is how:**
> wrap the topbar's contents in the same `.<prefix>-wrap` container the page
> uses (§1), and put the height on that wrap, not on the full-width bar.
>
> **Chrome density matches page density (2026-08-14, WI-3 prototype review) —
> this one is the topbar's own rule.** On a dense instrument-panel UI a spacious
> 52px+ topbar with a generously padded active pill reads as a separate design
> regime. Keep the bar ~46–48px, and give the selected tab a *quiet* treatment —
> low-contrast fill, tight padding, not a button. The code block below is the
> ratified version; earlier copies of this catalog prescribed 58px, an unwrapped
> bar, and a `--panel-3` active pill at `6px 12px`. Those are superseded.

```
.<prefix>-topbar       background: var(--panel);
                        border-bottom: 1px solid var(--border)
                        -- surface + border run full-width...

  .<prefix>-wrap       display: flex; align-items: center; height: 46px;
                        max-width: 1080px; margin: 0 auto; padding → page padding
                        -- ...but contents sit on the page's grid (§1, same wrap)

    .<prefix>-wordmark   flex-shrink: 0; display: flex; align-items: center; gap: 8px
      .<prefix>-mark     accent-coloured icon or initial
      .<prefix>-name     font-family: var(--font-mono); font-weight: 600
      .<prefix>-ver      font-size: var(--fs-xs); color: var(--text-3)

    .<prefix>-nav        display: flex; gap: 2px; margin-left: 24px
      a                  padding: 4px 8px; border-radius: var(--radius-sm);
                          color: var(--text-2)
      a:hover            color: var(--text)
      a.active           background: var(--panel-2); color: var(--accent)
                          -- quiet selected tab: one elevation step, tight
                             padding. NOT --panel-3, NOT button padding.

    .<prefix>-spacer     flex: 1

    .<prefix>-iconbtn    width: 36px; height: 36px; display: flex;
                          align-items: center; justify-content: center;
                          border-radius: var(--radius-sm); cursor: pointer
                          background: transparent; border: none; color: var(--text-2)
    .<prefix>-iconbtn:hover  background: var(--panel-2)
```

Tokens: `--panel`, `--panel-2`, `--border`, `--text`, `--text-2`, `--text-3`,
`--accent`, `--radius-sm`, `--font-mono`, `--fs-xs`.

## 3 — Buttons

```
.<prefix>-btn          display: inline-flex; align-items: center; gap: 6px;
                        font-size: var(--fs-sm); padding: 6px 14px;
                        border: 1px solid var(--border-2); border-radius: var(--radius);
                        background: var(--panel-2); color: var(--text);
                        cursor: pointer
.<prefix>-btn:hover    background: var(--panel-3)
.<prefix>-btn.primary  background: var(--btn-strong-bg); color: var(--btn-strong-text);
                        border-color: transparent
.<prefix>-btn:disabled opacity: 0.5; cursor: not-allowed
```

Tokens: `--panel-2`, `--panel-3`, `--border-2`, `--text`, `--radius`,
`--btn-strong-bg`, `--btn-strong-text`, `--fs-sm`.

## 4 — Inputs and fields

```
.<prefix>-field        margin-bottom: var(--space-3)
.<prefix>-label        display: block; font-size: var(--fs-sm);
                        color: var(--text-2); margin-bottom: 4px;
                        font-family: var(--font-mono)
.<prefix>-input,
.<prefix>-select       width: 100%; padding: 7px 10px;
                        background: var(--inset); border: 1px solid var(--border);
                        border-radius: var(--radius); color: var(--text);
                        font-size: var(--fs-sm)
.<prefix>-input:focus  border-color: var(--accent);
                        box-shadow: 0 0 0 2px var(--accent-soft);
                        outline: none
```

Tokens: `--inset`, `--border`, `--accent`, `--accent-soft`, `--text`, `--text-2`,
`--radius`, `--fs-sm`, `--space-3`, `--font-mono`.

## 5 — Panel / card

```
.<prefix>-panel        background: var(--panel); border: 1px solid var(--border);
                        border-radius: var(--radius-lg)
.<prefix>-panel.pad    padding: 16px 18px
```

Tokens: `--panel`, `--border`, `--radius-lg`.

## 6 — Stat strip

> **Plan 007 (2026-08-14, revised same day after blind review):** the stat
> strip is the *dashboard* summary header — see `archetypes.md`. Its rule is
> semantic, not positional: every stat answers a standing operational
> question, zero renders neutral, thresholds come from alerting semantics,
> and a stat that restates the table below it gets cut. On an *inventory*
> page, counts are filter-bar scope chips instead — there a count's job is
> to filter.
>
> **Corrected 2026-08-15.** This section previously described "a grid of metric
> cards" on a non-clickable `repeat(4, 1fr)` recipe. That is verbatim the
> **decorative summary** that `archetypes.md` names as the Dashboard's banned
> failure mode — the catalog was codifying the shape the archetype bans. The
> ratified grammar (Plan 007 WI-3 review, Q4) is below.

**Segmented clickable cells on one surface — integrated scopes, not metric
cards.** The strip is a *control*: each cell scopes the object list beneath it,
carries an active state, and is a link or button, not a `<div>`. Its cells sit
inside a single bordered surface divided by hairlines; they never become
individually bordered cards. The cell count comes from the domain's questions —
its urgency buckets or scopes, cert-watch has five — not from the grid. The old
`repeat(4, 1fr)` baked a layout default into a semantic decision; four cells is
perfectly fine when the domain has four things to say. (What `archetypes.md`
bans is the *decorative* summary, not the count.)

If a summary value is genuinely *not* an interaction with the object set below,
it does not belong in the strip. Give it a quieter treatment elsewhere (a
cross-reference link, an exception control that is silent at zero) rather than a
sixth cell that looks like a filter and isn't — the strip's semantic contract is
"these are scopes over the inventory immediately below."

```
.<prefix>-stats        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(0, 1fr));
                        border: 1px solid var(--border); border-radius: var(--radius-lg);
                        overflow: hidden
                        -- ONE surface; cell count is domain-driven, not fixed at 4

a.<prefix>-stat        display: block; padding: 10px 14px;      -- compressed
                        border-left: 1px solid var(--border);
                        color: inherit; text-decoration: none
                        -- a link (or button): clicking scopes the list below
a.<prefix>-stat:first-child  border-left: none
a.<prefix>-stat:hover        background: var(--row-hover)
a.<prefix>-stat.active       background: var(--panel-2)
                        -- reflects the filter currently applied

.<prefix>-stat-label   font-family: var(--font-mono); font-size: 10.5px;
                        text-transform: uppercase; letter-spacing: 0.05em;
                        color: var(--text-3); margin-bottom: 4px
.<prefix>-stat-val     font-family: var(--font-mono); font-size: 24px;
                        font-weight: 600; font-variant-numeric: tabular-nums;
                        color: var(--text)
.<prefix>-stat-sub     font-size: var(--fs-xs); color: var(--text-3); margin-top: 2px
                        -- the semantic line: "none" / "needs attention",
                           zero renders neutral
```

Tokens: `--border`, `--panel-2`, `--radius-lg`, `--row-hover`, `--text`,
`--text-3`, `--font-mono`, `--fs-xs`.

## 7 — Pill (status indicator)

An inline-flex dot + label for status. No background, no border.

```
.<prefix>-pill         display: inline-flex; align-items: center; gap: 6px;
                        font-size: var(--fs-sm)
.<prefix>-pill .dot    width: 7px; height: 7px; border-radius: 50%;
                        flex-shrink: 0
```

Tone classes set `.dot` background and text color using status tokens:
`.critical` → `--crit`, `.warning` → `--warn`, `.healthy`/`.ok` → `--ok`,
`.muted`/`.neutral` → `--text-3`. Domain-specific names (`.expired`, `.high`,
`.low`) are fine — map them to the same status tokens.

Tokens: `--ok`, `--warn`, `--crit`, `--text-3`, `--fs-sm`.

## 8 — Chip (metadata tag)

An inline-flex bordered tag for metadata. Mono font.

```
.<prefix>-chip         display: inline-flex; align-items: center;
                        font-family: var(--font-mono); font-size: var(--fs-xs);
                        padding: 2px 8px; border: 1px solid var(--border-2);
                        border-radius: 4px; color: var(--text-2)
```

Tone classes recolor border + text: `.ok` → `--ok`, `.warn` → `--warn`,
`.crit` → `--crit`, `.accent` → `--accent`, `.muted` → `--text-3`.

Tokens: `--border-2`, `--text-2`, `--text-3`, `--ok`, `--warn`, `--crit`,
`--accent`, `--font-mono`, `--fs-xs`.

## 9 — Table

Mono uppercase headers, bordered rows, row-hover highlight.

```
.<prefix>-table-wrap   border: 1px solid var(--border); border-radius: var(--radius-lg);
                        overflow: hidden
.<prefix>-table        width: 100%; border-collapse: collapse
.<prefix>-table th     font-family: var(--font-mono); font-size: 10.5px;
                        text-transform: uppercase; letter-spacing: 0.05em;
                        color: var(--text-3); text-align: left;
                        padding: 10px 14px; border-bottom: 1px solid var(--border)
.<prefix>-table td     padding: 10px 14px; border-bottom: 1px solid var(--border);
                        font-size: var(--fs-sm)
.<prefix>-table tbody tr:hover  background: var(--row-hover)
```

Tokens: `--border`, `--radius-lg`, `--text-3`, `--row-hover`, `--font-mono`,
`--fs-sm`.

## 10 — Empty state

Centred placeholder when a view has no data.

```
.<prefix>-empty        text-align: center; padding: 48px 24px; color: var(--text-3)
.<prefix>-empty .ico   width: 48px; height: 48px; margin: 0 auto 12px;
                        border-radius: 50%; display: flex; align-items: center;
                        justify-content: center; background: var(--panel-2)
.<prefix>-empty .title font-size: var(--fs-md); font-weight: 600;
                        color: var(--text); margin-bottom: 4px
.<prefix>-empty .sub   font-size: var(--fs-sm); color: var(--text-3)
```

Tokens: `--panel-2`, `--text`, `--text-3`, `--fs-md`, `--fs-sm`.

## 11 — Callout / alert

A bordered block with optional icon for status messages.

```
.<prefix>-callout      display: flex; gap: 10px; padding: 12px 14px;
                        border: 1px solid var(--border); border-radius: var(--radius);
                        background: var(--panel-2)
.<prefix>-callout.warn border-color: var(--warn); background: var(--warn-soft)
.<prefix>-callout.crit border-color: var(--crit); background: var(--crit-soft)
.<prefix>-callout.info border-color: var(--info); background: var(--info-soft)
```

Tokens: `--panel-2`, `--border`, `--radius`, `--warn`, `--crit`, `--info`,
`--warn-soft`, `--crit-soft`, `--info-soft`.

## 12 — Drop zone

Dashed-border target for file drops.

```
.<prefix>-drop         border: 2px dashed var(--border-2); border-radius: var(--radius-lg);
                        padding: 32px; text-align: center; color: var(--text-3);
                        background: var(--inset)
.<prefix>-drop:hover   border-color: var(--accent); background: var(--accent-soft)
```

Tokens: `--border-2`, `--accent`, `--accent-soft`, `--inset`, `--text-3`,
`--radius-lg`.

## 13 — Breadcrumb

```
.<prefix>-breadcrumb   display: flex; align-items: center; gap: 6px;
                        font-size: var(--fs-sm); color: var(--text-3)
.<prefix>-breadcrumb a color: var(--text-2)
.<prefix>-breadcrumb a:hover  color: var(--accent)
.<prefix>-breadcrumb .sep    color: var(--text-3); opacity: 0.5
```

Tokens: `--text-2`, `--text-3`, `--accent`, `--fs-sm`.

## 14 — Chain / precedence

A vertical ladder of nodes with a connecting spine — used for certificate trust
chains and GPO precedence.

```
.<prefix>-chain        position: relative; padding-left: 28px
.<prefix>-chain .spine position: absolute; left: 9px; top: 0; bottom: 0;
                        width: 2px; background: var(--border)
.<prefix>-chain .node  position: relative; padding: 12px 0
.<prefix>-chain .node::before  content: ""; position: absolute; left: -24px;
                        top: 16px; width: 10px; height: 10px;
                        border-radius: 50%; border: 2px solid var(--accent);
                        background: var(--bg)
```

Tokens: `--border`, `--accent`, `--bg`.

---

## Adding a new tool

1. Choose a 2–3 letter prefix (`ad-`, `kp-`, etc.).
2. Start with the app shell (§1), topbar (§2), and buttons (§3) — they give
   you a recognisably "family" frame with minimal CSS.
3. Add stat strips, tables, pills, and chips as the tool's views need them.
4. **Colours and spacing come from tokens.** Never write a raw colour — no
   `#hex`, no `rgb()`, no named colour — in tool CSS; draw every one from
   `token-contract.md`. Take sizes and spaces from the `--space-*`, `--radius-*`
   and `--fs-*` scales rather than inventing parallel values.

   The px figures in this catalog (46px, 10.5px, 24px, 1080px, 0.05em…) are
   **reference geometry, not values to paste.** They record the shapes the
   family converged on where no token exists — component heights, optical type
   sizes below `--fs-xs`, the page max-width. Reproduce the *geometry*; if you
   find yourself repeating one, it wants a tool-prefixed token (`--cw-topbar-h`)
   or promotion into the contract. This is why `check_patina.py` ratchets raw
   colour literals mechanically but deliberately does **not** ratchet px: this
   catalog itself specifies px paddings, so a px ratchet would be all noise.
5. Domain-specific patterns (posture grids, grade badges) are fine — just build
   them on the same tokens.
