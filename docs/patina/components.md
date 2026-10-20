<!-- VENDORED FROM patina 0.6.0 (1dffec1) -- patina-owned. Do not edit, reformat or lint this file; edit patina and re-run sync.sh. -->
# Reference components

`components.css` implements the 14 shapes in [patterns.md](patterns.md), using
contract tokens and a neutral `pt-` prefix. `macros/ui.j2` provides the shared
markup. The inventory example at `examples/components.html.j2` is synthetic;
its scope links lead to differently filtered example pages during browser
verification. Existing tools keep their components until deliberate adoption.

## Delivery and ownership

```bash
./sync.sh --components ../tool/templates cert-watch ../tool/static ../tool/tests
```

This adds `static/css/components.css` and `templates/macros/ui.j2`. Link the
stylesheet after `tokens.css` and import the macros in the application's Jinja
environment. Keep templates and checker scripts outside the public static
root. Default sync retains its existing behavior.

Both files have native-comment ownership delimiters, a SHA-256 of the owned
source text and their own recorded Git revision.
Source components use LF via `.gitattributes`; the gate canonicalizes a
consumer's Git CRLF transport to LF for comparison. Consumer tail bytes are
preserved exactly during resync, including a missing final newline.
The normal checker gains
`--components <templates-dir>`; pass `--extra <templates-dir>` to include local
template CSS/classes, and `--upstream` for pinned source comparison. `.j2`
files participate alongside `.html` files. Consumer tails survive sync and
remain subject to normal conformance checks. Existing unmarked or malformed
destinations are refused before token updates; `--adopt` preserves their
original bytes in a backup before replacing them. Commit source before sync.

## Frame

The base template owns the document, CSP, brand and page routes. Use
`.pt-app` as a full-height flex column, `.pt-topbar > .pt-wrap` for chrome,
and `.pt-page > .pt-wrap` for scrollable content. Both wraps share a 1080px
maximum and the same padding. The topbar wraps its controls on small screens.
The example includes the shared `theme.js` before paint and a `theme-toggle`
button; Plan 003's proposed system-default theme is still unratified.

## Macro API

Import once: `{% import "macros/ui.j2" as ui %}`. Required arguments precede
optional arguments. Named optional arguments keep call sites legible.

| Macro | Required arguments | Optional arguments / behavior |
|---|---|---|
| `button` | `label` | `primary`, `disabled`, `loading`, `type`, `id`, `name`, `value`. Default type is `button`; explicit `submit` and `reset` are supported. |
| `icon_button` | `label`, `text` | `id`, `disabled`. Label describes the action; glyph is hidden from accessibility APIs. |
| `nav` | `links` | `label`, `state`. Each link is `(href, text, active, disabled)`; unavailable routes become text. |
| `field` | `id`, `name`, `label` | `value`, `help`, `error`, `type`, `required`, `disabled`, `readonly`, `loading`, `placeholder`. `None` is an empty value; zero stays zero. |
| `select` | `id`, `name`, `label`, `options` | `selected`, `help`, `error`, `required`, `disabled`, `loading`. Options are `(value, text)` pairs; no options disables the control. |
| `panel` | none | `title`; caller supplies the body. |
| `stats` | none | `state`, `message`; caller supplies the scope cells in normal state. |
| `stat` | `label`, `value`, `href` | `sub`, `tone`, `active`, `disabled`. Route scopes the associated object list; `None` displays `Unknown`, zero stays neutral. |
| `pill` | `label` | `tone`; status never uses accent. |
| `chip` | `label` | `tone`; noninteractive metadata. |
| `collection_state` | none | `state`, `message`, `sub`; caller can supply an empty-state action. |
| `table` | `headers`, `rows`, `caption` | `state`, `message`. Each row is a sequence of cell values; headers use `scope="col"`. |
| `callout` | `message` | `tone`, `announce`; caller may supply app-authored extra markup. Announces only when requested. |
| `dropzone` | `id`, `name`, `label` | `help`, `error`, `disabled`, `loading`, `accept`, `multiple`. Labelled native file input; application owns upload and optional whole-zone drag handling. |
| `breadcrumb` | `items` | `label`. Items are `(href, text)` pairs; final node is current-page text. Empty paths omit the landmark. |
| `chain` | `nodes` | `label`, `state`, `message`. Nodes are `(title, sub)` pairs in an ordered list. |

Tones are `neutral`, `ok`, `warn`, `crit`, `info`; `accent` is available for
metadata chips. Unknown tones fall back to neutral. The application maps its
domain states to these tones; the library contains no certificate urgency,
grade, authorization or other domain logic. The dot and colour always have a
text label. Counts are application-provided numbers, never inferred from an
empty or incomplete result.
Table cells display `None` as `Unknown` while retaining measured zeroes.
Stat-cell values use the existing `--fs-md` role from the token contract;
`--fs-2xl` remains reserved for a page's single dominant figure.

Collections use `state="normal"`, `empty`, `loading` or `error`. A normal empty
table or chain supplies its empty state automatically. `stats` callers choose
state explicitly because the wrapper cannot count caller-generated cells.
Loading states expose busy/status semantics; errors expose an alert. Static
pills/chips and the frame have no fabricated loading or disabled behavior.

## Forms and application responsibilities

```jinja
{% call ui.panel('Edit record') %}
  {{ ui.field('record-name', 'name', 'Name', value=name,
              help='Choose a human-readable name.', error=name_error) }}
  {{ ui.button('Save', type='submit', primary=true) }}
{% endcall %}
```

Fields link the label, help and error to a unique control id. The error slot
always reserves at least one line; longer messages can grow for legibility.
Input, select and button heights are 36px, and validation/focus never change
border width. Loading disables the native control. Read-only fields remain
focusable. A table's labelled scroll region is keyboard-focusable, so wide
tables stay reachable without making the page itself overflow.

Use HTML autoescaping in the application's Jinja environment. Macro text and
attributes also escape explicitly so the `.j2` extension does not silently
disable escaping. Caller blocks contain application-authored markup. The
application validates URL destinations, chooses unique ids, supplies valid
rows/options/counts, implements state transitions and owns form processing,
permissions, CSRF and file validation. The reference does not submit data or
attach inline event handlers.

## Verification

`python3 scripts/selftest_components.py` tests ownership, recorded revisions,
safe adoption and tail preservation using disposable Git sources. It is
stdlib-only. `python3 -m unittest discover -s tests` checks real Jinja output;
Jinja 3.1.6 is a test dependency and is already supplied by consumer apps.
The checkers have no new dependencies, and patina has no package/build step.

The synthetic example provides rendered evidence; adoption into the live
agent-notes consumer remains Plan 006 WI-3 and was not performed in this pass.
The optional browser check requires Playwright with its Chromium browser:
`python3 tests/browser_components.py --artifacts <output-dir>`. It builds and
serves a disposable local consumer, exercises both themes and eight scenarios at
four widths, and saves screenshots/results. No live services or consumer
repositories are used.
