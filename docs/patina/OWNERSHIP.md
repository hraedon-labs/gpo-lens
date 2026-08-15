# Who owns what in this directory

Everything in here except this file is **patina-owned**: vendored verbatim from
the patina repository and verified by `check_patina.py --docs`. Do not edit,
reformat, or lint these files. Exclude this directory from your formatter --
"vendored code stays byte-identical" and "all repository files satisfy our
formatter" are both correct rules, and they collide here.

**patina-owned** (upstream decides; a sync overwrites your changes):
  the vendored docs in this directory, `patina-check.py`, the patina block in
  `css/tokens.css`, `theme.js`, `fonts/`.

**Consumer-owned** (you decide; a sync never touches these):
  `patina.toml` -- your conformance declaration, including which facets you
  claim and the evidence for them; `UI-INVENTORY.md`; your surface briefs and
  any recorded deviations; your ratchet baseline; all of your own CSS,
  including anything below the `/* patina:end */` marker.

The standard is upstream-owned. What you claim about your adoption of it is
yours.
