"""Pin the contrast of status-coloured TEXT in gpo-lens's own CSS.

patina guarantees ``--ok/--warn/--crit/--info`` >= 4.5:1 only on ``--bg`` and
``--panel``. gpo-lens also renders status text on ``--panel-2``, on a status
colour's own ``-soft`` tint (chips, indicators) and inside tinted containers
(flag/worse/better rows, verdict flag, callouts), where the raw 0.6.0 colours dip
below 4.5:1. gp.css therefore sets status text with
``--gp-{warn,crit,info}-text`` (the status colour nudged toward ``--text``), and
gives a chip inside a tinted container a plain ``--panel`` background so tints
never stack.

The modelled surfaces are DERIVED from gp.css, not hand-listed: every rule whose
background is ``var(--<tone>-soft)`` is a tinted container (or the element's own
tint), and the test asserts each container is covered by the chip override. A new
tinted container that is not covered fails the test. What it does NOT model: text
inside containers that gp.css does not tint but a template styles inline, and
muted (``--text-3``) text, which is below 4.5:1 by patina's own design (see
tests/browser/axe-baseline.json). It checks computed colours, not rendered pixels;
the axe browser gate is the rendered check.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

CSS = Path(__file__).resolve().parent.parent / "src" / "gpo_lens" / "web" / "static" / "css"
TOKENS = (CSS / "tokens.css").read_text(encoding="utf-8")
GP = (CSS / "gp.css").read_text(encoding="utf-8")
FLOOR = 4.5
TONES = ("ok", "warn", "crit", "info")

# selector -> tone: every rule that sets status-coloured text in gp.css.
TEXT_RULES = {
    ".gp-pill.critical": "crit",
    ".gp-pill.high": "warn",
    ".gp-pill.medium": "warn",
    ".gp-pill.info": "info",
    ".gp-pill.ok": "ok",
    ".gp-chip.ok": "ok",
    ".gp-chip.warn": "warn",
    ".gp-chip.crit": "crit",
    ".gp-chip.info": "info",
    ".gp-ind.crit .val": "crit",
    ".gp-ind.warn .val": "warn",
    ".gp-ind.info .val": "info",
    ".gp-allclear b": "ok",
    ".gp-btn-danger": "crit",
}


def _hex(h: str) -> list[float]:
    h = h.lstrip("#")
    return [int(h[i : i + 2], 16) for i in (0, 2, 4)]


def _lum(c: list[float]) -> float:
    def f(v: float) -> float:
        v /= 255
        return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4

    r, g, b = (f(v) for v in c)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast(a: list[float], b: list[float]) -> float:
    hi, lo = sorted((_lum(a), _lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _blend(fg: list[float], alpha: float, bg: list[float]) -> list[float]:
    return [fg[i] * alpha + bg[i] * (1 - alpha) for i in range(3)]


def _themes() -> dict[str, dict[str, str]]:
    text = re.sub(r"/\*.*?\*/", " ", TOKENS, flags=re.S)
    out: dict[str, dict[str, str]] = {}
    for m in re.finditer(r"(:root[^{]*)\{([^}]*)\}", text):
        name = "light" if "light" in m.group(1) else "dark"
        out.setdefault(name, {}).update(
            {k: v.strip() for k, v in re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", m.group(2))}
        )
    return out


def _text_colour(theme: dict[str, str], tone: str) -> list[float]:
    """Resolve the colour gp.css gives status text of this tone."""
    fg = _hex(theme[f"--{tone}"])
    m = re.search(
        rf"--gp-{tone}-text:\s*color-mix\(in srgb,\s*var\(--{tone}\)\s+(\d+)%,\s*var\(--text\)\)",
        GP,
    )
    if m is None:
        return fg
    p = int(m.group(1)) / 100
    return _blend(fg, p, _hex(theme["--text"]))


def _containers() -> dict[str, str]:
    """{selector: tone} for every gp.css rule that tints a background with a
    status ``-soft`` colour (hover/focus pseudo-classes stripped)."""
    css = re.sub(r"/\*.*?\*/", " ", GP, flags=re.S)
    out: dict[str, str] = {}
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", css):
        bg = re.search(r"(?<![-\w])background:\s*var\(--(ok|warn|crit|info)-soft\)", m.group(2))
        if not bg:
            continue
        for raw in m.group(1).split(","):
            sel = re.sub(r":(hover|focus\S*)", "", raw.strip())
            out[sel] = bg.group(1)
    return out


# Elements that carry their own tint AND are the text (handled per tone as the
# element's own surface), or hold no status text at all.
_NOT_CONTAINERS = ("a.gp-ind", ".gp-ind", ".gp-chip", ".gp-btn", ".gp-triage-error")


def _container_tints() -> dict[str, str]:
    return {sel: tone for sel, tone in _containers().items() if not sel.startswith(_NOT_CONTAINERS)}


def _surfaces(theme: dict[str, str], tone: str) -> dict[str, list[float]]:
    """Every surface a text of this tone can sit on: the three bases, its own
    soft tint over each (chip / indicator), and every derived container tint over
    each (a pill or text inside a flag row, callout, ...)."""
    out: dict[str, list[float]] = {}
    tints = {tone: tone, **{f"container {s}": t for s, t in _container_tints().items()}}
    for name in ("bg", "panel", "panel-2"):
        base = _hex(theme[f"--{name}"])
        out[name] = base
        for label, t in tints.items():
            soft = re.match(r"rgba\((\d+),\s*(\d+),\s*(\d+),\s*([\d.]+)\)", theme[f"--{t}-soft"])
            assert soft, theme[f"--{t}-soft"]
            rgb = [float(soft[i]) for i in (1, 2, 3)]
            out[f"{label} tint on {name}"] = _blend(rgb, float(soft[4]), base)
    return out


def test_every_tinted_container_is_derived_and_covers_chips() -> None:
    """Chips inside a container must not stack their tint on the container's."""
    containers = _container_tints()
    assert any("tr.flag" in sel for sel in containers), containers
    m = re.search(r":is\(([^)]*)\)\s*\.gp-chip\s*\{[^}]*background-color:\s*var\(--panel\)", GP)
    assert m, "the plain-panel chip override for tinted containers is missing"
    overrides = [x.strip() for x in m.group(1).split(",")]
    for sel in containers:
        last = sel.split()[-1]
        assert any(last.startswith(o) for o in overrides), (
            f"tinted container {sel!r} is not in the chip override {overrides}; a chip in it "
            "would sit on its own tint stacked over the container tint"
        )


@pytest.mark.parametrize("theme_name", ["dark", "light"])
@pytest.mark.parametrize("tone", TONES)
def test_status_text_meets_aa_on_every_surface(theme_name: str, tone: str) -> None:
    theme = _themes()[theme_name]
    fg = _text_colour(theme, tone)
    for surface, bg in _surfaces(theme, tone).items():
        ratio = _contrast(fg, bg)
        assert ratio >= FLOOR, f"{theme_name} {tone} text on {surface}: {ratio:.2f}:1 < {FLOOR}"


def _color_of(selector: str) -> str:
    # Last rule whose selector list contains `selector` and sets `color:`.
    found = ""
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", re.sub(r"/\*.*?\*/", " ", GP, flags=re.S)):
        sels = [s.strip() for s in m.group(1).split(",")]
        decl = re.search(r"(?<![-\w])color:\s*([^;]+)", m.group(2))
        if selector in sels and decl:
            found = decl.group(1).strip()
    return found


@pytest.mark.parametrize(("selector", "tone"), sorted(TEXT_RULES.items()))
def test_status_text_rules_use_the_pinned_colour(selector: str, tone: str) -> None:
    colour = _color_of(selector)
    allowed = {f"var(--{tone})", f"var(--gp-{tone}-text)"}
    assert colour in allowed, f"{selector}: unexpected colour {colour!r}"
    if tone != "ok":
        assert colour == f"var(--gp-{tone}-text)", (
            f"{selector} uses the raw --{tone}; it is below 4.5:1 on some surfaces"
        )
