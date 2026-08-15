#!/usr/bin/env python3
# patina:sha256 dab5b461ad26df663634f7534da6d383d096c2d2cca5d5d68e1e26ac4adc5857 rev:21ab0c3
"""check_patina.py -- the patina conformance gate (Plan 005).

Verifies that a consuming tool's vendored patina assets have not drifted and
that the tool's own CSS honours the token contract. Stdlib only; every family
tool is Python. Vendored into consumers by sync.sh as patina-check.py.

Checks:
  0. self stamp     -- a vendored copy carries a `# patina:sha256 <hash>` line
                       directly under the shebang; the gate hashes itself and
                       refuses to run if its own bytes were edited. Running
                       from a patina checkout (unstamped) is fine and noted.
  1. tokens block   -- css/tokens.css must carry EXACTLY ONE
                       /* patina:begin <rev> sha256:<hash> */ ... /* patina:end */
                       pair, in that order, whose bytes hash to the stamp.
                       Consumers may append CSS below the end marker -- that
                       tail is checked like any other tool CSS (checks 3+4).
  2. theme.js stamp -- first line // patina:sha256 <hash> must match the rest
                       of the file's bytes.
  3. token contract -- every var(--x) referenced in tool CSS must be defined
                       by the contract block or by the tool itself; the tool
                       must not redefine a contract token; with --prefix, all
                       tool-defined tokens must carry --<prefix>-.
  4. colour ratchet -- raw colour literals (#hex / rgb / hsl / oklch) in tool
                       CSS are fingerprinted against a committed baseline.
                       A NEW fingerprint fails even if the total is unchanged,
                       so a violation cannot be swapped for another one.
                       Removing one always passes. A line may be exempted with
                       `patina-allow: <reason>`; the reason is mandatory and
                       the number of exemptions is itself ratcheted. Size (px)
                       ratcheting was considered and deliberately deferred:
                       patterns.md itself specifies px paddings, so a px
                       ratchet is all noise today.

What check 1 does and does not prove:

  Without --upstream, the block hash is compared against a stamp stored in the
  same file. That proves INTEGRITY (nothing mangled the block after vendoring)
  and nothing else: anyone who edits a token value can recompute the stamp. To
  check actual DRIFT, pass --upstream <patina-checkout> (a git checkout).

  --upstream keeps two conditions apart, because conflating them makes a
  vendored standard behave like a coupled one:
    DRIFT (fails)  the block does not match patina AT THE REV IT IS STAMPED
                   WITH -- edited and re-stamped, or that history is gone.
    UPGRADE (note) patina has advanced past that rev. Adopting it is a
                   deliberate consumer change with a reviewable diff. A newer
                   upstream is never a conformance failure.

Usage:
  check_patina.py <static-dir> [--tokens css/tokens.css] [--theme theme.js]
                  [--no-theme] [--prefix cw] [--extra <dir>]...
                  [--upstream <patina-checkout>]
                  [--ratchet-file <path>] [--update-ratchet] [--report]

Exit: 0 clean (or --report), 1 on any failure, 2 on usage error.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

BEGIN_RE = re.compile(
    r"^/\* patina:begin (?P<rev>\S+) sha256:(?P<hash>[0-9a-f]{64}) \*/$", re.M
)
END_RE = re.compile(r"^/\* patina:end \*/$", re.M)
ACCENT_RE = re.compile(r"^/\* accent: (?P<accent>[A-Za-z0-9._-]+) \*/$", re.M)
THEME_STAMP_RE = re.compile(r"^// patina:sha256 (?P<hash>[0-9a-f]{64})")
SELF_STAMP_RE = re.compile(r"^# patina:sha256 (?P<hash>[0-9a-f]{64}) rev:(?P<rev>\S+)$")
TOKEN_DEF_RE = re.compile(r"(--[A-Za-z0-9_-]+)\s*:")
TOKEN_REF_RE = re.compile(r"var\(\s*(--[A-Za-z0-9_-]+)")
COLOR_RE = re.compile(r"(#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(|\boklch\()")
STYLE_BLOCK_RE = re.compile(r"<style[^>]*>(.*?)</style>", re.DOTALL | re.IGNORECASE)
INLINE_STYLE_RE = re.compile(r"""\bstyle\s*=\s*["']([^"']*)["']""", re.IGNORECASE)

# `patina-allow` alone is not enough -- an escape hatch with no stated reason
# is just a disabled check. The reason must be substantive (>= 4 chars).
ALLOW_RE = re.compile(r"patina-allow:\s*(?P<reason>\S.{3,})")
ALLOW_MARK = "patina-allow"

RATCHET_VERSION = 2


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def strip_comments_keep_lines(text: str) -> str:
    """Blank out /* ... */ spans but keep newlines so line numbers hold."""
    out = []
    i, n = 0, len(text)
    while i < n:
        j = text.find("/*", i)
        if j < 0:
            out.append(text[i:])
            break
        out.append(text[i:j])
        k = text.find("*/", j + 2)
        if k < 0:
            k = n - 2
        span = text[j : k + 2]
        out.append("".join(c if c == "\n" else " " for c in span))
        i = k + 2
    return "".join(out)


class Source:
    """A chunk of tool-owned CSS, with enough provenance for a useful error."""

    def __init__(self, label, text, line_offset=0):
        self.label = label
        self.text = text
        self.line_offset = line_offset  # lines preceding `text` in its file

    def at(self, i):
        return f"{self.label}:{self.line_offset + i + 1}"


class Gate:
    def __init__(self):
        self.failures = []
        self.notes = []

    def ok(self, msg):
        self.notes.append(f"[ok]   {msg}")

    def note(self, msg):
        self.notes.append(f"[note] {msg}")

    def fail(self, msg):
        self.failures.append(f"[FAIL] {msg}")


def check_self(gate: Gate):
    """A vendored copy must match its own stamp. The enforcement mechanism is
    the highest-leverage single file in the system; an unstamped, silently
    edited checker passes everything."""
    try:
        text = Path(__file__).resolve().read_text(encoding="utf-8")
    except OSError:
        return
    lines = text.split("\n")
    if len(lines) < 2:
        return
    m = SELF_STAMP_RE.match(lines[1])
    if not m:
        gate.note(
            "checker is unstamped -- running from a patina checkout "
            "(a vendored copy is stamped by sync.sh)"
        )
        return
    rest = "\n".join(lines[2:])
    if sha256_text(rest) != m.group("hash"):
        gate.fail(
            "patina-check.py: this checker's own bytes differ from its stamp "
            "-- the gate was edited in the consumer; re-run patina's sync.sh"
        )
    else:
        gate.ok(f"checker intact (patina {m.group('rev')})")


def split_vendored(text: str):
    """-> (rev, stamp, block, tail, tail_line_offset) or (None, err, ...).

    Fails closed. Exactly one begin marker and one end marker, in that order,
    or we refuse to interpret the file at all: every ambiguous shape here is
    either a mangled vendor or a consumer about to lose CSS.
    """
    begins = list(BEGIN_RE.finditer(text))
    ends = list(END_RE.finditer(text))
    if not begins and not ends:
        return None, "no stamped patina block found", None, None, 0
    if len(begins) != 1 or len(ends) != 1:
        return (
            None,
            f"malformed vendor markers ({len(begins)} begin, {len(ends)} end; "
            "expected exactly one of each) -- resolve by hand; re-syncing "
            "will not fix a duplicated marker",
            None,
            None,
            0,
        )
    b, e = begins[0], ends[0]
    if e.start() < b.end():
        return None, "patina:end appears before patina:begin", None, None, 0
    block = text[b.end() + 1 : e.start()]
    tail = text[e.end() :]
    tail = tail[1:] if tail.startswith("\n") else tail
    tail_offset = text[: e.end()].count("\n") + 1
    return b.group("rev"), b.group("hash"), block, tail, tail_offset


def stamped_rev(tokens_path: Path):
    """The patina revision a vendored file claims, or None."""
    if not tokens_path.is_file():
        return None
    m = BEGIN_RE.search(tokens_path.read_text(encoding="utf-8"))
    return m.group("rev") if m else None


def check_tokens_block(gate: Gate, tokens_path: Path, upstream: Path | None):
    """Returns (contract token names, tail Source or None)."""
    if not tokens_path.is_file():
        gate.fail(f"tokens file missing: {tokens_path}")
        return set(), None
    text = tokens_path.read_text(encoding="utf-8")
    rev, stamp_or_err, block, tail, tail_offset = split_vendored(text)
    if rev is None:
        gate.fail(
            f"{tokens_path.name}: {stamp_or_err} "
            "(unstamped legacy vendored copy, or hand-maintained fork) -- "
            "re-run patina's sync.sh"
        )
        # Fall back to treating the whole file as the contract so the
        # name checks still produce useful output during migration.
        return set(TOKEN_DEF_RE.findall(strip_comments_keep_lines(text))), None

    actual = sha256_text(block)
    if actual != stamp_or_err:
        gate.fail(
            f"{tokens_path.name}: patina block was EDITED after vendoring "
            f"(stamp {stamp_or_err[:12]}..., actual {actual[:12]}...) -- "
            "edit patina and re-sync instead"
        )
    elif upstream is not None:
        check_upstream(gate, text, block, rev, upstream)
    else:
        gate.ok(
            f"tokens block matches its stamp (patina {rev}) -- integrity only; "
            "pass --upstream to check drift against patina"
        )

    contract = set(TOKEN_DEF_RE.findall(strip_comments_keep_lines(block)))
    if not contract:
        gate.fail(
            f"{tokens_path.name}: the vendored block defines no tokens "
            "(truncated or corrupt) -- a validly stamped empty block would "
            "silently disable every contract check"
        )
    tail_src = None
    if tail and tail.strip():
        tail_src = Source(f"{tokens_path.name}(below patina:end)", tail, tail_offset)
    return contract, tail_src


def _git(upstream: Path, *args):
    """-> stdout, or None if git failed. Read-only queries only."""
    proc = subprocess.run(
        ["git", "-C", str(upstream), *args], capture_output=True, text=True
    )
    return proc.stdout if proc.returncode == 0 else None


def _derive(tokens_text: str, accent_text: str) -> str:
    """The bytes sync.sh places between the delimiters, reproduced exactly."""
    return tokens_text + "\n" + accent_text


def check_upstream(gate: Gate, vendored_text: str, block: str, rev: str, upstream: Path):
    """Compare the vendored block against patina AT THE REVISION IT CLAIMS, and
    report a newer upstream separately.

    These are two different conditions and conflating them is what makes a
    vendored standard behave like a coupled one:

      1. the block does not match the rev it is stamped with  -- DRIFT, fail.
         Someone edited the vendored copy and re-stamped it, or the history it
         names was rewritten underneath it.
      2. patina has moved on since that rev                   -- an available
         upgrade, not a defect. Adopting it is a deliberate consumer change
         with a reviewable diff, which is the entire point of vendoring.

    An earlier version of this function compared against the upstream working
    tree, so condition 2 was reported as condition 1 and a single commit to
    patina turned every consumer in the estate red.
    """
    am = ACCENT_RE.search(vendored_text)
    if not am:
        gate.fail(
            "cannot verify against upstream: vendored tokens.css has no "
            "/* accent: <name> */ header -- re-run sync.sh"
        )
        return
    accent = am.group("accent")
    tokens_rel, accent_rel = "tokens.css", f"accents/{accent}.css"

    if _git(upstream, "rev-parse", "--git-dir") is None:
        gate.fail(
            f"--upstream {upstream} is not a git checkout. The stamped revision "
            "is what makes 'stale' distinguishable from 'edited'; without "
            "history the comparison cannot tell them apart, so it is refused "
            "rather than guessed."
        )
        return
    if _git(upstream, "cat-file", "-e", f"{rev}^{{commit}}") is None:
        gate.fail(
            f"the vendored copy is stamped patina {rev}, which does not exist "
            f"in {upstream} -- fetch it, or the branch it came from was "
            "rebased/squashed and that revision is gone. Re-sync from a "
            "revision that exists, so the stamp names something checkable."
        )
        return

    pinned_tokens = _git(upstream, "show", f"{rev}:{tokens_rel}")
    pinned_accent = _git(upstream, "show", f"{rev}:{accent_rel}")
    if pinned_tokens is None or pinned_accent is None:
        gate.fail(
            f"patina {rev} does not contain {tokens_rel} and {accent_rel} -- "
            "the stamp names a revision that predates this accent, or the "
            "checkout is not patina"
        )
        return

    if sha256_text(_derive(pinned_tokens, pinned_accent)) != sha256_text(block):
        gate.fail(
            f"tokens block DRIFTED from patina {rev} (accent {accent}): the "
            "vendored bytes do not match what patina held at the revision this "
            "copy claims. It was edited and re-stamped -- edit patina and "
            "re-sync instead."
        )
        return
    gate.ok(f"tokens block matches patina at its stamped rev {rev} (accent {accent})")

    # Condition 2, reported and never failed.
    head = (_git(upstream, "rev-parse", "--short", "HEAD") or "").strip()
    head_tokens = _git(upstream, "show", f"HEAD:{tokens_rel}")
    head_accent = _git(upstream, "show", f"HEAD:{accent_rel}")
    if head_tokens is None or head_accent is None or not head:
        return
    if sha256_text(_derive(head_tokens, head_accent)) != sha256_text(block):
        gate.note(
            f"patina has advanced since {rev} (upstream HEAD {head}) -- an "
            "upgrade is available. Adopting it is a deliberate re-sync with a "
            "reviewable diff, not a conformance failure."
        )


def check_theme(gate: Gate, theme_path: Path):
    if not theme_path.is_file():
        gate.fail(f"theme.js missing: {theme_path}")
        return
    text = theme_path.read_text(encoding="utf-8")
    first_nl = text.find("\n")
    first, rest = text[: first_nl + 1], text[first_nl + 1 :]
    m = THEME_STAMP_RE.match(first)
    if not m:
        gate.fail("theme.js: no patina:sha256 stamp on line 1 -- re-run sync.sh")
        return
    if sha256_text(rest) != m.group("hash"):
        gate.fail("theme.js: bytes differ from stamp -- edited or stale; re-sync")
    else:
        gate.ok("theme.js intact")


def tool_css_sources(static_dir: Path, tokens_path: Path, extra_dirs=()):
    """Every chunk of CSS the tool owns: non-vendored .css files, <style> blocks
    and inline style="..." attributes in .html. The vendored tokens.css is
    excluded here -- its below-marker tail is added separately by the caller,
    because that region is consumer-owned and must not escape the gate."""
    sources = []
    for root in (static_dir, *extra_dirs):
        for p in sorted(root.rglob("*.css")):
            if p.resolve() == tokens_path.resolve():
                continue
            sources.append(Source(p.name, p.read_text(encoding="utf-8")))
        for p in sorted(root.rglob("*.html")):
            text = p.read_text(encoding="utf-8")
            for i, block in enumerate(STYLE_BLOCK_RE.findall(text)):
                sources.append(Source(f"{p.name}<style#{i + 1}>", block))
            inline = INLINE_STYLE_RE.findall(text)
            if inline:
                sources.append(Source(f"{p.name}[style=]", "\n".join(inline)))
    return sources


def check_contract(gate: Gate, contract: set, sources, prefix: str | None):
    defined, referenced = {}, {}
    for src in sources:
        text = strip_comments_keep_lines(src.text)
        for name in TOKEN_DEF_RE.findall(text):
            defined.setdefault(name, src.label)
        for name in TOKEN_REF_RE.findall(text):
            referenced.setdefault(name, src.label)

    for name, label in sorted(defined.items()):
        if name in contract:
            gate.fail(
                f"{label}: redefines contract token {name} -- "
                "contract values change in patina, not in a consumer"
            )
        elif prefix and not name.startswith(f"--{prefix}-"):
            gate.fail(
                f"{label}: local token {name} lacks the --{prefix}- prefix "
                "(contract rule: shared tokens unprefixed, tool tokens prefixed)"
            )
    undefined = {
        n: l for n, l in referenced.items() if n not in contract and n not in defined
    }
    for name, label in sorted(undefined.items()):
        gate.fail(f"{label}: var({name}) resolves to nothing (typo or drift)")
    if not undefined:
        gate.ok(
            f"token contract: {len(referenced)} names referenced, all resolve "
            f"({len(defined)} tool-local)"
        )


def fingerprint(label: str, line: str) -> str:
    """Identity of a violation: which file, and what the line says -- not where
    it sits, so reformatting and reordering don't churn the baseline."""
    return sha256_text(f"{label}\x00{' '.join(line.split())}")[:16]


def scan_colour_literals(gate: Gate, sources):
    """-> (violations {fp: {...}}, allow_count). Records a failure for every
    exemption that omits a reason."""
    violations, allows = {}, 0
    for src in sources:
        raw_lines = src.text.splitlines()
        exempt = set()
        for i, line in enumerate(raw_lines):
            if ALLOW_MARK not in line:
                continue
            if ALLOW_RE.search(line):
                exempt.add(i)
                allows += 1
            else:
                gate.fail(
                    f"{src.at(i)}: `{ALLOW_MARK}` without a reason -- write "
                    "`/* patina-allow: <why this literal must stay> */`"
                )
        for i, line in enumerate(strip_comments_keep_lines(src.text).splitlines()):
            if i in exempt:
                continue
            hits = COLOR_RE.findall(line)
            if not hits:
                continue
            fp = fingerprint(src.label, line)
            rec = violations.setdefault(
                fp,
                {"n": 0, "where": src.label, "sample": line.strip()[:70]},
            )
            rec["n"] += len(hits)
    return violations, allows


def load_ratchet(gate: Gate, path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        gate.fail(f"ratchet file {path} is unreadable: {exc}")
        return None
    if not isinstance(data, dict) or data.get("version") != RATCHET_VERSION:
        gate.fail(
            f"ratchet file {path} is not version {RATCHET_VERSION} (a scalar "
            "count cannot detect a swapped violation) -- re-baseline with "
            "--update-ratchet and review the diff"
        )
        return None
    return data


def write_ratchet(path: Path, violations, allows):
    payload = {
        "version": RATCHET_VERSION,
        "allows": allows,
        "color_literals": sorted(
            (
                {"fp": fp, "n": v["n"], "where": v["where"], "sample": v["sample"]}
                for fp, v in violations.items()
            ),
            key=lambda r: (r["where"], r["sample"]),
        ),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def check_ratchet(gate: Gate, sources, ratchet_file: Path, update: bool):
    violations, allows = scan_colour_literals(gate, sources)
    total = sum(v["n"] for v in violations.values())

    if update:
        write_ratchet(ratchet_file, violations, allows)
        gate.ok(
            f"ratchet baselined: {total} colour literals in {len(violations)} "
            f"lines, {allows} exemption(s) -> {ratchet_file}"
        )
        return
    if not ratchet_file.is_file():
        gate.fail(
            f"no ratchet baseline at {ratchet_file} -- run once with "
            f"--update-ratchet to record the current state ({total} literals)"
        )
        return
    data = load_ratchet(gate, ratchet_file)
    if data is None:
        return

    baseline = {r["fp"]: r for r in data.get("color_literals", [])}
    new = []
    for fp, v in violations.items():
        was = baseline.get(fp, {}).get("n", 0)
        if v["n"] > was:
            new.append(f"{v['where']}: {v['sample']}" + ("" if was == 0 else f"  (was {was}, now {v['n']})"))
    if new:
        gate.fail(
            f"colour-literal ratchet: {len(new)} NEW violation(s) not in the "
            "baseline. Swapping one violation for another does not pass -- use "
            "tokens, or `/* patina-allow: <reason> */`:\n         "
            + "\n         ".join(sorted(new)[:5])
        )

    gone = sorted(
        f"{r['where']}: {r['sample']}"
        for fp, r in baseline.items()
        if violations.get(fp, {}).get("n", 0) < r["n"]
    )
    if gone:
        gate.note(
            f"{len(gone)} baselined violation(s) fixed -- re-baseline with "
            "--update-ratchet to lock the improvement in:\n         "
            + "\n         ".join(gone[:5])
        )

    recorded_allows = data.get("allows", 0)
    if allows > recorded_allows:
        gate.fail(
            f"exemption ratchet: {allows} `{ALLOW_MARK}` lines > recorded "
            f"{recorded_allows}. Exemptions are ratcheted too, or the hatch "
            "becomes the mechanism."
        )
    if not new:
        gate.ok(
            f"colour-literal ratchet holds ({total} literals, "
            f"{allows} exemption(s))"
        )


# --- the adoption declaration (patina.toml) --------------------------------
#
# Conformance is a set of independent claims, not a ladder. A scalar level
# cannot express "this tier does not apply to this tool", which is a different
# fact from "this tool stopped here" -- and numbering the tiers implies that a
# higher number is better, which people and agents optimise toward whatever the
# prose says.
#
# patina fixes which MECHANISMS are legal for each facet; the consumer picks
# among them. A tool cannot claim `enforced` for something no script decides,
# because then machine proof, human review and author attestation become
# visually interchangeable in the output, which is the whole value of typing
# them separately.

FACETS = {
    "vendor": {
        "label": "vendor",
        "legal": {"enforced"},
        "about": "the vendored patina block is intact and matches its stamp",
    },
    "contract": {
        "label": "contract",
        "legal": {"enforced", "deferred"},
        "about": "token references resolve, no contract shadowing, prefix rule",
    },
    "content_model": {
        "label": "content model",
        "legal": {"reviewed", "attested", "advisory", "deferred", "not-applicable"},
        "about": "each concept has one reachable editing surface (UI-INVENTORY)",
    },
    "structure": {
        "label": "structure",
        "legal": {"reviewed", "deferred", "not-applicable"},
        "about": "surface briefs exist; no unjustified known failure modes",
    },
}

# `deferred` needs a trigger, not just an excuse: "deferred pending a second
# editing surface" is a decision, "deferred, not worth it" is a graveyard.
STATE_REQUIRES = {
    "enforced": (),
    "advisory": (),
    "attested": (),
    "reviewed": ("reviewed_through",),
    "deferred": ("why", "until"),
    "not-applicable": ("why",),
}

STATE_MECHANISM = {
    "enforced": "machine",
    "advisory": "machine, non-blocking",
    "attested": "author claim",
    "reviewed": "human",
    "deferred": "--",
    "not-applicable": "--",
}

MIN_REASON = 12


def load_declaration(gate: Gate, path: Path):
    import tomllib

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        gate.fail(f"declaration {path} is unreadable: {exc}")
        return None

    decl = data.get("patina")
    if not isinstance(decl, dict):
        gate.fail(f"{path.name}: missing a [patina] table")
        return None

    conformance = data.get("conformance", {})
    if not isinstance(conformance, dict) or not conformance:
        gate.fail(
            f"{path.name}: missing [conformance.<facet>] tables. Declaring "
            "nothing is not the same as claiming nothing -- state each facet."
        )
        return None

    for name, spec in conformance.items():
        if name not in FACETS:
            gate.fail(
                f"{path.name}: unknown conformance facet '{name}' "
                f"(known: {', '.join(sorted(FACETS))})"
            )
            continue
        if not isinstance(spec, dict) or "state" not in spec:
            gate.fail(f"{path.name}: [conformance.{name}] has no state")
            continue
        state = spec["state"]
        if state not in STATE_REQUIRES:
            gate.fail(
                f"{path.name}: [conformance.{name}] unknown state '{state}' "
                f"(known: {', '.join(sorted(STATE_REQUIRES))})"
            )
            continue
        if state not in FACETS[name]["legal"]:
            gate.fail(
                f"{path.name}: [conformance.{name}] cannot be '{state}' -- "
                f"legal here: {', '.join(sorted(FACETS[name]['legal']))}. "
                f"({FACETS[name]['label']} is decided by "
                f"{'a script' if 'enforced' in FACETS[name]['legal'] else 'a human'}.)"
            )
            continue
        for field in STATE_REQUIRES[state]:
            value = str(spec.get(field, "")).strip()
            if field in ("why", "until") and len(value) < MIN_REASON:
                gate.fail(
                    f"{path.name}: [conformance.{name}] is '{state}' and needs a "
                    f"substantive `{field}`. An unexplained exemption is just a "
                    "disabled check."
                )
            elif not value:
                gate.fail(
                    f"{path.name}: [conformance.{name}] is '{state}' and needs "
                    f"`{field}`"
                )

    missing = sorted(set(FACETS) - set(conformance))
    if missing:
        gate.fail(
            f"{path.name}: no claim made for {', '.join(missing)}. Silence is "
            "the condition this file exists to remove -- use 'deferred' or "
            "'not-applicable' with a reason."
        )
    return {"patina": decl, "conformance": conformance, "path": path}


def check_declared_version(gate: Gate, decl, rev: str, upstream: Path | None):
    """The consumer declares which patina release it tracks; the stamp records
    which revision it actually vendored. They must agree."""
    declared = str(decl["patina"].get("version", "")).strip()
    if not declared:
        gate.fail(f"{decl['path'].name}: [patina] has no version")
        return
    if upstream is None:
        gate.note(f"declares patina {declared} (unverified; pass --upstream)")
        return
    vendored = _git(upstream, "show", f"{rev}:VERSION")
    if vendored is None:
        gate.note(
            f"declares patina {declared}; the vendored rev {rev} predates "
            "VERSION, so the claim cannot be checked"
        )
        return
    vendored = vendored.strip()
    if vendored != declared:
        gate.fail(
            f"declares patina {declared} but the vendored revision {rev} is "
            f"patina {vendored}. Re-sync, or correct the declaration."
        )
    else:
        gate.ok(f"declared version {declared} matches the vendored revision")


def check_review_freshness(gate: Gate, decl):
    """A `reviewed` claim names the commit it was reviewed through, so the tool
    can say whether anything happened afterwards. A timeless boolean stays green
    forever while the pages change underneath it.

    Scoping this to UI-relevant paths is the obvious refinement and is
    deliberately not done yet -- storing the revision is already the hard part.
    """
    repo = decl["path"].resolve().parent
    for name, spec in sorted(decl["conformance"].items()):
        if spec.get("state") != "reviewed":
            continue
        through = str(spec.get("reviewed_through", "")).strip()
        if _git(repo, "rev-parse", "--git-dir") is None:
            gate.note(f"{name}: reviewed through {through} (not a git checkout)")
            continue
        if _git(repo, "cat-file", "-e", f"{through}^{{commit}}") is None:
            gate.fail(
                f"[conformance.{name}] is reviewed through {through}, which is "
                "not a commit in this repository"
            )
            continue
        head = (_git(repo, "rev-parse", "HEAD") or "").strip()
        full = (_git(repo, "rev-parse", through) or "").strip()
        if head and full and head != full:
            n = (_git(repo, "rev-list", "--count", f"{full}..HEAD") or "?").strip()
            spec["_stale"] = f"{n} commit(s) since review"


def facet_report(decl):
    """One line per facet, states typed, mechanism visible, and deliberately no
    rollup score: 3/4 would be read as worse than 4/4 and we would have
    reinvented the ladder with more syntax."""
    lines = ["", "conformance (declared):"]
    for name in FACETS:
        spec = decl["conformance"].get(name, {})
        state = spec.get("state", "undeclared")
        mark = {
            "enforced": "ok ",
            "advisory": " ~ ",
            "attested": "ok ",
            "reviewed": "ok ",
            "deferred": " - ",
            "not-applicable": "n/a",
        }.get(state, " ? ")
        if state == "reviewed" and spec.get("_stale"):
            mark = " ! "
        lines.append(
            f"  {mark} {FACETS[name]['label']:<14} {state:<15} "
            f"[{STATE_MECHANISM.get(state, '?')}]"
        )
        # Details go on their own lines, in full. Truncating them mid-word to
        # fit a column defeats the point: the reason IS the artifact.
        if state == "reviewed":
            through = str(spec.get("reviewed_through", "?"))[:12]
            extra = f" -- {spec['_stale']}" if spec.get("_stale") else ""
            lines.append(f"        reviewed through {through}{extra}")
        if spec.get("why"):
            lines.append(f"        why:   {spec['why']}")
        if spec.get("until"):
            lines.append(f"        until: {spec['until']}")
        # A claim is rarely all-or-nothing: cert-watch's content model IS
        # reviewed and has five enumerated open violations. Without somewhere to
        # say so the only honest options were to overclaim or to declare the
        # whole facet deferred, which would erase the review that happened.
        if spec.get("note"):
            lines.append(f"        note:  {spec['note']}")
    return lines


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("static_dir", type=Path)
    ap.add_argument("--tokens", default="css/tokens.css")
    ap.add_argument("--theme", default="theme.js")
    ap.add_argument(
        "--no-theme",
        action="store_true",
        help="consumer owns its theme bootstrap (e.g. a CSP-nonced inline "
        "script); skip the theme.js check",
    )
    ap.add_argument("--prefix", default=None)
    ap.add_argument(
        "--extra",
        type=Path,
        action="append",
        default=[],
        help="additional root to scan for tool CSS (e.g. a templates/ dir "
        "outside static/); repeatable",
    )
    ap.add_argument(
        "--upstream",
        type=Path,
        default=None,
        help="path to a patina checkout; re-derives the vendored block from it "
        "and reports real drift instead of mere integrity",
    )
    ap.add_argument(
        "--declaration",
        type=Path,
        default=None,
        help="path to the consumer's patina.toml adoption declaration; the "
        "conformance facets it claims are validated and reported",
    )
    ap.add_argument("--ratchet-file", type=Path, default=None)
    ap.add_argument("--update-ratchet", action="store_true")
    ap.add_argument(
        "--report",
        action="store_true",
        help="print status but always exit 0 (advisory; never use in CI)",
    )
    args = ap.parse_args()

    static_dir = args.static_dir
    if not static_dir.is_dir():
        print(f"error: not a directory: {static_dir}", file=sys.stderr)
        return 2
    for extra in args.extra:
        if not extra.is_dir():
            print(f"error: --extra is not a directory: {extra}", file=sys.stderr)
            return 2
    if args.upstream is not None and not args.upstream.is_dir():
        print(f"error: --upstream is not a directory: {args.upstream}", file=sys.stderr)
        return 2
    tokens_path = static_dir / args.tokens
    ratchet_file = args.ratchet_file or static_dir / "patina-ratchet.json"

    gate = Gate()
    decl = None
    if args.declaration is not None:
        if not args.declaration.is_file():
            print(f"error: no declaration at {args.declaration}", file=sys.stderr)
            return 2
        decl = load_declaration(gate, args.declaration)
    check_self(gate)
    if args.ratchet_file is None:
        gate.note(
            f"ratchet baseline defaults to {ratchet_file}, inside the served "
            "static root -- pass --ratchet-file to keep it out of the webroot"
        )
    contract, tail_src = check_tokens_block(gate, tokens_path, args.upstream)
    if decl is not None:
        rev = stamped_rev(tokens_path)
        if rev:
            check_declared_version(gate, decl, rev, args.upstream)
        check_review_freshness(gate, decl)
    if not args.no_theme:
        check_theme(gate, static_dir / args.theme)
    sources = tool_css_sources(static_dir, tokens_path, args.extra)
    if tail_src is not None:
        sources.append(tail_src)

    contract_state = "enforced"
    if decl is not None:
        contract_state = decl["conformance"].get("contract", {}).get("state", "enforced")
    if contract_state == "deferred":
        gate.note(
            "contract checks skipped: declared deferred. The declaration names "
            "why and what would reverse it -- this is a visible choice, not a "
            "silent gap."
        )
    elif contract:
        check_contract(gate, contract, sources, args.prefix)
    check_ratchet(gate, sources, ratchet_file, args.update_ratchet)

    for line in gate.notes + gate.failures:
        print(line)
    if decl is not None:
        for line in facet_report(decl):
            print(line)
    if gate.failures:
        print(f"\ncheck_patina: {len(gate.failures)} failure(s)")
        if args.report:
            print("(--report: exiting 0 despite failures)")
            return 0
        return 1
    print("\ncheck_patina: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
