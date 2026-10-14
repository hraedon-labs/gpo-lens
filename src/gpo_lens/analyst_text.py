"""Refuse analyst-typed text that carries GPP ``cpassword`` material.

Since schema v11 every ``cpassword`` value is redacted at ingest and no hash or
fingerprint of one is kept (see :mod:`gpo_lens.redaction`). Output masking can
therefore no longer learn a value from the database, so text an analyst types
*after* ingest (a triage note or rationale, an Ask question) would be stored or
sent exactly as typed. A cpassword is AES-encrypted with the key Microsoft
published (MS14-025), so its ciphertext is effectively the password, and the
triage log is append-only: a pasted value would persist.

:func:`check_analyst_text` is the one guard every analyst-text write or
emission goes through (``tests/test_analyst_text_guard.py`` enumerates them).
It **refuses** — it never rewrites — text that contains:

(a) a *labelled* cpassword in any form the ingest redactor recognises:
    :func:`redaction.redact_inline` (``cpassword="…"``, ``cpassword: …``,
    escaped quotes, any casing), :func:`redaction.redact_structure` when the
    text is JSON, and :func:`redaction.redact_element_tree` when it parses as
    XML (``<cpassword>`` elements, a word split across nodes, character
    references). ``cpassword=""`` and the redaction marker carry no value and
    pass.

(b) an *unlabelled* token shaped like GPP ciphertext:
    :func:`redaction.ciphertext_shaped`, the predicate the estate-wide
    ``Chaser`` uses (base64 of whole AES blocks, at least 22 characters, after
    canonicalisation: whitespace removed, URL-safe alphabet mapped to the
    standard one, ``=`` padding stripped). Free text is not a known value, so
    false positives are cut by exclusions that a value Windows wrote cannot
    meet (see :func:`_not_ciphertext`); their measured costs are in
    ``SECURITY.md``.

Tokens are runs of the base64 alphabet (both alphabets) with any trailing
``=`` padding; a token that ends a line is also joined with following lines
that each hold one token and with the token that starts the next line (a value
wrapped across lines, with prose before and after it), and windows between
``-``, ``_`` and ``/`` inside a token are tried too (``pw-<value>``,
``/tmp/<value>/x``).

(c) text the guard cannot inspect fully is refused as ``uninspectable``:
    structure nested beyond the redactor's recursion limit, or XML that the
    safe parser rejects for another reason than not being XML (a declared
    entity, internal or external; a bare external DTD reference parses and is
    inspected). The guard is total: it returns or raises
    :class:`CpasswordInAnalystTextError`, nothing else.

The guard is for accidents, not a determined insider: a value deliberately
broken up (spaces every four characters, homoglyphs, re-encoding) passes.
Callers check what they store or send plus :data:`STRADDLE_MARGIN` characters
past a truncation point (:func:`checked_slice`), so the work per request is
bounded however large the submitted field is.

Refusals carry the field name and a fixed reason, never the matched value or
any part of it.

This is a core module: it must not import ``narration`` or ``web``.
"""

from __future__ import annotations

import binascii
import json
import re
import sqlite3
from base64 import b64decode
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal
from xml.etree.ElementTree import ParseError

import defusedxml.ElementTree as SafeET

from gpo_lens.redaction import (
    canonical,
    ciphertext_shaped,
    mentions_cpassword,
    redact_element_tree,
    redact_inline,
    redact_structure,
)

Kind = Literal["labelled", "ciphertext", "uninspectable"]

_REASON = (
    "looks like it contains a Group Policy Preferences cpassword; remove it — the "
    "value is a recoverable credential (anyone can decrypt it with the key Microsoft "
    "published, MS14-025). Nothing was saved or sent."
)
_UNINSPECTABLE = (
    "could not be checked for a Group Policy Preferences cpassword (it is nested "
    "too deeply, or is XML that declares an entity); simplify it — a cpassword "
    "is a recoverable credential (MS14-025). Nothing was saved or sent."
)
_HINTS: dict[str, str] = {
    "labelled": (
        " If no value was meant, do not write a word directly after 'cpassword:' or 'cpassword='."
    ),
    "ciphertext": (
        " If it is not a credential (for example a base64-encoded hash or a line of a "
        "PEM certificate), refer to it by its hex hash or thumbprint, or leave it out."
    ),
    "uninspectable": (
        " Paste the plain text instead of the nested structure, or remove the XML "
        "<!DOCTYPE ...> entity declarations."
    ),
}

# What a migration copies instead of a legacy value the guard would refuse
# (the legacy row itself is left as it was; see ``store._migrate_legacy_triage``).
REFUSED_PRINCIPAL_MARKER = "[refused principal name]"
REFUSED_TEXT_MARKER = "[refused analyst text]"

# Characters past a truncation point that callers also check, so a value
# straddling the cut is still seen: the longest candidate (``_MAX_WINDOW``) plus
# room for the line breaks of a wrapped value.
STRADDLE_MARGIN = 1024

# A base64 run (standard or URL-safe alphabet) with any trailing padding.
# Every pattern here is matched with ``finditer``/``fullmatch`` only, never an
# unanchored ``search`` ending in ``$`` (quadratic on a long run).
_TOKEN = re.compile(r"[A-Za-z0-9+/_-]+(?:[ \t]*=)*")
_TOKEN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-")
_HEX = re.compile(r"[0-9A-Fa-f]+")
_SEPARATORS = "-_/"
# Bounds on the extra candidates (the window search is quadratic in separators).
# GPP values are short (an 8-15 character password is 43 base64 characters);
# 512 characters is 24 AES blocks (384 bytes, roughly a 190-character UTF-16
# password).
_MAX_WINDOW = 512
_MAX_SEPARATORS = 64
_MAX_WRAPPED_LINES = 32
# An identifier or path made of words: acronyms (``AD``), Capitalised words
# (``To``, ``Secure``), lowercase words of two or more letters, digit runs and
# separators. Matched piece by piece (``finditer``), never as a repeated
# alternation, which backtracks exponentially on a crafted token.
_WORD_PIECE = re.compile(r"[A-Z]{2,}(?![a-z])|[A-Z][a-z]+|[a-z]{2,}|[0-9]+|[-_/+.]")
_MIN_MEAN_WORD = 4
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


class CpasswordInAnalystTextError(ValueError):
    """Analyst-typed text carries cpassword material; nothing was stored.

    The message names the field and the reason only, never the value.
    """

    def __init__(self, field: str, kind: Kind) -> None:
        self.field = field
        self.kind = kind
        reason = _UNINSPECTABLE if kind == "uninspectable" else _REASON
        super().__init__(f"The {field} {reason}{_HINTS[kind]}")


def check_analyst_text(text: str | None, field: str) -> None:
    """Raise :class:`CpasswordInAnalystTextError` if *text* carries a cpassword.

    *field* is a human label for the refusal ("note", "rationale", "question").
    Total: returns, or raises :class:`CpasswordInAnalystTextError`; never
    anything else.
    """
    kind = cpassword_material(text or "")
    if kind is not None:
        raise CpasswordInAnalystTextError(field, kind)


def checked_slice(text: str | None, stored_length: int) -> str:
    """The part of *text* a caller that keeps ``text[:stored_length]`` must
    check: what it keeps plus :data:`STRADDLE_MARGIN` characters, so a value
    cut by the truncation is still refused and the work stays bounded."""
    return (text or "")[: stored_length + STRADDLE_MARGIN]


# Characters an AD sAMAccountName may not contain (Microsoft's sAMAccountName
# schema documentation), which also excludes the base64 ``+``, ``/`` and ``=``.
_ACCOUNT_FORBIDDEN = frozenset('"/\\[]:;|=,+*?<>')
_UPN_DOMAIN = re.compile(r"[\w-]+(?:\.[\w-]+)*")
MAX_PRINCIPAL_LENGTH = 256


def _account_part(part: str) -> bool:
    return bool(part) and not any(
        ch in _ACCOUNT_FORBIDDEN or ord(ch) < 32 or ord(ch) == 127 for ch in part
    )


def valid_principal_name(name: str) -> bool:
    """Is *name* an account name (and free of cpassword material)?

    Shapes: ``user``, ``user@domain`` (DNS-style domain) or ``DOMAIN\\user``
    (the domain may contain spaces: ``NT AUTHORITY``, ``IIS APPPOOL``). Each
    part may hold any character an AD account name may, i.e. none of
    ``"/\\[]:;|=,+*?<>`` and no control character; at most 256 characters.
    Used for names that arrive from outside (a forwarded-user header); the
    built-in principals already match.
    """
    if not name or len(name) > MAX_PRINCIPAL_LENGTH:
        return False
    domain, backslash, user = name.partition("\\")
    if backslash:
        if not (_account_part(domain) and _account_part(user)) or "@" in user:
            return False
    else:
        user, at, upn_domain = name.partition("@")
        if not _account_part(user):
            return False
        if at and not _UPN_DOMAIN.fullmatch(upn_domain):
            return False
    return cpassword_material(name) is None


def migrated_value(value: object, field: str) -> tuple[object, Kind | None]:
    """The value a migration may copy for a legacy *field*, and why it was
    replaced: the value itself, or (when the guard would refuse it) a marker
    with the refusal kind. Never raises; never returns the refused value."""
    if not isinstance(value, str):
        return value, None
    kind = cpassword_material(value)
    if kind is None:
        return value, None
    marker = REFUSED_PRINCIPAL_MARKER if field == "actor" else REFUSED_TEXT_MARKER
    return marker, kind


def cpassword_material(text: str) -> Kind | None:
    """Which kind of cpassword material *text* carries, or ``None``.

    Returns a kind, never the value.
    """
    if not text:
        return None
    labelled = _labelled(text)
    if labelled is not None:
        return labelled
    seen: set[str] = set()
    for token in _candidates(text):
        if token not in seen:
            seen.add(token)
            if _ciphertext_token(token):
                return "ciphertext"
    return None


# --- (a) labelled forms ---------------------------------------------------------


def _labelled(text: str) -> Kind | None:
    """``labelled``, ``uninspectable`` (structure the redactor cannot walk, or
    XML the safe parser rejects for another reason than not being XML), or
    None. Never raises."""
    if mentions_cpassword(text) and redact_inline(text)[1]:
        return "labelled"
    if mentions_cpassword(text) or "\\u" in text:
        try:
            obj = json.loads(text)
        except RecursionError:
            return "uninspectable"
        except ValueError:
            pass  # not JSON
        else:
            try:
                if redact_structure(obj)[1]:
                    return "labelled"
            except RecursionError:
                return "uninspectable"
    if "<" in text or "&" in text:
        for document in (text, f"<gpo-lens-text>{text}</gpo-lens-text>"):
            try:
                root = SafeET.fromstring(document)
            except ParseError:
                continue  # not XML
            except Exception:  # noqa: BLE001 - entities, external refs, encoding, depth
                return "uninspectable"
            try:
                if redact_element_tree(root):
                    return "labelled"
            except RecursionError:
                return "uninspectable"
    return None


# --- (b) unlabelled ciphertext-shaped tokens -------------------------------------


def _candidates(text: str) -> Iterator[str]:
    for match in _TOKEN.finditer(text):
        token = match.group(0)
        yield token
        yield from _windows(token)
    yield from _wrapped(text)


def _windows(token: str) -> Iterator[str]:
    """Sub-tokens between separators (``pw-<value>``, ``/tmp/<value>/x``)."""
    body = token.rstrip("= \t")
    cuts = [i for i, ch in enumerate(body) if ch in _SEPARATORS]
    if not cuts or len(cuts) > _MAX_SEPARATORS:
        return
    starts = [0, *(i + 1 for i in cuts)]
    ends = [*cuts, len(body)]
    for a in starts:
        for b in ends:
            if (a, b) != (0, len(body)) and b - a <= _MAX_WINDOW and _block_length(b - a):
                yield body[a:b]


def _wrapped(text: str) -> Iterator[str]:
    """A token ending a line joined with the following one-token lines and
    with the token that starts the next line after them (prose may follow it),
    each prefix of that chain, so a value wrapped across lines with commentary
    before and after it is still seen."""
    lines = text.splitlines()
    if len(lines) < 2:
        return
    # Per line, once: the stripped text and its canonical length when the
    # whole line is one token (else -1).
    stripped = [line.strip() for line in lines]
    sizes = [len(canonical(p)) if _TOKEN.fullmatch(p) else -1 for p in stripped]
    for i in range(len(lines) - 1):
        head = _line_end_token(lines[i])
        if head is None:
            continue
        length = len(canonical(head))
        pieces = [head]
        for j in range(i + 1, min(len(lines), i + 1 + _MAX_WRAPPED_LINES)):
            if sizes[j] < 0:
                # The chain ends at a line with more than one token: join the
                # token that starts it (``<rest of value> removed``).
                lead = _TOKEN.match(stripped[j])
                if lead is not None:
                    piece = lead.group(0)
                    if length + len(canonical(piece)) <= _MAX_WINDOW and _block_length(
                        length + len(canonical(piece))
                    ):
                        yield "".join(pieces) + piece
                break
            length += sizes[j]
            if length > _MAX_WINDOW:
                break
            pieces.append(stripped[j])
            if _block_length(length):
                yield "".join(pieces)


def _line_end_token(line: str) -> str | None:
    """The token (with any ``=`` padding) that ends *line*, or None. A linear
    scan from the end."""
    end = len(line.rstrip(" \t"))
    stop = end
    while stop and line[stop - 1] in "= \t":
        stop -= 1
    start = stop
    while start and line[start - 1] in _TOKEN_CHARS:
        start -= 1
    if start == stop:
        return None
    return line[start:end]


def _block_length(n: int) -> bool:
    """Cheap length prefilter: could *n* canonical characters be whole AES
    blocks? (The same arithmetic as :func:`redaction.ciphertext_shaped`.)"""
    return n >= 22 and n % 4 != 1 and (n * 3 // 4) % 16 == 0


def _ciphertext_token(token: str) -> bool:
    if not ciphertext_shaped(token):
        return False
    return not _not_ciphertext(token, canonical(token))


def _not_ciphertext(token: str, body: str) -> bool:
    """Exclusions for a ciphertext-shaped *body* (canonical form of *token*).

    Each one is something GPP ciphertext — the canonical base64 of random AES
    output, as Windows writes it — cannot be, or is only with negligible
    probability (measured rates in ``SECURITY.md``):

    * pure hex: SHA-1/SHA-256/MD5 digests and certificate thumbprints;
    * one letter case only: lowercase paths and slugs, upper-case constants;
    * non-canonical encoding: the unused low bits of the last character are
      not zero, which no base64 encoder (Windows included) emits;
    * the decoded bytes are text (all printable ASCII, or at least a quarter
      NUL bytes as in UTF-16, e.g. a PowerShell ``-EncodedCommand``);
    * an identifier or path built from words (``DisableIPSourceRouting``,
      ``LocalReviewRunnerError``): a CamelCase/kebab/snake/path shape whose
      letter segments average at least four characters.
    """
    if _HEX.fullmatch(body):
        return True
    if not (any(c.isupper() for c in body) and any(c.islower() for c in body)):
        return True
    if not _canonical_encoding(body):
        return True
    if _decodes_to_text(body):
        return True
    return _word_shaped(token)


def _canonical_encoding(body: str) -> bool:
    last = _ALPHABET.index(body[-1])
    remainder = len(body) % 4
    if remainder == 2:  # 4 unused bits
        return last % 16 == 0
    if remainder == 3:  # 2 unused bits
        return last % 4 == 0
    return True


def _decodes_to_text(body: str) -> bool:
    try:
        raw = b64decode(body + "=" * (-len(body) % 4), validate=True)
    except (binascii.Error, ValueError):
        return False
    if raw.count(0) * 4 >= len(raw):
        return True
    return raw.isascii() and raw.decode("ascii").isprintable()


def _word_shaped(token: str) -> bool:
    original = token.rstrip("= \t")
    position = 0
    words: list[int] = []
    for piece in _WORD_PIECE.finditer(original):
        if piece.start() != position:
            return False
        position = piece.end()
        if piece.group()[0].isalpha():
            words.append(position - piece.start())
    if position != len(original):
        return False
    return bool(words) and sum(words) >= _MIN_MEAN_WORD * len(words)


# --- existing rows (read-only) ----------------------------------------------------

# Stored operator-supplied text: every column a guarded write path fills — the
# analyst-typed note and rationale, and the actor (a principal name, which can
# come from a forwarded-user header). ``finding_triage`` is the legacy v1 table
# (never written since schema v8; its rows were copied into
# ``finding_triage_event``) and is listed for audit.
ANALYST_TEXT_COLUMNS: tuple[tuple[str, str], ...] = (
    ("finding_triage_event", "note"),
    ("finding_triage_event", "rationale"),
    ("finding_triage_event", "actor"),
    ("finding_triage", "note"),
    ("finding_triage", "actor"),
)
# Operator-supplied fields inside ``events`` payloads, by event type (``*``:
# every event type; the principal name is in every audit event).
ANALYST_TEXT_EVENT_FIELDS: tuple[tuple[str, str], ...] = (
    ("audit.narrate", "question"),
    ("*", "principal"),
)


@dataclass(frozen=True)
class RefusableRow:
    """A stored row whose analyst text the guard would now refuse (no value)."""

    table: str
    column: str
    row_id: int
    kind: Kind


def refusable_rows(conn: sqlite3.Connection) -> list[RefusableRow]:
    """Ids of stored analyst-text rows that :func:`check_analyst_text` would refuse.

    Read-only: nothing is rewritten (the triage log is append-only history; the
    operator decides). Returns ids and the kind of match, never a value.
    """
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    found: list[RefusableRow] = []
    for table, column in ANALYST_TEXT_COLUMNS:
        if table not in tables:
            continue
        query = f'SELECT id, "{column}" FROM "{table}" ORDER BY id'  # noqa: S608 - fixed names
        for row_id, value in conn.execute(query):
            kind = _stored_kind(value)
            if kind is not None:
                found.append(RefusableRow(table, column, int(row_id), kind))
    if "events" in tables:
        for event_type, field in ANALYST_TEXT_EVENT_FIELDS:
            if event_type == "*":
                rows = conn.execute(
                    "SELECT id, payload FROM events WHERE instr(payload, ?) > 0 ORDER BY id",
                    (f'"{field}"',),
                )
            else:
                rows = conn.execute(
                    "SELECT id, payload FROM events WHERE event_type = ? ORDER BY id",
                    (event_type,),
                )
            for row_id, payload in rows:
                try:
                    obj = json.loads(payload)
                except (TypeError, ValueError, RecursionError):
                    continue
                kind = _stored_kind(obj.get(field)) if isinstance(obj, dict) else None
                if kind is not None:
                    found.append(RefusableRow("events", f"payload.{field}", int(row_id), kind))
    return found


def _stored_kind(value: object) -> Kind | None:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return cpassword_material(value) if isinstance(value, str) else None


__all__ = [
    "ANALYST_TEXT_COLUMNS",
    "ANALYST_TEXT_EVENT_FIELDS",
    "MAX_PRINCIPAL_LENGTH",
    "REFUSED_PRINCIPAL_MARKER",
    "REFUSED_TEXT_MARKER",
    "STRADDLE_MARGIN",
    "CpasswordInAnalystTextError",
    "RefusableRow",
    "check_analyst_text",
    "checked_slice",
    "cpassword_material",
    "migrated_value",
    "refusable_rows",
    "valid_principal_name",
]
