"""Redact Group Policy Preferences ``cpassword`` values before they are stored.

A GPP ``cpassword`` is AES-encrypted with a key Microsoft published (MS14-025),
so the stored value is a recoverable credential. gpo-lens never needs the value:
the ``cpassword`` finding is about *presence*, and it is computed from the SYSVOL
files at ingest. No hash or fingerprint of a value is kept: nothing compares
values (trends count hits; the finding lifecycle tracks presence per GPO), and
any cpassword is already compromised, so "rotated" versus "unchanged" carries
no remediation meaning.

Two steps, both deterministic:

1. **Discovery and labelled redaction.** :func:`redact_element_tree` (report and
   SYSVOL XML) and :func:`redact_structure` (stored JSON) replace every
   *labelled* value with :data:`CPASSWORD_MARKER` and return the values found:
   an attribute or mapping key whose local name is ``cpassword`` in any casing
   or namespace; a ``<cpassword>`` element (its whole text, even when split
   across child nodes); and an inline assignment (``cpassword="…"``,
   ``cpassword: …``, escaped ``&quot;``/``\\"`` forms) found in any string *or in
   the concatenated text of a mixed-content element*, so ``cpass<b/>word="…"``
   is caught. Labelled values are redacted at any length. ``cpassword=""``
   carries no secret and is left empty.

2. **Copy chasing.** A discovered value can be repeated under another name (a
   GPO name, a description, a path, a sibling setting, an event payload). A
   :class:`Chaser` replaces such copies, under rules that keep it from
   rewriting unrelated truth:

   * *Estate-wide* copies are replaced only for values that are at least
     :data:`MIN_CHASE_LENGTH` characters and either look like GPP ciphertext
     (base64 of whole AES blocks, at least 22 characters) or mix letters and
     digits. Words such as ``Enabled`` or ``Administrators`` are never chased
     (no valid GPP cpassword looks like that). Values shorter than
     :data:`UNBOUNDED_CHASE_LENGTH` match only as a whole base64 token, never
     inside a longer run of base64 characters (so a short value cannot eat part
     of a GUID).
   * Inside the record that carries the labelled value (the same setting), its
     own copies are replaced from :data:`MIN_LOCAL_CHASE_LENGTH` characters, at
     token boundaries, and an exact whole-field copy at any length.
   * Copies are rewritten only in descriptive fields listed in
     :data:`REWRITABLE_FIELDS` / ``store.REWRITABLE_COLUMNS``. A copy in an
     identity or structural field (GUIDs, SIDs, SOM paths, CSE names, event
     types, finding keys, …) is never rewritten: the import or migration is
     refused with :class:`CredentialInIdentityError`, which names the field,
     never the value.

Values are compared canonically (:func:`canonical`: whitespace removed, the
URL-safe base64 alphabet mapped to the standard one, ``=`` padding stripped),
so a copy wrapped across lines or written URL-safe is still a copy.

3. **Verification.** :func:`sanitize_estate` re-runs discovery and the copy
   search over its own result (:func:`residual_locations`); ``store`` does the
   same over the rows as written and the raw database bytes, and the v11
   migration over every stored column. Any residual refuses with
   :class:`CpasswordResidualError` (nothing stored) or, in the migration, rolls
   the scrub back so the next open can rediscover the labelled sources.

4. **Diagnostics.** Inside :func:`guarded_diagnostics` (every ingest, save and
   migration path) warnings are held back and re-emitted only once every value
   of the run is known, then scrubbed like stored text; exceptions leaving the
   guard and log records created inside it are scrubbed too. A skipped or
   rejected input therefore cannot echo a value it shares with a labelled one.

This is a core module: stdlib only, and it must not import ``narration`` or
``web``.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import logging
import re
import warnings
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, cast
from xml.etree.ElementTree import Element

from gpo_lens.normalize import localname

if TYPE_CHECKING:
    from gpo_lens.model import Estate, Gpo

CPASSWORD_MARKER = "[redacted cpassword]"

# Detail persisted on every ``cpassword`` finding. It names no characters of the
# value: earlier releases stored the first four, which the v11 migration erases.
CPASSWORD_FINDING_DETAIL = (
    "cpassword attribute present; value not stored or shown "
    "(any cpassword is recoverable with the key Microsoft published, MS14-025)"
)

MIN_CHASE_LENGTH = 12
UNBOUNDED_CHASE_LENGTH = 22  # unpadded base64 of one 16-byte AES block
MIN_LOCAL_CHASE_LENGTH = 8

# Descriptive fields a copy may be replaced in, per model class. Every other
# string field is identity/structural truth: a copy there refuses the import.
REWRITABLE_FIELDS: dict[str, frozenset[str]] = {
    "Gpo": frozenset({"name", "description"}),
    "Setting": frozenset({"identity", "display_name", "display_value", "raw"}),
    "GpoLink": frozenset({"som_name"}),
    "Som": frozenset({"name"}),
    "WmiFilter": frozenset({"query"}),
    "OuRecord": frozenset({"name"}),
    "CoverageGap": frozenset({"display_name", "detail"}),
    "ResolvedPrincipal": frozenset({"name"}),
    "GroupMembership": frozenset({"name"}),
    "FindingCandidate": frozenset(
        {"summary", "detail", "remediation", "gpo_name", "evidence_refs"}
    ),
    "EvidenceRef": frozenset({"safe_projection"}),
}

_HINT = re.compile("cpassword", re.IGNORECASE)
_INLINE = re.compile(
    r"(?P<key>\bcpassword\b[\"']?\s*[:=]\s*)"
    r"(?!\[redacted cpassword\])"
    r"(?P<value>"
    r"\\\"[^\"\\]*\\\""  # JSON-escaped quotes: \"...\"
    r"|\"[^\"]*\""  # "..."
    r"|'[^']*'"  # '...'
    r"|&quot;.*?&quot;"  # still-escaped XML: &quot;...&quot;
    r"|&#34;.*?&#34;"
    r"|&#x22;.*?&#x22;"
    r"|[^\s;,<>\"'&\\]+"  # bare token
    r")",
    re.IGNORECASE | re.DOTALL,
)
_QUOTES = ('\\"', '"', "'", "&quot;", "&#34;", "&#x22;")
_TRAILING = ".,:!?)]}"
_B64 = "A-Za-z0-9+/"  # token boundary; "=" padding is consumed, not a boundary
_B64_BODY = re.compile(r"[A-Za-z0-9+/]+")


class CpasswordResidualError(RuntimeError):
    """Verification after redaction still found a value; nothing is stored."""

    def __init__(self, location: str) -> None:
        super().__init__(
            f"cpassword redaction could not be verified: a value remains in {location}; "
            "nothing was stored."
        )
        self.location = location


class CredentialInIdentityError(ValueError):
    """A cpassword value sits in an identity/structural field; refuse, don't corrupt."""

    def __init__(self, location: str) -> None:
        super().__init__(
            f"a GPP cpassword value is repeated in the identity field {location}; "
            "refusing to store it or to rewrite that field. Remove the value from "
            "the export (or the affected rows) and retry."
        )
        self.location = location


def is_cpassword_name(name: object) -> bool:
    """True for ``cpassword`` in any casing, with or without a namespace."""
    # len("cpassword") == 9; casefold can only shrink a few characters (ß→ss
    # grows), so anything shorter than 8 cannot fold to it.
    if not isinstance(name, str) or len(name) < 8:
        return False
    return localname(name).casefold() == "cpassword"


def mentions_cpassword(text: str) -> bool:
    """Cheap pre-check: does *text* contain ``cpassword`` in any casing?

    ASCII text is lower-cased (exact for ASCII); anything else uses the
    Unicode case-insensitive regex (``ſ`` and ``K`` fold to ``s``/``k``).
    """
    if text.isascii():
        return "cpassword" in text.lower()
    return _HINT.search(text) is not None


_MARKER_COMPACT = "".join(CPASSWORD_MARKER.split())


def _secret(value: object) -> bool:
    """A non-empty value that is not (a whitespace variant of) the marker."""
    if not isinstance(value, str):
        return False
    compact = "".join(value.split())
    return compact != "" and compact != _MARKER_COMPACT


def _unquote(value: str) -> tuple[str, str]:
    for quote in _QUOTES:
        if len(value) >= 2 * len(quote) and value.startswith(quote) and value.endswith(quote):
            return quote, value[len(quote) : -len(quote)]
    return "", value


def redact_inline(text: str) -> tuple[str, set[str]]:
    """Redact inline ``cpassword=…`` assignments; return ``(text, values)``."""
    found: set[str] = set()
    if not mentions_cpassword(text):
        return text, found

    def replace(match: re.Match[str]) -> str:
        quote, inner = _unquote(match.group("value"))
        if inner.strip() in ("", CPASSWORD_MARKER):
            return match.group(0)
        trail = ""
        if not quote:
            # A bare token ends at sentence punctuation: ``cpassword=X.``
            body = inner.rstrip(_TRAILING)
            inner, trail = (body, inner[len(body) :]) if body else (inner, "")
        found.add(inner)
        return f"{match.group('key')}{quote}{CPASSWORD_MARKER}{quote}{trail}"

    return _INLINE.sub(replace, text), found


def redact_text(text: str) -> str:
    """Inline redaction only (no copy chasing)."""
    return redact_inline(text)[0]


# XML/base64 whitespace a decoder ignores, and the URL-safe base64 alphabet.
_WS = " \t\r\n\f\v"
_SKELETON = str.maketrans({"-": "+", "_": "/", **dict.fromkeys(_WS)})
_B64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


def canonical(value: str) -> str:
    """Comparison form of a value: whitespace removed, URL-safe alphabet mapped
    to the standard one, trailing ``=`` padding stripped."""
    return value.translate(_SKELETON).rstrip("=")


def normalized_values(values: Iterable[str]) -> set[str]:
    """Canonical forms of *values* (see :func:`canonical`), without the marker."""
    marker = canonical(CPASSWORD_MARKER)
    out = {canonical(v) for v in values}
    return {v for v in out if v and v != marker}


def _ciphertext_shaped(value: str) -> bool:
    body = canonical(value)
    if len(body) < UNBOUNDED_CHASE_LENGTH or not _B64_BODY.fullmatch(body):
        return False
    if len(body) % 4 == 1:
        return False
    return (len(body) * 3 // 4) % 16 == 0


def chase_eligible(value: str) -> bool:
    """Estate-wide copy chasing applies to this value (compared canonically)."""
    body = canonical(value)
    if len(body) < MIN_CHASE_LENGTH or body in canonical(CPASSWORD_MARKER):
        return False
    if _ciphertext_shaped(body):
        return True
    return any(c.isalpha() for c in body) and any(c.isdigit() for c in body)


class Chaser:
    """Find and replace copies of known values, compared canonically.

    A carrier string matches when its *skeleton* (whitespace removed, URL-safe
    letters mapped) contains a value's canonical form, so a copy wrapped across
    lines or written URL-safe is still found; the replacement covers the
    original span, including the whitespace inside it and any ``=`` padding
    after it. A value that is not ciphertext-shaped (or any value of a local
    chaser) must also stand as a whole token: the characters around the
    original span may not be standard base64 letters.
    """

    def __init__(self, values: Iterable[str], *, local: bool = False) -> None:
        normalized = normalized_values(values)
        marker = canonical(CPASSWORD_MARKER)
        if local:
            eligible = {v for v in normalized if len(v) >= MIN_LOCAL_CHASE_LENGTH}
        else:
            eligible = {v for v in normalized if chase_eligible(v)}
        eligible = {v for v in eligible if v not in marker}
        self.local = local
        self.values: tuple[str, ...] = tuple(sorted(eligible, key=lambda v: (-len(v), v)))
        self.exact = frozenset(normalized) if local else frozenset()
        self._unbounded = frozenset(v for v in eligible if not local and _ciphertext_shaped(v))
        # JSON text escapes quotes and backslashes; such values need a walk.
        self.walk_needed = any(
            any(c in v for c in '"\\') or not v.isprintable() or not v.isascii()
            for v in self.values
        )

    def __bool__(self) -> bool:
        return bool(self.values or self.exact)

    def contains(self, text: str) -> bool:
        """Boundary-free superset test (a prefilter; never misses a match)."""
        skeleton = text.translate(_SKELETON)
        return any(v in skeleton for v in self.values)

    def _spans(self, text: str) -> list[tuple[int, int]]:
        skeleton = text.translate(_SKELETON)
        candidates = [v for v in self.values if v in skeleton]
        if not candidates:
            return []
        index = [i for i, ch in enumerate(text) if ch not in _WS]
        spans: list[tuple[int, int]] = []
        for value in candidates:
            k = skeleton.find(value)
            while k != -1:
                start, end = index[k], index[k + len(value) - 1] + 1
                end = _consume_padding(text, end)
                if value in self._unbounded or (
                    (start == 0 or text[start - 1] not in _B64_CHARS)
                    and (end == len(text) or text[end] not in _B64_CHARS)
                ):
                    if not any(start < e and s < end for s, e in spans):
                        spans.append((start, end))
                k = skeleton.find(value, k + 1)
        return sorted(spans)

    def hits(self, text: str) -> bool:
        if self.exact and canonical(text) in self.exact:
            return True
        return bool(self.values) and bool(self._spans(text))

    def sub(self, text: str) -> str:
        if self.exact and canonical(text) in self.exact:
            return CPASSWORD_MARKER
        for start, end in reversed(self._spans(text) if self.values else []):
            text = text[:start] + CPASSWORD_MARKER + text[end:]
        return text

    def hits_json(self, blob: str) -> bool:
        """Superset test on JSON text; escapes count as the whitespace or
        boundaries they encode."""
        if "\\" in blob:
            blob = _JSON_ESCAPE.sub(" ", blob)
        return self.contains(blob)


def _consume_padding(text: str, end: int) -> int:
    j = end
    while True:
        k = j
        while k < len(text) and text[k] in _WS:
            k += 1
        if k < len(text) and text[k] == "=":
            j = k + 1
        else:
            return j


_JSON_ESCAPE = re.compile(r"\\(?:u[0-9a-fA-F]{4}|.)")


# --- XML ---------------------------------------------------------------------


def _mixed(elem: Element) -> bool:
    if len(elem) == 0:
        return False
    if elem.text and elem.text.strip():
        return True
    return any(child.tail and child.tail.strip() for child in elem)


def redact_element_tree(root: Element, *, gate: bool = True) -> set[str]:
    """Redact every labelled cpassword value in *root*'s subtree, in place.

    Returns the distinct values removed (un-normalized) for copy chasing.
    """
    found: set[str] = set()
    if gate and not tree_mentions(root):
        return found
    for elem in list(root.iter()):
        if is_cpassword_name(elem.tag):
            # One value: the element's joined text, not its pieces (review r3 N-01).
            content = "".join("".join(elem.itertext()).split())
            if _secret(content):
                found.add(content)
            found.update(v for v in elem.attrib.values() if _secret(v))
            had_secret = bool(content) or any(_secret(v) for v in elem.attrib.values())
            for child in list(elem):
                elem.remove(child)
            for key, value in list(elem.attrib.items()):
                if value != "":
                    elem.set(key, CPASSWORD_MARKER)
            if had_secret:
                elem.text = CPASSWORD_MARKER
            if elem.tail:
                elem.tail, values = redact_inline(elem.tail)
                found |= values
            continue
        for key, value in list(elem.attrib.items()):
            if is_cpassword_name(key):
                if _secret(value):
                    found.add(value)
                    elem.set(key, CPASSWORD_MARKER)
            else:
                new, values = redact_inline(value)
                if values:
                    found |= values
                    elem.set(key, new)
        if elem.text:
            elem.text, values = redact_inline(elem.text)
            found |= values
        if elem.tail:
            elem.tail, values = redact_inline(elem.tail)
            found |= values
    # Mixed content: an assignment can be split across nodes (cpass<b/>word=…).
    # Deepest first, redact the value's characters in place across the text and
    # tail segments; elements and attributes are kept.
    for elem in reversed(list(root.iter())):
        if _mixed(elem):
            found |= _redact_segments(list(_xml_segments(elem)))
    return found


def tree_mentions(root: Element, source: str | None = None) -> bool:
    """Superset gate: could *root* hold any labelled form?

    Every form needs the word ``cpassword`` in a tag, an attribute name or
    value, or the element text. The text is tested joined across the whole
    tree (so a word split across nodes is seen), tags and attributes in one
    string; both joins only add adjacency, never remove it. When the document
    *source* is given and holds neither the word nor a character reference
    (``&#``, the only way to spell a letter differently once parsed), tags
    and attributes are covered by the source and are not walked.
    """
    if mentions_cpassword("".join(root.itertext())):
        return True
    if source is not None and "&#" not in source:
        return mentions_cpassword(source)
    names: list[str] = []
    for elem in root.iter():
        names.append(str(elem.tag))
        if elem.attrib:
            for key, value in elem.attrib.items():
                names.append(key)
                names.append(value)
    return mentions_cpassword("\x00".join(names))


def _xml_segments(elem: Element) -> Iterator[list[Any]]:
    """``[holder, attribute]`` text segments of *elem*'s content, in order."""
    yield [elem, "text"]
    for child in elem:
        yield from _xml_segments(child)
        yield [child, "tail"]


def _segment_get(seg: list[Any]) -> str:
    holder, key = seg
    if isinstance(holder, dict):
        value = holder.get(key)
    else:
        value = getattr(holder, key)
    return value if isinstance(value, str) else ""


def _segment_set(seg: list[Any], value: str) -> None:
    holder, key = seg
    if isinstance(holder, dict):
        holder[key] = value
    else:
        setattr(holder, key, value)


def _redact_segments(segments: list[list[Any]]) -> set[str]:
    """Redact inline assignments in the joined text of *segments*, in place.

    The value's characters are replaced by the marker in the segment where the
    value starts and removed from the segments it continues into; the key text
    and every other character stay where they were.
    """
    texts = [_segment_get(seg) for seg in segments]
    joined = "".join(texts)
    found: set[str] = set()
    spans: list[tuple[int, int]] = []
    if not mentions_cpassword(joined):
        return found
    for match in _INLINE.finditer(joined):
        quote, inner = _unquote(match.group("value"))
        if inner.strip() in ("", CPASSWORD_MARKER):
            continue
        if not quote:
            body = inner.rstrip(_TRAILING)
            inner = body or inner
        start = match.start("value") + len(quote)
        found.add(inner)
        spans.append((start, start + len(inner)))
    _apply_spans(segments, texts, spans)
    return found


def _apply_spans(segments: list[list[Any]], texts: list[str], spans: list[tuple[int, int]]) -> None:
    """Replace each span of the joined *texts* by the marker, in place.

    The marker goes where the span starts; the span's characters are removed
    from the segments it continues into. Everything else stays where it was.
    """
    if not spans:
        return
    offsets = []
    position = 0
    for text in texts:
        offsets.append(position)
        position += len(text)
    new_texts = list(texts)
    for start, end in sorted(spans, reverse=True):
        placed = False
        for i, text in enumerate(texts):
            lo, hi = offsets[i], offsets[i] + len(text)
            if hi <= start or lo >= end:
                continue
            a, b = max(start, lo) - lo, min(end, hi) - lo
            current = new_texts[i]
            # Offsets within an already-edited segment: edits run right-to-left.
            new_texts[i] = current[:a] + (CPASSWORD_MARKER if not placed else "") + current[b:]
            placed = True
    for seg, old, new in zip(segments, texts, new_texts, strict=True):
        if new != old:
            _segment_set(seg, new)


def _element_nodes(obj: Any) -> Iterator[dict[str, Any]]:
    """``element_to_dict`` nodes with children, deepest first."""
    if isinstance(obj, dict):
        for child in obj.get("children", []) or []:
            yield from _element_nodes(child)
        if "tag" in obj and obj.get("children"):
            yield obj
    elif isinstance(obj, list):
        for item in obj:
            yield from _element_nodes(item)


def joined_text(obj: Any) -> str:
    """All element text of an ``element_to_dict`` structure, in document order.

    The joined text of any subtree is a substring of this, so it serves as a
    superset gate for :func:`chase_joined`.
    """
    if isinstance(obj, dict) and "tag" in obj:
        return "".join(_segment_get(seg) for seg in _dict_segments(obj))
    if isinstance(obj, list):
        return "\x00".join(joined_text(item) for item in obj)
    return ""


def _joined_spans(node: dict[str, Any], chaser: Chaser) -> list[tuple[int, int]]:
    segments = list(_dict_segments(node))
    texts = [_segment_get(seg) for seg in segments]
    if sum(1 for t in texts if t) < 2:
        return []  # a single text node is covered by the per-string chase
    return chaser._spans("".join(texts))


def chase_joined(
    obj: Any, chaser: Chaser, location: str, *, rewritable: bool, field: str = ""
) -> Any:
    """Chase copies split across an element subtree's text nodes.

    ``<P>AAEC…<Span>…Dw==</Span></P>``: the joined text of an element (its text
    and every descendant's, as stored by ``element_to_dict``) is matched under
    the same rules, deepest element first, and the spanning pieces are
    redacted in place. Returns a new structure when anything changed; in a
    non-rewritable field a match refuses instead.
    """
    if not chaser.values or not isinstance(obj, (dict, list)):
        return obj
    if not chaser.contains(joined_text(obj)):
        return obj
    if not any(_joined_spans(node, chaser) for node in _element_nodes(obj)):
        return obj
    if not rewritable:
        raise CredentialInIdentityError(f"{field or 'value'} ({location})")
    new = copy.deepcopy(obj)
    for node in _element_nodes(new):
        segments = list(_dict_segments(node))
        texts = [_segment_get(seg) for seg in segments]
        _apply_spans(segments, texts, _joined_spans(node, chaser))
    return new


def joined_hits(obj: Any, chaser: Chaser) -> bool:
    """A copy split across an element subtree's text nodes remains."""
    return bool(chaser.values) and any(_joined_spans(node, chaser) for node in _element_nodes(obj))


# --- JSON-like structures -------------------------------------------------------


def _collect_text(obj: object, out: list[str]) -> None:
    """Collect string *values*, never mapping keys or element tag names."""
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if key != "tag":
                _collect_text(value, out)
    elif isinstance(obj, list):
        for value in obj:
            _collect_text(value, out)


def _is_mixed_dict(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and "tag" in obj
        and isinstance(obj.get("text"), str)
        and bool(obj.get("children"))
    )


def _has_mixed(obj: Any) -> bool:
    """Any ``element_to_dict`` node holding both text and children."""
    if isinstance(obj, dict):
        return _is_mixed_dict(obj) or any(_has_mixed(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_mixed(v) for v in obj)
    return False


def _dict_segments(obj: dict[str, Any]) -> Iterator[list[Any]]:
    """Text segments of an ``element_to_dict`` node in document order (no tails)."""
    yield [obj, "text"]
    for child in obj.get("children", []) or []:
        if isinstance(child, dict):
            yield from _dict_segments(child)


def _redact_obj(obj: Any, found: set[str]) -> Any:
    if isinstance(obj, str):
        new, values = redact_inline(obj)
        found |= values
        return new
    if isinstance(obj, list):
        return [_redact_obj(item, found) for item in obj]
    if not isinstance(obj, dict):
        return obj
    if is_cpassword_name(obj.get("tag")):
        texts: list[str] = []
        _collect_text(obj, texts)
        # One value: the element's joined text (not its pieces); attribute
        # values of the element are labelled individually.
        joined = "".join("".join(_segment_get(seg) for seg in _dict_segments(obj)).split())
        if _secret(joined):
            found.add(joined)
        attrs = obj.get("@attr")
        if isinstance(attrs, dict):
            found.update(v for v in attrs.values() if _secret(v))
        result: dict[str, Any] = {"tag": obj["tag"]}
        if any(t.strip() for t in texts):
            result["text"] = CPASSWORD_MARKER
        attrs = obj.get("@attr")
        if isinstance(attrs, dict):
            result["@attr"] = {k: (CPASSWORD_MARKER if v != "" else v) for k, v in attrs.items()}
        return result
    out: dict[str, Any] = {}
    for key, value in obj.items():
        if key == "@attr" and isinstance(value, dict):
            attrs_out: dict[str, Any] = {}
            for name, attr_value in value.items():
                if is_cpassword_name(name):
                    if _secret(attr_value):
                        found.add(attr_value)
                        attr_value = CPASSWORD_MARKER
                    attrs_out[name] = attr_value
                else:
                    attrs_out[name] = _redact_obj(attr_value, found)
            out[key] = attrs_out
        elif is_cpassword_name(key):
            texts = []
            _collect_text(value, texts)
            if isinstance(value, str):
                found.update(t for t in texts if _secret(t))
            elif _secret("".join(texts)):
                found.add("".join("".join(texts).split()))
            out[key] = CPASSWORD_MARKER if any(t.strip() for t in texts) else value
        else:
            out[key] = _redact_obj(value, found)
    # Mixed content stored by element_to_dict (text plus children): an
    # assignment split between the node's text and its children's text.
    if _is_mixed_dict(out):
        found |= _redact_segments(list(_dict_segments(out)))
    return out


def redact_structure(obj: Any) -> tuple[Any, set[str]]:
    """Return a labelled-value-redacted copy of a JSON-like structure, and the values."""
    found: set[str] = set()
    return _redact_obj(obj, found), found


def _blob(value: Any) -> str | None:
    """JSON text of a JSON-native container, or None (e.g. it holds dataclasses)."""
    try:
        # Same form ``store.save_estate`` writes, so the text can be reused.
        # Non-ASCII becomes ``\\u`` escapes: gates treat ``\\u`` as "walk".
        return json.dumps(value, sort_keys=True)
    except (TypeError, ValueError):
        return None


def _needs_walk(blob: str | None, chaser: Chaser) -> bool:
    if blob is None or chaser.exact or chaser.walk_needed:
        return True
    return chaser.hits_json(blob)


def chase(value: Any, chaser: Chaser, location: str, *, rewritable: bool, field: str = "") -> Any:
    """Replace copies in *value* (str, JSON-like or dataclass), or refuse.

    Descriptive (``rewritable``) strings are rewritten; a copy in any other
    string, or in a mapping key, raises :class:`CredentialInIdentityError`
    naming the field (``Class.field``) and *location* (e.g. the GPO id).
    """
    if not chaser:
        return value
    if isinstance(value, str):
        if not rewritable:
            # A record's own (local) values only rewrite that record's
            # descriptive fields; refusals come from the estate-wide rules.
            if not chaser.local and chaser.hits(value):
                raise CredentialInIdentityError(f"{field or 'value'} ({location})")
            return value
        return chaser.sub(value) if chaser.hits(value) else value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        cls = type(value).__name__
        allowed = REWRITABLE_FIELDS.get(cls, frozenset())
        changes: dict[str, Any] = {}
        for f in dataclasses.fields(value):
            if f.name.startswith("_"):
                continue
            old = getattr(value, f.name)
            label = f"{cls}.{f.name}"
            new = chase(old, chaser, location, rewritable=f.name in allowed, field=label)
            if isinstance(new, (dict, list)) and not chaser.local:
                new = chase_joined(new, chaser, location, rewritable=f.name in allowed, field=label)
            if new is not old:
                changes[f.name] = new
        return dataclasses.replace(value, **changes) if changes else value
    if isinstance(value, (dict, list, tuple)):
        if value and isinstance(value, (dict, list)) and not _needs_walk(_blob(value), chaser):
            return value
        if isinstance(value, dict):
            out: dict[Any, Any] = {}
            changed = False
            for key, item in value.items():
                chase(key, chaser, location, rewritable=False, field=f"{field} key")
                new_item = chase(item, chaser, location, rewritable=rewritable, field=field)
                changed |= new_item is not item
                out[key] = new_item
            return out if changed else value
        items = [
            chase(item, chaser, location, rewritable=rewritable, field=field) for item in value
        ]
        if all(a is b for a, b in zip(items, value, strict=True)):
            return value
        return type(value)(items) if isinstance(value, tuple) else items
    return value


# --- Estates ---------------------------------------------------------------------


def _strings(obj: Any) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
    elif dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        for f in dataclasses.fields(obj):
            if not f.name.startswith("_"):
                yield from _strings(getattr(obj, f.name))
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield from _strings(key)
            yield from _strings(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            yield from _strings(value)


def _label_pass(obj: Any, found: set[str]) -> Any:
    """Redact labelled forms everywhere in a model object; collect the values."""
    if isinstance(obj, str):
        new, values = redact_inline(obj)
        found |= values
        return new
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        changes: dict[str, Any] = {}
        for f in dataclasses.fields(obj):
            if f.name.startswith("_"):
                continue
            old = getattr(obj, f.name)
            if type(obj).__name__ == "Setting" and f.name == "raw":
                if not _needs_label_walk(old):
                    continue
                new, values = redact_structure(old)
                found |= values
            else:
                new = _label_pass(old, found)
            if new != old:
                changes[f.name] = new
        return dataclasses.replace(obj, **changes) if changes else obj
    if isinstance(obj, dict):
        if obj and not _needs_label_walk(obj):
            return obj
        if _is_mixed_dict(obj) or _has_mixed(obj):
            new_obj, values = redact_structure(obj)
            found |= values
            return new_obj
        return {k: _label_pass(v, found) for k, v in obj.items()}
    if isinstance(obj, list):
        items = [_label_pass(v, found) for v in obj]
        return items if any(a is not b for a, b in zip(items, obj, strict=True)) else obj
    if isinstance(obj, tuple):
        items = [_label_pass(v, found) for v in obj]
        changed = any(a is not b for a, b in zip(items, obj, strict=True))
        return tuple(items) if changed else obj
    return obj


def _dedupe_identities(gpo: Gpo) -> None:
    seen: dict[tuple[str, str], int] = {}
    for index, setting in enumerate(gpo.settings):
        key = (setting.side, setting.identity)
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1 and CPASSWORD_MARKER in setting.identity:
            gpo.settings[index] = dataclasses.replace(
                setting, identity=f"{setting.identity} #{seen[key]}"
            )


def sanitize_estate(
    estate: Estate, known: Iterable[str] = (), *, retain_serialized: bool = False
) -> frozenset[str]:
    """Redact labelled values, then chase every copy across the estate, in place.

    *known* adds values discovered elsewhere (the report tree, SYSVOL files).
    Returns every value discovered (un-normalized), for downstream scrubbing of
    records derived from the estate (findings). Raises
    :class:`CredentialInIdentityError` rather than rewrite a structural field.
    """
    found: set[str] = set(known)
    # Labelled forms; a setting's own values also chase through that setting.
    for gpo in estate.gpos:
        if not _gpo_may_label(gpo):
            continue
        for index, setting in enumerate(gpo.settings):
            if not _setting_mentions(setting):
                continue
            own: set[str] = set()
            labelled = _label_pass(setting, own)
            if own:
                local = Chaser(own, local=True)
                labelled = chase(labelled, local, f"GPO {gpo.id}", rewritable=False)
            if labelled is not setting:
                gpo.settings[index] = labelled
            found |= own
    rest: set[str] = set()
    labelled_estate = _label_pass(dataclasses.replace(estate, gpos=[]), rest)
    gpo_fields: set[str] = set()
    new_gpos = []
    for gpo in estate.gpos:
        settings = gpo.settings
        stripped = dataclasses.replace(gpo, settings=[])
        new = _label_pass(stripped, gpo_fields)
        new_gpos.append(dataclasses.replace(new, settings=settings) if new is not stripped else gpo)
    found |= rest | gpo_fields
    _assign(estate, labelled_estate, gpos=new_gpos)

    chaser = Chaser(found)
    if chaser:
        chased_gpos = []
        # One estate-wide superset test first: per-GPO tests only on a hit.
        any_setting_hit = _estate_may_hit(estate, chaser)
        for gpo in estate.gpos:
            location = f"GPO {gpo.id}"
            stripped = dataclasses.replace(gpo, settings=[])
            new_gpo = chase(stripped, chaser, location, rewritable=False)
            if any_setting_hit and _gpo_may_hit(gpo, chaser):
                settings = [
                    chase(s, chaser, location, rewritable=False) if _setting_hits(s, chaser) else s
                    for s in gpo.settings
                ]
            else:
                settings = gpo.settings
            if new_gpo is stripped and all(
                a is b for a, b in zip(settings, gpo.settings, strict=True)
            ):
                chased_gpos.append(gpo)
                continue
            new_gpo = dataclasses.replace(new_gpo, settings=settings)
            _dedupe_identities(new_gpo)
            chased_gpos.append(new_gpo)
        others = chase(dataclasses.replace(estate, gpos=[]), chaser, "estate", rewritable=False)
        _assign(estate, others, gpos=chased_gpos)
    try:
        residual = residual_locations(estate, found)
    finally:
        if not retain_serialized:
            _blob_memo.clear()
        _text_memo.clear()
    if residual:
        raise CpasswordResidualError(residual[0])
    values = frozenset(found)
    setattr(estate, _VALUES_ATTR, values | estate_cpassword_values(estate))
    return values


# Values discovered for an estate, kept on the in-memory object (not a dataclass
# field, so never serialized by asdict/repr) until the post-commit byte check.
_VALUES_ATTR = "_cpassword_values"


def estate_cpassword_values(estate: Estate) -> frozenset[str]:
    """Values discovered while sanitizing *estate* (empty if never sanitized)."""
    return cast("frozenset[str]", getattr(estate, _VALUES_ATTR, frozenset()))


def forget_cpassword_values(estate: Estate) -> None:
    """Drop the discovered values once the stored result has been verified."""
    if hasattr(estate, _VALUES_ATTR):
        delattr(estate, _VALUES_ATTR)


def residual_locations(estate: Estate, values: Iterable[str]) -> list[str]:
    """Independent re-check of a sanitized estate.

    Runs labelled discovery again (a labelled value must now be the marker) and
    searches every string for a canonical copy the chase rules cover. Returns
    the locations still holding one (empty when clean).
    """
    chaser = Chaser(values)
    out: list[str] = []
    any_setting_hit = bool(chaser) and _estate_may_hit(estate, chaser)
    for gpo in estate.gpos:
        may_label = _gpo_may_label(gpo)
        may_hit = any_setting_hit and _gpo_may_hit(gpo, chaser)
        for index, setting in enumerate(gpo.settings if (may_label or may_hit) else ()):
            found: set[str] = set()
            if may_label and _setting_mentions(setting):
                _label_pass(setting, found)
            if found or (
                may_hit
                and _setting_hits(setting, chaser)
                and (
                    any(chaser.hits(t) for t in _strings(setting))
                    or joined_hits(setting.raw, chaser)
                )
            ):
                # Positions only: the setting's own text may be the residual.
                out.append(f"setting #{index + 1} (GPO {gpo.id})")
        stripped = dataclasses.replace(gpo, settings=[])
        found = set()
        _label_pass(stripped, found)
        if found or (chaser and any(chaser.hits(t) for t in _strings(stripped))):
            out.append(f"GPO {gpo.id}")
    rest = dataclasses.replace(estate, gpos=[])
    found = set()
    _label_pass(rest, found)
    if found or (chaser and any(chaser.hits(t) for t in _strings(rest))):
        out.append("estate (SOM, WMI, OU, coverage or principal data)")
    return out


# Serialized form of a raw structure, memoized per object for one pass (the
# object is held so its id cannot be reused while the entry lives).
_blob_memo: dict[int, tuple[Any, str | None]] = {}


def _raw_blob(raw: Any) -> str | None:
    entry = _blob_memo.get(id(raw))
    if entry is not None and entry[0] is raw:
        return entry[1]
    blob = _blob(raw)
    if len(_blob_memo) > 500_000:
        _blob_memo.clear()
    _blob_memo[id(raw)] = (raw, blob)
    return blob


def _needs_label_walk(raw: Any) -> bool:
    """Superset gate for labelled discovery in a structure.

    Every labelled form either mentions ``cpassword`` contiguously in the JSON
    text, or (split across mixed-content nodes) sits in a node with both text
    and children. Such a node puts both keys in the JSON text, and only then is
    ``_has_mixed`` walked.
    """
    blob = _raw_blob(raw)
    if blob is None or mentions_cpassword(blob) or "\\u" in blob:
        return True
    return '"children"' in blob and '"text"' in blob and _has_mixed(raw)


_text_memo: dict[int, tuple[Gpo, tuple[int, ...], str]] = {}


def _settings_text(gpo: Gpo) -> str:
    """Memoized ``_gpo_settings_text`` (keyed by the GPO and its setting objects)."""
    key = tuple(map(id, gpo.settings))
    entry = _text_memo.get(id(gpo))
    if entry is not None and entry[0] is gpo and entry[1] == key:
        return entry[2]
    text = _gpo_settings_text(gpo)
    _text_memo[id(gpo)] = (gpo, key, text)
    return text


def _gpo_settings_text(gpo: Gpo) -> str:
    """All of a GPO's setting text and raw JSON (escapes as spaces), one string.

    Settings are separated by NUL, which is neither whitespace nor base64, so
    no match can span two settings: a GPO-level test is a superset of the
    per-setting tests it gates.
    """
    parts: list[str] = []
    for setting in gpo.settings:
        parts.extend(
            (
                setting.identity,
                setting.display_name,
                setting.display_value,
                setting.cse,
                setting.gpo_id,
                setting.side,
                setting.source_state,
            )
        )
        blob = _raw_blob(setting.raw)
        if blob is None:
            return ""  # not serializable: callers fall back to per-setting tests
        parts.append(_JSON_ESCAPE.sub(" ", blob) if "\\" in blob else blob)
        if '"children"' in blob:
            parts.append(joined_text(setting.raw))  # copies split across nodes
    return "\x00".join(parts)


def _gpo_may_label(gpo: Gpo) -> bool:
    text = _settings_text(gpo)
    if not text:
        return bool(gpo.settings)
    # Raw JSON is ASCII (escaped), so non-ASCII here comes from setting text,
    # which per-setting tests then examine.
    return (
        not text.isascii()
        or mentions_cpassword(text)
        or ('"children"' in text and '"text"' in text)
    )


def _estate_may_hit(estate: Estate, chaser: Chaser) -> bool:
    """``_gpo_may_hit`` for all GPOs at once (NUL-separated, still a superset)."""
    if chaser.exact or chaser.walk_needed:
        return True
    texts = []
    for gpo in estate.gpos:
        text = _settings_text(gpo)
        if not text and gpo.settings:
            return True
        texts.append(text)
    return chaser.contains("\x00".join(texts))


def _gpo_may_hit(gpo: Gpo, chaser: Chaser) -> bool:
    if chaser.exact or chaser.walk_needed:
        return True
    text = _settings_text(gpo)
    return (not text and bool(gpo.settings)) or chaser.contains(text)


def _setting_mentions(setting: Any) -> bool:
    blob = _raw_blob(setting.raw)
    if blob is None:
        return True
    text = "\x00".join(
        (setting.identity, setting.display_name, setting.display_value, setting.cse, blob)
    )
    if mentions_cpassword(text) or "\\u" in blob:
        return True
    return '"children"' in blob and '"text"' in blob and _has_mixed(setting.raw)


def _setting_hits(setting: Any, chaser: Chaser) -> bool:
    """Superset gate: could the chase change, or refuse, anything in *setting*?"""
    if chaser.exact or chaser.walk_needed:
        return True
    texts = "\x00".join(
        (
            setting.identity,
            setting.display_name,
            setting.display_value,
            setting.cse,
            setting.gpo_id,
            setting.side,
            setting.source_state,
        )
    )
    if chaser.contains(texts):
        return True
    blob = _raw_blob(setting.raw)
    if blob is None or chaser.hits_json(blob):
        return True
    return '"children"' in blob and chaser.contains(joined_text(setting.raw))


def _assign(estate: Estate, source: Estate, *, gpos: list[Gpo]) -> None:
    for f in dataclasses.fields(estate):
        if f.name.startswith("_") or f.name == "gpos":
            continue
        setattr(estate, f.name, getattr(source, f.name))
    estate.gpos = gpos
    estate._gpo_index = None


def sysvol_cpassword_values(gpos: Iterable[Gpo]) -> set[str]:
    """Every cpassword value in the GPOs' collected SYSVOL GPP XML (all forms).

    The parsed trees are scratch copies; the files are never modified.
    """
    from gpo_lens.detection._gpp import _walk_gpp_xml

    found: set[str] = set()
    for gpo in gpos:
        for walk in _walk_gpp_xml(gpo, only_known=False):
            root = walk.tree.getroot()
            if root is not None:
                found |= redact_element_tree(root)
    return found


def sysvol_values_at(paths: Iterable[str]) -> set[str]:
    """``sysvol_cpassword_values`` for bare SYSVOL GPO directories."""
    from types import SimpleNamespace

    return sysvol_cpassword_values(
        cast("Gpo", SimpleNamespace(id="", name="", sysvol_path=p)) for p in paths
    )


def sanitize_for_storage(estate: Estate) -> frozenset[str]:
    """``sanitize_estate`` with the estate's own SYSVOL values; returns all values.

    The JSON text computed for each setting's raw structure is kept for
    :func:`stored_json`; call :func:`release_serialized` after writing.
    """
    return sanitize_estate(estate, sysvol_cpassword_values(estate.gpos), retain_serialized=True)


def stored_json(raw: Any) -> str:
    """``json.dumps(raw, sort_keys=True)``, reusing the text sanitizing computed."""
    blob = _raw_blob(raw)
    return blob if blob is not None else json.dumps(raw, sort_keys=True)


def release_serialized() -> None:
    _blob_memo.clear()


def scrub_records(records: Iterable[Any], values: Iterable[str], location: str) -> list[Any]:
    """Labelled-form redaction plus copy chasing for derived records (findings).

    Descriptive fields per ``REWRITABLE_FIELDS``; a copy elsewhere refuses.
    """
    chaser = Chaser(values)
    out = []
    for record in records:
        found: set[str] = set()
        labelled = _label_pass(record, found)
        if found:
            chaser = Chaser(set(chaser.values) | found)
        record = chase(labelled, chaser, location, rewritable=False)
        recheck: set[str] = set()
        _label_pass(record, recheck)
        if recheck or (chaser and any(chaser.hits(t) for t in _strings(record))):
            raise CpasswordResidualError(location)
        out.append(record)
    return out


def iter_strings(obj: Any) -> Iterator[str]:
    """Every string (values and mapping keys) in a model object or structure."""
    return _strings(obj)


# --- Diagnostics ---------------------------------------------------------------

# Values discovered by the innermost active guard and every guard around it.
_ACTIVE_VALUES: ContextVar[tuple[set[str], ...]] = ContextVar(
    "gpo_lens_cpassword_diagnostic_values", default=()
)


def _active_values() -> set[str]:
    out: set[str] = set()
    for values in _ACTIVE_VALUES.get():
        out |= values
    return out


def scrub_diagnostic(text: str, values: Iterable[str] | None = None) -> str:
    """A human-facing message with labelled forms and discovered copies redacted."""
    text = redact_text(text)
    chaser = Chaser(_active_values() if values is None else values)
    return chaser.sub(text) if chaser and chaser.hits(text) else text


def scrub_exception(exc: BaseException | None, values: Iterable[str] | None = None) -> None:
    """Scrub an exception's message (and chained ones) in place."""
    pool = set(_active_values() if values is None else values)
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        exc.args = tuple(scrub_diagnostic(a, pool) if isinstance(a, str) else a for a in exc.args)
        for attr in ("msg", "filename", "filename2", "strerror", "text"):
            value = getattr(exc, attr, None)
            if isinstance(value, str):
                try:
                    setattr(exc, attr, scrub_diagnostic(value, pool))
                except (AttributeError, TypeError):
                    pass
        notes = getattr(exc, "__notes__", None)
        if isinstance(notes, list):
            notes[:] = [scrub_diagnostic(n, pool) if isinstance(n, str) else n for n in notes]
        exc = exc.__cause__ or exc.__context__


@contextmanager
def guarded_diagnostics(values: set[str] | None = None) -> Iterator[set[str]]:
    """Hold back warnings and scrub diagnostics against the run's values.

    Yields a mutable set; callers add values as they discover them. Warnings
    raised inside are re-emitted on exit (also when an exception escapes),
    scrubbed against every value known by then, including those of enclosing
    guards. An escaping exception is scrubbed in place. Log records created
    inside are scrubbed against the values known at that moment.
    """
    pool: set[str] = set() if values is None else values
    token = _ACTIVE_VALUES.set((*_ACTIVE_VALUES.get(), pool))
    caught: list[warnings.WarningMessage] = []
    try:
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            try:
                yield pool
            finally:
                caught = list(recorded)
    except BaseException as exc:
        scrub_exception(exc, _active_values())
        raise
    finally:
        everything = _active_values()
        _ACTIVE_VALUES.reset(token)
        for item in caught:
            message = item.message
            text = scrub_diagnostic(str(message), everything)
            category = item.category if isinstance(item.category, type) else UserWarning
            warnings.warn_explicit(text, category, item.filename, item.lineno or 0)


_base_record_factory = logging.getLogRecordFactory()


def _scrubbing_record_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
    record = _base_record_factory(*args, **kwargs)
    if _ACTIVE_VALUES.get():
        message = record.getMessage()
        clean = scrub_diagnostic(message)
        if clean != message:
            record.msg, record.args = clean, None
        if record.exc_info and record.exc_info[1] is not None:
            scrub_exception(record.exc_info[1])
    return record


if getattr(logging.getLogRecordFactory(), "__name__", "") != "_scrubbing_record_factory":
    logging.setLogRecordFactory(_scrubbing_record_factory)
