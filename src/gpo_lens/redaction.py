"""Redact Group Policy Preferences ``cpassword`` values before they are stored.

A GPP ``cpassword`` is AES-encrypted with a key Microsoft published (MS14-025),
so the stored value is a recoverable credential. gpo-lens never needs the value:
the ``cpassword`` finding is about *presence*, and it is computed from the SYSVOL
files at ingest. Every value that reaches the parsed model or the database is
therefore replaced with :data:`CPASSWORD_MARKER`. No hash or fingerprint of the
value is kept: nothing compares values (trend counts hits; the finding
lifecycle tracks presence per GPO), and any cpassword is already compromised,
so "rotated" versus "unchanged" carries no remediation meaning.

Three shapes are handled, in every casing and namespace:

* an attribute whose local name is ``cpassword`` (the real GPP form);
* an element whose local name is ``cpassword`` (its text and subtree);
* an inline assignment such as ``cpassword="..."`` inside text or another
  attribute value, which is how an escaped XML fragment stored verbatim looks
  after parsing.

An empty value (``cpassword=""``) carries no secret and is left empty.

This is a core module: stdlib only, and it must not import ``narration`` or
``web``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any
from xml.etree.ElementTree import Element

from gpo_lens.normalize import localname

CPASSWORD_MARKER = "[redacted cpassword]"

# Detail persisted on every ``cpassword`` finding. It names no characters of the
# value: earlier releases stored the first four, which the v11 migration erases.
CPASSWORD_FINDING_DETAIL = (
    "cpassword attribute present; value not stored or shown "
    "(any cpassword is recoverable with the key Microsoft published, MS14-025)"
)

# Known values shorter than this are redacted structurally only. A free-text
# substring replacement of a very short value would corrupt unrelated text.
MIN_KNOWN_VALUE_LENGTH = 6

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


def is_cpassword_name(name: object) -> bool:
    """True for ``cpassword`` in any casing, with or without a namespace."""
    return isinstance(name, str) and localname(name).casefold() == "cpassword"


def mentions_cpassword(text: str) -> bool:
    """Cheap pre-check: does *text* contain ``cpassword`` in any casing?"""
    return _HINT.search(text) is not None


def _inline_replacement(match: re.Match[str]) -> str:
    value = match.group("value")
    for quote in _QUOTES:
        if len(value) >= 2 * len(quote) and value.startswith(quote) and value.endswith(quote):
            inner = value[len(quote) : -len(quote)]
            if inner == "":
                return match.group(0)
            return f"{match.group('key')}{quote}{CPASSWORD_MARKER}{quote}"
    return f"{match.group('key')}{CPASSWORD_MARKER}"


def redact_text(text: str, known_values: Iterable[str] = ()) -> str:
    """Redact inline ``cpassword=...`` assignments and any known values in *text*."""
    out = text
    for value in sorted(set(known_values), key=len, reverse=True):
        if len(value) >= MIN_KNOWN_VALUE_LENGTH and value in out:
            out = out.replace(value, CPASSWORD_MARKER)
    if mentions_cpassword(out):
        out = _INLINE.sub(_inline_replacement, out)
    return out


def _secret(value: object) -> bool:
    return isinstance(value, str) and value != "" and value != CPASSWORD_MARKER


def redact_element_tree(root: Element) -> set[str]:
    """Redact every ``cpassword`` value in *root*'s subtree, in place.

    Returns the distinct values removed so a caller can scrub copies of them
    that were already derived elsewhere.
    """
    removed: set[str] = set()
    for elem in list(root.iter()):
        if is_cpassword_name(elem.tag):
            pieces = [t.strip() for t in elem.itertext() if t.strip()]
            content = "".join(pieces)
            for value in elem.attrib.values():
                if _secret(value):
                    removed.add(value)
            removed.update(p for p in pieces if _secret(p))
            if content and content != CPASSWORD_MARKER:
                removed.add(content)
            for child in list(elem):
                elem.remove(child)
            had_secret = bool(content) or any(_secret(v) for v in elem.attrib.values())
            for key, value in list(elem.attrib.items()):
                if value != "":
                    elem.set(key, CPASSWORD_MARKER)
            if had_secret:
                elem.text = CPASSWORD_MARKER
            if elem.tail and mentions_cpassword(elem.tail):
                elem.tail = redact_text(elem.tail)
            continue
        for key, value in list(elem.attrib.items()):
            if is_cpassword_name(key):
                if _secret(value):
                    removed.add(value)
                    elem.set(key, CPASSWORD_MARKER)
            elif mentions_cpassword(value):
                elem.set(key, redact_text(value))
        if elem.text and mentions_cpassword(elem.text):
            elem.text = redact_text(elem.text)
        if elem.tail and mentions_cpassword(elem.tail):
            elem.tail = redact_text(elem.tail)
    chase = {v for v in removed if len(v) >= MIN_KNOWN_VALUE_LENGTH}
    if chase:
        # A value can be copied into another field (a path, a description, a
        # second item). Replace every copy, or the output layer, which can no
        # longer learn the value from a cpassword field, could not mask it.
        for elem in root.iter():
            for key, value in list(elem.attrib.items()):
                if any(v in value for v in chase):
                    elem.set(key, redact_text(value, chase))
            if elem.text and any(v in elem.text for v in chase):
                elem.text = redact_text(elem.text, chase)
            if elem.tail and any(v in elem.tail for v in chase):
                elem.tail = redact_text(elem.tail, chase)
    return removed


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


def _redact_obj(obj: Any, removed: set[str]) -> Any:
    if isinstance(obj, str):
        return redact_text(obj) if mentions_cpassword(obj) else obj
    if isinstance(obj, list):
        return [_redact_obj(item, removed) for item in obj]
    if not isinstance(obj, dict):
        return obj
    if is_cpassword_name(obj.get("tag")):
        # An element_to_dict() rendering of a <cpassword> element: the whole
        # subtree is the secret. Keep only the tag and a marker.
        texts: list[str] = []
        _collect_text(obj, texts)
        removed.update(t for t in texts if _secret(t))
        result: dict[str, Any] = {"tag": obj["tag"]}
        if any(texts):  # a secret, or the marker from an earlier pass
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
                        removed.add(attr_value)
                        attr_value = CPASSWORD_MARKER
                    attrs_out[name] = attr_value
                else:
                    attrs_out[name] = _redact_obj(attr_value, removed)
            out[key] = attrs_out
        elif is_cpassword_name(key):
            # A mapping keyed by "cpassword" (any other record shape).
            if _secret(value):
                removed.add(value)
                out[key] = CPASSWORD_MARKER
            elif isinstance(value, (dict, list)):
                texts = []
                _collect_text(value, texts)
                removed.update(t for t in texts if _secret(t))
                out[key] = CPASSWORD_MARKER if any(texts) else value
            else:
                out[key] = value
        else:
            out[key] = _redact_obj(value, removed)
    return out


def redact_structure(obj: Any) -> tuple[Any, set[str]]:
    """Return a redacted copy of a JSON-like structure and the values removed.

    Understands the ``element_to_dict`` shape (``tag``/``text``/``@attr``/
    ``children``) used by ``Setting.raw`` and any mapping keyed ``cpassword``;
    every other string is scanned for inline assignments.
    """
    removed: set[str] = set()
    return _redact_obj(obj, removed), removed


def scrub_known_values(obj: Any, known_values: Iterable[str]) -> Any:
    """Replace known secret values inside every string of a JSON-like structure."""
    values = tuple(v for v in set(known_values) if len(v) >= MIN_KNOWN_VALUE_LENGTH)
    if not values:
        return obj

    def walk(item: Any) -> Any:
        if isinstance(item, str):
            return redact_text(item, values)
        if isinstance(item, list):
            return [walk(x) for x in item]
        if isinstance(item, dict):
            return {k: walk(v) for k, v in item.items()}
        return item

    return walk(obj)


def redact_json_text(text: str, known_values: Iterable[str] = ()) -> tuple[str, set[str]]:
    """Redact a stored JSON document (structurally) or, if not JSON, as text.

    Returns ``(new_text, removed_values)``. ``new_text`` is *text* unchanged
    when nothing needed redacting, so callers can skip no-op writes.
    """
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        parsed = None
    if isinstance(parsed, (dict, list)):
        redacted, removed = redact_structure(parsed)
        redacted = scrub_known_values(redacted, set(known_values) | removed)
        if redacted == parsed:
            return text, removed
        return json.dumps(redacted, sort_keys=True), removed
    new_text = redact_text(text, known_values)
    return new_text, set()
