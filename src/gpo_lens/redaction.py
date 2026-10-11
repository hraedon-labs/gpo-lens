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

This is a core module: stdlib only, and it must not import ``narration`` or
``web``.
"""

from __future__ import annotations

import dataclasses
import json
import re
from collections.abc import Iterable, Iterator
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
_B64 = "A-Za-z0-9+/"  # token boundary; "=" padding is consumed, not a boundary
_B64_BODY = re.compile(r"[A-Za-z0-9+/]+")


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
    return isinstance(name, str) and localname(name).casefold() == "cpassword"


def mentions_cpassword(text: str) -> bool:
    """Cheap pre-check: does *text* contain ``cpassword`` in any casing?"""
    return _HINT.search(text) is not None


def _secret(value: object) -> bool:
    return isinstance(value, str) and value.strip() != "" and value != CPASSWORD_MARKER


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
        if inner == "":
            return match.group(0)
        found.add(inner)
        return f"{match.group('key')}{quote}{CPASSWORD_MARKER}{quote}"

    return _INLINE.sub(replace, text), found


def redact_text(text: str) -> str:
    """Inline redaction only (no copy chasing)."""
    return redact_inline(text)[0]


def normalized_values(values: Iterable[str]) -> set[str]:
    """Each value plus its stripped and whitespace-free variants."""
    out: set[str] = set()
    for value in values:
        for variant in (value, value.strip(), "".join(value.split())):
            if variant and variant != CPASSWORD_MARKER:
                out.add(variant)
    return out


def _ciphertext_shaped(value: str) -> bool:
    body = value.rstrip("=")
    if len(body) < UNBOUNDED_CHASE_LENGTH or not _B64_BODY.fullmatch(body):
        return False
    if len(body) % 4 == 1:
        return False
    return (len(body) * 3 // 4) % 16 == 0


def chase_eligible(value: str) -> bool:
    """Estate-wide copy chasing applies to this (normalized) value."""
    if len(value) < MIN_CHASE_LENGTH or value in CPASSWORD_MARKER:
        return False
    if _ciphertext_shaped(value):
        return True
    return any(c.isalpha() for c in value) and any(c.isdigit() for c in value)


_TOKEN = re.compile(r"[A-Za-z0-9+/]+=*")
_JSON_ESCAPE = re.compile(r"\\(?:u[0-9a-fA-F]{4}|.)")


class Chaser:
    """Replace copies of known values under the boundary rules above.

    Base64-alphabet values are matched per token (a maximal run of
    ``[A-Za-z0-9+/]`` plus trailing ``=`` padding): a bounded value must *be* a
    token; a ciphertext-shaped value may also sit inside a longer token. Values
    with other characters (rare; synthetic) use a boundary-guarded regex.
    """

    def __init__(self, values: Iterable[str], *, local: bool = False) -> None:
        normalized = normalized_values(values)
        if local:
            eligible = {
                v
                for v in normalized
                if len(v) >= MIN_LOCAL_CHASE_LENGTH and v not in CPASSWORD_MARKER
            }
        else:
            eligible = {v for v in normalized if chase_eligible(v)}
        self.local = local
        self.values: tuple[str, ...] = tuple(sorted(eligible, key=lambda v: (-len(v), v)))
        self.exact = frozenset(normalized) if local else frozenset()
        bounded: set[str] = set()
        unbounded: list[str] = []
        other: list[str] = []
        for value in self.values:
            core = value.rstrip("=") or value
            if not _B64_BODY.fullmatch(core):
                other.append(rf"(?<![{_B64}]){re.escape(core)}=*(?![{_B64}])")
            elif not local and _ciphertext_shaped(value):
                unbounded.append(core)
            else:
                bounded.add(core)
        self._bounded = frozenset(bounded)
        self._unbounded = tuple(sorted(set(unbounded), key=len, reverse=True))
        self._min_unbounded = min((len(u) for u in self._unbounded), default=0)
        self._other = re.compile("|".join(other)) if other else None
        # JSON text escapes quotes and backslashes; such values need a walk.
        self.walk_needed = any(
            any(c in v for c in '"\\') or not v.isprintable() for v in self.values
        )

    def __bool__(self) -> bool:
        return bool(self._bounded or self._unbounded or self._other or self.exact)

    def _token_hit(self, token: str) -> bool:
        core = token.rstrip("=")
        if core in self._bounded:
            return True
        return len(core) >= self._min_unbounded > 0 and any(u in core for u in self._unbounded)

    def hits(self, text: str) -> bool:
        if self.exact and text.strip() in self.exact:
            return True
        if self._other is not None and self._other.search(text):
            return True
        if self._bounded or self._unbounded:
            return any(self._token_hit(m.group()) for m in _TOKEN.finditer(text))
        return False

    def _replace_token(self, match: re.Match[str]) -> str:
        token = match.group()
        core = token.rstrip("=")
        if core in self._bounded:
            return CPASSWORD_MARKER
        if not self._token_hit(token):
            return token
        for value in self._unbounded:
            core = core.replace(value, CPASSWORD_MARKER)
        return core if core != CPASSWORD_MARKER else CPASSWORD_MARKER

    def sub(self, text: str) -> str:
        if self.exact and text.strip() in self.exact:
            return CPASSWORD_MARKER
        if self._bounded or self._unbounded:
            text = _TOKEN.sub(self._replace_token, text)
        if self._other is not None:
            text = self._other.sub(CPASSWORD_MARKER, text)
        return text

    def hits_json(self, blob: str) -> bool:
        """``hits`` on JSON text, treating escapes as the boundaries they encode."""
        if "\\" in blob:
            blob = _JSON_ESCAPE.sub(" ", blob)
        return self.hits(blob)


# --- XML ---------------------------------------------------------------------


def _mixed(elem: Element) -> bool:
    if len(elem) == 0:
        return False
    if elem.text and elem.text.strip():
        return True
    return any(child.tail and child.tail.strip() for child in elem)


def redact_element_tree(root: Element) -> set[str]:
    """Redact every labelled cpassword value in *root*'s subtree, in place.

    Returns the distinct values removed (un-normalized) for copy chasing.
    """
    found: set[str] = set()
    for elem in list(root.iter()):
        if is_cpassword_name(elem.tag):
            pieces = [t.strip() for t in elem.itertext() if t.strip()]
            content = "".join(pieces)
            found.update(p for p in pieces if _secret(p))
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
    # Deepest first; collapse only an element whose joined text still holds one.
    for elem in reversed(list(root.iter())):
        if not _mixed(elem):
            continue
        joined = "".join(elem.itertext())
        new, values = redact_inline(joined)
        if values:
            found |= values
            for child in list(elem):
                elem.remove(child)
            elem.text = new
    return found


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


def _joined_text(obj: dict[str, Any]) -> str:
    """Concatenated element text of an ``element_to_dict`` node (no tails kept)."""
    parts = [obj["text"]] if isinstance(obj.get("text"), str) else []
    for child in obj.get("children", []) or []:
        if isinstance(child, dict):
            parts.append(_joined_text(child))
    return "".join(parts)


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
        found.update(t for t in texts if _secret(t))
        joined = "".join(t.strip() for t in texts if t.strip())
        if _secret(joined):
            found.add(joined)
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
            secrets = [t for t in texts if _secret(t)]
            found.update(secrets)
            out[key] = CPASSWORD_MARKER if any(t.strip() for t in texts) else value
        else:
            out[key] = _redact_obj(value, found)
    # Mixed content stored by element_to_dict (text plus children): an
    # assignment split between the node's text and its children.
    if "tag" in out and isinstance(out.get("text"), str) and out.get("children"):
        new, values = redact_inline(_joined_text(out))
        if values:
            found |= values
            out = {k: v for k, v in out.items() if k not in ("children", "text")}
            out["text"] = new
    return out


def redact_structure(obj: Any) -> tuple[Any, set[str]]:
    """Return a labelled-value-redacted copy of a JSON-like structure, and the values."""
    found: set[str] = set()
    return _redact_obj(obj, found), found


def _blob(value: Any) -> str | None:
    """JSON text of a JSON-native container, or None (e.g. it holds dataclasses)."""
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
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
            new = chase(
                old, chaser, location, rewritable=f.name in allowed, field=f"{cls}.{f.name}"
            )
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
                blob = _blob(old)
                if blob is not None and not mentions_cpassword(blob):
                    continue
                new, values = redact_structure(old)
                found |= values
            else:
                new = _label_pass(old, found)
            if new != old:
                changes[f.name] = new
        return dataclasses.replace(obj, **changes) if changes else obj
    if isinstance(obj, dict):
        blob = _blob(obj)
        if obj and blob is not None and not mentions_cpassword(blob):
            return obj
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


def sanitize_estate(estate: Estate, known: Iterable[str] = ()) -> frozenset[str]:
    """Redact labelled values, then chase every copy across the estate, in place.

    *known* adds values discovered elsewhere (the report tree, SYSVOL files).
    Returns every value discovered (un-normalized), for downstream scrubbing of
    records derived from the estate (findings). Raises
    :class:`CredentialInIdentityError` rather than rewrite a structural field.
    """
    found: set[str] = set(known)
    # Labelled forms; a setting's own values also chase through that setting.
    for gpo in estate.gpos:
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
        for gpo in estate.gpos:
            location = f"GPO {gpo.id}"
            stripped = dataclasses.replace(gpo, settings=[])
            new_gpo = chase(stripped, chaser, location, rewritable=False)
            settings = [
                chase(s, chaser, location, rewritable=False) if _setting_hits(s, chaser) else s
                for s in gpo.settings
            ]
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
    return frozenset(found)


def _setting_mentions(setting: Any) -> bool:
    texts = (setting.identity, setting.display_name, setting.display_value, setting.cse)
    if any(mentions_cpassword(t) for t in texts):
        return True
    blob = _blob(setting.raw)
    return blob is None or mentions_cpassword(blob)


def _setting_hits(setting: Any, chaser: Chaser) -> bool:
    if chaser.exact or chaser.walk_needed:
        return True
    texts = (
        setting.identity,
        setting.display_name,
        setting.display_value,
        setting.cse,
        setting.gpo_id,
        setting.side,
        setting.source_state,
    )
    if any(chaser.hits(t) for t in texts):
        return True
    blob = _blob(setting.raw)
    return blob is None or chaser.hits_json(blob)


def _assign(estate: Estate, source: Estate, *, gpos: list[Gpo]) -> None:
    for f in dataclasses.fields(estate):
        if f.name.startswith("_") or f.name == "gpos":
            continue
        setattr(estate, f.name, getattr(source, f.name))
    estate.gpos = gpos
    estate._gpo_index = None


def residual_copies(obj: Any, values: Iterable[str]) -> bool:
    """True if any chase-eligible value still occurs in any string of *obj*."""
    chaser = Chaser(values)
    return bool(chaser) and any(chaser.hits(s) for s in _strings(obj))


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
    """``sanitize_estate`` with the estate's own SYSVOL values; returns all values."""
    return sanitize_estate(estate, sysvol_cpassword_values(estate.gpos))


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
        out.append(chase(labelled, chaser, location, rewritable=False))
    return out
