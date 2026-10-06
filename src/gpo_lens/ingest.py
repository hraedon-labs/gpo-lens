"""Parse collector outputs into the normalized model."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import warnings
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol, cast, runtime_checkable
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as ET

from gpo_lens.model import (
    CoverageGap,
    DelegationEntry,
    Estate,
    Gpo,
    GpoLink,
    GroupMembership,
    OuRecord,
    ResolvedPrincipal,
    Setting,
    SettingRaw,
    Side,
    Som,
    SomLink,
    WmiFilter,
)
from gpo_lens.normalize import (
    canonical_guid,
    is_registry_cse,
    load_json,
    localname,
    parse_bool,
    parse_dt,
    parse_int,
)
from gpo_lens.normalize import (
    child_by_localname as _child_by_localname,
)
from gpo_lens.normalize import (
    children_by_localname as _children_by_localname,
)
from gpo_lens.paths import ci_child, ci_path
from gpo_lens.registry_pol import parse_registry_pol

# Decompression bomb guard: refuse to expand zip contents beyond this total.
_MAX_DECOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
# Lower cap for the in-memory baseline/golden zip path — baselines are
# typically <100 MB, so 256 MB is generous while preventing memory exhaustion.
_MAX_BASELINE_UNCOMPRESSED_BYTES = 256 * 1024 * 1024


@runtime_checkable
class _Readable(Protocol):
    def read(self, size: int = -1) -> bytes: ...


class SizeLimitedReader:
    """Wraps a readable stream and raises ValueError if bytes exceed a limit.

    Counts *actual* decompressed bytes during streaming reads, making it
    immune to zip-bomb attacks that spoof ``info.file_size`` headers.

    The ``read`` method caps the effective read size to 65536 bytes so that
    a caller passing a huge ``size`` (e.g. 1 GB) cannot cause an excessive
    single allocation before the limit check fires.
    """

    def __init__(self, source: _Readable, limit: int) -> None:
        self._source = source
        self._limit = limit
        self._total = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = 65536
        elif size > 0:
            size = min(size, 65536)
        # size == 0: pass through as-is
        chunk = self._source.read(size)
        if chunk:
            self._total += len(chunk)
            if self._total > self._limit:
                raise ValueError("zip decompressed size exceeds limit")
        return chunk


def _streaming_zip_read(
    zf: zipfile.ZipFile,
    name: str,
    total_counter: list[int],
    max_bytes: int | None = None,
) -> bytes:
    """Read a zip entry with streaming decompression size enforcement.

    Unlike ``zf.read(name)`` which decompresses the entire entry into
    memory before any size check, this reads in fixed-size chunks through
    :class:`SizeLimitedReader`, enforcing the cap *during* decompression.
    This prevents zip-bomb attacks where ``info.file_size`` headers are
    spoofed to a small value while the actual content is much larger.

    **Memory tradeoff:** The size limit is enforced *during* streaming
    decompression, but the full (capped) content is buffered into a
    ``BytesIO`` object in memory.  This is necessary because the caller
    (e.g. ``load_baseline_from_zip``) needs the complete bytes to open a
    nested ``ZipFile``.  Baseline zips are typically under 100 MB, well
    within the 2 GB cap.  For the ``_safe_extract`` path (disk extraction),
    bytes are written directly to disk, not buffered.
    """
    if max_bytes is None:
        max_bytes = _MAX_DECOMPRESSED_BYTES
    remaining = max_bytes - total_counter[0]
    if remaining <= 0:
        raise ValueError("zip decompressed size exceeds limit")

    buf = io.BytesIO()
    with zf.open(name) as src:
        wrapped = SizeLimitedReader(src, remaining)
        while True:
            chunk = wrapped.read(65536)
            if not chunk:
                break
            buf.write(chunk)
        bytes_read = wrapped._total

    total_counter[0] += bytes_read
    if total_counter[0] > max_bytes:
        raise ValueError("zip decompressed size exceeds limit")

    return buf.getvalue()


_localname = localname


def _load_json_records(path: str | Path) -> list[dict[str, Any]]:
    """Load JSON and return only dict entries, warning about skipped non-dicts.

    Consolidates the repeated ``load_json`` → list-wrap → non-dict-skip pattern
    used by ``parse_inheritance``, ``merge_metadata``, ``parse_wmi_filters``,
    ``parse_ou_tree``, ``parse_sites``, and ``parse_coverage_gaps``.
    """
    data = load_json(path)
    if isinstance(data, dict):
        return [data]
    if not isinstance(data, list):
        warnings.warn(
            f"Unexpected top-level {type(data).__name__} in {path}; expected object or array",
            stacklevel=2,
        )
        return []
    records = [r for r in data if isinstance(r, dict)]
    skipped = len(data) - len(records)
    if skipped:
        warnings.warn(
            f"Skipped {skipped} non-dict entr{'y' if skipped == 1 else 'ies'} in {path}",
            stacklevel=2,
        )
    return records


def _text(elem: Element | None) -> str | None:
    """Text content of an element, or None."""
    if elem is None:
        return None
    return elem.text


def element_to_dict(elem: Element) -> SettingRaw:
    """Recursively render an element as a lossless dict."""
    result: SettingRaw = {"tag": _localname(elem.tag)}
    if elem.text and elem.text.strip():
        result["text"] = elem.text.strip()
    if elem.attrib:
        result["@attr"] = dict(elem.attrib)
    children = [element_to_dict(child) for child in elem]
    if children:
        result["children"] = children
    return result


def _stable_hash(raw: SettingRaw) -> str:
    """Deterministic hash of a raw dict for generic fallback identity."""
    payload = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _first_non_empty_text_or_attr(elem: Element) -> str:
    """First non-empty text content or attribute value."""
    if elem.text and elem.text.strip():
        return elem.text.strip()
    for k, v in elem.attrib.items():
        if v and v.strip():
            return v.strip()
    for child in elem:
        result = _first_non_empty_text_or_attr(child)
        if result:
            return result
    return ""


_SEC_VALUE_TAGS = (
    "SettingBoolean",
    "SettingNumber",
    "SettingString",
    "StartupMode",
    "Log",
)


def _parse_security_setting(block: Element) -> tuple[str, str, str] | None:
    """Readable identity for a Security CSE block.

    Real exports name the setting with a child element, not an attribute:
    ``<Account><Name>ClearTextPassword</Name>``, ``<UserRightsAssignment><Name>
    SeAssignPrimaryTokenPrivilege</Name>``, ``<SecurityOptions><KeyName>…``,
    ``<RestrictedGroups><GroupName><Name>BUILTIN\\…``. Fall back to the legacy
    ``Name``/``Type`` attribute form for older fixtures.
    """
    # Identity prefix is the setting class. In the child-element form that is the
    # block's own tag (<Account>, <UserRightsAssignment>, …); in the legacy
    # attribute form (<Security Name=… Type="Account">) it is the Type attribute.
    # Both must agree so the same setting matches across exports.
    prefix = _localname(block.tag)
    name = _text(_child_by_localname(block, "Name"))
    if not name:
        name = _text(_child_by_localname(block, "KeyName"))
    if not name:
        gn = _child_by_localname(block, "GroupName")
        if gn is not None:
            name = _text(_child_by_localname(gn, "Name")) or _text(_child_by_localname(gn, "SID"))
    if not name and block.get("Name"):
        name = block.get("Name")
        prefix = block.get("Type") or prefix
    if not name:
        return None
    value = ""
    for vt in _SEC_VALUE_TAGS:
        ch = _child_by_localname(block, vt)
        if ch is not None and ch.text and ch.text.strip():
            value = ch.text.strip()
            break
    return f"{prefix}:{name}", name, value


def _parse_registry_setting(block: Element) -> tuple[str, str, str] | None:
    """Return (identity, display_name, display_value) for Registry / Windows Registry."""
    key = block.get("KeyName") or block.get("Key") or ""
    value_name = block.get("ValueName") or block.get("Name") or ""
    if key or value_name:
        identity = f"{key}:{value_name}" if (key and value_name) else (key or value_name)
        display_name = value_name or key or _localname(block.tag)
        display_value = _first_non_empty_text_or_attr(block)
        return identity, display_name, display_value
    return None


# Administrative-Templates option sub-elements that carry a configured value.
# These sit directly under <Policy> (alongside Name/State/Category) and hold the
# data the policy writes — dropped by the old parser, which surfaced only State
# (WI-080). Each has a <Name> label; the value lives in <Value> (text, a nested
# <Name>, or a collection of <Element>/<string> entries) or, for CheckBox, in a
# per-box <State>. <Text> is a display-only label with no value (skipped).
_ADMX_OPTION_TAGS = frozenset(
    {
        "DropDownList",
        "EditText",
        "EditTextBox",
        "Numeric",
        "CheckBox",
        "ListBox",
        "MultiText",
    }
)
_ADMX_SUMMARY_MAX = 160


def _summarize_admx_option(opt: Element) -> str | None:
    """Compact ``label: value`` summary for one Admin-Template option element.

    Returns ``None`` when the element carries no usable value (so it is omitted
    rather than rendered as an empty ``label:``).
    """
    tag = _localname(opt.tag)
    label = (_text(_child_by_localname(opt, "Name")) or "").strip().rstrip(":")

    if tag == "CheckBox":
        # No <Value>; the box's own <State> (Enabled/Disabled) is the data.
        st = (_text(_child_by_localname(opt, "State")) or "").strip()
        if not (label or st):
            return None
        return f"{label}: {st}" if label else st

    value_el = _child_by_localname(opt, "Value")
    val = ""
    if value_el is not None:
        direct = (value_el.text or "").strip()
        if direct:
            val = direct
        else:
            # Collection forms: DropDownList -> <Value><Name>selected</Name>;
            # ListBox -> <Value><Element>…; MultiText -> <Value><string>…
            picked = _text(_child_by_localname(value_el, "Name"))
            if picked and picked.strip():
                val = picked.strip()
            else:
                entries = [c for c in value_el if _localname(c.tag) in ("Element", "string")]
                if entries:
                    plural = "entry" if len(entries) == 1 else "entries"
                    val = f"[{len(entries)} {plural}]"

    if not val:
        return None
    return f"{label}: {val}" if label else val


def _summarize_admx_options(block: Element) -> str:
    """Join the configured values of a policy's option elements, length-capped."""
    parts: list[str] = []
    for opt in block:
        if _localname(opt.tag) not in _ADMX_OPTION_TAGS:
            continue
        summary = _summarize_admx_option(opt)
        if summary:
            parts.append(summary)
    joined = "; ".join(parts)
    if len(joined) > _ADMX_SUMMARY_MAX:
        joined = joined[: _ADMX_SUMMARY_MAX - 1].rstrip() + "…"
    return joined


def _parse_admin_template_policy(block: Element) -> tuple[str, str, str] | None:
    """Administrative-Templates ``<Policy>`` block (Registry CSE) -> readable row.

    These abstract the underlying registry value behind a friendly policy name
    and a GPMC category path; the raw key is not in the report. Use the
    category-qualified name as identity so it is both human-readable and unique
    within a side, replacing the opaque ``Registry:Policy:<hash>`` fallback.

    ``display_value`` is the policy ``State`` plus a compact summary of its
    configured option values when present (WI-080), e.g.
    ``Enabled — Maximum Log Size (KB): 2097120``. Policies with no options (or
    simply Disabled) keep the bare state.
    """
    name = _text(_child_by_localname(block, "Name"))
    if not name:
        return None
    state = _text(_child_by_localname(block, "State")) or ""
    category = _text(_child_by_localname(block, "Category")) or ""
    identity = f"{category}/{name}" if category else name
    options = _summarize_admx_options(block)
    display_value = f"{state} — {options}" if options else state
    return identity, name, display_value


_HIVE_SHORT = {
    "HKEY_LOCAL_MACHINE": "HKLM",
    "HKEY_CURRENT_USER": "HKCU",
    "HKEY_CLASSES_ROOT": "HKCR",
    "HKEY_USERS": "HKU",
    "HKEY_CURRENT_CONFIG": "HKCC",
}


def _parse_gpp_registry(block: Element) -> list[tuple[str, str, str, SettingRaw]]:
    """Expand a GPP Registry block into one row per concrete ``<Properties>``.

    GPP Registry preferences nest the real writes several levels down
    (``<RegistrySettings>``/``<Collection name>``*/``<Registry>``/
    ``<Properties hive key name value type>``). Parsing the top block as a single
    setting collapses the whole tree into one hashed blob (the unreadable
    ``Registry:Policy:<hash>`` rows); instead emit one readable
    ``HIVE\\key:name = value`` row per ``<Properties>``, each carrying its own
    lossless ``raw`` so the GPP action (C/R/U/D) survives for merge logic.
    """
    out: list[tuple[str, str, str, SettingRaw]] = []
    for props in block.iter():
        if _localname(props.tag) != "Properties":
            continue
        if props.get("key") is None and props.get("hive") is None:
            continue
        hive = props.get("hive") or ""
        hive = _HIVE_SHORT.get(hive, hive)
        key = props.get("key") or ""
        value_name = props.get("name") or ""
        rtype = props.get("type") or ""
        value = props.get("value") or ""
        path = f"{hive}\\{key}" if (hive and key) else (hive or key)
        identity = f"{path}:{value_name}" if value_name else path
        display_name = value_name or "(Default)"
        display_value = f"[{rtype}] {value}" if rtype else value
        out.append((identity, display_name, display_value, element_to_dict(props)))
    return out


def _parse_classic_registry_setting(block: Element) -> tuple[str, str, str] | None:
    """Classic ``<RegistrySetting>`` block: ``<KeyPath>`` + ``<Value><Name>/data``."""
    keypath = _text(_child_by_localname(block, "KeyPath"))
    val = _child_by_localname(block, "Value")
    if keypath is None and val is None:
        return None
    name = ""
    data = ""
    if val is not None:
        name = _text(_child_by_localname(val, "Name")) or ""
        for data_tag in ("Number", "String", "Boolean", "ExpandString"):
            d = _child_by_localname(val, data_tag)
            if d is not None and d.text and d.text.strip():
                data = d.text.strip()
                break
    keypath = keypath or ""
    identity = f"{keypath}:{name}" if (keypath and name) else (keypath or name)
    display_name = name or keypath or _localname(block.tag)
    return identity, display_name, data


# GPP-item Properties attributes, in priority order, that name/locate the item
# when its own ``name`` attribute is blank (e.g. File copy ops, Folder ops).
_GPP_ITEM_KEY_ATTRS = (
    "targetPath",
    "fromPath",
    "path",
    "shortcutPath",
    "serviceName",
    "key",
    "label",
    "value",
)
_GPP_ITEM_VALUE_ATTRS = (
    "path",
    "targetPath",
    "fromPath",
    "shortcutPath",
    "value",
    "startupType",
    "label",
)


def _parse_gpp_container(block: Element) -> list[tuple[str, str, str, SettingRaw]]:
    """Expand a generic GPP-preferences container into one row per item.

    GPP CSEs (Drive Maps, Printers, Services, Scheduled Tasks, Shortcuts, Files,
    Folders, Local Users and Groups, Power Options, …) wrap N items in a
    ``clsid``-bearing container; each item carries a ``uid`` and usually a human
    ``name`` plus a ``<Properties>`` element. Emit each item as its own readable
    row (``ItemType:name``) instead of hashing the whole container.
    """
    if block.get("clsid") is None:
        return []
    items = [c for c in block if c.get("uid") is not None]
    if not items:
        return []
    out: list[tuple[str, str, str, SettingRaw]] = []
    for item in items:
        item_type = _localname(item.tag)
        props = _child_by_localname(item, "Properties")
        pattr = dict(props.attrib) if props is not None else {}
        name = (item.get("name") or pattr.get("name") or "").strip()
        if not name:
            for a in _GPP_ITEM_KEY_ATTRS:
                if pattr.get(a):
                    name = pattr[a]
                    break
        if not name:
            name = item_type
        action = pattr.get("action", "")
        val = ""
        for a in _GPP_ITEM_VALUE_ATTRS:
            if pattr.get(a):
                val = pattr[a]
                break
        display_value = f"[{action}] {val}".strip() if action else (val or item_type)
        out.append((f"{item_type}:{name}", name, display_value, element_to_dict(item)))
    return out


# Child elements whose text names a setting, tried in priority order.
_IDENTITY_CHILD_TAGS = (
    "Name",
    "SubcategoryName",
    "KeyName",
    "Command",
    "Path",
    "IssuedTo",
    "Id",
)
# Child elements whose text summarises a setting's value, tried in priority order.
_VALUE_CHILD_TAGS = (
    "SettingValue",
    "SettingNumber",
    "SettingBoolean",
    "SettingString",
    "State",
    "StartupMode",
    "DefaultSecurityLevel",
    "Value",
    "URL",
    "Type",
)


def _readable_identity(cse: str, block: Element) -> tuple[str, str, str]:
    """Readable identity for any block that no CSE-specific parser claimed.

    Builds ``<BlockType>:<natural key>`` from the first naming child or
    attribute (so e.g. ``AuditSetting:Audit Credential Validation``,
    ``FavoriteURL:Company Intranet``), degrading to the block type alone for a
    genuine singleton (``PlaceFavoritesAtTop``). Never emits a hash — an opaque
    digest is useless to a human reader; a possibly-non-unique readable key is
    disambiguated with an ordinal at append time instead.
    """
    bl = _localname(block.tag)
    key = None
    for ck in _IDENTITY_CHILD_TAGS:
        ch = _child_by_localname(block, ck)
        if ch is not None and ch.text and ch.text.strip():
            key = ch.text.strip()
            break
    if key is None:
        # A naming child that wraps its value (e.g. RestrictedGroups/GroupName/Name).
        for ck in _IDENTITY_CHILD_TAGS:
            ch = _child_by_localname(block, ck)
            if ch is not None:
                nested = _text(_child_by_localname(ch, "Name"))
                if nested:
                    key = nested
                    break
    if key is None:
        for ak in ("name", "Name", "Type", "id", "Id"):
            if block.get(ak):
                key = block.get(ak)
                break
    value = ""
    for vt in _VALUE_CHILD_TAGS:
        ch = _child_by_localname(block, vt)
        if ch is not None and ch.text and ch.text.strip():
            value = ch.text.strip()
            break
    if not value:
        value = _first_non_empty_text_or_attr(block)
    if key:
        return f"{bl}:{key}", key, value
    return bl, bl, value


# Folder Redirection reports the target folder as a KnownFolder GUID; map the
# common ones so the identity reads "Documents", not an opaque GUID.
_KNOWN_FOLDERS = {
    "fdd39ad0-238f-46af-adb4-6c85480369c7": "Documents",
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
    "a520a1a4-1780-4ff6-bd18-167343c5af16": "AppData (Roaming)",
    "1777f761-68ad-4d8a-87bd-30b759fa33dd": "Favorites",
    "374de290-123f-4565-9164-39c4925e467b": "Downloads",
    "33e28130-4e1e-4676-835a-98395c3bc3bb": "Pictures",
    "4bd8d571-6d19-48d3-be97-422220080e43": "Music",
    "18989b1d-99b5-455b-841c-ab7c74e4ddfc": "Videos",
    "b97d20bb-f46a-4c97-ba10-5e3608430854": "Start Menu",
    "62ab5d82-fdc1-4dc3-a9dd-070d1d495d97": "Contacts",
    "bfb9d5e0-c6a9-404c-b2b2-ae6db6af4968": "Links",
    "4c5c32ff-bb9d-43b0-b5b4-2d72e54eaaa4": "Saved Games",
    "7d1d3a04-debb-4115-95cf-2f29da2920da": "Searches",
}


def _parse_folder_redirection(block: Element) -> tuple[str, str, str] | None:
    """``<Folder><Id>{GUID}</Id>`` -> friendly known-folder name + destination."""
    fid = _text(_child_by_localname(block, "Id"))
    if not fid:
        return None
    name = _KNOWN_FOLDERS.get(fid.strip("{}").lower(), fid)
    loc = _child_by_localname(block, "Location")
    dest = _text(_child_by_localname(loc, "DestinationPath")) if loc is not None else ""
    return f"Folder Redirection:{name}", name, dest or ""


def _parse_generic_setting(cse: str, block: Element) -> tuple[str, str, str]:
    """Readable fallback identity/display for any CSE block (never a hash)."""
    return _readable_identity(cse, block)


_AUDIT_CSE = "Advanced Audit Configuration"
_AUDIT_VALUES = {"0": "No Auditing", "1": "Success", "2": "Failure", "3": "Success and Failure"}
_LEGACY_IE_NOTE = (
    "Internet Explorer Maintenance is a legacy, deprecated extension; "
    "these settings do not work with Internet Explorer 10 or newer."
)


def _audit_fields(guid: str, name: str, target: str, value: str) -> tuple[str, str, str, str]:
    """Canonical system subcategory identity; per-user flags stay a separate axis."""
    identity = canonical_guid(guid)
    target = target.strip()
    if target.lower() != "system":
        if not re.fullmatch(r"S-\d+(?:-\d+)+", target, re.IGNORECASE):
            return (
                f"{identity}:{target or '(missing target)'}",
                name or identity,
                f"Unknown audit target: {target or '(missing)'}",
                "Unknown or missing PolicyTarget; target scope is not interpreted.",
            )
        # Per-user masks also encode exclusion flags: never apply the system
        # 0–3 vocabulary to them, or collapse them into system subcategories.
        return (
            f"{identity}:{target or '(missing target)'}",
            name or identity,
            f"Per-user audit flags: {value}",
            "Per-user audit target; inclusion/exclusion flags are preserved, not simulated.",
        )
    return (
        identity,
        name or identity,
        _AUDIT_VALUES.get(value.strip(), f"Unknown audit value: {value or '(missing)'}"),
        ""
        if value.strip() in _AUDIT_VALUES
        else "Unknown system audit SettingValue; not interpreted.",
    )


def _parse_audit_setting(block: Element) -> tuple[str, str, str, dict[str, object], str]:
    raw = cast(dict[str, object], element_to_dict(block))
    raw["cse_parser"] = "advanced_audit"
    fields = {
        tag: (_text(_child_by_localname(block, tag)) or "").strip()
        for tag in ("SubcategoryGuid", "SubcategoryName", "PolicyTarget", "SettingValue")
    }
    try:
        identity, name, value, note = _audit_fields(
            fields["SubcategoryGuid"],
            fields["SubcategoryName"],
            fields["PolicyTarget"],
            fields["SettingValue"],
        )
        state = "blocked" if value.startswith("Unknown") else "normal"
    except ValueError:
        identity = (
            f"AuditSetting:invalid-guid:{fields['SubcategoryGuid'] or fields['SubcategoryName']}"
        )
        name = fields["SubcategoryName"] or "Invalid audit subcategory"
        value = f"Unknown audit subcategory: {fields['SettingValue']}"
        note = "Invalid or missing audit subcategory GUID; not comparable."
        state = "blocked"
    if note:
        raw["source_note"] = note
    return identity, name, value, raw, state


_PKI_LABELS = {
    "EFSSettings:AllowEFS": "Allow Encrypting File System (EFS)",
    "EFSSettings:Options": "EFS options",
    "EFSSettings:CacheTimeout": "EFS cache timeout",
    "EFSSettings:KeyLen": "EFS key length",
    "RootCertificateSettings:AllowNewCAs": "Allow new root certificate authorities",
    "RootCertificateSettings:TrustThirdPartyCAs": "Trust third-party root certificate authorities",
    "RootCertificateSettings:RequireUPNNamingConstraints": "Require UPN naming constraints",
}
_PKI_GROUPS = {
    "EFSSettings": "EFS",
    "RootCertificateSettings": "Root certificate",
    "AutoEnrollmentSettings": "Certificate autoenrollment",
    "AutoEnrollment": "Certificate autoenrollment",
    "CertificateTrustSettings": "Certificate trust",
    "CertificatePathValidationSettings": "Certificate path validation",
}
_PKI_STORES = {
    "TrustedRootCertificates",
    "IntermediateCertificationAuthorities",
    "TrustedPublishers",
    "UntrustedCertificates",
    "Certificates",
    "EFSRecoveryAgents",
}


def _parse_public_key(block: Element) -> list[tuple[str, str, str, dict[str, object]]]:
    """Expand PKI scalar fields and certificate entries without interpreting masks.

    Identities use schema paths, never configured values or translated labels.
    Certificate identities include their store and thumbprint (or issuer/serial).
    Unrecognized structures remain explicit generic evidence.
    """
    tag = _localname(block.tag)
    out: list[tuple[str, str, str, dict[str, object]]] = []
    if tag in _PKI_GROUPS:

        def walk(elem: Element, path: str) -> None:
            for child in elem:
                child_tag = _localname(child.tag)
                key = f"{path}:{child_tag}"
                if len(child):
                    walk(child, key)
                    continue
                value = (child.text or "").strip()
                label = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", child_tag)
                name = _PKI_LABELS.get(key, f"{_PKI_GROUPS[tag]}: {label[0:1]}{label[1:].lower()}")
                raw = cast(dict[str, object], element_to_dict(block))
                raw.update(cse_parser="public_key", property_path=key)
                out.append((key, name, value, raw))

        walk(block, tag)
    elif tag in _PKI_STORES or tag == "Certificate":
        certificates = [e for e in block.iter() if _localname(e.tag) == "Certificate"]
        for cert in certificates:
            fields = {_localname(c.tag): (c.text or "").strip() for c in cert if not len(c)}
            thumbprint = fields.get("Thumbprint") or fields.get("CertificateHash") or ""
            key = re.sub(r"\s", "", thumbprint).lower()
            if not key and fields.get("SerialNumber") and fields.get("IssuedBy"):
                key = f"{fields['IssuedBy']}:{fields['SerialNumber']}"
            if not key:
                # Names alone cannot distinguish two certificates issued to
                # the same subject. Keep that entry as unclassified evidence.
                raw = cast(dict[str, object], element_to_dict(cert))
                raw.update(
                    cse_parser="public_key_unclassified",
                    source_note="Certificate has no thumbprint or issuer/serial key; "
                    "not comparable.",
                )
                out.append(
                    (
                        f"{tag}:Certificate:unclassified",
                        fields.get("IssuedTo") or tag,
                        "Unclassified certificate",
                        raw,
                    )
                )
                continue
            raw = cast(dict[str, object], element_to_dict(cert))
            raw.update(cse_parser="public_key", certificate_store=tag)
            name = f"{tag}: {fields.get('IssuedTo') or key}"
            value = "; ".join(f"{k}: {v}" for k, v in sorted(fields.items()))
            out.append((f"{tag}:Certificate:{key}", name, value, raw))
    return out


def _parse_settings(gpo_elem: Element, gpo_id: str) -> list[Setting]:
    """Parse all settings from a GPO element."""
    settings: list[Setting] = []
    # Track identities used per side so a readable-but-non-unique key (two
    # singleton blocks of the same type, lacking any natural key) is suffixed
    # with an ordinal instead of resolved by an opaque hash.
    seen: dict[tuple[str, str], int] = {}

    def _emit(
        side: Side,
        cse: str,
        identity: str,
        name: str,
        value: str,
        raw: dict[str, object],
        enabled: bool,
        source_state: str = "normal",
    ) -> None:
        n = seen.get((side, identity), 0) + 1
        seen[(side, identity)] = n
        if n > 1:
            identity = f"{identity} #{n}"
        settings.append(
            Setting(
                gpo_id=gpo_id,
                side=side,
                cse=cse,
                identity=identity,
                display_name=name,
                display_value=value,
                raw=raw,
                from_disabled_side=not enabled,
                source_state=source_state,
            )
        )

    sides: tuple[Side, ...] = ("Computer", "User")
    for side_name in sides:
        side_elem = _child_by_localname(gpo_elem, side_name)
        if side_elem is None:
            continue
        enabled = parse_bool(_text(_child_by_localname(side_elem, "Enabled")))
        for ext_data in _children_by_localname(side_elem, "ExtensionData"):
            cse_elem = _child_by_localname(ext_data, "Name")
            cse = cse_elem.text if cse_elem is not None and cse_elem.text else "Unknown"
            for ext in _children_by_localname(ext_data, "Extension"):
                # Check for blocked extension
                children = list(ext)
                legacy_ie = cse.strip().lower() == "internet explorer maintenance"
                if legacy_ie and not children:
                    _emit(
                        side_name,
                        cse,
                        f"{cse}:legacy",
                        "Legacy Internet Explorer Maintenance",
                        "",
                        {"cse_parser": "legacy_deprecated", "source_note": _LEGACY_IE_NOTE},
                        enabled,
                        source_state="legacy_deprecated",
                    )
                    continue
                if len(children) == 1 and _localname(children[0].tag) == "Blocked":
                    _emit(
                        side_name,
                        cse,
                        f"{cse}:blocked",
                        "(blocked extension)",
                        "",
                        {
                            "blocked": True,
                            "cse_parser": "legacy_deprecated",
                            "source_note": _LEGACY_IE_NOTE,
                        }
                        if legacy_ie
                        else {"blocked": True},
                        enabled,
                        source_state="blocked",
                    )
                    continue
                # Walk direct child elements as setting blocks
                for block in children:
                    bl = _localname(block.tag)
                    if bl == "AuditSetting":
                        identity, name, value, audit_raw, state = _parse_audit_setting(block)
                        prior = next(
                            (
                                s
                                for s in settings
                                if s.side == side_name
                                and s.cse == _AUDIT_CSE
                                and s.identity == identity
                            ),
                            None,
                        )
                        if prior is not None:
                            duplicates = prior.raw.setdefault("duplicate_xml", [])
                            if isinstance(duplicates, list):
                                duplicates.append(audit_raw)
                            if prior.display_value != value:
                                prior.raw["audit_disagreement"] = True
                                prior.raw["source_note"] = (
                                    "Audit sources disagree: duplicate XML subcategory values; "
                                    "first XML value retained."
                                )
                            continue
                        _emit(
                            side_name, _AUDIT_CSE, identity, name, value, audit_raw, enabled, state
                        )
                        continue
                    if cse.strip().lower() == "public key":
                        public_key = _parse_public_key(block)
                        if public_key:
                            for identity, name, value, pki_raw in public_key:
                                _emit(
                                    side_name,
                                    "Public Key",
                                    identity,
                                    name,
                                    value,
                                    pki_raw,
                                    enabled,
                                    source_state="blocked"
                                    if pki_raw.get("cse_parser") == "public_key_unclassified"
                                    else "normal",
                                )
                            continue
                    # GPP preferences wrap N concrete items several levels down;
                    # expand each into its own readable row rather than hashing
                    # the whole container into one opaque blob. Registry GPP has a
                    # richer key (HIVE\\key:name) so it is tried first.
                    multi = _parse_gpp_registry(block) if is_registry_cse(cse) else []
                    if not multi:
                        multi = _parse_gpp_container(block)
                    if multi:
                        for identity, name, value, raw in multi:
                            _emit(
                                side_name,
                                cse,
                                identity,
                                name,
                                value,
                                cast(dict[str, object], raw),
                                enabled,
                            )
                        continue
                    raw = element_to_dict(block)
                    if cse.strip().lower() == "public key":
                        pki_unknown = cast(dict[str, object], raw)
                        pki_unknown.update(
                            cse_parser="public_key_unclassified",
                            source_note="Unrecognized Public Key structure; raw evidence retained.",
                        )
                    if cse.strip().lower() == "internet explorer maintenance":
                        legacy_raw = cast(dict[str, object], raw)
                        legacy_raw.update(
                            cse_parser="legacy_deprecated", source_note=_LEGACY_IE_NOTE
                        )
                        identity, name, value = _readable_identity(cse, block)
                        _emit(
                            side_name,
                            cse,
                            identity,
                            name,
                            value,
                            legacy_raw,
                            enabled,
                            source_state="legacy_deprecated",
                        )
                        continue
                    # Try CSE-specific identity
                    parsed: tuple[str, str, str] | None = None
                    if cse == "Security":
                        parsed = _parse_security_setting(block)
                    elif bl == "Blocked":
                        # A <Blocked> flag sibling (extension not blocked) — give
                        # it a stable readable key, not a per-value hash.
                        parsed = (f"{cse}:Blocked", "(extension blocked flag)", _text(block) or "")
                    elif cse.strip().lower() == "registry" and bl == "Policy":
                        parsed = _parse_admin_template_policy(block)
                    elif cse == "Folder Redirection" and bl == "Folder":
                        parsed = _parse_folder_redirection(block)
                    elif bl == "RegistrySetting":
                        parsed = _parse_classic_registry_setting(block)
                    elif is_registry_cse(cse):
                        parsed = _parse_registry_setting(block)
                    if parsed is None:
                        parsed = _parse_generic_setting(cse, block)
                    identity, display_name, display_value = parsed
                    _emit(
                        side_name,
                        cse,
                        identity,
                        display_name,
                        display_value,
                        cast(dict[str, object], raw),
                        enabled,
                        source_state="blocked"
                        if raw.get("cse_parser") == "public_key_unclassified"
                        else "normal",
                    )
    return settings


def _parse_links(gpo_elem: Element, gpo_id: str) -> list[GpoLink]:
    """Parse all LinksTo elements."""
    links: list[GpoLink] = []
    for link_elem in _children_by_localname(gpo_elem, "LinksTo"):
        som_name = _text(_child_by_localname(link_elem, "SOMName")) or ""
        som_path = _text(_child_by_localname(link_elem, "SOMPath")) or ""
        enabled = parse_bool(_text(_child_by_localname(link_elem, "Enabled")))
        enforced = parse_bool(_text(_child_by_localname(link_elem, "NoOverride")))
        links.append(
            GpoLink(
                gpo_id=gpo_id,
                som_name=som_name,
                som_path=som_path,
                link_enabled=enabled,
                enforced=enforced,
            )
        )
    return links


def _parse_delegation(gpo_elem: Element, gpo_id: str) -> list[DelegationEntry]:
    """Parse delegation entries from SecurityDescriptor/Permissions.

    Handles both the older flat ``Permission`` element (where Trustee/Standard
    are text) and the newer ``TrusteePermissions`` nested structure observed
    in real exports (Trustee/Name, Trustee/SID, Standard/GPOGroupedAccessEnum,
    Type/PermissionType).
    """
    entries: list[DelegationEntry] = []
    sd = _child_by_localname(gpo_elem, "SecurityDescriptor")
    if sd is None:
        return entries
    perms = _child_by_localname(sd, "Permissions")
    if perms is None:
        return entries
    present = _child_by_localname(perms, "PermissionsPresent")
    if present is not None and present.text and present.text.strip().lower() == "false":
        return entries

    # First try the newer nested TrusteePermissions structure
    for perm in _children_by_localname(perms, "TrusteePermissions"):
        trustee_elem = _child_by_localname(perm, "Trustee")
        trustee = ""
        trustee_sid = None
        if trustee_elem is not None:
            trustee = _text(_child_by_localname(trustee_elem, "Name")) or _text(trustee_elem) or ""
            trustee_sid = _text(_child_by_localname(trustee_elem, "SID"))
            if trustee_sid is None:
                trustee_sid = _text(_child_by_localname(trustee_elem, "TrusteeSID"))

        perm_type = ""
        standard_elem = _child_by_localname(perm, "Standard")
        if standard_elem is not None:
            perm_type = _text(_child_by_localname(standard_elem, "GPOGroupedAccessEnum")) or ""

        allowed = True
        type_elem = _child_by_localname(perm, "Type")
        if type_elem is not None:
            type_text = _text(_child_by_localname(type_elem, "PermissionType")) or ""
            if type_text.strip().lower() == "deny":
                allowed = False

        entries.append(
            DelegationEntry(
                gpo_id=gpo_id,
                trustee=trustee,
                trustee_sid=trustee_sid,
                permission=perm_type,
                allowed=allowed,
            )
        )

    # Only fall back to flat Permission if no TrusteePermissions were found
    if not entries:
        for perm in _children_by_localname(perms, "Permission"):
            trustee = _text(_child_by_localname(perm, "Trustee")) or ""
            trustee_sid = _text(_child_by_localname(perm, "TrusteeSID"))
            if trustee_sid is None:
                trustee_sid = _text(_child_by_localname(perm, "SID"))
            perm_type = (
                _text(_child_by_localname(perm, "Standard"))
                or _text(_child_by_localname(perm, "Type"))
                or ""
            )
            allowed = True
            deny = _child_by_localname(perm, "AccessDenied")
            if deny is not None and deny.text and deny.text.strip().lower() == "true":
                allowed = False
            entries.append(
                DelegationEntry(
                    gpo_id=gpo_id,
                    trustee=trustee,
                    trustee_sid=trustee_sid,
                    permission=perm_type,
                    allowed=allowed,
                )
            )
    return entries


def parse_report(xml_path: str | Path) -> list[Gpo]:
    """Parse one or more GPOs from a report XML file.

    Handles both shapes the collector emits:

    * many ``<GPO>`` elements under a root wrapper (``AllGPOs.xml``) — the
      wrapper itself also carries localname ``GPO`` in some exports, so the
      distinguishing signal is the presence of a nested ``<GPO>`` child.
    * a single ``<GPO>`` as the root itself (per-GPO backups and the
      Microsoft Security Baseline ``gpreport.xml`` shape) — no nested
      ``<GPO>`` child, so the root *is* the GPO and ``root.iter()`` would
      otherwise skip it (the loop excludes ``gpo_elem is root``).

    Mirrors ``parse_report_xml`` (the bytes-based variant) which handles the
    same two shapes. An empty wrapper (root localname GPO, no children) is
    treated as the wrapper case and returns ``[]`` rather than mis-parsing
    the wrapper itself as a malformed single GPO.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    if root is None:
        return []
    gpos: list[Gpo] = []
    root_is_gpo = _localname(root.tag) == "GPO"
    has_nested_gpo = any(_localname(child.tag) == "GPO" for child in root)
    # Single-GPO-as-root: root localname is GPO, no nested <GPO>, and at
    # least one non-GPO child (e.g. <Identifier>) — the last clause rejects
    # an empty wrapper so it returns [] instead of yielding a phantom GPO.
    has_content = any(_localname(child.tag) != "GPO" for child in root)
    if root_is_gpo and not has_nested_gpo and has_content:
        gpo = _parse_single_gpo(root)
        if gpo is not None:
            gpos.append(gpo)
        return gpos
    for gpo_elem in root.iter():
        if gpo_elem is root:
            continue
        if _localname(gpo_elem.tag) == "GPO":
            gpo = _parse_single_gpo(gpo_elem)
            if gpo is not None:
                gpos.append(gpo)
    return gpos


def parse_report_xml(xml_bytes: bytes) -> list[Gpo]:
    """Parse one or more GPOs from raw XML bytes (handles UTF-8 and UTF-16)."""
    if xml_bytes[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = xml_bytes.decode("utf-16")
    elif xml_bytes[:3] == b"\xef\xbb\xbf":
        text = xml_bytes.decode("utf-8-sig")
    else:
        text = xml_bytes.decode("utf-8")
    root = ET.fromstring(text)
    gpos: list[Gpo] = []
    root_is_gpo = _localname(root.tag) == "GPO"
    has_nested_gpo = any(_localname(child.tag) == "GPO" for child in root)
    has_content = any(_localname(child.tag) != "GPO" for child in root)
    if root_is_gpo and not has_nested_gpo and has_content:
        # Single-GPO document (per-GPO backup, baseline gpreport.xml): root
        # itself is the GPO. Without this branch, the loop below would skip
        # it via the ``gpo_elem is root`` guard.
        gpo = _parse_single_gpo(root)
        if gpo is not None:
            gpos.append(gpo)
    else:
        for gpo_elem in root.iter():
            if gpo_elem is root:
                continue
            if _localname(gpo_elem.tag) == "GPO":
                gpo = _parse_single_gpo(gpo_elem)
                if gpo is not None:
                    gpos.append(gpo)
    return gpos


def load_baseline_from_zip(zip_path: str | Path) -> list[Gpo]:
    """Load baseline GPOs from a Microsoft Security Baseline zip.

    Microsoft ships baselines as nested zips.  This function handles both:
    - Direct zip with ``GPOs/{GUID}/gpreport.xml`` structure
    - Outer zip containing inner baseline zips

    Returns all GPOs found across all baseline GPOs in the archive.

    Uses streaming decompression with :func:`_streaming_zip_read` to enforce
    the uncompressed-size cap *during* extraction, preventing zip-bomb
    attacks that spoof ``info.file_size`` headers.

    **Memory tradeoff:** The size limit is enforced during streaming
    decompression via :class:`SizeLimitedReader`, but the full (capped)
    decompressed content of each entry is buffered in memory (as a
    ``BytesIO``) before parsing.  This is necessary because inner zips
    require the complete byte stream to open.  Baseline zips are
    typically under 100 MB, well within the 2 GB cap.
    """
    gpos: list[Gpo] = []
    total_bytes = [0]
    with zipfile.ZipFile(str(zip_path)) as outer:
        for name in outer.namelist():
            if name.endswith(".zip"):
                try:
                    inner_data = _streaming_zip_read(
                        outer,
                        name,
                        total_bytes,
                        max_bytes=_MAX_BASELINE_UNCOMPRESSED_BYTES,
                    )
                    with zipfile.ZipFile(io.BytesIO(inner_data)) as inner:
                        gpos.extend(
                            _extract_gpos_from_zip(
                                inner,
                                total_bytes,
                                max_bytes=_MAX_BASELINE_UNCOMPRESSED_BYTES,
                            )
                        )
                except (ValueError, zipfile.BadZipFile, KeyError) as exc:
                    warnings.warn(f"Skipping inner zip {name}: {exc}", stacklevel=1)
            elif name.endswith("gpreport.xml"):
                try:
                    raw = _streaming_zip_read(
                        outer,
                        name,
                        total_bytes,
                        max_bytes=_MAX_BASELINE_UNCOMPRESSED_BYTES,
                    )
                    gpos.extend(parse_report_xml(raw))
                except (ET.ParseError, KeyError, ValueError, UnicodeDecodeError) as exc:
                    warnings.warn(f"Skipping entry in zip: {exc}", stacklevel=1)

        if not gpos:
            gpos.extend(
                _extract_gpos_from_zip(
                    outer,
                    total_bytes,
                    max_bytes=_MAX_BASELINE_UNCOMPRESSED_BYTES,
                )
            )

    return gpos


def _extract_gpos_from_zip(
    zf: zipfile.ZipFile,
    total_counter: list[int] | None = None,
    max_bytes: int | None = None,
) -> list[Gpo]:
    """Extract GPOs from gpreport.xml files in a zip.

    Uses streaming decompression via :func:`_streaming_zip_read` to enforce
    the uncompressed-size cap during extraction.
    """
    _total = total_counter if total_counter is not None else [0]
    gpos: list[Gpo] = []
    for name in zf.namelist():
        if name.endswith("gpreport.xml"):
            try:
                raw = _streaming_zip_read(zf, name, _total, max_bytes=max_bytes)
                gpos.extend(parse_report_xml(raw))
            except (ET.ParseError, KeyError, ValueError, UnicodeDecodeError) as exc:
                warnings.warn(f"Skipping entry in zip: {exc}", stacklevel=1)
                continue
    return gpos


def _side_bool(side_elem: Element | None, child_name: str) -> bool:
    """Parse a boolean child under a side element."""
    text = _text(_child_by_localname(side_elem, child_name)) if side_elem is not None else None
    return parse_bool(text)


def _side_int(side_elem: Element | None, child_name: str) -> int | None:
    """Parse an int child under a side element."""
    text = _text(_child_by_localname(side_elem, child_name)) if side_elem is not None else None
    return parse_int(text)


def _parse_single_gpo(gpo_elem: Element) -> Gpo | None:
    """Parse a single GPO element.

    Returns ``None`` (with a warning) when the element has no valid
    identifier — callers should skip ``None`` results.
    """
    id_elem = _child_by_localname(gpo_elem, "Identifier")
    raw_id = _text(_child_by_localname(id_elem, "Identifier")) if id_elem is not None else ""
    try:
        gpo_id = canonical_guid(raw_id) if raw_id else ""
    except ValueError:
        gpo_id = ""
    if not gpo_id:
        name = _text(_child_by_localname(gpo_elem, "Name")) or ""
        warnings.warn(
            f"GPO '{name}' has no valid identifier; skipping",
            stacklevel=1,
        )
        return None
    domain = (_text(_child_by_localname(id_elem, "Domain")) or "") if id_elem is not None else ""
    name = _text(_child_by_localname(gpo_elem, "Name")) or ""
    created = parse_dt(_text(_child_by_localname(gpo_elem, "CreatedTime")))
    modified = parse_dt(_text(_child_by_localname(gpo_elem, "ModifiedTime")))
    read = parse_dt(_text(_child_by_localname(gpo_elem, "ReadTime")))

    computer = _child_by_localname(gpo_elem, "Computer")
    user = _child_by_localname(gpo_elem, "User")

    computer_enabled = _side_bool(computer, "Enabled")
    user_enabled = _side_bool(user, "Enabled")
    computer_ver_ds = _side_int(computer, "VersionDirectory")
    computer_ver_sysvol = _side_int(computer, "VersionSysvol")
    user_ver_ds = _side_int(user, "VersionDirectory")
    user_ver_sysvol = _side_int(user, "VersionSysvol")

    sd = _child_by_localname(gpo_elem, "SecurityDescriptor")
    sddl = _text(_child_by_localname(sd, "SDDL")) if sd is not None else None
    # <Owner> holds <Name>/<SID> children, so its own .text is just the
    # whitespace between them — read the children (Name preferred).
    owner: str | None = None
    if sd is not None:
        owner_elem = _child_by_localname(sd, "Owner")
        if owner_elem is not None:
            for child_name in ("Name", "SID"):
                child_text = _text(_child_by_localname(owner_elem, child_name))
                if child_text and child_text.strip():
                    owner = child_text.strip()
                    break
    filter_data = parse_bool(_text(_child_by_localname(gpo_elem, "FilterDataAvailable")))
    description = _text(_child_by_localname(gpo_elem, "Description"))

    gpo = Gpo(
        id=gpo_id,
        name=name,
        domain=domain,
        created=created,
        modified=modified,
        read=read,
        computer_enabled=computer_enabled,
        user_enabled=user_enabled,
        computer_ver_ds=computer_ver_ds,
        computer_ver_sysvol=computer_ver_sysvol,
        user_ver_ds=user_ver_ds,
        user_ver_sysvol=user_ver_sysvol,
        sddl=sddl,
        owner=owner,
        filter_data_available=filter_data,
        wmi_filter=None,
        sysvol_path=None,
        description=description,
        links=_parse_links(gpo_elem, gpo_id),
        settings=_parse_settings(gpo_elem, gpo_id),
        delegation=_parse_delegation(gpo_elem, gpo_id),
    )
    return gpo


# ``Get-GPInheritance`` returns a ``Microsoft.GroupPolicy.SomType`` enum for
# ``ContainerType``. The console *displays* it as "Domain"/"OU", but
# ``ConvertTo-Json`` (PowerShell 5.1) serializes the underlying integer
# (observed: Domain=1, OU=2). The rest of gpo-lens treats ``container_type`` as
# the canonical lowercase string ("domain"/"ou"/"site") — sites are appended
# separately with that contract — so normalize here, tolerating both the int
# and string forms (a future ``-EnumsAsStrings`` collector would emit names).
_SOM_TYPE_INTS = {0: "site", 1: "domain", 2: "ou"}
_SOM_TYPE_NAMES = {
    "site": "site",
    "domain": "domain",
    "ou": "ou",
    "organizationalunit": "ou",
}


def _normalize_container_type(raw: object) -> str:
    if isinstance(raw, bool):  # guard: bool is an int subclass
        return ""
    if isinstance(raw, int):
        return _SOM_TYPE_INTS.get(raw, "")
    if isinstance(raw, str):
        s = raw.strip()
        if s.isdigit():
            return _SOM_TYPE_INTS.get(int(s), "")
        return _SOM_TYPE_NAMES.get(s.lower(), s.lower())
    return ""


def parse_inheritance(json_path: str | Path) -> list[Som]:
    """Parse GPInheritance dump into a list of ``Som``."""
    records = _load_json_records(json_path)
    soms: list[Som] = []
    for record in records:
        path = record.get("Path", "")
        name = record.get("Name", "")
        container_type = _normalize_container_type(record.get("ContainerType", ""))
        inheritance_blocked = record.get("GpoInheritanceBlocked", False)
        if isinstance(inheritance_blocked, str):
            inheritance_blocked = inheritance_blocked.strip().lower() == "true"
        som = Som(
            path=path,
            name=name,
            container_type=container_type,
            inheritance_blocked=bool(inheritance_blocked),
        )
        links_raw = record.get("InheritedGpoLinks", [])
        if isinstance(links_raw, dict):
            links_raw = [links_raw]
        for link in links_raw:
            gpo_id_raw = link.get("GpoId")
            if not gpo_id_raw:
                continue
            try:
                gpo_id = canonical_guid(gpo_id_raw)
            except ValueError:
                continue
            raw_order = link.get("Order", 0)
            if isinstance(raw_order, bool):
                order_val = 0
            elif isinstance(raw_order, (int, float)):
                order_val = int(raw_order)
            elif raw_order is not None:
                parsed = parse_int(str(raw_order))
                order_val = parsed if parsed is not None else 0
            else:
                order_val = 0
            raw_enabled = link.get("Enabled", True)
            raw_enforced = link.get("Enforced", False)
            enabled_val = (
                parse_bool(str(raw_enabled)) if isinstance(raw_enabled, str) else bool(raw_enabled)
            )
            enforced_val = (
                parse_bool(str(raw_enforced))
                if isinstance(raw_enforced, str)
                else bool(raw_enforced)
            )
            som.links.append(
                SomLink(
                    gpo_id=gpo_id,
                    order=order_val or 0,
                    enabled=enabled_val,
                    enforced=enforced_val,
                    target=link.get("Target", ""),
                )
            )
        soms.append(som)
    return soms


def merge_metadata(json_path: str | Path, gpos: list[Gpo]) -> None:
    """Read metadata JSON and back-fill WMI filter + version fields."""
    records = _load_json_records(json_path)
    by_id = {g.id: g for g in gpos}
    for record in records:
        raw_id = record.get("Id", "")
        if not raw_id:
            continue
        try:
            gpo_id = canonical_guid(raw_id)
        except ValueError:
            continue
        gpo = by_id.get(gpo_id)
        if gpo is None:
            continue
        wmi = record.get("WmiFilter")
        if wmi is not None:
            gpo.wmi_filter = wmi if isinstance(wmi, str) else None
        # Back-fill versions if report value was missing
        if gpo.computer_ver_ds is None:
            gpo.computer_ver_ds = parse_int(str(record.get("ComputerVersionDirectory", "")))
        if gpo.computer_ver_sysvol is None:
            gpo.computer_ver_sysvol = parse_int(str(record.get("ComputerVersionSysvol", "")))
        if gpo.user_ver_ds is None:
            gpo.user_ver_ds = parse_int(str(record.get("UserVersionDirectory", "")))
        if gpo.user_ver_sysvol is None:
            gpo.user_ver_sysvol = parse_int(str(record.get("UserVersionSysvol", "")))


def attach_sysvol_paths(sysvol_dir: str | Path, gpos: list[Gpo]) -> None:
    """Match each GPO to its SYSVOL folder by canonical id."""
    base = Path(sysvol_dir)
    if not base.exists():
        return
    base_resolved = base.resolve()
    unmatched = 0
    for gpo in gpos:
        # SYSVOL directories use the standard 8-4-4-4-12 hyphenated GUID form;
        # the canonical id is bare (no hyphens), so generate both forms.
        gid = gpo.id
        candidates = [base / gid, base / gid.upper()]
        if len(gid) == 32:
            hyphenated = f"{gid[0:8]}-{gid[8:12]}-{gid[12:16]}-{gid[16:20]}-{gid[20:32]}"
            candidates[:0] = [
                base / f"{{{hyphenated.upper()}}}",
                base / hyphenated,
                base / hyphenated.upper(),
            ]
        matched = False
        for cand in candidates:
            if cand.exists():
                resolved = cand.resolve()
                if resolved.is_relative_to(base_resolved):
                    gpo.sysvol_path = str(resolved)
                    matched = True
                    break
        if not matched and any(cand.exists() for cand in candidates):
            unmatched += 1
    if unmatched > 0:
        warnings.warn(
            f"{unmatched} GPO(s) had SYSVOL paths outside the base directory; skipped",
            stacklevel=1,
        )


def augment_blocked_registry_from_pol(gpos: list[Gpo]) -> None:
    """Resolve ``<Blocked/>`` Registry extensions from the binary ``Registry.pol``.

    The GPO report sometimes renders the Registry CSE as ``<Blocked/>`` (the
    GPMC could not read it). When that happens the affected side carries a
    single placeholder setting with ``source_state="blocked"`` and no values.
    The authoritative values live in ``Machine/Registry.pol`` /
    ``User/Registry.pol`` (PReg binary format). Where that file exists, this
    replaces the blocked placeholder with the real settings, tagged
    ``source_state="registry_pol"``. Where it is absent, the placeholder is
    kept (we cannot fabricate values).

    Read-only and deterministic. Does not touch report-rendered Registry
    settings (those are kept as-is).
    """
    _SIDE_DIR = {"Computer": "Machine", "User": "User"}
    for gpo in gpos:
        if not gpo.sysvol_path:
            continue
        base = Path(gpo.sysvol_path)
        blocked_idxs = [
            i
            for i, s in enumerate(gpo.settings)
            if s.source_state == "blocked" and "registr" in s.cse.lower()
        ]
        if not blocked_idxs:
            continue
        # Group blocked placeholders by side; one placeholder per blocked side.
        blocked_sides = {gpo.settings[i].side for i in blocked_idxs}
        resolved_sides: set[str] = set()
        additions: list[Setting] = []
        for side in blocked_sides:
            # Side dir casing varies on a real SYSVOL (default GPOs use MACHINE);
            # resolve case-insensitively for a case-sensitive analysis host.
            pol = ci_path(base, _SIDE_DIR.get(side, side), "Registry.pol")
            if pol is None:
                continue
            try:
                records = parse_registry_pol(pol.read_bytes())
            except (OSError, ValueError):
                continue
            if not records:
                continue
            resolved_sides.add(side)
            for rec in records:
                identity = (
                    f"{rec.key}:{rec.value_name}"
                    if (rec.key and rec.value_name)
                    else (rec.key or rec.value_name)
                )
                additions.append(
                    Setting(
                        gpo_id=gpo.id,
                        side=side,
                        cse="Registry",
                        identity=identity,
                        display_name=rec.value_name or rec.key,
                        display_value=rec.display_value,
                        raw={
                            "key": rec.key,
                            "value_name": rec.value_name,
                            "type_code": rec.type_code,
                            "type_name": rec.type_name,
                            "size": rec.size,
                            "source": "registry_pol",
                        },
                        from_disabled_side=False,
                        source_state="registry_pol",
                    )
                )
        if resolved_sides:
            blocked_set = set(blocked_idxs)
            gpo.settings = [
                s
                for i, s in enumerate(gpo.settings)
                if i not in blocked_set or gpo.settings[i].side not in resolved_sides
            ]
            gpo.settings.extend(additions)


def augment_audit_from_csv(gpos: list[Gpo]) -> None:
    """Read copied audit.csv, joining report evidence by target and GUID.

    Report XML remains the displayed value on disagreement. CSV-only policies
    are first-class settings; malformed rows remain blocked evidence. No input
    file is changed. Paths resolving outside the copied policy folder are refused.
    """
    for gpo in gpos:
        if not gpo.sysvol_path:
            continue
        base = Path(gpo.sysvol_path)
        path = ci_path(base, "Machine", "Microsoft", "Windows NT", "Audit", "audit.csv")
        if path is None:
            continue
        source_note = ""
        try:
            if not path.resolve().is_relative_to(base.resolve()):
                raise ValueError("audit.csv resolves outside the copied GPO folder")
            data = path.read_bytes()
            text = data.decode(
                "utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
            )
            reader = csv.DictReader(io.StringIO(text), strict=True)
            required = {"Policy Target", "Subcategory", "Subcategory GUID", "Setting Value"}
            if not required.issubset(reader.fieldnames or []):
                raise ValueError("audit.csv is missing required column headers")
            rows = list(reader)
        except (OSError, UnicodeError, ValueError, csv.Error) as exc:
            source_note = f"Audit CSV unreadable: {exc}"
            rows = []
        if source_note:
            gpo.settings.append(
                Setting(
                    gpo_id=gpo.id,
                    side="Computer",
                    cse=_AUDIT_CSE,
                    identity="audit.csv:unreadable",
                    display_name="Advanced Audit CSV evidence",
                    display_value="Unknown",
                    raw={"source_note": source_note},
                    from_disabled_side=not gpo.computer_enabled,
                    source_state="blocked",
                )
            )
            continue
        xml = {
            s.identity: s
            for s in gpo.settings
            if s.cse == _AUDIT_CSE
            and s.side == "Computer"
            and s.raw.get("cse_parser") == "advanced_audit"
        }
        csv_seen: dict[str, Setting] = {}
        for index, row in enumerate(rows, 1):
            # Audit options and global SACLs share this file but have no
            # subcategory GUID. Retain them as unsupported evidence, never
            # mistake their numeric masks for a subcategory SettingValue.
            note = ""
            state = "audit_csv"
            try:
                if None in row or any(v is None for v in row.values()):
                    raise ValueError("incomplete or extra CSV columns")
                identity, name, value, note = _audit_fields(
                    row["Subcategory GUID"],
                    row["Subcategory"],
                    row["Policy Target"],
                    row["Setting Value"],
                )
                if value.startswith("Unknown"):
                    state = "blocked"
            except ValueError:
                identity, name, value = (
                    f"audit.csv:row:{index}",
                    row.get("Subcategory") or "Audit CSV row",
                    "Unknown",
                )
                note = "Invalid or unsupported audit CSV row; not interpreted."
                state = "blocked"
            raw: dict[str, object] = {"cse_parser": "advanced_audit_csv", "audit_csv": row}
            if note:
                raw["source_note"] = note
            existing = xml.get(identity) or csv_seen.get(identity)
            if existing is not None:
                existing.raw["audit_csv"] = row
                evidence_rows = existing.raw.setdefault("audit_csv_rows", [])
                if isinstance(evidence_rows, list):
                    evidence_rows.append(row)
                if existing.display_value != value:
                    existing.raw["audit_disagreement"] = True
                    existing.raw["source_note"] = (
                        "Audit sources disagree: retained XML/first CSV value "
                        f"{existing.display_value}; "
                        f"CSV value {value}. No effective machine state is inferred."
                    )
                continue
            setting = Setting(
                gpo_id=gpo.id,
                side="Computer",
                cse=_AUDIT_CSE,
                identity=identity,
                display_name=name,
                display_value=value,
                raw=raw,
                from_disabled_side=not gpo.computer_enabled,
                source_state=state,
            )
            csv_seen[identity] = setting
            setting.raw["audit_csv_rows"] = [row]
            if xml and state != "blocked":
                setting.raw["audit_disagreement"] = True
                setting.raw["source_note"] = (
                    "Audit sources disagree: CSV subcategory is absent from XML."
                )
            gpo.settings.append(setting)
        for identity, setting in xml.items():
            if "audit_csv" not in setting.raw:
                setting.raw["audit_disagreement"] = True
                setting.raw["source_note"] = (
                    "Audit sources disagree: XML subcategory is absent from CSV."
                )


def parse_wmi_filters(json_path: str | Path) -> list[WmiFilter]:
    """Parse ``wmi-filters.json`` into a list of :class:`WmiFilter`."""
    records = _load_json_records(json_path)
    filters: list[WmiFilter] = []
    for record in records:
        name = record.get("Name", "")
        query = record.get("Query", "")
        if name:
            filters.append(WmiFilter(name=name, query=query))
    return filters


def parse_ou_tree(json_path: str | Path) -> list[OuRecord]:
    """Parse ``ou-tree.json`` (raw gPLink / gPOptions) into :class:`OuRecord` list."""
    json_records = _load_json_records(json_path)
    records: list[OuRecord] = []
    for record in json_records:
        dn = record.get("DistinguishedName", "")
        name = record.get("Name", "")
        gp_link = record.get("gPLink")
        gp_options = record.get("gPOptions")
        opt_val: int | None = None
        if gp_options is not None:
            try:
                opt_val = int(gp_options)
            except (ValueError, TypeError):
                opt_val = None
        records.append(OuRecord(dn=dn, name=name, gp_link=gp_link, gp_options=opt_val))
    return records


def parse_principals(json_path: str | Path) -> dict[str, ResolvedPrincipal]:
    """Parse ``principals.json`` into a ``{sid: ResolvedPrincipal}`` map.

    The file is optional (Plan 020 A.2); callers should only invoke this when
    the file exists. SIDs are canonicalized to lowercase. Each entry carries
    ``name``, ``sam``, ``type``, and ``domain`` from the collector's
    point-in-time directory lookup.
    """
    data = load_json(json_path)
    if not isinstance(data, dict):
        return {}
    raw_principals = data.get("principals")
    if not isinstance(raw_principals, dict):
        if isinstance(data, dict) and any(k.lower().startswith("s-1-") for k in data):
            warnings.warn(
                "principals.json appears to be a flat SID map (no 'principals' "
                'wrapper key); expected {"principals": {"<sid>": ...}} format',
                stacklevel=2,
            )
        return {}
    out: dict[str, ResolvedPrincipal] = {}
    for sid_raw, entry in raw_principals.items():
        if not isinstance(entry, dict):
            continue
        sid = sid_raw.strip().lower()
        if not sid:
            continue
        name = entry.get("name") or sid
        sam = entry.get("sam") or ""
        ptype = entry.get("type") or "Unresolved"
        domain = entry.get("domain") or ""
        resolved = ptype != "Unresolved" and bool(name) and name != sid
        out[sid] = ResolvedPrincipal(
            sid=sid,
            name=name,
            sam=sam,
            principal_type=ptype,
            domain=domain,
            resolved=resolved,
        )
    return out


def parse_group_members(json_path: str | Path) -> dict[str, GroupMembership]:
    """Parse ``group-members.json`` into a ``{sid: GroupMembership}`` map.

    The file is optional (Plan 020 B); callers should only invoke this when
    the file exists. SIDs are canonicalized to lowercase. Each entry carries
    ``name``, ``members`` (a tuple of direct-member SIDs), and ``member_count``.
    Well-known groups with no enumerable membership carry an ``implicit`` note.
    """
    data = load_json(json_path)
    if not isinstance(data, dict):
        return {}
    raw_groups = data.get("groups")
    if not isinstance(raw_groups, dict):
        if isinstance(data, dict) and any(k.lower().startswith("s-1-") for k in data):
            warnings.warn(
                "group-members.json appears to be a flat SID map (no 'groups' "
                'wrapper key); expected {"groups": {"<sid>": ...}} format',
                stacklevel=2,
            )
        return {}
    out: dict[str, GroupMembership] = {}
    for sid_raw, entry in raw_groups.items():
        if not isinstance(entry, dict):
            continue
        sid = sid_raw.strip().lower()
        if not sid:
            continue
        name = entry.get("name") or sid
        members_raw = entry.get("members")
        if not isinstance(members_raw, list):
            members_raw = []
        members = tuple(m.strip().lower() for m in members_raw if isinstance(m, str) and m.strip())
        member_count = entry.get("member_count")
        if not isinstance(member_count, int):
            member_count = len(members)
        implicit = entry.get("implicit") or ""
        out[sid] = GroupMembership(
            sid=sid,
            name=name,
            members=members,
            member_count=member_count,
            implicit=implicit,
        )
    return out


# gPLink segment: ``[LDAP://CN={guid},...;flags]``. flags bit 0 = link
# disabled, bit 1 = enforced (NoOverride).
_GPLINK_RE = re.compile(r"\[LDAP://CN=(\{[^}]+\}|[^,;]+),[^;]*;(\d+)\]", re.IGNORECASE)


def _parse_gplink(raw: str | None, target_dn: str) -> list[SomLink]:
    """Parse a raw ``gPLink`` attribute into ordered :class:`SomLink` entries.

    Order is the segment position (1-based) as written. Invalid GUID segments
    are skipped rather than raising.
    """
    links: list[SomLink] = []
    if not raw:
        return links
    order = 0
    for match in _GPLINK_RE.finditer(raw):
        guid_raw, flags_raw = match.group(1), match.group(2)
        try:
            gpo_id = canonical_guid(guid_raw)
        except ValueError:
            continue
        order += 1
        flags = int(flags_raw)
        links.append(
            SomLink(
                gpo_id=gpo_id,
                order=order,
                enabled=(flags & 1) == 0,
                enforced=(flags & 2) != 0,
                target=target_dn,
            )
        )
    return links


def parse_sites(json_path: str | Path) -> list[Som]:
    """Parse ``sites.json`` into site scope-of-management nodes.

    Each AD site becomes a :class:`Som` with ``container_type="site"`` carrying
    its *direct* gPLink GPOs. Sites are a parallel scoping axis (not OU
    ancestors); their per-machine application (IP subnet -> site) is
    intentionally not resolved here.
    """
    records = _load_json_records(json_path)
    sites: list[Som] = []
    for record in records:
        dn = record.get("DistinguishedName", "")
        name = record.get("Name", "")
        som = Som(
            path=dn,
            name=name,
            container_type="site",
            inheritance_blocked=False,
        )
        som.links = _parse_gplink(record.get("gPLink"), dn)
        sites.append(som)
    return sites


def parse_coverage_gaps(
    inventory_path: Path, errors_path: Path, gpos: list[Gpo]
) -> list[CoverageGap]:
    """Reconcile the authoritative inventory + collector failures against the export.

    A GPO present in ``gpo-inventory.json`` (ideally produced by a privileged
    run) but absent from the ingested GPOs is an inaccessible coverage gap. A
    GPO named in ``collection-errors.json`` that also did not make it into the
    export is a collection failure. Both are named, never silently dropped.
    Either file being absent is fine (older exports reconcile to no gaps).
    """
    known = {g.id for g in gpos}
    seen: set[str] = set()
    gaps: list[CoverageGap] = []

    if inventory_path.exists():
        for rec in _load_json_records(inventory_path):
            raw = rec.get("Id") or rec.get("id") or ""
            try:
                gid = canonical_guid(raw)
            except ValueError:
                continue
            if gid in known or gid in seen:
                continue
            gaps.append(
                CoverageGap(
                    gpo_id=gid,
                    display_name=rec.get("DisplayName") or rec.get("displayName"),
                    kind="inaccessible",
                    detail="In the GPO inventory but absent from the export "
                    "(the collection account could not read it)",
                )
            )
            seen.add(gid)

    if errors_path.exists():
        for rec in _load_json_records(errors_path):
            raw = rec.get("GpoId") or rec.get("gpo_id") or ""
            if not raw:
                continue
            try:
                gid = canonical_guid(raw)
            except ValueError:
                continue
            if gid in known or gid in seen:
                continue
            gaps.append(
                CoverageGap(
                    gpo_id=gid,
                    display_name=rec.get("DisplayName") or rec.get("display_name"),
                    kind="collection_error",
                    detail=rec.get("Error")
                    or rec.get("Stage")
                    or "the collector reported a read failure",
                )
            )
            seen.add(gid)

    return gaps


def _scan_sysvol_gaps(gpos: list[Gpo]) -> list[CoverageGap]:
    """Walk each GPO's SYSVOL Preferences once, surfacing both coverage-honesty
    signals in a single pass:

    * ``unreadable_sysvol`` — a Preferences subtree the parser cannot enter
      (a Windows-produced zip extracted on Linux often drops the traversal
      ``x`` bit on subdirectories). Remediation: ``chmod -R +rX`` on the
      SYSVOL-Policies directory.
    * ``corrupt_gpp_xml`` — a readable-but-unparseable Preferences XML file
      (truncated download, mid-copy snapshot, or a tampered export).

    The GPP scanners in ``detection.py`` catch ``ET.ParseError`` and skip
    unreadable dirs (correct for resilience), which means a corrupt or
    invisible ``ScheduledTasks.xml`` is silently invisible — a coverage-honesty
    hazard for a security tool. This walker replaces the former two-pass design
    that walked the same Preferences tree twice per ingest; callers now filter
    by ``kind`` directly.
    """
    gaps: list[CoverageGap] = []
    for gpo in gpos:
        if not gpo.sysvol_path:
            continue
        base = Path(gpo.sysvol_path)
        unreadable: list[str] = []
        corrupt: list[str] = []
        for side_dir in ("Machine", "User"):
            side = ci_child(base, side_dir)
            if side is None:
                continue
            prefs = ci_child(side, "Preferences")
            if prefs is None:
                continue
            side_flagged = False
            try:
                entries = sorted(prefs.iterdir())
            except OSError as exc:
                unreadable.append(f"{side_dir}/Preferences ({exc.__class__.__name__})")
                side_flagged = True
                continue
            for entry in entries:
                try:
                    candidates: list[Path] = []
                    if entry.is_dir():
                        candidates.extend(sorted(c for c in entry.iterdir() if c.is_file()))
                    elif entry.is_file():
                        candidates.append(entry)
                except OSError as exc:
                    # Lost traversal bit on this Preferences subdir: the GPP
                    # scanners cannot enter it, so its content is invisible.
                    # Flag the side once and keep walking siblings so a single
                    # bad subdir does not hide corrupt XML in its siblings.
                    if not side_flagged:
                        unreadable.append(f"{side_dir}/Preferences ({exc.__class__.__name__})")
                        side_flagged = True
                    continue
                for fp in candidates:
                    if fp.suffix.lower() != ".xml":
                        continue
                    try:
                        ET.parse(fp)
                    except (ET.ParseError, UnicodeDecodeError, OSError):
                        # ParseError = malformed XML; UnicodeDecodeError =
                        # wrong/invalid encoding declaration; OSError =
                        # file became unreadable between iterdir and parse.
                        # All three are "this GPP file is unusable" from the
                        # perspective of the security scanners that feed off
                        # Preferences XML.
                        rel = fp.relative_to(base)
                        corrupt.append(str(rel))
        if unreadable:
            gaps.append(
                CoverageGap(
                    gpo_id=gpo.id,
                    display_name=gpo.name,
                    kind="unreadable_sysvol",
                    detail=(
                        f"GPP content in {', '.join(unreadable)} is invisible. "
                        f"If this is a zip extraction, run: chmod -R +rX on the "
                        f"SYSVOL-Policies directory."
                    ),
                )
            )
        if corrupt:
            gaps.append(
                CoverageGap(
                    gpo_id=gpo.id,
                    display_name=gpo.name,
                    kind="corrupt_gpp_xml",
                    detail=(
                        f"GPP XML failed to parse: {', '.join(corrupt)}. "
                        f"cPassword/GPP detectors cannot read these files; treat "
                        f"the GPO's GPP-derived findings as incomplete."
                    ),
                )
            )
    return gaps


def _scan_missing_sysvol(sysvol_root: Path | None, gpos: list[Gpo]) -> list[CoverageGap]:
    """Flag an export that carries no SYSVOL policy files at all.

    The settings tables come from the report XML, so a SYSVOL-less export still
    renders and *looks* complete. But every SYSVOL-sourced detector — cPassword,
    GPP Scheduled Tasks, GPP Local Users & Groups, and Registry.pol blocked-
    extension resolution — reads only from ``gpo.sysvol_path`` and silently
    returns nothing when it is unset (``detection.py`` guards on it). A run that
    quietly reports ZERO cPassword hits because SYSVOL was never collected is
    indistinguishable from a genuinely clean estate, so surface it loudly as a
    single estate-level coverage gap rather than per GPO.

    Triggers when no GPO matched a SYSVOL folder: either the directory is absent
    (``-SkipSysvol``, or a collector copy that no-op'd) or present but empty.
    """
    if not gpos:
        return []
    if any(gpo.sysvol_path for gpo in gpos):
        return []
    if sysvol_root is None:
        reason = "the SYSVOL-Policies directory is absent from the export"
    else:
        reason = f"{sysvol_root.name} is present but contains no policy folders"
    return [
        CoverageGap(
            gpo_id="",
            display_name=None,
            kind="missing_sysvol",
            detail=(
                f"No SYSVOL policy files were collected ({reason}). GPP-based "
                f"detectors — cPassword secrets, GPP Scheduled Tasks, GPP Local "
                f"Users & Groups, and Registry.pol resolution — could not run and "
                f"will report ZERO regardless of actual exposure. Re-run the "
                f"collector and confirm its 'SYSVOL copy' section wrote files; if "
                f"the export was zipped on Windows, also confirm the archive "
                f"actually contains SYSVOL-Policies/."
            ),
        )
    ]


def _try_load[T](
    path: Path,
    fn: Callable[..., T],
    label: str,
    *args: Any,
) -> T | None:
    """Load an optional file, warning on error instead of raising.

    Consolidates the repeated ``if path.exists(): try: ... except: warn`` pattern
    in :func:`load_estate`. Returns ``None`` when the file is absent or
    unparseable — callers treat that as "skip this input."
    """
    if not path.exists():
        return None
    try:
        return fn(path, *args)
    except (OSError, ValueError) as exc:
        warnings.warn(f"Skipping {label}: {exc}", stacklevel=2)
        return None


def _try_action(path: Path, fn: Callable[..., None], label: str, *args: Any) -> None:
    """Run a side-effecting loader (e.g. ``merge_metadata``) with the same guard."""
    if not path.exists():
        return
    try:
        fn(path, *args)
    except (OSError, ValueError) as exc:
        warnings.warn(f"Skipping {label}: {exc}", stacklevel=2)


def load_estate(sample_dir: str | Path) -> Estate:
    """Orchestrate loading a full estate from a sample directory."""
    src = Path(sample_dir)
    report_path = src / "AllGPOs.xml"
    if not report_path.exists():
        raise FileNotFoundError(f"AllGPOs.xml not found in {src}")
    gpos: list[Gpo] = []
    # A missing AllGPOs.xml raised above. A *corrupt* primary input is a
    # different failure: the charter promises coverage honesty, and silently
    # producing an empty Estate from an unparseable report would violate it
    # (the estate would look complete with zero GPOs). Fail fast instead —
    # previously this caught ParseError/OSError/UnicodeDecodeError and warned.
    try:
        gpos = parse_report(report_path)
    except (ET.ParseError, UnicodeDecodeError) as exc:
        raise ValueError(f"AllGPOs.xml in {src} is not parseable: {exc}") from exc
    except OSError as exc:
        raise OSError(f"AllGPOs.xml in {src} could not be read: {exc}") from exc
    domain = gpos[0].domain if gpos else ""

    soms = (
        _try_load(
            src / "gp-inheritance.json",
            parse_inheritance,
            "gp-inheritance.json",
        )
        or []
    )

    # AD sites are a parallel scoping axis; append them as container_type="site"
    # SOMs. Absent sites.json (older exports) changes nothing.
    sites = _try_load(src / "sites.json", parse_sites, "sites.json")
    if sites:
        soms.extend(sites)

    _try_action(
        src / "gpo-metadata.json",
        merge_metadata,
        "gpo-metadata.json",
        gpos,
    )

    sysvol_dir = src / "SYSVOL-Policies"
    alt = src / "SYSVOL" / "Policies"
    sysvol_root = sysvol_dir if sysvol_dir.exists() else (alt if alt.exists() else None)
    if sysvol_root is not None:
        attach_sysvol_paths(sysvol_root, gpos)

    # Resolve <Blocked/> Registry extensions from the binary Registry.pol where
    # SYSVOL is present. No-op when SYSVOL wasn't copied or nothing is blocked.
    augment_blocked_registry_from_pol(gpos)
    augment_audit_from_csv(gpos)

    wmi_filters = (
        _try_load(
            src / "wmi-filters.json",
            parse_wmi_filters,
            "wmi-filters.json",
        )
        or []
    )
    ou_tree = (
        _try_load(
            src / "ou-tree.json",
            parse_ou_tree,
            "ou-tree.json",
        )
        or []
    )

    coverage_gaps = parse_coverage_gaps(
        src / "gpo-inventory.json", src / "collection-errors.json", gpos
    )

    coverage_gaps.extend(_scan_sysvol_gaps(gpos))
    coverage_gaps.extend(_scan_missing_sysvol(sysvol_root, gpos))

    principals = (
        _try_load(
            src / "principals.json",
            parse_principals,
            "principals.json",
        )
        or {}
    )
    group_members = (
        _try_load(
            src / "group-members.json",
            parse_group_members,
            "group-members.json",
        )
        or {}
    )

    return Estate(
        domain=domain,
        gpos=gpos,
        soms=soms,
        wmi_filters=wmi_filters,
        ou_tree=ou_tree,
        coverage_gaps=coverage_gaps,
        principals=principals,
        group_members=group_members,
    )
