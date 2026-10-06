"""Shared safe projections for human exports and view payloads.

Never serialize raw Setting subtrees. Mask credential values even when a
collector flattened them into display text, and mark omitted evidence/audit
fields explicitly. This module is independent of the web and narration.
"""

from __future__ import annotations

import dataclasses
import html
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import quote, unquote

from gpo_lens.display import serialize_result

REDACTED = "[REDACTED]"
_SECRET_KEY = re.compile(
    r"^(?:cpassword|password|passwd|pwd|secret|credential|token|"
    r"(?:access|auth|refresh)[_-]?token|private[_-]?key|api[_-]?key)$",
    re.I,
)
_SECRET_IDENTITY = re.compile(
    r"(?:^|[\\/.:])(?:cpassword|password|passwd|pwd|secret|credential|token|"
    r"private[_-]?key|api[_-]?key)(?:$|[\\/.:])",
    re.I,
)
_ASSIGNMENT = re.compile(
    r"""(?i)\b(cpassword|password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s;,<>]+)"""
)
# Exact registry value names, never a substring search for "password".
# The parser's Registry/Registry.pol/GPP records establish value context;
# password-policy settings (e.g. PasswordComplexity) are not credential values.
_WINDOWS_CREDENTIAL_NAMES = frozenset(
    {
        "defaultpassword",
        "altdefaultpassword",
        "proxypassword",
        "servicepassword",
        "bindpassword",
        "adminpassword",
        "databasepassword",
        "sqlpassword",
    }
)
_USERINFO = re.compile(r"(?i)(?:[a-z][a-z0-9+.-]*://|\\\\|//)[^\s/@\\:]*:([^\s/@\\]+)@")
_COMMAND_OPTIONS = {
    "schtasks": r"/(?:rp|p)",
    "cmdkey": r"/pass",
    "powershell": r"-(?:password|proxypassword)",
    "pwsh": r"-(?:password|proxypassword)",
}
# GPP locators such as <Drive/Properties @path> contain names, not XML values.
_RAW_FRAGMENT = re.compile(
    r"</?(?![A-Za-z][\w:.-]*(?:/[A-Za-z][\w:.-]*)? @[A-Za-z][\w:.-]*>)"
    r"[A-Za-z][^>]*>|^[OGDS]:.*\([A-Z]+;",
    re.S,
)
_OMIT = {
    "raw",
    "raw_xml",
    "raw_source",
    "source_fragment",
    "sddl",
    "evidence_json",
    "metadata_json",
}
_AUDIT = {
    "actor",
    "note",
    "rationale",
    "revoked_by",
    "triage_actor",
    "triage_note",
    "triage_events",
}
_VALUE = {
    "display_value",
    "reg_data",
    "old_value",
    "new_value",
    "val_a",
    "val_b",
    "expected_value",
    "actual_value",
    "golden_value",
    "live_value",
    "value",
    "data",
    "safe_projection",
}


# Exact schema fields for public counts, never a primitive-type exemption for
# password/token/credential keys. Table headers are projected as positional rows.
_PUBLIC_AGGREGATE_FIELDS = frozenset(
    {
        "cpassword_hit_count",
        "ms16_072_vulnerable_count",
        "broken_ref_count",
        "admx_gap_count",
        "danger_finding_count",
        "gpo_count",
        "som_count",
        "total_settings",
        "total_delegation_entries",
        "coverage_gap_count",
    }
)


def _mapping(value: object) -> Mapping[str, Any] | None:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: getattr(value, f.name) for f in dataclasses.fields(value)}
    if isinstance(value, Mapping):
        return value
    return None


def _credential_name(name: object) -> bool:
    return bool(_SECRET_KEY.fullmatch(str(name))) or str(name).lower() in _WINDOWS_CREDENTIAL_NAMES


def _credential_material(value: object) -> bool:
    """A secret field is sensitive regardless of the stored primitive type."""
    return value not in (None, "")


def _registry_payload(mapping: Mapping[str, Any]) -> tuple[str, ...]:
    """Read concrete credential values from the supported parser record shapes."""
    values: list[str] = []
    attrs = mapping.get("@attr")
    if isinstance(attrs, Mapping) and ("key" in attrs or "hive" in attrs):
        if _credential_name(attrs.get("name", attrs.get("ValueName", ""))):
            for key in ("value", "data", "Value"):
                if isinstance(attrs.get(key), str) and attrs[key]:
                    values.append(attrs[key])
    # GPMC's <Value><Name>DefaultPassword</Name><String>...</String></Value>.
    children = mapping.get("children")
    if str(mapping.get("tag", "")).lower() == "value" and isinstance(children, list):
        if any(
            isinstance(child, Mapping)
            and child.get("tag") == "Name"
            and _credential_name(child.get("text", ""))
            for child in children
        ):
            for child in children:
                if isinstance(child, Mapping) and child.get("tag") in {"String", "Data", "Value"}:
                    if isinstance(child.get("text"), str) and child["text"]:
                        values.append(child["text"])
    return tuple(values)


def _command_secrets(mapping: Mapping[str, Any]) -> tuple[str, ...]:
    """Known Windows credential switches in task commands, including XML shapes.

    Match complete options only for known executables. Quoted values may contain
    spaces; ':' and '=' forms as well as a separate argument are accepted.
    This is credential discovery, never command execution or policy evaluation.
    """
    attrs = mapping.get("@attr")
    properties = attrs if isinstance(attrs, Mapping) else mapping
    command = properties.get(
        "command", properties.get("appName", properties.get("Path", properties.get("exePath", "")))
    )
    arguments = properties.get("arguments", "")
    if str(mapping.get("tag", "")).lower() == "exec":
        children = mapping.get("children", [])
        if isinstance(children, list):
            for child in children:
                if isinstance(child, Mapping):
                    if str(child.get("tag", "")).lower() == "command":
                        command = child.get("text", "")
                    elif str(child.get("tag", "")).lower() == "arguments":
                        arguments = child.get("text", "")
    if not isinstance(command, str) or not isinstance(arguments, str):
        return ()
    executable = re.split(r"[\\/]", command.strip().strip("\"'"))[-1].lower()
    executable = executable.removesuffix(".exe")
    option = _COMMAND_OPTIONS.get(executable)
    if option is None:
        return ()
    pattern = (
        rf"(?i)(?:^|\s){option}(?:\s*[:=]\s*|\s+)"
        r"""(?:"((?:\\.|`.|""|[^"\\`])*)"|'((?:''|[^'])*)'|([^\s]+))"""
    )
    values: set[str] = set()
    for match in re.finditer(pattern, arguments):
        double, single, bare = match.groups()
        value = next((g for g in match.groups() if g is not None), "")
        if not value:
            continue
        # Keep the source spelling as well as the decoded value: arguments and
        # copied evidence can contain different representations of a password.
        values.add(value)
        if double is not None:
            decoded = re.sub(r'\\(["\\])|`(.)|""', lambda m: m[1] or m[2] or '"', double)
            values.add(decoded)
        elif single is not None:
            values.add(single.replace("''", "'"))
    return tuple(sorted(values))


def secret_values(value: object) -> tuple[str, ...]:
    """Discover credential values while retaining no raw source fragments."""
    secrets: set[str] = set()
    visited: set[int] = set()

    def discover(obj: object) -> None:
        # Query results can repeat a SOM (and its entire link chain) for each
        # matching link. Inspect a shared container once within this call; all
        # its credential values still join the same masking context.
        if id(obj) in visited:
            return
        mapping = _mapping(obj)
        if mapping is not None:
            visited.add(id(obj))
            sensitive = _sensitive(mapping)
            if _credential_name(mapping.get("tag", "")):
                leaf = mapping.get("text")
                if _credential_material(leaf):
                    secrets.add(str(leaf))
            secrets.update(_registry_payload(mapping))
            secrets.update(_command_secrets(mapping))
            for key, child in mapping.items():
                if (
                    key not in _PUBLIC_AGGREGATE_FIELDS
                    and (_credential_name(key) or (sensitive and key in _VALUE))
                    and _credential_material(child)
                ):
                    secrets.add(str(child))
                discover(child)
        elif isinstance(obj, (list, tuple, set, frozenset)):
            visited.add(id(obj))
            for child in obj:
                discover(child)
        elif isinstance(obj, str):
            for match in _USERINFO.finditer(obj):
                secrets.add(match[1])
                secrets.add(unquote(match[1]))

    discover(value)
    return tuple(sorted(secrets, key=lambda s: (-len(s), s)))


def _sensitive(mapping: Mapping[str, Any]) -> bool:
    if any(
        _SECRET_IDENTITY.search(str(mapping.get(k, "")))
        for k in ("identity", "reg_value_name", "field_path", "value_name")
    ) or bool(_SECRET_KEY.fullmatch(str(mapping.get("display_name", "")))):
        return True
    identity = str(mapping.get("identity", ""))
    registry_context = (
        str(mapping.get("cse", "")).lower() in {"registry", "windows registry"}
        or "\\" in identity
        or "reg_value_name" in mapping
        or ("key" in mapping and "value_name" in mapping)
    )
    if registry_context and any(
        _credential_name(name)
        for name in (
            identity.rsplit(":", 1)[-1],
            mapping.get("display_name", ""),
            mapping.get("reg_value_name", ""),
            mapping.get("value_name", ""),
        )
    ):
        return True
    return bool(_registry_payload(mapping))


def _variant_pattern(variant: str) -> str:
    # Hex digits in %XX and \\uXXXX escapes are case-insensitive; literal
    # characters are not, so a differently-cased non-secret is never masked.
    def hex_digits(digits: str) -> str:
        return "".join(f"[{d.lower()}{d.upper()}]" if d.isalpha() else d for d in digits)

    parts: list[str] = []
    for m in re.finditer(r"%([0-9A-Fa-f]{2})|\\u([0-9A-Fa-f]{4})|(.)", variant, re.DOTALL):
        if m[1] is not None:
            parts.append("%" + hex_digits(m[1]))
        elif m[2] is not None:
            parts.append(r"\\u" + hex_digits(m[2]))
        else:
            parts.append(re.escape(m[3]))
    return "".join(parts)


def _secret_variants(secrets: Iterable[str]) -> tuple[tuple[re.Pattern[str], bool], ...]:
    # Older report generators escape at their own render boundary. Include
    # those known renderings so output files and stdout cannot reveal an
    # entity-encoded copy of a credential. Structured views mask before render.
    # Form-encoding ('+' for space) is deliberately absent: it would mask
    # unrelated text such as 'a+b' for a secret 'a b'; '%20' is covered.
    # Copies already escaped in the source data for a later renderer
    # (Markdown backslashes, CSV-doubled quotes, double HTML entities) are
    # out of scope: secret-keyed fields are always redacted by key.
    variants: dict[str, bool] = {}
    for secret in secrets:
        substring_mask = len(secret) >= 6 and not secret.isnumeric()
        utf8 = secret.encode("utf-8", errors="surrogatepass")
        percent = quote(utf8, safe="")
        utf16 = secret.encode("utf-16-be", errors="surrogatepass")
        unicode_escaped = "".join(
            rf"\u{int.from_bytes(utf16[i : i + 2], 'big'):04x}" for i in range(0, len(utf16), 2)
        )
        for variant in {
            secret,
            percent,
            json.dumps(secret, ensure_ascii=True)[1:-1],
            json.dumps(secret, ensure_ascii=False)[1:-1],
            unicode_escaped,
            html.escape(secret),
            html.escape(secret, quote=False),
            secret.replace("`", "&#96;"),
            html.escape(secret.replace("|", "\\|").replace("\n", " "), quote=False),
        }:
            if variant and variant != REDACTED:
                # Escaping must not turn a short secret into an unbounded one.
                # A real long credential can equal a short one's escaped form.
                # In that ambiguous case the long credential must stay masked.
                variants[variant] = variants.get(variant, False) or substring_mask
    ordered = sorted(variants.items(), key=lambda item: (-len(item[0]), item[0]))
    return tuple(
        (
            re.compile(
                _variant_pattern(variant)
                if substring_mask
                else r"(?<![\w.-])" + _variant_pattern(variant) + r"(?![\w.-])"
            ),
            substring_mask,
        )
        for variant, substring_mask in ordered
    )


def _mask_text(value: str, variants: tuple[tuple[re.Pattern[str], bool], ...]) -> str:
    # Short/numeric credentials still mask standalone copies (WI-101), but
    # never substrings of dates, GUIDs, counts or policy names: their patterns
    # carry token boundaries that treat '-' and '.' as part of a token.
    # Credential keys are redacted independently.
    for pattern, _substring_mask in variants:
        value = pattern.sub(REDACTED, value)
    return _ASSIGNMENT.sub(lambda m: m[1] + "=" + REDACTED, value)


def safe_text(value: str, *, secrets: Iterable[str] = ()) -> str:
    """Mask credentials in already-rendered text without destroying its markup.

    Structured projections omit raw fragments before rendering. CLI reports
    have already rendered their HTML/Markdown and must retain that structure.
    """
    return _mask_text(value, _secret_variants(set(secrets) | set(secret_values(value))))


def safe_data(value: object, *, include_audit: bool = True, secrets: Iterable[str] = ()) -> Any:
    """JSON-compatible projection; mask raw and duplicated credential values.

    Raw credential attributes are inspected before omission. External secret
    values carry that context into diffs, active filters and other projections
    whose typed result intentionally omits source subtrees.
    """
    secrets = set(secrets) | set(secret_values(value))
    # Discovery already visited every source string. Prepare escaped spellings
    # once for this projection rather than rediscovering/sorting for each field.
    variants = _secret_variants(s for s in secrets if s != REDACTED)

    def project(obj: object) -> Any:
        mapping = _mapping(obj)
        if mapping is not None:
            sensitive = _sensitive(mapping)
            raw = mapping.get("raw")
            if raw is not None:

                def contains_secret(child: object) -> bool:
                    m = _mapping(child)
                    if m is not None:
                        return any(
                            (_SECRET_KEY.fullmatch(str(k)) and _credential_material(v))
                            or contains_secret(v)
                            for k, v in m.items()
                        )
                    if isinstance(child, (list, tuple)):
                        return any(contains_secret(v) for v in child)
                    return False

                sensitive = sensitive or contains_secret(raw)
            result: dict[str, Any] = {}
            for key, child in mapping.items():
                if key in _OMIT or (key in _AUDIT and not include_audit):
                    result[key] = REDACTED
                elif key in _PUBLIC_AGGREGATE_FIELDS and isinstance(child, (int, float)):
                    result[key] = child
                elif (
                    _credential_name(key)
                    or (key == "text" and _credential_name(mapping.get("tag", "")))
                    or (sensitive and key in _VALUE)
                ) and _credential_material(child):
                    result[key] = REDACTED
                else:
                    result[key] = project(child)
            return result
        if isinstance(obj, (list, tuple)):
            return [project(v) for v in obj]
        if isinstance(obj, (set, frozenset)):
            return [project(v) for v in sorted(obj, key=str)]
        if isinstance(obj, str):
            if obj == REDACTED:
                return obj
            if _RAW_FRAGMENT.search(obj):
                return REDACTED
            return _mask_text(obj, variants)
        return serialize_result(obj)

    return project(value)
