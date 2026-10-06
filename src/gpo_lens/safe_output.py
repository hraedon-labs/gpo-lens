"""Shared safe projections for human exports and view payloads.

Never serialize raw Setting subtrees. Mask credential values even when a
collector flattened them into display text, and mark omitted evidence/audit
fields explicitly. This module is independent of the web and narration.
"""

from __future__ import annotations

import dataclasses
import html
import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import unquote

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
_RAW_FRAGMENT = re.compile(r"</?[A-Za-z][^>]*>|^[OGDS]:.*\([A-Z]+;", re.S)
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


def _mapping(value: object) -> Mapping[str, Any] | None:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: getattr(value, f.name) for f in dataclasses.fields(value)}
    if isinstance(value, Mapping):
        return value
    return None


def _credential_name(name: object) -> bool:
    return bool(_SECRET_KEY.fullmatch(str(name))) or str(name).lower() in _WINDOWS_CREDENTIAL_NAMES


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
            secrets.update(_registry_payload(mapping))
            secrets.update(_command_secrets(mapping))
            for key, child in mapping.items():
                if (
                    (_SECRET_KEY.fullmatch(str(key)) or (sensitive and key in _VALUE))
                    and isinstance(child, str)
                    and child
                ):
                    secrets.add(child)
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


def _secret_variants(secrets: Iterable[str]) -> tuple[str, ...]:
    # Older report generators escape at their own render boundary. Include
    # those known renderings so output files and stdout cannot reveal an
    # entity-encoded copy of a credential. Structured views mask before render.
    variants: set[str] = set()
    for secret in secrets:
        variants.update(
            {
                secret,
                html.escape(secret),
                html.escape(secret, quote=False),
                secret.replace("`", "&#96;"),
                html.escape(secret.replace("|", "\\|").replace("\n", " "), quote=False),
            }
        )
    return tuple(sorted((s for s in variants if s and s != REDACTED), key=lambda s: (-len(s), s)))


def _mask_text(value: str, variants: tuple[str, ...]) -> str:
    for secret in variants:
        value = value.replace(secret, REDACTED)
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
                            (_SECRET_KEY.fullmatch(str(k)) and bool(v)) or contains_secret(v)
                            for k, v in m.items()
                        )
                    if isinstance(child, (list, tuple)):
                        return any(contains_secret(v) for v in child)
                    return False

                sensitive = sensitive or contains_secret(raw)
            result = {}
            for key, child in mapping.items():
                if key in _OMIT or (key in _AUDIT and not include_audit):
                    result[key] = REDACTED
                elif (
                    _SECRET_KEY.fullmatch(str(key)) or (sensitive and key in _VALUE)
                ) and child not in (None, ""):
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
