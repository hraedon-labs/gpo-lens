"""Shared safe projections for human exports and view payloads.

Never serialize raw Setting subtrees. Mask credential values even when a
collector flattened them into display text, and mark omitted evidence/audit
fields explicitly. This module is independent of the web and narration.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable, Mapping
from typing import Any

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


def secret_values(value: object) -> tuple[str, ...]:
    """Discover credential values while retaining no raw source fragments."""
    secrets: set[str] = set()

    def discover(obj: object) -> None:
        mapping = _mapping(obj)
        if mapping is not None:
            sensitive = _sensitive(mapping)
            for key, child in mapping.items():
                if (
                    (_SECRET_KEY.fullmatch(str(key)) or (sensitive and key in _VALUE))
                    and isinstance(child, str)
                    and child
                ):
                    secrets.add(child)
                discover(child)
        elif isinstance(obj, (list, tuple, set, frozenset)):
            for child in obj:
                discover(child)

    discover(value)
    return tuple(sorted(secrets, key=lambda s: (-len(s), s)))


def _sensitive(mapping: Mapping[str, Any]) -> bool:
    return any(
        _SECRET_IDENTITY.search(str(mapping.get(k, "")))
        for k in ("identity", "reg_value_name", "field_path", "value_name")
    ) or bool(_SECRET_KEY.fullmatch(str(mapping.get("display_name", ""))))


def safe_data(value: object, *, include_audit: bool = True, secrets: Iterable[str] = ()) -> Any:
    """JSON-compatible projection; mask raw and duplicated credential values.

    Raw credential attributes are inspected before omission. External secret
    values carry that context into diffs, active filters and other projections
    whose typed result intentionally omits source subtrees.
    """
    secrets = set(secrets) | set(secret_values(value))
    ordered_secrets = sorted((s for s in secrets if s != REDACTED), key=lambda s: (-len(s), s))

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
            for secret in ordered_secrets:
                obj = obj.replace(secret, REDACTED)
            return _ASSIGNMENT.sub(lambda m: m[1] + "=" + REDACTED, obj)
        return serialize_result(obj)

    return project(value)
